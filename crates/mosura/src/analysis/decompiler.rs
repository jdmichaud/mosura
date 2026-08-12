//! Bridge from the analysis `Program` to the decompiler (A6's foundation).
//!
//! The decompiler-driven analyzers (`DecompilerSwitchAnalyzer`, parameter-ID) run the
//! ported decompiler on one function and read back its recovered jump tables
//! ([`Funcdata::jump_tables`]) and prototype ([`Funcdata::func_proto`]). This builds a
//! decompiler `Funcdata` from the loaded `Program` (its memory blocks as the image) and
//! runs the pipeline — the analog of Ghidra's `DecompInterface.decompileFunction`.

use crate::analysis::program::Program;
use crate::decompile::funcdata::Funcdata;
use crate::decompile::space::Address;

/// Decompile the function at `entry` over the `Program`'s loaded memory, returning the
/// decompiled [`Funcdata`] — or `None` if the language tables are unavailable. Callers
/// then read [`Funcdata::jump_tables`] / [`Funcdata::func_proto`].
pub fn decompile_function(program: &Program, entry: Address) -> Option<Funcdata> {
    // Cached (Ghidra `SleighLanguageProvider.getLanguage`): the tables and the default decode
    // context are resolved once per process. A plain `lang::load` here re-read the `.sla`/
    // `.pspec` for every function, and a single transient read failure silently changed *that
    // function's* decode (an unreadable `.pspec` gave an all-zero context register = 16-bit
    // real mode) — see `lang::load_cached`.
    let (spec, ctx) = crate::lang::load_cached(&program.language_id)?;
    // The decompiler reads code + any jump/data tables out of the image, so pass every
    // initialized block (code reached via the entry, tables via constant addresses).
    let chunks: Vec<(u64, &[u8])> = program
        .memory
        .blocks()
        .filter_map(|b| b.bytes.as_deref().map(|bytes| (b.start().offset, bytes)))
        .collect();
    if chunks.is_empty() {
        return None;
    }
    let name = format!("FUN_{:08x}", entry.offset);
    // FlowOverride::CALL_RETURN sites (Ghidra `getFlowOverride`, flow.cc:416): the analysis's
    // `SharedReturnAnalyzer` retypes a shared-return tail-call `jmp` reference to a call, so a
    // call-typed flow reference marks the override. The flow builder converts only those whose
    // instruction actually ends in a BRANCH (a `jmp`), so a normal `call` at a call-typed reference
    // is left untouched. This is the multi-function context Ghidra decompiles with (the isolated
    // datatest path has no such references, keeping the corpus byte-identical).
    let call_return: std::collections::HashSet<u64> = program
        .reference_manager
        .references()
        .filter(|r| r.ref_type.is_call())
        .map(|r| r.from.offset)
        .collect();
    // Decode under the Program's own compiler spec (Ghidra `DecompInterface` reads the
    // Architecture's `CompilerSpec`): a Watcom LE binary resolves the `__watcall` register
    // convention (`specs/x86-32-watcom.cspec`) rather than the datatest x86-64 SysV default,
    // so parameters/returns are recovered instead of the whole program decompiling as `void(void)`.
    // Per-function isolation, faithful to Ghidra's `DecompilerSwitchAnalyzer`: it decompiles each
    // candidate through a `DecompilerCallback` and a single function's decompiler failure is caught
    // and logged, never aborting the analysis pass (DecompInterface returns an error result, not a
    // crash). Mirror that here — a panic inside the ported pipeline on one function yields no
    // jump-table/prototype for it and the pass continues. The half-built `f` is discarded on
    // failure (return None), so no caller observes a partially-decompiled state.
    //
    // The guard covers the FLOW BUILD as well as the simplification pipeline, because the flow
    // build decompiles too: it simplifies a partial function on every round of multistage
    // jump-table recovery (`build.rs`). Guarding only the second phase left the first unprotected,
    // and that is where a real failure landed — an Open Watcom `signl.c` whose overlapping
    // unaligned stack locations never reach SSA, so heritage stalls and `ActionRedundBranch` then
    // trims a MULTIEQUAL that has no inputs.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut f = crate::decompile::build::raw_funcdata_flow_image_overrides(
            spec,
            name,
            &chunks,
            entry.offset,
            ctx,
            &call_return,
            &program.language_id,
            &program.compiler_spec_id,
        );
        // CALLEE-EVIDENCE EFFECTS, before the pipeline: for each direct call, record which
        // registers the CALLEE overwrites that the default convention calls `<unaffected>`.
        // `guard_calls` consults this per call site, so a callee that does not honour the
        // convention no longer lets the caller's stale pre-call value flow across.
        //
        // This must happen HERE and not inside the decompiler: it needs the callee's body, which
        // only the whole-program `Program` has. It is also why Ghidra cannot do it — it recovers a
        // prototype from one function in isolation, and asked about the same WAR2 callee through
        // the whole-image wrapper it emits the same truncated function.
        record_callee_effects(program, spec, ctx, &mut f);
        // SELF-EVIDENCE PROTOTYPE — the same scan, turned on THIS function. A callee that returns
        // in a register the default model calls `<unaffected>` is not merely mis-typed at its call
        // sites: decompiling it ON ITS OWN, nothing consumes the value, so the instruction that
        // computes it is DEAD and is removed, the only reads of its inputs go with it, and
        // `recover_input_params` then has no trials left — the function comes back as
        // `void FUN_x(void) { return; }`. Measured on regout `bump_` (`add ebx,eax ; ret`), and it
        // is what the WAR2 survey's 5-byte `void FUN(void){ return; }` rows actually are: not
        // stubs, but functions whose entire body was eliminated. That is why `void_proto` shows up
        // in every top-5 mismatch cluster — it is the SYMPTOM, and the body is the defect.
        //
        // Gated on a NON-EMPTY overwrite set, so it applies only to the anomaly it describes: a
        // function that writes an `<unaffected>` register and never restores it. `callee_effects`
        // is already conservative (straight line, no branch or call, must reach a `ret`), so an
        // ordinary function returns None and nothing changes. Both halves are set together —
        // giving the input list alone would recover a prototype for a body that has already been
        // deleted, which is a right signature over wrong bytes.
        if let Some(reg) = f.spaces.by_name("register") {
            if let Some((writes, reads)) = callee_effects(program, spec, ctx, entry.offset, reg, &f)
            {
                if !writes.is_empty() {
                    f.proto_model.output =
                        Some(crate::decompile::recover::recovered_output_list(&writes));
                    if !reads.is_empty() {
                        f.proto_model.input =
                            Some(crate::decompile::recover::recovered_input_list(&reads));
                    }
                }
            }
        }
        crate::decompile::pipeline::decompile(&mut f);
        f
    }));
    match outcome {
        Ok(f) => Some(f),
        Err(_) => {
            eprintln!(
                "decompile_function: pipeline failed for FUN_{:08x} — skipping (no switch/proto)",
                entry.offset
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::loader;

    #[test]
    fn recovers_switch_jump_table_through_bridge() {
        if crate::lang::load_cached("x86:LE:64:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        let data = std::fs::read(crate::paths::analysis_corpus_dir().join("switchtab.elf")).unwrap();
        let program = loader::load(&data).unwrap();
        // classify() @ 0x401010 — the dense 7-case switch → jump table (-O2: classify.cold
        // sits at 0x401000, below the entry).
        let mut f = decompile_function(&program, Address::new(program.default_space, 0x40_1010)).unwrap();
        let jts = f.jump_tables();
        let total: usize = jts.iter().map(|t| t.targets.len()).sum();
        eprintln!(
            "switch recovery: {} table(s), targets {:?}",
            jts.len(),
            jts.iter().map(|t| (t.op_addr, t.targets.len())).collect::<Vec<_>>()
        );
        assert!(!jts.is_empty(), "decompiler should recover classify's jump table via the bridge");
        assert!(total >= 7, "7 case targets (0..=6), got {total}");
    }
}

/// Registers a callee overwrites that the default convention declares `<unaffected>`.
///
/// Decodes the callee's instructions from the image and reports the registers it writes without
/// restoring before its terminal return. Such a register is one this callee does not preserve,
/// whatever the model says — and the model is a DEFAULT: Watcom sets `modify` per translation
/// unit via `#pragma aux`, and hand-written assembly obeys whatever contract its callers were
/// built against. Measured on WAR2: 264 such registers across 245 functions.
///
/// Deliberately conservative. The walk is linear and stops at the first branch or call, so a
/// callee it cannot follow keeps today's behaviour rather than acquiring a guess.
fn record_callee_effects(
    program: &Program,
    spec: &crate::sleigh::engine::Spec,
    ctx: &[u32],
    f: &mut crate::decompile::funcdata::Funcdata,
) {
    use crate::decompile::opcode::OpCode;
    // GATED OFF BY DEFAULT — one gap left, documented below.
    //
    // Both halves of the per-call prototype now exist. `callee_effects` recovers, from the callee's
    // own body, the registers it writes without restoring AND the registers it reads before writing
    // — its `modify` and `parm` lists. `guard_calls` marks the former killedbycall at that call
    // site; `recover::recovered_output_list` maps them as that call's OUTPUT storage when the
    // default `<output>` does not explain the return; and `check_input_trial_use` vetoes an
    // argument trial for any register the callee never reads. Measured on the regout MVE
    // (oracle/ground-truth/src/regout.c), which reproduces the WAR2 FUN_00074744 defect:
    //
    //   gated off   pxVar1 = pxRam08049070; func_0x08048106(param_2); *pxVar1 = param_1;
    //   enabled     pxVar1 = (xunknown1 *)func_0x08048106(param_2);   *pxVar1 = param_1;
    //
    // The store now goes through the call's RESULT instead of the caller's stale pre-call pointer,
    // which was wrong code on both sides of the call. The argument veto took the same call from 5
    // spurious arguments to 1.
    //
    // REMAINING GAP, and why it is still gated: the source passes TWO arguments
    // (`bump(p, n)` — `parm caller [ebx] [eax]`), and EBX is dropped.
    //
    // MEASURED, not assumed. Instrumenting the trials at `build_input_from_trials` gives EBX
    // `used=false active=false defnouse=false` — the INACTIVE branch of `check_input_trial_use`,
    // reached when the value is realistic but `ancestor_op_use` finds it is NOT used solely to feed
    // this call. It is NOT the argument veto (EAX and EBX both come back `vetoed=false`; only
    // ECX/EDX/stack are vetoed), and it is NOT the call's output shadowing the input — the call
    // still has `out=None` at that point, so `resolve_call_output` has not run yet.
    //
    // Both halves of the per-call prototype are live and the pass is ON. `MOSURA_CALLEE_EFFECTS=0`
    // disables it.
    //
    // The gap that kept this gated is closed. It was not a representational impossibility, as three
    // successive readings claimed: pass-correlating the verdicts showed `check_input_trial_use`
    // marks the both-directions register ACTIVE, and `fillin_map`'s definitely-not-used chain rule
    // (fspec.rs:498-511) cleared it afterwards — a fully-`dnu` exclusion group latches
    // `seendefnouse` and marks every LATER trial inactive. Suppressing EDX in the middle of
    // watcall's EAX/EDX/EBX/ECX sequence took EBX down with it. Replacing the model's input list
    // with the callee's own (`recovered_input_list`) makes the recovered registers consecutive
    // groups, leaving the faithful rule nothing to fire on, and retires the suppression entirely.
    //
    // On the regout MVE, which reproduces WAR2 FUN_00074744:
    //
    //   before   pxVar1 = pxRam08049070; func_0x08048106(param_2);            *pxVar1 = param_1;
    //   now      pxVar1 = (xunknown1 *)func_0x08048106(xRam08049070,param_2); *pxVar1 = param_1;
    //
    // which is the source: `p = bump(g_dst, n); *p = v` — both arguments, in the order
    // `parm caller [ebx] [eax]` declares, and the result consumed by the store.
    if std::env::var_os("MOSURA_CALLEE_EFFECTS").is_some_and(|v| v == "0") {
        return;
    }
    let Some(reg) = f.spaces.by_name("register") else { return };
    let calls: Vec<crate::decompile::op::OpId> =
        f.op_ids().filter(|&op| f.op(op).code() == OpCode::Call).collect();
    if std::env::var_os("MOSURA_EFFECTS_DEBUG").is_some() {
        eprintln!("record_callee_effects: {} ops, {} direct calls", f.op_ids().count(), calls.len());
    }
    type Effects = Option<(
        Vec<(crate::decompile::space::Address, u32)>,
        Vec<(crate::decompile::space::Address, u32)>,
    )>;
    let mut cache: std::collections::HashMap<u64, Effects> = std::collections::HashMap::new();
    // Function entry points, sorted — a callee's extent is [entry, next_entry), which bounds the
    // control-flow input walk.
    let mut ends: Vec<u64> =
        program.function_manager.functions().map(|fu| fu.entry.offset).collect();
    ends.sort_unstable();
    for call in calls {
        let Some(t) = f.op(call).input(0) else { continue };
        // A CALL's input 0 carries its target in the varnode's LOCATION, not as a constant
        // value — the same field printc reads to name `func_0x<addr>`. Testing `is_constant()`
        // here found nothing and the pass was silently inert.
        let target = f.vn(t).loc.offset;
        if target == 0 {
            continue;
        }
        let eff = cache
            .entry(target)
            .or_insert_with(|| callee_effects(program, spec, ctx, target, reg, f))
            .clone();
        // When the linear scan cannot follow the callee (it branches — i.e. most real callees),
        // fall back to the control-flow input analysis. Without it the call reverts to the
        // convention's full register list, whose empty leading slots read as holes and cost the
        // argument entirely.
        let eff = match eff {
            Some(v) => Some(v),
            None => callee_inputs_cfg(program, spec, ctx, target, reg, f, &ends)
                .map(|reads| (Vec::new(), reads)),
        };
        let Some((regs, reads)) = eff else { continue }; // no evidence — claim nothing
        if std::env::var_os("MOSURA_EFFECTS_DEBUG").is_some() {
            eprintln!("callee {target:08x} overwrites {regs:?} reads {reads:?}");
        }
        let cs = f.call_specs.entry(call).or_default();
        cs.overwrites = regs;
        cs.reads = Some(reads);
    }
}

/// One straight-line pass over a callee's body, recovering BOTH halves of its prototype: the
/// registers it writes without restoring (its `modify`/output storage) and the registers it reads
/// before writing (its input storage).
///
/// `None` when the walk cannot follow the body — the first branch or call ends it and nothing is
/// claimed, so an unscannable callee keeps today's behaviour rather than acquiring a guess.
#[allow(clippy::type_complexity)]
fn callee_effects(
    program: &Program,
    spec: &crate::sleigh::engine::Spec,
    ctx: &[u32],
    entry: u64,
    reg: crate::decompile::space::SpaceId,
    f: &crate::decompile::funcdata::Funcdata,
) -> Option<(Vec<(crate::decompile::space::Address, u32)>, Vec<(crate::decompile::space::Address, u32)>)>
{
    use crate::decompile::opcode::OpCode;
    use crate::decompile::space::Address;
    let mut written: Vec<(Address, u32)> = Vec::new();
    let mut restored: Vec<u64> = Vec::new();
    // Every register offset written so far, whatever the model says about it — a read AFTER one of
    // these is the callee's own value, not an argument the caller supplied.
    let mut written_any: Vec<u64> = Vec::new();
    let mut reads: Vec<(Address, u32)> = Vec::new();
    let mut pc = entry;
    for _ in 0..64 {
        let bytes = program.memory.read_window(Address::new(program.default_space, pc), 16);
        if bytes.is_empty() {
            break;
        }
        let Some(insn) = spec.disassemble_ctx(&bytes, pc, ctx).into_iter().next() else { break };
        if insn.bytes.is_empty() {
            break;
        }
        let is_pop = insn.mnemonic.eq_ignore_ascii_case("POP");
        let mut is_ret = false;
        for o in &insn.ops {
            match OpCode::from_u32(o.opcode) {
                Some(OpCode::Return) => is_ret = true,
                // A branch ends what this LINEAR walk can prove. Reads gathered so far are a
                // LOWER BOUND (the entry block executes unconditionally), and a lower bound is
                // not usable here: `recovered_input_list` REPLACES the convention's list, so a
                // short list silently truncates the argument list. Measured on the twoarg MVE —
                // `add2b_` reads EDX in its entry block and EAX only after the branch, and
                // returning just EDX dropped the EAX argument.
                //
                // The complete answer needs the callee's control flow, which `callee_inputs_cfg`
                // computes; this linear scan stays conservative and claims nothing.
                Some(OpCode::Call) | Some(OpCode::Callind) | Some(OpCode::Branch)
                | Some(OpCode::Branchind) | Some(OpCode::Cbranch) => return None,
                _ => {}
            }
            // Inputs BEFORE the output, so an instruction that reads and writes the same register
            // (`add ebx,eax`) counts EBX as an argument as well as an overwrite — which is exactly
            // the shape this whole track exists for.
            for a in &o.ins {
                let Some(v) = a.as_var() else { continue };
                if v.space != "register" {
                    continue;
                }
                let addr = Address::new(reg, v.offset);
                // `ret` and every push/pop read the stack pointer; that is the frame moving, not an
                // argument. Asked of the space manager, never by hardcoding ESP.
                if f.spaces.space_by_spacebase(addr, v.size).is_some() {
                    continue;
                }
                if !written_any.contains(&v.offset) && !reads.iter().any(|&(a, _)| a == addr) {
                    reads.push((addr, v.size));
                }
            }
            let Some(out) = &o.out else { continue };
            if out.space != "register" {
                continue;
            }
            let addr = Address::new(reg, out.offset);
            // The STACK POINTER is written by `ret` itself (the pop) and by every push/pop on the
            // way. It is not an overwrite of a caller value, and recording it made the call site
            // sprout spurious parameters. Ask the space manager which register it is rather than
            // hardcoding ESP — that constant is the x86-64-vs-cspec class this project retired.
            if f.spaces.space_by_spacebase(addr, out.size).is_some() {
                continue;
            }
            written_any.push(out.offset);
            if is_pop {
                restored.push(out.offset); // saved and restored ⇒ preserved after all
            } else if f.proto_model.has_effect(addr, out.size)
                == crate::decompile::fspec::effect::UNAFFECTED
                && !written.iter().any(|&(a, _)| a == addr)
            {
                written.push((addr, out.size));
            }
        }
        if is_ret {
            written.retain(|&(a, _)| !restored.contains(&a.offset));
            // A register the callee saved on entry and popped back is not an argument either — the
            // push READ it, but only to preserve it.
            reads.retain(|&(a, _)| !restored.contains(&a.offset));
            return Some((written, reads));
        }
        pc += insn.bytes.len() as u64;
    }
    None // ran off the end of the window without reaching a return — no evidence
}

/// The registers a callee reads BEFORE writing, over its whole control flow — its real input set.
///
/// `callee_effects`' linear walk stops at the first branch, and its partial answer is unusable
/// because `recovered_input_list` REPLACES the convention's list: a short list truncates the
/// argument list rather than extending it. Real callees branch, so without this they fall back to
/// the convention, where the empty slots ahead of a used register read as holes and
/// `force_inactive_chain` (a faithful port of Ghidra `fspec.cc:1111`) marks the live trial
/// inactive — and the argument is dropped. Measured: 601 mismatching WAR2 functions have an
/// original doing `mov <argreg>,imm32 ; call` whose argument we lose that way.
///
/// A register is an input if SOME path from the entry reaches a read of it with no earlier write.
/// That is a may-analysis, so the walk follows both edges of a conditional and unions the results.
/// State is `(pc, written-mask)` and each is visited once, which bounds the search; anything that
/// cannot be followed (an indirect branch, a target outside the extent) simply ends that path.
///
/// A CALL is treated as WRITING every argument register. That under-claims — a register read after
/// a call is not reported as an input — which is the safe direction: over-claiming would add
/// arguments the callee never takes.
fn callee_inputs_cfg(
    program: &Program,
    spec: &crate::sleigh::engine::Spec,
    ctx: &[u32],
    entry: u64,
    reg: crate::decompile::space::SpaceId,
    f: &crate::decompile::funcdata::Funcdata,
    ends: &[u64],
) -> Option<Vec<(crate::decompile::space::Address, u32)>> {
    use crate::decompile::opcode::OpCode;
    use crate::decompile::space::Address;
    let end = match ends.binary_search(&entry) {
        Ok(i) => *ends.get(i + 1)?,
        Err(_) => return None,
    };
    if end <= entry || end - entry > 8192 {
        return None;
    }
    // The convention's own parameter registers are the only candidates worth tracking.
    let cand: Vec<(u64, u32)> = f
        .proto_model
        .input
        .as_ref()?
        .entry
        .iter()
        .filter(|e| e.space == reg)
        .map(|e| (e.addressbase, e.size))
        .collect();
    if cand.is_empty() {
        return None;
    }
    let bit = |off: u64| cand.iter().position(|&(b, _)| b == off).map(|i| 1u32 << i);
    let mut inputs = 0u32;
    let mut seen: std::collections::HashSet<(u64, u32)> = std::collections::HashSet::new();
    let mut work: Vec<(u64, u32)> = vec![(entry, 0)];
    let mut steps = 0usize;
    while let Some((mut pc, mut written)) = work.pop() {
        loop {
            steps += 1;
            if steps > 20_000 || pc < entry || pc >= end || !seen.insert((pc, written)) {
                break;
            }
            let bytes = program.memory.read_window(Address::new(program.default_space, pc), 16);
            if bytes.is_empty() {
                break;
            }
            let Some(insn) = spec.disassemble_ctx(&bytes, pc, ctx).into_iter().next() else { break };
            if insn.bytes.is_empty() {
                break;
            }
            let next = pc + insn.bytes.len() as u64;
            let mut ends_path = false;
            let mut targets: Vec<u64> = Vec::new();
            for o in &insn.ops {
                // READS first: an instruction that reads and writes the same register (`add
                // ebx,eax`) still has EBX as an input.
                for a in &o.ins {
                    if let Some(v) = a.as_var() {
                        if v.space == "register" {
                            if let Some(b) = bit(v.offset) {
                                if written & b == 0 {
                                    inputs |= b;
                                }
                            }
                        }
                    }
                }
                match OpCode::from_u32(o.opcode) {
                    Some(OpCode::Return) | Some(OpCode::Branchind) => ends_path = true,
                    Some(OpCode::Call) | Some(OpCode::Callind) => {
                        written |= (1u32 << cand.len()) - 1; // a call clobbers the argument registers
                    }
                    Some(OpCode::Branch) | Some(OpCode::Cbranch) => {
                        if let Some(t) = o.ins.first().and_then(|a| a.as_var()) {
                            if t.space == "ram" {
                                targets.push(t.offset);
                            }
                        }
                        if OpCode::from_u32(o.opcode) == Some(OpCode::Branch) {
                            ends_path = true; // unconditional: only the target continues
                        }
                    }
                    _ => {}
                }
                if let Some(out) = &o.out {
                    if out.space == "register" {
                        if let Some(b) = bit(out.offset) {
                            written |= b;
                        }
                    }
                }
            }
            for t in targets {
                if t >= entry && t < end {
                    work.push((t, written));
                }
            }
            if ends_path {
                break;
            }
            pc = next;
        }
    }
    let out: Vec<(Address, u32)> = cand
        .iter()
        .enumerate()
        .filter(|(i, _)| inputs & (1u32 << i) != 0)
        .map(|(_, &(b, sz))| (Address::new(reg, b), sz))
        .collect();
    if out.is_empty() { None } else { Some(out) }
}
