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
    let mut call_return: std::collections::HashSet<u64> = program
        .reference_manager
        .references()
        .filter(|r| r.ref_type.is_call())
        .map(|r| r.from.offset)
        .collect();
    // THUNKS. `SharedReturnAnalysisCmd` deliberately skips a jump whose source IS a function entry
    // — in Ghidra that is a thunk, and the ThunkAnalyzer marks the function so the decompiler never
    // walks its body. mosura records no thunk status, so the flow builder FOLLOWED the jump and
    // decompiled the TARGET's body as if it were this function: `FUN_00051e93` is five bytes,
    // `jmp 0x164d9`, and came out as the target's flags-assembly expression with fourteen
    // undefined locals — a description of a different function entirely.
    //
    // Treating it as the tail call it is costs nothing and reuses the machinery already here: the
    // flow builder rewrites the BRANCH to CALL + RETURN, so the body becomes `return f();`.
    let entries: std::collections::HashSet<u64> =
        program.function_manager.functions().map(|f| f.entry.offset).collect();
    for r in program.reference_manager.references() {
        if r.ref_type.is_call() || !entries.contains(&r.from.offset) {
            continue;
        }
        // A jump FROM one function's entry TO a different function's entry.
        if entries.contains(&r.to.offset) && r.to.offset != r.from.offset {
            call_return.insert(r.from.offset);
        }
    }
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
            // THIS function's own `modify` list, from a complete walk of its body. Straight-line
            // `callee_effects` cannot supply it — it gives up at the first branch, and a function
            // with a loop is exactly the case that needs it.
            let cfg = callee_writes_cfg(program, spec, ctx, entry.offset, reg, &f, true);
            f.own_modify = cfg.as_ref().map(|(w, _)| w.clone());
            // Registers the function SAVES AND RESTORES are callee-saved, not arguments. Every
            // prologue does `push ebp`, which READS the incoming EBP — without this the custom
            // register-convention recovery below declares an EBP parameter on almost every
            // function, and the same for any saved ESI/EDI. A declaration built from that is not a
            // recovered contract, it is noise.
            f.own_saved = cfg.as_ref().map(|(_, r)| r.clone());
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
        // The COMPLETE write set over the callee's whole CFG — computed whether or not the
        // straight-line scan succeeded, because the downgrade it feeds is exactly the case the
        // straight-line scan cannot reach.
        if let Some((w, _)) = callee_writes_cfg(program, spec, ctx, target, reg, f, false) {
            f.call_specs.entry(call).or_default().writes_all = Some(w);
        }
        let Some((regs, reads)) = eff else { continue }; // scan bailed — claim nothing
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
/// Every register the callee at `entry` writes, over its WHOLE reachable body — or `None` when that
/// cannot be established.
///
/// [`callee_effects`] answers the same question along a straight line and gives up at the first
/// branch, which is sound for an UPGRADE ("this callee provably clobbers the register, so guard
/// it"). The opposite direction needs the opposite guarantee: to DOWNGRADE a killedbycall register
/// to unaffected at a call site, the evidence must be that the callee writes it on NO path.
/// Absence from a straight-line scan does not say that; absence from a walk of the whole reachable
/// body does.
///
/// Conservative by construction — anything that could write a register this walk cannot see returns
/// `None`: a nested CALL, an indirect branch or call, or running past the instruction budget.
fn callee_writes_cfg(
    program: &Program,
    spec: &crate::sleigh::engine::Spec,
    ctx: &[u32],
    entry: u64,
    reg: crate::decompile::space::SpaceId,
    f: &crate::decompile::funcdata::Funcdata,
    calls_clobber: bool,
) -> Option<(Vec<u64>, Vec<u64>)> {
    use crate::decompile::opcode::OpCode;
    use crate::decompile::space::Address;
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut frontier: Vec<u64> = vec![entry];
    let mut writes: Vec<u64> = Vec::new();
    // A register the callee POPS is one it saved and gave back — preserved, not clobbered.
    // `callee_effects` already draws this distinction (`is_pop` -> `restored`); without it here the
    // walk reports every callee-saved register as written, the downgrade never fires for it, and a
    // caller holding a value across the call has that value killed.
    //
    // Measured on WAR2's FUN_000458ec, whose callee saves and restores EDX: the caller's
    // `param_2 = param_2 + 1` lost its consumer, was absorbed into the call as a second argument,
    // and the loop counter stopped advancing — an INFINITE LOOP in the emitted C, not merely
    // different bytes.
    let mut restored: Vec<u64> = Vec::new();
    let mut budget = 512usize;
    while let Some(pc) = frontier.pop() {
        if !seen.insert(pc) {
            continue;
        }
        budget = budget.checked_sub(1)?;
        let bytes = program.memory.read_window(Address::new(program.default_space, pc), 16);
        if bytes.is_empty() {
            return None;
        }
        let insn = spec.disassemble_ctx(&bytes, pc, ctx).into_iter().next()?;
        if insn.bytes.is_empty() {
            return None;
        }
        let mut fallthrough = true;
        let is_pop = insn.mnemonic.eq_ignore_ascii_case("POP");
        for o in &insn.ops {
            match OpCode::from_u32(o.opcode) {
                Some(OpCode::Return) => fallthrough = false,
                Some(OpCode::Call) | Some(OpCode::Callind) => {
                    // For the DOWNGRADE question ("does this callee leave the register alone?") a
                    // nested call is unknown and the whole answer must be withheld. For the
                    // function's OWN `modify` list the answer is known: whatever the convention
                    // lets a call destroy, this function destroys too by containing one.
                    if !calls_clobber {
                        return None;
                    }
                    for e in f.proto_model.effectlist.iter() {
                        if e.space == reg && e.effect == crate::decompile::fspec::effect::KILLEDBYCALL
                            && !writes.contains(&e.offset)
                        {
                            writes.push(e.offset);
                        }
                    }
                }
                Some(OpCode::Branchind) => {
                    return None;
                }
                // A BRANCH/CBRANCH into the CONSTANT space is p-code-relative control flow WITHIN
                // one instruction (SLEIGH's internal `goto <n>`), not a machine branch: it must not
                // be followed as an address and does not stop the fall-through.
                Some(OpCode::Branch) => {
                    let v = o.ins.first().and_then(|a| a.as_var())?;
                    if v.space != "const" {
                        fallthrough = false;
                        frontier.push(v.offset);
                    }
                }
                Some(OpCode::Cbranch) => {
                    let v = o.ins.first().and_then(|a| a.as_var())?;
                    if v.space != "const" {
                        frontier.push(v.offset);
                    }
                }
                _ => {}
            }
            let Some(out) = &o.out else { continue };
            if out.space != "register" {
                continue;
            }
            let addr = Address::new(reg, out.offset);
            // The stack pointer moves on every push/pop and on `ret`; that is the frame, not a
            // clobber of a caller value. Asked of the space manager, never hardcoded.
            if f.spaces.space_by_spacebase(addr, out.size).is_some() {
                continue;
            }
            if is_pop {
                if !restored.contains(&out.offset) {
                    restored.push(out.offset);
                }
            } else if !writes.contains(&out.offset) {
                writes.push(out.offset);
            }
        }
        if fallthrough {
            frontier.push(pc + insn.bytes.len() as u64);
        }
    }
    writes.retain(|o| !restored.contains(o));
    Some((writes, restored))
}

/// `(registers written and not restored, registers read before being written)` — the callee's
/// recovered `modify` and `parm` lists.
type RegSlot = (crate::decompile::space::Address, u32);
type CalleeEffects = (Vec<RegSlot>, Vec<RegSlot>);

fn callee_effects(
    program: &Program,
    spec: &crate::sleigh::engine::Spec,
    ctx: &[u32],
    entry: u64,
    reg: crate::decompile::space::SpaceId,
    f: &crate::decompile::funcdata::Funcdata,
) -> Option<CalleeEffects> {
    use crate::decompile::opcode::OpCode;
    use crate::decompile::space::Address;
    // `(storage, width, position of its LAST write)`. The position orders the recovered OUTPUT
    // list: a return value is the register written closest to the `ret`, while an earlier write to
    // some other register is an intermediate. Ordering by FIRST write made `movsx edx,dx` outrank
    // the `and eax,edx` that actually produces FUN_0001ed28's return, so EDX became the output, the
    // EAX computation went dead, and the ENTIRE BODY was eliminated — 48 bytes down to a bare
    // `push ebp ; mov ebp,esp ; pop ebp ; ret`.
    let mut written: Vec<(Address, u32, usize)> = Vec::new();
    let mut seq = 0usize;
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
        seq += 1;
        let mut is_ret = false;
        for o in &insn.ops {
            match OpCode::from_u32(o.opcode) {
                Some(OpCode::Return) => is_ret = true,
                // Anything that leaves the straight line: stop and claim nothing.
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
                // Only storage the convention could actually pass an argument in. Without this
                // the FLAG registers come through — every `cmp`/`shl` reads them — and this list
                // becomes the function's own `<input>` model via `recovered_input_list`, which
                // gives each recovered register its own resource group IN ORDER. The flags then
                // occupy groups 1..5, the real EDX/EBX land in groups 6..7, and the run of
                // inactive flag trials trips `force_inactive_chain` (maxchain=2), which marks every
                // LATER trial inactive — so both real parameters are dropped.
                //
                // FUN_0004d95c is the specimen: `shl eax,0x10 ; shl edx,0x8 ; or eax,edx ;
                // or eax,ebx` recovered as `uint4 f(int4 param_1)` with EDX and EBX left as
                // declared-but-never-assigned locals. 579 emitted TUs carry such a local and NONE
                // are byte-clean. The `written` list already had this filter; `reads` did not.
                let plausible = f
                    .proto_model
                    .input
                    .as_ref()
                    .is_some_and(|pl| pl.possible_param(addr, v.size));
                if plausible
                    && !written_any.contains(&v.offset)
                    && !reads.iter().any(|&(a, _)| a == addr)
                {
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
            } else {
                // Only registers the CONVENTION has an opinion about. Dropping the old
                // `== UNAFFECTED` gate entirely let the flag and segment registers in
                // (`ZF`/`CF`/… and the segment bases show up as writes of every `cmp`), and
                // `recovered_output_list` gives each recovered register its own resource group, so
                // a flag landed ahead of the real return register and `derive_output_map` picked
                // it — the regout MVE stopped capturing its call's result.
                let e = f.proto_model.has_effect(addr, out.size);
                let known = e == crate::decompile::fspec::effect::UNAFFECTED
                    || e == crate::decompile::fspec::effect::KILLEDBYCALL;
                if !known {
                    continue;
                }
                // Every non-stack-pointer register the callee writes and does not restore, WITHOUT
                // gating on what the model calls the register.
                //
                // This used to record only registers the model called `<unaffected>` — the
                // "surprising" ones, since the list's first consumer was the killedbycall UPGRADE
                // in `guard_calls`. But the same list is also the callee's recovered OUTPUT storage
                // (`recover::recovered_output_list`), and that question has nothing to do with the
                // model: a register the callee writes and leaves written is a candidate return
                // value whether or not the convention claims it is preserved. Gating the two
                // together meant correcting the convention silently emptied the output list.
                // WIDEST write at an address wins. This list doubles as the function's recovered
                // OUTPUT storage, and deduping on address alone kept whichever width was written
                // FIRST: FUN_00043898 does `mov al,[eax+0x1f]` before `mov ax,[eax*2+0x97e08]`, so
                // the 1-byte AL was recorded, the 2-byte AX ignored, and the function came back
                // `char` — emitting `mov al` where the original returns the full word in AX.
                match written.iter_mut().find(|(a, _, _)| *a == addr) {
                    Some(e) if out.size > e.1 => {
                        e.1 = out.size;
                        e.2 = seq;
                    }
                    Some(e) => e.2 = seq, // remember the LAST write to this register
                    None => written.push((addr, out.size, seq)),
                }
            }
        }
        if is_ret {
            written.retain(|&(a, _, _)| !restored.contains(&a.offset));
            // A SUB-REGISTER write is not output storage of its own. `recovered_output_list` gives
            // every recovered register its own resource group in list order, so an early `mov ah,1`
            // landed ahead of the later `xor eax,eax` and `derive_output_map` picked AH — the
            // function's actual return of 0 was dropped and FUN_00011ab8 lost its `xor eax,eax`
            // (25 bytes -> 23). Drop any entry wholly contained in another's range; the containing
            // write is the storage, the partial one is an intermediate.
            let ranges: Vec<(u64, u32)> = written.iter().map(|&(a, sz, _)| (a.offset, sz)).collect();
            written.retain(|&(a, sz, _)| {
                !ranges.iter().any(|&(o, s)| {
                    (o, s) != (a.offset, sz) && o <= a.offset && a.offset + sz as u64 <= o + s as u64
                })
            });
            // A register the callee saved on entry and popped back is not an argument either — the
            // push READ it, but only to preserve it.
            reads.retain(|&(a, _)| !restored.contains(&a.offset));
            // Most-recently-written first: the return value, then earlier intermediates.
            written.sort_by(|a, b| b.2.cmp(&a.2));
            let written = written.into_iter().map(|(a, sz, _)| (a, sz)).collect();
            return Some((written, reads));
        }
        pc += insn.bytes.len() as u64;
    }
    None // ran off the end of the window without reaching a return — no evidence
}
