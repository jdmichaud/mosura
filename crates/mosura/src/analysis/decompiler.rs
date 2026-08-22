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
    // The loader knows which sections are read-only, and the decompiler needs it: Ghidra's
    // `Scope::isReadOnly` gates `RulePtrsubCharConstant` on exactly this. It used to be dropped
    // here, so the decompiler had no read-only channel at all.
    let readonly_ranges: Vec<(u64, u64)> = program
        .memory
        .blocks()
        .filter(|b| !b.write && b.bytes.is_some())
        .map(|b| (b.start().offset, b.end().offset))
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
        // Everything from the flow build to the end of the pipeline is a closure, because Ghidra's
        // `ActionRestartGroup` may need to run it twice: `clearAnalysis` throws the graph away and
        // `ActionStart`'s `followFlow` regenerates it. mosura generates p-code out here rather than
        // inside the action tree, so this is where the rebuild has to live.
        let build_one = |prev: Option<&crate::decompile::Funcdata>| {
        let mut f = crate::decompile::build::raw_funcdata_flow_image_overrides(
            spec,
            name.clone(),
            &chunks,
            entry.offset,
            ctx,
            &call_return,
            &program.language_id,
            &program.compiler_spec_id,
        );
        f.readonly_ranges = readonly_ranges.clone();
        // Which Ghidra global-scope context this decompile models is the PROGRAM's property —
        // application (default) or standalone — see `Program::global_scope_all_loaded`.
        f.global_scope_all_loaded = program.global_scope_all_loaded;
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
            // For the function's OWN lists the flow-walk is the wrong tool: it bails on the
            // first BRANCHIND, and a function with a SWITCH has one by construction -- so the
            // biggest functions, the ones whose `modify` list matters most, got none. Watcom then
            // had to preserve every scratch register the body uses: WAR2's FUN_0006c6f0 (1,963 B,
            // a switch) grew three extra saves (`PUSH EBX/ECX/EDX`), shifting every frame offset
            // in the function. The union-over-instructions the lists want does not need flow at
            // all: analysis already resolved the switch targets when it computed the RECORDED
            // BODY, and every instruction in the body contributes its writes and restores
            // regardless of path. Walk that.
            let cfg = own_effects_over_body(program, spec, ctx, entry, reg, &f)
                .or_else(|| callee_writes_cfg(program, spec, ctx, entry.offset, reg, &f, NestedCalls::Blanket).map(|(w, r)| (w, r)));
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
            // Carry the deadcode-delay override across a restart — the one piece of state
            // Ghidra's `Funcdata::clear` deliberately preserves (funcdata.cc:106).
            if let Some(p) = prev {
                f.deadcode_delay_override = p.deadcode_delay_override.clone();
                f.apply_deadcode_delay_override();
            }
            f
        };
        let mut f = build_one(None);
        crate::decompile::pipeline::decompile(&mut f);
        let mut restarts = 0;
        while f.restart_pending && restarts < crate::decompile::pipeline::MAX_RESTARTS {
            restarts += 1;
            if std::env::var("MOSURA_RESTART_DEBUG").is_ok() {
                eprintln!("RESTART re-running decompile (attempt {restarts})");
            }
            f = build_one(Some(&f));
            crate::decompile::pipeline::decompile(&mut f);
        }
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
    // The callee's stack-cleanup contract (RET vs RET n), per callee, memoized: the same callee is
    // called many times per function (63 memset calls in FUN_0001fdbc alone).
    let mut cleanup_cache: std::collections::HashMap<u64, Option<u32>> = std::collections::HashMap::new();
    // The caller-cleaned callee's own modify set (calls_clobber=true walk), per callee, memoized
    // like the cleanup contract — same callees, same fan-in.
    let mut modify_cache: std::collections::HashMap<u64, Option<Vec<u64>>> = std::collections::HashMap::new();
    // The caller-cleaned family's contracts use the BLANKET walk (sb98's landed semantics)
    // while the general population uses the transitive one — TWO different computations
    // that must never share a cache entry: a callee reached through both paths (one site
    // caller-cleaned, another not) previously got whichever ran first, an order-dependent
    // contamination that surfaced as two caller-cleaned pragmas losing ECX.
    let mut cleaned_cache: std::collections::HashMap<u64, Option<Vec<u64>>> = std::collections::HashMap::new();
    // THE PER-(TU, CALLEE) CONTRACT MAP — Increment 1 of the reopened sb99 design
    // (docs/byte-exact-status.md): ONE value per callee for this caller, transitive
    // body-truth NARROWED by this caller's own survival testimony, consumed by BOTH the
    // emitted callee pragma and the thunk own-contract inheritance (which therefore agree
    // by construction — the consistency defect that cost 0x5d00a/0x71caf in the sb99
    // rounds cannot recur). Caller-cleaned callees are EXEMPT from the veto: their full
    // recovered kill set is the landed sb98 result, and the veto on them re-broke measured
    // EXACTs in the add-direction (FUN_00011128, FUN_0004dee0).
    //
    // The CFG for the survival walk is built on a throwaway CLONE with the pipeline's own
    // builder — building it in place corrupts the later pipeline (measured 734 → 139).
    let cfg_probe: Option<crate::decompile::funcdata::Funcdata> = if calls.is_empty() {
        None
    } else {
        let mut probe = f.clone();
        crate::decompile::cfg::build_cfg(&mut probe);
        Some(probe)
    };
    let call_pos: std::collections::HashMap<crate::decompile::op::OpId, (usize, usize)> = {
        let mut m = std::collections::HashMap::new();
        if let Some(probe) = cfg_probe.as_ref() {
            for (bi, blk) in probe.blocks().iter().enumerate() {
                for (oi, &opid) in blk.ops.iter().enumerate() {
                    if calls.contains(&opid) {
                        m.insert(opid, (bi, oi + 1));
                    }
                }
            }
        }
        m
    };
    // Vetoes are keyed by TARGET and unioned over ALL of this caller's call sites to it:
    // the emitted pragma is one declaration per (TU, callee), so the contract must satisfy
    // every site's testimony — and every call op to one callee then carries the SAME
    // contract, by construction.
    let mut veto_cache: std::collections::HashMap<u64, Vec<u64>> = std::collections::HashMap::new();
    // THE NO-SAVE TESTIMONY, the survival veto's complement: a GPR the CALLER's own
    // contract must preserve (it neither clobbers it at return nor saves-and-restores it)
    // cannot have been killed by ANY callee this TU calls — the original compiler's own
    // codegen would otherwise have forced the save our recompile demonstrably adds
    // (FUN_00072c37 grew PUSH/POP ESI around a callee whose transitive truth clobbers ESI;
    // the original's declaration evidently preserved it). Computed from the caller's own
    // body walk: writes ∪ restored = every register it touches; the six pragma GPRs outside
    // that union are preserved-without-saving, and veto every non-caller-cleaned contract.
    let tu_preserve_veto: Vec<u64> = {
        let own = callee_writes_cfg(program, spec, ctx, f.addr.offset, reg, f, NestedCalls::Blanket);
        match own {
            Some((w, r)) => [0u64, 4, 8, 0xc, 0x18, 0x1c]
                .into_iter()
                .filter(|&g| {
                    !w.iter().chain(r.iter()).any(|&o| (o & !3) == g)
                })
                .collect(),
            // The caller's own walk failed (indirect flow): no testimony, veto nothing.
            None => Vec::new(),
        }
    };
    // Each call op's argument-register read set, from the whole-program prototype recovery
    // (empty when the pass is off — the walks then behave exactly as the landed baseline).
    let call_reads: std::collections::HashMap<crate::decompile::op::OpId, Vec<u64>> = {
        let mut m = std::collections::HashMap::new();
        for &c in &calls {
            if let Some(t) = f.op(c).input(0) {
                let va = f.vn(t).loc.offset;
                if let Some(p) = program.recovered_protos.get(&va) {
                    let regspace = f.spaces.by_name("register");
                    let regs: Vec<u64> = p
                        .params
                        .iter()
                        .filter(|prm| Some(prm.addr.space) == regspace)
                        .map(|prm| prm.addr.offset)
                        .collect();
                    if !regs.is_empty() {
                        m.insert(c, regs);
                    }
                }
            }
        }
        m
    };
    let sites_of: std::collections::HashMap<u64, Vec<(usize, usize)>> = {
        let mut m: std::collections::HashMap<u64, Vec<(usize, usize)>> = std::collections::HashMap::new();
        for &c in &calls {
            if let (Some(t), Some(&pos)) = (f.op(c).input(0), call_pos.get(&c)) {
                let va = f.vn(t).loc.offset;
                if va != 0 {
                    m.entry(va).or_default().push(pos);
                }
            }
        }
        m
    };

    // The stack pointer's register offset, for reading `RET n` off the lifted p-code.
    let esp_off = f
        .spaces
        .by_name("stack")
        .and_then(|st| f.spaces.get(st).spacebase.first().map(|&(a, _)| a.offset));
    for &call in &calls {
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
        if let Some((w, _)) = callee_writes_cfg(program, spec, ctx, target, reg, f, NestedCalls::Fail) {
            f.call_specs.entry(call).or_default().writes_all = Some(w);
        }
        // The call site's stack-pointer change, from the callee's own return instruction —
        // per-callee knowledge Ghidra carries on every analyzed function's prototype in its
        // database (`ActionDefaultParams` copies it onto the call, coreaction.cc:2327),
        // INDEPENDENT of whether the whole-program pass recovered the callee's parameters.
        // This used to live inside the recovered-proto branch below, so the DEFAULT
        // configuration modelled every watcall call as EXTRAPOP_UNKNOWN: the INDIRECT chain
        // left every stack placeholder unresolvable (PH abort-UNRESOLVED at all nine calls
        // of FUN_000191b8) and every stack argument was silently dropped — the dominant
        // mechanism of the missing-only census (docs/byte-exact-status.md, open thread 1b's
        // endgame). extrapop counts the return-address slot plus whatever the callee's
        // `RET n` pops.
        if let Some(sp) = esp_off {
            let cl = *cleanup_cache
                .entry(target)
                .or_insert_with(|| callee_cleanup(program, spec, ctx, target, sp));
            if let Some(n) = cl {
                f.call_specs.entry(call).or_default().extrapop = Some(4 + n as i32);
                // SHADOW CENSUS (stack-args frontier): a callee popping its own stack
                // bytes (`RET n`, n>0) declares n/4 stack argument slots — the watcall
                // overflow family the trial chain currently starves.
                if n > 0 && std::env::var_os("MOSURA_STACKARG_SHADOW").is_some() {
                    eprintln!("[stackarg] call@{:#x} callee {target:#x} pops {n}", f.op(call).seqnum.pc.offset);
                }
            }
            // PER-CALL MODEL EVIDENCE: the caller popping this call's arguments itself. Only
            // meaningful when the callee's `RET` provably pops nothing (`cl == Some(0)`) — a
            // `RET n` callee plus a caller ADD would be double cleanup, i.e. not a convention
            // we recognize. The fallthrough instruction is re-disassembled from bytes rather
            // than searched in `f`'s ops so the test cannot confuse the ORIGINAL `ADD ESP,n`
            // with the extrapop INT_ADD the decompiler itself inserts at the call's pc.
            if cl == Some(0) {
                let pc = f.op(call).seqnum.pc.offset;
                let n = caller_cleanup_after(program, spec, ctx, pc, sp);
                if std::env::var_os("MOSURA_ARG_DEBUG").is_some() {
                    eprintln!("[cdecl-evd] call@{pc:#x} target={target:#x} caller_cleans={n:?}");
                }
                if let Some(n) = n {
                    // The callee's clobber contract for the caller-pops pragma — the
                    // LANDED sb98 semantics: body writes with nested calls as the
                    // convention's BLANKET kill set. NOT the transitive fixed-point: the
                    // original's DECLARED contract is a per-TU latent (headers/pragmas of
                    // the original build), and it provably sides with the blanket at some
                    // callees (FUN_00011128 saves EBX/ECX around 0x52874, whose transitive
                    // truth is narrower) and with the transitive truth at others
                    // (FUN_00031d58's callee — the standing residue). Choosing between
                    // them PER CALLEE needs the callers' dataflow testimony
                    // (docs/byte-exact-status.md sb99, the parked design); until then the
                    // measured-landed blanket stands.
                    let modify = cleaned_cache
                        .entry(target)
                        .or_insert_with(|| {
                            callee_writes_cfg(program, spec, ctx, target, reg, f, NestedCalls::Blanket)
                                .map(|(w, _)| w)
                        })
                        .clone();
                    let cs = f.call_specs.entry(call).or_default();
                    cs.caller_cleans = Some(n);
                    cs.cdecl_modify = modify;
                }
            }
        }
        // THE CALLEE'S CONTRACT for this call — see the map's doc at `cfg_probe` above.
        // Caller-cleaned calls are handled in their own branch below (blanket, no veto).
        if f.call_specs.get(&call).and_then(|c| c.caller_cleans).unwrap_or(0) == 0 {
            let m = modify_cache
                .entry(target)
                .or_insert_with(|| transitive_contract(program, spec, ctx, target, reg, f))
                .clone();
            if let Some(mut w) = m {
                if let (Some(sites), Some(probe)) = (sites_of.get(&target), cfg_probe.as_ref()) {
                    let veto = veto_cache
                        .entry(target)
                        .or_insert_with(|| {
                            w.iter()
                                .copied()
                                // Only the six pragma-expressible GPRs are worth walking:
                                // ESP/EBP are rejected by Watcom in a modify list (E1122)
                                // and flag offsets never render.
                                .filter(|&c| matches!(c & !3, 0 | 4 | 8 | 0xc | 0x18 | 0x1c))
                                .filter(|&c| {
                                    sites
                                        .iter()
                                        .any(|&pos| {
                                            // The veto walks run WITHOUT the arity map:
                                            // survival-into-a-later-call's-argument is
                                            // exactness testimony (below), not license to
                                            // narrow the landed kill sets — threading it
                                            // here rewrote increment-1 contracts under the
                                            // prototype pass (FUN_00012360's 0x58ff8 lost
                                            // its ECX kill and the EXACT with it).
                                            survives_call(
                                                probe,
                                                reg,
                                                pos,
                                                c,
                                                &Default::default(),
                                                &Default::default(),
                                            )
                                        })
                                })
                                .collect::<Vec<u64>>()
                        })
                        .clone();
                    w.retain(|c| !veto.contains(c));
                }
                w.retain(|&c| !tu_preserve_veto.contains(&(c & !3)));
                let cs = f.call_specs.entry(call).or_default();
                cs.cdecl_modify = Some(w);
            }
        }
        // THE CALLEE'S OWN RECOVERED PROTOTYPE, when the whole-program pass has established one.
        //
        // `callee_effects` below answers the same question by walking the callee's body in a
        // straight line, and gives up at its first branch or call. That reaches only the simplest
        // bodies, which is why the mechanism was right and barely moved the population. Decompiling
        // the callee answers it completely — and decompiling every function is something the
        // whole-program pass already does, so the answer exists and was simply being discarded.
        //
        // It REPLACES the scan rather than merging with it: two derivations of one callee's
        // parameter list can disagree, and the complete one is not improved by the partial one's
        // opinion. `derive_input_map` then treats the list as fact rather than as candidates,
        // exactly as Ghidra's `ActionDefaultParams` copies a callee's recovered prototype onto the
        // call (coreaction.cc:2327).
        //
        // A missing entry means the pass has not run, or the callee could not be decompiled, or the
        // target is indirect — never "this callee takes no arguments". Absence falls through to the
        // scan, which falls through to the default convention.
        if let Some(proto) = program.recovered_protos.get(&target) {
            if std::env::var_os("MOSURA_EFFECTS_DEBUG").is_some() {
                eprintln!(
                    "callee {target:08x} recovered proto: params={:?} out={:?}",
                    proto.params.iter().map(|p| (f.spaces.get(p.addr.space).name.clone(), p.addr.offset, p.size)).collect::<Vec<_>>(),
                    proto.output.as_ref().map(|o| (f.spaces.get(o.addr.space).name.clone(), o.addr.offset, o.size))
                );
            }
            // A recovered parameter's size is the width the CALLEE READS, which is not the width
            // of the slot it arrives in. This callee reads DX and BX, two bytes each, while the
            // caller writes whole 4-byte registers — and a 4-byte trial cannot justify into an
            // entry whose maximum size is 2, so every such argument was dropped and a five-argument
            // call came out with one. An exclusion entry (a register) is a slot dedicated whole to
            // one parameter, so the convention's own declared width is the slot width. A
            // non-exclusion entry (the stack overflow area) parcels out ALIGNMENT-strided slots:
            // the region's total size says nothing about one parameter, but the granule does —
            // the caller pushes whole granules (dwords under watcall/cdecl) however few bytes the
            // callee reads. Keeping the recovered 1-byte width made the caller's 4-byte push fail
            // justification against the injected entry and scrambled the site's value↔slot
            // pairing (FUN_000659ec's inverted arguments), so a stack width rounds up to the
            // granule.
            let slots: Vec<(crate::decompile::space::Address, u32)> = proto
                .params
                .iter()
                .map(|p| {
                    let width = f
                        .proto_model
                        .input
                        .as_ref()
                        .and_then(|pl| {
                            pl.entry
                                .iter()
                                .find(|e| e.justified_contain(p.addr, p.size).is_some())
                                .map(|e| if e.is_exclusion_slot() {
                                    e.size
                                } else {
                                    p.size.div_ceil(e.alignment.max(1)) * e.alignment.max(1)
                                })
                        })
                        .unwrap_or(p.size);
                    (p.addr, width.max(p.size))
                })
                .collect();
            let cs = f.call_specs.entry(call).or_default();
            cs.reads = Some(slots);
            cs.reads_recovered = true;
            if let Some((regs, _)) = eff {
                cs.overwrites = regs;
            }
            continue;
        }
        let Some((regs, reads)) = eff else { continue }; // scan bailed — claim nothing
        if std::env::var_os("MOSURA_EFFECTS_DEBUG").is_some() {
            eprintln!("callee {target:08x} overwrites {regs:?} reads {reads:?}");
        }
        let cs = f.call_specs.entry(call).or_default();
        cs.overwrites = regs;
        cs.reads = Some(reads);
    }

    // EXACTNESS (contract-design Increment 2), computed once every call's contract is
    // known: one of a call's own argument registers (its callee's recovered register
    // parameters) surviving the call — reaching a later plain read, a later call's matching
    // argument, or riding THROUGH intervening calls whose recovered contracts preserve it —
    // proves this TU declared the callee `modify exact` (OW CallZap folds parm.used into
    // the zap otherwise, i86reg.c:263; the 12c58 zero riding one definition through a loop's
    // two calls). Inert without the whole-program prototype pass (`call_reads` empty).
    if !call_reads.is_empty() {
        let call_kills: std::collections::HashMap<crate::decompile::op::OpId, Vec<u64>> = calls
            .iter()
            .filter_map(|&c| {
                f.call_specs.get(&c).and_then(|cs| cs.cdecl_modify.clone()).map(|k| (c, k))
            })
            .collect();
        for &call in &calls {
            let Some(own) = call_reads.get(&call) else { continue };
            let exact = if let (Some(&pos), Some(probe)) = (call_pos.get(&call), cfg_probe.as_ref())
            {
                own.iter().any(|&r| {
                    matches!(r & !3, 0 | 4 | 8 | 0xc)
                        && survives_call(probe, reg, pos, r, &call_reads, &call_kills)
                })
            } else {
                false
            };
            if exact {
                f.call_specs.entry(call).or_default().cdecl_exact = true;
            }
        }
    }
}

/// The function's own `(writes, restores)` over its RECORDED BODY -- the union over every
/// instruction analysis placed in the function, switch arms included, which is exactly what the
/// `modify`/saved lists mean. No flow is followed, so a BRANCHIND cannot end the answer; `None`
/// only when the body is missing or an instruction fails to decode. Register accounting matches
/// `callee_writes_cfg`: POPs are restores, other register writes are writes, sub-register writes
/// normalize to their containing register, stack/frame pointers are the frame rather than
/// clobbers, and a CALL adds what the convention lets a call destroy.
fn own_effects_over_body(
    program: &Program,
    spec: &crate::sleigh::engine::Spec,
    ctx: &[u32],
    entry: crate::decompile::space::Address,
    reg: crate::decompile::space::SpaceId,
    f: &crate::decompile::funcdata::Funcdata,
) -> Option<(Vec<u64>, Vec<u64>)> {
    use crate::decompile::opcode::OpCode;
    use crate::decompile::space::Address;
    let func = program.function_manager.function_at(entry)?;
    let body = func.body();
    if body.is_empty() {
        return None;
    }
    let mut writes: Vec<u64> = Vec::new();
    let mut restored: Vec<u64> = Vec::new();
    let mut budget = 4096usize;
    for r in body.ranges() {
        let mut pc = r.min;
        while pc <= r.max {
            budget = budget.checked_sub(1)?;
            let bytes = program.memory.read_window(Address::new(program.default_space, pc), 16);
            if bytes.is_empty() {
                return None;
            }
            let insn = spec.disassemble_ctx(&bytes, pc, ctx).into_iter().next()?;
            if insn.bytes.is_empty() {
                return None;
            }
            let is_pop = insn.mnemonic.eq_ignore_ascii_case("POP");
        let is_push = insn.mnemonic.eq_ignore_ascii_case("PUSH");
            for o in &insn.ops {
                // A BRANCH out of this function's recorded body to another function's entry
                // is a TAIL CALL (the thunk shape SharedReturn rewrites to call+return): the
                // tail-callee's contract IS this function's, and without it a thunk gets no
                // `modify` list at all — Watcom then assumes the default (preserve
                // everything), must save what the callee kills, and can no longer emit the
                // original's bare `JMP` (FUN_00072357 grew PUSH EBX/ECX + CALL + RET).
                if OpCode::from_u32(o.opcode) == Some(OpCode::Branch) {
                    if let Some(v) = o.ins.first().and_then(|a| a.as_var()) {
                        if v.space != "const"
                            && !body.contains(Address::new(program.default_space, v.offset))
                        {
                            if let Some(w2) =
                                transitive_contract(program, spec, ctx, v.offset, reg, f)
                            {
                                for off in w2 {
                                    if !writes.contains(&off) {
                                        writes.push(off);
                                    }
                                }
                            }
                        }
                    }
                }
                if matches!(OpCode::from_u32(o.opcode), Some(OpCode::Call) | Some(OpCode::Callind)) {
                    // A nested call contributes the convention's kill set — the LANDED
                    // semantics of the function's own `modify` list. (Resolving it with the
                    // nested callee's transitive contract instead can only SHRINK this
                    // list, and a narrower own-contract forces Watcom to SAVE the
                    // difference — a corpus-wide regression risk with no grounding: the
                    // original's own declared contract is as unobservable as its callees'.)
                    for e in f.proto_model.effectlist.iter() {
                        if e.space == reg
                            && e.effect == crate::decompile::fspec::effect::KILLEDBYCALL
                            && !writes.contains(&e.offset)
                        {
                            writes.push(e.offset);
                        }
                    }
                }
                let Some(out) = &o.out else { continue };
                if out.space != "register" {
                    continue;
                }
                let addr = Address::new(reg, out.offset);
                if f.spaces.space_by_spacebase(addr, out.size).is_some() {
                    continue;
                }
                let key = if out.size < 4 { out.offset & !3 } else { out.offset };
                if is_pop {
                    if !restored.contains(&key) {
                        restored.push(key);
                    }
                } else if !writes.contains(&key) {
                    writes.push(key);
                }
            }
            pc += insn.bytes.len() as u64;
        }
    }
    writes.retain(|o| !restored.contains(o));
    Some((writes, restored))
}

/// The callee's stack-cleanup contract, read from its own return instructions over a walk of its
/// reachable body: `Some(n)` when every return agrees it pops `n` argument bytes, `None` when the
/// body cannot be fully walked (indirect flow, budget) or the returns disagree -- an unseen return
/// could contradict the seen ones, so partial coverage answers nothing rather than guessing.
/// Nested calls are tolerated: another function's returns do not change what THIS one's `RET n`
/// says. The p-code reading itself is [`crate::recompile::convention::callee_stack_cleanup`].
fn callee_cleanup(
    program: &Program,
    spec: &crate::sleigh::engine::Spec,
    ctx: &[u32],
    entry: u64,
    sp: u64,
) -> Option<u32> {
    use crate::decompile::opcode::OpCode;
    use crate::decompile::space::Address;
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut frontier: Vec<u64> = vec![entry];
    let mut insns: Vec<crate::sleigh::Instruction> = Vec::new();
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
        for o in &insn.ops {
            match OpCode::from_u32(o.opcode) {
                Some(OpCode::Return) => fallthrough = false,
                Some(OpCode::Branchind) => return None, // unresolvable flow: returns may be unseen
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
        }
        let next = pc + insn.bytes.len() as u64;
        insns.push(insn);
        if fallthrough {
            frontier.push(next);
        }
    }
    crate::recompile::convention::callee_stack_cleanup(&insns, sp)
}

/// Per-caller SURVIVAL testimony on the caller's RAW CFG — the sb99 design's veto,
/// landed: does any path from `start` (the position just after a call) reach a READ of a
/// register overlapping `cand` before an op writes it, before any further call (whose own
/// contract re-opens the question)? A read proves THIS TU was compiled against a
/// declaration in which the register SURVIVES the callee — different callers of one callee
/// were provably built against different declarations (0x5cf88: the 191b8 wrapper family
/// saves EDX around it, the 0x292c7 caller reads EDX straight across it), which is why the
/// contract, like the pragma that carries it, is per-TU. Real blocks make the walk sound
/// where the parked byte-window first cut was not: conditional paths are walked, a jump
/// target's reads only count when reached FROM the call, and noreturn fallthrough into
/// foreign bytes cannot happen — the CFG ends where the function does.
fn survives_call(
    f: &crate::decompile::funcdata::Funcdata,
    reg: crate::decompile::space::SpaceId,
    start: (usize, usize),
    cand: u64,
    // Per-call argument-register reads (each CALL op's callee's recovered read set) — the
    // raw graph carries no argument inputs, so a value flowing INTO a later call's argument
    // register is invisible to the plain operand scan. With the whole-program prototype
    // recovery on, this map makes that flow a READ: reaching a call whose callee reads
    // `cand` (unwritten since `start`) proves survival exactly as a plain read does.
    // Empty map = the baseline behavior.
    call_reads: &std::collections::HashMap<crate::decompile::op::OpId, Vec<u64>>,
    // Per-call RECOVERED kill sets (`CallSpec::cdecl_modify`), for walking through preserving
    // calls; empty map = every call ends the path (the veto-collection behavior).
    call_kills: &std::collections::HashMap<crate::decompile::op::OpId, Vec<u64>>,
) -> bool {
    use crate::decompile::opcode::OpCode;
    let lo = cand & !3;
    let overlaps = |f: &crate::decompile::funcdata::Funcdata, v: crate::decompile::VarnodeId| {
        let vn = f.vn(v);
        vn.loc.space == reg && vn.loc.offset < lo + 4 && vn.loc.offset + vn.size as u64 > lo
    };
    let mut seen = vec![false; f.num_blocks()];
    let mut work: Vec<(usize, usize)> = vec![start];
    while let Some((b, i0)) = work.pop() {
        let blk = &f.blocks()[b];
        let mut open = true; // the path is still asking about the pre-call value
        for &opid in &blk.ops[i0..] {
            let o = f.op(opid);
            for slot in 0..o.num_inputs() {
                if let Some(v) = o.input(slot) {
                    if overlaps(f, v) {
                        return true;
                    }
                }
            }
            if matches!(o.code(), OpCode::Call | OpCode::Callind) {
                if call_reads.get(&opid).is_some_and(|rs| rs.iter().any(|&r| (r & !3) == lo)) {
                    return true;
                }
                // A call whose RECOVERED CONTRACT preserves `cand` is transparent to the
                // walk: the value rides through it (the loop shape — EDX set once, received
                // by every iteration's calls, surviving each via the other's preservation).
                // No contract, or a contract killing `cand`, ends the path conservatively.
                if call_kills
                    .get(&opid)
                    .is_some_and(|ks| !ks.iter().any(|&k| (k & !3) == lo))
                {
                    continue;
                }
                open = false;
                break;
            }
            if o.output.is_some_and(|v| overlaps(f, v)) || o.code() == OpCode::Return {
                open = false;
                break;
            }
        }
        if open {
            for &succ in &blk.out_edges {
                let si = succ.0 as usize;
                if !seen[si] {
                    seen[si] = true;
                    work.push((si, 0));
                }
            }
        }
    }
    false
}

fn transitive_contract(
    program: &Program,
    spec: &crate::sleigh::engine::Spec,
    ctx: &[u32],
    entry: u64,
    reg: crate::decompile::space::SpaceId,
    f: &crate::decompile::funcdata::Funcdata,
) -> Option<Vec<u64>> {
    use crate::analysis::program::CalleeContract;
    {
        let cache = program.contract_cache.lock().unwrap();
        match cache.get(&entry) {
            Some(CalleeContract::Done(v)) => return v.clone(),
            Some(CalleeContract::InProgress) => return None,
            None => {}
        }
    }
    program.contract_cache.lock().unwrap().insert(entry, CalleeContract::InProgress);
    let r = callee_writes_cfg(program, spec, ctx, entry, reg, f, NestedCalls::Transitive)
        .map(|(w, _)| w);
    program.contract_cache.lock().unwrap().insert(entry, CalleeContract::Done(r.clone()));
    r
}

/// The caller-side cleanup at one CALL site: disassemble the call instruction at `pc` (for its
/// length), then its fallthrough instruction; `Some(n)` when the latter is `ESP = ESP + n`
/// ([`crate::recompile::convention::caller_stack_cleanup`]) — the original caller removing the
/// arguments it pushed.
fn caller_cleanup_after(
    program: &Program,
    spec: &crate::sleigh::engine::Spec,
    ctx: &[u32],
    pc: u64,
    sp: u64,
) -> Option<u32> {
    use crate::decompile::space::Address;
    let bytes = program.memory.read_window(Address::new(program.default_space, pc), 16);
    let call = spec.disassemble_ctx(&bytes, pc, ctx).into_iter().next()?;
    if call.bytes.is_empty() {
        return None;
    }
    let next = pc + call.bytes.len() as u64;
    let bytes = program.memory.read_window(Address::new(program.default_space, next), 16);
    let insn = spec.disassemble_ctx(&bytes, next, ctx).into_iter().next()?;
    if insn.bytes.is_empty() {
        return None;
    }
    crate::recompile::convention::caller_stack_cleanup(&insn, sp)
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
/// How [`callee_writes_cfg`] accounts a nested call inside the walked body.
#[derive(Clone, Copy, PartialEq)]
enum NestedCalls {
    /// Withhold the whole answer (the downgrade question: unknown means unusable).
    Fail,
    /// The convention's kill set (the function's own `modify` list: a contained call destroys
    /// whatever the convention lets a call destroy).
    Blanket,
    /// Resolve a DIRECT nested call with the nested callee's own transitive contract
    /// ([`transitive_contract`], memoized whole-program in `Program::contract_cache`);
    /// indirect, cyclic, or failed edges fall back to the blanket.
    Transitive,
}

fn callee_writes_cfg(
    program: &Program,
    spec: &crate::sleigh::engine::Spec,
    ctx: &[u32],
    entry: u64,
    reg: crate::decompile::space::SpaceId,
    f: &crate::decompile::funcdata::Funcdata,
    nested: NestedCalls,
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
        let is_push = insn.mnemonic.eq_ignore_ascii_case("PUSH");
        for o in &insn.ops {
            match OpCode::from_u32(o.opcode) {
                Some(OpCode::Return) => fallthrough = false,
                Some(op @ (OpCode::Call | OpCode::Callind)) => {
                    // For the DOWNGRADE question ("does this callee leave the register alone?") a
                    // nested call is unknown and the whole answer must be withheld. For the
                    // function's OWN `modify` list the answer is known: whatever the convention
                    // lets a call destroy, this function destroys too by containing one. The
                    // TRANSITIVE mode resolves a direct nested call with the NESTED callee's own
                    // contract instead — the knowledge the original compiler's callers visibly
                    // had (FUN_00012360 hoists a zeroed EBX across a call whose transitive body
                    // preserves it; the convention blanket said killed and cost the hoist).
                    let resolved: Option<Vec<u64>> = match nested {
                        NestedCalls::Fail => return None,
                        NestedCalls::Blanket => None,
                        NestedCalls::Transitive => {
                            if op == OpCode::Call {
                                o.ins
                                    .first()
                                    .and_then(|a| a.as_var())
                                    .filter(|v| v.space != "const")
                                    .and_then(|v| {
                                        transitive_contract(program, spec, ctx, v.offset, reg, f)
                                    })
                            } else {
                                None // indirect: unknowable, fall to the blanket
                            }
                        }
                    };
                    if let Some(w) = resolved {
                        for off in w {
                            if !writes.contains(&off) {
                                writes.push(off);
                            }
                        }
                        continue;
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
            // NORMALIZE a sub-register write to the register that CONTAINS it, before anything
            // compares the two lists. `mov ah,..` writes offset 1 and `pop eax` restores offset 0;
            // matching them by raw offset lets a high-byte write survive the saved-and-restored
            // filter below. FUN_00010d70 saves and restores EBX, ECX, EDX and EBP, yet its AH/DH/BH
            // writes came through as offsets 1/9/0xd and were reported as destroying EAX, EDX and
            // EBX — so the emitted `modify` list told Watcom to skip two saves the original makes,
            // and the function compiled 4 bytes short.
            let key = if out.size < 4 { out.offset & !3 } else { out.offset };
            if is_pop {
                if !restored.contains(&key) {
                    restored.push(key);
                }
            } else if !writes.contains(&key) {
                writes.push(key);
            }
        }
        if fallthrough {
            frontier.push(pc + insn.bytes.len() as u64);
        }
    }
    if std::env::var_os("MOSURA_MODIFY").is_some() {
        eprintln!(
            "MODIFY entry={entry:#x} writes={:x?} restored={:x?} nested={}",
            writes,
            restored,
            match nested {
                NestedCalls::Fail => "fail",
                NestedCalls::Blanket => "blanket",
                NestedCalls::Transitive => "transitive",
            }
        );
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
    // Census-only companion: register reads sourced by PUSH insns (prologue saves read their
    // register; without the save/restore pairing they masquerade as arguments).
    let mut push_reads: Vec<u64> = Vec::new();
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
        let is_push = insn.mnemonic.eq_ignore_ascii_case("PUSH");
        seq += 1;
        let mut is_ret = false;
        for o in &insn.ops {
            match OpCode::from_u32(o.opcode) {
                Some(OpCode::Return) => is_ret = true,
                // Anything that leaves the straight line: stop and claim nothing.
                Some(OpCode::Call) | Some(OpCode::Callind) | Some(OpCode::Branch)
                | Some(OpCode::Branchind) | Some(OpCode::Cbranch) => {
                    // SHADOW CENSUS (missing-args thread): reads collected BEFORE the exit
                    // are valid reads-before-write whatever follows — count what the bail
                    // discards.
                    if std::env::var_os("MOSURA_SCAN_SHADOW").is_some() && !reads.is_empty() {
                        let rs: Vec<String> = reads
                            .iter()
                            .filter(|(a, _)| !push_reads.contains(&a.offset))
                            .map(|(a, sz)| format!("{:#x}/{sz}", a.offset))
                            .collect();
                        if !rs.is_empty() {
                            eprintln!("[scanbail] callee {entry:#x} at {:?} prefix-reads [{}]",
                                OpCode::from_u32(o.opcode), rs.join(" "));
                        }
                    }
                    return None;
                }
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
                    if is_push {
                        push_reads.push(v.offset);
                    }
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
