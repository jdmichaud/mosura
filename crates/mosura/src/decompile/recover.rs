//! Return-value recovery — a port of Ghidra's `ActionReturnRecovery` (`coreaction.cc`) +
//! the core of `AncestorRealistic` (`funcdata_varnode.cc`).
//!
//! Every RETURN is given the candidate return-convention registers as inputs (RAX for
//! integers/pointers, XMM0 for floats). After heritage links each to the value reaching
//! that RETURN, [`is_realistic`] decides which candidate actually holds a returned value —
//! i.e. its value traces back to a *real write the function made*, not to the unwritten
//! passthrough register. The non-realistic candidates are removed, so dead-code keeps
//! exactly the return value and the scratch register writes die.
//!
//! `is_realistic` ports `AncestorRealistic`'s essence for the return-register case (where
//! the candidates are never directwrite parameters, so an unwritten input is not realistic);
//! the full action's directwrite/unaffected/kill machinery is for input-parameter trials.

use std::collections::HashSet;

use super::fspec::{trial_flags, ParamActive};
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::space::Address;
use super::varnode::VarnodeId;

const RAX: u64 = 0x0;
const XMM0: u64 = 0x1200;

/// SysV integer argument registers, in order: RDI, RSI, RDX, RCX, R8, R9.
const ARG_REGS: [u64; 6] = [0x38, 0x30, 0x10, 0x8, 0x80, 0x88];

/// Does `vn`'s value trace back to a real write the function made (a "solid" definition),
/// rather than to the unwritten passthrough register? Traverses transparent ops (COPY,
/// SUBPIECE, extensions) and MULTIEQUALs; any solid producer (arithmetic, LOAD, …) or a
/// constant is realistic.
fn is_realistic(f: &Funcdata, vn: VarnodeId, seen: &mut HashSet<VarnodeId>) -> bool {
    let v = f.vn(vn);
    if v.is_constant() {
        return true;
    }
    if !v.is_written() {
        return false; // an unwritten input — the function never set this register
    }
    if !seen.insert(vn) {
        return false; // a cycle contributes no fresh realism
    }
    let def = v.def.unwrap();
    match f.op(def).code() {
        // transparent value movement — keep tracing the source
        OpCode::Copy | OpCode::Subpiece | OpCode::IntZext | OpCode::IntSext => {
            f.op(def).input(0).is_some_and(|i| is_realistic(f, i, seen))
        }
        // a join is realistic if any incoming value is
        OpCode::Multiequal => f.op(def).inrefs.clone().iter().any(|&i| is_realistic(f, i, seen)),
        // a CONCAT — heritage refinement (`refine_overlaps`) splits a free wide read into a `PIECE`
        // of its lanes, so an unwritten passthrough register becomes `PIECE(hi, lo)`. The returned
        // value lives in the least-significant lane (little-endian); the high lane is just fill (a
        // zero-extend or a leftover). Ghidra's `AncestorRealistic::enterNode` (`funcdata_varnode.cc`)
        // descends the offset-0 PIECE through its low piece (slot 1) rather than treating the join as
        // solid, so a `PIECE(0, unwritten)` / `PIECE(unwritten, unwritten)` is NOT a real return
        // (else a void function or a 4-byte return gains a spurious 8-byte one).
        OpCode::Piece => f.op(def).input(1).is_some_and(|i| is_realistic(f, i, seen)),
        // INDIRECT — Ghidra `AncestorRealistic::enterNode` CPUI_INDIRECT (funcdata_varnode.cc:2045).
        // An *indirect creation* models a call clobber: mosura's `recover_call_effects` builds these
        // with an indirect-zero (`#0:8`) input, which Ghidra reports as `pop_failkill` (killedbycall —
        // no value flows out), so the candidate is NOT a real value. But a *passthrough* INDIRECT
        // (the across-call stack-slot guard, `newIndirectOp`) carries a value THROUGH the call:
        // Ghidra enters the node and keeps traversing input(0), the value flowing across — and a
        // return-address storage location is invalid (`pop_fail`).
        OpCode::Indirect => {
            if f.vn(vn).is_indirect_creation() || f.vn(vn).is_return_address() {
                false
            } else {
                f.op(def).input(0).is_some_and(|i| is_realistic(f, i, seen))
            }
        }
        // arithmetic / LOAD / etc. — a real computed value
        _ => true,
    }
}

/// Append the candidate return-convention registers (RAX, XMM0) to every RETURN op, so
/// heritage links them to the value reaching each RETURN. Runs pre-heritage.
pub fn recover_return(f: &mut Funcdata) {
    let Some(reg) = f.spaces.by_name("register") else { return };
    let rets: Vec<OpId> = f.op_ids().filter(|&op| f.op(op).code() == OpCode::Return).collect();
    for ret in rets {
        // RAX/XMM0 at 8 bytes, plus XMM0 at 4 bytes for a `float` return (the low lane of a
        // zeroed XMM0). resolve keeps the first realistic, so the wider candidates win first.
        for (off, size) in [(RAX, 8), (XMM0, 8), (XMM0, 4)] {
            let v = f.new_varnode(size, Address::new(reg, off));
            f.op_append_input(ret, v);
        }
    }
}

/// True when `vn` is an 8-byte value built as `PIECE(constant_high, low)` — a narrow value sitting
/// in a zeroed (or otherwise constant-padded) wide register. The genuine return is the low part, so
/// the wide candidate should defer to the narrower one (Ghidra's output prototype recovers the
/// minimal covering storage — a `float` return is `XMM0:4`, not the zero-extended `XMM0:8`).
fn is_const_padded_piece(f: &Funcdata, vn: VarnodeId) -> bool {
    let Some(def) = f.vn(vn).def else { return false };
    if f.op(def).code() != OpCode::Piece {
        return false;
    }
    f.op(def).input(0).is_some_and(|hi| f.vn(hi).is_constant())
}

/// Maximum number of evaluation passes before the trial decisions are committed structurally — a
/// port of Ghidra's `ParamActive::maxpass` (set from `getMaxInputDelay`, fspec.cc:5335). `0` means
/// the single pass available in today's (non-iterating) pipeline commits immediately, so the
/// recovery stays byte-identical to the old greedy prune; the mainloop flip raises this so the
/// commit DEFERS until heritage + simplification have stabilized across passes.
const RETURN_MAXPASS: i32 = 0;
const CALL_MAXPASS: i32 = 0;

/// Keep only the realistic return-value candidate on each RETURN (preferring RAX over XMM0 when both
/// are realistic, as a function returns one value) — a port of Ghidra's `ActionReturnRecovery`
/// (coreaction.cc:1907). The recovery is two-phase and DEFERRED through a persistent [`ParamActive`]
/// ([`Funcdata::active_output`]): each invocation evaluates the candidate trials
/// ([`check_output_trial_use`]) but the structural rewrite ([`build_return_output`]) only runs once
/// the trials are *fully checked* (`numpasses > maxpass`), so a premature decision on an unstable
/// early-pass graph can't irreversibly drop a real return. Runs post-heritage.
pub fn resolve_return(f: &mut Funcdata) {
    setup_active_output(f);
    check_output_trial_use(f);
    if f.active_output.as_ref().is_some_and(|a| a.is_fully_checked()) {
        build_return_output(f);
        f.active_output = None; // Ghidra `Funcdata::clearActiveOutput`
    }
}

/// Ghidra `Funcdata::initActiveOutput` (coreaction.cc:4651): create the output trial container once,
/// a trial per candidate return slot. All RETURN ops carry the identical candidate layout that
/// [`recover_return`] appended, so the trials (and their `op_slot`s) are gathered from the first.
fn setup_active_output(f: &mut Funcdata) {
    if f.active_output.is_some() {
        return;
    }
    let reg = f.spaces.by_name("register");
    let mut active = ParamActive::new(reg);
    active.set_max_pass(RETURN_MAXPASS);
    if let Some(ret) = f.op_ids().find(|&op| f.op(op).code() == OpCode::Return) {
        let n = f.op(ret).num_inputs();
        for slot in 1..n {
            if let Some(v) = f.op(ret).input(slot) {
                let (loc, size) = (f.vn(v).loc, f.vn(v).size as u32);
                let ti = active.register_trial(loc, size);
                active.trial[ti].op_slot = slot as u32;
            }
        }
    }
    f.active_output = Some(active);
}

/// Ghidra `ActionReturnRecovery::apply` evaluation loop (coreaction.cc:1916): mark every not-yet-
/// checked trial whose candidate is a realistic return value at some RETURN (the `AncestorRealistic`
/// essence, here [`is_realistic`]) as active; an unrealistic candidate is left unchecked so a later
/// pass can reconsider it as the dataflow refines. Then advance the pass counter and, once
/// `numpasses > maxpass`, mark the container fully checked (which gates the commit).
fn check_output_trial_use(f: &mut Funcdata) {
    let rets: Vec<OpId> = f.op_ids().filter(|&op| f.op(op).code() == OpCode::Return).collect();
    let ntrials = f.active_output.as_ref().map_or(0, |a| a.num_trials());
    let mut verdicts: Vec<usize> = Vec::new(); // indices of trials found realistic this pass
    for ti in 0..ntrials {
        let (checked, slot) = {
            let t = &f.active_output.as_ref().unwrap().trial[ti];
            (t.flags & trial_flags::CHECKED != 0, t.op_slot as usize)
        };
        if checked {
            continue;
        }
        let realistic = rets.iter().any(|&ret| {
            f.op(ret)
                .input(slot)
                .is_some_and(|v| is_realistic(f, v, &mut HashSet::new()) && !is_const_padded_piece(f, v))
        });
        if realistic {
            verdicts.push(ti);
        }
    }
    let active = f.active_output.as_mut().unwrap();
    for ti in verdicts {
        active.trial[ti].mark_active();
    }
    active.finish_pass();
    if active.get_num_passes() > active.get_max_pass() {
        active.mark_fully_checked();
    }
}

/// Ghidra `ActionReturnRecovery::buildReturnOutput` (coreaction.cc:1837) reduced to mosura's single-
/// return-value case: keep, on each RETURN, the first realistic non-constant-padded candidate
/// (RAX before XMM0, by slot order) and remove the rest. Gated behind the fully-checked trials, so
/// it commits the prune only once the decision is stable. (The per-RETURN realism check — rather
/// than the shared trial flags — preserves the exact survivors of the old greedy prune.)
fn build_return_output(f: &mut Funcdata) {
    let rets: Vec<OpId> = f.op_ids().filter(|&op| f.op(op).code() == OpCode::Return).collect();
    for ret in rets {
        let n = f.op(ret).num_inputs();
        // slot 0 is the return address; slots 1.. are the candidate return registers. Skip a wide
        // candidate that is just a constant-padded narrow value so the narrow candidate wins.
        let keep = (1..n).find(|&slot| {
            let v = f.op(ret).input(slot).unwrap();
            is_realistic(f, v, &mut HashSet::new()) && !is_const_padded_piece(f, v)
        });
        for slot in (1..n).rev() {
            if Some(slot) != keep {
                f.op_remove_input(ret, slot);
            }
        }
    }
}

/// Append the candidate integer argument registers (RDI…R9) to every CALL op, so heritage
/// links them to the value each holds at the call site. Runs pre-heritage. (Mirrors
/// `recover_return` on the input side — Ghidra's `ActionFuncLink`/`ParamActive` setup.)
pub fn recover_call_args(f: &mut Funcdata) {
    let Some(reg) = f.spaces.by_name("register") else { return };
    let calls: Vec<OpId> =
        f.op_ids().filter(|&op| matches!(f.op(op).code(), OpCode::Call | OpCode::Callind)).collect();
    for call in calls {
        for off in ARG_REGS {
            let v = f.new_varnode(8, Address::new(reg, off));
            f.op_append_input(call, v);
        }
    }
}

/// Model each CALL's effect on the registers and the function's aliased stack locals with INDIRECT
/// ops — a port of Ghidra's `Heritage::guardCalls` (heritage.cc:1443) driven by the calling
/// convention's `EffectRecord` list ([`super::fspec::sysv_effect_list`] / `lookup_effect`,
/// fspec.cc:2472, the `FuncProto::hasEffect` query).
///
/// For each register location appearing in the function, the convention's effect decides the
/// guard, exactly as `guardCalls` branches on `fc->hasEffect(transAddr,size)`:
///   - `killedbycall` (the caller-saved volatile registers `RAX,RCX,RDX,RSI,RDI,R8,R9,XMM0..7`) ⇒
///     an *indirect creation* (`Funcdata::newIndirectCreation`): a value out of nothing, with no
///     realistic ancestor. This is the RAX clobber — a `mov eax,0` set up before a varargs/printf
///     call no longer survives to the RETURN, and a later call's leftover-register "argument" is
///     not mistaken for a parameter.
///   - `unaffected` (callee-saved `RBX,RSP,RBP,R12..R15`) ⇒ no guard; the value flows across.
///   - `unknown_effect` (`R10/R11`, flags) ⇒ left unguarded here (Ghidra's `newIndirectOp` pass-
///     through path for registers is not yet needed by the corpus).
///
/// For the stack it is load-bearing for correctness (this is the `unknown_effect`/flow-through case
/// `guardCalls` handles with `newIndirectOp`): a call with an unknown prototype may modify any stack
/// slot a passed pointer can reach, so without the INDIRECT a call-modified local constant-folds to
/// its pre-call value (collapsing conditions such as switchhide's switch index).
///
/// `alias_boundary` (from [`super::alias::alias_boundary`], computed by a probe heritage) is the
/// shallowest escaped stack offset; the callee can reach every slot at or above it (Ghidra
/// `AliasChecker::hasLocalAlias`: `offset >= aliasBoundary`), so only those are guarded. A
/// non-aliased local (a spilled loop variable touched only by direct load/store) is left untouched,
/// so its loop SSA is undisturbed. `None` ⇒ nothing escapes ⇒ no stack slot is guarded.
/// Runs post-CFG, pre-heritage; the INDIRECTs splice into each call's block after the call.
pub fn recover_call_effects(f: &mut Funcdata, alias_boundary: Option<i64>) {
    let Some(reg) = f.spaces.by_name("register") else { return };
    let stack = f.spaces.by_name("stack");
    let efflist = super::fspec::sysv_effect_list(&f.spaces);

    // The register locations to consider guarding: the distinct offsets that appear in the
    // function's varnodes (Ghidra guards a range only once it is heritaged / in the dataflow).
    let mut reg_offsets: Vec<u64> = Vec::new();
    let mut seen_reg = HashSet::new();
    let mut stack_slots: Vec<(u64, _)> = Vec::new();
    let mut seen_stk = HashSet::new();
    for i in 0..f.num_varnodes() as u32 {
        let vn = f.vn(VarnodeId(i));
        if vn.loc.space == reg && seen_reg.insert(vn.loc.offset) {
            reg_offsets.push(vn.loc.offset);
        }
        if let (Some(stk), Some(boundary)) = (stack, alias_boundary) {
            if vn.loc.space == stk
                && (vn.loc.offset as i64) >= boundary
                && seen_stk.insert((vn.loc.offset, vn.size))
            {
                stack_slots.push((vn.loc.offset, vn.size));
            }
        }
    }
    // Guard the caller-saved (killedbycall) registers — at the convention's full-register width,
    // which `normalize_read_size` reconciles with any narrow sub-register reads (e.g. EAX of RAX).
    let killed: Vec<u64> = reg_offsets
        .into_iter()
        .filter(|&off| {
            super::fspec::lookup_effect(&efflist, Address::new(reg, off), 8)
                == super::fspec::effect::KILLEDBYCALL
        })
        .collect();

    for b in 0..f.num_blocks() as u32 {
        let bid = super::block::BlockId(b);
        let ops = f.block(bid).ops.clone();
        let mut new_ops = Vec::with_capacity(ops.len());
        for op in ops {
            new_ops.push(op);
            if !matches!(f.op(op).code(), OpCode::Call | OpCode::Callind) {
                continue;
            }
            let seq = f.op(op).seqnum;
            for &off in &killed {
                // Ghidra `newIndirectCreation`: input(0) is an indirect-zero constant (no prior
                // value flows in), and the output is a created value with no realistic ancestor.
                let zero = f.new_const(8, 0);
                let ind = f.new_op(OpCode::Indirect, seq, vec![zero]);
                let out = f.new_output(ind, 8, Address::new(reg, off));
                f.vn_mut(out).set_indirect_creation();
                f.op_mut(ind).parent = Some(bid);
                new_ops.push(ind);
            }
            if let Some(stk) = stack {
                for &(off, size) in &stack_slots {
                    let pre = f.new_varnode(size, Address::new(stk, off));
                    let ind = f.new_op(OpCode::Indirect, seq, vec![pre]);
                    let out = f.new_output(ind, size, Address::new(stk, off));
                    // Ghidra `Heritage::guardCalls`: the guarded range here is an aliased *mapped*
                    // stack local (`holdind = (fl & addrtied) != 0` is true for these slots), so the
                    // across-call INDIRECT output is `setAddrForce`d. addrforce makes it auto-live, so
                    // dead-code keeps the INDIRECT chain and — propagating its consume backward — the
                    // write-only spill store that feeds it survives as a real `xStack_NN = …` variable.
                    f.vn_mut(out).set_addr_force();
                    f.op_mut(ind).parent = Some(bid);
                    new_ops.push(ind);
                }
            }
        }
        f.set_block_ops(bid, new_ops);
    }
}

/// Keep the call's real arguments: the contiguous prefix of candidate registers (from RDI) whose
/// value is realistic (set by the caller); the first scratch register ends the argument list. A port
/// of Ghidra's `ActionActiveParam` (coreaction.cc:1725) / `FuncCallSpecs::checkInputTrialUse`
/// (fspec.cc:5585), DEFERRED through a per-CALL persistent [`ParamActive`]
/// ([`Funcdata::active_inputs`]): each invocation evaluates and *frees* (rather than removes)
/// definitely-dead candidate slots ([`check_input_trial_use`]), but the structural prune
/// ([`build_input_from_trials`]) only commits once the trials are fully checked (`numpasses >
/// maxpass`). So an unstable early-pass graph can't irreversibly drop a real argument. Runs
/// post-heritage.
pub fn resolve_call_args(f: &mut Funcdata) {
    let calls: Vec<OpId> =
        f.op_ids().filter(|&op| matches!(f.op(op).code(), OpCode::Call | OpCode::Callind)).collect();
    for call in calls {
        setup_active_input(f, call);
        check_input_trial_use(f, call);
        if f.active_inputs.get(&call).is_some_and(|a| a.is_fully_checked()) {
            build_input_from_trials(f, call);
            f.active_inputs.remove(&call); // Ghidra `FuncCallSpecs::clearActiveInput`
        }
    }
}

/// Ghidra `FuncCallSpecs::initActiveInput` (fspec.cc:5331) + the candidate-trial registration
/// heritage does in `guardCalls` (heritage.cc:1481): create the per-CALL trial container once, a
/// trial per candidate argument slot (the registers [`recover_call_args`] appended).
fn setup_active_input(f: &mut Funcdata, call: OpId) {
    if f.active_inputs.contains_key(&call) {
        return;
    }
    let reg = f.spaces.by_name("register");
    let mut active = ParamActive::new(reg);
    active.is_recover_subcall = true;
    active.set_max_pass(CALL_MAXPASS);
    let n = f.op(call).num_inputs();
    for slot in 1..n {
        if let Some(v) = f.op(call).input(slot) {
            let (loc, size) = (f.vn(v).loc, f.vn(v).size as u32);
            let ti = active.register_trial(loc, size);
            active.trial[ti].op_slot = slot as u32;
        }
    }
    f.active_inputs.insert(call, active);
}

/// Ghidra `FuncCallSpecs::checkInputTrialUse` (fspec.cc:5585): mark each not-yet-checked trial
/// active (its candidate is a realistic, caller-set value — the [`is_realistic`] essence of
/// `AncestorRealistic`) or definitely-not-used. A definitely-not-used candidate has its dataflow
/// *freed* — the input slot is set to a constant 0 (fspec.cc:5650-5651) — rather than removed, so
/// the slot count stays stable across passes; the structural removal is deferred to
/// [`build_input_from_trials`]. Then advance the pass counter and gate fully-checked.
fn check_input_trial_use(f: &mut Funcdata, call: OpId) {
    let ntrials = f.active_inputs.get(&call).map_or(0, |a| a.num_trials());
    // (trial index, op slot, realistic) for every trial unchecked at entry, evaluated on the current
    // (pre-free) dataflow so no trial's verdict depends on another's freeing.
    let mut verdicts: Vec<(usize, usize, bool)> = Vec::new();
    for ti in 0..ntrials {
        let (checked, slot) = {
            let t = &f.active_inputs[&call].trial[ti];
            (t.flags & trial_flags::CHECKED != 0, t.op_slot as usize)
        };
        if checked {
            continue;
        }
        let realistic = f.op(call).input(slot).is_some_and(|v| is_realistic(f, v, &mut HashSet::new()));
        verdicts.push((ti, slot, realistic));
    }
    // Free the dataflow of the definitely-not-used slots (Ghidra opSetInput(op, newConstant(sz,0))).
    for &(_, slot, realistic) in &verdicts {
        if realistic {
            continue;
        }
        if let Some(v) = f.op(call).input(slot) {
            if !f.vn(v).is_constant() {
                let size = f.vn(v).size as u32;
                let zero = f.new_const(size, 0);
                f.op_set_input(call, slot, zero);
            }
        }
    }
    let active = f.active_inputs.get_mut(&call).unwrap();
    for (ti, _, realistic) in verdicts {
        if realistic {
            active.trial[ti].mark_active();
        } else {
            active.trial[ti].mark_no_use();
        }
    }
    active.finish_pass();
    if active.get_num_passes() > active.get_max_pass() {
        active.mark_fully_checked();
    }
}

/// Ghidra `FuncCallSpecs::buildInputFromTrials` (fspec.cc:5685) reduced to mosura's case: keep the
/// leading run of active trials (the realistic prefix from the first argument register) and remove
/// the rest. Walking trials in `op_slot` order, the first inactive trial ends the argument list —
/// Ghidra's `forceInactiveChain`/`forceNoUse` "no holes after a gap" rule for this convention. Gated
/// behind fully-checked trials so the prune commits only once the decision is stable.
fn build_input_from_trials(f: &mut Funcdata, call: OpId) {
    let mut trials: Vec<(usize, bool)> =
        f.active_inputs[&call].trial.iter().map(|t| (t.op_slot as usize, t.is_active())).collect();
    trials.sort_by_key(|&(slot, _)| slot);
    let mut keep_max = 0usize; // op slots 1..=keep_max are arguments
    for &(slot, is_active) in &trials {
        if is_active && slot == keep_max + 1 {
            keep_max = slot;
        } else {
            break;
        }
    }
    let n = f.op(call).num_inputs();
    for slot in (1..n).rev() {
        if slot > keep_max {
            f.op_remove_input(call, slot);
        }
    }
}

/// SysV output (return) registers, in priority order: RAX (integer/pointer) then XMM0 (float).
const OUT_REGS: [u64; 2] = [RAX, XMM0];

/// Recover each call's return value — a port of Ghidra's `ActionActiveReturn` /
/// `FuncCallSpecs::checkOutputTrialUse` + `buildOutputFromTrials` (fspec.cc:5661/5770). After
/// [`recover_call_effects`] models a call's `killedbycall` output registers as indirect-creations
/// and dead-code removes the unused ones, an output register (RAX, else XMM0) whose creation
/// *survived* (its value is read) is, by Ghidra's `checkOutputTrialUse`, the call's active return
/// value: its INDIRECT-creation output is moved to be the CALL's own output (`opSetOutput`) and the
/// INDIRECT is destroyed. So `RAX = INDIRECT()` (rendered `extraout_RAX`) becomes `RAX = CALL(...)`
/// — `xVar = func(...)`. Runs post-dead-code (so only *used* creations remain), pre-type-inference.
pub fn resolve_call_output(f: &mut Funcdata) {
    let Some(reg) = f.spaces.by_name("register") else { return };
    let calls: Vec<OpId> =
        f.op_ids().filter(|&op| matches!(f.op(op).code(), OpCode::Call | OpCode::Callind)).collect();
    for call in calls {
        if f.op(call).output.is_some() {
            continue; // already has a recovered output
        }
        let Some(bid) = f.op(call).parent else { continue };
        let block_ops = f.block(bid).ops.clone();
        let Some(pos) = block_ops.iter().position(|&o| o == call) else { continue };
        // The clobber INDIRECTs sit in a contiguous run right after the call; gather the surviving
        // indirect-creation outputs (the unused ones were already removed by dead-code).
        let mut creations: Vec<(OpId, VarnodeId)> = Vec::new();
        for &op in &block_ops[pos + 1..] {
            if f.op(op).code() != OpCode::Indirect {
                break;
            }
            if let Some(out) = f.op(op).output {
                if f.vn(out).is_indirect_creation() && !f.vn(out).descend.is_empty() {
                    creations.push((op, out));
                }
            }
        }
        // The single active output is the first present output register (RAX, then XMM0): a
        // function returns one value (Ghidra's output `ParamList::fillinMap` picks the one entry).
        let chosen = OUT_REGS.iter().find_map(|&off| {
            creations.iter().copied().find(|&(_, v)| {
                let l = f.vn(v).loc;
                l.space == reg && l.offset == off
            })
        });
        if let Some((indop, outvn)) = chosen {
            f.op_set_output(call, outvn); // move the trial varnode to be the CALL's output
            f.op_destroy(indop); // destroy the now-empty INDIRECT
            let kept: Vec<OpId> = f.block(bid).ops.iter().copied().filter(|&o| o != indop).collect();
            f.set_block_ops(bid, kept);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::{BlockBasic, Funcdata, OpCode, SeqNum};

    /// A RETURN with candidate inputs `[retaddr, RAX, XMM0]` where each named register is
    /// either a real write (an INT_ADD output) or the unwritten function input.
    fn ret_with(rax_written: bool, xmm0_written: bool) -> (Funcdata, OpId) {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let mk = |f: &mut Funcdata, off: u64, written: bool| -> VarnodeId {
            if written {
                let a = f.new_input(8, Address::new(reg, 0x38));
                let c = f.new_const(8, 1);
                let op = f.new_op(OpCode::IntAdd, seq, vec![a, c]);
                f.new_output(op, 8, Address::new(reg, off))
            } else {
                f.new_input(8, Address::new(reg, off))
            }
        };
        let rax = mk(&mut f, RAX, rax_written);
        let xmm0 = mk(&mut f, XMM0, xmm0_written);
        let retaddr = f.new_input(8, Address::new(reg, 0x20));
        let ret = f.new_op(OpCode::Return, seq, vec![retaddr, rax, xmm0]);
        f.set_blocks(vec![BlockBasic { ops: vec![ret], ..Default::default() }]);
        (f, ret)
    }

    fn kept_offset(f: &Funcdata, ret: OpId, reg_off: u64) -> bool {
        f.op(ret).num_inputs() == 2 && {
            let v = f.op(ret).input(1).unwrap();
            f.vn(v).loc.offset == reg_off
        }
    }

    #[test]
    fn integer_return_keeps_rax() {
        let (mut f, ret) = ret_with(true, false);
        resolve_return(&mut f);
        assert!(kept_offset(&f, ret, RAX), "RAX (written) is the return value");
    }

    #[test]
    fn float_return_keeps_xmm0() {
        let (mut f, ret) = ret_with(false, true);
        resolve_return(&mut f);
        assert!(kept_offset(&f, ret, XMM0), "XMM0 (written) is the return value, not the unwritten RAX");
    }

    #[test]
    fn void_return_keeps_nothing() {
        let (mut f, ret) = ret_with(false, false);
        resolve_return(&mut f);
        assert_eq!(f.op(ret).num_inputs(), 1, "neither register written ⇒ void");
    }

    #[test]
    fn both_written_prefers_rax() {
        let (mut f, ret) = ret_with(true, true);
        resolve_return(&mut f);
        assert!(kept_offset(&f, ret, RAX), "a function returns one value; prefer RAX");
    }

    /// A CALL with candidate inputs `[target, RDI, RSI, RDX, RCX, R8, R9]` where the first
    /// `written` (in SysV order) are real computed writes and the rest are scratch registers.
    fn call_with(written: usize) -> (Funcdata, OpId) {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let target = f.new_const(8, 0x400430);
        let mut inputs = vec![target];
        for (i, &off) in ARG_REGS.iter().enumerate() {
            let v = if i < written {
                let c = f.new_const(8, 0x10 + i as u64);
                let op = f.new_op(OpCode::Copy, seq, vec![c]);
                f.new_output(op, 8, Address::new(reg, off))
            } else {
                f.new_input(8, Address::new(reg, off))
            };
            inputs.push(v);
        }
        let call = f.new_op(OpCode::Call, seq, inputs);
        f.set_blocks(vec![BlockBasic { ops: vec![call], ..Default::default() }]);
        (f, call)
    }

    #[test]
    fn call_keeps_contiguous_written_args() {
        let (mut f, call) = call_with(2); // RDI, RSI written; RDX.. scratch
        resolve_call_args(&mut f);
        assert_eq!(f.op(call).num_inputs(), 3, "[target, RDI, RSI] — two arguments");
    }

    #[test]
    fn call_with_no_set_registers_has_no_args() {
        let (mut f, call) = call_with(0);
        resolve_call_args(&mut f);
        assert_eq!(f.op(call).num_inputs(), 1, "only the call target remains");
    }

    /// A CALL `[target, RDI, RSI]` where RDI is a realistic write and RSI flows through an INDIRECT.
    /// `creation` selects whether that INDIRECT is an indirect *creation* (a killedbycall clobber) or
    /// a *passthrough* (the across-call stack-slot guard, `newIndirectOp`).
    fn call_arg_through_indirect(creation: bool) -> (Funcdata, OpId) {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let target = f.new_const(8, 0x400430);
        // RDI: a realistic computed write, so the argument prefix starts active.
        let c0 = f.new_const(8, 0x10);
        let cp0 = f.new_op(OpCode::Copy, seq, vec![c0]);
        let rdi = f.new_output(cp0, 8, Address::new(reg, ARG_REGS[0]));
        // RSI: a value reaching the call through an INDIRECT. For a passthrough, input(0) is the real
        // value flowing across the call; for a creation, the indirect-zero `#0` placeholder.
        let ind_in = if creation { f.new_const(8, 0) } else { f.new_const(8, 0x99) };
        let ind = f.new_op(OpCode::Indirect, seq, vec![ind_in]);
        let rsi = f.new_output(ind, 8, Address::new(reg, ARG_REGS[1]));
        if creation {
            f.vn_mut(rsi).set_indirect_creation();
        }
        let call = f.new_op(OpCode::Call, seq, vec![target, rdi, rsi]);
        f.set_blocks(vec![BlockBasic { ops: vec![cp0, ind, call], ..Default::default() }]);
        for &op in &[cp0, ind, call] {
            f.op_mut(op).parent = Some(crate::decompile::BlockId(0));
        }
        (f, call)
    }

    /// Ghidra `AncestorRealistic::enterNode` CPUI_INDIRECT (funcdata_varnode.cc:2052): flow THROUGH a
    /// call (a passthrough INDIRECT — the across-call stack-slot guard) is entered and its input(0)
    /// traversed, so a call argument reaching the call through one is a real argument. This is
    /// loopcomment's dropped 2nd arg: the value loaded from an aliased stack local, guarded across an
    /// earlier call by a passthrough INDIRECT. Fails if INDIRECT is treated as wholesale unrealistic.
    #[test]
    fn arg_through_passthrough_indirect_is_realistic() {
        let (mut f, call) = call_arg_through_indirect(false);
        resolve_call_args(&mut f);
        assert_eq!(f.op(call).num_inputs(), 3, "[target, RDI, RSI] — RSI flows through a passthrough INDIRECT");
    }

    /// The complementary case: an indirect *creation* (killedbycall clobber, indirect-zero input) is
    /// a value out of nothing — Ghidra's `pop_failkill` — so the candidate is dropped (no holes after
    /// the realistic prefix). Guards the creation branch the passthrough fix must not disturb.
    #[test]
    fn arg_through_indirect_creation_is_dropped() {
        let (mut f, call) = call_arg_through_indirect(true);
        resolve_call_args(&mut f);
        assert_eq!(f.op(call).num_inputs(), 2, "[target, RDI] — the RSI clobber is not a real argument");
    }

    /// A CALL followed by an RAX indirect-creation clobber; `used` decides whether the clobber's
    /// value is read (so the creation survived dead-code) — modeling the post-dead-code state
    /// `resolve_call_output` consumes.
    fn call_then_rax_creation(used: bool) -> (Funcdata, OpId, OpId) {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let target = f.new_const(8, 0x400430);
        let call = f.new_op(OpCode::Call, seq, vec![target]);
        let zero = f.new_const(8, 0);
        let ind = f.new_op(OpCode::Indirect, seq, vec![zero]);
        let out = f.new_output(ind, 8, Address::new(reg, RAX));
        f.vn_mut(out).set_indirect_creation();
        let mut ops = vec![call, ind];
        if used {
            // a consumer of the call's RAX result (an INT_ADD reading it)
            let c = f.new_const(8, 1);
            let add = f.new_op(OpCode::IntAdd, seq, vec![out, c]);
            f.new_output(add, 8, Address::new(reg, RAX));
            ops.push(add);
        }
        f.set_blocks(vec![BlockBasic { ops, ..Default::default() }]);
        for &op in &[call, ind] {
            f.op_mut(op).parent = Some(crate::decompile::BlockId(0));
        }
        (f, call, ind)
    }

    #[test]
    fn used_rax_creation_becomes_call_output() {
        let (mut f, call, ind) = call_then_rax_creation(true);
        resolve_call_output(&mut f);
        // the call now produces RAX; the INDIRECT was destroyed
        let out = f.op(call).output.expect("call has a recovered output");
        assert_eq!(f.vn(out).loc.offset, RAX);
        assert!(f.op(ind).is_dead(), "the promoted INDIRECT is destroyed");
    }

    #[test]
    fn unused_rax_creation_is_not_promoted() {
        let (mut f, call, _ind) = call_then_rax_creation(false);
        resolve_call_output(&mut f);
        assert!(f.op(call).output.is_none(), "an unused clobber is not a return value");
    }

    /// Pre-seed a trial container over an op's candidate slots (1..) with a raised `maxpass`, to
    /// emulate the mainloop-flip configuration where the structural commit is deferred.
    fn seed_active(f: &mut Funcdata, op: OpId, maxpass: i32) -> ParamActive {
        let reg = f.spaces.by_name("register");
        let mut active = ParamActive::new(reg);
        active.set_max_pass(maxpass);
        let n = f.op(op).num_inputs();
        for slot in 1..n {
            let v = f.op(op).input(slot).unwrap();
            let (loc, size) = (f.vn(v).loc, f.vn(v).size as u32);
            let ti = active.register_trial(loc, size);
            active.trial[ti].op_slot = slot as u32;
        }
        active
    }

    #[test]
    fn return_recovery_defers_until_fully_checked() {
        // With maxpass raised (the flip configuration), one resolve pass evaluates the trials but
        // keeps every candidate — the structural commit lands only once numpasses > maxpass.
        let (mut f, ret) = ret_with(true, false); // RAX written (realistic), XMM0 not
        f.active_output = Some(seed_active(&mut f, ret, 1));

        resolve_return(&mut f); // pass 1: numpasses 0->1, not > 1 ⇒ no commit
        assert_eq!(f.op(ret).num_inputs(), 3, "deferred: all candidates retained after one pass");
        assert!(f.active_output.is_some(), "trials persist until fully checked");

        resolve_return(&mut f); // pass 2: numpasses 1->2, > 1 ⇒ commit
        assert!(kept_offset(&f, ret, RAX), "committed: RAX kept once the deferral resolves");
        assert!(f.active_output.is_none(), "active_output cleared on commit (clearActiveOutput)");
    }

    #[test]
    fn call_arg_recovery_defers_until_fully_checked() {
        // The per-CALL trials defer identically: the prune commits only after the trials are fully
        // checked, so an unstable early pass can't irreversibly drop a real argument.
        let (mut f, call) = call_with(2); // RDI, RSI written; RDX.. scratch
        let active = seed_active(&mut f, call, 1);
        f.active_inputs.insert(call, active);

        resolve_call_args(&mut f); // pass 1: dead slots freed to const 0, but none removed
        assert_eq!(f.op(call).num_inputs(), 7, "deferred: all candidate slots retained after one pass");
        assert!(f.active_inputs.contains_key(&call), "per-call trials persist until fully checked");

        resolve_call_args(&mut f); // pass 2: fully checked ⇒ commit the prune
        assert_eq!(f.op(call).num_inputs(), 3, "committed: [target, RDI, RSI] once the deferral resolves");
        assert!(!f.active_inputs.contains_key(&call), "active_inputs entry cleared on commit");
    }
}
