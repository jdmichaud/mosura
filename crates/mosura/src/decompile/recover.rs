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
//!
//! Realism is only the first of Ghidra's two return-trial gates (`ActionReturnRecovery::apply`,
//! coreaction.cc:1930-1931): a candidate is a genuine return value only if it is ALSO used *only* to
//! feed the RETURN — [`ancestor_op_use`] (a port of `Funcdata::ancestorOpUse`). A value that is
//! realistic but consumed elsewhere (e.g. array-address arithmetic left in RAX that is really a
//! STORE address) is not returned; without this gate such leftovers become a spurious return.

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
        // An *indirect creation* models a call clobber: heritage's `guard_calls` builds these
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

/// Realism for a value reached while walking BACK from a *call argument* trial — a port of Ghidra
/// `AncestorRealistic::enterNode` (funcdata_varnode.cc:2033) for the register-input case. It differs
/// from [`is_realistic`] in exactly one place: the unwritten-input base case. `is_realistic` is the
/// return-register port, where the trial *is* the candidate register and an unwritten input is never a
/// real return (Ghidra `AncestorRealistic::execute` funcdata_varnode.cc:2211 early-returns false when
/// `op->getIn(slot)->isInput()`). But an input reached *through* a copy/subpiece/piece/zext chain is a
/// value flowing from the caller — Ghidra's `enterNode` returns `pop_success` for it (a "normal
/// parameter, not active movement, but valid"). So here an unwritten input is REALISTIC unless it is a
/// return-address storage location (Ghidra's `pop_fail`). (The `isUnaffected`/`!isDirectWrite`
/// sub-cases that Ghidra also fails are inert for SysV call-input trials: the candidates are the
/// argument registers, never callee-saved/unaffected storage — and mosura carries no such flag on the
/// raw-decompile path.) The top-level "trial itself is the input" case is handled by the caller
/// ([`check_input_trial_use`]), mirroring the `execute` early-return.
fn realistic_faithful(f: &Funcdata, vn: VarnodeId, seen: &mut HashSet<VarnodeId>) -> bool {
    let v = f.vn(vn);
    if v.is_constant() {
        return true;
    }
    if !v.is_written() {
        return !v.is_return_address(); // a traversed-to input: pop_success unless a return address
    }
    if !seen.insert(vn) {
        return false;
    }
    let def = v.def.unwrap();
    match f.op(def).code() {
        OpCode::Copy | OpCode::Subpiece | OpCode::IntZext | OpCode::IntSext => {
            f.op(def).input(0).is_some_and(|i| realistic_faithful(f, i, seen))
        }
        OpCode::Multiequal => {
            f.op(def).inrefs.clone().iter().any(|&i| realistic_faithful(f, i, seen))
        }
        OpCode::Piece => f.op(def).input(1).is_some_and(|i| realistic_faithful(f, i, seen)),
        OpCode::Indirect => {
            if f.vn(vn).is_indirect_creation() || f.vn(vn).is_return_address() {
                false
            } else {
                f.op(def).input(0).is_some_and(|i| realistic_faithful(f, i, seen))
            }
        }
        _ => true,
    }
}

/// Ghidra `trim_recurse_max` (architecture.cc:1419): how many ancestor-copy levels
/// [`ancestor_op_use`] recurses through before giving up.
const TRIM_RECURSE_MAX: i32 = 5;

/// Ghidra `TraverseNode` flags (expression.hh:62) — path-annotation bits threaded through the
/// forward walk of [`only_op_use`] so that, at a fork, [`is_alternate_path_valid`] can judge which
/// path is the more plausible parameter/return flow.
mod traverse {
    pub const ACTIONALT: u32 = 1; // alternate path crossed a solid action / non-incidental COPY
    pub const INDIRECT: u32 = 2; // main path crossed an INDIRECT
    pub const INDIRECTALT: u32 = 4; // alternate path crossed an INDIRECT
    pub const LSB_TRUNCATED: u32 = 8; // low byte(s) of the original value were truncated
    pub const CONCAT_HIGH: u32 = 0x10; // value was concatenated as the most-significant portion
}

/// Ghidra `TraverseNode::isAlternatePathValid` (expression.cc:28): at a Varnode where two paths to a
/// CALL/RETURN diverge, is the alternate path the more likely parameter/return flow? mosura marks no
/// COPY incidental, so the incidental-COPY skip loop (which only advances through COPYs Ghidra
/// explicitly flagged incidental) is a no-op here and is elided.
fn is_alternate_path_valid(f: &Funcdata, vn: VarnodeId, flags: u32) -> bool {
    use traverse::{ACTIONALT, INDIRECT, INDIRECTALT};
    if flags & (INDIRECT | INDIRECTALT) == INDIRECT {
        return true; // main path crossed an INDIRECT, alternate did not
    }
    if flags & (INDIRECT | INDIRECTALT) == INDIRECTALT {
        return false; // alternate crossed an INDIRECT, main did not
    }
    if flags & ACTIONALT != 0 {
        return true; // alternate crossed a dedicated COPY
    }
    if f.vn(vn).descend.len() != 1 {
        return false; // `loneDescend() == 0` (zero or several descendants)
    }
    let Some(op) = f.vn(vn).def else { return true };
    !f.op(op).is_marker() // a MULTIEQUAL / INDIRECT def indicates multiple values
}

/// Ghidra `Funcdata::checkCallDoubleUse` (funcdata_varnode.cc:1756): the trial value also flows into
/// a SECOND call `op` (besides `opmatch`) at some slot; is that a legitimate double-use (so it does
/// not disqualify the trial)? For RETURN recovery (`opmatch` a RETURN) the same-callee block is
/// skipped (opcodes differ) and only the input-active branch runs — and mosura's per-call
/// `active_inputs` is empty at `resolve_return` time, so this returns `false` there (the call counts
/// as a real use), matching Ghidra when the callee's inputs are not yet active. The same-callee
/// ordering uses block position for `getSeqNum().getOrder()` (mosura has no global op order).
fn check_call_double_use(
    f: &Funcdata,
    opmatch: OpId,
    op: OpId,
    vn: VarnodeId,
    fl: u32,
    trial_addr: Address,
) -> bool {
    let Some(j) = f.op(op).inrefs.iter().position(|&x| x == vn) else { return false };
    if j == 0 {
        return false; // flow traces to the (indirect) call target, definitely not a param
    }
    if f.op(op).code() == f.op(opmatch).code() {
        // Same callee? Direct call → same entry (target-constant value); indirect → same target vn.
        let same_fn = match (f.op(op).input(0), f.op(opmatch).input(0)) {
            (Some(a), Some(b)) => {
                if f.op(opmatch).code() == OpCode::Call {
                    f.vn(a).is_constant() && f.vn(b).is_constant() && f.vn(a).loc == f.vn(b).loc
                } else {
                    a == b
                }
            }
            _ => false,
        };
        if same_fn {
            if let Some(ct) = f.active_inputs.get(&op).and_then(|a| trial_for_slot(a, j)) {
                if ct.addr == trial_addr {
                    if f.op(op).parent == f.op(opmatch).parent {
                        if block_pos(f, opmatch) < block_pos(f, op) {
                            return true; // opmatch has dibs
                        }
                    } else {
                        return true; // same callee, different blocks — assume legit double-use
                    }
                }
            }
        }
    }
    if let Some(active) = f.active_inputs.get(&op) {
        if let Some(ct) = trial_for_slot(active, j) {
            if ct.flags & trial_flags::CHECKED != 0 {
                if ct.flags & trial_flags::ACTIVE != 0 {
                    return false;
                }
            } else if is_alternate_path_valid(f, vn, fl) {
                return false;
            }
            return true;
        }
    }
    false
}

/// Ghidra `ParamActive::getTrialForInputVarnode` (fspec.cc): the trial at op-input slot `j`.
fn trial_for_slot(active: &ParamActive, j: usize) -> Option<&super::fspec::ParamTrial> {
    active.trial.iter().find(|t| t.op_slot as usize == j)
}

/// The op's position within its parent block — a stand-in for `PcodeOp::getSeqNum().getOrder()` in
/// the same-block ordering test of [`check_call_double_use`] (mosura has no global op order).
fn block_pos(f: &Funcdata, op: OpId) -> usize {
    f.op(op)
        .parent
        .and_then(|b| f.block(b).ops.iter().position(|&o| o == op))
        .unwrap_or(usize::MAX)
}

/// Is `vn` used by return op `op` as a return-VALUE input (slot ≥ 1)? Ghidra's `onlyOpUse` checks
/// only the single trial slot (`op->getIn(trial.getSlot())==vn`), because its return carries one
/// output trial per storage. mosura's [`recover_return`] instead appends several OVERLAPPING fixed
/// candidates (RAX:8, XMM0:8, XMM0:4) as sibling input slots, so one reaching value legitimately
/// feeds more than one of them (a `float`/`double` return reaches both XMM0:8 and XMM0:4). All those
/// slots are the SAME return's output recovery — not an external use — so any of them counts as the
/// return use. (`opslot` is retained for signature symmetry with the CALL-input reuse.)
fn is_return_value_use(f: &Funcdata, op: OpId, opslot: usize, vn: VarnodeId) -> bool {
    let _ = opslot;
    f.op(op).inrefs.iter().skip(1).any(|&x| x == vn)
}

/// Ghidra `Funcdata::onlyOpUse` (funcdata_varnode.cc:1805): forward-walk the value of `invn`; return
/// `true` iff it is only used to feed `opmatch` at `opslot` (transforming ops are traversed), `false`
/// once it reaches a real use — a STORE/LOAD/BRANCH, a CALL that isn't a legitimate double-use, a
/// persistent output, or another RETURN. `active_output` is whether return recovery is in progress
/// (Ghidra's `data.activeoutput != 0`). `trial_addr` is the candidate's storage address, for the
/// double-use same-memory test.
fn only_op_use(
    f: &Funcdata,
    invn: VarnodeId,
    opmatch: OpId,
    opslot: usize,
    trial_addr: Address,
    main_flags: u32,
    active_output: bool,
) -> bool {
    use traverse::{ACTIONALT, CONCAT_HIGH, INDIRECTALT, LSB_TRUNCATED};
    let mut varlist: Vec<(VarnodeId, u32)> = vec![(invn, main_flags)];
    let mut marked: HashSet<VarnodeId> = HashSet::new();
    marked.insert(invn);
    let mut res = true;
    let mut i = 0;
    'outer: while i < varlist.len() {
        let (vn, base_flags) = varlist[i];
        i += 1;
        for op in f.vn(vn).descend.clone() {
            if op == opmatch && is_return_value_use(f, op, opslot, vn) {
                continue; // the parameter/return use we are evaluating
            }
            let mut cur_flags = base_flags;
            match f.op(op).code() {
                // these ops define a real USE of a variable
                OpCode::Branch | OpCode::Cbranch | OpCode::Branchind | OpCode::Load
                | OpCode::Store => {
                    res = false;
                }
                OpCode::Call | OpCode::Callind => {
                    if check_call_double_use(f, opmatch, op, vn, cur_flags, trial_addr) {
                        continue;
                    }
                    res = false;
                }
                OpCode::Indirect => cur_flags |= INDIRECTALT,
                OpCode::Copy => {
                    // a non-internal COPY is a dedicated action on the alternate path (mosura marks
                    // no COPY incidental, so only the output-space test remains).
                    if let Some(out) = f.op(op).output {
                        if f.spaces.get(f.vn(out).loc.space).kind != super::space::SpaceKind::Internal
                        {
                            cur_flags |= ACTIONALT;
                        }
                    }
                }
                OpCode::Return => {
                    if f.op(opmatch).code() == OpCode::Return {
                        if is_return_value_use(f, op, opslot, vn) {
                            continue; // a return-value-slot use in a (possibly different) RETURN
                        }
                    } else if active_output && f.op(op).input(0) != Some(vn) {
                        if !is_alternate_path_valid(f, vn, cur_flags) {
                            continue; // don't consider this a "use"
                        }
                    }
                    res = false;
                }
                OpCode::Multiequal | OpCode::IntSext | OpCode::IntZext | OpCode::Cast => {} // transparent
                OpCode::Piece => {
                    if f.op(op).input(0) == Some(vn) {
                        // concatenated as most-significant piece
                        if cur_flags & LSB_TRUNCATED != 0 {
                            continue; // original lsb truncated + replaced — no longer a use
                        }
                        cur_flags |= CONCAT_HIGH;
                    }
                }
                OpCode::Subpiece => {
                    if let Some(c) = f.op(op).input(1) {
                        if f.vn(c).is_constant() && f.vn(c).loc.offset != 0 && cur_flags & CONCAT_HIGH == 0 {
                            cur_flags |= LSB_TRUNCATED; // low byte(s) thrown away
                        }
                    }
                }
                _ => cur_flags |= ACTIONALT,
            }
            if !res {
                break 'outer;
            }
            if let Some(subvn) = f.op(op).output {
                if f.vn(subvn).is_persist() {
                    res = false;
                    break 'outer;
                }
                if marked.insert(subvn) {
                    varlist.push((subvn, cur_flags));
                }
            }
        }
    }
    res
}

/// Ghidra `Funcdata::ancestorOpUse` (funcdata_varnode.cc:1917): is the trial Varnode likely used only
/// to feed `opmatch` (at `opslot`)? Walks back through ancestor copies/joins, then runs
/// [`only_op_use`] at each top ancestor. `offset` is the byte offset within the current Varnode of
/// the value ultimately reaching the trial. This is the USE half of Ghidra's return-trial gate —
/// paired with the realism half ([`is_realistic`]) exactly as `ActionReturnRecovery::apply`
/// (coreaction.cc:1930-1931) pairs `AncestorRealistic::execute` with `ancestorOpUse`.
#[allow(clippy::too_many_arguments)]
fn ancestor_op_use(
    f: &Funcdata,
    maxlevel: i32,
    invn: VarnodeId,
    opmatch: OpId,
    opslot: usize,
    offset: i64,
    main_flags: u32,
    trial_addr: Address,
    active_output: bool,
    mmark: &mut HashSet<OpId>,
) -> bool {
    if maxlevel == 0 {
        return false;
    }
    let v = f.vn(invn);
    if !v.is_written() {
        // Ghidra accepts an unwritten input only if it is typelocked; mosura has no typelocked
        // varnodes on the raw-decompile path, so a non-typelocked unwritten input is rejected. (In
        // the combined gate this never changes a kept trial: `is_realistic` already rejects unwritten
        // inputs.)
        return false;
    }
    let def = v.def.unwrap();
    let rec = |i, off, flags, mmark: &mut HashSet<OpId>| {
        ancestor_op_use(f, maxlevel - 1, i, opmatch, opslot, off, flags, trial_addr, active_output, mmark)
    };
    match f.op(def).code() {
        OpCode::Indirect => {
            // an indirect creation is an output-trial marker, never an "only use"
            if f.vn(invn).is_indirect_creation() {
                return false;
            }
            f.op(def).input(0).is_some_and(|i| rec(i, offset, main_flags | traverse::INDIRECT, mmark))
        }
        OpCode::Multiequal => {
            if !mmark.insert(def) {
                return false; // trim the loop
            }
            let inrefs = f.op(def).inrefs.clone();
            let mut r = false;
            for iv in inrefs {
                if rec(iv, offset, main_flags, mmark) {
                    r = true;
                    break;
                }
            }
            mmark.remove(&def);
            r
        }
        OpCode::Copy => {
            let in0 = f.op(def).input(0);
            // Ghidra recurses only for an internal-space (or incidental) COPY; mosura has no
            // incidental flag, so only the internal-space case recurses. Otherwise this is a top
            // ancestor.
            let internal = in0
                .is_some_and(|i| f.spaces.get(f.vn(i).loc.space).kind == super::space::SpaceKind::Internal);
            if internal {
                return rec(in0.unwrap(), offset, main_flags, mmark);
            }
            only_op_use(f, invn, opmatch, opslot, trial_addr, main_flags, active_output)
        }
        OpCode::Piece => {
            // concatenation is artificial — recurse into the piece matching `offset`
            let hi = f.op(def).input(0);
            let lo = f.op(def).input(1);
            if offset == 0 {
                return lo.is_some_and(|l| rec(l, 0, main_flags, mmark)); // least-significant piece
            }
            let lo_size = lo.map_or(0, |l| f.vn(l).size as i64);
            if offset == lo_size {
                return hi.is_some_and(|h| rec(h, 0, main_flags, mmark)); // most-significant piece
            }
            false
        }
        OpCode::Subpiece => {
            let in0 = f.op(def).input(0);
            let new_off = f.op(def).input(1).map_or(0, |c| f.vn(c).loc.offset) as i64;
            // (Ghidra's `setRemFormed` side-effect for a `SUBPIECE(REM/SREM,0)` is omitted — inert:
            // mosura's output recovery doesn't model `deriveOutputMap`'s remainder-in-high-register
            // kludge, and the traversal verdict is unaffected by the flag.)
            let internal = f.spaces.get(v.loc.space).kind == super::space::SpaceKind::Internal;
            let overlap = in0.map_or(-1, |i| overlap_bytes(f, invn, i));
            if internal || overlap == new_off {
                return in0.is_some_and(|i| rec(i, offset + new_off, main_flags, mmark));
            }
            only_op_use(f, invn, opmatch, opslot, trial_addr, main_flags, active_output)
        }
        OpCode::Call | OpCode::Callind => false, // a call is never a good single-op-use indication
        _ => only_op_use(f, invn, opmatch, opslot, trial_addr, main_flags, active_output),
    }
}

/// Ghidra `Varnode::overlap` for the contained-subpiece case: the byte offset of `inner` within
/// `outer` (little-endian, same space), or `-1` if `inner` is not contained. Used by
/// [`ancestor_op_use`]'s SUBPIECE case to detect an extract to the same storage location.
fn overlap_bytes(f: &Funcdata, inner: VarnodeId, outer: VarnodeId) -> i64 {
    let (a, b) = (f.vn(inner), f.vn(outer));
    if a.loc.space != b.loc.space {
        return -1;
    }
    if a.loc.offset >= b.loc.offset && a.loc.offset + a.size as u64 <= b.loc.offset + b.size as u64 {
        (a.loc.offset - b.loc.offset) as i64
    } else {
        -1
    }
}

/// The USE half of Ghidra's return-trial gate for a single RETURN input: `is_realistic` (the realism
/// half) AND `ancestor_op_use` (the trial value is only used to feed this RETURN). Mirrors
/// `ActionReturnRecovery::apply` coreaction.cc:1930-1931.
fn return_trial_kept(f: &Funcdata, ret: OpId, slot: usize) -> bool {
    let Some(v) = f.op(ret).input(slot) else { return false };
    if !is_realistic(f, v, &mut HashSet::new()) || is_const_padded_piece(f, v) {
        return false;
    }
    let addr = f.vn(v).loc;
    ancestor_op_use(f, TRIM_RECURSE_MAX, v, ret, slot, 0, 0, addr, true, &mut HashSet::new())
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
/// checked trial whose candidate passes BOTH return-trial gates at some RETURN (coreaction.cc:1930-
/// 1931 — `AncestorRealistic::execute` AND `ancestorOpUse`, here [`return_trial_kept`]) as active; a
/// candidate that fails either gate is left unchecked so a later pass can reconsider it as the
/// dataflow refines. Then advance the pass counter and, once `numpasses > maxpass`, mark the
/// container fully checked (which gates the commit).
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
        let kept = rets.iter().any(|&ret| return_trial_kept(f, ret, slot));
        if kept {
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
        // slot 0 is the return address; slots 1.. are the candidate return registers. Keep the first
        // slot that passes the full gate (realistic AND only-used-by-this-return, minus a
        // constant-padded wide candidate so a narrower one wins) — consistent with the trial
        // evaluation in [`check_output_trial_use`].
        let keep = (1..n).find(|&slot| return_trial_kept(f, ret, slot));
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

/// Ghidra `FuncCallSpecs::checkInputTrialUse` (fspec.cc:5585) — the register (non-spacebase) branch
/// (fspec.cc:5638-5651). Each not-yet-checked argument trial gets one of three verdicts:
///   - `AncestorRealistic::execute` accepts it (the value has a realistic caller-set ancestor — a
///     top-level input trial is rejected, but an input reached *through* a copy chain is accepted,
///     [`realistic_faithful`]) AND [`ancestor_op_use`] confirms it is used only to feed this call ⇒
///     `markActive` (a genuine argument);
///   - realistic but not only-used-here ⇒ `markInactive` (Ghidra: "not actively used" — dataflow
///     preserved);
///   - not realistic but the trial varnode is itself a function input ⇒ `markInactive` ("Not likely a
///     parameter but maybe" — a passed-through input, dataflow PRESERVED so the function's own
///     parameter recovery can still see it, fspec.cc:5645);
///   - otherwise ⇒ `markNoUse`, and the dataflow is *freed* (the input slot is set to a constant 0,
///     fspec.cc:5650-5651) — the value is unaffected/killed-by-call, not an argument.
/// The structural removal is deferred to [`build_input_from_trials`]; freeing keeps the slot count
/// stable across passes. Then advance the pass counter and gate fully-checked.
fn check_input_trial_use(f: &mut Funcdata, call: OpId) {
    /// Trial disposition, in Ghidra's `ParamTrial` terms.
    enum Verdict {
        Active,   // markActive — a genuine argument
        Inactive, // markInactive — dataflow PRESERVED (may still be a parameter)
        NoUse,    // markNoUse — dataflow FREED (definitely not an argument)
    }
    let ntrials = f.active_inputs.get(&call).map_or(0, |a| a.num_trials());
    // (trial index, op slot, verdict) for every trial unchecked at entry, evaluated on the current
    // (pre-free) dataflow so no trial's verdict depends on another's freeing.
    let mut verdicts: Vec<(usize, usize, Verdict)> = Vec::new();
    for ti in 0..ntrials {
        let (checked, slot) = {
            let t = &f.active_inputs[&call].trial[ti];
            (t.flags & trial_flags::CHECKED != 0, t.op_slot as usize)
        };
        if checked {
            continue;
        }
        let verdict = match f.op(call).input(slot) {
            None => Verdict::NoUse,
            Some(v) => {
                let vn_is_input = f.vn(v).is_input();
                // `AncestorRealistic::execute`: a top-level input trial is not realistic (the
                // early-return at funcdata_varnode.cc:2211), but a written chain reaching an input via
                // traversal is (`realistic_faithful`).
                let realistic = !vn_is_input && realistic_faithful(f, v, &mut HashSet::new());
                if realistic {
                    let addr = f.vn(v).loc;
                    let aou = ancestor_op_use(
                        f, TRIM_RECURSE_MAX, v, call, slot, 0, 0, addr, false, &mut HashSet::new(),
                    );
                    if aou { Verdict::Active } else { Verdict::Inactive }
                } else if vn_is_input {
                    Verdict::Inactive
                } else {
                    Verdict::NoUse
                }
            }
        };
        verdicts.push((ti, slot, verdict));
    }
    // Free the dataflow of the definitely-not-used (`markNoUse`) slots only; `markInactive` preserves
    // its dataflow (Ghidra frees only when `trial.isDefinitelyNotUsed()`, fspec.cc:5649-5651).
    for (_, slot, verdict) in &verdicts {
        if !matches!(verdict, Verdict::NoUse) {
            continue;
        }
        if let Some(v) = f.op(call).input(*slot) {
            if !f.vn(v).is_constant() {
                let size = f.vn(v).size as u32;
                let zero = f.new_const(size, 0);
                f.op_set_input(call, *slot, zero);
            }
        }
    }
    let active = f.active_inputs.get_mut(&call).unwrap();
    for (ti, _, verdict) in verdicts {
        match verdict {
            Verdict::Active => active.trial[ti].mark_active(),
            Verdict::Inactive => active.trial[ti].mark_inactive(),
            Verdict::NoUse => active.trial[ti].mark_no_use(),
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
/// heritage's `guard_calls` models a call's `killedbycall` output registers as indirect-creations
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

    // ---- ancestorOpUse (the USE gate) — paths the corpus exercises plus its unexercised branches --

    /// `RAX = INT_ADD(RDI, 1)`, read by the RETURN; `extra` optionally attaches a second use of RAX.
    fn rax_add(extra: impl FnOnce(&mut Funcdata, VarnodeId, SeqNum)) -> (Funcdata, OpId) {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let rdi = f.new_input(8, Address::new(reg, 0x38));
        let c = f.new_const(8, 1);
        let add = f.new_op(OpCode::IntAdd, seq, vec![rdi, c]);
        let rax = f.new_output(add, 8, Address::new(reg, RAX));
        extra(&mut f, rax, seq);
        let retaddr = f.new_input(8, Address::new(reg, 0x20));
        let ret = f.new_op(OpCode::Return, seq, vec![retaddr, rax]);
        (f, ret)
    }

    #[test]
    fn return_value_only_used_by_return_is_kept() {
        let (f, ret) = rax_add(|_, _, _| {});
        assert!(return_trial_kept(&f, ret, 1), "a computed value used only by the return is a real return value");
    }

    #[test]
    fn return_value_used_as_store_address_is_voided() {
        // condconst's essence: RAX holds `&array[i]` arithmetic that is actually a STORE address left
        // in the register, not a returned value — onlyOpUse hits CPUI_STORE, so ancestorOpUse rejects
        // it and the return becomes void.
        let (f, ret) = rax_add(|f, rax, seq| {
            let space_annot = f.new_const(8, 0);
            let val = f.new_const(4, 0x10);
            f.new_op(OpCode::Store, seq, vec![space_annot, rax, val]); // STORE _, RAX(addr), val
        });
        assert!(!return_trial_kept(&f, ret, 1), "a value used as a STORE address is not a return value");
    }

    #[test]
    fn return_value_copied_to_persistent_global_is_voided() {
        // A value COPYd into a persistent (global) location before returning is stored to a global,
        // not returned — onlyOpUse stops at the persistent output.
        let (f, ret) = rax_add(|f, rax, seq| {
            let cp = f.new_op(OpCode::Copy, seq, vec![rax]);
            let reg = f.spaces.by_name("ram").unwrap();
            let g = f.new_output(cp, 8, Address::new(reg, 0x600000));
            f.vn_mut(g).flags |= crate::decompile::varnode::flags::PERSIST;
        });
        assert!(!return_trial_kept(&f, ret, 1), "a value stored to a persistent global is not a return value");
    }

    #[test]
    fn return_multiequal_of_store_addresses_is_voided() {
        // The exact condconst IR: `RAX = MULTIEQUAL(a, b)` where each of a, b is a leftover STORE
        // address. Exercises ancestorOpUse's MULTIEQUAL recursion into both arms.
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let rdi = f.new_input(8, Address::new(reg, 0x38));
        let mut store_addr = |f: &mut Funcdata, k: u64| -> VarnodeId {
            let c = f.new_const(8, k);
            let add = f.new_op(OpCode::IntAdd, seq, vec![rdi, c]);
            let a = f.new_output(add, 8, Address::new(reg, RAX));
            let sp = f.new_const(8, 0);
            let v = f.new_const(4, 0x10);
            f.new_op(OpCode::Store, seq, vec![sp, a, v]); // a is a STORE address
            a
        };
        let a = store_addr(&mut f, 12);
        let b = store_addr(&mut f, 16);
        let phi = f.new_op(OpCode::Multiequal, seq, vec![a, b]);
        let rax = f.new_output(phi, 8, Address::new(reg, RAX));
        let retaddr = f.new_input(8, Address::new(reg, 0x20));
        let ret = f.new_op(OpCode::Return, seq, vec![retaddr, rax]);
        assert!(!return_trial_kept(&f, ret, 1), "a MULTIEQUAL of leftover STORE addresses is not returned (condconst)");
    }

    #[test]
    fn overlapping_return_candidates_keep_the_value() {
        // A float/double return reaches BOTH the XMM0:8 and XMM0:4 sibling candidates that
        // recover_return appends. When evaluating one, onlyOpUse must count the value's use at the
        // OTHER return-value slot as the return use (not an external use) — otherwise a valid return
        // is wrongly voided. Guards [`is_return_value_use`].
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let rdi = f.new_input(8, Address::new(reg, 0x38));
        let c = f.new_const(8, 1);
        let add = f.new_op(OpCode::IntAdd, seq, vec![rdi, c]);
        let v = f.new_output(add, 8, Address::new(reg, XMM0)); // XMM0:8 candidate value
        let z = f.new_const(8, 0);
        let subop = f.new_op(OpCode::Subpiece, seq, vec![v, z]);
        let sub = f.new_output(subop, 4, Address::new(reg, XMM0)); // XMM0:4 sibling view of the same value
        let retaddr = f.new_input(8, Address::new(reg, 0x20));
        let ret = f.new_op(OpCode::Return, seq, vec![retaddr, v, sub]);
        assert!(return_trial_kept(&f, ret, 1), "the value also feeding the sibling XMM0:4 candidate is still a real return");
    }

    /// A CALL reading `v` at slot 1, plus a `RETURN` (the opmatch during return recovery). `active`
    /// selects whether the CALL's slot-1 input trial is marked active (a real parameter there) or
    /// checked-but-inactive (proved not a parameter). Returns `(f, ret, call, v)`.
    fn call_double_use_setup(active: bool) -> (Funcdata, OpId, OpId, VarnodeId) {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let rdi = f.new_input(8, Address::new(reg, 0x38));
        let c = f.new_const(8, 1);
        let addop = f.new_op(OpCode::IntAdd, seq, vec![rdi, c]);
        let v = f.new_output(addop, 8, Address::new(reg, RAX));
        let target = f.new_const(8, 0x400400);
        let call = f.new_op(OpCode::Call, seq, vec![target, v]); // second CALL reads v at slot 1
        let retaddr = f.new_input(8, Address::new(reg, 0x20));
        let ret = f.new_op(OpCode::Return, seq, vec![retaddr, v]);
        let mut ai = ParamActive::new(Some(reg));
        let ti = ai.register_trial(Address::new(reg, 0x38), 8);
        ai.trial[ti].op_slot = 1;
        if active {
            ai.trial[ti].mark_active();
        } else {
            ai.trial[ti].mark_inactive();
        }
        f.active_inputs.insert(call, ai);
        (f, ret, call, v)
    }

    #[test]
    fn check_call_double_use_accepts_inactive_second_call_trial() {
        // The callee proved v is not its parameter at that slot (trial checked, inactive) ⇒ a
        // legitimate double-use: checkCallDoubleUse returns true (doesn't disqualify the trial).
        let (f, ret, call, v) = call_double_use_setup(false);
        let addr = f.vn(v).loc;
        assert!(check_call_double_use(&f, ret, call, v, 0, addr), "an inactive second-call trial is a legitimate double-use");
    }

    #[test]
    fn check_call_double_use_rejects_active_second_call_trial() {
        // v IS the second call's active parameter there ⇒ not a legitimate double-use for the return.
        let (f, ret, call, v) = call_double_use_setup(true);
        let addr = f.vn(v).loc;
        assert!(!check_call_double_use(&f, ret, call, v, 0, addr), "an active second-call trial disqualifies the double-use");
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
        // value flowing across the call — a written, only-used-by-this-call computed value (loopcomment's
        // aliased-stack-local load), which passes BOTH input-trial gates: AncestorRealistic (a solid
        // write reached by traversal) AND ancestorOpUse (used only to feed this call). A bare *constant*
        // here would fail ancestorOpUse (funcdata_varnode.cc:1922 — unwritten, non-input ⇒ false), just
        // as it does in Ghidra. For a creation, input(0) is the indirect-zero `#0` placeholder.
        let mut extra = Vec::new();
        let ind_in = if creation {
            f.new_const(8, 0)
        } else {
            let a = f.new_const(8, 0x40);
            let b = f.new_const(8, 0x8);
            let add = f.new_op(OpCode::IntAdd, seq, vec![a, b]);
            let src = f.new_output(add, 8, Address::new(reg, 0x100)); // scratch, not an argument register
            extra.push(add);
            src
        };
        let ind = f.new_op(OpCode::Indirect, seq, vec![ind_in]);
        let rsi = f.new_output(ind, 8, Address::new(reg, ARG_REGS[1]));
        if creation {
            f.vn_mut(rsi).set_indirect_creation();
        }
        let call = f.new_op(OpCode::Call, seq, vec![target, rdi, rsi]);
        let mut ops = vec![cp0];
        ops.extend(extra);
        ops.push(ind);
        ops.push(call);
        f.set_blocks(vec![BlockBasic { ops: ops.clone(), ..Default::default() }]);
        for &op in &ops {
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
