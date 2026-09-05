//! Return-value recovery — a port of Ghidra's `ActionReturnRecovery` (`coreaction.cc`) +
//! the core of `AncestorRealistic` (`funcdata_varnode.cc`).
//!
//! The candidate return storage is registered DURING heritage, not enumerated here:
//! [`super::heritage::guard_returns`] asks the compiler spec (`FuncProto::characterizeAsOutput`,
//! heritage.cc:1660) about every heritaged range and gives each match a trial plus an input on
//! every RETURN. [`init_active_output`] only opens the trial container. Once heritage has linked
//! those inputs to the value reaching each RETURN, [`is_realistic`] decides which candidate
//! actually holds a returned value — i.e. its value traces back to a *real write the function
//! made*, not to the unwritten passthrough register. The non-realistic candidates are removed, so
//! dead-code keeps exactly the return value and the scratch register writes die.
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

use super::alias::AliasChecker;
use super::fspec::{trial_flags, Containment, ParamActive, ParamEntry, ParamList, ParamTrial, EXTRAPOP_UNKNOWN};
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::space::{Address, SpaceKind};
use super::varnode::VarnodeId;

/// x86-64 register offsets, for the hand-built SysV fixtures below. The recovery itself no longer
/// names a register: return candidates come from the compiler spec (see [`init_active_output`]).
#[cfg(test)]
const RAX: u64 = 0x0;
#[cfg(test)]
const XMM0: u64 = 0x1200;

/// SysV integer argument registers, in order: RDI, RSI, RDX, RCX, R8, R9 — for the hand-built
/// x86-64 fixtures below. The recovery itself no longer names a register: argument candidates come
/// from the compiler spec (see [`init_active_input`]).
#[cfg(test)]
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
        // A value reached THROUGH the traversal that is an unwritten input is a normal parameter —
        // Ghidra `AncestorRealistic::enterNode` returns `pop_success` for it (funcdata_varnode.cc:2040),
        // valid unless it is a return-address storage location (`pop_fail`, :2053). The top-level case
        // where the trial varnode ITSELF is directly an input is rejected by the caller
        // ([`return_trial_kept`]), mirroring `AncestorRealistic::execute`'s early-return (:2205). (The
        // `isUnaffected`/`!isDirectWrite` sub-cases Ghidra also fails, :2036/2038, are inert here — the
        // reached inputs are the argument registers, never callee-saved/unaffected storage — an
        // approximation the call-argument side no longer makes: see [`AncestorRealistic`].)
        return !v.is_return_address();
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

/// Ghidra `AncestorRealistic` (funcdata.hh:43, funcdata_varnode.cc:1996-2245): is the data-flow
/// into a parameter trial *realistic* — does the value show active movement into the trial's
/// storage, rather than being an untouched input or a call-killed leftover? A depth-first
/// traversal back through the trial's ancestors over an explicit state stack: every node is
/// entered once ([`Self::enter_node`]) and backtracked out of once ([`Self::upon_pop`]). The
/// arbitration happens at MULTIEQUALs: a *solid* movement (COPY, LOAD, arithmetic) on one input
/// can override a *failkill* (a killed-by-call creation) on another — unless the trial is not
/// allowed a failing path, or the failing path cannot be attributed to conditional execution
/// ([`Self::check_conditional_exe`]), in which case the trial is slated for `final_input_check`.
///
/// A dedicated COPY into the trial storage (`MOV EAX,ESP` feeding a call) is itself solid
/// movement: Ghidra walks the COPY chain only far enough to rule out an unaffected / non-direct-
/// write input and then pops `PopSolid` WITHOUT entering whatever defines the chain's head. The
/// flattened walk this replaces recursed through the COPY into the head's defining INDIRECT and
/// applied the killed-by-call rejection there — dropping the argument (WAR2's FUN_00066da8: the
/// stack-buffer address passed to a call was judged no-use, and the body collapsed; the oracle
/// keeps the argument).
///
/// Visitation marks use a set instead of Ghidra's `Varnode::mark` bit (same semantics). The op
/// flags `PcodeOp::isIncidentalCopy` and `isStoreUnmapped` read as `false`: mosura carries
/// neither (the first is set only on `incidentalcopy` injection payloads, flow.cc:1202; the second
/// only on STOREs by `ActionInternalStorage`, coreaction.cc:4960, so it can never hold for the
/// COPY-chain ops the walk tests it on). Nor is the varnode-level `Varnode::incidental_copy`
/// property (x86.pspec `<incidentalcopy>`: ST0-ST7) carried.
struct AncestorRealistic {
    state_stack: Vec<AncestorState>,
    marked: HashSet<VarnodeId>,
    multi_depth: i32,
    allow_failing_path: bool,
}

/// Ghidra `AncestorRealistic::State` (funcdata.hh:46): a node in the depth-first traversal.
#[derive(Clone, Copy)]
struct AncestorState {
    /// Operation along the path to the Varnode.
    op: OpId,
    /// `vn = op.input(slot)`.
    slot: usize,
    /// `seen_solid0` / `seen_solid1` / `seen_kill`.
    flags: u32,
    /// Offset of the (eventual) trial value, within a possibly larger register.
    offset: i64,
}

mod ancestor_state {
    pub const SEEN_SOLID0: u32 = 1; // a solid movement into the Varnode occurred on at least one path to MULTIEQUAL
    pub const SEEN_SOLID1: u32 = 2; // a solid movement into anything other than slot 0 occurred
    pub const SEEN_KILL: u32 = 4; // the Varnode is killed by a call on at least one path to MULTIEQUAL
}

impl AncestorState {
    /// Constructor given a Varnode read (funcdata.hh:60).
    fn new(op: OpId, slot: usize) -> Self {
        AncestorState { op, slot, flags: 0, offset: 0 }
    }
    /// Constructor from an old state pulled back through a CPUI_SUBPIECE (funcdata.hh:69): the
    /// data ultimately in the SUBPIECE output is copied from a non-zero offset within the input.
    fn from_subpiece(f: &Funcdata, op: OpId, old: &AncestorState) -> Self {
        let in1 = f.op(op).input(1).expect("a SUBPIECE has two inputs");
        AncestorState { op, slot: 0, flags: 0, offset: old.offset + f.vn(in1).loc.offset as i64 }
    }
    fn solid_slot(&self) -> usize {
        if self.flags & ancestor_state::SEEN_SOLID0 != 0 { 0 } else { 1 }
    }
    fn mark_solid(&mut self, s: usize) {
        self.flags |= if s == 0 { ancestor_state::SEEN_SOLID0 } else { ancestor_state::SEEN_SOLID1 };
    }
    fn mark_kill(&mut self) {
        self.flags |= ancestor_state::SEEN_KILL;
    }
    fn seen_solid(&self) -> bool {
        self.flags & (ancestor_state::SEEN_SOLID0 | ancestor_state::SEEN_SOLID1) != 0
    }
    fn seen_kill(&self) -> bool {
        self.flags & ancestor_state::SEEN_KILL != 0
    }
}

/// Ghidra `AncestorRealistic` traversal commands (funcdata.hh:79).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AncestorCmd {
    /// Extending path into new Varnode.
    EnterNode,
    /// Backtracking, from path that contained a reasonable ancestor.
    PopSuccess,
    /// Backtracking, from path with successful, solid, movement, via COPY, LOAD, or other arith/logical.
    PopSolid,
    /// Backtracking, from path with a bad ancestor.
    PopFail,
    /// Backtracking, from path with a bad ancestor, specifically killedbycall.
    PopFailKill,
}

impl AncestorRealistic {
    fn new() -> Self {
        AncestorRealistic { state_stack: Vec::new(), marked: HashSet::new(), multi_depth: 0, allow_failing_path: false }
    }

    /// Ghidra `AncestorRealistic::execute` (funcdata_varnode.cc:2205): perform a full ancestor
    /// check on the input `slot` of `op` for `trial`. `allow_fail` is true if we allow and test
    /// for failing paths due to conditional execution.
    fn execute(&mut self, f: &Funcdata, op: OpId, slot: usize, trial: &mut ParamTrial, allow_fail: bool) -> bool {
        self.allow_failing_path = allow_fail;
        self.marked.clear(); // make sure to clear out any old data
        self.state_stack.clear();
        self.multi_depth = 0;
        // If the parameter itself is an input, we don't consider this realistic, we expect to see
        // active movement into the parameter. There are some cases where this doesn't happen, but
        // they are rare and failure here doesn't necessarily mean further analysis won't still
        // declare this a parameter
        let Some(vn) = f.op(op).input(slot) else { return false };
        if f.vn(vn).is_input() && !trial.has_cond_exe_effect() {
            return false; // make sure we are not retesting
        }
        // Run the depth first traversal
        let mut command = AncestorCmd::EnterNode;
        self.state_stack.push(AncestorState::new(op, slot)); // start by entering the initial node
        while !self.state_stack.is_empty() {
            // continue until all paths have been exhausted
            command = match command {
                AncestorCmd::EnterNode => self.enter_node(f, trial),
                pop => self.upon_pop(f, trial, pop),
            };
        }
        match command {
            AncestorCmd::PopSuccess => {
                trial.set_ancestor_realistic();
                true
            }
            AncestorCmd::PopSolid => {
                trial.set_ancestor_realistic();
                trial.set_ancestor_solid();
                true
            }
            _ => false,
        }
    }

    /// Ghidra `AncestorRealistic::enterNode` (funcdata_varnode.cc:2033): analyze a new node that
    /// has just entered, during the depth-first traversal. Returns the command indicating the next
    /// traversal step: push (`EnterNode`), or pop (`PopSuccess`, `PopFail`, `PopSolid`...).
    fn enter_node(&mut self, f: &Funcdata, trial: &mut ParamTrial) -> AncestorCmd {
        use AncestorCmd::*;
        let state = *self.state_stack.last().expect("enter_node runs with a node on the stack");
        // If the node has already been visited, we truncate the traversal to prevent cycles.
        // We always return success assuming the proper result will get returned along the first path
        let state_vn = f.op(state.op).input(state.slot).expect("the traversed slot is a live input");
        if self.marked.contains(&state_vn) {
            return PopSuccess;
        }
        let v = f.vn(state_vn);
        if !v.is_written() {
            if v.is_input() {
                if v.is_unaffected() {
                    return PopFail;
                }
                if v.is_persist() {
                    return PopSuccess; // a global input, not active movement, but a valid possibility
                }
                if !v.is_direct_write() {
                    return PopFail;
                }
            }
            return PopSuccess; // probably a normal parameter, not active movement, but valid
        }
        self.marked.insert(state_vn); // mark that the varnode has now been visited
        let op = v.def.expect("a written varnode has a defining op");
        match f.op(op).code() {
            OpCode::Indirect => {
                if v.is_indirect_creation() {
                    // backtracking is stopped by a call
                    trial.set_ind_create_formed();
                    let in0 = f.op(op).input(0).expect("an INDIRECT has two inputs");
                    if f.vn(in0).is_constant() && f.vn(in0).is_indirect_creation() {
                        // `isIndirectZero`: true only if not a possible output
                        return PopFailKill; // truncate this path, indicating killedbycall
                    }
                    return PopSuccess; // otherwise it could be valid
                }
                if !indirect_is_store(f, op) {
                    // if flow goes THROUGH a call
                    if v.is_return_address() {
                        return PopFail; // storage address location is completely invalid
                    }
                    if trial.is_killed_by_call() {
                        return PopFail; // "likely" killedbycall is invalid
                    }
                }
                self.state_stack.push(AncestorState::new(op, 0));
                EnterNode // enter the new node
            }
            OpCode::Subpiece => {
                // Extracting to a temporary, or to the same storage location, or otherwise
                // incidental are viewed as just another node on the path to traverse
                let in0 = f.op(op).input(0).expect("a SUBPIECE has two inputs");
                let in1 = f.op(op).input(1).expect("a SUBPIECE has two inputs");
                if f.spaces.get(v.loc.space).kind == SpaceKind::Internal
                    || varnode_overlap(f, state_vn, in0) == f.vn(in1).loc.offset as i64
                {
                    self.state_stack.push(AncestorState::from_subpiece(f, op, &state));
                    return EnterNode; // push into the new node
                }
                // For other SUBPIECES, do a minimal traversal to rule out unaffected or other
                // invalid inputs, but otherwise treat it as valid, active, movement into the parameter
                let mut cur = op;
                loop {
                    let vn = f.op(cur).input(0).expect("a COPY/SUBPIECE has an input");
                    if !self.marked.contains(&vn) && f.vn(vn).is_input() {
                        if f.vn(vn).is_unaffected() || !f.vn(vn).is_direct_write() {
                            return PopFail;
                        }
                    }
                    match f.vn(vn).def {
                        Some(d) if matches!(f.op(d).code(), OpCode::Copy | OpCode::Subpiece) => cur = d,
                        _ => break,
                    }
                }
                PopSolid // treat the COPY as a solid movement
            }
            OpCode::Copy => {
                // Copies to a temporary, or between varnodes with same storage location, or
                // otherwise incidental are viewed as just another node on the path to traverse
                let in0 = f.op(op).input(0).expect("a COPY has an input");
                if f.spaces.get(v.loc.space).kind == SpaceKind::Internal || v.loc == f.vn(in0).loc {
                    self.state_stack.push(AncestorState::new(op, 0));
                    return EnterNode; // push into the new node
                }
                // For other COPIES, do a minimal traversal to rule out unaffected or other
                // invalid inputs, but otherwise treat it as valid, active, movement into the parameter
                let mut vn = in0;
                loop {
                    if !self.marked.contains(&vn) && f.vn(vn).is_input() && !f.vn(vn).is_direct_write() {
                        return PopFail;
                    }
                    // (`op->isStoreUnmapped()` — never set in mosura, see the type docs)
                    let Some(d) = f.vn(vn).def else { break };
                    match f.op(d).code() {
                        OpCode::Copy | OpCode::Subpiece => vn = f.op(d).input(0).expect("a COPY/SUBPIECE has an input"),
                        OpCode::Piece => vn = f.op(d).input(1).expect("a PIECE has two inputs"), // follow least significant piece
                        _ => break,
                    }
                }
                PopSolid // treat the COPY as a solid movement
            }
            OpCode::Multiequal => {
                self.multi_depth += 1;
                self.state_stack.push(AncestorState::new(op, 0));
                EnterNode // nothing to check, start traversing inputs of MULTIEQUAL
            }
            OpCode::Piece => {
                if v.size > trial.size {
                    // Did we already pull-back from a SUBPIECE? If the trial is getting pieced
                    // together and then truncated in a register, this is evidence of artificial
                    // data-flow.
                    let in0 = f.op(op).input(0).expect("a PIECE has two inputs");
                    let in1 = f.op(op).input(1).expect("a PIECE has two inputs");
                    if state.offset == 0 && f.vn(in1).size <= trial.size {
                        // Truncation corresponds to least significant piece, follow slot=1
                        self.state_stack.push(AncestorState::new(op, 1));
                        return EnterNode;
                    } else if state.offset == f.vn(in1).size as i64 && f.vn(in0).size <= trial.size {
                        // Truncation corresponds to most significant piece, follow slot=0
                        self.state_stack.push(AncestorState::new(op, 0));
                        return EnterNode;
                    }
                    if f.spaces.get(v.loc.space).kind != SpaceKind::Spacebase {
                        return PopFail;
                    }
                }
                PopSolid
            }
            _ => PopSolid, // any other LOAD or arithmetic/logical operation is viewed as solid movement
        }
    }

    /// Ghidra `AncestorRealistic::uponPop` (funcdata_varnode.cc:2138): backtrack into a previously
    /// visited node. `pop_command` is the type of pop being performed; returns the command to
    /// execute (push or pop) after the current pop.
    fn upon_pop(&mut self, f: &Funcdata, trial: &mut ParamTrial, pop_command: AncestorCmd) -> AncestorCmd {
        use AncestorCmd::*;
        let n = self.state_stack.len();
        let state_op = self.state_stack[n - 1].op;
        if f.op(state_op).code() == OpCode::Multiequal {
            // All the interesting action happens for MULTIEQUAL branch points. `prevstate` is
            // `state_stack[n - 2]`: the state previous to the one being popped.
            let num_input = f.op(state_op).num_inputs();
            let mut pop_command = pop_command;
            if pop_command == PopFail {
                // for a pop_fail, we always pop and pass along the fail
                self.multi_depth -= 1;
                self.state_stack.pop();
                return pop_command;
            } else if pop_command == PopSolid && self.multi_depth == 1 && num_input == 2 {
                let slot = self.state_stack[n - 1].slot;
                self.state_stack[n - 2].mark_solid(slot); // indicate we have seen a "solid" that could override a "failkill"
            } else if pop_command == PopFailKill {
                self.state_stack[n - 2].mark_kill(); // indicate we have seen a "failkill" along at least one path of MULTIEQUAL
            }
            self.state_stack[n - 1].slot += 1; // move to the next sibling
            if self.state_stack[n - 1].slot == num_input {
                // if we have traversed all siblings
                let prevstate = self.state_stack[n - 2];
                if prevstate.seen_solid() {
                    // if we have seen an overriding "solid" along at least one path
                    pop_command = PopSuccess; // this is always a success
                    if prevstate.seen_kill() {
                        // UNLESS we have seen a failkill
                        if self.allow_failing_path {
                            let state = self.state_stack[n - 1];
                            if !self.check_conditional_exe(f, &state) {
                                // that can NOT be attributed to conditional execution
                                pop_command = PopFail; // in which case we fail despite having solid movement
                            } else {
                                trial.set_cond_exe_effect(); // slate this trial for additional testing
                            }
                        } else {
                            pop_command = PopFail;
                        }
                    }
                } else if prevstate.seen_kill() {
                    // if we have seen a failkill without solid movement
                    pop_command = PopFailKill; // this is always a failure
                } else {
                    pop_command = PopSuccess; // seeing neither solid nor failkill is still a success
                }
                self.multi_depth -= 1;
                self.state_stack.pop();
                return pop_command;
            }
            return EnterNode;
        }
        self.state_stack.pop();
        pop_command
    }

    /// Ghidra `AncestorRealistic::checkConditionalExe` (funcdata_varnode.cc:1998): are there two
    /// input flows, one of which is a normal *solid* flow? `state` is the MULTIEQUAL's own node
    /// and its own solid slot is consulted, exactly as Ghidra does (the solid marks land on the
    /// previous state, so this reads slot 1 unless the MULTIEQUAL node itself was marked).
    fn check_conditional_exe(&self, f: &Funcdata, state: &AncestorState) -> bool {
        let Some(bl) = f.op(state.op).parent else { return false };
        if f.block(bl).in_edges.len() != 2 {
            return false;
        }
        let solid_block = f.block(bl).in_edges[state.solid_slot()];
        if f.block(solid_block).out_edges.len() != 1 {
            return false;
        }
        true
    }
}

/// Ghidra `Varnode::overlap(const Varnode &)` (varnode.cc:178) over `Address::overlap`
/// (address.cc): the relative point of overlap of `a` within `b` — the byte offset of `a`'s least
/// significant byte inside `b` — or -1 when `a` does not lie in `b` (different space, a constant,
/// or out of range).
fn varnode_overlap(f: &Funcdata, a: VarnodeId, b: VarnodeId) -> i64 {
    let (va, vb) = (f.vn(a), f.vn(b));
    let address_overlap = |skip: u64| -> i64 {
        if va.loc.space != vb.loc.space {
            return -1; // must be in same address space to overlap
        }
        let spc = f.spaces.get(va.loc.space);
        if spc.kind == SpaceKind::Constant {
            return -1; // must not be constants
        }
        let dist = spc.wrap_offset(va.loc.offset.wrapping_add(skip).wrapping_sub(vb.loc.offset));
        if dist >= vb.size as u64 {
            return -1; // but must fall before op+size
        }
        dist as i64
    };
    if !f.spaces.is_big_endian(va.loc.space) {
        address_overlap(0) // little endian
    } else {
        let over = address_overlap(va.size as u64 - 1); // big endian
        if over != -1 { vb.size as i64 - 1 - over } else { -1 }
    }
}

/// Ghidra `PcodeOp::isIndirectStore` (op.hh): whether an INDIRECT models a `CPUI_STORE` (vs. a call
/// clobber/passthrough). mosura carries no explicit flag, so it is read from the INDIRECT's guarded
/// (causing) op — a STORE means the value flows through the store; a CALL/CALLIND is the call
/// passthrough the killed-by-call check in [`AncestorRealistic`] rejects.
fn indirect_is_store(f: &Funcdata, indirect: OpId) -> bool {
    f.op(indirect).guarded_op().is_some_and(|g| f.op(g).code() == OpCode::Store)
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
    let trace = std::env::var("MOSURA_AOU_PC").ok().and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .is_some_and(|pc| f.op(opmatch).seqnum.pc.offset == pc);
    'outer: while i < varlist.len() {
        let (vn, base_flags) = varlist[i];
        i += 1;
        for op in f.vn(vn).descend.clone() {
            if trace {
                debug!(crate::debug::Topic::Args, "vn {}+{:#x} reader {:?}@{:#x} (opmatch slot{opslot} inputmatch={})",
                    f.spaces.get(f.vn(vn).loc.space).name, f.vn(vn).loc.offset,
                    f.op(op).code(), f.op(op).seqnum.pc.offset,
                    f.op(op).input(opslot) == Some(vn));
            }
            if op == opmatch && f.op(op).input(opslot) == Some(vn) {
                // The parameter/return use we are evaluating — Ghidra skips ONLY the trial's own
                // slot (funcdata_varnode.cc:1823-1825). A use of the value at ANOTHER slot of the
                // same op falls through to the opcode cases (e.g. `check_call_double_use` for a
                // CALL, the own-slot RETURN test below), which can reject it as a real use:
                // deindirect's `param_3+5` feeds RSI and RDX of the same call, and only the RSI
                // trial is the argument.
                continue;
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
                        if f.op(op).input(opslot) == Some(vn) {
                            continue; // the same trial slot in a (possibly different) RETURN
                        }
                    } else if active_output && f.op(op).input(0) != Some(vn)
                        && !is_alternate_path_valid(f, vn, cur_flags) {
                            continue; // don't consider this a "use"
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
            // ancestor. The space tested is `invn`'s — the varnode being examined, which for a COPY
            // is the DEFINED one (funcdata_varnode.cc, `invn->getSpace()->getType()==IPTR_INTERNAL`)
            // — not the copied-from input's. The SUBPIECE arm below already reads `v.loc.space` for
            // exactly this test; this arm read the input's space instead.
            let internal = f.spaces.get(v.loc.space).kind == super::space::SpaceKind::Internal;
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
    // Ghidra `AncestorRealistic::execute` (funcdata_varnode.cc:2205): if the trial varnode is ITSELF
    // a function input, it is not a realistic return — we expect to see active movement into the
    // return register — so reject before the traversal. (A value reached THROUGH a copy/piece chain
    // to an input is a different case: a normal parameter, kept by [`is_realistic`].)
    if f.vn(v).is_input() {
        return false;
    }
    if !is_realistic(f, v, &mut HashSet::new()) {
        return false;
    }
    let addr = f.vn(v).loc;
    ancestor_op_use(f, TRIM_RECURSE_MAX, v, ret, slot, 0, 0, addr, true, &mut HashSet::new())
}

/// Open return-value recovery on `f` — a port of Ghidra `Funcdata::initActiveOutput`
/// (funcdata_varnode.cc:585), called from `ActionPrototypeTypes::apply` (coreaction.cc:4651) when the
/// prototype's output is not locked. Creates the (empty) trial container and sets its pass budget
/// from the convention's `getMaxOutputDelay` — the number of heritage passes that must complete
/// before every possible return location has data-flow. Runs pre-heritage.
///
/// The trials themselves are registered DURING heritage, by [`super::heritage::guard_returns`]
/// asking `characterizeAsOutput` of each heritaged range (heritage.cc:1660). Ghidra never
/// enumerates candidate return registers, and neither does mosura any more: this RETIRES
/// `recover_return`, which appended hardcoded x86-64 `RAX:8`/`XMM0:8` varnodes to every RETURN
/// pre-heritage. Those constants are correct only by coincidence on the x86-64 SysV corpus — under
/// any 32-bit convention (WAR2's `__watcall`, which returns in `EAX:4`) neither candidate matched
/// any storage, no trial was ever usable, and EVERY function recovered a `void` return, deleting
/// its return value as dead code.
pub fn init_active_output(f: &mut Funcdata) {
    let reg = f.spaces.by_name("register");
    let mut active = ParamActive::new(reg);
    // funcdata_varnode.cc:588 — a nonzero delay is capped at 3 passes.
    let maxdelay = f.called_model().max_output_delay(&f.spaces);
    active.set_max_pass(if maxdelay > 0 { 3 } else { 0 });
    f.active_output = Some(active);
}

/// Maximum number of evaluation passes before the call-input trial decisions are committed
/// structurally — a stand-in for Ghidra's `ParamActive::maxpass` (set from `getMaxInputDelay`,
/// fspec.cc:5335). `0` means the single pass available in today's (non-iterating) pipeline commits
/// immediately, so the recovery stays byte-identical to the old greedy prune; the mainloop flip
/// raises this so the commit DEFERS until heritage + simplification have stabilized across passes.
///
/// ⚠️ THIS IS THE ONLY DORMANT MAXPASS — the RETURN side is already faithful. Measured on the
/// pinned x86-64 SysV model: the INPUT list is 15 entries whose max space delay is **1** (the lone
/// `stack` overflow entry, base 0x8 size 500 align 8; every register entry is delay 0), so Ghidra's
/// `initActiveInput` gives it `maxPass = 3` and a call needs FOUR evaluations to commit. The OUTPUT
/// list is 4 entries, ALL register, max delay **0**, so `Funcdata::initActiveOutput`
/// (funcdata_varnode.cc:585-592, ported verbatim in [`init_active_output`] including the `>0 => 3`
/// cap) gives it `maxPass = 0` and it commits on pass 1. So the return side needs no repeat
/// scheduling and gets Ghidra's own answer from the single `ActionResolveCalls`; the input side
/// cannot, and that asymmetry is a property of the CONVENTIONS (an input stack area exists, an
/// output one does not), not an accident of mosura's pipeline.
const CALL_MAXPASS: i32 = 0;

/// Commit the recovered return value on every RETURN — a port of Ghidra's `ActionReturnRecovery`
/// (coreaction.cc:1907). The candidate trials were registered during heritage by
/// [`super::heritage::guard_returns`] (`characterizeAsOutput` over each heritaged range); this
/// evaluates them ([`check_output_trial_use`]) and, once they are *fully checked*
/// (`numpasses > maxpass`), maps them onto the convention's output storage
/// ([`derive_output_map`], Ghidra `FuncProto::deriveOutputMap`) and rewrites each RETURN
/// ([`build_return_output`]). The deferral means a premature decision on an unstable early-pass
/// graph can't irreversibly drop a real return. Runs post-heritage.
///
/// Returns the change count per Ghidra's `ActionReturnRecovery::apply` convention: +1 per
/// not-yet-checked trial evaluated (coreaction.cc:1933) and +1 when the fully-checked trials commit
/// the structural rewrite (coreaction.cc:1951) — so a repeating group sees work-in-progress as
/// change, and quiescence (trials committed, container cleared) as 0.
pub fn resolve_return(f: &mut Funcdata) -> u32 {
    if f.active_output.is_none() {
        return 0; // coreaction.cc:1911 — recovery already committed (or never opened)
    }
    let mut count = check_output_trial_use(f);
    if f.active_output.as_ref().is_some_and(|a| a.is_fully_checked()) {
        if let Some(outlist) = f.proto_model.output.clone() {
            // Record how much of the return storage this function was found to produce, before
            // the evidence is optimized away (see `Funcdata::output_storage_size`).
            f.output_storage_size = derive_output_map(&outlist, f.active_output.as_mut().unwrap());
        }
        build_return_output(f);
        f.active_output = None; // Ghidra `Funcdata::clearActiveOutput`
        count += 1; // coreaction.cc:1951 — the commit is a change
    }
    count
}

/// Ghidra `ActionReturnRecovery::apply` evaluation loop (coreaction.cc:1916): mark every not-yet-
/// checked trial whose candidate passes BOTH return-trial gates at some RETURN (coreaction.cc:1930-
/// 1931 — `AncestorRealistic::execute` AND `ancestorOpUse`, here [`return_trial_kept`]) as active; a
/// candidate that fails either gate is left unchecked so a later pass can reconsider it as the
/// dataflow refines. Then advance the pass counter and, once `numpasses > maxpass`, mark the
/// container fully checked (which gates the commit).
///
/// Returns +1 per not-yet-checked trial evaluated — Ghidra's unconditional `count += 1` inside the
/// per-RETURN trial loop (coreaction.cc:1933), with mosura's RETURN iteration fused into the
/// `any()`. Checked trials contribute 0, so the count bottoms out once every trial is decided.
fn check_output_trial_use(f: &mut Funcdata) -> u32 {
    let rets: Vec<OpId> = f.op_ids().filter(|&op| !f.op(op).is_dead() && f.op(op).code() == OpCode::Return).collect();
    let ntrials = f.active_output.as_ref().map_or(0, |a| a.num_trials());
    let mut count = 0u32;
    let mut verdicts: Vec<usize> = Vec::new(); // indices of trials found realistic this pass
    for ti in 0..ntrials {
        let (checked, slot) = {
            let t = &f.active_output.as_ref().unwrap().trial[ti];
            (t.flags & trial_flags::CHECKED != 0, t.op_slot as usize)
        };
        if checked {
            continue;
        }
        count += 1; // coreaction.cc:1933 — an unchecked trial evaluation is a change
        // MARK `tail_return_write` (`Funcdata::tail_return_write`, from the original's bytes):
        // the EAX trial is kept on the bytes' word — every return path writes EAX right
        // before its epilogue — where `ancestorOpUse` would discard a value that is also
        // consumed elsewhere (the buffer a function fills AND returns).
        let forced = f.tail_return_write && {
            let t = &f.active_output.as_ref().unwrap().trial[ti];
            Some(t.addr.space) == f.spaces.by_name("register") && t.addr.offset == 0 && t.size == 4
        };
        let kept = forced || rets.iter().any(|&ret| return_trial_kept(f, ret, slot));
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
    count
}

/// Ghidra `ActionReturnRecovery::buildReturnOutput` (coreaction.cc:1836): rewrite each RETURN to
/// carry exactly the recovered return value. The used trials (marked by [`derive_output_map`], in
/// `sortTrials` order) name the RETURN input slots that hold it; every other candidate input is
/// dropped, so the scratch-register writes that fed them die as dead code.
///
/// A MULTI-PIECE verdict — the return storage heritaged (or lane-lifted) as separate pieces, each
/// its own trial — is reassembled with a `PIECE` op inserted before the RETURN, whose output is a
/// single varnode spanning the whole (coreaction.cc:1850-1867 two-piece case, :1869-1904 the
/// several-piece chain), `writeMask`ed so the new varnode causes no additional heritage. This is
/// what turns a 4-byte-lane `movaps` return setup back into the convention's whole return register:
/// mixfloatint's `addsd` sum reaches its RETURN as two 4-byte XMM0 lane trials, the PIECE rebuilds
/// the 8-byte `XMM0_Qa` value, and `RuleHumptyDumpty` then collapses `PIECE(SUB(sum,4),SUB(sum,0))`
/// into the sum itself — Ghidra's own trace fires exactly that extra HumptyDumpty at the RETURN.
/// Without the branch the RETURN kept only the least-significant lane and the prototype degraded to
/// a truncated `SUB84(...)` integer return.
///
/// The whole's address: Ghidra asks `constructJoinAddress` (translate.cc:817), which for pieces
/// that are CONTIGUOUS in a little-endian space answers the low piece's address (checking a whole
/// register of the combined size is actually named there before skipping the join space). mosura's
/// used trials can only be contiguous pieces of the ONE entry [`derive_output_map`] selected — a
/// register the compiler spec names — so the low address IS that check's answer; the formal
/// JoinRecord branch (non-contiguous pieces, i.e. a register-PAIR return convention) needs join-
/// space support mosura lacks and commits the least-significant piece only, exactly as the same
/// case in [`build_call_output_from_trials`] does.
fn build_return_output(f: &mut Funcdata) {
    // The used trials, in trial order — Ghidra breaks at the first not-used trial (coreaction.cc:1843).
    let used: Vec<(u32, Address, u32)> = {
        let active = f.active_output.as_ref().unwrap();
        (0..active.num_trials())
            .map_while(|i| {
                let t = &active.trial[i];
                t.is_used().then_some((t.op_slot, t.addr, t.size))
            })
            .collect()
    };
    for ret in live_returns(f) {
        let n = f.op(ret).num_inputs();
        // The used trials' varnodes at this RETURN — Ghidra's `newparam` past the slot-0
        // return-address reference, stopping at a slot past this op's inputs (coreaction.cc:1846).
        let mut pieces: Vec<(VarnodeId, Address, u32)> = Vec::new();
        for &(slot, addr, size) in &used {
            if (slot as usize) >= n {
                break;
            }
            pieces.push((f.op(ret).input(slot as usize).unwrap(), addr, size));
        }
        let value: Option<VarnodeId> = match pieces.as_slice() {
            // Easy zero or one return varnode case (coreaction.cc:1848).
            [] => None,
            &[(vn, _, _)] => Some(vn),
            // Two piece concatenation case (coreaction.cc:1850): trial 0 is the least-significant
            // piece, trial 1 the most-significant (`sortTrials` order).
            &[(lovn, lo_a, lo_s), (hivn, hi_a, hi_s)] => {
                if lo_a.space == hi_a.space && lo_a.offset.wrapping_add(lo_s as u64) == hi_a.offset {
                    let seq = f.op(ret).seqnum;
                    let newop = f.new_op(OpCode::Piece, seq, vec![hivn, lovn]);
                    let whole = f.new_output(newop, lo_s + hi_s, lo_a);
                    f.vn_mut(whole).set_write_mask(); // coreaction.cc:1861
                    f.op_insert_before(newop, ret);
                    Some(whole)
                } else {
                    Some(lovn) // JoinRecord case — unported (see above)
                }
            }
            // Several varnodes from a single container (coreaction.cc:1869): concatenate the
            // contiguous run into a single result, one PIECE per step, breaking at the first gap.
            _ => {
                let (mut preexist, cur_a, mut cur_s) = pieces[0];
                for &(vn, a, s) in &pieces[1..] {
                    if a.space != cur_a.space || cur_a.offset.wrapping_add(cur_s as u64) != a.offset
                    {
                        break; // coreaction.cc:1899 — offmatch mismatch ends the run
                    }
                    let seq = f.op(ret).seqnum;
                    let newop = f.new_op(OpCode::Piece, seq, vec![vn, preexist]);
                    let whole = f.new_output(newop, cur_s + s, cur_a);
                    f.vn_mut(whole).set_write_mask(); // coreaction.cc:1892
                    f.op_insert_before(newop, ret);
                    preexist = whole;
                    cur_s += s;
                }
                Some(preexist)
            }
        };
        // opSetAllInput(retop, newparam): slot 0 (the return-address reference) plus the value.
        for slot in (1..n).rev() {
            f.op_remove_input(ret, slot);
        }
        if let Some(v) = value {
            f.op_append_input(ret, v);
        }
    }
}

/// The live RETURN ops of `f`, in block/op order — Ghidra's `beginOp(CPUI_RETURN)` walk.
fn live_returns(f: &Funcdata) -> Vec<OpId> {
    f.op_ids().filter(|&op| !f.op(op).is_dead() && f.op(op).code() == OpCode::Return).collect()
}

/// Open argument recovery on every call — a port of Ghidra `FuncCallSpecs::initActiveInput`
/// (fspec.cc:5330), called from `ActionFuncLink::funcLinkInput` (coreaction.cc:1483) for every
/// sub-function whose prototype is not input-locked. Creates the (empty) per-call trial container
/// and sets its pass budget from the convention's `getMaxInputDelay`. Runs pre-heritage.
///
/// The trials themselves are registered DURING heritage, by [`super::heritage::guard_calls`] asking
/// `characterizeAsInputParam` of each heritaged range at each call site (heritage.cc:1495). This
/// RETIRES `recover_call_args`, the input-side twin of the retired `recover_return`: it appended
/// hardcoded x86-64 `RDI…R9` varnodes at width 8 to every CALL. On x86-32 those offsets are not the
/// argument registers at all — `0x10:8` spans ESP *and* EBP, `0x8:8` spans EDX *and* EBX, and the
/// other four land in non-GPR register space — so every call site grew six spurious wide reads over
/// ranges no instruction writes.
pub fn init_active_input(f: &mut Funcdata) {
    let reg = f.spaces.by_name("register");
    let maxdelay = f.called_model().max_input_delay(&f.spaces);
    let calls: Vec<OpId> = f
        .op_ids()
        .filter(|&op| !f.op(op).is_dead() && matches!(f.op(op).code(), OpCode::Call | OpCode::Callind))
        .collect();
    // Ghidra `ActionFuncLink::funcLinkInput` (coreaction.cc:1479): a non-null `getSpacebase()` on the
    // convention's input list is exactly the signal "this call site needs a stack-pointer
    // placeholder" — i.e. the convention can pass parameters on the stack, so the offset of the stack
    // pointer at each call has to be recovered before any stack range can be tried as an argument.
    let spacebase = f.called_model().input.as_ref().and_then(|pl| pl.get_spacebase(&f.spaces));
    for call in calls {
        // Ghidra `ActionFuncLink::funcLinkInput`'s INPUT-LOCKED branch (coreaction.cc:1485-1509):
        // a call whose callee's prototype is KNOWN builds its inputs directly from that prototype
        // and never opens trial recovery — `initActiveInput` is gated `(!inputlocked)||varargs`
        // (:1482), so `isInputActive` stays false and neither `guardCalls`' trial registration nor
        // `checkInputTrialUse` ever runs on the call. mosura's input-lock is a RECOVERED callee
        // prototype (`CallSpec::reads_recovered` — the whole-program pass's port of the database
        // prototype `ActionDefaultParams` would copy).
        //
        // Register-only prototypes take this branch; a prototype naming STACK storage keeps the
        // trial path, whose stack-argument handling is measured and fixed (the anchored
        // placeholder). Ghidra's locked branch covers stack parameters too (the `opStackLoad`
        // arm); porting that half retires the trial override entirely and is the follow-on.
        //
        // What the pre-built input buys beyond skipping the trials: the varnode is created at the
        // PROTOTYPE's width, pre-heritage, so the heritage range for the register is at least that
        // wide. Trials get their width from the heritaged range instead — the width of whatever
        // the caller happens to read elsewhere. Measured on WAR2's `FUN_00015224` family: the
        // caller's only EAX read is the callee's 1-byte return (`test al,al`), so the heritage
        // range is AL, the trial commits 1 byte, the caller's own parameter comes out `xunknown1`,
        // and Watcom materializes the byte with an `AND EAX,0xff` the original does not have. The
        // callee's own prototype says 4; building the input at 4 passes the register through
        // untouched.
        let mut active = ParamActive::new(reg);
        active.is_recover_subcall = true;
        // fspec.cc:5335 — `maxdelay = getMaxInputDelay(); if (maxdelay > 0) maxdelay = 3;`
        active.set_max_pass(if maxdelay > 0 { 3 } else { CALL_MAXPASS });
        // The container goes in FIRST: `createPlaceholder` -> `setStackPlaceholderSlot` reserves
        // the slot on the trial container too (fspec.hh:1671), and mosura's `isInputActive` test
        // is the presence of this entry.
        f.active_inputs.insert(call, active);
        locked_register_inputs(f, call);
        if let Some(sb) = spacebase {
            // coreaction.cc:1511-1512. For a locked call this still runs — Ghidra skips the
            // placeholder only when a locked STACK parameter carried the spacebase flag instead
            // (:1500-1505), and the register-only locked calls handled above have none.
            super::fspec::create_placeholder(f, call, sb);
        }
    }
}

/// Ghidra `ActionFuncLink::funcLinkInput`'s locked-with-varargs shape (coreaction.cc:1485-1498
/// under `isDotdotdot`), register half: register one trial per recovered parameter at the
/// PROTOTYPE's storage and width, `markActive` it (Ghidra :1491 — "Parameter is not optional",
/// which also marks it CHECKED, locking the verdict), and append the matching free input varnode.
/// The container stays open, so `guard_calls` keeps offering ranges and call-site evidence can ADD
/// arguments beyond the prototype.
///
/// The varargs shape rather than the plain locked one, deliberately: a recovered prototype is
/// USE-based — the callee's body is authoritative about the parameters it reads and blind to the
/// ones it merely receives — so it UNDER-states. Locking to it drops arguments the caller plainly
/// passes: measured on WAR2, the plain-locked form lost 25 functions, e.g.
/// `func_0x0004c978(0xbe6, 0x4921c)` truncated to one argument because the callee never touches
/// its second parameter. The union (prototype as a floor, extras by evidence) is the monotone rule
/// this campaign already measured, expressed through Ghidra's own varargs machinery.
///
/// What the pre-built input buys beyond the locked verdict: the varnode is created at the
/// PROTOTYPE's width, pre-heritage, so the register's heritage range is at least that wide.
/// Organic trials get their width from the heritaged range — the width of whatever the caller
/// happens to read elsewhere. Measured on WAR2's `FUN_00015224` family: the caller's only EAX read
/// is the callee's 1-byte return (`test al,al`), so the range was AL, the trial committed 1 byte,
/// the caller's own parameter came out `xunknown1`, and Watcom materialized the byte with an
/// `AND EAX,0xff` the original does not have. The prototype says 4; the pre-built input passes the
/// register through untouched.
///
/// A prototype naming STACK storage keeps the plain trial path (whose stack handling is measured
/// and fixed — the anchored placeholder); porting the `opStackLoad` arm is the follow-on.
fn locked_register_inputs(f: &mut Funcdata, call: OpId) -> bool {
    let pc = f.op(call).seqnum.pc.offset;
    let Some(cs) = f.call_specs.get(&call) else {
        debug!(crate::debug::Topic::Args, "call@{pc:#x} no call_spec");
        return false;
    };
    if !cs.reads_recovered {
        debug!(crate::debug::Topic::Args, "call@{pc:#x} reads_recovered=false");
        return false;
    }
    let Some(reads) = cs.reads.clone() else { return false };
    let Some(reg) = f.spaces.by_name("register") else { return false };
    if reads.is_empty() || !reads.iter().all(|(a, _)| a.space == reg) {
        debug!(crate::debug::Topic::Args, "call@{pc:#x} reads empty or non-register");
        return false;
    }
    debug!(crate::debug::Topic::Args, "call@{pc:#x} locking {} register params", reads.len());
    for (addr, sz) in reads {
        let ti = {
            let active = f.active_inputs.get_mut(&call).expect("container inserted first");
            let ti = active.register_trial(addr, sz);
            active.trial[ti].mark_active();
            ti
        };
        let invn = f.new_varnode(sz, addr);
        f.op_append_input(call, invn);
        let slot = f.op(call).num_inputs() - 1;
        f.active_inputs.get_mut(&call).unwrap().trial[ti].op_slot = slot as u32;
    }
    true
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
///
/// Returns the change count per Ghidra's `ActionActiveParam::apply` convention: per call, +1 while
/// the trials are not yet fully checked ("Count a change, to indicate we still have work to do",
/// coreaction.cc:1748) and +1 when the fully-checked trials commit the prune (coreaction.cc:1756).
/// NOTE (loop-join prerequisite, campaign Brick E): Ghidra re-enters a call only while
/// `fc->isInputActive()` — the container, created once by heritage's guardCalls, is never
/// re-initialized after `clearActiveInput`. mosura's [`setup_active_input`] re-creates a cleared
/// container, so a *repeating* caller would re-commit (and re-count) every pass; joining a repeating
/// group requires porting the isInputActive once-gate along with the full pass protocol.
/// Ghidra `Funcdata::sortCallSpecs` (funcdata.cc:516) + `compareCallspecs` (funcdata.cc:504): the
/// call sites in dominance (block-index) order, "so that earlier calls get evaluated first. Order
/// affects parameter analysis." This ordering is load-bearing: a value flowing to TWO calls (a
/// cross-block double-use) is attributed to whichever call [`resolve_call_args`] evaluates FIRST —
/// its trial commits `markActive`, and the later call's `check_call_double_use` then sees that
/// active trial and yields the value (`checkCallDoubleUse`, funcdata_varnode.cc:1787). Ghidra keys
/// on the structured block index (`getParent()->getIndex()`, the reverse-post-order Ghidra's
/// `structureReset`/`findSpanningTree` assigns) then the op's within-block order. mosura numbers its
/// `BlockId`s by ADDRESS (a non-Ghidra adaptation, cfg.rs:256), so the faithful key is the block's
/// reverse-postorder position — the same DFS-over-out-edges RPO the spanning tree computes, from
/// [`super::dominator::postorder`] — then [`block_pos`] within the block. deindirect/indproto share
/// one parameter setup between two sibling calls; the else-branch call sits in the block Ghidra (and
/// mosura's RPO) indexes FIRST though its address is HIGHER, so address-order evaluation picked the
/// wrong call. (Ghidra sorts once in `startProcessing` after `structureReset`; mosura's CFG is stable
/// across the mainloop, so recomputing the order per invocation yields the same fixed sequence.)
fn call_specs_in_dominance_order(f: &Funcdata) -> Vec<OpId> {
    let nb = f.num_blocks();
    let po = super::dominator::postorder(f);
    let mut rpo_num = vec![usize::MAX; nb];
    for (i, &b) in po.iter().rev().enumerate() {
        rpo_num[b] = i;
    }
    let mut calls: Vec<OpId> =
        f.op_ids()
        .filter(|&op| !f.op(op).is_dead() && matches!(f.op(op).code(), OpCode::Call | OpCode::Callind))
        .collect();
    calls.sort_by_key(|&op| {
        let ridx = f
            .op(op)
            .parent
            .and_then(|b| rpo_num.get(b.0 as usize).copied())
            .unwrap_or(usize::MAX);
        (ridx, block_pos(f, op))
    });
    calls
}

pub fn resolve_call_args(f: &mut Funcdata) -> u32 {
    let mut count = 0u32;
    let calls: Vec<OpId> = call_specs_in_dominance_order(f);
    // Ghidra `ActionActiveParam::apply` (coreaction.cc:1731): one deferred `AliasChecker` over the
    // function's stack space for the whole pass; `checkInputTrialUse` asks it about every stack
    // trial, and the escapes are gathered at the first question, from the graph as it stands then.
    let stack_space = f.spaces.by_name("stack");
    let mut aliascheck = AliasChecker::gather(f, stack_space, true);
    // Set up EVERY call's trial container before checking any (Ghidra creates each `FuncCallSpecs`'
    // `ParamActive` at heritage-time `guardCalls`, so all are `isInputActive` during
    // `ActionActiveParam`). `check_call_double_use`/`checkCallDoubleUse` (funcdata_varnode.cc:1756)
    // consults the OTHER call's active trials to accept a legitimate cross-call double-use — a value
    // (e.g. piecestruct's `&xStack_18`) that append-all leaves on a second, non-consuming call must
    // not be rejected as a competing use, which drops the real arg on the first call. mosura's old
    // per-call setup+check loop left a not-yet-processed callee's container absent, so the double-use
    // was spuriously rejected.
    for call in calls {
        // Ghidra `ActionActiveParam::apply` (coreaction.cc:1739) does everything below under
        // `if (fc->isInputActive())`. mosura's `isInputActive` is the presence of the call's entry
        // in `active_inputs`: `init_active_input` creates it and the `clearActiveInput` below
        // removes it. The gate used to be unnecessary because the retired `setup_active_input`
        // re-created the container from the CALL's input slots on every pass, so a call that had
        // already committed its arguments silently re-entered trial evaluation.
        if !f.is_input_active(call) {
            continue;
        }
        // A call whose CALLEE PROTOTYPE HAS BEEN RECOVERED is not a candidate list to be tested.
        // `derive_input_map` already says so ("its entries are not candidates to be tested — they
        // are facts") and re-marks the matching trials active — but by then the damage is done,
        // because `check_input_trial_use` runs FIRST and its `markNoUse` verdict does not merely
        // mark: it FREES THE DATAFLOW, setting the input slot to a constant 0 (fspec.cc:5650-5651).
        // Re-marking a trial cannot restore a varnode that has been replaced by a constant.
        //
        // Measured on `FUN_00013c50` with the `proto-pass` switch on. Heritage binds the argument
        // correctly to `r0x0:4(0x13c5e:12)` — the output of the call five instructions earlier,
        // which is the value the original passes by doing nothing at all. That value has other
        // readers, so `ancestorOpUse` cannot say "used only to feed this call", the trial is freed,
        // and the call commits `func_0x0005a48c(0)`. Watcom then emits the `XOR EAX,EAX` that the
        // original does not have. Ghidra, asked with the callee's parameter forced, emits
        // `FUN_0005a48c(forced_1)`.
        //
        // Ghidra never reaches that path. `ActionDefaultParams` copies the callee's recovered
        // prototype onto the call (coreaction.cc:2327), which leaves it NOT input-active, and
        // `ActionActiveParam` does all of its work under `if (fc->isInputActive())` — so
        // `checkInputTrialUse` never runs on a call whose prototype is known. Skipping the realism
        // check here is that same gate, expressed where mosura keeps the recovered list.
        check_input_trial_use(f, call, &mut aliascheck);
        if f.active_inputs.get(&call).is_some_and(|a| a.is_fully_checked()) {
            // `ActionActiveParam::apply`: a call slated by a conditional-execution effect gets
            // its final realism pass before the commit.
            if f.active_inputs[&call].needs_final_check() {
                final_input_check(f, call);
            }
            // coreaction.cc:1752-1754 — deriveInputMap decides which trials are the parameters and
            // leaves them in parameter order; buildInputFromTrials then commits that list.
            derive_input_map(f, call);
            build_input_from_trials(f, call);
            // Ghidra `FuncCallSpecs::clearActiveInput` (fspec.hh:1696) flips a flag and KEEPS the
            // trials, so the call can be re-opened later with everything it learned. mosura used
            // to remove the container here, which is what made the ordering defect unrecoverable.
            if let Some(a) = f.active_inputs.get_mut(&call) {
                a.active = false;
            }
            count += 1; // coreaction.cc:1756 — the commit is a change
        } else {
            count += 1; // coreaction.cc:1748 — trials still being evaluated: work to do
        }
    }
    count
}

// `setup_active_input` is gone: it rebuilt each call's trial container from the CALL's input slots
// on every pass, which only worked because `recover_call_args` had appended a fixed candidate list
// pre-heritage. The container is now created once by [`init_active_input`] and its trials are
// registered during heritage by `guard_calls`' `characterizeAsInputParam` query
// (heritage.cc:1495), exactly as Ghidra does.

/// Ghidra `FuncCallSpecs::checkInputTrialUse` (fspec.cc:5585) — the register (non-spacebase) branch
/// (fspec.cc:5638-5651). Each not-yet-checked argument trial gets one of three verdicts:
///   - `AncestorRealistic::execute` accepts it (the value has a realistic caller-set ancestor — a
///     top-level input trial is rejected, but an input reached *through* a copy chain is accepted,
///     [`AncestorRealistic`]) AND [`ancestor_op_use`] confirms it is used only to feed this call ⇒
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
fn check_input_trial_use(f: &mut Funcdata, call: OpId, aliascheck: &mut AliasChecker) {
    /// Trial disposition, in Ghidra's `ParamTrial` terms.
    enum Verdict {
        Active,   // markActive — a genuine argument
        Inactive, // markInactive — dataflow PRESERVED (may still be a parameter)
        NoUse,    // markNoUse — dataflow FREED (definitely not an argument)
    }
    // Storage the CALLEE'S OWN recovered prototype says it reads. A trial at one of these is not a
    // candidate to be tested — see the note in `resolve_call_args`.
    let recovered: Vec<(Address, u32)> =
        f.call_specs.get(&call).and_then(|cs| cs.reads.clone()).unwrap_or_default();
    let ntrials = f.active_inputs.get(&call).map_or(0, |a| a.num_trials());
    // fspec.cc:5585-5598 — when the model's extrapop is unknown (`__watcall`), the callee's own
    // recovered extrapop is HARD evidence about which stack trials are active: a callee that pops
    // its parameters pops exactly the bytes they occupy. (`getExtraPop`, not the effective one —
    // "too unreliable"; an extrapop of 4 might be a _cdecl convention and does not necessarily
    // mean that there are no parameters.) mosura's `CallSpec::extrapop` is the callee's `RET n`
    // plus the return-address slot, `None` when unknown — Ghidra's `extrapop_unknown`.
    // (`hasModel()`: mosura's function always carries a model.)
    let mut callee_pop = f.called_model().extrapop == EXTRAPOP_UNKNOWN;
    let mut expop: i32 = 0;
    if callee_pop {
        expop = f.call_specs.get(&call).and_then(|cs| cs.extrapop).unwrap_or(EXTRAPOP_UNKNOWN);
        if expop == EXTRAPOP_UNKNOWN || expop <= 4 {
            callee_pop = false;
        }
    }
    // How many trials this evaluation actually sees. Print it beside the `[trials]` line from
    // `build_input_from_trials` and the two must agree: a trial registered after the evaluation
    // has run is never given a verdict, and an unevaluated trial is dropped from the argument
    // list. The two counts disagreeing is the whole diagnosis for a silently missing argument.
    if crate::debug::on(crate::debug::Topic::Args) {
        let seen: Vec<String> = f.active_inputs[&call]
            .trial
            .iter()
            .map(|t| format!("{}+{:#x}/{}", f.spaces.get(t.addr.space).name, t.addr.offset, t.size))
            .collect();
        debug!(crate::debug::Topic::Args,
            "call@{:#x} ntrials={ntrials} [{}]",
            f.op(call).seqnum.pc.offset,
            seen.join(" ")
        );
    }
    // Each unchecked trial is evaluated, marked and (for `markNoUse`) freed IN-LOOP — Ghidra's
    // sequential semantics (both the marking and the constant-0 free happen inside the trial loop,
    // fspec.cc:5613-5651) — so a later trial's [`check_call_double_use`] sees the verdicts of the
    // trials evaluated before it (the `isChecked`/`isActive` branch, funcdata_varnode.cc:1787).
    for ti in 0..ntrials {
        let (checked, slot, killed_by_call) = {
            let t = &f.active_inputs[&call].trial[ti];
            (t.flags & trial_flags::CHECKED != 0, t.op_slot as usize, t.flags & trial_flags::KILLEDBYCALL != 0)
        };
        if checked {
            continue;
        }
        // INSTRUMENT: the trial's actual input varnode and its def, so a wrong verdict names
        // its evidence (the flags alone cannot distinguish "wrong input wired" from "right
        // input judged wrong").
        if crate::debug::on(crate::debug::Topic::Args) {
            let d = f.op(call).input(slot).map(|v| {
                let vn = f.vn(v);
                let def = vn.def.map(|d| format!("{:?}@{:#x}:{}", f.op(d).code(), f.op(d).seqnum.pc.offset, f.op(d).seqnum.uniq));
                format!(
                    "{}+{:#x}/{} written={} def={:?}",
                    f.spaces.get(vn.loc.space).name, vn.loc.offset, vn.size, vn.is_written(), def
                )
            });
            debug!(crate::debug::Topic::Args,
                "call@{:#x} trial#{ti} slot={slot} kbc={killed_by_call} input={:?}",
                f.op(call).seqnum.pc.offset, d
            );
        }
        let verdict = match f.op(call).input(slot) {
            None => Verdict::NoUse,
            Some(v) => {
                // Ghidra branches on the trial varnode's space (fspec.cc:5600-5650). A stack
                // (spacebase) trial, fspec.cc:5605-5622: a slot the callee can reach through an
                // escaped pointer (`hasLocalAlias`) is no-use; so is one outside the model's local
                // range (the caller's own incoming-parameter slots); when the callee's recovered
                // extrapop is known (`callee_pop`) the trials INSIDE the popped bytes are active
                // and the rest no-use, with no realism walk at all; otherwise `AncestorRealistic`
                // runs with `allowFail = false` and an unrealistic stack trial is no-use. A register
                // trial runs with `allowFail = true`, and an unrealistic INPUT is merely inactive
                // ("not likely a parameter but maybe"). A trial that passes under a
                // conditional-execution effect slates the call for [`final_input_check`].
                let is_stack = f.spaces.get(f.vn(v).loc.space).kind == SpaceKind::Spacebase;
                let vn_is_input = f.vn(v).is_input();
                let mut trial = f.active_inputs[&call].trial[ti].clone();
                let stack_pretest = if !is_stack {
                    None
                } else if aliascheck.has_local_alias(f, v) {
                    Some((Verdict::NoUse, "hasLocalAlias"))
                } else if !f.proto_model.localrange.in_range(f.vn(v).loc, 1) {
                    Some((Verdict::NoUse, "localrange"))
                } else if callee_pop {
                    let end = trial.addr.offset.wrapping_add((trial.size - 1) as u64) as i32;
                    Some((if end < expop { Verdict::Active } else { Verdict::NoUse }, "callee_pop"))
                } else {
                    None
                };
                if let Some((verdict, why)) = stack_pretest {
                    debug!(crate::debug::Topic::Args,
                            "call@{:#x} trial#{ti} slot={slot} vn=stack+{:#x} {why} callee_pop={callee_pop} expop={expop} alias_boundary={:#x} alias={:x?} -> {}",
                            f.op(call).seqnum.pc.offset,
                            f.vn(v).loc.offset,
                            aliascheck.alias_boundary(),
                            aliascheck.alias(),
                            match verdict { Verdict::Active => "active", Verdict::Inactive => "inactive", Verdict::NoUse => "nouse" }
                        );
                    verdict
                } else {
                let realistic = AncestorRealistic::new().execute(f, call, slot, &mut trial, !is_stack);
                // Carry the flags the walk set (`indcreate_formed`, `condexe_effect`,
                // `ancestor_realistic`, `ancestor_solid`) back onto the live trial.
                f.active_inputs.get_mut(&call).unwrap().trial[ti].flags = trial.flags;
                if realistic {
                    let addr = f.vn(v).loc;
                    let aou = ancestor_op_use(
                        f, TRIM_RECURSE_MAX, v, call, slot, 0, 0, addr, false, &mut HashSet::new(),
                    );
                    debug!(crate::debug::Topic::Args, "call@{:#x} trial#{ti} slot={slot} -> {aou}", f.op(call).seqnum.pc.offset);
                    if aou {
                        if trial.has_cond_exe_effect() {
                            f.active_inputs.get_mut(&call).unwrap().mark_needs_final_check();
                        }
                        Verdict::Active
                    } else {
                        Verdict::Inactive
                    }
                } else if vn_is_input && !is_stack {
                    Verdict::Inactive
                } else {
                    Verdict::NoUse
                }
                }
            }
        };
        // Free the dataflow of a definitely-not-used (`markNoUse`) slot only; `markInactive`
        // preserves its dataflow (Ghidra frees only when `trial.isDefinitelyNotUsed()`,
        // fspec.cc:5649-5651).
        // A trial the callee's recovered prototype names is an argument by the callee's own
        // evidence, and no realism verdict taken at this one call site overrides that. Ghidra
        // reaches the same place by not running this check at all on a call whose prototype was
        // copied from the callee.
        let verdict = {
            let t = &f.active_inputs[&call].trial[ti];
            if recovered.iter().any(|&(a, sz)| a == t.addr && sz >= t.size) {
                Verdict::Active
            } else {
                verdict
            }
        };
        if matches!(verdict, Verdict::NoUse) {
            if let Some(v) = f.op(call).input(slot) {
                if !f.vn(v).is_constant() {
                    let size = f.vn(v).size;
                    let zero = f.new_const(size, 0);
                    f.op_set_input(call, slot, zero);
                }
            }
        }
        let active = f.active_inputs.get_mut(&call).unwrap();
        match verdict {
            Verdict::Active => active.trial[ti].mark_active(),
            Verdict::Inactive => active.trial[ti].mark_inactive(),
            Verdict::NoUse => active.trial[ti].mark_no_use(),
        }
    }
    if crate::debug::on(crate::debug::Topic::Args) {
        let v: Vec<String> = f.active_inputs[&call]
            .trial
            .iter()
            .map(|t| {
                format!(
                    "{}+{:#x}/{}{}{}{}",
                    f.spaces.get(t.addr.space).name,
                    t.addr.offset,
                    t.size,
                    if t.flags & trial_flags::CHECKED != 0 { "C" } else { "-" },
                    if t.is_active() { "A" } else { "-" },
                    if t.is_definitely_not_used() { "D" } else { "-" },
                )
            })
            .collect();
        debug!(crate::debug::Topic::Args, "verdict call@{:#x} [{}]", f.op(call).seqnum.pc.offset, v.join(" "));
    }
    let active = f.active_inputs.get_mut(&call).unwrap();
    active.finish_pass();
    if active.get_num_passes() > active.get_max_pass() {
        active.mark_fully_checked();
    }
}

/// Ghidra `FuncCallSpecs::finalInputCheck` (fspec.cc:5565): trials marked active under a
/// conditional-execution effect are re-run through [`AncestorRealistic`] with no failing path
/// allowed, now that the control-flow has settled; one that no longer passes is marked no-use.
fn final_input_check(f: &mut Funcdata, call: OpId) {
    let mut ancestor_real = AncestorRealistic::new();
    let n = f.active_inputs[&call].num_trials();
    for i in 0..n {
        let mut trial = f.active_inputs[&call].trial[i].clone();
        if !trial.is_active() || !trial.has_cond_exe_effect() {
            continue;
        }
        let slot = trial.op_slot as usize;
        if !ancestor_real.execute(f, call, slot, &mut trial, false) {
            trial.mark_no_use();
        }
        f.active_inputs.get_mut(&call).unwrap().trial[i] = trial;
    }
}

/// Ghidra `FuncCallSpecs::deriveInputMap` (fspec.hh:1494 → `ProtoModel::deriveInputMap`,
/// fspec.hh:791 → `ParamListStandard::fillinMap`, fspec.cc:1285): decide which of the accumulated
/// trials are the actual parameters. Matches each trial to a convention entry, fills the holes,
/// enforces the exclusion/no-hole rules per resource section, marks the survivors `used`, and —
/// through `build_trial_map`'s `sort_trials` — leaves the trials in FORMAL PARAMETER ORDER.
///
/// The function and return sides have always gone through this; the call side had not, because the
/// retired `recover_call_args` appended its fixed `RDI…R9` list in argument order and made op-slot
/// order coincide with parameter order. It does not coincide once the candidates come from
/// heritage, which walks the register space in ADDRESS order (`RDX` at `0x10` before `RDI` at
/// `0x38`). (Ghidra calls `resolveModel` first, coreaction.cc:1752, to pick between the models of a
/// `ProtoModelMerged`; mosura resolves the CURRENT function's merged model in `ActionInputPrototype`
/// (`fspec::resolve_model`), and a call's model is the callee's — never merged under the specs
/// that declare one (they set no `<eval_called_prototype>`), so nothing is resolved here.)
fn derive_input_map(f: &mut Funcdata, call: OpId) {
    // The callee's OWN input storage where its body could be read (`CallSpec::reads`) — the input
    // half of the per-call prototype, and the twin of [`recovered_output_list`]. It must REPLACE the
    // model's list rather than filter its results: `fillin_map`'s definitely-not-used chain rule
    // (fspec.rs:498-511) latches on the first fully-`dnu` exclusion group and marks every LATER
    // trial inactive, so suppressing a register in the middle of the DEFAULT sequence (EDX, in
    // watcall's EAX/EDX/EBX/ECX) silently takes the recovered registers after it down too. Given the
    // callee's real list the recovered registers are CONSECUTIVE groups and there is no hole for the
    // latch to catch — the rule stays faithful and simply has nothing to fire on.
    // A register-only recovered prototype no longer arrives here as a MODEL: its parameters are
    // pre-registered as fixed active trials with pre-built inputs (`locked_register_inputs`,
    // Ghidra's locked-with-varargs shape), and the CONVENTION list does the union fillin over
    // fixed-plus-organic trials. Substituting the recovered list as the model here would cap the
    // arguments at the prototype — measured at 25 lost functions, because a use-based prototype
    // under-states (a parameter the callee ignores leaves no trace in it). Prototypes naming STACK
    // storage still take the model path below, whose stack handling is separately measured.
    let locked_register = f.call_specs.get(&call).is_some_and(|cs| {
        cs.reads_recovered
            && cs.reads.as_ref().is_some_and(|r| {
                !r.is_empty() && f.spaces.by_name("register").is_some_and(|reg| r.iter().all(|(a, _)| a.space == reg))
            })
    });
    let recovered = if locked_register {
        None
    } else {
        f.call_specs
            .get(&call)
            .and_then(|cs| cs.reads.as_ref())
            .filter(|r| !r.is_empty())
            .map(|r| recovered_input_list(r))
    };
    let committed = recovered.is_some();
    // The CALL'S OWN model's list (Ghidra: `FuncCallSpecs` IS-a `FuncProto`; a caller-cleaned
    // call takes the cspec's `__cdecl` stack-only list, everything else the default convention).
    let Some(input) = recovered.or_else(|| f.input_list_for_call(call).cloned()) else { return };
    // What the convention's own list would have marked used, computed before the mutable borrow.
    // Used below to keep propagation monotone.
    let model_used: Option<std::collections::HashSet<(Address, u32)>> = if committed {
        f.input_list_for_call(call).cloned().and_then(|m| {
            f.active_inputs.get(&call).map(|a| {
                // PRE-FILLIN ACTIVE is the evidence bar. The monotone rule's whole rationale
                // (below) is that the CALL SITE shows an argument the callee ignores "because the
                // caller still has to place the value" — and active-before-fillin is precisely
                // `check_input_trial_use`'s verdict that the value was placed to feed this call.
                // `fillin_map` additionally marks the POSITIONAL HOLES between actives used AND
                // active (an inactive trial sandwiched in the model's group order), which carry
                // no call-site evidence at all; resurrecting one puts a phantom middle argument
                // back after the recovered list correctly excluded it. Measured on regout's
                // `use_ -> bump_` (`add ebx,eax; ret`): trials EAX active, EBX active, EDX a dead
                // passthrough of param_2 — the model probe hole-filled EDX between them and the
                // union re-marked it, emitting `func_0x08048106(xRam..., param_2, param_2)` where
                // the verified reference (and the callee's own two-register prototype) has two
                // arguments.
                let pre_active: std::collections::HashSet<(Address, u32)> =
                    a.trial.iter().filter(|t| t.is_active()).map(|t| (t.addr, t.size)).collect();
                let mut probe = a.clone();
                m.fillin_map(&mut probe);
                probe
                    .trial
                    .iter()
                    .filter(|t| t.is_used() && pre_active.contains(&(t.addr, t.size)))
                    .map(|t| (t.addr, t.size))
                    .collect()
            })
        })
    } else {
        None
    };
    let call_pc = f.op(call).seqnum.pc.offset;
    let Some(active) = f.active_inputs.get_mut(&call) else { return };
    // A recovered list is the CALLEE'S OWN prototype, so its entries are not candidates to be
    // tested — they are facts. Ghidra reaches the same place from the other side: when a call spec
    // has no model of its own, `ActionDefaultParams` does `fc->copy(otherfunc->getFuncProto())`
    // (coreaction.cc:2327), copying the callee's recovered prototype onto the call, after which the
    // arguments no longer depend on trial realism at all.
    //
    // Without this a PASS-THROUGH argument is lost: in `f(x) { g(x); }` the varnode reaching the
    // call IS f's own input, so `AncestorRealistic::execute` takes its `isInput()` early-out
    // (funcdata_varnode.cc:2205 — "we expect to see active movement into the parameter") and the
    // trial is marked INACTIVE, and `fillin_map` only marks ACTIVE trials used. Measured on the
    // regmodify MVE, where `keep` is recovered as `int4 FUN_08048106(int4 param_1)` and the call
    // was still emitted as `func_0x08048106()`.
    if committed {
        for t in active.trial.iter_mut() {
            if input.entry.iter().any(|e| e.justified_contain(t.addr, t.size).is_some()) {
                t.mark_active();
            }
        }
    }
    input.fillin_map(active);

    // INSTRUMENT (`MOSURA_MONO=1`): what propagation did to this call's trials. Prints the trial
    // container AFTER the recovered list was applied, alongside the set the convention's own list
    // would have marked used, so a demotion (used by the model, unused here) is visible directly.
    if crate::debug::on(crate::debug::Topic::Args) {
        let show: Vec<String> = active
            .trial
            .iter()
            .map(|t| {
                let m = model_used.as_ref().is_some_and(|s| s.contains(&(t.addr, t.size)));
                format!(
                    "sp{:?}+{:#x}/{}{}{}",
                    t.addr.space,
                    t.addr.offset,
                    t.size,
                    if t.is_used() { "=used" } else { "=UNUSED" },
                    if m { ",model" } else { "" }
                )
            })
            .collect();
        debug!(crate::debug::Topic::Args,
            "call@{call_pc:#x} committed={committed} recovered_entries={} model_used={} trials=[{}]",
            input.entry.len(),
            model_used.as_ref().map_or(0, |s| s.len()),
            show.join(" ")
        );
    }

    // MONOTONE: a propagated prototype may ADD arguments, never remove them.
    //
    // The callee's body is authoritative about the parameters it USES and blind to the ones it
    // merely RECEIVES — a parameter the callee ignores leaves no trace in it, at any number of
    // propagation rounds, while the call site shows it plainly because the caller still has to
    // place the value. So a recovered list that is NARROWER than the convention's is missing
    // evidence rather than correcting it.
    //
    // Measured over the 104 WAR2 functions whose verdict propagation changes: of the 26 it fixes,
    // 25 gain arguments; of the 78 it breaks, 43 LOSE arguments while only one of the wins does.
    // "Propagation removed an argument" is thus an almost perfect predictor of a regression.
    //
    // The model-derived result is computed on a clone and unioned in by storage, not by index —
    // `fillin_map` synthesizes hole trials, so the two containers need not agree in length or
    // order and zipping them would silently pair the wrong trials.
    if committed {
        if let Some(model_used) = model_used {
            for t in active.trial.iter_mut() {
                if !t.is_used() && model_used.contains(&(t.addr, t.size)) {
                    t.mark_used();
                }
            }
        }
    }
}

/// Ghidra `FuncCallSpecs::buildInputFromTrials` (fspec.cc:5685): rebuild the CALL's input list from
/// the trials [`derive_input_map`] marked `used`, in trial order — which is parameter order. A
/// trial's `op_slot` is used only to FETCH the varnode it already refers to, never to order the
/// arguments (that inversion is what made the old reduction depend on the retired fixed candidate
/// list). Runs once the trials are fully checked, so the prune commits on a stable decision.
///
/// The spacebase `markNotMapped` branch (fspec.cc:5736) is not reachable: `guard_calls` declines to
/// register a trial for a spacebase range at all, lacking `FuncCallSpecs::getSpacebaseOffset`.
///
/// The `isUnref` branch IS reachable and IS ported. It was previously skipped on the premise that
/// "`guard_calls` creates a varnode for every trial it registers" — true, but `build_trial_map`
/// (inside `fillin_map`) registers FURTHER trials that `guard_calls` never saw: the unref holes it
/// synthesizes for argument slots ahead of a used one. `force_inactive_chain`'s tail then marks
/// those holes ACTIVE ("fill in holes of inactive trials"), `fillin_map` marks every active trial
/// USED, and they arrive here with no varnode. Ghidra creates one:
/// ```text
///     if (paramtrial.isUnref())         // recovered unreferenced address as part of prototype
///       vn = data.newVarnode(sz,Address(spc,off));   // We need to create the varnode
/// ```
/// Dropping them instead RENUMBERS the argument list. A call whose only real argument is the
/// watcall SECOND one (EDX) was emitted as a one-argument call, so the recompiled code passes it in
/// EAX — the original's `add edx,0x12 ; call` came back as `lea eax,[edx+0x12] ; call`. That shape
/// is the single most common first divergence among WAR2's near-miss functions. It is the exact
/// call-site twin of the signature defect fixed in `printc::rendered_param_slots`.
fn build_input_from_trials(f: &mut Funcdata, call: OpId) {
    // fspec.cc:5703-5734 — the used trials, in trial order, each naming the slot it lives in.
    let used: Vec<(usize, u32, bool, Address)> = f.active_inputs[&call]
        .trial
        .iter()
        .filter(|t| t.is_used())
        .map(|t| (t.op_slot as usize, t.size, t.is_unref(), t.addr))
        .collect();
    let n = f.op(call).num_inputs();
    if crate::debug::on(crate::debug::Topic::Args) {
        // EVERY trial, not just the used ones. A trial that exists and is not marked used looks
        // exactly like a trial that was never registered if only the used ones are printed, and
        // those two have completely different causes.
        let all: Vec<String> = f.active_inputs[&call]
            .trial
            .iter()
            .map(|t| {
                format!(
                    "{}+{:#x}/{}{}{}{}{}{}[e{:?}s{}]",
                    f.spaces.get(t.addr.space).name,
                    t.addr.offset,
                    t.size,
                    if t.flags & crate::decompile::fspec::trial_flags::CHECKED != 0 { "C" } else { "-" },
                    if t.is_active() { "A" } else { "-" },
                    if t.is_used() { "U" } else { "-" },
                    if t.is_definitely_not_used() { "D" } else { "-" },
                    if t.is_unref() { "R" } else { "-" },
                    t.entry,
                    t.slot,
                )
            })
            .collect();
        debug!(crate::debug::Topic::Args, "trials call@{:#x} {}", f.op(call).seqnum.pc.offset, all.join(" "));
    }
    if crate::debug::on(crate::debug::Topic::Args) {
        for (slot, sz, unref, addr) in &used {
            let vn = if *slot > 0 && *slot < n { f.op(call).input(*slot) } else { None };
            // The WHOLE input list and the placeholder slot alongside the trial's recorded slot:
            // a trial that names the wrong slot is indistinguishable from one whose varnode never
            // resolved, and the two have opposite fixes.
            let inputs: Vec<String> = (0..n)
                .map(|i| match f.op(call).input(i) {
                    Some(v) => {
                        let sep = if i == *slot { "*" } else { ":" };
                        let sp = &f.spaces.get(f.vn(v).loc.space).name;
                        let w = if f.vn(v).is_written() { "w" } else { "-" };
                        format!("{i}{sep}{sp}+{:#x}/{}{w}", f.vn(v).loc.offset, f.vn(v).size)
                    }
                    None => format!("{i}:?"),
                })
                .collect();
            debug!(crate::debug::Topic::Args,
                "call@{:#x} slot={slot} size={sz} unref={unref} addr={}+{:#x} vn={:?} inputs=[{}]",
                f.op(call).seqnum.pc.offset,
                f.spaces.get(addr.space).name,
                addr.offset,
                vn.map(|v| (f.vn(v).size, f.vn(v).is_written(), f.vn(v).is_free())),
                inputs.join(" ")
            );
        }
    }
    let mut newparam: Vec<VarnodeId> = vec![f.op(call).input(0).expect("CALL has a target")];
    for (slot, sz, unref, addr) in used {
        // fspec.cc:5717 — the unreferenced slot has no varnode at the call; create one, so the
        // arguments after it keep their position in the list.
        //
        // And mark it for heritage. A varnode manufactured after renaming has run is FREE: it sits
        // at the parameter's storage address and is linked to nothing, so it carries no value and
        // renders as a constant. The caller then emits an instruction to produce that constant —
        // `XOR EAX,EAX` for an argument the original passed implicitly, because the value was
        // already in the register.
        //
        // `setActiveHeritage` is how every other manufactured read in this port joins the next
        // renaming round (heritage.cc:1671, and `guard_returns_overlapping` for the same reason:
        // "a free ancestor then stops ancestorOpUse dead"). Without it the argument exists in the
        // signature and nowhere in the data flow.
        //
        // The flag is correct under this port's convention, and it is NOT what the propagated-
        // prototype defect turned out to be. `MOSURA_ARG_DEBUG` settled that, and the answer is
        // worth recording because two readings of the emitted C had pointed the other way:
        //
        //   [arg] call@0x13c6b slot=1 size=4 unref=FALSE addr=register+0x0
        //         vn=Some((4, written=false, free=false))
        //
        // The trial is not unreferenced, so this branch never runs for it. A varnode exists and is
        // linked — and it is UNWRITTEN. The caller's EAX at that point holds the result of the
        // call five instructions earlier, and the original passes it by doing nothing at all; the
        // read simply never resolved to that call's recovered return value, so the argument has no
        // reaching definition and prints as a constant.
        //
        // That makes it an ordering problem between one call's OUTPUT recovery and the next call's
        // INPUT recovery, not a heritage-marking problem and not a prototype problem.
        //
        // The two sit in different loops, and that placement is FAITHFUL to Ghidra:
        // `ActionResolveCalls` (arguments) is a member of the mainloop, while `ActionActiveReturn`
        // (call outputs) is in the fullloop tail (coreaction.cc:5688). So a call's arguments commit
        // while the preceding call still has no output at all. Ghidra survives this because a
        // fullloop round that commits outputs forces another round; mosura's argument list is
        // committed and its trial container cleared by then, so the second round has nothing left
        // to re-evaluate.
        //
        // The fix is therefore NOT to move an action — that would diverge from the reference for a
        // reason the reference does not have. It is to let a call whose argument resolved to an
        // unwritten varnode be re-opened once outputs commit, which is the shape Ghidra's repeated
        // fullloop already assumes.
        if unref {
            // A RE-COMMIT (the mosura-only `reopen_input` round, open thread 1) must not
            // manufacture a second varnode for the hole: `delete_unused_trials` renumbered this
            // trial's slot to the position of the one manufactured on the first commit, and the
            // heritage pass in between has already renamed that varnode (linked it to its reaching
            // def or made it a function input). Manufacturing again left a FREE read of an
            // already-heritaged register at the call, which the next heritage classifies as
            // "new read in an old range" (`prev == 2`) and answers with a deadcode-delay bump and a
            // restart — on nearly every survey decompile (Ghidra: ~0.25%), with the register space
            // pre-live through pass 1 of the restarted run. Ghidra commits exactly once, so its one
            // manufactured varnode is the one the next pass renames; reusing ours is that shape.
            if slot > 0 && slot < n {
                if let Some(prev) = f.op(call).input(slot) {
                    let pv = f.vn(prev);
                    if !pv.is_constant() && pv.loc == addr && pv.size == sz {
                        newparam.push(prev);
                        continue;
                    }
                }
            }
            let v = f.new_varnode(sz, addr);
            f.vn_mut(v).set_active_heritage();
            newparam.push(v);
            continue;
        }
        if slot == 0 || slot >= n {
            continue;
        }
        let Some(mut vn) = f.op(call).input(slot) else { continue };
        // fspec.cc:5720 — the varnode is wider than the parameter: truncate with a SUBPIECE.
        if f.vn(vn).size > sz {
            let (addr, seq) = (f.vn(vn).loc, f.op(call).seqnum);
            let zero = f.new_const(1, 0);
            let sub = f.new_op(OpCode::Subpiece, seq, vec![vn, zero]);
            if let Some(bid) = f.op(call).parent {
                f.op_mut(sub).parent = Some(bid);
            }
            f.op_insert_before(sub, call);
            vn = f.new_output(sub, sz, addr);
        }
        newparam.push(vn);
    }
    // ORDERING REPAIR (docs/byte-exact-status.md, open thread 1): if an argument resolved to a
    // varnode that is LINKED but UNWRITTEN, its definition is a preceding call's output that has
    // not been committed yet — `ActionActiveReturn` runs in the fullloop tail, after this. Record
    // the call so the output commit can re-open it; without that the argument prints as a constant
    // and the caller emits an instruction to produce a value the original passed implicitly.
    // The state to detect, spelled against the ALIGNED flag model: an argument varnode that is
    // FREE and not a constant — no def, no input marking. (The previous spelling
    // `!written && !is_free && !input` keyed on the old makeFree mis-port, which left INSERT on
    // a displaced call output; it also matched EVERY constant argument, since a constant was
    // "not free" under the old definition. With `makeFree` clearing INSERT and constants free,
    // the uncommitted-output class is exactly the free non-constants among the resolved args.)
    let unwritten = newparam
        .iter()
        .skip(1)
        .any(|&v| f.vn(v).is_free() && !f.vn(v).is_constant());
    if unwritten {
        f.calls_awaiting_output.insert(call);
    }
    f.op_set_all_input(call, &newparam); // fspec.cc:5739
    if let Some(active) = f.active_inputs.get_mut(&call) {
        active.delete_unused_trials(); // fspec.cc:5740
    }
}

/// Recover each call's return value — a faithful port of Ghidra's `ActionActiveReturn::apply`
/// (coreaction.cc:1773) for the CALL-output side: `checkOutputTrialUse` → `deriveOutputMap` →
/// `buildOutputFromTrials` (fspec.cc:5661 / 1721 / 5770). This RETIRES the earlier first-present-of-
/// `[RAX,XMM0]` single-pick adaptation (no-adaptation-grandfathered): that heuristic could only pick a
/// *whole* register, so when the mainloop's range-driven normalize splits a return register into
/// pieces (deindirect2: `AX:2` + the upper 6 bytes, because a later `xor ax,ax` writes the sub-
/// register), it cannot reassemble them — Ghidra does, via the 2-trial `findPreexistingWhole` path,
/// so the call directly outputs the merged whole (a `unique`) and the register range is left free for
/// the sub-register return. See [[task6-call-output-in-rax]].
///
/// heritage's `guard_calls` models a call's `killedbycall` output registers as INDIRECT creations;
/// this reads them back as output trials. For each surviving creation whose storage is a return
/// register (`characterize_as_param` on the SysV output list — Ghidra `characterizeAsOutput`,
/// fspec.cc:4336), a trial is registered and marked active iff its varnode is live (mosura runs pre-
/// dead-code, so `!descend.is_empty()` stands in for Ghidra's post-dead-code
/// `collectOutputTrialVarnodes`, which sees only creations that survived the mainloop sweep,
/// fspec.cc:5536). [`derive_output_map`] then picks the single output storage and marks its piece(s)
/// used, and [`build_call_output_from_trials`] moves the used varnode(s) to be the call's output.
/// Runs post-heritage, pre-type-inference.
///
/// PLACEMENT NOTE: mosura registers the output trials here (post-heritage) rather than in
/// `guard_calls` — the surviving INDIRECT creations ARE the heritaged ranges, so their `(addr,size)`
/// exactly match what Ghidra's in-heritage `registerTrial` would record, and this mirrors how the
/// input side (`setup_active_input`) already consolidates guardCalls' trial registration post-heritage.
///
/// Returns the change count per Ghidra's `ActionActiveReturn::apply` convention: +1 per call whose
/// output trials were resolved and committed (coreaction.cc:1788, the `isOutputActive` body). A call
/// that already has an output — or yields no usable trial — contributes 0, so the count bottoms out
/// once every recoverable call output is built (mosura's `output.is_some()` skip standing in for
/// Ghidra's cleared `isOutputActive` gate).
pub fn resolve_call_output(f: &mut Funcdata) -> u32 {
    let mut count = 0u32;
    // ORDERING REPAIR, second half (docs/byte-exact-status.md, open thread 1). Outputs commit HERE,
    // in the fullloop tail; arguments committed earlier, in the mainloop. Any call whose argument
    // resolved to a linked-but-unwritten varnode is re-opened now that the definition exists, so
    // `ActionResolveCalls` re-derives it on the next round — the shape Ghidra's repeated fullloop
    // already assumes. Each call gets exactly one such round (`reopened_inputs`), so this cannot
    // cycle, and the re-open is counted as a change so the enclosing loop actually runs again.
    for call in std::mem::take(&mut f.calls_awaiting_output) {
        if f.reopen_input(call) {
            count += 1;
        }
    }
    let reg = f.spaces.by_name("register");
    // The convention's output (return) list, decoded from the compiler spec's `<default_proto>`.
    let Some(outlist) = f.called_model().output.clone() else { return 0 };
    // Live calls only: Ghidra's `numCalls()`/`getCallSpecs(i)` loop can never see a destroyed call —
    // `PcodeOpBank::destroy` (op.cc:989) removes the op from the per-opcode code lists (op.cc:997)
    // and `deleteCallSpecs` (funcdata.hh:128) prunes its call spec. mosura's `op_ids()` is a flat
    // range over the append-only op Vec (dead ops included), so every per-opcode collector here
    // skips dead ops to keep those iteration semantics. A call destroyed with an unreachable block
    // (blockRemoveInternal) keeps a stale `parent` — deref'ing it is the tm_clones OOB panic (D2).
    let calls: Vec<OpId> =
        f.op_ids()
        .filter(|&op| !f.op(op).is_dead() && matches!(f.op(op).code(), OpCode::Call | OpCode::Callind))
        .collect();
    for call in calls {
        if f.op(call).output.is_some() {
            continue; // already has a recovered output
        }
        let Some(bid) = f.op(call).parent else { continue };
        let block_ops = f.block(bid).ops.clone();
        let Some(pos) = block_ops.iter().position(|&o| o == call) else { continue };
        // collectOutputTrialVarnodes (fspec.cc:5536) fused with guardCalls' output-trial registration
        // (heritage.cc:1469): walk BACKWARD from the call (`op->previousOp()`, fspec.cc:5543) over the
        // contiguous INDIRECT run right before it — the placement Ghidra's `newIndirectCreation`
        // (`opInsertBefore`) and mosura's [`guard_calls`] both use. A creation at a return register
        // becomes a trial; checkOutputTrialUse marks it active iff live (present).
        // The registers THIS callee is known to overwrite, recovered from its own body.
        let recovered: Vec<(Address, u32)> =
            f.call_specs.get(&call).map(|cs| cs.overwrites.clone()).unwrap_or_default();
        let mut active = ParamActive::new(reg);
        let mut vnmap: Vec<(Address, OpId, VarnodeId)> = Vec::new();
        for &op in block_ops[..pos].iter().rev() {
            if f.op(op).code() != OpCode::Indirect {
                break;
            }
            let Some(out) = f.op(op).output else { continue };
            if !f.vn(out).is_indirect_creation() {
                continue;
            }
            let (loc, size) = (f.vn(out).loc, f.vn(out).size);
            // A register THIS callee is known to overwrite (recovered from its own body,
            // `CallSpec::overwrites`) is an output candidate even though the cspec's `<output>`
            // list does not mention it: that list describes the DEFAULT convention, and these
            // callees do not follow it. Without this the killedbycall guard alone leaves the
            // post-call value an unnamed indirect creation and the caller consumes something
            // undefined — measurably worse than doing nothing.
            let is_recovered = recovered.iter().any(|&(a, sz)| a == loc && sz == size);
            if !is_recovered
                && outlist.characterize_as_param(loc, size) == Containment::NoContainment
            {
                continue; // not a return register (RCX/RSI/... clobbers) — plain killedbycall
            }
            let ti = active.register_trial(loc, size);
            if f.vn(out).descend.is_empty() {
                active.trial[ti].mark_inactive(); // present-but-dead ⇒ Ghidra markInactive (fspec.cc:5675)
            } else {
                active.trial[ti].mark_active(); // a live creation ⇒ the value is used
            }
            vnmap.push((loc, op, out));
        }
        if active.num_trials() == 0 {
            continue;
        }
        // `derive_output_map` is destructive — `mark_no_use` CLEARS the ACTIVE flag (fspec.hh:250),
        // so the trials cannot be re-mapped afterwards. Keep the as-collected state for stage two.
        let collected = if recovered.is_empty() { None } else { Some(active.clone()) };
        derive_output_map(&outlist, &mut active);
        // The default convention did not explain this call's return. Ghidra stops here, because a
        // `FuncCallSpecs` it never got to analyse carries only the default model. We have the
        // callee's own body, and `CallSpec::overwrites` says which storage it writes and does not
        // restore; when one of those is LIVE at the call site, that storage IS this callee's return
        // — the `#pragma aux ... value [ebx]` the source declared and the default `<output>` cannot
        // express. Re-run the map against a per-call output list built from that evidence.
        //
        // Second stage rather than one merged list because `firstOnly` (fspec.cc:1649) admits one
        // entry per storage class: EBX would be suppressed by EAX merely for sharing TYPECLASS_
        // GENERAL, even at a call site where EAX is dead. Staging also keeps the default path
        // bit-identical, so a call the convention already explains cannot be re-decided here.
        if let Some(mut restaged) = collected.filter(|_| !active.trial.iter().any(|t| t.is_used())) {
            let recovered_out = recovered_output_list(&recovered);
            derive_output_map(&recovered_out, &mut restaged);
            if restaged.trial.iter().any(|t| t.is_used()) {
                active = restaged;
            }
        }
        // buildOutputFromTrials (fspec.cc:5770): collect the used trials' varnodes in address
        // (least-significant-first) order, then reassemble.
        let mut used: Vec<(Address, OpId, VarnodeId)> = active
            .trial
            .iter()
            .filter(|t| t.is_used())
            .filter_map(|t| vnmap.iter().find(|(a, _, _)| *a == t.addr).copied())
            .collect();
        used.sort_by_key(|(a, _, _)| (a.space.0, a.offset));
        build_call_output_from_trials(f, call, bid, &used);
        if f.op(call).output.is_some() {
            count += 1; // coreaction.cc:1788 — a committed call output is a change
        }
    }
    count
}

/// The INPUT storage recovered from a callee's own body, as a [`ParamList`] — the registers it reads
/// before writing, in the order it reads them, which is the order the source's `parm caller [...]`
/// lists them. One exclusion entry per register, each its own resource group so they fill as
/// consecutive formal parameters.
pub(crate) fn recovered_input_list(reads: &[(Address, u32)]) -> ParamList {
    ParamList {
        entry: reads
            .iter()
            .enumerate()
            .map(|(i, &(addr, size))| ParamEntry {
                group: i as u32,
                type_class: 0, // TYPECLASS_GENERAL
                space: addr.space,
                addressbase: addr.offset,
                size,
                minsize: 1,
                alignment: 0, // exclusion — a single slot
            })
            .collect(),
        // [start, sentinel] — `separate_sections` (fspec.rs:393) indexes `resource_start[1]`, and a
        // sentinel past the last group means the single section covers every entry.
        resource_start: vec![0, reads.len() as u32],
        is_output: false,
    }
}

/// The output storage recovered from a callee's own body, as a [`ParamList`] `derive_output_map` can
/// map trials against — the per-call half of Ghidra's `FuncCallSpecs : FuncProto`, whose `store`
/// (fspec.hh:1400) may describe storage the *model* does not.
///
/// One exclusion entry per recovered register, each its own resource group so none excludes another,
/// and each `TYPECLASS_GENERAL` — these are integer/pointer returns by construction (they are
/// registers the default convention calls `<unaffected>`; the float stack is not among them).
/// `minsize = 1` so a sub-register read of the returned value still justifies into its entry.
pub(crate) fn recovered_output_list(recovered: &[(Address, u32)]) -> ParamList {
    ParamList {
        entry: recovered
            .iter()
            .enumerate()
            .map(|(i, &(addr, size))| ParamEntry {
                group: i as u32,
                type_class: 0, // TYPECLASS_GENERAL
                space: addr.space,
                addressbase: addr.offset,
                size,
                minsize: 1,
                alignment: 0, // exclusion — a single slot, not a stack area
            })
            .collect(),
        resource_start: vec![0, recovered.len() as u32],
        is_output: true,
    }
}

/// Ghidra `ParamListStandardOut::fillinMap` output-map (fspec.cc:1721) reduced to what the SysV
/// output convention exercises: find the output entry best covered by the active trials — the most
/// contiguous least-significant-justified bytes, preferring a more generic type class then larger
/// coverage — and mark the trials it justified-contains as USED (the rest not-used). A single return
/// register with one live trial is used directly; a return register split into contiguous pieces
/// (both justified-contained in the same entry) has BOTH pieces marked used, so
/// `build_call_output_from_trials` reassembles them.
///
/// `firstOnly` (fspec.cc:1649): only the FIRST entry of each storage class may match — a return is
/// justified into the first register of its class (RAX/XMM0), never a lone high-half register
/// (RDX/XMM1), which is only reachable as the high piece of a `join_dual_class` 16-byte pair. mosura's
/// output resolution lands here directly: Ghidra's non-fallback `fillinMap` first tries the
/// `join_dual_class` model rule (`MultiSlotAssign::fillinOutputMap`, modelrules.cc:902) and, for every
/// SysV single-class return it does NOT fire (a lone RAX fires it trivially → still used; a lone
/// RDX/XMM1 fails `isFirstInClass`; two same-group RAX pieces fail the consecutive-group check),
/// falling through to `fillinMapFallback(active, true)` (fspec.cc:1762) — so this fallback-with-
/// firstOnly IS the effective map for all cases here. The one un-exercised divergence is a genuine
/// 16-byte RAX:RDX return, where `join_dual_class` would additionally take RDX; that pair case is
/// deferred (no corpus fixture returns a 128-bit integer). The multi-precision `extracheck_low/high` +
/// `isRemFormed`/`isIndCreateFormed` guards (fspec.cc:1676-1681) are omitted — inert for mosura's
/// single-register SysV output entries, which never set those flags.
/// Returns the contiguous coverage of the selected entry by its used trials — the width of the
/// return storage this function was found to actually produce. `None` when no entry was selected
/// (the function returns nothing).
fn derive_output_map(outlist: &ParamList, active: &mut ParamActive) -> Option<u32> {
    let mut best: Option<usize> = None;
    let mut best_cover = 0u32;
    let mut best_class = u8::MAX; // Ghidra `bestclass = TYPECLASS_PTR` — worse than GENERAL(0)/FLOAT(1)
    for (ei, e) in outlist.entry.iter().enumerate() {
        // firstOnly: skip an entry that is not the first of its storage class (RDX after RAX, XMM1
        // after XMM0) — those carry only the high half of a dual-class join, never a lone return.
        if outlist.entry[..ei].iter().any(|p| p.type_class == e.type_class) {
            continue;
        }
        // Contiguous least-justified coverage of this entry by its active trials.
        let mut pieces: Vec<(u64, u32)> = active
            .trial
            .iter()
            .filter(|t| t.is_active())
            .filter_map(|t| e.justified_contain(t.addr, t.size).map(|off| (off, t.size)))
            .collect();
        if pieces.is_empty() {
            continue;
        }
        pieces.sort_by_key(|&(off, _)| off);
        let mut offmatch = 0u64;
        for (off, size) in pieces {
            if off != offmatch {
                break; // a gap — coverage stops at the least-justified contiguous run
            }
            offmatch += size as u64;
        }
        let cover = offmatch as u32;
        if cover < e.minsize {
            continue; // didn't cover the entry's minimum — not this entry
        }
        // Prefer a more generic type restriction, else larger coverage (fspec.cc:1688).
        if e.type_class < best_class || cover > best_cover {
            best = Some(ei);
            best_cover = cover;
            best_class = e.type_class;
        }
    }
    let recovered = match best {
        None => {
            for t in active.trial.iter_mut() {
                t.mark_no_use();
                t.clear_entry();
            }
            None
        }
        Some(be) => {
            for t in active.trial.iter_mut() {
                if t.is_active() && outlist.entry[be].justified_contain(t.addr, t.size).is_some() {
                    t.mark_used();
                    t.set_entry(be, outlist.entry[be].group); // fspec.cc:1658
                } else {
                    t.mark_no_use();
                    t.clear_entry(); // fspec.cc:1662/1665
                }
            }
            Some(best_cover)
        }
    };
    // fspec.cc:1668 — the unmatched trials sink below the used ones, so a consumer that stops at the
    // first not-used trial still sees every used one.
    active.sort_trials();
    recovered
}

/// Ghidra `FuncCallSpecs::findPreexistingWhole` (fspec.cc:5750): if two varnodes are each the lone
/// input of one common `PIECE` op, return that op's output (their merged whole), else `None`.
fn find_preexisting_whole(f: &Funcdata, vn1: VarnodeId, vn2: VarnodeId) -> Option<VarnodeId> {
    let op1 = lone_descend(f, vn1)?;
    let op2 = lone_descend(f, vn2)?;
    if op1 != op2 || f.op(op1).code() != OpCode::Piece {
        return None;
    }
    f.op(op1).output
}

/// Ghidra `Varnode::loneDescend`: the single op reading `vn`, or `None` if it has zero or several.
fn lone_descend(f: &Funcdata, vn: VarnodeId) -> Option<OpId> {
    match f.vn(vn).descend.as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

/// Ghidra `FuncCallSpecs::buildOutputFromTrials` (fspec.cc:5770), reduced to the register cases the
/// SysV output convention produces: move the used trial varnode(s) to be the CALL's output and
/// destroy the INDIRECTs that held them. One used trial → its varnode becomes the output directly. Two
/// used trials (a return register split into low+high pieces) → if they already flow into a common
/// `PIECE` (`findPreexistingWhole`), that pre-existing whole becomes the call output and the `PIECE` +
/// both INDIRECTs are removed, so the call directly outputs the reassembled value (Ghidra's
/// `u0x…9 = callind …`) rather than leaving the register split. `used` is in least-significant-first
/// (address) order.
fn build_call_output_from_trials(
    f: &mut Funcdata,
    call: OpId,
    bid: super::block::BlockId,
    used: &[(Address, OpId, VarnodeId)],
) {
    let mut remove: Vec<OpId> = Vec::new();
    match used {
        [(_, indop, outvn)] => {
            // Single, properly justified output (fspec.cc:5787).
            f.op_set_output(call, *outvn);
            f.op_destroy(*indop);
            remove.push(*indop);
        }
        [(_, lo_ind, lovn), (_, hi_ind, hivn)] => {
            // Two trials — merge into a single output (fspec.cc:5806). little-endian: `used[0]` is the
            // low piece, `used[1]` the high piece.
            if let Some(whole) = find_preexisting_whole(f, *hivn, *lovn) {
                let piece_def = f.vn(whole).def; // the PIECE op (Ghidra `finaloutvn->getDef()`)
                f.op_set_output(call, whole);
                if let Some(p) = piece_def {
                    f.op_destroy(p);
                    remove.push(p);
                }
                f.op_destroy(*hi_ind);
                f.op_destroy(*lo_ind);
                remove.push(*hi_ind);
                remove.push(*lo_ind);
            }
            // else: no pre-existing whole ⇒ Ghidra constructs a join-space varnode + two SUBPIECEs
            // (fspec.cc:5823). That branch needs join-space support and is not reachable on the current
            // single-pass corpus (the split only appears once the mainloop's un-scoped normalize runs);
            // it is deferred with the batch-retirement that produces clean split pieces. Leave the call
            // output unset (as the retired code did for a non-single output).
        }
        _ => {} // 0 used ⇒ void; >2 ⇒ Ghidra `buildOutputFromTrials` returns without an output.
    }
    if !remove.is_empty() {
        let kept: Vec<OpId> = f.block(bid).ops.iter().copied().filter(|o| !remove.contains(o)).collect();
        f.set_block_ops(bid, kept);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::{BlockBasic, Funcdata, OpCode, SeqNum};

    /// Stand in for heritage having run: attach the SysV convention and register one output trial
    /// per candidate input already on `ret`, exactly as [`super::heritage::guard_returns`]'
    /// `characterizeAsOutput` branch does for each heritaged range. `None` (caller skips) when the
    /// Ghidra tree — and so the compiler spec the candidates now come from — isn't present.
    fn open_output_trials(f: &mut Funcdata, ret: OpId) -> Option<()> {
        f.proto_model = crate::decompile::build::test_sysv_proto_model()?;
        init_active_output(f);
        let maxpass = f.active_output.as_ref().unwrap().get_max_pass();
        f.active_output = Some(seed_active(f, ret, maxpass));
        Some(())
    }

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
        let Some(()) = open_output_trials(&mut f, ret) else { return };
        resolve_return(&mut f);
        assert!(kept_offset(&f, ret, RAX), "RAX (written) is the return value");
    }

    #[test]
    fn float_return_keeps_xmm0() {
        let (mut f, ret) = ret_with(false, true);
        let Some(()) = open_output_trials(&mut f, ret) else { return };
        resolve_return(&mut f);
        assert!(kept_offset(&f, ret, XMM0), "XMM0 (written) is the return value, not the unwritten RAX");
    }

    #[test]
    fn void_return_keeps_nothing() {
        let (mut f, ret) = ret_with(false, false);
        let Some(()) = open_output_trials(&mut f, ret) else { return };
        resolve_return(&mut f);
        assert_eq!(f.op(ret).num_inputs(), 1, "neither register written ⇒ void");
    }

    #[test]
    fn both_written_prefers_rax() {
        let (mut f, ret) = ret_with(true, true);
        let Some(()) = open_output_trials(&mut f, ret) else { return };
        resolve_return(&mut f);
        assert!(kept_offset(&f, ret, RAX), "a function returns one value; prefer RAX");
    }

    #[test]
    fn bare_float_return_commits_the_wide_xmm0_trial() {
        // A `float` return: the 4-byte value sits in a zero-padded XMM0 — `XMM0:8 =
        // PIECE(#0:4, f:4)`. With the overlapping XMM0:4 sibling candidate retired (see
        // [`recover_return`]), the XMM0:8 trial must COMMIT (not void): Ghidra registers the
        // heritaged range as the single output trial (`guardReturns`, heritage.cc:1652) and
        // `buildReturnOutput` commits it — there is no const-padded-PIECE narrowing in Ghidra's
        // return recovery. The 8→4 width narrowing happens later on the IR (the
        // SubvariableFlow/SubfloatFlow rule family), not here.
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        // f:4 = FLOAT_ADD(xmm1_in:4, xmm1_in:4)  — a real computed float
        let xmm1 = f.new_input(4, Address::new(reg, XMM0 + 0x40));
        let fadd = f.new_op(OpCode::FloatAdd, seq, vec![xmm1, xmm1]);
        let fval = f.new_output(fadd, 4, Address::new(reg, XMM0));
        // XMM0:8 = PIECE(#0:4, f:4) — the zero-padded wide register
        let zero = f.new_const(4, 0);
        let piece = f.new_op(OpCode::Piece, seq, vec![zero, fval]);
        let xmm0 = f.new_output(piece, 8, Address::new(reg, XMM0));
        let rax = f.new_input(8, Address::new(reg, RAX)); // unwritten
        let retaddr = f.new_input(8, Address::new(reg, 0x20));
        let ret = f.new_op(OpCode::Return, seq, vec![retaddr, rax, xmm0]);
        f.set_blocks(vec![BlockBasic { ops: vec![ret], ..Default::default() }]);
        let Some(()) = open_output_trials(&mut f, ret) else { return };
        resolve_return(&mut f);
        assert!(
            kept_offset(&f, ret, XMM0),
            "a zero-padded float return commits the XMM0:8 trial (width narrowing is downstream IR work)"
        );
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
        let store_addr = |f: &mut Funcdata, k: u64| -> VarnodeId {
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
    fn sibling_slot_use_fails_the_own_slot_test() {
        // A value reaching TWO return-value slots of the same RETURN (here via a SUBPIECE view —
        // the shape the retired XMM0:4 sibling candidate used to produce). Ghidra's `onlyOpUse`
        // skips ONLY the trial's own slot (funcdata_varnode.cc:1823-1825, and the RETURN case's
        // own-slot test at :1852-1854): the value's use at the OTHER slot is a real use, so the
        // trial is rejected. (The former any-slot accommodation existed for the retired XMM0:4
        // sibling candidate; with disjoint RAX:8/XMM0:8 candidates the only corpus occurrence is
        // impliedfield's RAX-slot/XMM0-slot value flow, where Ghidra's own rule also rejects the
        // XMM0 trial and the first-match RAX commit is unchanged.)
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
        assert!(
            !return_trial_kept(&f, ret, 1),
            "the value's use at a sibling return-value slot is a real use under the own-slot test"
        );
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
    fn call_with(written: usize) -> Option<(Funcdata, OpId)> {
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
        open_call_recovery(&mut f, call)?;
        Some((f, call))
    }

    /// Put a hand-built CALL into the state the pipeline reaches just before `resolve_call_args`:
    /// the convention loaded, and the per-call trial container that `init_active_input` creates
    /// plus the trials `heritage`'s `guard_calls` registers. The trials are registered in the order
    /// heritage produces them — the register space walked by ADDRESS (`RDX` at `0x10` before `RDI`
    /// at `0x38`) — not in argument order, because that difference is exactly what the argument
    /// recovery has to get right. `None` when the pinned .sla is absent (test skips).
    fn open_call_recovery(f: &mut Funcdata, call: OpId) -> Option<()> {
        f.proto_model = crate::decompile::build::test_sysv_proto_model()?;
        let reg = f.spaces.by_name("register");
        let mut active = ParamActive::new(reg);
        active.set_max_pass(CALL_MAXPASS);
        active.is_recover_subcall = true;
        let mut slots: Vec<(usize, Address, u32)> = (1..f.op(call).num_inputs())
            .filter_map(|slot| {
                let v = f.op(call).input(slot)?;
                Some((slot, f.vn(v).loc, f.vn(v).size))
            })
            .collect();
        slots.sort_by_key(|&(_, loc, size)| (loc.offset, size));
        for (slot, loc, size) in slots {
            let ti = active.register_trial(loc, size);
            active.trial[ti].op_slot = slot as u32;
        }
        f.active_inputs.insert(call, active);
        Some(())
    }

    #[test]
    fn call_keeps_contiguous_written_args() {
        let Some((mut f, call)) = call_with(2) else { return }; // RDI, RSI written; RDX.. scratch
        resolve_call_args(&mut f);
        assert_eq!(f.op(call).num_inputs(), 3, "[target, RDI, RSI] — two arguments");
    }

    #[test]
    fn call_with_no_set_registers_has_no_args() {
        let Some((mut f, call)) = call_with(0) else { return };
        resolve_call_args(&mut f);
        assert_eq!(f.op(call).num_inputs(), 1, "only the call target remains");
    }

    /// A CALL `[target, RDI, RSI]` where RDI is a realistic write and RSI flows through an INDIRECT.
    /// `creation` selects whether that INDIRECT is an indirect *creation* (a killedbycall clobber) or
    /// a *passthrough* (the across-call stack-slot guard, `newIndirectOp`).
    fn call_arg_through_indirect(creation: bool) -> Option<(Funcdata, OpId)> {
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
        } else {
            // A *call* passthrough: model the causing op as a CALL so `indirect_is_store` is false
            // (Ghidra `PcodeOp::isIndirectStore` == false) and the killed-by-call reject applies.
            let earlier_target = f.new_const(8, 0x400400);
            let earlier_call = f.new_op(OpCode::Call, seq, vec![earlier_target]);
            f.op_mut(ind).guarded_op = Some(earlier_call);
            extra.insert(0, earlier_call);
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
        open_call_recovery(&mut f, call)?;
        Some((f, call))
    }

    /// Ghidra `AncestorRealistic::enterNode` CPUI_INDIRECT (funcdata_varnode.cc:2052-2054): a
    /// *killed-by-call* register trial whose value flows THROUGH a *call* passthrough INDIRECT is
    /// invalid (`pop_fail`) — the callee overwrote the register, so the value is not the caller's
    /// argument. So an RSI arg reaching the call through a call-passthrough is dropped, exactly like a
    /// creation. (A non-killed *stack* trial, or a value through a STORE-modeling passthrough
    /// `isIndirectStore`, is kept — that keep-path is exercised by the corpus, e.g. loopcomment's
    /// aliased-stack-local 2nd arg, which does not regress under this reject.)
    #[test]
    fn register_arg_through_call_passthrough_is_dropped() {
        let Some((mut f, call)) = call_arg_through_indirect(false) else { return };
        resolve_call_args(&mut f);
        assert_eq!(f.op(call).num_inputs(), 2, "[target, RDI] — the RSI passthrough of a call clobber is not an argument");
    }

    /// The complementary case: an indirect *creation* (killedbycall clobber, indirect-zero input) is
    /// a value out of nothing — Ghidra's `pop_failkill` — so the candidate is dropped (no holes after
    /// the realistic prefix). Guards the creation branch the passthrough fix must not disturb.
    #[test]
    fn arg_through_indirect_creation_is_dropped() {
        let Some((mut f, call)) = call_arg_through_indirect(true) else { return };
        resolve_call_args(&mut f);
        assert_eq!(f.op(call).num_inputs(), 2, "[target, RDI] — the RSI clobber is not a real argument");
    }

    /// A CALL followed by an RAX indirect-creation clobber; `used` decides whether the clobber's
    /// value is read (so the creation survived dead-code) — modeling the post-dead-code state
    /// `resolve_call_output` consumes.
    fn call_then_rax_creation(used: bool) -> Option<(Funcdata, OpId, OpId)> {
        let pm = crate::decompile::build::test_sysv_proto_model()?;
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        f.proto_model = pm;
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let target = f.new_const(8, 0x400430);
        let call = f.new_op(OpCode::Call, seq, vec![target]);
        let zero = f.new_const(8, 0);
        let ind = f.new_op(OpCode::Indirect, seq, vec![zero]);
        let out = f.new_output(ind, 8, Address::new(reg, RAX));
        f.vn_mut(out).set_indirect_creation();
        // Ghidra `newIndirectCreation` splices the clobber INDIRECT BEFORE the call, and
        // `collectOutputTrialVarnodes` walks backward from the call to find it.
        let mut ops = vec![ind, call];
        if used {
            // a consumer of the call's RAX result (an INT_ADD reading it), after the call
            let c = f.new_const(8, 1);
            let add = f.new_op(OpCode::IntAdd, seq, vec![out, c]);
            f.new_output(add, 8, Address::new(reg, RAX));
            ops.push(add);
        }
        f.set_blocks(vec![BlockBasic { ops, ..Default::default() }]);
        for &op in &[call, ind] {
            f.op_mut(op).parent = Some(crate::decompile::BlockId(0));
        }
        Some((f, call, ind))
    }

    #[test]
    fn used_rax_creation_becomes_call_output() {
        let Some((mut f, call, ind)) = call_then_rax_creation(true) else { return };
        resolve_call_output(&mut f);
        // the call now produces RAX; the INDIRECT was destroyed
        let out = f.op(call).output.expect("call has a recovered output");
        assert_eq!(f.vn(out).loc.offset, RAX);
        assert!(f.op(ind).is_dead(), "the promoted INDIRECT is destroyed");
    }

    #[test]
    fn unused_rax_creation_is_not_promoted() {
        let Some((mut f, call, _ind)) = call_then_rax_creation(false) else { return };
        resolve_call_output(&mut f);
        assert!(f.op(call).output.is_none(), "an unused clobber is not a return value");
    }

    #[test]
    fn split_call_output_reassembles_via_preexisting_whole() {
        // deindirect2's shape (the reassembly path the single-pass corpus never exercises — it
        // activates once the mainloop's un-scoped normalize splits the return register): a later
        // sub-register write splits the return register into two INDIRECT-creation pieces (AX:2 low +
        // the upper 6 bytes) that a wide read reassembles via a PIECE. `buildOutputFromTrials`' 2-trial
        // path (`findPreexistingWhole`) must set that pre-existing whole — a fresh unique, as Ghidra's
        // `u0x…9 = callind …` — to be the call output and remove the PIECE + both INDIRECTs.
        let Some(pm) = crate::decompile::build::test_sysv_proto_model() else { return };
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        f.proto_model = pm;
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let target = f.new_const(8, 0x400430);
        let call = f.new_op(OpCode::Callind, seq, vec![target]);
        // The two call-clobber pieces of RAX: AX:2 (offset 0) and the upper 6 bytes (offset 2).
        let mk_creation = |f: &mut Funcdata, off: u64, size: u32| -> (OpId, VarnodeId) {
            let zero = f.new_const(size, 0);
            let ind = f.new_op(OpCode::Indirect, seq, vec![zero]);
            let out = f.new_output(ind, size, Address::new(reg, off));
            f.vn_mut(out).set_indirect_creation();
            (ind, out)
        };
        let (ind_lo, ax) = mk_creation(&mut f, RAX, 2);
        let (ind_hi, upper6) = mk_creation(&mut f, RAX + 2, 6);
        // The wide read reassembles them into a unique whole: `whole:8 = PIECE(upper6, AX)`.
        let piece = f.new_op(OpCode::Piece, seq, vec![upper6, ax]);
        let whole = f.new_output_unique(piece, 8);
        // A consumer of the whole (a STORE `*addr = whole`), as deindirect2's `*ptr = rax`.
        let sp = f.new_const(8, 0);
        let addr = f.new_input(8, Address::new(reg, 0x38));
        let store = f.new_op(OpCode::Store, seq, vec![sp, addr, whole]);
        // The clobber INDIRECTs sit BEFORE the call (Ghidra `newIndirectCreation`); the reassembly
        // PIECE + its consumer follow it — `resolve_call_output` walks backward to the two creations.
        let ops = vec![ind_lo, ind_hi, call, piece, store];
        f.set_blocks(vec![BlockBasic { ops: ops.clone(), ..Default::default() }]);
        for &op in &ops {
            f.op_mut(op).parent = Some(crate::decompile::BlockId(0));
        }
        resolve_call_output(&mut f);
        assert_eq!(f.op(call).output, Some(whole), "the call directly outputs the reassembled whole (a unique)");
        assert_eq!(f.vn(whole).def, Some(call), "the whole is now defined by the call; the STORE still reads it");
        assert!(f.op(ind_lo).is_dead() && f.op(ind_hi).is_dead(), "both piece INDIRECTs are removed");
        assert!(f.op(piece).is_dead(), "the reassembly PIECE is removed — the call outputs the whole directly");
        assert!(!f.block(crate::decompile::BlockId(0)).ops.contains(&piece), "the PIECE is dropped from the block");
    }

    #[test]
    fn lone_rdx_clobber_is_not_a_return() {
        // A live RDX:4 clobber with no RAX return is NOT a return: RDX is only the high half of a
        // RAX:RDX dual-class join, so `firstOnly` skips it and the call stays void — matching Ghidra
        // (loopcomment: `func_0x00100580(0x100924)` is void, not `iVar = func_…`). Guards the fillinMap
        // firstOnly semantics: without them a spuriously-live high-half clobber becomes a bogus return.
        let Some(pm) = crate::decompile::build::test_sysv_proto_model() else { return };
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        f.proto_model = pm;
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let target = f.new_const(8, 0x400430);
        let call = f.new_op(OpCode::Call, seq, vec![target]);
        let zero = f.new_const(4, 0);
        let ind = f.new_op(OpCode::Indirect, seq, vec![zero]);
        let rdx = f.new_output(ind, 4, Address::new(reg, 0x10)); // RDX:4 clobber
        f.vn_mut(rdx).set_indirect_creation();
        let c = f.new_const(4, 1); // a reader, so the clobber is live pre-dead-code
        let add = f.new_op(OpCode::IntAdd, seq, vec![rdx, c]);
        f.new_output(add, 4, Address::new(reg, 0x10));
        f.set_blocks(vec![BlockBasic { ops: vec![call, ind, add], ..Default::default() }]);
        for &op in &[call, ind] {
            f.op_mut(op).parent = Some(crate::decompile::BlockId(0));
        }
        resolve_call_output(&mut f);
        assert!(f.op(call).output.is_none(), "a lone RDX clobber (not first-in-class) is not a SysV return");
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
            let (loc, size) = (f.vn(v).loc, f.vn(v).size);
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
        let Some(pm) = crate::decompile::build::test_sysv_proto_model() else { return };
        f.proto_model = pm;
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
        let Some((mut f, call)) = call_with(2) else { return }; // RDI, RSI written; RDX.. scratch
        let active = seed_active(&mut f, call, 1);
        f.active_inputs.insert(call, active);

        resolve_call_args(&mut f); // pass 1: dead slots freed to const 0, but none removed
        assert_eq!(f.op(call).num_inputs(), 7, "deferred: all candidate slots retained after one pass");
        assert!(f.is_input_active(call), "per-call trials persist until fully checked");

        resolve_call_args(&mut f); // pass 2: fully checked ⇒ commit the prune
        assert_eq!(f.op(call).num_inputs(), 3, "committed: [target, RDI, RSI] once the deferral resolves");
        assert!(!f.is_input_active(call), "active_inputs entry cleared on commit");
    }
}
