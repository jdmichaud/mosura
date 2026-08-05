//! Flow-type classification — a port of Ghidra's
//! `app/plugin/processors/sleigh/SleighInstructionPrototype.java` flow-flag logic
//! (`walkTemplates`, `flowListToFlowType`, `convertFlowFlags`) plus the flow-override
//! mapping in `program/model/listing/FlowOverride.java` (`getModifiedFlowType`).
//!
//! Ghidra computes an instruction's [`FlowType`] by walking its p-code templates in emit
//! order, accumulating per-op flow flags, then collapsing the flag set to a standard flow
//! type. mosura's lifter produces the concrete lifted p-code (not the unbuilt templates),
//! but the flag derivation is op-for-op the same: a real flow `BRANCH`/`CBRANCH` carries a
//! `ram`-space target (Ghidra's `JUMPOUT` destination type — confirmed by lifting `jmp
//! rel8/rel32` and `jz rel8`), while an in-instruction p-code-relative branch carries a
//! `const`-space target (Ghidra's `J_RELATIVE`/`J_NEXT`). `BRANCHIND`/`CALLIND`/`RETURN`
//! map directly. This file mirrors the Java method-by-method.

use crate::analysis::program::RefType;
use crate::decompile::opcode::OpCode;
use crate::sleigh::pcode::{PArg, PcodeOp};

// SleighInstructionPrototype.java:46-54 — the flow flags used to resolve flow type.
const RETURN: u32 = 0x01;
const CALL_INDIRECT: u32 = 0x02;
const BRANCH_INDIRECT: u32 = 0x04;
const CALL: u32 = 0x08;
const JUMPOUT: u32 = 0x10;
const NO_FALLTHRU: u32 = 0x20;
const BRANCH_TO_END: u32 = 0x40;
const CROSSBUILD: u32 = 0x80;
const LABEL: u32 = 0x100;

/// The flow override applied to an instruction (Ghidra `FlowOverride`). We only model the
/// variants the ported analyzers set; the rest pass through unchanged.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FlowOverride {
    None,
    CallReturn,
}

/// The destination kind of a lifted `BRANCH`/`CBRANCH`, i.e. which `ConstTpl` destination
/// type Ghidra's `walkTemplates` sees (SleighInstructionPrototype.java:227-254). mosura reads
/// the *lifted* p-code rather than the templates, so the kind is recovered from the target
/// varnode: a `const`-space target is p-code-relative (`J_RELATIVE`), a `ram` target equal to
/// the instruction's own address is `J_START`, one equal to the address *after* it is
/// `J_NEXT`, and anything else is a real out-of-instruction destination.
enum Dest {
    Relative,
    Start,
    Next,
    Out,
}

fn dest_kind(op: &PcodeOp, inst_start: u64, inst_next: u64) -> Dest {
    match op.ins.first() {
        Some(PArg::Var(v)) if v.space == "ram" => {
            if v.offset == inst_next {
                Dest::Next
            } else if v.offset == inst_start {
                Dest::Start
            } else {
                Dest::Out
            }
        }
        _ => Dest::Relative,
    }
}

/// Per-op flow flags — `SleighInstructionPrototype.walkTemplates`'s opcode switch
/// (SleighInstructionPrototype.java:217-266), arm for arm. Returns `None` for a non-flow op.
///
/// The `J_NEXT` arms are what keep an instruction with an INTERNAL loop honest: x86's
/// `rep movs` lifts to a guard `CBRANCH` at the instruction's own next address plus a
/// `BRANCH` back to a p-code-relative label, so its flags collapse to
/// `NO_FALLTHRU | BRANCH_TO_END` — `FALL_THROUGH`. Classifying it off the last p-code op
/// instead calls it an unconditional branch, which is how mosura came to believe `rep movs`
/// ends a flow.
fn op_flow_flags(op: &PcodeOp, inst_start: u64, inst_next: u64) -> Option<u32> {
    match OpCode::from_u32(op.opcode) {
        Some(OpCode::Branchind) => Some(BRANCH_INDIRECT | NO_FALLTHRU),
        Some(OpCode::Branch) => Some(match dest_kind(op, inst_start, inst_next) {
            Dest::Next => BRANCH_TO_END,
            Dest::Start | Dest::Relative => NO_FALLTHRU,
            Dest::Out => JUMPOUT | NO_FALLTHRU,
        }),
        Some(OpCode::Cbranch) => Some(match dest_kind(op, inst_start, inst_next) {
            Dest::Next => BRANCH_TO_END,
            Dest::Start | Dest::Relative => 0,
            Dest::Out => JUMPOUT,
        }),
        Some(OpCode::Call) => Some(CALL),
        Some(OpCode::Callind) => Some(CALL_INDIRECT),
        Some(OpCode::Return) => Some(RETURN | NO_FALLTHRU),
        _ => None,
    }
}

/// Accumulate the per-op flow flags (`SleighInstructionPrototype.flowListToFlowType`): the
/// running flags clear `NO_FALLTHRU | CROSSBUILD | LABEL` before OR-ing in each op's flags,
/// so the last flow op dominates the fall-through decision. `None` when the instruction has
/// no flow op at all (Ghidra's `flowState == null` → `RefType.FALL_THROUGH`).
fn flow_flags(ops: &[PcodeOp], inst_start: u64, inst_next: u64) -> Option<u32> {
    let mut have_flow = false;
    let mut flags: u32 = 0;
    for op in ops {
        if let Some(f) = op_flow_flags(op, inst_start, inst_next) {
            flags &= !(NO_FALLTHRU | CROSSBUILD | LABEL);
            flags |= f;
            have_flow = true;
        }
    }
    have_flow.then_some(flags)
}

/// Ghidra's `FlowType` — the full result set of `convertFlowFlags`, including the arms
/// mosura's [`RefType`] (a *reference*-type subset) cannot name. Kept internal; the public
/// accessors below project it onto what each caller needs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FlowKind {
    FallThrough,
    Invalid,
    Terminator,
    ConditionalTerminator,
    JumpTerminator,
    Ref(RefType),
}

impl FlowKind {
    /// `FlowType.hasFallthrough()` — the `setHasFall()` column of `RefType`'s flow-type
    /// table (RefType.java:97-286). `INVALID` has fall-through.
    fn has_fallthrough(self) -> bool {
        match self {
            FlowKind::FallThrough | FlowKind::Invalid | FlowKind::ConditionalTerminator => true,
            FlowKind::Terminator | FlowKind::JumpTerminator => false,
            FlowKind::Ref(r) => matches!(
                r,
                RefType::ConditionalJump
                    | RefType::ConditionalComputedJump
                    | RefType::UnconditionalCall
                    | RefType::ConditionalCall
                    | RefType::ComputedCall
                    | RefType::ConditionalComputedCall
            ),
        }
    }
}

/// `SleighInstructionPrototype.flowListToFlowType` → `convertFlowFlags` — the whole switch.
fn classify(ops: &[PcodeOp], inst_start: u64, inst_next: u64) -> FlowKind {
    let Some(mut flow_flags) = flow_flags(ops, inst_start, inst_next) else {
        return FlowKind::FallThrough; // flowState == null
    };
    if flow_flags & LABEL != 0 {
        flow_flags |= BRANCH_TO_END;
    }
    flow_flags &= !(CROSSBUILD | LABEL);
    use FlowKind::*;
    use RefType as R;
    match flow_flags {
        f if f == 0 || f == BRANCH_TO_END => FallThrough,
        f if f == CALL => Ref(R::UnconditionalCall),
        f if f == CALL | NO_FALLTHRU | RETURN => Ref(R::CallTerminator),
        f if f == CALL_INDIRECT | NO_FALLTHRU | RETURN => Ref(R::ComputedCallTerminator),
        f if f == CALL | BRANCH_TO_END => Ref(R::ConditionalCall),
        f if f == CALL | NO_FALLTHRU | JUMPOUT => Ref(R::ComputedJump),
        f if f == CALL | NO_FALLTHRU | BRANCH_TO_END | RETURN => Ref(R::UnconditionalCall),
        f if f == CALL_INDIRECT => Ref(R::ComputedCall),
        f if f == BRANCH_INDIRECT | NO_FALLTHRU => Ref(R::ComputedJump),
        f if f == BRANCH_INDIRECT | BRANCH_TO_END
            || f == BRANCH_INDIRECT | NO_FALLTHRU | BRANCH_TO_END
            || f == BRANCH_INDIRECT | JUMPOUT | NO_FALLTHRU | BRANCH_TO_END =>
        {
            Ref(R::ConditionalComputedJump)
        }
        f if f == CALL_INDIRECT | BRANCH_TO_END || f == CALL_INDIRECT | NO_FALLTHRU | BRANCH_TO_END => {
            Ref(R::ConditionalComputedCall)
        }
        f if f == RETURN | NO_FALLTHRU => Terminator,
        f if f == RETURN | BRANCH_TO_END || f == RETURN | NO_FALLTHRU | BRANCH_TO_END => {
            ConditionalTerminator
        }
        f if f == JUMPOUT => Ref(R::ConditionalJump),
        f if f == JUMPOUT | NO_FALLTHRU => Ref(R::UnconditionalJump),
        f if f == JUMPOUT | NO_FALLTHRU | BRANCH_TO_END => Ref(R::ConditionalJump),
        f if f == JUMPOUT | NO_FALLTHRU | RETURN => JumpTerminator,
        f if f == JUMPOUT | NO_FALLTHRU | BRANCH_INDIRECT => Ref(R::ComputedJump),
        f if f == BRANCH_INDIRECT | NO_FALLTHRU | RETURN => JumpTerminator,
        f if f == NO_FALLTHRU => Terminator,
        f if f == BRANCH_TO_END | JUMPOUT => Ref(R::ConditionalJump),
        f if f == NO_FALLTHRU | BRANCH_TO_END => FallThrough,
        _ => Invalid,
    }
}

/// The instruction's flow type, as a *reference* type — `None` for the arms mosura's
/// [`RefType`] does not model (`FALL_THROUGH`, the terminators, `INVALID`); callers fall back
/// to leaving the disassembler's base reference type in place.
pub fn flow_type(ops: &[PcodeOp], inst_start: u64, inst_next: u64) -> Option<RefType> {
    match classify(ops, inst_start, inst_next) {
        FlowKind::Ref(r) => Some(r),
        _ => None,
    }
}

/// `Instruction.hasFallthrough()` — whether flow continues to `inst_next`. Ghidra reads it off
/// the prototype's flow type (`FlowType.hasFallthrough`), which is what this does; classifying
/// off the last p-code op instead misreads every instruction with an internal loop.
pub fn has_fallthrough(ops: &[PcodeOp], inst_start: u64, inst_next: u64) -> bool {
    classify(ops, inst_start, inst_next).has_fallthrough()
}

/// Whether the instruction's flow type is exactly Ghidra's `RefType.TERMINATOR` — the
/// `RETURN | NO_FALLTHRU` and bare `NO_FALLTHRU` arms.
/// `SharedReturnAnalysisCmd.checkIfCouldHaveFallThruTo` compares against it directly.
pub fn is_terminator_flow(ops: &[PcodeOp], inst_start: u64, inst_next: u64) -> bool {
    classify(ops, inst_start, inst_next) == FlowKind::Terminator
}

/// `FlowOverride.getModifiedFlowType` — apply a flow override to a base flow type. Faithful
/// port of the `CALL_RETURN` arm (the only override mosura's analyzers set). Returns the
/// (possibly modified) flow type.
// faithful port of Ghidra's flow-override mapping; the computed/terminal branches map to the
// same RefType but test distinct flow properties, so the cascade is kept as-is
#[allow(clippy::if_same_then_else)]
pub fn modified_flow_type(original: RefType, ov: FlowOverride) -> RefType {
    let flow = original;
    // NONE, or a non jump/terminal/call flow, is returned unchanged.
    if ov == FlowOverride::None || !(is_jump(flow) || is_terminal(flow) || is_call(flow)) {
        return flow;
    }
    match ov {
        FlowOverride::None => flow,
        FlowOverride::CallReturn => {
            if is_conditional(flow) {
                if is_computed(flow) {
                    RefType::ConditionalComputedCall
                } else if is_terminal(flow) {
                    RefType::ComputedCallTerminator
                } else {
                    flow // don't replace
                }
            } else if is_computed(flow) {
                RefType::ComputedCallTerminator
            } else if is_terminal(flow) {
                RefType::ComputedCallTerminator
            } else {
                RefType::CallTerminator
            }
        }
    }
}

/// `RefTypeFactory.getDefaultJumpOrCallFlowType` — derive the *reference* type Ghidra
/// writes for a flow whose instruction flow-type is `flow` (used by the reference fixup in
/// `InstructionDB.setFlowOverride`, which re-derives the flow reference's type after an
/// override). Critically, a `CALL_TERMINATOR` *instruction* flow yields an
/// `UNCONDITIONAL_CALL` *reference* (Ghidra `RefType.CALL_TERMINATOR` doc: "A corresponding
/// Reference should generally specify UNCONDITIONAL_CALL"), and `COMPUTED_CALL_TERMINATOR`
/// yields `COMPUTED_CALL`. Returns `None` for a non jump/call flow (the Java `return null`).
pub fn default_jump_or_call_flow_type(flow: RefType) -> Option<RefType> {
    if is_conditional(flow) {
        if is_computed(flow) {
            if is_call(flow) {
                return Some(RefType::ConditionalComputedCall);
            } else if is_jump(flow) {
                return Some(RefType::ConditionalComputedJump);
            }
        } else if is_call(flow) {
            return Some(RefType::ConditionalCall);
        } else if is_jump(flow) {
            return Some(RefType::ConditionalJump);
        }
    }
    if is_computed(flow) {
        if is_call(flow) {
            return Some(RefType::ComputedCall);
        } else if is_jump(flow) {
            return Some(RefType::ComputedJump);
        }
    } else if is_call(flow) {
        return Some(RefType::UnconditionalCall);
    } else if is_jump(flow) {
        return Some(RefType::UnconditionalJump);
    }
    None
}

// RefType predicate helpers mirroring Ghidra's RefType.isJump/isCall/isComputed/etc. over
// the subset mosura models.
fn is_jump(r: RefType) -> bool {
    matches!(
        r,
        RefType::UnconditionalJump
            | RefType::ConditionalJump
            | RefType::ComputedJump
            | RefType::ConditionalComputedJump
    )
}
fn is_call(r: RefType) -> bool {
    matches!(
        r,
        RefType::UnconditionalCall
            | RefType::ConditionalCall
            | RefType::ComputedCall
            | RefType::ConditionalComputedCall
            | RefType::CallTerminator
            | RefType::ComputedCallTerminator
    )
}
fn is_computed(r: RefType) -> bool {
    matches!(
        r,
        RefType::ComputedJump
            | RefType::ComputedCall
            | RefType::ConditionalComputedJump
            | RefType::ConditionalComputedCall
            | RefType::ComputedCallTerminator
    )
}
fn is_conditional(r: RefType) -> bool {
    matches!(
        r,
        RefType::ConditionalJump | RefType::ConditionalCall | RefType::ConditionalComputedJump | RefType::ConditionalComputedCall
    )
}
fn is_terminal(r: RefType) -> bool {
    matches!(r, RefType::CallTerminator | RefType::ComputedCallTerminator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sleigh::pcode::{PArg, Varnode};

    fn ram(off: u64) -> PArg {
        PArg::Var(Varnode { space: "ram".into(), offset: off, size: 8 })
    }
    fn reg(off: u64) -> PArg {
        PArg::Var(Varnode { space: "register".into(), offset: off, size: 8 })
    }
    fn op(opcode: OpCode, ins: Vec<PArg>) -> PcodeOp {
        PcodeOp { opcode: opcode as u32, out: None, ins }
    }
    /// A one-instruction probe at 0x1000 of length 2, so `inst_next` is 0x1002 — no test
    /// destination below coincides with either, keeping them plain `JUMPOUT` targets.
    const START: u64 = 0x1000;
    const NEXT: u64 = 0x1002;
    fn ft(ops: &[PcodeOp]) -> Option<RefType> {
        flow_type(ops, START, NEXT)
    }
    fn is_term(ops: &[PcodeOp]) -> bool {
        is_terminator_flow(ops, START, NEXT)
    }
    fn falls(ops: &[PcodeOp]) -> bool {
        has_fallthrough(ops, START, NEXT)
    }

    #[test]
    fn branchind_is_computed_jump() {
        // `jmp *[mem]` / `jmp reg` → BRANCHIND → BRANCH_INDIRECT | NO_FALLTHRU.
        assert_eq!(ft(&[op(OpCode::Branchind, vec![ram(0x404000)])]), Some(RefType::ComputedJump));
        assert_eq!(ft(&[op(OpCode::Branchind, vec![reg(0)])]), Some(RefType::ComputedJump));
    }

    #[test]
    fn callind_is_computed_call() {
        assert_eq!(ft(&[op(OpCode::Callind, vec![reg(0)])]), Some(RefType::ComputedCall));
    }

    #[test]
    fn ram_branch_is_unconditional_jump_cbranch_conditional() {
        assert_eq!(ft(&[op(OpCode::Branch, vec![ram(0x401010)])]), Some(RefType::UnconditionalJump));
        assert_eq!(
            ft(&[op(OpCode::Cbranch, vec![ram(0x401010), reg(0x200)])]),
            Some(RefType::ConditionalJump)
        );
    }

    #[test]
    fn call_is_unconditional_call_ret_unmapped() {
        assert_eq!(ft(&[op(OpCode::Call, vec![ram(0x401100)])]), Some(RefType::UnconditionalCall));
        // RETURN → RETURN | NO_FALLTHRU → TERMINATOR (not in mosura's subset) → None.
        assert_eq!(ft(&[op(OpCode::Return, vec![reg(0x288)])]), None);
    }

    #[test]
    fn terminator_flow_is_ret_and_no_fallthru_only() {
        // `ret` → RETURN | NO_FALLTHRU → TERMINATOR.
        assert!(is_term(&[op(OpCode::Return, vec![reg(0x288)])]));
        // `hlt` → BRANCH to a `const` (p-code-relative) target → bare NO_FALLTHRU → TERMINATOR.
        assert!(is_term(&[op(
            OpCode::Branch,
            vec![PArg::Var(Varnode { space: "const".into(), offset: 0, size: 8 })]
        )]));
        // Everything with a real destination is not a terminator.
        assert!(!is_term(&[op(OpCode::Branch, vec![ram(0x401010)])]));
        assert!(!is_term(&[op(OpCode::Call, vec![ram(0x401100)])]));
        assert!(!is_term(&[op(OpCode::Branchind, vec![reg(0)])]));
        // No flow op at all → FALL_THROUGH, not TERMINATOR.
        assert!(!is_term(&[op(OpCode::Copy, vec![reg(0)])]));
    }

    /// The `J_NEXT` arms of `walkTemplates` (SleighInstructionPrototype.java:227,246). An
    /// instruction with an INTERNAL loop — x86 `rep movs`, whose lifted form is a guard
    /// `CBRANCH` to its own next address plus a p-code-relative `BRANCH` back — collapses to
    /// `NO_FALLTHRU | BRANCH_TO_END`, i.e. `FALL_THROUGH`. Reading the LAST p-code op instead
    /// sees the trailing `BRANCH` and calls it an unconditional jump, which is what split
    /// WAR2's `FUN_00012e68` at a `rep movsw`.
    #[test]
    fn rep_string_op_internal_loop_falls_through() {
        let pc_rel = PArg::Var(Varnode { space: "const".into(), offset: 3, size: 8 });
        let rep_movs = [
            op(OpCode::IntEqual, vec![reg(0x10), reg(0x20)]),
            op(OpCode::Cbranch, vec![ram(NEXT), reg(0x200)]), // guard exit → J_NEXT
            op(OpCode::Load, vec![reg(0x30)]),
            op(OpCode::Store, vec![reg(0x38)]),
            op(OpCode::Branch, vec![pc_rel]), // loop back → J_RELATIVE
        ];
        assert!(falls(&rep_movs), "`rep movs` falls through to the next instruction");
        assert!(!is_term(&rep_movs), "`rep movs` is FALL_THROUGH, not TERMINATOR");
        assert_eq!(ft(&rep_movs), None, "FALL_THROUGH is not a reference type");
    }

    /// The fall-through column of Ghidra's flow-type table (RefType.java `setHasFall`).
    #[test]
    fn has_fallthrough_matches_ghidras_flow_type_table() {
        assert!(falls(&[op(OpCode::Copy, vec![reg(0)])])); // FALL_THROUGH
        assert!(falls(&[op(OpCode::Call, vec![ram(0x401100)])])); // UNCONDITIONAL_CALL
        assert!(falls(&[op(OpCode::Callind, vec![reg(0)])])); // COMPUTED_CALL
        assert!(falls(&[op(OpCode::Cbranch, vec![ram(0x401010), reg(0x200)])])); // CONDITIONAL_JUMP
        assert!(!falls(&[op(OpCode::Branch, vec![ram(0x401010)])])); // UNCONDITIONAL_JUMP
        assert!(!falls(&[op(OpCode::Branchind, vec![reg(0)])])); // COMPUTED_JUMP
        assert!(!falls(&[op(OpCode::Return, vec![reg(0x288)])])); // TERMINATOR
    }

    #[test]
    fn call_return_override_makes_computed_call_terminator() {
        // COMPUTED_JUMP + CALL_RETURN → COMPUTED_CALL_TERMINATOR (the PLT tail-call case).
        assert_eq!(
            modified_flow_type(RefType::ComputedJump, FlowOverride::CallReturn),
            RefType::ComputedCallTerminator
        );
        // UNCONDITIONAL_JUMP + CALL_RETURN → CALL_TERMINATOR.
        assert_eq!(
            modified_flow_type(RefType::UnconditionalJump, FlowOverride::CallReturn),
            RefType::CallTerminator
        );
        // None override is identity.
        assert_eq!(
            modified_flow_type(RefType::ComputedJump, FlowOverride::None),
            RefType::ComputedJump
        );
    }
}
