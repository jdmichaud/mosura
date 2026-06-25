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

/// Per-op flow flags (Ghidra `walkTemplates`). A real flow `BRANCH`/`CBRANCH` is one whose
/// first input is a `ram`-space target (the lifted form of `JUMPOUT`); a `const`-space
/// target is an in-instruction p-code-relative branch (`J_RELATIVE`/`J_NEXT`), which is
/// `NO_FALLTHRU`/`BRANCH_TO_END` respectively. Returns `None` for a non-flow op.
fn op_flow_flags(op: &PcodeOp) -> Option<u32> {
    let target_is_ram = matches!(op.ins.first(), Some(PArg::Var(v)) if v.space == "ram");
    match OpCode::from_u32(op.opcode) {
        Some(OpCode::Branchind) => Some(BRANCH_INDIRECT | NO_FALLTHRU),
        Some(OpCode::Branch) => Some(if target_is_ram {
            // A `ram` target is a branch out of the instruction (ConstTpl default branch).
            JUMPOUT | NO_FALLTHRU
        } else {
            // A `const` p-code-relative branch: J_RELATIVE/J_START → NO_FALLTHRU.
            NO_FALLTHRU
        }),
        Some(OpCode::Cbranch) => Some(if target_is_ram {
            JUMPOUT
        } else {
            // A `const` p-code-relative conditional branch (internal): no flow flag.
            0
        }),
        Some(OpCode::Call) => Some(CALL),
        Some(OpCode::Callind) => Some(CALL_INDIRECT),
        Some(OpCode::Return) => Some(RETURN | NO_FALLTHRU),
        _ => None,
    }
}

/// Collapse the accumulated per-op flags to a flow type
/// (`SleighInstructionPrototype.flowListToFlowType`): the running flags clear
/// `NO_FALLTHRU | CROSSBUILD | LABEL` before OR-ing in each op's flags, so the last
/// flow op dominates the fall-through decision.
pub fn flow_type(ops: &[PcodeOp]) -> Option<RefType> {
    let mut have_flow = false;
    let mut flags: u32 = 0;
    for op in ops {
        if let Some(f) = op_flow_flags(op) {
            flags &= !(NO_FALLTHRU | CROSSBUILD | LABEL);
            flags |= f;
            have_flow = true;
        }
    }
    if !have_flow {
        return None; // no flow op → FALL_THROUGH (handled by the caller)
    }
    convert_flow_flags(flags)
}

/// `SleighInstructionPrototype.convertFlowFlags` — map the flag set to a standard flow
/// type. Returns `None` for the cases mosura's `RefType` doesn't model (the conditional /
/// label / cross-build forms that don't arise for the x86-64 flow we classify here);
/// callers fall back to leaving the disassembler's base reference type in place.
fn convert_flow_flags(mut flow_flags: u32) -> Option<RefType> {
    if flow_flags & LABEL != 0 {
        flow_flags |= BRANCH_TO_END;
    }
    flow_flags &= !(CROSSBUILD | LABEL);
    // The exact `switch (flowFlags)` in convertFlowFlags. Only the arms whose result is in
    // mosura's RefType subset are mapped; the others return None (unmodeled).
    Some(match flow_flags {
        0 | BRANCH_TO_END => return None, // FALL_THROUGH (not a reference type)
        f if f == CALL => RefType::UnconditionalCall,
        f if f == CALL_INDIRECT => RefType::ComputedCall,
        f if f == BRANCH_INDIRECT | NO_FALLTHRU => RefType::ComputedJump,
        f if f == JUMPOUT => RefType::ConditionalJump,
        f if f == JUMPOUT | NO_FALLTHRU => RefType::UnconditionalJump,
        f if f == JUMPOUT | NO_FALLTHRU | BRANCH_TO_END => RefType::ConditionalJump,
        f if f == BRANCH_TO_END | JUMPOUT => RefType::ConditionalJump,
        // CALL_INDIRECT | NO_FALLTHRU | RETURN → COMPUTED_CALL_TERMINATOR; CALL | NO_FALLTHRU
        // | RETURN → CALL_TERMINATOR; etc. — not reachable from a single x86 instruction's
        // base flags (those terminator forms come from the FlowOverride below), so left
        // unmodeled.
        _ => return None,
    })
}

/// `FlowOverride.getModifiedFlowType` — apply a flow override to a base flow type. Faithful
/// port of the `CALL_RETURN` arm (the only override mosura's analyzers set). Returns the
/// (possibly modified) flow type.
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

    #[test]
    fn branchind_is_computed_jump() {
        // `jmp *[mem]` / `jmp reg` → BRANCHIND → BRANCH_INDIRECT | NO_FALLTHRU.
        assert_eq!(flow_type(&[op(OpCode::Branchind, vec![ram(0x404000)])]), Some(RefType::ComputedJump));
        assert_eq!(flow_type(&[op(OpCode::Branchind, vec![reg(0)])]), Some(RefType::ComputedJump));
    }

    #[test]
    fn callind_is_computed_call() {
        assert_eq!(flow_type(&[op(OpCode::Callind, vec![reg(0)])]), Some(RefType::ComputedCall));
    }

    #[test]
    fn ram_branch_is_unconditional_jump_cbranch_conditional() {
        assert_eq!(flow_type(&[op(OpCode::Branch, vec![ram(0x401010)])]), Some(RefType::UnconditionalJump));
        assert_eq!(
            flow_type(&[op(OpCode::Cbranch, vec![ram(0x401010), reg(0x200)])]),
            Some(RefType::ConditionalJump)
        );
    }

    #[test]
    fn call_is_unconditional_call_ret_unmapped() {
        assert_eq!(flow_type(&[op(OpCode::Call, vec![ram(0x401100)])]), Some(RefType::UnconditionalCall));
        // RETURN → RETURN | NO_FALLTHRU → TERMINATOR (not in mosura's subset) → None.
        assert_eq!(flow_type(&[op(OpCode::Return, vec![reg(0x288)])]), None);
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
