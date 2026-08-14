//! Calling-convention facts a rebuild has to reproduce, recovered from the subject's own code.
//!
//! A prototype says *where* the arguments are. It does not say **who removes them from the
//! stack**, and that is not a free choice: it decides whether the function ends `RET` or `RET n`,
//! and whether each of its callers carries an `ADD ESP,n` afterwards. Get it wrong and every such
//! function is one instruction from exact, in both directions at once — measured on WAR2, 101
//! functions carry a `RET`/`RET n` divergence, 13 of them with no other defect at all.
//!
//! Unlike the rendering choices in [`crate::decompile::emit`], this is not something to search:
//! the subject states it. The function's own return instruction says exactly how far it moves the
//! stack pointer, and reading it is recovery of the same kind as reading a prologue to recover the
//! build flags — not a peek at the answer.
//!
//! The recovery is expressed over lifted p-code so it holds wherever SLEIGH does. `RET` and
//! `RET n` differ by one `INT_ADD` on the stack pointer; an architecture that returns through a
//! link register performs neither the load nor the adjustment and correctly recovers zero.

use crate::decompile::opcode::OpCode;
use crate::sleigh::pcode::{PArg, PcodeOp};
use crate::sleigh::Instruction;

/// The lifter reports opcodes as raw p-code numbers; `OpCode` is the canonical statement of that
/// numbering, so it is read through rather than copied as constants a third time.
fn is(op: &PcodeOp, code: OpCode) -> bool {
    OpCode::from_u32(op.opcode) == Some(code)
}

/// Bytes the **callee** removes from the stack beyond the return address — Ghidra's
/// `extrapop` less the return address itself.
///
/// `sp` is the stack pointer's `register`-space offset. Returns `None` when the function has no
/// return instruction, or when its returns disagree, because a single answer would be a guess and
/// a guess here is silently wrong code in every caller.
pub fn callee_stack_cleanup(insns: &[Instruction], sp: u64) -> Option<u32> {
    let mut answer: Option<u32> = None;
    for insn in insns {
        if !insn.ops.iter().any(|o| is(o, OpCode::Return)) {
            continue;
        }
        let n = cleanup_of(&insn.ops, sp)?;
        match answer {
            Some(prev) if prev != n => return None, // returns disagree — no single contract
            _ => answer = Some(n),
        }
    }
    answer
}

/// The cleanup performed by one return instruction: how far it moves the stack pointer, less the
/// slot it consumed for the return address.
fn cleanup_of(ops: &[PcodeOp], sp: u64) -> Option<u32> {
    // Everything this instruction adds to the stack pointer. `RET` adds the return-address slot;
    // `RET n` adds it and then n.
    let mut moved: i64 = 0;
    for op in ops {
        if !is(op, OpCode::IntAdd) {
            continue;
        }
        let Some(out) = op.out.as_ref() else { continue };
        if !is_reg(out, sp) {
            continue;
        }
        // `SP = SP + k`, in either operand order.
        let (a, b) = (op.ins.first(), op.ins.get(1));
        let k = match (a, b) {
            (Some(PArg::Var(x)), Some(PArg::Var(y))) if is_reg(x, sp) && y.is_const() => y.offset,
            (Some(PArg::Var(x)), Some(PArg::Var(y))) if is_reg(y, sp) && x.is_const() => x.offset,
            _ => return None, // a computed adjustment is not a fixed contract
        };
        moved += sign_extend(k, out.size);
    }

    // The return address occupies a stack slot only where the return actually took it from the
    // stack. An architecture that returns through a link register loads nothing and adjusts
    // nothing, and must recover 0 rather than a negative cleanup.
    let ret_slot = ops
        .iter()
        .find(|o| is(o, OpCode::Return))
        .and_then(|r| r.ins.first())
        .and_then(|a| match a {
            PArg::Var(v) => Some(v),
            _ => None,
        })
        .and_then(|target| {
            // Was `target` loaded from the stack pointer within this same instruction?
            ops.iter().find(|o| {
                is(o, OpCode::Load)
                    && o.out.as_ref().is_some_and(|out| out.space == target.space && out.offset == target.offset)
                    && o.ins.iter().any(|a| matches!(a, PArg::Var(v) if is_reg(v, sp)))
            })
        })
        .and_then(|load| load.out.as_ref().map(|o| o.size as i64))
        .unwrap_or(0);

    u32::try_from(moved - ret_slot).ok()
}

fn is_reg(v: &crate::sleigh::pcode::Varnode, off: u64) -> bool {
    v.space == "register" && v.offset == off
}

fn sign_extend(v: u64, size: u32) -> i64 {
    if size == 0 || size >= 8 {
        return v as i64;
    }
    let bits = size * 8;
    let m = 1u64 << (bits - 1);
    ((v & (m.wrapping_mul(2).wrapping_sub(1))) ^ m).wrapping_sub(m) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lift(hex: &str) -> Vec<Instruction> {
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        crate::sleigh::disassemble("x86:LE:32:default", &bytes, 0x1000).expect("language tables")
    }

    /// ESP's `register`-space offset for the x86 tables the tests lift with.
    fn esp() -> u64 {
        crate::lang::load_cached("x86:LE:32:default")
            .and_then(|(s, _)| s.register_offset("ESP"))
            .expect("ESP")
    }

    /// A plain return removes nothing of its own: it pops the return address and stops. Reporting
    /// 4 here would make every caller add 4 to the stack pointer that the original does not.
    #[test]
    fn a_plain_return_cleans_up_nothing() {
        assert_eq!(callee_stack_cleanup(&lift("c3"), esp()), Some(0));
    }

    /// `RET n` is the whole point: the callee removes n bytes of arguments, so its declaration has
    /// to say callee-pops and its callers must not add n themselves.
    #[test]
    fn ret_n_reports_exactly_n() {
        assert_eq!(callee_stack_cleanup(&lift("c20400"), esp()), Some(4));
        assert_eq!(callee_stack_cleanup(&lift("c20c00"), esp()), Some(12));
    }

    /// The instruction stream is scanned for returns wherever they are, not just at the end — a
    /// function with an early exit still has one contract.
    #[test]
    fn a_return_is_found_anywhere_in_the_stream() {
        // xor eax,eax ; ret 8
        assert_eq!(callee_stack_cleanup(&lift("31c0c20800"), esp()), Some(8));
    }

    /// Two returns that disagree describe no single contract, and answering anyway would put a
    /// wrong `ADD ESP` in every caller. `None` keeps the caller honest about not knowing.
    #[test]
    fn disagreeing_returns_have_no_single_answer() {
        // ret ; ret 4  — two exits, two different contracts
        assert_eq!(callee_stack_cleanup(&lift("c3c20400"), esp()), None);
    }

    /// A stream with no return at all yields no contract rather than a default one.
    #[test]
    fn no_return_means_no_answer() {
        assert_eq!(callee_stack_cleanup(&lift("31c0"), esp()), None);
    }

    /// Stack adjustments that are not part of the return do not count: an epilogue's `ADD ESP,8`
    /// balances the frame, it does not remove arguments. Only the returning instruction's own
    /// movement is the contract.
    #[test]
    fn frame_teardown_before_the_return_is_not_cleanup() {
        // add esp,8 ; ret
        assert_eq!(callee_stack_cleanup(&lift("83c408c3"), esp()), Some(0));
        // add esp,8 ; ret 4
        assert_eq!(callee_stack_cleanup(&lift("83c408c20400"), esp()), Some(4));
    }
}
