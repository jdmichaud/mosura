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

/// What a definition's own pop-contract reading amounts to, which is three answers and not two.
///
/// [`callee_stack_cleanup`] returns `None` both for a body with no return at all and for one whose
/// returns disagree, and the two must be treated differently: the first is a function whose
/// contract simply is not written in its own region (a tail `JMP` into a shared epilogue), where
/// weaker evidence is the only evidence there is; the second is a function that appears to hold two
/// contracts, which no function does — it means the region boundary took in a neighbour's `RET`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnPopContract {
    /// The function's own returns agree: direct evidence, and it outranks anything indirect.
    Agreed(u32),
    /// No return in the region at all — the contract is not stated here.
    Silent,
    /// Returns that disagree: a boundary error, not a second contract.
    Undecided,
}

/// Read a definition's own pop-contract, separating "not stated here" from "states two things".
pub fn own_pop_contract(insns: &[Instruction], sp: u64) -> OwnPopContract {
    let has_return = insns.iter().any(|i| i.ops.iter().any(|o| is(o, OpCode::Return)));
    match (callee_stack_cleanup(insns, sp), has_return) {
        (Some(n), _) => OwnPopContract::Agreed(n),
        (None, false) => OwnPopContract::Silent,
        (None, true) => OwnPopContract::Undecided,
    }
}

/// The contract a definition should DECLARE, given its own reading and a CFG walk's answer
/// (`Funcdata::ret_pop`, which is what every CALLER of this function uses).
///
/// The walk is the fallback and never the override. It can leave the function through a shared
/// epilogue and read a return belonging to someone else's contract — measured on WAR2: taking it
/// unconditionally put `RET 0x4`/`RET 0x8`/`RET 0x18` on 8 library functions whose originals end in
/// a bare `RET`. So it answers only where the body is SILENT, which is exactly the tail-JMP case
/// where the definition would otherwise fall back on the callee-pops default and contradict every
/// caller. `Undecided` declares nothing: covering a boundary error with a walk that has the same
/// weakness would hide it.
pub fn declared_pop_contract(own: OwnPopContract, walked: Option<u32>) -> Option<u32> {
    match own {
        OwnPopContract::Agreed(n) => Some(n),
        OwnPopContract::Silent => walked,
        OwnPopContract::Undecided => None,
    }
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

/// The CALLER-side argument cleanup at one call site: `Some(n)` iff `insn` (the call's
/// fallthrough instruction) does nothing but move the stack pointer UP by a fixed `n > 0`
/// bytes — Watcom's `ADD ESP,n` after a `__cdecl`/vararg call (`83 C4 n` / `81 C4 n`). The
/// evidence half of per-call prototype-model selection: a call the CALLER cleans while the
/// callee's own `RET` pops nothing is a caller-parms call, not `__watcall`.
///
/// Deliberately rejects instructions with memory or flow ops (`POP reg` also adds 4 to ESP,
/// but popping a VALUE is indistinguishable there from popping an argument; Watcom's cdecl
/// cleanup idiom is the ADD).
pub fn caller_stack_cleanup(insn: &Instruction, sp: u64) -> Option<u32> {
    use OpCode::*;
    if insn.ops.iter().any(|o| {
        matches!(
            OpCode::from_u32(o.opcode),
            Some(Return | Call | Callind | Branch | Cbranch | Branchind | Load | Store)
        )
    }) {
        return None;
    }
    let n = cleanup_of(&insn.ops, sp)?;
    (n > 0 && n % 4 == 0 && n <= 500).then_some(n)
}

/// The CALLER-side cleanup for the call whose fallthrough begins `window` — [`caller_stack_cleanup`]
/// with the scheduler accounted for. Watcom's -onatx hoists the next statement's loads across the
/// `ADD ESP,n` (WAR2 0x33ad0: `CALL sprintf ; MOV AH,[0x8127a] ; ADD ESP,0xc`), so the cleanup is
/// not always the first instruction after the call. Walk the window, skipping instructions that
/// neither touch the stack pointer nor transfer control; stop — the evidence is absent, not merely
/// displaced — at any flow op or any other stack-pointer use, so a cleanup is never claimed across
/// a block boundary or a PUSH/POP.
pub fn caller_stack_cleanup_scan(window: &[Instruction], sp: u64) -> Option<u32> {
    use OpCode::*;
    for insn in window {
        if let Some(n) = caller_stack_cleanup(insn, sp) {
            return Some(n);
        }
        let touches_sp_or_flow = insn.ops.iter().any(|o| {
            matches!(
                OpCode::from_u32(o.opcode),
                Some(Return | Call | Callind | Branch | Cbranch | Branchind)
            ) || o.out.as_ref().is_some_and(|v| is_reg(v, sp))
                || o.ins.iter().any(|a| matches!(a, PArg::Var(v) if is_reg(v, sp)))
        });
        if touches_sp_or_flow {
            return None;
        }
    }
    None
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

    /// The three readings a body admits, which `callee_stack_cleanup`'s `Option` cannot tell apart:
    /// a return that answers, no return at all, and returns that contradict each other.
    #[test]
    fn a_body_states_its_contract_or_states_nothing_or_states_two_things() {
        // ret
        assert_eq!(own_pop_contract(&lift("c3"), esp()), OwnPopContract::Agreed(0));
        // ret 8
        assert_eq!(own_pop_contract(&lift("c20800"), esp()), OwnPopContract::Agreed(8));
        // jmp +0 — a body that never returns inside its own region (the tail-JMP shape)
        assert_eq!(own_pop_contract(&lift("eb00"), esp()), OwnPopContract::Silent);
        // ret 8 ; ret — one function cannot pop two different amounts
        assert_eq!(own_pop_contract(&lift("c20800c3"), esp()), OwnPopContract::Undecided);
    }

    /// The walk is a FALLBACK. It answers only for a silent body; it never overrides the function's
    /// own returns, and it never covers a boundary error.
    ///
    /// Both directions are pinned because taking the walk unconditionally was measurably wrong:
    /// on WAR2 it put `RET 0x4`/`RET 0x8`/`RET 0x18` on 8 library functions whose originals end in
    /// a bare `RET`, the walk having left the function through a shared epilogue.
    #[test]
    fn the_walk_fills_a_silent_body_and_never_overrides_one_that_speaks() {
        use OwnPopContract::*;
        // silent: the walk is the only evidence there is — this is the case that fixes the defect
        assert_eq!(declared_pop_contract(Silent, Some(0)), Some(0));
        assert_eq!(declared_pop_contract(Silent, None), None);
        // the body speaks: the walk cannot contradict it, in either direction
        assert_eq!(declared_pop_contract(Agreed(0), Some(8)), Some(0));
        assert_eq!(declared_pop_contract(Agreed(8), Some(0)), Some(8));
        // a boundary error declares nothing rather than borrowing an answer with the same weakness
        assert_eq!(declared_pop_contract(Undecided, Some(0)), None);
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

    /// The direct shape: the cleanup IS the first instruction of the window.
    #[test]
    fn scan_finds_the_immediate_cleanup() {
        // add esp,0xc ; test ah,ah
        assert_eq!(caller_stack_cleanup_scan(&lift("83c40c84e4"), esp()), Some(12));
    }

    /// The scheduler shape that lost sprintf's arguments (WAR2 0x33ad0): a load interleaved
    /// between the call and its cleanup must be skipped, not treated as evidence-absent.
    #[test]
    fn scan_skips_a_scheduled_load_before_the_cleanup() {
        // mov ah,[0x8127a] ; add esp,0xc ; test ah,ah
        assert_eq!(caller_stack_cleanup_scan(&lift("8a257a12080083c40c84e4"), esp()), Some(12));
    }

    /// A PUSH between the call and a later ADD is another stack-pointer use: the window's stack
    /// discipline is broken and no cleanup may be claimed.
    #[test]
    fn scan_stops_at_a_push() {
        // push eax ; add esp,0xc
        assert_eq!(caller_stack_cleanup_scan(&lift("5083c40c"), esp()), None);
    }

    /// A branch ends the basic block: a cleanup on the far side belongs to another path.
    #[test]
    fn scan_stops_at_a_branch() {
        // jz +2 ; add esp,0xc
        assert_eq!(caller_stack_cleanup_scan(&lift("740283c40c"), esp()), None);
    }

    /// A POP also adds to ESP, but popping a VALUE is indistinguishable from popping an
    /// argument — it is an ESP use, so the scan stops rather than skipping it.
    #[test]
    fn scan_stops_at_a_pop() {
        // pop ecx ; add esp,8
        assert_eq!(caller_stack_cleanup_scan(&lift("5983c408"), esp()), None);
    }
}
