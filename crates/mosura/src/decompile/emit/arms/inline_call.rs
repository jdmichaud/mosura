//! `inline-call` — a short-circuit clause whose only statement assigns a call's result to a
//! variable the clause's own condition consumes (`(a) || (iVar1 = f(x), iVar1 == 0)`) prints the
//! call inside the compare, `(a) || (f(x) == 0)`. Ghidra names every call result
//! (`ActionMarkExplicit::baseExplicit`, coreaction.cc:3015: `def->isCall()`), so the port prints
//! the comma form; this compiler materializes the clause's boolean from that form (`SETZ AL ;
//! AND EAX,0xff`) where the original — written with the call in the condition — branches on the
//! flags (`TEST EAX,EAX ; JNZ`): WAR2 FUN_0004d0f8 (EXACT with the call inlined), FUN_000164cc,
//! 50 functions on round f0 carry a comma-clause call and an extra `SETcc`. Value-identical: the
//! call keeps its position (it is the clause's only statement) and its single use is the compare.
//! The witness (`recovered.inline_call.sites`, from `buildconfig::inline_calls_from_evidence`
//! over this arm's candidates): no `SETcc` in the original between the call and the clause's
//! branch. A target-informed emit choice, NOT Ghidra.
//!
//! The arm is a SETUP pass (like `load-hoist`): it fills the printer's `force_implied` set with
//! the witnessed call results, consulted by `is_explicit`; the statement printer then emits no
//! statement for the call and the condition renders it inline.
use crate::decompile::block::BlockId;
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::{exit_basic, PrintC};
use crate::decompile::structure::{FlowKind, Structured};
use crate::decompile::varnode::VarnodeId;

/// The census, after the structure is built: every clause block that renders under Ghidra's
/// `comma_separate` modifier — operand 1 of a short-circuit node, and a `while` condition — whose
/// only statement is a call assignment the clause's branch consumes, reported as `(call address,
/// branch address)` and inlined where witnessed.
pub(crate) fn recognize(pr: &mut PrintC<'_>, s: &Structured) {
    let mut leaves: Vec<BlockId> = Vec::new();
    for idx in 0..s.blocks.len() {
        match s.blocks[idx].kind {
            FlowKind::CondAnd | FlowKind::CondOr => collect_leaves(s, s.blocks[idx].components[1], &mut leaves),
            FlowKind::WhileDo => collect_leaves(s, s.blocks[idx].components[0], &mut leaves),
            _ => {}
        }
    }
    leaves.sort_by_key(|b| b.0);
    leaves.dedup();
    for bid in leaves {
        let Some((v, call_pc, branch_pc)) = clause_call(pr, bid) else { continue };
        pr.report.inline_call.candidates.push((call_pc, branch_pc));
        if pr.recovered.inline_call.sites.contains(&call_pc) {
            pr.force_implied.insert(v);
        }
    }
}

/// The basic leaves under a condition node: a leaf itself, or every leaf of a nested
/// short-circuit (both operands render under the inherited modifier), or a list's exit block.
fn collect_leaves(s: &Structured, idx: usize, out: &mut Vec<BlockId>) {
    match s.blocks[idx].kind {
        FlowKind::Basic(bid) => out.push(bid),
        FlowKind::CondAnd | FlowKind::CondOr => {
            for &c in &s.blocks[idx].components {
                collect_leaves(s, c, out);
            }
        }
        _ => {
            if let Some(bid) = exit_basic(s, idx) {
                out.push(bid);
            }
        }
    }
}

/// The clause shape: the block's live CBRANCH; exactly one printable statement, a CALL/CALLIND
/// whose explicit output has one live use; that use reaches the branch condition through implied
/// single-use values inside the block; nothing else with a side effect or an explicit output.
fn clause_call(pr: &PrintC<'_>, bid: BlockId) -> Option<(VarnodeId, u64, u64)> {
    let ops: &[OpId] = &pr.f.block(bid).ops;
    let cbr = ops.iter().rev().copied().find(|&op| !pr.f.op(op).is_dead() && pr.f.op(op).code() == OpCode::Cbranch)?;
    let cond = pr.f.op(cbr).input(1)?;
    let mut call: Option<(OpId, VarnodeId)> = None;
    for &op in ops {
        let o = pr.f.op(op);
        if o.is_dead() || o.is_marker() {
            continue;
        }
        match o.code() {
            OpCode::Cbranch | OpCode::Branch => {}
            OpCode::Call | OpCode::Callind => {
                if call.is_some() {
                    return None;
                }
                let out = o.output?;
                if !pr.is_explicit(out) {
                    return None;
                }
                call = Some((op, out));
            }
            OpCode::Store | OpCode::Callother | OpCode::Return | OpCode::Branchind => return None,
            _ => {
                if o.output.is_some_and(|w| pr.is_explicit(w)) {
                    return None;
                }
            }
        }
    }
    let (cop, v) = call?;
    let uses: Vec<OpId> = pr.f.vn(v).descend.iter().copied().filter(|&u| !pr.f.op(u).is_dead()).collect();
    if uses.len() != 1 || pr.f.op(uses[0]).is_marker() {
        return None;
    }
    if !ops.contains(&uses[0]) {
        return None;
    }
    // forward from the use to the branch condition: implied, single-use values only
    let mut w = pr.f.op(uses[0]).output?;
    let mut steps = 0;
    while w != cond {
        if pr.is_explicit(w) {
            return None;
        }
        let ws: Vec<OpId> = pr.f.vn(w).descend.iter().copied().filter(|&u| !pr.f.op(u).is_dead()).collect();
        if ws.len() != 1 || !ops.contains(&ws[0]) {
            return None;
        }
        w = pr.f.op(ws[0]).output?;
        steps += 1;
        if steps > 8 {
            return None;
        }
    }
    Some((v, pr.f.op(cop).seqnum.pc.offset, pr.f.op(cbr).seqnum.pc.offset))
}

/// The inline-call's candidates the report pass collects (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Every comma-clause call assignment whose result the clause's branch consumes, as
    /// `(call address, branch address)`: the original either branches on the flags (no
    /// materialized boolean) or carries a `SETcc` between the two.
    pub candidates: Vec<(u64, u64)>,
}

/// The inline-call's witnessed decisions the recovered pass renders (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Sites {
    /// Call addresses whose result prints inline in the clause's condition (`inline-call`,
    /// `inline_call` candidates evidence, `buildconfig::inline_calls_from_evidence`).
    pub sites: std::collections::HashSet<u64>,
}
