//! `sum-order=original` — the terms of a left-nested implicit INT_ADD chain print in the ORIGINAL's
//! schedule order (each inline term placed by the earliest original address among its ops,
//! swapped within the slots such terms occupy): Watcom evaluates a sum's terms in source order,
//! so two independent terms schedule as written, while the reference print keeps the IR's
//! left-nested order — Ghidra's term canonicalization, not the source's. A target-informed emit
//! choice, NOT Ghidra. The gate is the `sum-order` axis of `EmitChoices` (default `ghidra` = the
//! reference order; the survey's RECOVERED emit selects `original` — where the old flag applied;
//! raw/ has no recovery and keeps the reference order), replacing the per-function `RecoveredChoices::sum_order` flag the survey set from the
//! `MOSURA_SUMORD` environment variable (review R2b, commit 4 — fable-b's finding: that flag was
//! no witness, it was a landed rendering choice behind an env var). The evidence is the IR's own
//! original addresses, so there is no `*_from_evidence` witness: the decision is the axis itself.
//!
//! Moved verbatim out of printc.rs (commit 4): the reordering (`sum_chain_reordered`, one caller,
//! with its own recursive helper `term_min_pc`) and the consult that sat inline in `render_op_inner`'s `IntAdd` arm; the only textual changes
//! are `self.` → `pr.`, the sibling call, the gate's path (the arm's State from the axis) and
//! the answer form (`return r` → `return Some(r)`).
//!
//! Review R6 settled the experiment leftovers this arm carried: the `[sumord]` census print is the
//! `sum-order` topic of `crate::debug` (`--debug sum-order`, commit 2); the context knob
//! `MOSURA_SUMORD_CTX=all` (the non-pointer A/B, measured on zc26 and lost) is gone with its branch
//! (commit 3a) — pointer-context chains only, the landed behaviour.
use crate::decompile::emit::{EmitChoices, SumOrder};
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;
use crate::decompile::varnode::VarnodeId;

/// The arm's state: its configuration (the `sum-order` axis).
#[derive(Debug, Default)]
pub(crate) struct State {
    /// `sum-order=original`: the chain's terms print in the original's schedule order.
    pub(crate) original: bool,
}

impl State {
    pub(crate) fn new(choices: &EmitChoices) -> Self {
        State { original: choices.sum_order == SumOrder::Original }
    }
}

/// The arm's answer at `ValueSite::Sum`: `op` the INT_ADD root.
pub(crate) fn render(pr: &mut PrintC<'_>, op: OpId) -> Option<(String, u8)> {
    if pr.arms.sum_order.original {
        if let Some(r) = sum_chain_reordered(pr, op) {
            return Some(r);
        }
    }
    None
}

/// Render `v` as an operand of an operator of precedence `parent`, parenthesizing when
/// the sub-expression binds looser (`right` operands also parenthesize at equal
/// precedence, for left-associativity).
/// `sum-order` (see [`RecoveredChoices::sum_order`]): the left-nested implicit INT_ADD
/// chain rooted at `op`, when its value is a LOAD/STORE address (directly or through one
/// CAST/COPY/PTRADD), printed with its terms in the original's computation order. Each
/// term prints through the same cast rule as the reference (`cast_operand` on the chain
/// op/slot that holds it), so only the ORDER changes. `None` when the chain is not in
/// pointer context, has fewer than two non-constant terms, or already prints in that
/// order — the reference arm then renders it.
fn sum_chain_reordered(pr: &mut PrintC<'_>, op: OpId) -> Option<(String, u8)> {
    let ram = pr.f.spaces.by_name("ram");
    // pointer context: the chain's value feeds an address slot
    let out = pr.f.op(op).output?;
    let is_addr_use = |s: &PrintC<'_>, v: VarnodeId| -> bool {
        s.f.vn(v).descend.iter().any(|&c| {
            let co = s.f.op(c);
            matches!(co.code(), OpCode::Load | OpCode::Store) && co.input(1) == Some(v)
        })
    };
    let in_ptr_context = is_addr_use(pr, out)
        || pr.f.vn(out).descend.iter().any(|&c| {
            let co = pr.f.op(c);
            matches!(co.code(), OpCode::Cast | OpCode::Copy | OpCode::Ptradd)
                && co.output.is_some_and(|o2| is_addr_use(pr, o2))
        });
    // SUM-ORDER CENSUS (MOSURA_SUMORD_CENSUS=1): size the lever outside pointer context
    // — the reorder is computed for every chain and reported with its context; only
    // pointer-context chains change the print.
    let census = crate::debug::on(crate::debug::Topic::SumOrder);
    if !in_ptr_context && !census {
        return None;
    }
    // flatten the left spine: ((A + K) + B) prints A, K, B
    let inline_add = |s: &PrintC<'_>, v: VarnodeId| -> Option<OpId> {
        let vn = s.f.vn(v);
        let d = vn.def?;
        (s.f.op(d).code() == OpCode::IntAdd && !s.is_explicit(v) && vn.descend.len() == 1).then_some(d)
    };
    let mut rights: Vec<(OpId, usize)> = Vec::new();
    let mut cur = op;
    while let Some(inner) = pr.f.op(cur).input(0).and_then(|v| inline_add(pr, v)) {
        rights.push((cur, 1));
        cur = inner;
    }
    let mut terms: Vec<(OpId, usize)> = vec![(cur, 0), (cur, 1)];
    terms.extend(rights.into_iter().rev());
    // Only COMPUTED terms (those with inline ops at original addresses) move, and only
    // among the slots they already occupy, ordered by their earliest address; constants
    // and bare variables keep their reference slots. Measured (zc25): moving a constant
    // out of the middle cost FUN_00031100 its EXACT, and pushing a bare variable behind
    // the computed terms cost FUN_0005fb24 its shape (its original evaluates
    // `iVar1 + 0x10` first, by LEA) — while the reorder that converts FUN_000294b8 and
    // the 0x25a04 family holds with the constant left in place (dumpwc probes).
    let mut slots: Vec<usize> = Vec::new();
    let mut pcs: Vec<u64> = Vec::new();
    for (i, &(o, slot)) in terms.iter().enumerate() {
        let v = pr.f.op(o).input(slot)?;
        if !pr.f.vn(v).is_constant() {
            if let Some(pc) = term_min_pc(pr, v, ram, 0) {
                slots.push(i);
                pcs.push(pc);
            }
        }
    }
    if slots.len() < 2 {
        return None;
    }
    let mut order: Vec<usize> = (0..slots.len()).collect();
    order.sort_by_key(|&k| pcs[k]); // stable: ties keep the reference order
    if order.iter().enumerate().all(|(k, &j)| k == j) {
        return None;
    }
    if census {
        debug!(crate::debug::Topic::SumOrder, "pc {:#x} ctx={} terms={}", pr.f.op(op).seqnum.pc.offset, if in_ptr_context { "ptr" } else { "nonptr" }, terms.len());
        if !in_ptr_context {
            return None;
        }
    }
    let mut placed: Vec<(OpId, usize)> = terms.clone();
    for (k, &j) in order.iter().enumerate() {
        placed[slots[k]] = terms[slots[j]];
    }
    let mut parts: Vec<String> = Vec::new();
    for (i, &(o, slot)) in placed.iter().enumerate() {
        parts.push(pr.cast_operand(o, slot, 12, i > 0));
    }
    Some((parts.join(" + "), 12))
}

/// The earliest original (ram) address among the inline ops that compute `v` — the
/// instruction where the term's computation starts. `None` for constants, explicit
/// (named) values and inputs, which materialize nothing of their own here.
fn term_min_pc(pr: &PrintC<'_>, v: VarnodeId, ram: Option<crate::decompile::space::SpaceId>, depth: usize) -> Option<u64> {
    let vn = pr.f.vn(v);
    if depth > 16 || vn.is_constant() || pr.is_explicit(v) {
        return None;
    }
    let d = vn.def?;
    let o = pr.f.op(d);
    let mut best = (Some(o.seqnum.pc.space) == ram).then_some(o.seqnum.pc.offset);
    for k in 0..o.num_inputs() {
        if let Some(pc) = o.input(k).and_then(|iv| term_min_pc(pr, iv, ram, depth + 1)) {
            best = Some(best.map_or(pc, |b: u64| b.min(pc)));
        }
    }
    best
}
