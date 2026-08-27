//! `return-split=paths` — the tail pair [plain `if` testing B] + [basic whose sole statement
//! returns (zext of) the SAME B] prints as per-path constant returns: `return 1;` injected at the
//! body's end and `return 0;` on the fall-through (constants swapped when the structured condition
//! is the negation). Value-identical by construction — the returned varnode IS the tested one, so
//! it is true exactly on the taken path; gates: no else arm, no goto records on either component,
//! nothing else printable in the tail block. Per function under the `return-split` axis, or per
//! site by witness (`recovered.return_split_sites`, from `buildconfig::split_returns_from_evidence`
//! over this arm's `return_split_candidates` report). A target-informed emit choice, NOT Ghidra:
//! the reference decompiler prints the merged boolean return.
//!
//! Moved verbatim out of printc.rs (review R2b, commit 7): the consult that sat inline in
//! `emit_structured_body`'s `FlowKind::List` walk and its three single-caller helpers
//! (`sole_bool_return`, `same_bool_value`, `emit_if_with_tail`); the only textual changes are
//! `self.` → `pr.`, the sibling calls, `comps[i + 1]` → the site's `tail`, the flag's path (the
//! arm's State from the axis) and the answer form (`i += 2; continue` → `Answer::Emitted`, the
//! port advancing past the pair). The pair's PRECONDITION — two components left in the list —
//! stays the port's: it is what makes the site exist.
//!
//! The arm answers ONE site kind, `SiteKind::ListTail`.
// return-split=paths (the axis doc in emit.rs carries the measured probe): the
// tail pair [plain `if` testing B] + [basic whose sole statement returns
// (zext of) the SAME B] prints as per-path constant returns — `return 1;`
// injected at the body's end and `return 0;` on the fall-through (constants
// swapped when the structured condition is the negation). Value-identical by
// construction: the returned varnode IS the tested one, so it is true exactly
// on the taken path. Gates: no else arm, no goto records on either component,
// and nothing else printable in the tail block.
use crate::decompile::block::BlockId;
use crate::decompile::emit::arms::{Answer, Arm, Site, SiteKind};
use crate::decompile::emit::{EmitChoices, ReturnSplit};
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;
use crate::decompile::varnode::VarnodeId;
use crate::decompile::structure::{FlowKind, Structured};
use std::fmt::Write as _;

/// The arm's state: its configuration (the witness set is the port's).
#[derive(Debug, Default)]
pub(crate) struct State {
    /// `return-split=paths` is on for the whole function.
    pub(crate) paths: bool,
}

impl State {
    pub(crate) fn new(choices: &EmitChoices) -> Self {
        State { paths: choices.return_split == ReturnSplit::Paths }
    }
}

/// The arm, as the [`super::ARMS`] table holds it.
pub const ARM: Arm = Arm {
    name: "return-split: a tail boolean return as per-path constant returns (return-split=paths)",
    kinds: &[SiteKind::ListTail],
    try_emit,
};

fn try_emit(pr: &mut PrintC<'_>, site: Site<'_>, out: &mut String) -> Option<Answer> {
    let Site::ListTail { s, c, tail, indent } = site else { return None };
    if matches!(s.blocks[c].kind, FlowKind::If)
        && s.node_gotos.get(&c).is_none()
        && s.node_gotos.get(&tail).is_none()
    {
        if let (Some(cond), Some((tail_bid, ret_b))) = (
            pr.plain_if_condition_vn(s, c),
            sole_bool_return(pr, s, tail),
        ) {
            // structural candidacy holds — record it for the target profile
            // (on EVERY print, both axis values), then apply under the axis
            // OR a recovered per-site decision
            let key = pr.plain_if_branch_pc(s, c);
            if let Some(pc) = key {
                pr.report.return_split_candidates.push(pc);
            }
            let apply = pr.arms.return_split.paths
                || key.is_some_and(|pc| {
                    pr.recovered.return_split_sites.contains(&pc)
                });
            if apply && same_bool_value(pr, cond, ret_b) {
                let negated = s.blocks[c].negated;
                let (then_k, tail_k) = if negated { (0, 1) } else { (1, 0) };
                emit_if_with_tail(pr, s, c, indent, out, &format!("return {then_k};"));
                let pad = "  ".repeat(indent);
                let _ = writeln!(out, "{pad}return {tail_k};");
                // the tail block's ops are consumed by this rendering
                let _ = tail_bid;
                return Some(Answer::Emitted);
            }
        }
    }
    None
}

/// The boolean behind a basic block whose ONLY printable statement is `return (zext of)
/// B` with `B` a bool-op output: `Some((block, B))`, else `None`. Ops that inline into
/// the return expression (implied outputs) are fine; anything that would print its own
/// statement (explicit output, store, call) declines.
fn sole_bool_return(pr: &PrintC<'_>, s: &Structured, tail_idx: usize) -> Option<(BlockId, VarnodeId)> {
    let FlowKind::Basic(bid) = s.blocks[tail_idx].kind else { return None };
    let mut ret = None;
    for &op in &pr.f.block(bid).ops {
        let o = pr.f.op(op);
        if o.is_dead() || o.is_marker() {
            continue;
        }
        match o.code() {
            OpCode::Return => {
                if ret.is_some() {
                    return None;
                }
                ret = Some(op);
            }
            OpCode::Store | OpCode::Call | OpCode::Callind | OpCode::Callother => return None,
            OpCode::Branch | OpCode::Cbranch | OpCode::Branchind => return None,
            _ => {
                if o.output.is_some_and(|v| pr.is_explicit(v)) {
                    return None; // would print its own assignment before the return
                }
            }
        }
    }
    let ret = ret?;
    let mut v = pr.f.op(ret).input(1)?;
    // peel the printer-transparent links (COPY/ZEXT chains) down to the boolean
    for _ in 0..6 {
        let d = pr.f.vn(v).def?;
        if pr.f.op(d).is_bool_output() {
            if pr.f.vn(v).size != 1 {
                return None;
            }
            return Some((bid, v));
        }
        match pr.f.op(d).code() {
            OpCode::Copy | OpCode::IntZext => v = pr.f.op(d).input(0)?,
            _ => return None,
        }
    }
    None
}

/// Whether two 1-byte booleans provably hold the same value: the same varnode, or
/// outputs of two bool ops with the same opcode and pairwise-identical inputs (the
/// rules duplicate the predicate rather than CSE it — the branch's compare and the
/// return's compare are distinct ops over the same operands in the measured IR).
fn same_bool_value(pr: &PrintC<'_>, a: VarnodeId, b: VarnodeId) -> bool {
    if a == b {
        return true;
    }
    let (Some(da), Some(db)) = (pr.f.vn(a).def, pr.f.vn(b).def) else { return false };
    let (oa, ob) = (pr.f.op(da), pr.f.op(db));
    if oa.code() != ob.code() || oa.num_inputs() != ob.num_inputs() || !oa.is_bool_output() {
        return false;
    }
    (0..oa.num_inputs()).all(|i| match (oa.input(i), ob.input(i)) {
        (Some(x), Some(y)) => {
            x == y
                || (pr.f.vn(x).is_constant()
                    && pr.f.vn(y).is_constant()
                    && pr.f.vn(x).constant_value() == pr.f.vn(y).constant_value()
                    && pr.f.vn(x).size == pr.f.vn(y).size)
        }
        _ => false,
    })
}

/// Emit a `FlowKind::If` / `FlowKind::IfElse`, collapsing `else { if … }` into `else if …`.
///
/// Faithful port of `PrintC::emitBlockIf`'s pending-brace handling (printc.cc:2882-2943): when
/// an `if`/`else`'s else-arm is itself an `if` (`FlowBlock::t_if`), Ghidra prints the `else`
/// keyword and emits the nested `if` in "pending brace" mode — the nested `if`'s opening brace
/// is only issued if its condition block emits a leading statement; otherwise the `if` glues
/// onto the `else` on one line (`else if (…)`). `else_if` is true when this block sits in that
/// else-position and the caller has just written the bare `else` keyword (no trailing newline).
/// ccompare normalizes `else { if … }` and `else if …` to the same token skeleton, so this
/// changes no corpus score — it makes the emitted C match Ghidra's exact rendering.
/// `emit_if` with an extra statement injected as the LAST line of the then-body — the
/// `return-split` rendering. Only called for plain `If` (no else), where the body's
/// closing brace is the emission's final line.
fn emit_if_with_tail(pr: &mut PrintC<'_>, s: &Structured, idx: usize, indent: usize, out: &mut String, tail: &str) {
    let mut buf = String::new();
    pr.emit_if(s, idx, indent, &mut buf, false);
    // insert before the final closing-brace line
    let insert_at = buf.trim_end_matches('\n').rfind('\n').map(|p| p + 1).unwrap_or(0);
    let inner_pad = "  ".repeat(indent + 1);
    buf.insert_str(insert_at, &format!("{inner_pad}{tail}\n"));
    out.push_str(&buf);
}
