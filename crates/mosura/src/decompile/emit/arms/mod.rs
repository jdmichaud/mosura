//! The Watcom emit ARMS (review R2): target-informed emit choices — NOT Ghidra — that the faithful
//! printer (`printc.rs`, a port) reaches through named seams only. Each arm becomes its own file
//! here, named after its `docs/*-arm.md`, moved verbatim from printc.rs one commit at a time under
//! the census-identity contract (a full emit's `recovered/` AND `raw/` byte-identical to the
//! previous tree, the corpus gates green).
//!
//! THE SEAMS — every arm effect passes through one of these, nothing else:
//! - [`try_emit`], the statement-level hook: the port calls it at the [`Site`]s — a structured loop
//!   node, the head of an if, an if without an else, one op of a block's statement list — and the
//!   arms answer in one FIXED order ([`ARMS`]), first match wins; no two arms declare the same site
//!   kind (a unit test over the table holds it), so a future overlap fails loudly instead of being
//!   resolved by list order. At this skeleton the table is the documented order and `try_emit`
//!   still dispatches by a `match` on the site (the arms live in printc.rs); from commit 1 each
//!   moved arm becomes a value the table holds (`Arm { name, kinds, try_emit }`) and `try_emit`
//!   iterates the table, so that by the last move the `match` is gone and the table IS the order.
//!   The hook carries no arm logic — an arm's own debugging travels with the arm.
//! - [`render_value`], the value-render chokepoint at the expression printer's dispatch
//!   ([`ValueSite`]): sdiv-pow2 answers for the root of a division chain; frame-fill will answer for
//!   anything rooted in a stack slot its aggregate swallowed (the slot's name, its PTRSUB, an
//!   element, a piece, the fused store — today six inline consults of `frame_agg` in printc.rs,
//!   rerouted here by the frame_fill commit); order documented at the function.
//! - Arm SETUP (the recognizers filling the witness maps, the frame-fill gate and its declaration
//!   effect) is state construction when the printer is built — not a print-time seam. If a
//!   declaration effect cannot keep identity that way it becomes an explicit `declarations` seam
//!   here, never an inline consult.
//!
//! THE ARM SURFACE — what the arms may touch of the printer, all `pub(crate)` on [`PrintC`] and
//! listed here so the boundary is reviewable in one place (an `ArmCtx` narrowing is the follow-up
//! once the moves are done). At the skeleton: `try_emit_rep_movs`, `try_emit_sparse_switch`,
//! `try_emit_if_nested`, `movsd_run_at`, `sdiv_pow2_render`, and the field `sparse_switch`. Each
//! move commit extends this list with exactly what its arm reads.
//!
//! THE MOVES (one commit each, identity-gated): 0 this skeleton — the seams wired, delegating to
//! the code still in printc.rs; 1 string_ops; 2 struct_copy; 3 sparse_switch; 4 frame_fill (the
//! value-render answers and the declaration setup); 5 sdiv_pow2; 6 nested_conds.
//!
//! R2b — the older `RecoveredChoices`-driven renderings are choices too and still sit in the port:
//! complement compares (`complement_sites`), unsigned compares (`unsigned_cmp_sites`), return
//! splits (`return_split_sites`), the narrow return (`narrow_return`), widened locals
//! (`widen_local_reps`), entry snapshots (`snapshot_sites`), TEST-witnessed loads
//! (`testmem_sites`), store orders (`store_orders`), call argument orders (`call_arg_orders`),
//! arm swaps (`arm_swap_sites`), array subscripts (`array_index_sites`), narrow joins
//! (`join_narrow_sites`), the sum order (`sum_orders`), the interleave orders (`ilv_orders`). One
//! per commit after this series, so the end state reads "printc.rs = the port + the seams".
use super::super::op::OpId;
use super::super::printc::PrintC;
use super::super::structure::Structured;

/// The kinds of site the statement-level hook is called from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteKind {
    /// A structured loop node (`emit_structured_body`): a lifted REP loop may be one call.
    LoopNode,
    /// The head of an if that is not an `else if` (`emit_if`): a compare tree may be a switch.
    IfEntry,
    /// An if without an else, after the port's else analysis (`emit_if`): a short-circuit may be
    /// nested ifs.
    IfWithoutElse,
    /// One op of a block's statement list: a MOVSD run may be one struct assignment.
    BlockOp,
}

/// One call of the statement-level hook.
pub enum Site<'s> {
    LoopNode { s: &'s Structured, idx: usize, indent: usize },
    IfEntry { s: &'s Structured, idx: usize, indent: usize },
    IfWithoutElse { s: &'s Structured, idx: usize, indent: usize },
    BlockOp { block_ops: &'s [OpId], op: OpId, pc: u64 },
}

impl Site<'_> {
    pub fn kind(&self) -> SiteKind {
        match self {
            Site::LoopNode { .. } => SiteKind::LoopNode,
            Site::IfEntry { .. } => SiteKind::IfEntry,
            Site::IfWithoutElse { .. } => SiteKind::IfWithoutElse,
            Site::BlockOp { .. } => SiteKind::BlockOp,
        }
    }
}

/// What an arm answered at a site.
pub enum Answer {
    /// The arm wrote the statement(s) into `out`; the port emits nothing for the site.
    Emitted,
    /// One fused statement replacing `members` (the port writes it in its own statement form).
    Fused { stmt: String, members: Vec<OpId> },
}

/// The arms in the order they are tried, each with the site kinds it declares. First match wins;
/// no two arms declare the same kind (`tests::arms_declare_disjoint_site_kinds`).
pub const ARMS: [(&str, &[SiteKind]); 4] = [
    ("string-ops: a lifted REP MOVS/STOS/CMPS/SCAS as memcpy/memset/memcmp/strlen (docs/rep-string-intrinsic-arm.md)", &[SiteKind::LoopNode]),
    ("sparse-switch: Watcom's compare tree as the switch it came from (docs/sparse-switch-arm.md)", &[SiteKind::IfEntry]),
    ("struct-copy: a plain MOVSD run as the struct assignment (docs/struct-copy-arm.md)", &[SiteKind::BlockOp]),
    ("nested-conds: a short-circuit as nested ifs (cond-form=nested, docs/byte-exact-families.md sb58 / byte-exact-status.md sb65)", &[SiteKind::IfWithoutElse]),
];

/// The statement-level hook. Tries the arms of [`ARMS`] that declare the site's kind, in table
/// order; `None` = no arm answered, the port prints the site itself.
pub fn try_emit(p: &mut PrintC<'_>, site: Site<'_>, out: &mut String) -> Option<Answer> {
    match site {
        Site::LoopNode { s, idx, indent } => p.try_emit_rep_movs(s, idx, indent, out).then_some(Answer::Emitted),
        Site::IfEntry { s, idx, indent } => {
            (p.sparse_switch && p.try_emit_sparse_switch(s, idx, indent, out)).then_some(Answer::Emitted)
        }
        Site::IfWithoutElse { s, idx, indent } => p.try_emit_if_nested(s, idx, indent, out).then_some(Answer::Emitted),
        Site::BlockOp { block_ops, op, pc } => {
            p.movsd_run_at(block_ops, op, pc).map(|(stmt, members)| Answer::Fused { stmt, members })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The at-most-one-arm-per-site-kind rule is a static property of the table: every pair of
    /// arms declares disjoint kinds, so "first match wins" never has two candidates.
    #[test]
    fn arms_declare_disjoint_site_kinds() {
        for (i, (a, ka)) in ARMS.iter().enumerate() {
            for (b, kb) in ARMS.iter().skip(i + 1) {
                for k in *ka {
                    assert!(!kb.contains(k), "arms `{a}` and `{b}` both declare {k:?}");
                }
            }
        }
        for kind in [SiteKind::LoopNode, SiteKind::IfEntry, SiteKind::IfWithoutElse, SiteKind::BlockOp] {
            assert_eq!(ARMS.iter().filter(|(_, ks)| ks.contains(&kind)).count(), 1, "{kind:?} has exactly one arm");
        }
    }
}

/// One call of the value-render chokepoint.
pub enum ValueSite {
    /// The root of an expression the port is about to render (`render_op_inner`): a witnessed
    /// SBB/SAR chain prints as `x / 2^n`.
    Division { op: OpId },
}

/// The value-render chokepoint: the rendering and its precedence, or `None` = the port renders
/// the value itself. Answerers in order: sdiv-pow2 (a division chain root); frame-fill joins in
/// its move commit (a value rooted in a swallowed stack slot).
pub fn render_value(p: &mut PrintC<'_>, site: ValueSite) -> Option<(String, u8)> {
    match site {
        ValueSite::Division { op } => p.sdiv_pow2_render(op),
    }
}
