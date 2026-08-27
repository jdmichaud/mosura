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
//!   ([`ValueSite`]): string-ops answers the strlen fold and sdiv-pow2 the root of a division
//!   chain, in that order (render_op_inner's); frame-fill will answer for
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
//! once the moves are done). Each move commit extends this list with exactly what its arm reads:
//! - delegates of the arms not yet moved: `try_emit_sparse_switch`, `try_emit_if_nested`,
//!   `sdiv_pow2_render`, and the field `sparse_switch`;
//! - string_ops (commit 1): the fields `f`, `recovered`, `report`, `h`, `force_explicit`, the arm's
//!   own state `rep_movs`, `rep_skip`, `strlen_alias`, `strlen_exprs` (commit 7 moves it), and
//!   `suppressed` — a PRINTER SERVICE FOR THE ARMS, not Ghidra's: the ops an arm has covered,
//!   which the port's own statement printer then skips; the methods `name_of`, `render_var`,
//!   `lvalue_of`, `is_explicit`, `strlen_arg`; the free helpers `strip_copies`, `collect_basics`,
//!   `render_const_typed`;
//! - struct_copy (commit 2): the choice flag `struct_copy`, the fields `high_of`, `high_members`,
//!   `nonprinting` (and `f`, `recovered`, `suppressed` already open); no methods.
//!
//! THE MOVES (one commit each, identity-gated): 0 the skeleton — the seams wired, delegating to
//! the code still in printc.rs; 1 string_ops; 2 struct_copy; 3 sparse_switch; 4 frame_fill (the
//! value-render answers and the declaration setup); 5 sdiv_pow2; 6 nested_conds; 7 the ARM STATE
//! — through the moves each arm's witness state (`rep_movs`, `rep_skip`, `strlen_alias`, … typed by
//! the arm's module) stays a `PrintC` field so every move is verbatim; commit 7 relocates it into
//! one `arms::State` (per-arm state structs composed in it) held by `PrintC` as a single field,
//! together with the `ArmCtx` narrowing of the surface. The series' acceptance therefore reads:
//! zero arm LOGIC in printc.rs after the moves, zero arm identifiers after commit 7.
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

pub mod string_ops;
pub mod struct_copy;

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
    /// ANY structured node, before the port prints it: a node a collapsed string op covers emits
    /// nothing.
    Node,
}

/// One call of the statement-level hook.
pub enum Site<'s> {
    LoopNode { s: &'s Structured, idx: usize, indent: usize },
    IfEntry { s: &'s Structured, idx: usize, indent: usize },
    IfWithoutElse { s: &'s Structured, idx: usize, indent: usize },
    BlockOp { block_ops: &'s [OpId], op: OpId, pc: u64, reordered: &'s std::collections::HashSet<OpId> },
    Node { s: &'s Structured, idx: usize },
}

impl Site<'_> {
    pub fn kind(&self) -> SiteKind {
        match self {
            Site::LoopNode { .. } => SiteKind::LoopNode,
            Site::IfEntry { .. } => SiteKind::IfEntry,
            Site::IfWithoutElse { .. } => SiteKind::IfWithoutElse,
            Site::BlockOp { .. } => SiteKind::BlockOp,
            Site::Node { .. } => SiteKind::Node,
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

/// One arm as the table holds it: its name (with its doc), the site kinds it declares, and its
/// answer at a site of one of those kinds.
pub struct Arm {
    /// Read by the table test and by the debug facility to come (R6); not on the print path.
    #[allow(dead_code)]
    pub name: &'static str,
    pub kinds: &'static [SiteKind],
    pub try_emit: fn(&mut PrintC<'_>, Site<'_>, &mut String) -> Option<Answer>,
}

/// The arms in the order they are tried, each with the site kinds it declares. First match wins;
/// no two arms declare the same kind (`tests::arms_declare_disjoint_site_kinds`). An arm not yet
/// moved out of printc.rs sits here as a thin delegate.
pub const ARMS: [Arm; 4] = [
    string_ops::ARM,
    Arm {
        name: "sparse-switch: Watcom's compare tree as the switch it came from (docs/sparse-switch-arm.md)",
        kinds: &[SiteKind::IfEntry],
        try_emit: |p, site, out| match site {
            Site::IfEntry { s, idx, indent } => (p.sparse_switch && p.try_emit_sparse_switch(s, idx, indent, out)).then_some(Answer::Emitted),
            _ => None,
        },
    },
    struct_copy::ARM,
    Arm {
        name: "nested-conds: a short-circuit as nested ifs (cond-form=nested, docs/byte-exact-families.md sb58 / byte-exact-status.md sb65)",
        kinds: &[SiteKind::IfWithoutElse],
        try_emit: |p, site, out| match site {
            Site::IfWithoutElse { s, idx, indent } => p.try_emit_if_nested(s, idx, indent, out).then_some(Answer::Emitted),
            _ => None,
        },
    },
];

/// The statement-level hook: the first arm of [`ARMS`] that declares the site's kind answers;
/// `None` = no arm answered, the port prints the site itself. The table IS the dispatch.
pub fn try_emit(p: &mut PrintC<'_>, site: Site<'_>, out: &mut String) -> Option<Answer> {
    let kind = site.kind();
    let arm = ARMS.iter().find(|arm| arm.kinds.contains(&kind))?;
    (arm.try_emit)(p, site, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The at-most-one-arm-per-site-kind rule is a static property of the table: every pair of
    /// arms declares disjoint kinds, so "first match wins" never has two candidates.
    #[test]
    fn arms_declare_disjoint_site_kinds() {
        for (i, a) in ARMS.iter().enumerate() {
            for b in ARMS.iter().skip(i + 1) {
                for k in a.kinds {
                    assert!(!b.kinds.contains(k), "arms `{}` and `{}` both declare {k:?}", a.name, b.name);
                }
            }
        }
        for kind in [SiteKind::LoopNode, SiteKind::IfEntry, SiteKind::IfWithoutElse, SiteKind::BlockOp, SiteKind::Node] {
            assert_eq!(ARMS.iter().filter(|a| a.kinds.contains(&kind)).count(), 1, "{kind:?} has exactly one arm");
        }
    }
}

/// One call of the value-render chokepoint.
pub enum ValueSite {
    /// The root of an expression the port is about to render (`render_op_inner`): a `len + 1`
    /// alias folds to `strlen`'s value, a witnessed SBB/SAR chain prints as `x / 2^n`.
    OpRoot { op: OpId },
}

/// The value-render chokepoint: the rendering and its precedence, or `None` = the port renders
/// the value itself. Answerers in order: string-ops (the strlen fold), sdiv-pow2 (a division
/// chain root); frame-fill joins in its move commit (a value rooted in a swallowed stack slot).
pub fn render_value(p: &mut PrintC<'_>, site: ValueSite) -> Option<(String, u8)> {
    match site {
        ValueSite::OpRoot { op } => string_ops::strlen_fold(p, op).or_else(|| p.sdiv_pow2_render(op)),
    }
}
