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
//! THE ARM SURFACE — what the arms may touch of the printer — is exactly [`SURFACE_FIELDS`],
//! [`SURFACE_METHODS`] and [`SURFACE_HELPERS`] below, the single source of truth: no list in prose,
//! so nothing can drift from what is checked. `tests::arms_touch_only_the_documented_surface`
//! enforces them — it scans every arm file for `p.`/`pr.`/`me.` member accesses (a call by its
//! paren, a field otherwise) and every `use crate::decompile::printc::{..}` item, fails on any touch
//! or import outside the consts, and fails the other way on a listed member no arm uses. All of them
//! are `pub(crate)` on `PrintC`. The `ArmCtx` trait (accessor methods, so the compiler itself
//! refuses a touch outside the list) is R2c, once R2b has stopped touching the port.
//!
//! THE STATE RULE (commit 7): state only the ARM reads lives in the arm's own `State` (its choice
//! flag, its witness maps, its walk cells), composed into [`State`] — the printer's one `arms`
//! field, which the port never reads. State the PORT reads is not arm state but a PRINTER SERVICE.
//!
//! PRINTER SERVICES — the FIVE port fields an arm WRITES and the port READS (the reverse of a
//! seam; each documented at its field, all on the surface): `suppressed` (ops an arm covered, the
//! statement printer skips them), `sparse_consumed` (nodes the switch consumed, the root loop and
//! component walk skip them), `sparse_cond_override` (the condition the switch walk installed for
//! a node, the if emitter prints it), `strlen_alias` and `strlen_exprs` (V3 strlen's `len + 1`
//! aliases and folded expressions, the value renderer prints them as the strlen form). Beside
//! them, string-ops' `Site::Node` derives a node's coverage at print time (a predicate, not a
//! mark); commit 8 asks whether that becomes a mark at setup too, leaving one node mechanism.
//!
//! THE MOVES (one commit each, identity-gated): 0 the skeleton — the seams wired, delegating to
//! the code then still in printc.rs; 1 string_ops; 2 struct_copy; 3 sparse_switch; 4 frame_fill
//! (the value-render answers and the declarations seam); 5 sdiv_pow2; 6 nested_conds; 7 the ARM
//! STATE — through the moves each arm's state (`rep_movs`, `rep_skip`, the sparse walk cells, …
//! typed by the arm's module) stayed a `PrintC` field so every move was verbatim; commit 7
//! relocated it into [`State`] (per-arm state structs composed in it), the printer's single field
//! `arms`, and made the surface a test. The `ArmCtx` narrowing is R2c; whether string-ops fills the
//! node service at setup (retiring `Site::Node`) is commit 8. The series' acceptance therefore
//! reads: zero arm LOGIC in printc.rs after the moves; after commit 7 the port names the arms only
//! as `arms::State`, the five services and the seams.
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
use super::super::types::Datatype;
use super::super::varmap::StackSymbol;
use super::super::varnode::VarnodeId;
use super::EmitChoices;

/// The arms' state, one field on the printer (review R2, commit 7): each arm's configuration
/// (its choice flag) and working state live in its own `State`, built by that arm's
/// `State::new(choices)`; the port never reads an arm's flag — every consumer is inside the arm.
#[derive(Debug)]
pub(crate) struct State {
    pub(crate) string_ops: string_ops::State,
    pub(crate) struct_copy: struct_copy::State,
    pub(crate) sparse_switch: sparse_switch::State,
    pub(crate) frame_fill: frame_fill::State,
    pub(crate) sdiv_pow2: sdiv_pow2::State,
    pub(crate) nested_conds: nested_conds::State,
}

impl State {
    pub(crate) fn new(choices: &EmitChoices) -> Self {
        State {
            string_ops: string_ops::State::new(choices),
            struct_copy: struct_copy::State::new(choices),
            sparse_switch: sparse_switch::State::new(choices),
            frame_fill: frame_fill::State::new(choices),
            sdiv_pow2: sdiv_pow2::State::new(choices),
            nested_conds: nested_conds::State::new(choices),
        }
    }
}

pub mod frame_fill;
pub mod nested_conds;
pub mod sdiv_pow2;
pub mod sparse_switch;
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
    sparse_switch::ARM,
    struct_copy::ARM,
    nested_conds::ARM,
];

/// The statement-level hook: the first arm of [`ARMS`] that declares the site's kind answers;
/// `None` = no arm answered, the port prints the site itself. The table IS the dispatch.
pub fn try_emit(p: &mut PrintC<'_>, site: Site<'_>, out: &mut String) -> Option<Answer> {
    let kind = site.kind();
    let arm = ARMS.iter().find(|arm| arm.kinds.contains(&kind))?;
    (arm.try_emit)(p, site, out)
}

/// THE ARM SURFACE (see the module doc): every printer member an arm file may touch, by kind.
pub const SURFACE_FIELDS: &[&str] = &[
    "arms", "f", "recovered", "report", "h", "force_explicit", "suppressed", "names", "decls",
    "stack_declared", "stack_space", "stack_syms", "high_stack_off", "high_of", "high_members",
    "nonprinting", "labels", "comma_separate", "sparse_consumed", "sparse_cond_override",
    "strlen_alias", "strlen_exprs",
];
pub const SURFACE_METHODS: &[&str] = &[
    "name_of", "render_var", "lvalue_of", "is_explicit", "strlen_arg", "emit_structured", "render_op",
    "lab_name", "first_pc", "next_flow_after", "plain_if_condition_vn", "spacebase_sym_at", "frame_off",
    "type_of", "stack_slot_name", "declare_stack", "collect_conj_clauses", "render_cond_expr", "emit_basic",
];
/// The free helpers of `printc` an arm file may import.
pub const SURFACE_HELPERS: &[&str] = &[
    "PrintC", "collect_basics", "entry_basic", "exit_basic", "operand_oriented", "render_const_typed", "strip_copies",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The arm files, as text, for the surface scan.
    const ARM_SOURCES: [(&str, &str); 6] = [
        ("string_ops.rs", include_str!("string_ops.rs")),
        ("struct_copy.rs", include_str!("struct_copy.rs")),
        ("sparse_switch.rs", include_str!("sparse_switch.rs")),
        ("frame_fill.rs", include_str!("frame_fill.rs")),
        ("sdiv_pow2.rs", include_str!("sdiv_pow2.rs")),
        ("nested_conds.rs", include_str!("nested_conds.rs")),
    ];

    /// Every `p.`/`pr.`/`me.` member access and every `use crate::decompile::printc::{..}` item in
    /// the arm files is on the documented surface — and every listed member is used by some arm.
    #[test]
    fn arms_touch_only_the_documented_surface() {
        let access = regex::Regex::new(r"\b(?:p|pr|me)\.([a-z_][a-z_0-9]*)\s*(\()?").unwrap();
        let import = regex::Regex::new(r"use crate::decompile::printc::(?:\{([^}]*)\}|([A-Za-z_][A-Za-z_0-9]*));").unwrap();
        let mut violations = Vec::new();
        let mut used_fields = std::collections::BTreeSet::new();
        let mut used_methods = std::collections::BTreeSet::new();
        let mut used_helpers = std::collections::BTreeSet::new();
        for (name, src) in ARM_SOURCES {
            for (lineno, line) in src.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                for cap in access.captures_iter(code) {
                    let ident = cap.get(1).unwrap().as_str();
                    let call = cap.get(2).is_some();
                    let ok = if call { SURFACE_METHODS.contains(&ident) } else { SURFACE_FIELDS.contains(&ident) };
                    if call { used_methods.insert(ident.to_string()); } else { used_fields.insert(ident.to_string()); }
                    if !ok {
                        violations.push(format!("{name}:{}: `{}` is not on the documented surface", lineno + 1, cap.get(0).unwrap().as_str().trim()));
                    }
                }
            }
            for cap in import.captures_iter(src) {
                let items = cap.get(1).map(|m| m.as_str()).or_else(|| cap.get(2).map(|m| m.as_str())).unwrap_or("");
                for item in items.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    used_helpers.insert(item.to_string());
                    if !SURFACE_HELPERS.contains(&item) {
                        violations.push(format!("{name}: imports `{item}` from printc, not on the documented surface"));
                    }
                }
            }
        }
        for f in SURFACE_FIELDS { if !used_fields.contains(*f) { violations.push(format!("field `{f}` is listed but no arm touches it")); } }
        for m in SURFACE_METHODS { if !used_methods.contains(*m) { violations.push(format!("method `{m}` is listed but no arm calls it")); } }
        for h in SURFACE_HELPERS { if !used_helpers.contains(*h) { violations.push(format!("helper `{h}` is listed but no arm imports it")); } }
        assert!(violations.is_empty(), "arm surface violations:\n{}", violations.join("\n"));
    }

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

/// One call of the value-render chokepoint: the situation the port is about to render.
pub enum ValueSite<'v> {
    /// The root of an expression (`render_op_inner`): a `len + 1` alias folds to `strlen`'s
    /// value, a witnessed SBB/SAR chain prints as `x / 2^n`.
    OpRoot { op: OpId },
    /// `partial_symbol`: the piece `v`, `off` bytes into `base` — a piece of a slot the frame
    /// aggregate covers is its field, never `<field expr>._off_size_` (0x66100, COMPILE_FAIL
    /// E1032). Replaces the inline consult the frame-fill landing called seam 6 (printc.rs:861
    /// at 6b6533b).
    SlotPiece { base: VarnodeId, off: u64, v: VarnodeId },
    /// `name_of`: the stack slot `foff` inside the recovered symbol `sym` — an element or a
    /// split-pair piece of a swallowed symbol is the field at its slot (0x4e06e's
    /// `aiStack_2c[0]`, COMPILE_FAIL E1011 in probe w4bp). Replaces the inline consult of seams 4/5
    /// (printc.rs:998 at 6b6533b).
    SlotName { id: u32, foff: i64, sym: &'v StackSymbol, ty: &'v Datatype },
    /// `stack_slot_name`: a slot by frame offset is its field. Replaces the inline consult at the
    /// head of the slot namer (printc.rs:1667 at 6b6533b).
    SlotOffset { off: i64, ty: &'v Datatype },
    /// `render_spacebase_ptrsub`: an address inside the frame is `(T *)(base + delta)` (`base`
    /// itself for the aggregate's own bottom), a value (`deref`) `*(T *)(base + delta)`. Replaces
    /// the inline consult at printc.rs:1870 (6b6533b).
    SlotAddress { off: i64, deref: bool },
    /// `render_assign`: the coalesced whole-symbol store (`struct-locals=coalesce`) of `sym` from
    /// `src` writes the field at its slot. Replaces the inline consult at printc.rs:2707 (6b6533b).
    /// The sixth consult, the declaration (printc.rs:1939), is the [`declare_slot`] seam.
    FusedStore { sym: &'v StackSymbol, src: VarnodeId },
}

/// The value-render chokepoint — ONE hook with situations, the same shape as [`try_emit`]'s
/// sites: the rendering and its precedence, or `None` = the port renders the value itself. The
/// situations are disjoint, so order matters only INSIDE `OpRoot`: string-ops (the strlen fold)
/// then sdiv-pow2 (a division chain root), as `render_op_inner` had them; every slot situation
/// has exactly one answerer, frame-fill. The precedence is read for `OpRoot` only; the slot
/// situations' callers take the text.
pub fn render_value(p: &mut PrintC<'_>, site: ValueSite<'_>) -> Option<(String, u8)> {
    match site {
        ValueSite::OpRoot { op } => string_ops::strlen_fold(p, op).or_else(|| sdiv_pow2::render(p, op)),
        other => frame_fill::render_value(p, &other),
    }
}

/// THE DECLARATIONS SEAM — the one arm effect that is neither a statement nor a value, and the
/// ONLY declaration-level seam: a slot inside the frame aggregate declares the ONE aggregate
/// instead of itself. WHY it is not setup state: the port declares a frame offset on its FIRST
/// USE, while it prints, and any offset of the frame may be that first use — the aggregate's
/// declaration effect is therefore decided at that moment, at the port's `declare_stack`, not
/// from a list built beforehand. So it is an explicit seam (fable-b, seq 217), never an inline
/// consult; `true` = an arm declared it, the port declares nothing.
pub fn declare_slot(p: &mut PrintC<'_>, start: i64) -> bool {
    frame_fill::declare_slot(p, start)
}
