//! The Watcom emit ARMS (review R2): target-informed emit choices — NOT Ghidra — that the faithful
//! printer (`printc.rs`, a port) reaches through named seams only. Each arm becomes its own file
//! here, named after its `docs/*-arm.md`, moved verbatim from printc.rs one commit at a time under
//! the census-identity contract (a full emit's `recovered/` AND `raw/` byte-identical to the
//! previous tree, the corpus gates green).
//!
//! THE SEAMS — every arm effect passes through one of these, nothing else:
//! - [`try_emit`], the statement-level hook: the port calls it at the [`Site`]s — a structured loop
//!   node, the head of an if, an if without an else, one op of a block's statement list, a RETURN
//!   statement (struct-return, 2026-08-28) — and the
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
//! THE STATE RULE (commits 7, 7b): state only the ARM reads lives in the arm's own `State` (its
//! choice flag, its witness maps, its walk cells), composed into [`State`] — the printer's one
//! `arms` field, which the port never reads. State the PORT reads is not arm state but a PRINTER
//! SERVICE — and a service is a MARK the port applies generically, never a rendering rule: "skip
//! this op", "skip this covered node", "skip this consumed node", "print that node's condition"
//! are marks; "print this value as `strlen(s)`" is the arm's rule and is asked through the value
//! seam (`ValueSite::Var`, 7b), with the maps behind it as arm state. And a site kind is never a
//! predicate: what an arm can decide at setup it marks (commit 8 retired `Site::Node`).
//!
//! PRINTER SERVICES — the FOUR marks: port fields an arm WRITES and the port READS generically
//! (the reverse of a seam; each documented at its field, all on the surface, each with its own
//! semantics and consult points): `suppressed` (ops an arm covered — the statement printer skips
//! them), `covered_nodes` (nodes a collapsed string op covers, marked at setup — consulted at
//! `emit_structured_body` only, commit 8), `sparse_consumed` (nodes the switch printed elsewhere,
//! marked while it prints — consulted at the root loop and the component walk), and
//! `sparse_cond_override` (the condition the switch walk installed for a node — the if emitter
//! prints it). Two node marks, not one: their semantics and their consult points differ, and a
//! single service with the union of points would change what is skipped in both directions.
//! A fifth service, of a new kind (R2b, commit 8): `var_counter`, the port's NAME ALLOCATOR — an
//! arm that invents a temp (entry snapshots) advances it and takes the next `uVarN`, and the
//! port's own naming continues from there; an arm bumping the port's counter is that service,
//! not a leak.
//!
//! THE MOVES (one commit each, identity-gated): 0 the skeleton — the seams wired, delegating to
//! the code then still in printc.rs; 1 string_ops; 2 struct_copy; 3 sparse_switch; 4 frame_fill
//! (the value-render answers and the declarations seam); 5 sdiv_pow2; 6 nested_conds; 7 the ARM
//! STATE — through the moves each arm's state (`rep_movs`, `rep_skip`, the sparse walk cells, …
//! typed by the arm's module) stayed a `PrintC` field so every move was verbatim; commit 7
//! relocated it into [`State`] (per-arm state structs composed in it), the printer's single field
//! `arms`, and made the surface a test; 7b moved the strlen rendering rule out of `render_var`
//! behind `ValueSite::Var`; 8 turned string-ops' print-time `Node` predicate into the setup mark
//! `covered_nodes`. The `ArmCtx` narrowing is R2c. The series' acceptance therefore reads: zero
//! arm LOGIC in printc.rs; the port names the arms only as `arms::State`, the four marks and the
//! seams.
//!
//! R2b — the older `RecoveredChoices`-driven renderings are choices too and still sit in the port:
//! complement compares (`complement_sites`), unsigned compares (`unsigned_cmp_sites`), return
//! splits (`return_split_sites`), the narrow return (`narrow_return`), widened locals
//! (`widen_local_reps`), entry snapshots (`snapshot_sites`), TEST-witnessed loads
//! (`testmem_sites`), store orders (`store_orders`), call argument orders (`call_arg_orders`),
//! arm swaps (`arm_swap_sites`), array subscripts (`array_index_sites`), narrow joins
//! (`join_narrow_sites`), the sum order (`sum_order`), the interleave orders (`ilv_orders`), the
//! tier-2 materializations (`tier2_sites`). One
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
    pub(crate) complement_cmp: complement_cmp::State,
    pub(crate) ext_cast: ext_cast::State,
    pub(crate) sum_order: sum_order::State,
    pub(crate) join_narrow: join_narrow::State,
    pub(crate) array_index: array_index::State,
    pub(crate) return_split: return_split::State,
    pub(crate) snapshot: snapshot::State,
    pub(crate) struct_return: struct_return::State,
    pub(crate) testmem: testmem::State,
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
            complement_cmp: complement_cmp::State::new(choices),
            ext_cast: ext_cast::State::new(choices),
            sum_order: sum_order::State::new(choices),
            join_narrow: join_narrow::State::new(choices),
            array_index: array_index::State::new(choices),
            return_split: return_split::State::new(choices),
            snapshot: snapshot::State::new(choices),
            struct_return: struct_return::State::new(choices),
            testmem: testmem::State::new(choices),
        }
    }
}

pub mod cmp_order;
pub mod cmp_sign;
pub mod complement_cmp;
pub mod ext_cast;
pub mod load_hoist;
pub mod mask_cast;
pub mod ptr_offset;
pub mod return_widen;
pub mod array_index;
pub mod frame_fill;
pub mod nested_conds;
pub mod sdiv_pow2;
pub mod sparse_switch;
pub mod string_ops;
pub mod struct_copy;
pub mod unsigned_cmp;
pub mod snapshot;
pub mod return_split;
pub mod join_narrow;
pub mod sum_order;
pub mod testmem;
pub mod struct_return;

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
    /// The last two components of a structured list (`emit_structured_body`, `FlowKind::List`):
    /// a plain if + a bool-returning basic may print as per-path returns. R2b, commit 7.
    ListTail,
    /// A RETURN op of a block's statement list, after the block-op site declined: a hidden
    /// struct return whose RETURN carries no value prints `return __ret` (struct-return,
    /// 2026-08-28).
    Return,
}

/// One call of the statement-level hook.
#[derive(Clone, Copy)]
pub enum Site<'s> {
    LoopNode { s: &'s Structured, idx: usize, indent: usize },
    IfEntry { s: &'s Structured, idx: usize, indent: usize },
    IfWithoutElse { s: &'s Structured, idx: usize, indent: usize },
    BlockOp { block_ops: &'s [OpId], op: OpId, pc: u64, reordered: &'s std::collections::HashSet<OpId> },
    ListTail { s: &'s Structured, c: usize, tail: usize, indent: usize },
    Return { op: OpId, pad: &'s str },
}

impl Site<'_> {
    pub fn kind(&self) -> SiteKind {
        match self {
            Site::LoopNode { .. } => SiteKind::LoopNode,
            Site::IfEntry { .. } => SiteKind::IfEntry,
            Site::IfWithoutElse { .. } => SiteKind::IfWithoutElse,
            Site::BlockOp { .. } => SiteKind::BlockOp,
            Site::ListTail { .. } => SiteKind::ListTail,
            Site::Return { .. } => SiteKind::Return,
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
pub const ARMS: [Arm; 6] = [
    string_ops::ARM,
    sparse_switch::ARM,
    struct_copy::ARM,
    nested_conds::ARM,
    return_split::ARM,
    struct_return::ARM,
];

/// The statement-level hook: the first arm of [`ARMS`] that declares the site's kind answers;
/// `None` = no arm answered, the port prints the site itself. The table IS the dispatch.
pub fn try_emit(p: &mut PrintC<'_>, site: Site<'_>, out: &mut String) -> Option<Answer> {
    let kind = site.kind();
    // every arm declaring the kind is asked in table order; the first answer wins (an arm writes
    // to `out` only when it answers)
    ARMS.iter().filter(|arm| arm.kinds.contains(&kind)).find_map(|arm| (arm.try_emit)(p, site, out))
}

/// THE ARM SURFACE (see the module doc): every printer member an arm file may touch, by kind.
#[cfg_attr(not(test), allow(dead_code))] // the documented list; read by the surface test
pub const SURFACE_FIELDS: &[&str] = &[
    "arms", "f", "recovered", "report", "h", "force_explicit", "suppressed", "names", "decls",
    "stack_declared", "stack_space", "stack_syms", "high_stack_off", "high_ram_off", "high_of", "high_members",
    "nonprinting", "labels", "comma_separate", "sparse_consumed", "sparse_cond_override", "covered_nodes",
    "var_counter", "array_elem", "force_implied",
];
#[cfg_attr(not(test), allow(dead_code))] // the documented list; read by the surface test
pub const SURFACE_METHODS: &[&str] = &[
    "name_of", "render_var", "lvalue_of", "is_explicit", "strlen_arg", "emit_structured", "render_op",
    "lab_name", "first_pc", "next_flow_after", "plain_if_condition_vn", "spacebase_sym_at", "frame_off",
    "type_of", "stack_slot_name", "declare_stack", "collect_conj_clauses", "render_cond_expr", "emit_basic",
    "cast_operand",
    "is_partial_symbol",
    "emit_if",
    "plain_if_branch_pc",
    "operand",
    "render_mem",
    "get_input_cast",
    "callee_name",
];
/// The free helpers of `printc` an arm file may import.
#[cfg_attr(not(test), allow(dead_code))] // the documented list; read by the surface test
pub const SURFACE_HELPERS: &[&str] = &[
    "render_const",
    "PrintC", "collect_basics", "entry_basic", "exit_basic", "operand_oriented", "render_const_typed", "strip_copies",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The arm files, as text, for the surface scan — every `pub mod` of this module must be here
    /// (`arms_touch_only_the_documented_surface` checks that against this file's own source, so a
    /// new arm file cannot slip past the scan).
    const ARM_SOURCES: [(&str, &str); 22] = [
        ("ptr_offset.rs", include_str!("ptr_offset.rs")),
        ("load_hoist.rs", include_str!("load_hoist.rs")),
        ("cmp_order.rs", include_str!("cmp_order.rs")),
        ("cmp_sign.rs", include_str!("cmp_sign.rs")),
        ("return_widen.rs", include_str!("return_widen.rs")),
        ("ext_cast.rs", include_str!("ext_cast.rs")),
        ("mask_cast.rs", include_str!("mask_cast.rs")),
        ("string_ops.rs", include_str!("string_ops.rs")),
        ("struct_copy.rs", include_str!("struct_copy.rs")),
        ("sparse_switch.rs", include_str!("sparse_switch.rs")),
        ("frame_fill.rs", include_str!("frame_fill.rs")),
        ("sdiv_pow2.rs", include_str!("sdiv_pow2.rs")),
        ("nested_conds.rs", include_str!("nested_conds.rs")),
        ("unsigned_cmp.rs", include_str!("unsigned_cmp.rs")),
        ("snapshot.rs", include_str!("snapshot.rs")),
        ("return_split.rs", include_str!("return_split.rs")),
        ("array_index.rs", include_str!("array_index.rs")),
        ("join_narrow.rs", include_str!("join_narrow.rs")),
        ("sum_order.rs", include_str!("sum_order.rs")),
        ("testmem.rs", include_str!("testmem.rs")),
        ("complement_cmp.rs", include_str!("complement_cmp.rs")),
        ("struct_return.rs", include_str!("struct_return.rs")),
    ];

    /// Every `p.`/`pr.`/`me.` member access and every `use crate::decompile::printc::{..}` item in
    /// the arm files is on the documented surface — and every listed member is used by some arm.
    #[test]
    fn arms_touch_only_the_documented_surface() {
        let access = regex::Regex::new(r"\b(?:p|pr|me)\.([a-z_][a-z_0-9]*)\s*(\()?").unwrap();
        let import = regex::Regex::new(r"use crate::decompile::printc::(?:\{([^}]*)\}|([A-Za-z_][A-Za-z_0-9]*));").unwrap();
        let mut violations = Vec::new();
        // every arm module is scanned: the `pub mod x;` lines of this file against ARM_SOURCES
        let this = include_str!("mod.rs");
        for line in this.lines() {
            if let Some(name) = line.strip_prefix("pub mod ").and_then(|r| r.strip_suffix(';')) {
                let file = format!("{name}.rs");
                if !ARM_SOURCES.iter().any(|(n, _)| *n == file) {
                    violations.push(format!("arm module `{name}` is not in ARM_SOURCES — the surface scan does not see it"));
                }
            }
        }
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

    /// The declarations family's answerers are exactly the documented ones, in the documented
    /// order: each seam's body names its answerer modules (`<arm>::<seam>(`) as `DECLARATION_SEAMS`
    /// lists them, and nothing else.
    #[test]
    fn declaration_seams_have_the_documented_answerers() {
        let this = include_str!("mod.rs");
        for (seam, answerers) in DECLARATION_SEAMS {
            let head = format!("fn {seam}");
            let start = this.find(&head).unwrap_or_else(|| panic!("seam `{seam}` not found"));
            let body = &this[start..];
            let end = body.find("\n}\n").expect("seam body end");
            let body = &body[..end];
            let re = regex::Regex::new(&format!(r"([a-z_]+)::{seam}\(")).unwrap();
            let found: Vec<&str> = re.captures_iter(body).map(|c| c.get(1).unwrap().as_str()).collect();
            assert_eq!(&found, answerers, "seam `{seam}` answerers (in order)");
        }
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
        for kind in [SiteKind::LoopNode, SiteKind::IfEntry, SiteKind::IfWithoutElse, SiteKind::BlockOp, SiteKind::Return] {
            assert_eq!(ARMS.iter().filter(|a| a.kinds.contains(&kind)).count(), 1, "{kind:?} has exactly one arm");
        }
    }
}

/// One call of the value-render chokepoint: the situation the port is about to render.
pub enum ValueSite<'v> {
    /// The root of an expression (`render_op_inner`): a `len + 1` alias folds to `strlen`'s
    /// value, a witnessed SBB/SAR chain prints as `x / 2^n`.
    OpRoot { op: OpId },
    /// A value the port is about to render (`render_var`, after its snapshot names): a strlen
    /// result or a `len + 1` alias prints as the strlen form. Replaces the two inline blocks the
    /// port kept under a service label until commit 7b (printc.rs:1246-1253 at 3fe8bae).
    Var { v: VarnodeId },
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
    /// `eq_bin`: an `==`/`!=` (`sym`, at the port's precedence `prec`) the port is about to
    /// render — an all-ones narrow equality whose original immediate is the zero-extended spelling
    /// prints as `(uintN)x sym 0xffN`. Replaces the inline block at printc.rs:1941-1966 (33d6e37);
    /// R2b, commit 1.
    Equality { op: OpId, sym: &'static str, prec: u8 },
    /// `render_negated`'s equality flip (`!(a == b)` printed `a != b`): the same compare
    /// reached through a negated branch. Only `cmp-sign` answers here — an operand's sign
    /// must not depend on the branch's orientation; `unsigned-cmp` does not (measured: on the
    /// negated sites it re-spelled FUN_0002dfb0's `param_4 != -1` as `(uint2)param_4 !=
    /// 0xffff`, −0.258, round e16).
    NegatedEquality { op: OpId, sym: &'static str, prec: u8 },
    /// `cmp_bin`: a `<`/`<=` (`strict`, at the port's precedence `prec`) the port is about to
    /// render — a compare the original spelled through the complemented condition prints
    /// complemented. Replaces the inline consult at the head of cmp_bin (33d6e37); R2b, commit 2.
    Compare { op: OpId, strict: bool, prec: u8 },
    /// `render_op_inner`'s INT_ZEXT (`signed` false) / INT_SEXT: the `ext-cast=promotion`
    /// rendering of an extension at or below int width (emit/arms/ext_cast.rs).
    Extension { op: OpId, signed: bool },
    /// One argument (`slot`, an input index) of the CALL/CALLIND `op` the port is about to
    /// render: the `mask-cast` arm's narrow cast where the original masks it (emit/arms/mask_cast.rs).
    CallArg { op: OpId, slot: usize },
    /// The value a `return` statement returns (after the narrowed return's low-part selection):
    /// a widened return's sign (`return-widen`).
    ReturnValue { v: VarnodeId },
    /// `render_op_inner`'s `Load` arm: `out` the loaded value, `addr` its address — a witnessed
    /// masked narrow load prints its deref at int width. Replaces the inline width consult
    /// (33d6e37); R2b, commit 3.
    Load { out: VarnodeId, addr: VarnodeId },
    /// `render_op_inner`'s `IntAdd` arm: `op` the root of a left-nested INT_ADD chain — its terms
    /// print in the original's schedule order under `sum-order=original`. Replaces the inline
    /// consult (33d6e37); R2b, commit 4.
    Sum { op: OpId },
    /// `render_mem`: `addr` the address it is about to dereference — an inlined scaled-index temp
    /// renders as the subscript. Replaces the inline consult at the head of render_mem (8bd43ce);
    /// R2b, commit 6.
    Deref { addr: VarnodeId, vty: &'v Datatype },
    /// `render_var`, before anything else: `v` the value about to render — a snapshotted entry
    /// value renders as its temp's name. Replaces the inline consult at the head of render_var
    /// (8bd43ce); R2b, commit 8.
    VarEntry { v: VarnodeId },
}

/// The value-render chokepoint — ONE hook with situations, the same shape as [`try_emit`]'s
/// sites: the rendering and its precedence, or `None` = the port renders the value itself. The
/// situations are disjoint, so order matters only INSIDE `OpRoot`: string-ops (the strlen fold)
/// then sdiv-pow2 (a division chain root), as `render_op_inner` had them; `Var` has one answerer,
/// string-ops; every other situation has exactly one answerer — the match below is the list.
/// The precedence is read at the expression situations; the slot situations' callers take the
/// text.
pub fn render_value(p: &mut PrintC<'_>, site: ValueSite<'_>) -> Option<(String, u8)> {
    // THE ORDERED ANSWERERS (explicit, documented here; a site with two answerers lists them in
    // the order they are asked, first answer wins):
    //   OpRoot:      string-ops, sdiv-pow2, struct-return (a witnessed CALL)
    //   Compare:     complement-cmp (the immediate flavour), then cmp-order (the operand swap), then cmp-sign
    //   Equality:    unsigned-cmp, then cmp-sign (a narrow signed operand the original zero-extends)
    //   NegatedEquality: cmp-sign only
    //   ReturnValue: return-widen (the sign of a widened narrow return)
    //   Extension:   ext-cast (the promotion rendering of INT_ZEXT / INT_SEXT)
    //   CallArg:     mask-cast (a call argument the original masks before the call)
    //   Var:         struct-return (the hidden pointer -> `__ret`), string-ops
    //   Deref:       struct-return (a field write through the hidden pointer), array-index
    //   SlotName / SlotOffset / SlotAddress / SlotPiece / FusedStore:
    //                struct-return (a typed struct local's slot), frame-fill
    // struct-return's slot answers decline by frame-fill's SETUP state (`declined_by_frame_fill`,
    // decided at recognize), never by this order.
    match site {
        ValueSite::OpRoot { op } => string_ops::strlen_fold(p, op)
            .or_else(|| sdiv_pow2::render(p, op))
            .or_else(|| struct_return::render_value(p, &ValueSite::OpRoot { op })),
        ValueSite::Var { v } => struct_return::render_value(p, &ValueSite::Var { v }).or_else(|| string_ops::render_var_value(p, v)),
        ValueSite::Equality { op, sym, prec } => unsigned_cmp::render(p, op, sym, prec).or_else(|| cmp_sign::render(p, op, sym, prec)),
        ValueSite::NegatedEquality { op, sym, prec } => cmp_sign::render(p, op, sym, prec),
        ValueSite::Compare { op, strict, prec } => complement_cmp::render(p, op, strict, prec)
            .or_else(|| cmp_order::render(p, op, strict, prec))
            .or_else(|| cmp_sign::render(p, op, if strict { "<" } else { "<=" }, prec)),
        ValueSite::ReturnValue { v } => return_widen::render(p, v),
        ValueSite::Extension { op, signed } => ext_cast::render(p, op, signed),
        ValueSite::CallArg { op, slot } => mask_cast::render(p, op, slot),
        ValueSite::Load { out, addr } => testmem::render(p, out, addr),
        ValueSite::Sum { op } => sum_order::render(p, op),
        ValueSite::Deref { addr, vty } => struct_return::render_value(p, &ValueSite::Deref { addr, vty })
            .or_else(|| array_index::render(p, addr))
            .or_else(|| ptr_offset::render(p, addr, vty)),
        ValueSite::VarEntry { v } => snapshot::render(p, v),
        other => struct_return::render_value(p, &other).or_else(|| frame_fill::render_value(p, &other)),
    }
}

// THE DECLARATIONS SEAMS — one family, four situations, each with its answerer(s) listed here
// (`DECLARATION_SEAMS`, held by a test):
//   * a SLOT's declaration (`declare_slot`: the port is about to declare the stack slot at
//     `start`; struct-return answers `true` when a typed struct local declares it, then frame-fill
//     when its aggregate does — the order is explicit below, and struct-return's answer is decided
//     by frame-fill's SETUP state, never by the order);
//   * a LOCAL's declared type (`local_decl_type`: the port is about to declare a genuine local;
//     join-narrow answers the narrowed type);
//   * the declarations the port does NOT know about (`init_decls`: temps an arm invented, with
//     their initializers, printed by the port after its own locals; entry snapshots answer);
//   * the function's own SIGNATURE (`signature`: the port is about to assemble the return type
//     and the parameter list; struct-return answers a preamble of struct declarations, the struct
//     return type and the hidden parameter to drop — the design note of 2026-08-28, seq 527/528).
// They are separate functions because their answers differ in type (a bool "declared it", an
// `Option<Datatype>`, a list of `(name, type, initializer)`, a `Signature`), not because each arm
// gets its own seam. RULE: a further declaration-level seam needs a design note in the channel
// first — the family must not grow one function per arm (review R2b, commits 5 and 8, fable-b's
// notes).

/// The family, as a table: each seam with its answerers in the order they are asked. The test
/// `declaration_seams_have_the_documented_answerers` holds this against the functions' bodies.
#[cfg_attr(not(test), allow(dead_code))]
pub const DECLARATION_SEAMS: &[(&str, &[&str])] = &[
    ("declare_slot", &["struct_return", "frame_fill"]),
    ("local_decl_type", &["join_narrow"]),
    ("init_decls", &["snapshot"]),
    ("signature", &["struct_return"]),
];

/// What the signature seam answers: the lines printed BEFORE the definition (struct
/// declarations), the return type when it changes, the parameter varnode to drop when one does.
pub(crate) struct Signature {
    pub(crate) preamble: Vec<String>,
    pub(crate) ret_ty: Option<String>,
    pub(crate) drop: Option<VarnodeId>,
}

/// The function's own signature, about to be assembled by the port (consulted exactly once, at
/// the assembly of `ret_ty`/`plist` in print_c_inner): one answerer, struct-return; `None` = the
/// port's own signature. R-struct-return, 2026-08-28.
pub(crate) fn signature(p: &mut PrintC<'_>) -> Option<Signature> {
    struct_return::signature(p)
}
/// The declared type of a genuine local `name_of` is about to declare (`v` the varnode, `ty` its
/// value type): one answerer, join-narrow; `None` = the port's own declaration width. Replaces
/// the inline consult in name_of (8bd43ce); R2b, commit 5.
pub(crate) fn local_decl_type(p: &mut PrintC<'_>, v: VarnodeId, ty: &Datatype) -> Option<Datatype> {
    join_narrow::local_decl_type(p, v, ty)
}

/// The declarations WITH initializers the port prints after the plain locals — the temps an arm
/// invented, which the port has no declaration of: one answerer, entry snapshots. Asked in the
/// DECLARATION BLOCK ONLY (print_c_inner reads it twice there, for the printing loop and for the
/// blank-line condition — one place, one seam). R2b, commit 8.
pub(crate) fn init_decls<'p>(p: &'p PrintC<'_>) -> &'p [(String, Datatype, String)] {
    snapshot::init_decls(p)
}

/// THE DECLARATIONS SEAM — the one arm effect that is neither a statement nor a value, and the
/// ONLY declaration-level seam: a slot inside the frame aggregate declares the ONE aggregate
/// instead of itself. WHY it is not setup state: the port declares a frame offset on its FIRST
/// USE, while it prints, and any offset of the frame may be that first use — the aggregate's
/// declaration effect is therefore decided at that moment, at the port's `declare_stack`, not
/// from a list built beforehand. So it is an explicit seam (fable-b, seq 217), never an inline
/// consult; `true` = an arm declared it, the port declares nothing.
pub fn declare_slot(p: &mut PrintC<'_>, start: i64) -> bool {
    struct_return::declare_slot(p, start) || frame_fill::declare_slot(p, start)
}
