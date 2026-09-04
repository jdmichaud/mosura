//! `cond-form=nested` — a plain `if` whose printed `&&` spine carries statement-bearing basic
//! clauses prints as nested ifs split before each such clause, so the clause's statements run
//! exactly when every earlier clause held (the axis doc in emit.rs carries the measured probe and
//! the faithfulness trap; landed faithfully at sb58, docs/byte-exact-families.md; recovered per site
//! at sb65, docs/byte-exact-status.md — `recovered.nested_conds.sites` from
//! `buildconfig::nested_conds_from_evidence`). A target-informed emit choice, NOT Ghidra: the
//! reference decompiler prints the short-circuit with the guarded statements inside the condition.
//! This arm has no `docs/*-arm.md`; the two status documents above are its record.
//!
//! Moved verbatim out of printc.rs (review R2, commit 6): the entry (`try_emit_if_nested`) and its
//! only private helper (`basic_clause_stmts`); the only textual change is `self.` → `pr.`. The
//! clause walk it shares with the port's condition renderer (`collect_conj_clauses`,
//! `render_cond_expr`) stays in the port.
//!
//! The arm answers ONE seam, `Site::IfWithoutElse` — an if without an else, after the port's else
//! analysis — under its gate (`cond-form=nested` for the whole function, or a witnessed site).
use crate::decompile::block::BlockId;
use crate::decompile::emit::arms::{Answer, Arm, Site, SiteKind};
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::{exit_basic, PrintC};
use crate::decompile::structure::{FlowKind, Structured};
use std::fmt::Write as _;

/// The arm, as the [`super::ARMS`] table holds it.
pub const ARM: Arm = Arm {
    name: "nested-conds: a short-circuit as nested ifs (cond-form=nested, docs/byte-exact-families.md sb58 / byte-exact-status.md sb65)",
    kinds: &[SiteKind::IfWithoutElse],
    try_emit,
};

fn try_emit(pr: &mut PrintC<'_>, site: Site<'_>, out: &mut String) -> Option<Answer> {
    let Site::IfWithoutElse { s, idx, indent } = site else { return None };
    try_emit_if_nested(pr, s, idx, indent, out).then_some(Answer::Emitted)
}

/// Whether a BASIC condition clause carries statements of its own — anything that would
/// print before its boolean (an explicit-output op, a store, a call). `None` = not a
/// basic clause (compound clauses keep their statements inside their own parens).
fn basic_clause_stmts(pr: &PrintC<'_>, s: &Structured, idx: usize) -> Option<(BlockId, bool)> {
    let FlowKind::Basic(bid) = s.blocks[idx].kind else { return None };
    let mut has = false;
    for &op in &pr.f.block(bid).ops {
        let o = pr.f.op(op);
        if o.is_dead() || o.is_marker() {
            continue;
        }
        match o.code() {
            OpCode::Cbranch | OpCode::Branch => {}
            OpCode::Store | OpCode::Call | OpCode::Callind | OpCode::Callother => has = true,
            _ => {
                if o.output.is_some_and(|v| pr.is_explicit(v)) {
                    has = true;
                }
            }
        }
    }
    Some((bid, has))
}

/// The `cond-form=nested` rendering (the axis doc in emit.rs carries the measured probe
/// and the faithfulness trap): a plain `if` whose printed `&&` spine carries
/// statement-bearing BASIC clauses prints as nested ifs split before each such clause —
/// the clause's statements then run exactly when every earlier clause held, which is
/// short-circuit evaluation spelled structurally. Clause text comes from
/// `render_cond_expr` at the exact effective negation `collect_conj_clauses` recorded,
/// so the printed predicates are the collapsed rendering's own, regrouped. Returns
/// false (fall back to collapsed) when a gate declines.
fn try_emit_if_nested(pr: &mut PrintC<'_>, s: &Structured, idx: usize, indent: usize, out: &mut String) -> bool {
    let fb = &s.blocks[idx];
    if !matches!(fb.kind, FlowKind::If) {
        return false;
    }
    let negated = fb.negated;
    let (cond_idx, body_idx) = (fb.components[0], fb.components[1]);
    let mut clauses = Vec::new();
    pr.collect_conj_clauses(s, cond_idx, negated, &mut clauses);
    if clauses.len() < 2 {
        return false;
    }
    // the win condition: some non-first BASIC clause carries statements; and no goto
    // records anywhere in the condition (their placement is the collapsed form's)
    let mut split_at = vec![false; clauses.len()];
    let mut any_split = false;
    for (i, &(c, _)) in clauses.iter().enumerate() {
        if s.node_gotos.get(&c).is_some() {
            return false;
        }
        if let Some((_, has)) = basic_clause_stmts(pr, s, c) {
            if has && i > 0 {
                split_at[i] = true;
                any_split = true;
            }
        }
    }
    if !any_split || s.node_gotos.get(&cond_idx).is_some() {
        return false;
    }
    // structural candidacy holds — record `(key, clause branch pcs)` for the target
    // profile (on EVERY print), then apply under the axis OR a recovered decision
    let clause_pcs: Vec<u64> = clauses
        .iter()
        .filter_map(|&(c, _)| {
            exit_basic(s, c).and_then(|bid| {
                pr.f.block(bid).ops.iter().rev().copied().find_map(|op| {
                    (!pr.f.op(op).is_dead() && pr.f.op(op).code() == OpCode::Cbranch)
                        .then(|| pr.f.op(op).seqnum.pc.offset)
                })
            })
        })
        .collect();
    let key = clause_pcs.first().copied();
    if let Some(k) = key {
        pr.report.nested_conds.candidates.push((k, clause_pcs.clone()));
    }
    if !(pr.arms.nested_conds.nested || key.is_some_and(|k| pr.recovered.nested_conds.sites.contains(&k))) {
        return false;
    }
    let mut buf = String::new();
    let mut depth = indent;
    let mut pending: Vec<String> = Vec::new();
    let mut opened = 0usize;
    for (i, &(c, neg)) in clauses.iter().enumerate() {
        if split_at[i] {
            let pad = "  ".repeat(depth);
            let joined = pending.join(" && ");
            let _ = writeln!(buf, "{pad}if ({joined}) {{");
            depth += 1;
            opened += 1;
            pending.clear();
        }
        // a BASIC clause's statements print at the current level (clause 0's before the
        // first `if`, exactly where the collapsed form hoists them); its boolean renders
        // WITHOUT comma_separate so the leaf arm does not print them a second time.
        // Compound (||) clauses render under comma_separate and keep their statements
        // inside their own parens, as the collapsed form does.
        match basic_clause_stmts(pr, s, c) {
            Some((bid, _)) => {
                pr.emit_basic(bid, depth, &mut buf);
                let saved = pr.comma_separate;
                pr.comma_separate = false;
                let e = pr.render_cond_expr(s, c, neg);
                pr.comma_separate = saved;
                pending.push(format!("({e})"));
            }
            None => {
                let saved = pr.comma_separate;
                pr.comma_separate = true;
                let e = pr.render_cond_expr(s, c, neg);
                pr.comma_separate = saved;
                pending.push(format!("({e})"));
            }
        }
    }
    let pad = "  ".repeat(depth);
    let joined = pending.join(" && ");
    let _ = writeln!(buf, "{pad}if ({joined}) {{");
    depth += 1;
    opened += 1;
    pr.emit_structured(s, body_idx, depth, &mut buf);
    for k in (0..opened).rev() {
        let _ = writeln!(buf, "{}}}", "  ".repeat(indent + k));
    }
    out.push_str(&buf);
    true
}

/// The arm's state: its configuration (the witness, `recovered.nested_conds.sites`, is the port's).
#[derive(Debug, Default)]
pub(crate) struct State {
    /// `cond-form=nested` is on for the whole function.
    pub(crate) nested: bool,
}

impl State {
    pub(crate) fn new(choices: &crate::decompile::emit::EmitChoices) -> Self {
        State { nested: choices.cond_form == crate::decompile::emit::CondForm::Nested }
    }
}

/// The nested-conds's candidates the report pass collects (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Every statement-carrying short-circuit the `cond-form` axis could nest, as
    /// `(key, clause branch addresses)` where `key` is the FIRST clause's CBRANCH address —
    /// stable and recomputable at apply time. The clause addresses give the target rule the
    /// span to scan: a `SETcc` inside it means the original materialized a clause boolean
    /// (the collapsed comma form); none means branch-only (the nested form).
    pub candidates: Vec<(u64, Vec<u64>)>,
}

/// The nested-conds's witnessed decisions the recovered pass renders (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Sites {
    /// Short-circuit keys (first-clause branch address) to render as nested ifs
    /// (`cond-form`).
    pub sites: std::collections::HashSet<u64>,
}
