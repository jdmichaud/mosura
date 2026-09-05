//! `for-rotate` — a loop the port prints in Ghidra's overflow syntax, `while( true ) { if (A)
//! break; body }` or `while( true ) { if ((A) || (B)) break; body }`, whose first clause `A` tests
//! the loop variable the body iterates last, prints as the `for` loop the source wrote —
//! `for (init; !A; iterate) { [if (B) break;] body }` — where the original ROTATED the loop:
//! entered by a jump to the test at the loop's end, the test's branch jumping backward to the
//! body. This compiler rotates a `for` loop and not a `while` loop (measured on the subject
//! FUN_0005beb0: the `for` form is byte-exact, the `while` form tests at the top and jumps
//! back), and Ghidra's `BlockWhileDo::finalTransform` (block.cc:3358) declines the for-loop
//! rewrite for every overflow loop, so the port keeps the `while( true )` — which this
//! compiler tests at the top. 146 non-exact functions carry the top/bottom test swap on round
//! f0. Value-identical: the same test on the same values before every iteration, the same
//! break, the iterate moved from the body's last statement to the header (Ghidra's own
//! for-loop hoist, `for_parts`).
//!
//! Witness (`recovered.for_rotate.sites`, from `buildconfig::rotated_loops_from_evidence` over
//! this arm's candidates, the first clause's branch address): the original's branch at that
//! address jumps BACKWARD — the test sits at the loop end. A top-of-loop test (a `while` in the
//! source) branches forward and keeps the port's form. A target-informed emit choice, NOT Ghidra.
//!
//! The arm is a SETUP pass (`recognize`, after the port's own for-loop detection) that marks the
//! loops and suppresses their iterate and initializer statements; the printer's overflow
//! emission asks `try_emit_for` first — a named helper, not a site, like `counted-loop`.
use crate::decompile::emit::EmitChoices;
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::{entry_basic, exit_basic, operand_oriented, PrintC};
use crate::decompile::structure::{FlowKind, Structured};
use crate::decompile::varnode::VarnodeId;
use std::collections::HashMap;
use std::fmt::Write as _;

/// A marked loop: the port's for-loop parts, the first clause's node and its effective
/// negation as the overflow rendering would print it, and the rest of the break condition.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Parts {
    init_var: Option<VarnodeId>,
    iterate: OpId,
    phi_out: VarnodeId,
    a_node: usize,
    a_neg: bool,
    rest: Option<(usize, bool)>,
}

/// The arm's state: the loops `recognize` marked, by structure node.
#[derive(Debug, Default)]
pub(crate) struct State {
    pub(crate) loops: HashMap<usize, Parts>,
}

impl State {
    pub(crate) fn new(_choices: &EmitChoices) -> Self {
        State::default()
    }
}

/// The setup pass over the structure: every overflow-syntax while-do whose first clause is a
/// statement-free compare and whose body iterates a loop variable is a candidate; the witnessed
/// ones are marked and their iterate / initializer suppressed.
pub(crate) fn recognize(pr: &mut PrintC<'_>, s: &Structured, idx: usize) {
    if matches!(s.blocks[idx].kind, FlowKind::WhileDo) && s.blocks[idx].has_overflow_syntax() {
        if let Some((parts, branch_pc)) = loop_parts(pr, s, idx) {
            pr.report.for_rotate.candidates.push(branch_pc);
            if pr.recovered.for_rotate.sites.contains(&branch_pc) {
                pr.arms.for_rotate.loops.insert(idx, parts);
                pr.suppressed.insert(parts.iterate);
                if let Some(d) = parts.init_var.and_then(|iv| pr.f.vn(iv).def) {
                    pr.suppressed.insert(d);
                }
            }
        }
    }
    for &c in &s.blocks[idx].components.clone() {
        recognize(pr, s, c);
    }
}

/// Whether the condition leaf `idx` prints statements of its own (anything but the branch and
/// implied values) — such a leaf cannot be a `for` header's test.
fn leaf_has_stmts(pr: &PrintC<'_>, s: &Structured, idx: usize) -> bool {
    let FlowKind::Basic(bid) = s.blocks[idx].kind else { return true };
    pr.f.block(bid).ops.iter().any(|&op| {
        let o = pr.f.op(op);
        if o.is_dead() || o.is_marker() {
            return false;
        }
        match o.code() {
            OpCode::Cbranch | OpCode::Branch => false,
            OpCode::Store | OpCode::Call | OpCode::Callind | OpCode::Callother => true,
            _ => o.output.is_some_and(|v| pr.is_explicit(v)),
        }
    })
}

/// The `for` shape of overflow loop `idx`: the first clause (the whole condition when it is
/// one leaf, else operand 0 of a short-circuit whose printed break connective is `||`), its
/// effective negation exactly as `render_cond_expr` derives it, the port's for-loop parts
/// anchored on that clause, and no goto records on the pieces. Returns the parts and the
/// first clause's branch address.
fn loop_parts(pr: &PrintC<'_>, s: &Structured, idx: usize) -> Option<(Parts, u64)> {
    let comps = &s.blocks[idx].components;
    if comps.len() != 2 {
        return None;
    }
    let (cond, body) = (comps[0], comps[1]);
    let negated = s.blocks[idx].negated;
    if s.node_gotos.contains_key(&cond) || s.node_gotos.contains_key(&body) {
        return None;
    }
    let (a_node, a_neg, rest) = match s.blocks[cond].kind {
        FlowKind::Basic(_) => (cond, negated, None),
        FlowKind::CondAnd | FlowKind::CondOr => {
            let is_and = matches!(s.blocks[cond].kind, FlowKind::CondAnd);
            // the break condition prints as a disjunction: `(A) || (B)` — break on either
            if is_and != negated {
                return None;
            }
            let (c0, c1) = (s.blocks[cond].components[0], s.blocks[cond].components[1]);
            let (f0, f1) = s.blocks[cond].cond_flip;
            if !matches!(s.blocks[c0].kind, FlowKind::Basic(_)) {
                return None;
            }
            if s.node_gotos.contains_key(&c0) || s.node_gotos.contains_key(&c1) {
                return None;
            }
            if let Some(eb) = exit_basic(s, cond) {
                if s.gotos.contains_key(&eb) {
                    return None;
                }
            }
            let a_neg = negated ^ operand_oriented(pr.f, s, c0) ^ f0;
            let b_neg = negated ^ operand_oriented(pr.f, s, c1) ^ f1;
            (c0, a_neg, Some((c1, b_neg)))
        }
        _ => return None,
    };
    if leaf_has_stmts(pr, s, a_node) {
        return None;
    }
    let FlowKind::Basic(a_bid) = s.blocks[a_node].kind else { return None };
    if s.gotos.contains_key(&a_bid) {
        return None;
    }
    let (init_var, iterate, phi_out) = pr.for_parts(s, a_node, body)?;
    let branch = pr.f.block(a_bid).ops.iter().rev().copied().find(|&op| !pr.f.op(op).is_dead() && pr.f.op(op).code() == OpCode::Cbranch)?;
    let branch_pc = pr.f.op(branch).seqnum.pc.offset;
    // the iterate is the header's: a labeled tail block would keep its label with no statement
    // after it (`LAB: }` — E1082 on the subject's FUN_00018238, FUN_00028aa8, round f2)
    if pr.f.op(iterate).parent.is_some_and(|b| pr.labels.contains(&b)) {
        return None;
    }
    // a constant initializer against a constant bound: this compiler folds the entry test of
    // the port's `while( true )` form itself (the test is decidable at the initializer) and
    // rotates the loop; the `for` form then duplicates the body's leading break test at the
    // loop end and hoists its loads (the subject's FUN_0006eec5 0.950 → 0.762, FUN_000289f8 −0.211,
    // round f2). The arm's win is the undecidable entry test.
    let init_const = init_var.is_some_and(|iv| {
        let vn = pr.f.vn(iv);
        vn.is_constant() || vn.def.is_some_and(|d| pr.f.op(d).code() == OpCode::Copy && pr.f.op(d).input(0).is_some_and(|c| pr.f.vn(c).is_constant()))
    });
    if init_const && compare_against_constant(pr, branch) {
        return None;
    }
    Some((Parts { init_var, iterate, phi_out, a_node, a_neg, rest }, branch_pc))
}

/// Whether the branch's condition is a compare with a constant operand (through negations
/// and copies) — with a constant initializer, an entry test this compiler decides itself.
fn compare_against_constant(pr: &PrintC<'_>, cbranch: OpId) -> bool {
    let Some(mut v) = pr.f.op(cbranch).input(1) else { return false };
    for _ in 0..4 {
        let Some(d) = pr.f.vn(v).def else { return false };
        match pr.f.op(d).code() {
            OpCode::BoolNegate | OpCode::Copy => {
                let Some(x) = pr.f.op(d).input(0) else { return false };
                v = x;
            }
            _ => break,
        }
    }
    let Some(d) = pr.f.vn(v).def else { return false };
    let o = pr.f.op(d);
    (0..o.num_inputs()).any(|i| o.input(i).is_some_and(|x| pr.f.vn(x).is_constant()))
}

/// The overflow emission's first question: a marked loop prints as
/// `for (init; !A; iterate) { [stmts; if (B) break;] body }`. Returns whether the arm printed it.
pub(crate) fn try_emit_for(pr: &mut PrintC<'_>, s: &Structured, idx: usize, indent: usize, out: &mut String) -> bool {
    let Some(parts) = pr.arms.for_rotate.loops.get(&idx).copied() else { return false };
    let comps = s.blocks[idx].components.clone();
    let pad = "  ".repeat(indent);
    let bpad = "  ".repeat(indent + 1);
    // the port's for-loop header: a label on the front leaf prints above the loop
    if let Some(b) = entry_basic(s, comps[0]) {
        if pr.labels.remove(&b) {
            let name = pr.lab_name(b);
            let _ = writeln!(out, "{}{}:", "  ".repeat(indent.saturating_sub(1)), name);
        }
    }
    let init_s = match parts.init_var {
        Some(iv) => {
            let lhs = pr.lvalue_of(parts.phi_out);
            let rhs = match pr.f.vn(iv).def {
                Some(d) => pr.render_op(d).0,
                None => pr.render_var(iv).0,
            };
            format!("{lhs} = {rhs}")
        }
        None => String::new(),
    };
    // the continue test is the first clause's negation, at the negation the overflow rendering
    // gives the clause
    let cond = pr.render_cond_expr(s, parts.a_node, !parts.a_neg);
    let iter_s = pr.render_assign(parts.iterate);
    let _ = writeln!(out, "{pad}for ({init_s}; {cond}; {iter_s}) {{");
    if let Some((b_node, b_neg)) = parts.rest {
        pr.emit_structured(s, b_node, indent + 1, out);
        let b = pr.render_cond_expr(s, b_node, b_neg);
        let _ = writeln!(out, "{bpad}if ({b}) break;");
    }
    pr.emit_structured(s, comps[1], indent + 1, out);
    let _ = writeln!(out, "{pad}}}");
    true
}

/// The for-rotate's candidates the report pass collects (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Every overflow loop with the `for` shape (`for-rotate`): the first clause's branch
    /// address. The original either jumps backward there (the test at the loop end — a rotated
    /// `for`) or forward (a top test — a `while`).
    pub candidates: Vec<u64>,
}

/// The for-rotate's witnessed decisions the recovered pass renders (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Sites {
    /// First-clause branch addresses whose loop prints as a `for` (`for-rotate`, `for_rotate`
    /// candidates evidence, `buildconfig::rotated_loops_from_evidence`).
    pub sites: std::collections::HashSet<u64>,
}
