//! `counted-loop` — a do-while whose loop variable starts at a constant, steps by a constant
//! and is tested against a constant prints as the `for` loop the source wrote, where the
//! original's bytes iterate at the loop END right after a call (`CALL ; INC EBX ; CMP EBX,4 ;
//! JLE`). Ghidra prints the do-while (`BlockDoWhile` never takes the for-loop rewrite,
//! block.cc:3358) with the increment as the body's last statement, and this compiler's
//! scheduler hoists that statement above the preceding call (`INC EBX ; CALL`, WAR2
//! FUN_0003e858, FUN_0003e7ec); as the loop's own iterate clause it stays at the end.
//! Value-identical: the `for` form tests the loop variable before the first iteration, so the
//! arm fires only when that test is TRUE on the constant initializer.
//!
//! Witness: `recovered.counted_loop_sites`, from `buildconfig::counted_loops_from_evidence`
//! over this arm's `counted_loop_candidates` (the loop's branch address and the loop
//! variable's register) — the original iterates the register right before the loop's compare,
//! and a CALL sits right before the iterate. A target-informed emit choice, NOT Ghidra.
//!
//! The arm is a SETUP pass (`recognize`, after the port's own for-loop detection) that marks
//! the loops and suppresses their iterate and initializer statements; the printer's do-while
//! emission asks `try_emit_for` first — a named helper, not a site: `SiteKind::LoopNode` is
//! string-ops' and the arms declare disjoint kinds.
use crate::decompile::emit::EmitChoices;
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::{entry_basic, PrintC};
use crate::decompile::structure::{FlowKind, Structured};
use crate::decompile::varnode::VarnodeId;
use std::collections::HashMap;
use std::fmt::Write as _;

/// A marked loop: the constant initializer, the iterate op, the loop variable.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Parts {
    init: VarnodeId,
    iterate: OpId,
    var: VarnodeId,
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

/// The setup pass over the structure: every plain do-while with the counted shape is a
/// candidate; the witnessed ones are marked and their iterate / initializer suppressed.
pub(crate) fn recognize(pr: &mut PrintC<'_>, s: &Structured, idx: usize) {
    if matches!(s.blocks[idx].kind, FlowKind::DoWhile) && !s.blocks[idx].has_overflow_syntax() {
        if let Some((parts, branch_pc, reg)) = do_while_parts(pr, s, idx) {
            pr.report.counted_loop_candidates.push((branch_pc, reg));
            if pr.recovered.counted_loop_sites.contains(&branch_pc) {
                pr.arms.counted_loop.loops.insert(idx, parts);
                pr.suppressed.insert(parts.iterate);
                if let Some(d) = pr.f.vn(parts.init).def {
                    pr.suppressed.insert(d);
                }
            }
        }
    }
    for &c in &s.blocks[idx].components.clone() {
        recognize(pr, s, c);
    }
}

/// The counted shape of do-while `idx`: the loop variable (`find_loop_variable` /
/// `test_iterate_form`, the port's own for-loop anchors applied to a do-while's head and
/// tail), a constant initializer in the single predecessor, and a condition that is TRUE at
/// the initializer. Returns the parts, the loop's branch address and the variable's register.
fn do_while_parts(pr: &PrintC<'_>, s: &Structured, idx: usize) -> Option<(Parts, u64, (u64, u32))> {
    macro_rules! decline {
        ($($arg:tt)*) => {{
            crate::debug!(crate::debug::Topic::ForLoop, "counted-loop node {idx} DECLINE {}", format!($($arg)*));
            return None;
        }};
    }
    if s.blocks[idx].components.len() != 1 {
        decline!("{} components", s.blocks[idx].components.len());
    }
    let body = s.blocks[idx].components[0];
    let head = entry_basic(s, body)?;
    let Some(cbranch) = pr.structured_last_op(s, body) else { decline!("no typed last op") };
    if pr.f.op(cbranch).code() != OpCode::Cbranch {
        decline!("last op {:?} is not CBRANCH", pr.f.op(cbranch).code());
    }
    let tail = pr.f.op(cbranch).parent?;
    if pr.f.block(tail).out_edges.len() != 2 || !pr.f.block(tail).out_edges.contains(&head) {
        decline!("tail out-edges {:?} head {:?}", pr.f.block(tail).out_edges, head);
    }
    let cond_var = pr.f.op(cbranch).input(1)?;
    // the iterate is the body's last STATEMENT: in a do-while the condition's own ops (the
    // compare and its boolean layer) sit between it and the branch, so skip them — the port's
    // for-loop anchor (`last`) is the last op of the tail outside the condition expression
    let mut cond_ops: Vec<OpId> = Vec::new();
    let mut stack = vec![cond_var];
    while let Some(v) = stack.pop() {
        let Some(d) = pr.f.vn(v).def else { continue };
        let o = pr.f.op(d);
        if o.parent != Some(tail) || cond_ops.contains(&d) {
            continue;
        }
        if !matches!(
            o.code(),
            OpCode::BoolNegate | OpCode::Copy | OpCode::BoolAnd | OpCode::BoolOr | OpCode::IntEqual | OpCode::IntNotequal
                | OpCode::IntLess | OpCode::IntLessequal | OpCode::IntSless | OpCode::IntSlessequal
        ) {
            continue;
        }
        cond_ops.push(d);
        for i in 0..o.num_inputs() {
            if let Some(w) = o.input(i) {
                stack.push(w);
            }
        }
    }
    let pos = pr.f.block(tail).ops.iter().position(|&o| o == cbranch)?;
    let last = *pr.f.block(tail).ops[..pos].iter().rev().find(|o| !cond_ops.contains(o) && !pr.f.op(**o).is_dead())?;
    let slot = pr.f.block(head).in_edges.iter().position(|&p| p == tail)?;
    let Some((phi, iterate)) = pr.find_loop_variable(cond_var, head, tail, last, slot) else { decline!("findLoopVariable (last {:?})", pr.f.op(last).code()) };
    let var = pr.f.op(phi).output?;
    if !pr.test_iterate_form(var, iterate) {
        decline!("testIterateForm");
    }
    // a constant step
    let io = pr.f.op(iterate);
    if !matches!(io.code(), OpCode::IntAdd | OpCode::IntSub) || !io.input(1).is_some_and(|c| pr.f.vn(c).is_constant()) {
        decline!("iterate {:?} is not a constant step", io.code());
    }
    let iter_out = io.output?;
    // the constant initializer: a COPY in the loop's single predecessor
    if pr.f.block(head).in_edges.len() != 2 {
        decline!("head has {} in-edges", pr.f.block(head).in_edges.len());
    }
    let init_slot = 1 - slot;
    let initvn = pr.f.op(phi).input(init_slot)?;
    let init_def = pr.f.vn(initvn).def?;
    let ido = pr.f.op(init_def);
    if ido.is_marker() || ido.code() != OpCode::Copy || !ido.input(0).is_some_and(|c| pr.f.vn(c).is_constant()) {
        decline!("initializer {:?} is not a constant copy", ido.code());
    }
    let pred = pr.f.block(head).in_edges[init_slot];
    if ido.parent != Some(pred) || pr.f.block(pred).out_edges.len() != 1 {
        decline!("initializer not in the single predecessor");
    }
    let k0 = pr.f.vn(ido.input(0)?).constant_value();
    // the loop continues while the printed condition holds; the `for` form tests it before the
    // first iteration, on the initializer — it has to hold there
    match cond_true_at(pr, cond_var, s.blocks[idx].negated, iter_out, var, k0) {
        Some(true) => {}
        Some(false) => decline!("the condition is false at the initializer {k0:#x}"),
        None => decline!("the condition is not a compare of the loop variable with a constant"),
    }
    let vn = pr.f.vn(iter_out);
    if pr.f.spaces.by_name("register") != Some(vn.loc.space) {
        decline!("the loop variable is not a register");
    }
    let branch_pc = pr.f.op(cbranch).seqnum.pc.offset;
    Some((Parts { init: initvn, iterate, var }, branch_pc, (vn.loc.offset, vn.size)))
}

/// Whether the do-while's printed condition (the CBRANCH's boolean, negated when the structure
/// says so) is TRUE with the loop variable worth `k0`. The compare has to test the iterated
/// value (or the loop variable) against a constant; anything else is `None`.
fn cond_true_at(pr: &PrintC<'_>, cond: VarnodeId, negated: bool, x1: VarnodeId, x2: VarnodeId, k0: u64) -> Option<bool> {
    let mut v = cond;
    let mut neg = negated;
    for _ in 0..4 {
        let d = pr.f.vn(v).def?;
        match pr.f.op(d).code() {
            OpCode::BoolNegate => {
                neg = !neg;
                v = pr.f.op(d).input(0)?;
            }
            OpCode::Copy => v = pr.f.op(d).input(0)?,
            _ => break,
        }
    }
    let d = pr.f.vn(v).def?;
    let o = pr.f.op(d);
    let (a, b) = (o.input(0)?, o.input(1)?);
    let is_x = |w: VarnodeId| w == x1 || w == x2;
    let size = pr.f.vn(a).size;
    let mask = if size >= 8 { u64::MAX } else { (1u64 << (8 * size)) - 1 };
    let (l, r) = if is_x(a) && pr.f.vn(b).is_constant() {
        (k0 & mask, pr.f.vn(b).constant_value() & mask)
    } else if pr.f.vn(a).is_constant() && is_x(b) {
        (pr.f.vn(a).constant_value() & mask, k0 & mask)
    } else {
        return None;
    };
    let sext = |u: u64| -> i64 {
        if size >= 8 || u & (1u64 << (8 * size - 1)) == 0 {
            u as i64
        } else {
            (u | !mask) as i64
        }
    };
    let raw = match o.code() {
        OpCode::IntEqual => l == r,
        OpCode::IntNotequal => l != r,
        OpCode::IntLess => l < r,
        OpCode::IntLessequal => l <= r,
        OpCode::IntSless => sext(l) < sext(r),
        OpCode::IntSlessequal => sext(l) <= sext(r),
        _ => return None,
    };
    Some(raw ^ neg)
}

/// The do-while emission's first question: a marked loop prints as `for (init; cond; iterate)`
/// around the body (its iterate suppressed). Returns whether the arm printed the loop.
pub(crate) fn try_emit_for(pr: &mut PrintC<'_>, s: &Structured, idx: usize, indent: usize, out: &mut String) -> bool {
    let Some(parts) = pr.arms.counted_loop.loops.get(&idx).copied() else { return false };
    let body = s.blocks[idx].components[0];
    let negated = s.blocks[idx].negated;
    let pad = "  ".repeat(indent);
    if let Some(b) = entry_basic(s, body) {
        if pr.labels.remove(&b) {
            let name = pr.lab_name(b);
            let _ = writeln!(out, "{}{}:", "  ".repeat(indent.saturating_sub(1)), name);
        }
    }
    let lhs = pr.lvalue_of(parts.var);
    // the initializer's expression (the constant the suppressed COPY assigns), as the port's
    // own for-loop header renders it
    let init = match pr.f.vn(parts.init).def {
        Some(d) => pr.render_op(d).0,
        None => pr.render_var(parts.init).0,
    };
    let cond = pr.render_condition(s, body, negated);
    let iter = pr.render_assign(parts.iterate);
    let _ = writeln!(out, "{pad}for ({lhs} = {init}; {cond}; {iter}) {{");
    pr.emit_structured(s, body, indent + 1, out);
    let _ = writeln!(out, "{pad}}}");
    true
}
