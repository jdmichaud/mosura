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
//! A second shape at the same site (2026-09-03, the EXACT push — docs/exact-arms.md): the tail
//! returns a variable that is a MULTIEQUAL of two CONSTANTS, one assigned in the if's condition
//! block ahead of the branch (`x = 0;`), the other at the end of the if body (`x = 1;`) — the
//! merged form Ghidra builds when the compiler shares one epilogue between `return 0;` and
//! `return 1;`. The original materializes each constant on its own path (a `XOR AL,AL`
//! right before an epilogue, after the branch — the witness `recovered.const_phi_sites`, from
//! `buildconfig::const_phi_returns_from_evidence` over this arm's `const_phi_candidates`); the
//! arm suppresses both assignments and prints the per-path returns. Value-identical: the phi's
//! value on each path IS that path's constant.
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
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::{exit_basic, render_const, PrintC};
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
    kinds: &[SiteKind::ListTail, SiteKind::Return],
    try_emit,
};

fn try_emit(pr: &mut PrintC<'_>, site: Site<'_>, out: &mut String) -> Option<Answer> {
    if let Site::Return { op, pad } = site {
        return branch_return(pr, op, pad, out);
    }
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
            // the branch may test the NEGATION of the returned bool (`JZ` over `x != 0`: the
            // CBRANCH input is a BOOL_NEGATE the structure prints back positive) — peel it and
            // fold the flip into the structure's own negation (FUN_0002a31c, FUN_0002ac70)
            let (cond0, flips) = peel_negations(pr, cond);
            if apply && same_bool_value(pr, cond0, ret_b) {
                let negated = s.blocks[c].negated ^ flips;
                let (then_k, tail_k) = if negated { (0, 1) } else { (1, 0) };
                emit_if_with_tail(pr, s, c, indent, out, &format!("return {then_k};"));
                let pad = "  ".repeat(indent);
                let _ = writeln!(out, "{pad}return {tail_k};");
                // the tail block's ops are consumed by this rendering
                let _ = tail_bid;
                return Some(Answer::Emitted);
            }
        }
        // the constant-phi shape (see the module doc)
        if let Some(split) = const_phi_split(pr, s, c, tail) {
            pr.report.const_phi_candidates.push((split.branch_pc, split.k_tail));
            if pr.recovered.const_phi_sites.contains(&split.branch_pc) {
                if let Some(copy_tail) = split.copy_tail {
                    pr.suppressed.insert(copy_tail);
                }
                pr.suppressed.insert(split.copy_body);
                let then_k = render_const(split.k_body, split.size);
                let tail_k = render_const(split.k_tail, split.size);
                emit_if_with_tail(pr, s, c, indent, out, &format!("return {then_k};"));
                let pad = "  ".repeat(indent);
                let _ = writeln!(out, "{pad}return {tail_k};");
                return Some(Answer::Emitted);
            }
        }
    }
    None
}

/// The constant-phi tail: the if `c`'s condition block assigns constant `k_tail` to a variable
/// (`copy_tail`), the if body's exit block assigns `k_body` to it (`copy_body`), and the tail
/// block's only statement returns the phi of the two.
struct ConstPhiSplit {
    branch_pc: u64,
    /// The tail constant's COPY, or `None` when the tail input is the tested value itself
    /// (`cVar1 != 0` false ⇒ `cVar1 == 0`: the phi carries the call result, worth 0 there).
    copy_tail: Option<crate::decompile::op::OpId>,
    copy_body: crate::decompile::op::OpId,
    k_tail: u64,
    k_body: u64,
    size: u32,
}

fn const_phi_split(pr: &PrintC<'_>, s: &Structured, c: usize, tail: usize) -> Option<ConstPhiSplit> {
    use crate::debug::Topic;
    if !matches!(s.blocks[c].kind, FlowKind::If) || s.blocks[c].components.len() != 2 {
        return None;
    }
    // the condition component's last basic block: the block with the branch (the component
    // is a List when earlier statements fold into it — FUN_0002c4e4's `if (..) return 0;`)
    let cond_bid = exit_basic(s, s.blocks[c].components[0])?;
    let Some(body_exit) = exit_basic(s, s.blocks[c].components[1]) else {
        crate::debug!(Topic::Recover, "const-phi: no body exit");
        return None;
    };
    // the branch: the condition block's live CBRANCH (`plain_if_branch_pc` for a Basic
    // condition; the same op when the condition component is a List)
    let branch_pc = pr
        .f
        .block(cond_bid)
        .ops
        .iter()
        .rev()
        .copied()
        .find(|&op| !pr.f.op(op).is_dead() && pr.f.op(op).code() == OpCode::Cbranch)
        .map(|op| pr.f.op(op).seqnum.pc.offset)?;
    // the tail: a basic block whose only printable statement is `return v`
    let FlowKind::Basic(tail_bid) = s.blocks[tail].kind else { return None };
    let mut ret = None;
    for &op in &pr.f.block(tail_bid).ops {
        let o = pr.f.op(op);
        if o.is_dead() || o.is_marker() || o.is_return_copy() {
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
                    crate::debug!(Topic::Recover, "const-phi @{branch_pc:x}: tail statement {:?}", o.code());
                    return None;
                }
            }
        }
    }
    let v = thru_copy(pr, pr.f.op(ret?).input(1)?);
    let Some(phi) = pr.f.vn(v).def else {
        crate::debug!(Topic::Recover, "const-phi @{branch_pc:x}: returned value has no def");
        return None;
    };
    let po = pr.f.op(phi);
    if po.code() != OpCode::Multiequal || po.num_inputs() != 2 {
        crate::debug!(Topic::Recover, "const-phi @{branch_pc:x}: returned value def {:?} x{}", po.code(), po.num_inputs());
        return None;
    }
    // the value the branch tests against zero (`x != 0` / `x == 0`): a phi input that IS that
    // value on the tail path is worth 0 there — Ghidra's `return cVar1 != '\0';` of
    // FUN_0002a228 / FUN_0002a31c, where the original's `TEST AL,AL ; JZ epilogue` returns
    // the tested register itself
    let tested = pr
        .f
        .block(cond_bid)
        .ops
        .iter()
        .rev()
        .copied()
        .find(|&op| !pr.f.op(op).is_dead() && pr.f.op(op).code() == OpCode::Cbranch)
        .and_then(|cb| pr.f.op(cb).input(1))
        .map(|b| thru_copy(pr, b))
        .and_then(|b| pr.f.vn(b).def)
        .and_then(|d| {
            let o = pr.f.op(d);
            if !matches!(o.code(), OpCode::IntNotequal | OpCode::IntEqual) {
                return None;
            }
            let (x, k) = (o.input(0)?, o.input(1)?);
            (pr.f.vn(k).is_constant() && pr.f.vn(k).constant_value() == 0).then(|| thru_copy(pr, x))
        });
    // each phi input: a COPY of a constant, in the condition block or in the body's exit block
    let mut tail_side = None;
    let mut body_side = None;
    for i in 0..2 {
        let input = po.input(i)?;
        if tested.is_some_and(|x| x == thru_copy(pr, input)) && tail_side.is_none() {
            tail_side = Some((None, 0u64));
            continue;
        }
        // the phi input's own def is the COPY of the constant (into the variable itself, or
        // into a unique the phi merges: FUN_0002c4e4's `xVar2 = 0` is a unique at the branch)
        let Some(copy) = pr.f.vn(input).def else { return None };
        let co = pr.f.op(copy);
        if co.code() != OpCode::Copy {
            crate::debug!(Topic::Recover, "const-phi @{branch_pc:x}: input {i} def {:?}", co.code());
            return None;
        }
        let k = co.input(0)?;
        if !pr.f.vn(k).is_constant() {
            crate::debug!(Topic::Recover, "const-phi @{branch_pc:x}: input {i} copies a non-constant");
            return None;
        }
        let Some(parent) = co.parent else { return None };
        if parent == cond_bid {
            tail_side = Some((Some(copy), pr.f.vn(k).constant_value()));
        } else if parent == body_exit {
            body_side = Some((copy, pr.f.vn(k).constant_value()));
        } else {
            crate::debug!(
                Topic::Recover,
                "const-phi @{branch_pc:x}: input {i} in block {:?} (cond {:?}, body exit {:?})",
                parent,
                cond_bid,
                body_exit
            );
            return None;
        }
    }
    let (copy_tail, k_tail) = tail_side?;
    let (copy_body, k_body) = body_side?;
    if k_tail == k_body || !pr.is_explicit(v) {
        return None;
    }
    Some(ConstPhiSplit { branch_pc, copy_tail, copy_body, k_tail, k_body, size: pr.f.vn(v).size })
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
        // heritage's return-guard COPY of a persistent global (`markReturnCopy`) prints nothing
        if o.is_dead() || o.is_marker() || o.is_return_copy() {
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
/// Resolve a value through a chain of COPYs.
///
/// Since `RuleBoolNegate` was ported faithfully (Order Z(5)) a negated comparison is a comparison
/// flipped IN PLACE plus a COPY of it -- Ghidra's shape, and Ghidra's `RulePropagateCopy` clears
/// those copies before its own consumers look. Ours survive to print time at some sites, and this
/// arm's gate below is an IDENTITY test, so a COPY between the `if`'s condition and the returned
/// boolean made it decline: measured, 15 EXACT of the port's round.
///
/// Looking through the copy here is NOT the `render_negated` question and the two must not be
/// argued alike. `render_negated` is the PRINTER: it must render what Ghidra renders, Ghidra has no
/// COPY arm, and adding one there would be a divergence (Bob's tripwire test pins exactly that).
/// This is an EMIT ARM whose whole purpose is to print what Ghidra does not -- Watcom's
/// materialised `1`/`0` where both decompilers print the merged boolean. Its gate exists to decide
/// whether the WATCOM rewrite is value-identical, and a COPY does not change a value. Teaching it
/// to see through one repairs a target-side witness the new IR shape broke; it does not make the
/// printer less faithful.
fn thru_copy(pr: &PrintC<'_>, mut v: VarnodeId) -> VarnodeId {
    // bounded: a copy chain in a well-formed function is short, and a bound is cheaper than
    // trusting that it can never cycle
    for _ in 0..8 {
        let Some(d) = pr.f.vn(v).def else { break };
        if pr.f.op(d).code() != OpCode::Copy {
            break;
        }
        match pr.f.op(d).input(0) {
            Some(i) => v = i,
            None => break,
        }
    }
    v
}

/// The value under any chain of BOOL_NEGATEs (through copies), and whether the chain flips.
fn peel_negations(pr: &PrintC<'_>, v: VarnodeId) -> (VarnodeId, bool) {
    let mut v = thru_copy(pr, v);
    let mut flips = false;
    while let Some(d) = pr.f.vn(v).def {
        let o = pr.f.op(d);
        if o.code() != OpCode::BoolNegate {
            break;
        }
        let Some(x) = o.input(0) else { break };
        v = thru_copy(pr, x);
        flips = !flips;
    }
    (v, flips)
}

/// The branch form of a lone `return <bool>;` (the module doc): `if (cond) { return 1; }
/// return 0;` where the original branched over the constant instead of materializing the bool.
/// Value-identical.
fn branch_return(pr: &mut PrintC<'_>, op: OpId, pad: &str, out: &mut String) -> Option<Answer> {
    if pr.comma_separate {
        return None;
    }
    let v = pr.f.op(op).input(1)?;
    let (b, flips) = peel_negations(pr, v);
    let d = pr.f.vn(b).def?;
    let bo = pr.f.op(d);
    if !bo.is_bool_output() || bo.code() == OpCode::BoolNegate || pr.f.vn(v).size != 1 {
        return None;
    }
    let pc = bo.seqnum.pc.offset;
    pr.report.branch_return_candidates.push(pc);
    if !pr.recovered.branch_return_sites.contains(&pc) {
        return None;
    }
    let cond = pr.render_var(v).0;
    let _ = flips; // the rendered bool already carries its negation
    let _ = writeln!(out, "{pad}if ({cond}) {{");
    let _ = writeln!(out, "{pad}  return 1;");
    let _ = writeln!(out, "{pad}}}");
    let _ = writeln!(out, "{pad}return 0;");
    Some(Answer::Emitted)
}

fn same_bool_value(pr: &PrintC<'_>, a: VarnodeId, b: VarnodeId) -> bool {
    let (a, b) = (thru_copy(pr, a), thru_copy(pr, b));
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
