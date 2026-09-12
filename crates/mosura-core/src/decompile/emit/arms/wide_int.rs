//! Narrow consumers of wide arithmetic, represented by word-sized primitives.
//!
//! This arm does not change the IR or the reference casts. It answers `OpRoot`
//! for a SUBPIECE of an implicit product or unsigned quotient/remainder. The
//! complete input width is retained by the primitive's contract; a low product
//! alone may use ordinary unsigned multiplication modulo the output width.
//! Compiler selection and primitive implementations belong to `recompile`.
//! Recognition uses typed data flow; recovery checks the arithmetic operation
//! at its original instruction address. Unknown shapes retain the port's C.
use std::collections::HashSet;

use crate::decompile::emit::{EmitChoices, WideInt};
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;
use crate::decompile::types::Datatype;
use crate::decompile::varnode::VarnodeId;

#[derive(Debug, Default)]
pub(crate) struct State { split: bool }

impl State {
    pub(crate) fn new(choices: &EmitChoices) -> Self {
        Self { split: choices.wide_int == WideInt::Split32 }
    }
}

/// A candidate's operation and the original wide arithmetic it requires.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub op: OpId,
    pub arithmetic: Vec<(u64, OpCode)>,
}

#[derive(Debug, Default, Clone)]
pub struct Report { pub candidates: Vec<Candidate> }

#[derive(Debug, Default, Clone)]
pub struct Sites { pub sites: HashSet<OpId> }

#[derive(Clone, Copy)]
enum Word {
    Constant(u32),
    Value(VarnodeId, bool), // sign-extend at this value's own width
}

/// Only implicit pure operations may be replaced by their input expression.
/// Explicit wide variables must keep their declaration and all their uses.
fn definition(pr: &PrintC<'_>, v: VarnodeId) -> Option<OpId> {
    if pr.is_explicit(v) { return None; }
    let op = pr.f.vn(v).def?;
    (!pr.f.op(op).is_dead()).then_some(op)
}

fn uncast(pr: &PrintC<'_>, mut v: VarnodeId) -> VarnodeId {
    while let Some(op) = definition(pr, v) {
        let o = pr.f.op(op);
        if !matches!(o.code(), OpCode::Copy | OpCode::Cast) { break; }
        let Some(input) = o.input(0) else { break };
        if pr.f.vn(input).size != pr.f.vn(v).size { break; }
        v = input;
    }
    v
}

fn extended(pr: &PrintC<'_>, v: VarnodeId) -> Option<(Word, bool)> {
    let v = uncast(pr, v);
    let vn = pr.f.vn(v);
    if vn.size != 8 { return None; }
    if vn.is_constant() && vn.constant_value() <= u64::from(u32::MAX) {
        return Some((Word::Constant(vn.constant_value() as u32), false));
    }
    let o = pr.f.op(definition(pr, v)?);
    let signed = match o.code() {
        OpCode::IntZext => false,
        OpCode::IntSext => true,
        _ => return None,
    };
    let input = o.input(0)?;
    matches!(pr.f.vn(input).size, 1 | 2 | 4).then_some((Word::Value(input, signed), signed))
}

fn product(pr: &PrintC<'_>, v: VarnodeId) -> Option<(OpId, Word, Word, bool)> {
    let v = uncast(pr, v);
    let op = definition(pr, v)?;
    let o = pr.f.op(op);
    if pr.f.vn(v).size != 8 || o.code() != OpCode::IntMult { return None; }
    let (a, sa) = extended(pr, o.input(0)?)?;
    let (b, sb) = extended(pr, o.input(1)?)?;
    // A nonnegative constant can serve either product. Mixed variable extension
    // kinds need their own arithmetic; they cannot select signed MUL by a guess.
    if sa != sb && !matches!(a, Word::Constant(_)) && !matches!(b, Word::Constant(_)) {
        return None;
    }
    let signed = sa || sb;
    if signed && [a, b].iter().any(|w| matches!(w, Word::Constant(n) if *n > i32::MAX as u32)) {
        return None;
    }
    Some((op, a, b, signed))
}

/// A dividend supplied as words, not a named eight-byte C object.
fn pair(pr: &PrintC<'_>, v: VarnodeId) -> Option<(Word, Word)> {
    let v = uncast(pr, v);
    let vn = pr.f.vn(v);
    if vn.size != 8 { return None; }
    if vn.is_constant() {
        return Some((Word::Constant(vn.constant_value() as u32), Word::Constant((vn.constant_value() >> 32) as u32)));
    }
    if let Some((word, false)) = extended(pr, v) { return Some((word, Word::Constant(0))); }
    let o = pr.f.op(definition(pr, v)?);
    if o.code() == OpCode::Piece {
        let (hi, lo) = (o.input(0)?, o.input(1)?);
        if pr.f.vn(hi).size == 4 && pr.f.vn(lo).size == 4 {
            return Some((Word::Value(lo, false), Word::Value(hi, false)));
        }
    }
    if o.code() == OpCode::IntLeft {
        let count = pr.f.vn(o.input(1)?);
        if count.is_constant() && count.constant_value() == 32 {
            let (word, false) = extended(pr, o.input(0)?)? else { return None };
            return Some((Word::Constant(0), word));
        }
    }
    None
}

enum Expression {
    Product { a: Word, b: Word, signed: bool, shift: u32 },
    Divide { a: Word, b: Word, divisor: Word, product: bool, remainder: bool },
}

fn shape(pr: &PrintC<'_>, op: OpId) -> Option<(Expression, Candidate)> {
    let o = pr.f.op(op);
    if o.code() != OpCode::Subpiece || !matches!(pr.f.vn(o.output?).size, 1 | 2 | 4) { return None; }
    let offset = pr.f.vn(o.input(1)?);
    if !offset.is_constant() { return None; }
    let mut shift = u32::try_from(offset.constant_value()).ok()?.checked_mul(8)?;
    let mut v = uncast(pr, o.input(0)?);
    if pr.f.vn(v).size != 8 { return None; }
    while let Some(d) = definition(pr, v) {
        let o = pr.f.op(d);
        if o.code() != OpCode::IntRight { break; }
        let count = pr.f.vn(o.input(1)?);
        if !count.is_constant() { return None; }
        shift = shift.checked_add(u32::try_from(count.constant_value()).ok()?)?;
        v = uncast(pr, o.input(0)?);
    }
    if shift >= 64 { return None; }
    let witness = |d: OpId| (pr.f.op(d).seqnum.pc.offset, pr.f.op(d).code());
    if let Some((d, a, b, signed)) = product(pr, v) {
        return Some((Expression::Product { a, b, signed, shift }, Candidate { op, arithmetic: vec![witness(d)] }));
    }
    if shift != 0 { return None; }
    let d = definition(pr, v)?;
    let o = pr.f.op(d);
    if !matches!(o.code(), OpCode::IntDiv | OpCode::IntRem) { return None; }
    let (divisor, false) = extended(pr, o.input(1)?)? else { return None };
    let numerator = o.input(0)?;
    let mut arithmetic = vec![witness(d)];
    let (a, b, product) = if let Some((m, a, b, false)) = product(pr, numerator) {
        arithmetic.push(witness(m));
        (a, b, true)
    } else {
        let (lo, hi) = pair(pr, numerator)?;
        (lo, hi, false)
    };
    Some((Expression::Divide { a, b, divisor, product, remainder: o.code() == OpCode::IntRem }, Candidate { op, arithmetic }))
}

fn word_text(pr: &mut PrintC<'_>, word: Word) -> String {
    match word {
        Word::Constant(n) => format!("0x{n:x}"),
        Word::Value(v, signed) => {
            let ty = if signed { Datatype::Int(pr.f.vn(v).size) } else { Datatype::Uint(pr.f.vn(v).size) };
            format!("({}){}", ty.name(), pr.operand(v, 14, false))
        }
    }
}

pub(crate) fn render(pr: &mut PrintC<'_>, op: OpId) -> Option<(String, u8)> {
    let (expr, candidate) = shape(pr, op)?;
    pr.report.wide_int.candidates.push(candidate);
    if !pr.arms.wide_int.split || !pr.recovered.wide_int.sites.contains(&op) { return None; }
    let text = match expr {
        Expression::Product { a, b, signed, shift } => {
            let (a, b) = (word_text(pr, a), word_text(pr, b));
            if shift == 0 {
                format!("((uint4)({a}) * (uint4)({b}))")
            } else {
                let name = if signed { "__mosura_smul_shift" } else { "__mosura_umul_shift" };
                format!("{name}({a}, {b}, {shift})")
            }
        }
        Expression::Divide { a, b, divisor, product, remainder } => {
            let (a, b, divisor) = (word_text(pr, a), word_text(pr, b), word_text(pr, divisor));
            let name = match (product, remainder) {
                (true, false) => "__mosura_umuldiv32",
                (true, true) => "__mosura_umulrem32",
                (false, false) => "__mosura_udiv64_32",
                (false, true) => "__mosura_urem64_32",
            };
            format!("{name}({a}, {b}, {divisor})")
        }
    };
    let out = pr.f.op(op).output?;
    let ty = pr.type_of(out);
    let ty = if ty.size() == pr.f.vn(out).size { ty } else { Datatype::Uint(pr.f.vn(out).size) };
    Some((format!("({}){text}", ty.name()), 14))
}
