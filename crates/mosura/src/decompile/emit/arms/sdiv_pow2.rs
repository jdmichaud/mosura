//! `sdiv-pow2` — Watcom's SBB template for a signed division by 2^n (`SAR` after `SBB`) prints as
//! `x / 2^n`, the dividend through the signed cast rule the arithmetic shift already carries
//! (docs/sdiv-pow2-arm.md, W3; the witness is `recovered.sdiv_pow2_sites`, from
//! `buildconfig::sdiv_pow2_from_evidence`). A target-informed emit choice, NOT Ghidra: the
//! reference decompiler prints the chain.
//!
//! Moved verbatim out of printc.rs (review R2, commit 5): the chain recognizer
//! ([`sdiv_pow2_shape`]) and the renderer ([`render`], the former `sdiv_pow2_render`; the only
//! textual change is `self.` → `pr.`).
//!
//! The arm answers ONE seam, `ValueSite::OpRoot`, SECOND after string-ops' strlen fold — the order
//! `render_op_inner` had inline; the `sdiv-pow2=div` choice gate lives here (an unwitnessed or
//! ungated site still reports its candidate to the survey through `report.sdiv_pow2_candidates`).
use crate::decompile::funcdata::Funcdata;
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::{render_const_typed, strip_copies, PrintC};
use crate::decompile::types::Datatype;
use crate::decompile::varnode::VarnodeId;

/// `sdiv-pow2`: is `op` an `INT_SRIGHT(a, n)` that is Watcom's signed power-of-two division?
/// Returns `(x, n, exact)`: `exact` when `a` is the lifted SBB chain
/// `INT_SUB(INT_ADD(x, INT_MULT(s, -2^n)), ZEXT(SLESS(LEFT(s, n-1), 0)))` with `s = SRIGHT(x, bits-1)`,
/// else the bare shift (its dividend proven non-negative, the chain folded) — both `x / 2^n`.
fn sdiv_pow2_shape(f: &Funcdata, op: OpId) -> Option<(VarnodeId, u32, bool)> {
    let o = f.op(op);
    // the exact chain roots at an arithmetic shift; the folded bare shift may have become a
    // logical one once its dividend was proven non-negative (`(uint1)x * 0x4d >> 8`, 0x2d520)
    if o.is_dead() || !matches!(o.code(), OpCode::IntSright | OpCode::IntRight) {
        return None;
    }
    let (a, k) = (o.input(0)?, o.input(1)?);
    if !f.vn(k).is_constant() {
        return None;
    }
    let n = f.vn(k).constant_value() as u32;
    let size = f.vn(a).size;
    if n == 0 || n >= 8 * size || size > 8 {
        return None;
    }
    let mask = if size >= 8 { u64::MAX } else { (1u64 << (8 * size)) - 1 };
    let konst = |v: VarnodeId, val: u64| f.vn(v).is_constant() && (f.vn(v).constant_value() & mask) == (val & mask);
    let def = |v: VarnodeId, code: OpCode| -> Option<OpId> {
        let d = f.vn(strip_copies(f, v)).def?;
        (!f.op(d).is_dead() && f.op(d).code() == code).then_some(d)
    };
    let exact = (|| -> Option<VarnodeId> {
        if o.code() != OpCode::IntSright {
            return None;
        }
        let sub = def(a, OpCode::IntSub)?;
        let (b, z) = (f.op(sub).input(0)?, f.op(sub).input(1)?);
        let zext = def(z, OpCode::IntZext)?;
        let sless = def(f.op(zext).input(0)?, OpCode::IntSless)?;
        if !konst(f.op(sless).input(1)?, 0) {
            return None;
        }
        let left = def(f.op(sless).input(0)?, OpCode::IntLeft)?;
        if !konst(f.op(left).input(1)?, (n - 1) as u64) {
            return None;
        }
        let s = strip_copies(f, f.op(left).input(0)?);
        let sr = def(s, OpCode::IntSright)?;
        if !konst(f.op(sr).input(1)?, (8 * size - 1) as u64) {
            return None;
        }
        let x = strip_copies(f, f.op(sr).input(0)?);
        let add = def(b, OpCode::IntAdd)?;
        let (p, q) = (f.op(add).input(0)?, f.op(add).input(1)?);
        let neg = (1u64 << n).wrapping_neg();
        let mult_of = |m: VarnodeId| -> bool {
            def(m, OpCode::IntMult).is_some_and(|md| {
                let mo = f.op(md);
                mo.input(0).is_some_and(|s2| strip_copies(f, s2) == s) && mo.input(1).is_some_and(|c| konst(c, neg))
            })
        };
        let x2 = strip_copies(f, if mult_of(q) { p } else if mult_of(p) { q } else { return None });
        // the sign shift reads the dividend itself, or the value it was arithmetically pre-shifted
        // from (`(v >> 0x10) / 8` takes its sign from `v`: the same sign) — 0x27298
        let same_sign = x2 == x
            || def(x2, OpCode::IntSright).is_some_and(|pd| f.op(pd).input(0).is_some_and(|v| strip_copies(f, v) == x));
        same_sign.then_some(x2)
    })();
    match exact {
        Some(x) => Some((x, n, true)),
        None => {
            // (b) a shift over a chain that did NOT match is never the bare shape (rendering it
            // `chain / 2^n` would apply the rounding correction twice — 0x4f5e0)
            let chainlike = def(a, OpCode::IntSub).is_some_and(|sd| f.op(sd).input(1).is_some_and(|z| def(z, OpCode::IntZext).is_some()));
            if chainlike {
                return None;
            }
            Some((a, n, false))
        }
    }
}

/// `sdiv-pow2`: report a candidate shift and, at a witnessed site under the `div` arm, render
/// `x / 2^n` — the dividend through the signed cast rule the arithmetic shift already carries.
pub(crate) fn render(pr: &mut PrintC<'_>, op: OpId) -> Option<(String, u8)> {
    let (x, n, exact) = sdiv_pow2_shape(pr.f, op)?;
    let pc = pr.f.op(op).seqnum.pc.offset;
    pr.report.sdiv_pow2_candidates.push((pc, n));
    if !pr.sdiv_pow2_div || !pr.recovered.sdiv_pow2_sites.contains(&pc) {
        return None;
    }
    let size = pr.f.vn(x).size;
    let _ = exact;
    // the dividend is SIGNED in the source (the template is the signed division): an operand
    // Ghidra typed unsigned prints with the `(int4)` cast, else Watcom compiles `x / 2` as SHR
    let (t, prec) = pr.render_var(x);
    let t = if prec < 13 { format!("({t})") } else { t };
    let l = if matches!(pr.type_of(x), Datatype::Int(_)) { t } else { format!("({}){t}", Datatype::Int(size).name()) };
    Some((format!("{l} / {}", render_const_typed(1u64 << n, size, true)), 13))
}
