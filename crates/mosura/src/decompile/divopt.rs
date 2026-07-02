//! Division-by-constant recovery — a port of Ghidra's `RuleDivOpt` (`ruleaction.cc`). A
//! compiler turns `x / d` into a multiply by a "magic" constant followed by a shift; this
//! recovers the divisor `d` from the magic constant. Ghidra does the reverse with 128-bit
//! arithmetic (`uint8[2]`); Rust's native `u128` makes the port direct.
//!
//! This module provides the divisor computation (`calc_divisor`) plus `RuleDivOpt` for the
//! unsigned *add-correction* form real compilers emit:
//! `(mulhi + ((x - mulhi) >> e2)) >> e1` with `mulhi = high(x * M)`, which equals
//! `(x * (M + 2^h)) >> (h + e1 + e2)` (h = the high-half bit-width) and recovers to `x / d`.

use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::action::Rule;
use super::varnode::VarnodeId;

/// Recover the divisor of `x / d` from the magic constant. `magic` is the multiplier, `n`
/// is the total right-shift (`subpiece_bytes*8 + shift`), `xsize` is the operand bit-width.
/// Returns 0 if `magic`/`n` do not correspond to a clean division. Port of
/// `RuleDivOpt::calcDivisor` with `u128` standing in for Ghidra's `uint8[2]`.
pub fn calc_divisor(n: u32, magic: u128, xsize: u32) -> u64 {
    if n > 127 || xsize > 64 || magic <= 1 {
        return 0;
    }
    let y = magic - 1; // c - 1
    let power: u128 = 1u128 << n; // 2^n
    let mut q = power / y;
    let mut r = power % y;
    if q > u64::MAX as u128 {
        return 0; // q does not fit in 64 bits (q[1] != 0)
    }
    if y < q {
        return 0;
    }
    let mut diff: u64 = 0;
    if r >= q {
        q += 1;
        r = r.wrapping_sub(y).wrapping_add(q);
        if r >= q {
            return 0;
        }
        diff = q as u64;
    }
    let maxx: u64 = if xsize == 64 { u64::MAX } else { (1u64 << xsize) - 1 };
    diff = diff.wrapping_add((q as u64).wrapping_sub(r as u64));
    if diff == 0 {
        return q as u64;
    }
    let tmp = power / diff as u128;
    if tmp > u64::MAX as u128 {
        return q as u64; // tmp[1] != 0
    }
    if (tmp as u64) <= maxx {
        return 0;
    }
    q as u64
}

/// Constant value of `v`, if constant.
fn cval(f: &Funcdata, v: VarnodeId) -> Option<u64> {
    f.vn(v).is_constant().then(|| f.vn(v).constant_value())
}

/// Match `mulhi = SUBPIECE(INT_MULT(ext(x) | x, M), off)` — the high half of `x * M`.
/// Returns `(x, M, high_shift_bits, signed)` where `signed` means the dividend was
/// sign-extended (a signed division) rather than zero-extended.
fn match_mulhi(f: &Funcdata, v: VarnodeId) -> Option<(VarnodeId, u64, u32, bool)> {
    let sub = f.vn(v).def?;
    if f.op(sub).code() != OpCode::Subpiece {
        return None;
    }
    let off = cval(f, f.op(sub).input(1)?)?;
    let mult = f.vn(f.op(sub).input(0)?).def?;
    if f.op(mult).code() != OpCode::IntMult {
        return None;
    }
    let (m0, m1) = (f.op(mult).input(0)?, f.op(mult).input(1)?);
    for (cvn, xvn) in [(m1, m0), (m0, m1)] {
        if let Some(magic) = cval(f, cvn) {
            let (x, signed) = match f.vn(xvn).def {
                Some(d) if f.op(d).code() == OpCode::IntZext => (f.op(d).input(0)?, false),
                Some(d) if f.op(d).code() == OpCode::IntSext => (f.op(d).input(0)?, true),
                _ => (xvn, false),
            };
            return Some((x, magic, (off as u32) * 8, signed));
        }
    }
    None
}

/// Recover unsigned division by a constant from the add-correction magic-multiply form
/// (Ghidra's `RuleDivTermAdd` + `RuleDivOpt`, unsigned path), rewriting it to `x / d`.
pub struct RuleDivOpt;

impl Rule for RuleDivOpt {
    fn name(&self) -> &str {
        "divopt"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntRight, OpCode::IntSright, OpCode::Subpiece, OpCode::IntSub]
    }
    fn apply_op(&mut self, op: OpId, f: &mut Funcdata) -> u32 {
        match f.op(op).code() {
            // the multiply-by-reciprocal form ending in a shift or SUBPIECE (Ghidra `findForm`)
            OpCode::IntRight | OpCode::IntSright | OpCode::Subpiece => {
                let r = find_form_apply(op, f);
                if r != 0 || f.op(op).code() != OpCode::IntRight {
                    r
                } else {
                    try_unsigned(op, f) // else the add-correction form (RuleDivTermAdd + findForm)
                }
            }
            OpCode::IntSub => try_signed(op, f),
            _ => 0,
        }
    }
}

/// Ghidra `Varnode::isConstantExtended` (varnode.cc:799): a constant, possibly zero/sign-extended or
/// assembled by a `PIECE` of two constants, returned as its full (up to 128-bit) value — the
/// reciprocal multiplier. mosura carries Ghidra's `uint8[2]` as one `u128` (`val[0]` = low 64,
/// `val[1]` = high 64).
fn is_constant_extended(f: &Funcdata, v: VarnodeId) -> Option<u128> {
    if f.vn(v).is_constant() {
        return Some(f.vn(v).constant_value() as u128);
    }
    let size = f.vn(v).size;
    if size <= 8 || size > 16 {
        return None; // must be written; currently only up to 128-bit values
    }
    let d = f.vn(v).def?;
    let pack = |lo: u64, hi: u64| Some(((hi as u128) << 64) | lo as u128);
    match f.op(d).code() {
        OpCode::IntZext => {
            let vn0 = f.op(d).input(0)?;
            if f.vn(vn0).is_constant() {
                return pack(f.vn(vn0).constant_value(), 0);
            }
        }
        OpCode::IntSext => {
            let vn0 = f.op(d).input(0)?;
            if f.vn(vn0).is_constant() {
                let insize = f.vn(vn0).size;
                let mut val0 = f.vn(vn0).constant_value();
                if insize < 8 {
                    let sh = 64 - 8 * insize; // sign-extend within the 64-bit word
                    val0 = (((val0 << sh) as i64) >> sh) as u64;
                }
                let val1 = if (val0 >> 63) & 1 != 0 { u64::MAX } else { 0 };
                return pack(val0, val1);
            }
        }
        OpCode::Piece => {
            let vnlo = f.op(d).input(1)?; // Low part of piece
            let vnhi = f.op(d).input(0)?; // High part
            if f.vn(vnlo).is_constant() && f.vn(vnhi).is_constant() {
                let mut val0 = f.vn(vnlo).constant_value();
                let mut val1 = f.vn(vnhi).constant_value();
                let losize = f.vn(vnlo).size;
                if losize == 8 {
                    return pack(val0, val1);
                }
                val0 |= val1 << (8 * losize);
                val1 >>= 8 * (8 - losize);
                return pack(val0, val1);
            }
        }
        _ => {}
    }
    None
}

/// Ghidra `RuleDivOpt::findForm`: detect the multiply-by-reciprocal division rooted at `op` (a
/// shift or a SUBPIECE), returning `(x, n, magic, xsize, signed)` where the divisor is
/// `calc_divisor(n, magic, xsize)` and `signed` selects INT_SDIV vs INT_DIV.
fn find_form(f: &Funcdata, op: OpId) -> Option<(VarnodeId, u32, u128, u32, bool)> {
    let root = f.op(op).code();
    // optional leading shift contributes its amount to n
    let (mut n, mut cur, shift_signed): (i64, OpId, Option<bool>) = match root {
        OpCode::IntRight | OpCode::IntSright => {
            let vn = f.op(op).input(0)?;
            f.vn(vn).def?; // must be written
            let n = cval(f, f.op(op).input(1)?)? as i64;
            (n, f.vn(vn).def?, Some(root == OpCode::IntSright))
        }
        OpCode::Subpiece => (0, op, None), // SUBPIECE is the (required) root
        _ => return None,
    };
    // optional SUBPIECE keeping the high bits
    if f.op(cur).code() == OpCode::Subpiece {
        let c = cval(f, f.op(cur).input(1)?)? as i64;
        let invn = f.op(cur).input(0)?;
        f.vn(invn).def?;
        let out_size = f.vn(f.op(cur).output?).size as i64;
        if out_size + c != f.vn(invn).size as i64 {
            return None; // must keep the high bits
        }
        n += 8 * c;
        cur = f.vn(invn).def?;
    } else if shift_signed.is_none() {
        return None; // SUBPIECE root but no SUBPIECE found
    }
    if f.op(cur).code() != OpCode::IntMult {
        return None;
    }
    let (mi0, mi1) = (f.op(cur).input(0)?, f.op(cur).input(1)?);
    let (magic, xvn) = if let Some(m) = is_constant_extended(f, mi0) {
        (m, mi1)
    } else if let Some(m) = is_constant_extended(f, mi1) {
        (m, mi0)
    } else {
        return None;
    };
    let ext = f.vn(xvn).def?;
    let extopc = f.op(ext).code();
    let out_size = f.vn(f.op(op).output?).size;
    let (xsize, signed, resvn) = match extopc {
        // Signed magic division is `(mulhi >> e) - (x s>> 63)`: the high-multiply shift alone is
        // NOT `x s/ d` (it is off by one for negative x; the sign-bit subtraction supplies the
        // correction, which Ghidra folds in via `moveSignBitExtraction`). Until that is ported
        // (the full signed chain, RuleDivOpt's signed path), recovering the inner shift here would
        // emit an incorrect `INT_SDIV` and strand the `- (x s>> 63)` term — so defer the signed
        // form to the dedicated signed handler, which matches the whole INT_SUB shape.
        OpCode::IntSext => return None,
        OpCode::IntZext => {
            let inner = f.op(ext).input(0)?;
            let xsize = f.vn(inner).size * 8; // (approximates Ghidra's getNZMask for clean values)
            let resvn = if f.vn(xvn).size == out_size { xvn } else { inner };
            (xsize, false, resvn)
        }
        _ => (f.vn(xvn).size * 8, false, xvn), // no extension ⇒ treat as unsigned
    };
    // signed mismatch: the extension and shift signedness must agree, else the extension bits
    // are truncated and the form only holds when no extension bits survive
    let mismatch =
        (!signed && shift_signed == Some(true)) || (signed && shift_signed == Some(false));
    if mismatch && 8 * out_size as i64 - n != xsize as i64 {
        return None;
    }
    Some((resvn, n as u32, magic, xsize, signed))
}

/// Ghidra `RuleDivOpt::checkFormOverlap`: a SUBPIECE-rooted form is superseded when its output
/// feeds an INT_RIGHT/INT_SRIGHT that is itself a valid (containing) form — let that one win.
fn check_form_overlap(f: &Funcdata, op: OpId) -> bool {
    if f.op(op).code() != OpCode::Subpiece {
        return false;
    }
    let out = match f.op(op).output {
        Some(o) => o,
        None => return false,
    };
    for super_op in f.vn(out).descend.clone() {
        if !matches!(f.op(super_op).code(), OpCode::IntRight | OpCode::IntSright) {
            continue;
        }
        match f.op(super_op).input(1) {
            Some(c) if !f.vn(c).is_constant() => return true, // const may not have propagated yet
            None => return true,
            _ => {}
        }
        if find_form(f, super_op).is_some() {
            return true;
        }
    }
    false
}

/// Apply [`find_form`] (Ghidra `RuleDivOpt::applyOp`): rewrite the matched form to `x / d`.
fn find_form_apply(op: OpId, f: &mut Funcdata) -> u32 {
    let Some((x, n, magic, xsize, signed)) = find_form(f, op) else { return 0 };
    if check_form_overlap(f, op) || f.vn(x).is_free() {
        return 0;
    }
    let xsize = if signed { xsize.saturating_sub(1) } else { xsize }; // one less bit for the signbit
    let out_size = f.vn(f.op(op).output.unwrap()).size;
    // Ghidra inserts a width extension/truncation when `x` isn't already the output width; that
    // recovers more divisions but mosura's printer renders the inserted ops where Ghidra absorbs
    // them — pushing the output *further* from Ghidra's `--c`. So restrict to the matched width.
    if f.vn(x).size != out_size {
        return 0;
    }
    let d = calc_divisor(n, magic, xsize);
    if d == 0 {
        return 0;
    }
    let dc = f.new_const(out_size, d);
    f.op_set_opcode(op, if signed { OpCode::IntSdiv } else { OpCode::IntDiv });
    f.op_set_all_input(op, &[x, dc]);
    1
}

/// Unsigned add-correction form: `(mulhi + ((x - mulhi) >> e2)) >> e1` ⇒ `x / d`.
fn try_unsigned(op: OpId, f: &mut Funcdata) -> u32 {
    let Some(e1) = f.op(op).input(1).and_then(|v| cval(f, v)) else { return 0 };
    let Some(add) = f.op(op).input(0).and_then(|v| f.vn(v).def) else { return 0 };
    if f.op(add).code() != OpCode::IntAdd || f.op(add).num_inputs() != 2 {
        return 0;
    }
    let (a, b) = (f.op(add).input(0).unwrap(), f.op(add).input(1).unwrap());
    for (mulhi_v, inner_v) in [(a, b), (b, a)] {
        let Some((x, magic, h, signed)) = match_mulhi(f, mulhi_v) else { continue };
        if signed {
            continue;
        }
        let Some(inner) = f.vn(inner_v).def else { continue };
        if f.op(inner).code() != OpCode::IntRight {
            continue;
        }
        let Some(e2) = f.op(inner).input(1).and_then(|v| cval(f, v)) else { continue };
        let Some(sub) = f.op(inner).input(0).and_then(|v| f.vn(v).def) else { continue };
        if f.op(sub).code() != OpCode::IntSub
            || f.op(sub).input(0) != Some(x)
            || f.op(sub).input(1) != Some(mulhi_v)
        {
            continue;
        }
        let xsize = f.vn(x).size * 8;
        if h >= 128 || xsize == 0 {
            continue;
        }
        let d = calc_divisor(h + e1 as u32 + e2 as u32, magic as u128 + (1u128 << h), xsize);
        if d == 0 {
            continue;
        }
        let dc = f.new_const(f.vn(f.op(op).output.unwrap()).size, d);
        f.op_set_opcode(op, OpCode::IntDiv);
        f.op_set_all_input(op, &[x, dc]);
        return 1;
    }
    0
}

/// The signed high-multiply correction `mulhi + x`: when the signed reciprocal `M` has its top
/// bit set, the 64-bit-truncated magic stored in the code is `M - 2^64`, and the high half of
/// `sext(x)*that` is short by exactly `x` — so the compiler adds `x` back. The recovered divisor
/// uses the *stored* magic, identical to the non-add signed form; the `+ x` is a high-multiply
/// fixup, not a change of coefficient. Returns `(x, magic, h, signed)` when `v` is
/// `mulhi(sext(x)*magic) + x` with the same `x`.
fn add_correction(f: &Funcdata, v: VarnodeId) -> Option<(VarnodeId, u64, u32, bool)> {
    let add = f.vn(v).def?;
    if f.op(add).code() != OpCode::IntAdd || f.op(add).num_inputs() != 2 {
        return None;
    }
    let (p, q) = (f.op(add).input(0)?, f.op(add).input(1)?);
    for (w, other) in [(p, q), (q, p)] {
        if let Some((x, magic, h, signed)) = match_mulhi(f, w) {
            if other == x && signed {
                return Some((x, magic, h, signed));
            }
        }
    }
    None
}

/// Signed sign-subtraction form: `(mulhi_s >> e) - (x s>> (size-1))` ⇒ `x s/ d`, where `mulhi_s`
/// may be the bare high-multiply or carry the `+ x` high-multiply correction.
fn try_signed(op: OpId, f: &mut Funcdata) -> u32 {
    let (a, b) = match (f.op(op).input(0), f.op(op).input(1)) {
        (Some(a), Some(b)) => (a, b),
        _ => return 0,
    };
    // b = x s>> (size-1) — the sign-bit replication
    let Some(sgn) = f.vn(b).def else { return 0 };
    if f.op(sgn).code() != OpCode::IntSright {
        return 0;
    }
    let (Some(xb), Some(shamt)) = (f.op(sgn).input(0), f.op(sgn).input(1).and_then(|v| cval(f, v)))
    else {
        return 0;
    };
    // a = mulhi_s, optionally shifted right by e
    let (mulhi_v, e) = match f.vn(a).def {
        Some(d) if f.op(d).code() == OpCode::IntSright => {
            (f.op(d).input(0).unwrap(), f.op(d).input(1).and_then(|v| cval(f, v)).unwrap_or(99))
        }
        _ => (a, 0),
    };
    // mulhi_v is the bare high-multiply, or the signed high-multiply correction `mulhi + x`
    let Some((x, magic, h, signed)) = match_mulhi(f, mulhi_v).or_else(|| add_correction(f, mulhi_v))
    else {
        return 0;
    };
    let size = f.vn(x).size;
    if !signed || x != xb || shamt != (size * 8 - 1) as u64 || h >= 128 {
        return 0;
    }
    let d = calc_divisor(h + e as u32, magic as u128, size * 8 - 1); // signed: magic uncorrected, xsize-1
    if d == 0 {
        return 0;
    }
    let dc = f.new_const(f.vn(f.op(op).output.unwrap()).size, d);
    f.op_set_opcode(op, OpCode::IntSdiv);
    f.op_set_all_input(op, &[x, dc]);
    1
}

/// Recover modulo from `x - (x / d) * d` ⇒ `x % d` (Ghidra's `RuleModOpt`).
pub struct RuleModOpt;

impl Rule for RuleModOpt {
    fn name(&self) -> &str {
        "modopt"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSub]
    }
    fn apply_op(&mut self, op: OpId, f: &mut Funcdata) -> u32 {
        let (Some(x), Some(mul_v)) = (f.op(op).input(0), f.op(op).input(1)) else { return 0 };
        let Some(mul) = f.vn(mul_v).def else { return 0 };
        if f.op(mul).code() != OpCode::IntMult || f.op(mul).num_inputs() != 2 {
            return 0;
        }
        let (m0, m1) = (f.op(mul).input(0).unwrap(), f.op(mul).input(1).unwrap());
        for (dv, dc_v) in [(m0, m1), (m1, m0)] {
            let Some(d) = cval(f, dc_v) else { continue };
            let Some(div) = f.vn(dv).def else { continue };
            let code = f.op(div).code();
            if !matches!(code, OpCode::IntSdiv | OpCode::IntDiv) {
                continue;
            }
            // div = (x / d)
            if f.op(div).input(0) != Some(x) || f.op(div).input(1).and_then(|v| cval(f, v)) != Some(d)
            {
                continue;
            }
            let dc = f.new_const(f.vn(f.op(op).output.unwrap()).size, d);
            f.op_set_opcode(op, if code == OpCode::IntSdiv { OpCode::IntSrem } else { OpCode::IntRem });
            f.op_set_all_input(op, &[x, dc]);
            return 1;
        }
        0
    }
}

/// Depth-1 functional equivalence (Ghidra's `functionalEqualityLevel == 0`): the same
/// varnode, equal constants, or the same op applied to pairwise-equal operands. The sign
/// correction is computed once but may reach the add and the subtract as distinct varnodes.
fn equiv(f: &Funcdata, a: VarnodeId, b: VarnodeId) -> bool {
    if a == b {
        return true;
    }
    match (f.vn(a).def, f.vn(b).def) {
        (Some(da), Some(db)) => {
            f.op(da).code() == f.op(db).code()
                && f.op(da).num_inputs() == f.op(db).num_inputs()
                && (0..f.op(da).num_inputs()).all(|i| {
                    let (ia, ib) = (f.op(da).input(i).unwrap(), f.op(db).input(i).unwrap());
                    ia == ib
                        || (f.vn(ia).is_constant()
                            && f.vn(ib).is_constant()
                            && f.vn(ia).constant_value() == f.vn(ib).constant_value())
                })
        }
        _ => false,
    }
}

/// Recover signed modulo by a power of two: `((x + corr) & (2^k-1)) - corr` ⇒ `x % 2^k`,
/// where `corr` is the sign-rounding correction added before the mask and subtracted after
/// (Ghidra's `RuleSignMod2nOpt`). Ghidra matches the correction as `INT_ADD(.., MULT(corr,-1))`;
/// mosura's pipeline has already folded that to an `INT_SUB`, so we match that shape.
pub struct RuleSignMod2nOpt;

impl Rule for RuleSignMod2nOpt {
    fn name(&self) -> &str {
        "signmod2n"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSub]
    }
    fn apply_op(&mut self, op: OpId, f: &mut Funcdata) -> u32 {
        let (Some(m), Some(corr)) = (f.op(op).input(0), f.op(op).input(1)) else { return 0 };
        // the correction is a sign-bit extraction (a right shift), used on both sides
        let Some(cdef) = f.vn(corr).def else { return 0 };
        if !matches!(f.op(cdef).code(), OpCode::IntRight | OpCode::IntSright) {
            return 0;
        }
        // m = ZEXT(and) — the masked value widened back; peel the optional extension
        let and = match f.vn(m).def {
            Some(d) if f.op(d).code() == OpCode::IntZext => f.op(d).input(0).and_then(|v| f.vn(v).def),
            d => d,
        };
        let Some(and) = and else { return 0 };
        if f.op(and).code() != OpCode::IntAnd {
            return 0;
        }
        let (Some(and_in), Some(mask_v)) = (f.op(and).input(0), f.op(and).input(1)) else { return 0 };
        let Some(mask) = cval(f, mask_v) else { return 0 };
        if mask == 0 || (mask & (mask + 1)) != 0 {
            return 0; // mask+1 must be a power of two (the modulus)
        }
        // and_in = SUBPIECE(add, 0) (the masked value is computed truncated) or add directly
        let add = match f.vn(and_in).def {
            Some(d)
                if f.op(d).code() == OpCode::Subpiece
                    && f.op(d).input(1).and_then(|v| cval(f, v)) == Some(0) =>
            {
                f.op(d).input(0).and_then(|v| f.vn(v).def)
            }
            d => d,
        };
        let Some(add) = add else { return 0 };
        if f.op(add).code() != OpCode::IntAdd || f.op(add).num_inputs() != 2 {
            return 0;
        }
        // the addend equal to the subtracted correction is `corr`; the other is the dividend
        let (a0, a1) = (f.op(add).input(0).unwrap(), f.op(add).input(1).unwrap());
        let x = if equiv(f, a0, corr) {
            a1
        } else if equiv(f, a1, corr) {
            a0
        } else {
            return 0;
        };
        let dc = f.new_const(f.vn(x).size, mask + 1);
        f.op_set_opcode(op, OpCode::IntSrem);
        f.op_set_all_input(op, &[x, dc]);
        1
    }
}

/// True if `sh` computes the sign bit of `v` — `v >> (w-1)` (logical or arithmetic right shift).
fn is_sign_shift(f: &Funcdata, sh: VarnodeId, v: VarnodeId, size: u32) -> bool {
    let Some(d) = f.vn(sh).def else { return false };
    matches!(f.op(d).code(), OpCode::IntRight | OpCode::IntSright)
        && f.op(d).input(0).is_some_and(|x| equiv(f, x, v))
        && f.op(d).input(1).and_then(|c| cval(f, c)) == Some((8 * size - 1) as u64)
}

/// Recover signed `x % 2` from the *division* form `x - ((x + (x >> (w-1))) & ~1)` (Ghidra's
/// `RuleSignMod2nOpt2`, mod-2 special case). The rounded value `(x + signbit) & ~(2^k-1)` is
/// subtracted from `x`, leaving `x % 2^k`; for k=1 the correction is just the sign bit. (The
/// general `2^k` case routes the correction through a MULTIEQUAL and is left for later.)
pub struct RuleSignMod2nOpt2;

impl Rule for RuleSignMod2nOpt2 {
    fn name(&self) -> &str {
        "signmod2n2"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSub]
    }
    fn apply_op(&mut self, op: OpId, f: &mut Funcdata) -> u32 {
        let (Some(base), Some(and_out)) = (f.op(op).input(0), f.op(op).input(1)) else { return 0 };
        // and_out = INT_AND(adj, ~(2^k-1))
        let Some(and) = f.vn(and_out).def else { return 0 };
        if f.op(and).code() != OpCode::IntAnd {
            return 0;
        }
        let (Some(adj), Some(mask_v)) = (f.op(and).input(0), f.op(and).input(1)) else { return 0 };
        let Some(maskc) = cval(f, mask_v) else { return 0 };
        let size = f.vn(base).size;
        let full = if size >= 8 { u64::MAX } else { (1u64 << (8 * size)) - 1 };
        let npow = (!maskc).wrapping_add(1) & full; // the modulus 2^k
        if npow.count_ones() != 1 || npow != 2 {
            return 0; // only the mod-2 add form here
        }
        // adj = INT_ADD(V, V >> (w-1)) — the sign-bit correction
        let Some(adj_def) = f.vn(adj).def else { return 0 };
        if f.op(adj_def).code() != OpCode::IntAdd || f.op(adj_def).num_inputs() != 2 {
            return 0;
        }
        let (a0, a1) = (f.op(adj_def).input(0).unwrap(), f.op(adj_def).input(1).unwrap());
        let v = if is_sign_shift(f, a0, a1, size) {
            a1
        } else if is_sign_shift(f, a1, a0, size) {
            a0
        } else {
            return 0;
        };
        if !equiv(f, v, base) {
            return 0;
        }
        let dc = f.new_const(size, npow);
        f.op_set_opcode(op, OpCode::IntSrem);
        f.op_set_all_input(op, &[base, dc]);
        1
    }
}

/// Ghidra `RuleDivTermAdd::findSubshift` (ruleaction.cc:7910): match `sub(V,#c)` or `sub(V,#c)>>n`,
/// requiring the SUBPIECE to keep the high bytes. Returns `(subop, n + c*8, shiftopc)` where
/// `shiftopc` is `Some(shift)` if a right-shift was involved and `None` (Ghidra's `CPUI_MAX`) when
/// the root itself was the SUBPIECE.
fn find_subshift(f: &Funcdata, op: OpId) -> Option<(OpId, u64, Option<OpCode>)> {
    let root = f.op(op).code();
    let (subop, mut n, shiftopc): (OpId, u64, Option<OpCode>) = if root != OpCode::Subpiece {
        // Must be a right shift with the SUBPIECE as its written input.
        let vn = f.op(op).input(0)?;
        if !f.vn(vn).is_written() {
            return None;
        }
        let subop = f.vn(vn).def?;
        if f.op(subop).code() != OpCode::Subpiece {
            return None;
        }
        (subop, cval(f, f.op(op).input(1)?)?, Some(root))
    } else {
        (op, 0, None)
    };
    let c = cval(f, f.op(subop).input(1)?)?;
    let out_size = f.vn(f.op(subop).output?).size as u64;
    let in_size = f.vn(f.op(subop).input(0)?).size as u64;
    if out_size + c != in_size {
        return None; // SUBPIECE is not keeping the high part
    }
    n += 8 * c;
    Some((subop, n, shiftopc))
}

/// Ghidra `RuleDivTermAdd` (ruleaction.cc:7830; getOpList 7792): reassemble the trailing `+ V`
/// correction of an optimized division:
///   - `sub(ext(V)*c, b) >> d  +  V   =>   sub( (ext(V)*(c + 2^n))>>n, 0 )`   (n = d + b*8)
/// folding the add-term back into the multiplier (the left-shift signedness, if any, must match the
/// extension signedness) so [`RuleDivOpt`] can then recover `V / k`.
pub struct RuleDivTermAdd;

impl Rule for RuleDivTermAdd {
    fn name(&self) -> &str {
        "divtermadd"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece, OpCode::IntRight, OpCode::IntSright]
    }
    fn apply_op(&mut self, op: OpId, f: &mut Funcdata) -> u32 {
        let Some((subop, n, shiftopc)) = find_subshift(f, op) else {
            return 0;
        };
        if n > 127 {
            return 0; // Up to 128-bits
        }
        let Some(multvn) = f.op(subop).input(0) else { return 0 };
        if !f.vn(multvn).is_written() {
            return 0;
        }
        let Some(multop) = f.vn(multvn).def else { return 0 };
        if f.op(multop).code() != OpCode::IntMult {
            return 0;
        }
        let Some(mult_in1) = f.op(multop).input(1) else { return 0 };
        let Some(mult_const) = is_constant_extended(f, mult_in1) else { return 0 };

        let Some(extvn) = f.op(multop).input(0) else { return 0 };
        if !f.vn(extvn).is_written() {
            return 0;
        }
        let Some(extop) = f.vn(extvn).def else { return 0 };
        let opc = f.op(extop).code();
        let root = f.op(op).code();
        if opc == OpCode::IntZext {
            if root == OpCode::IntSright {
                return 0;
            }
        } else if opc == OpCode::IntSext && root == OpCode::IntRight {
            return 0;
        }

        // multConst += 2^n  (Ghidra's set_u128/leftshift128/add128, native u128; n <= 127 here).
        let mult_const = mult_const.wrapping_add(1u128 << (n as u32));
        let Some(x) = f.op(extop).input(0) else { return 0 };
        let extsize = f.vn(extvn).size;

        let Some(out) = f.op(op).output else { return 0 };
        let descs: Vec<OpId> = f.vn(out).descend.clone();
        for addop in descs {
            if f.op(addop).code() != OpCode::IntAdd {
                continue;
            }
            if f.op(addop).input(0) != Some(x) && f.op(addop).input(1) != Some(x) {
                continue;
            }
            // Construct the new constant, multiply, and shift.
            let new_const_vn = f.new_extended_constant(extsize, mult_const, op);
            let newmultop =
                f.new_op_before_sized(op, OpCode::IntMult, vec![extvn, new_const_vn], extsize);
            let newmultvn = f.op(newmultop).output.unwrap();
            let sopc = shiftopc.unwrap_or(OpCode::IntRight); // CPUI_MAX -> INT_RIGHT
            let nconst = f.new_const(4, n);
            let newshiftop = f.new_op_before_sized(op, sopc, vec![newmultvn, nconst], extsize);
            let newshiftvn = f.op(newshiftop).output.unwrap();
            // Rewrite the add into a truncating SUBPIECE of the reassembled shift.
            let zero = f.new_const(4, 0);
            f.op_set_opcode(addop, OpCode::Subpiece);
            f.op_set_input(addop, 0, newshiftvn);
            f.op_set_input(addop, 1, zero);
            return 1;
        }
        0
    }
}

/// Ghidra `RuleDivTermAdd2` (ruleaction.cc:7951): simplify a second optimized-division form. With
/// `W = sub(zext(V)*c, d)`:
///   - `W + ((V - W) >> 1)   =>   sub( (zext(V)*(c + 2^n))>>(n+1), 0 )`   (n = d*8)
/// all extensions and right-shifts unsigned, `n` equal to the SUBPIECE truncation.
pub struct RuleDivTermAdd2;

impl Rule for RuleDivTermAdd2 {
    fn name(&self) -> &str {
        "divtermadd2"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntRight]
    }
    fn apply_op(&mut self, op: OpId, f: &mut Funcdata) -> u32 {
        let Some(in1) = f.op(op).input(1) else { return 0 };
        if cval(f, in1) != Some(1) {
            return 0; // must be `>> 1`
        }
        let Some(in0) = f.op(op).input(0) else { return 0 };
        if !f.vn(in0).is_written() {
            return 0;
        }
        let subop = f.vn(in0).def.unwrap();
        if f.op(subop).code() != OpCode::IntAdd {
            return 0;
        }
        // One INT_ADD operand is `W * -1`; the other is x.
        let mut found: Option<(VarnodeId, VarnodeId)> = None; // (compvn = W*-1, x)
        for i in 0..2usize {
            let Some(compvn) = f.op(subop).input(i) else { continue };
            if !f.vn(compvn).is_written() {
                continue;
            }
            let compop = f.vn(compvn).def.unwrap();
            if f.op(compop).code() != OpCode::IntMult {
                continue;
            }
            let Some(invn) = f.op(compop).input(1) else { continue };
            if !f.vn(invn).is_constant() {
                continue;
            }
            if f.vn(invn).constant_value() == super::nzmask::calc_mask(f.vn(invn).size) {
                let x = f.op(subop).input(1 - i).unwrap();
                found = Some((compvn, x));
                break;
            }
        }
        let Some((compvn, x)) = found else { return 0 };

        // z = W = the value multiplied by -1.
        let z = f.op(f.vn(compvn).def.unwrap()).input(0).unwrap();
        if !f.vn(z).is_written() {
            return 0;
        }
        let subpieceop = f.vn(z).def.unwrap();
        if f.op(subpieceop).code() != OpCode::Subpiece {
            return 0;
        }
        let Some(suboff) = cval(f, f.op(subpieceop).input(1).unwrap()) else { return 0 };
        let n = suboff * 8;
        let in0size = f.vn(f.op(subpieceop).input(0).unwrap()).size as u64;
        let zsize = f.vn(z).size as u64;
        if n != 8 * (in0size - zsize) {
            return 0;
        }
        let multvn = f.op(subpieceop).input(0).unwrap();
        if !f.vn(multvn).is_written() {
            return 0;
        }
        let multop = f.vn(multvn).def.unwrap();
        if f.op(multop).code() != OpCode::IntMult {
            return 0;
        }
        let Some(mult_const) = is_constant_extended(f, f.op(multop).input(1).unwrap()) else {
            return 0;
        };
        let zextvn = f.op(multop).input(0).unwrap();
        if !f.vn(zextvn).is_written() {
            return 0;
        }
        let zextop = f.vn(zextvn).def.unwrap();
        if f.op(zextop).code() != OpCode::IntZext {
            return 0;
        }
        if f.op(zextop).input(0) != Some(x) {
            return 0;
        }

        let zextsize = f.vn(zextvn).size;
        let Some(out) = f.op(op).output else { return 0 };
        let descs: Vec<OpId> = f.vn(out).descend.clone();
        for addop in descs {
            if f.op(addop).code() != OpCode::IntAdd {
                continue;
            }
            if f.op(addop).input(0) != Some(z) && f.op(addop).input(1) != Some(z) {
                continue;
            }
            // multConst += 2^n
            let new_const = mult_const.wrapping_add(1u128.checked_shl(n as u32).unwrap_or(0));
            let new_const_vn = f.new_extended_constant(zextsize, new_const, op);
            let newmultop =
                f.new_op_before_sized(op, OpCode::IntMult, vec![zextvn, new_const_vn], zextsize);
            let newmultvn = f.op(newmultop).output.unwrap();
            let nconst = f.new_const(4, n + 1);
            let newshiftop =
                f.new_op_before_sized(op, OpCode::IntRight, vec![newmultvn, nconst], zextsize);
            let newshiftvn = f.op(newshiftop).output.unwrap();
            let zero = f.new_const(4, 0);
            f.op_set_opcode(addop, OpCode::Subpiece);
            f.op_set_input(addop, 0, newshiftvn);
            f.op_set_input(addop, 1, zero);
            return 1;
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_known_unsigned_divisors_32bit() {
        // `x / 3`  (u32): x * 0xAAAAAAAB >> 33  → n = 4*8 + 1 = 33
        assert_eq!(calc_divisor(33, 0xAAAAAAAB, 32), 3);
        // `x / 5`  (u32): x * 0xCCCCCCCD >> 34  → n = 4*8 + 2 = 34
        assert_eq!(calc_divisor(34, 0xCCCCCCCD, 32), 5);
        // `x / 7`  (u32): x * 0x24924925 >> 34, but with the +x correction Ghidra handles
        //   the standard form `x / 9`: x * 0x38E38E39 >> 33 → n = 33
        assert_eq!(calc_divisor(33, 0x38E38E39, 32), 9);
    }

    #[test]
    fn recovers_known_unsigned_divisors_64bit() {
        // `x / 3`  (u64): x * 0xAAAAAAAAAAAAAAAB >> 65 → n = 8*8 + 1 = 65
        assert_eq!(calc_divisor(65, 0xAAAAAAAAAAAAAAAB, 64), 3);
        // `x / 5`  (u64): x * 0xCCCCCCCCCCCCCCCD >> 66 → n = 66
        assert_eq!(calc_divisor(66, 0xCCCCCCCCCCCCCCCD, 64), 5);
    }

    #[test]
    fn rejects_non_divisor_magic() {
        assert_eq!(calc_divisor(33, 0x12345678, 32), 0);
        assert_eq!(calc_divisor(0, 2, 32), 0);
    }

    #[test]
    fn recovers_unsigned_add_correction_division() {
        use crate::decompile::action::{Action, ActionPool};
        use crate::decompile::space::{Address, SpaceManager};
        use crate::decompile::{BlockBasic, Funcdata, SeqNum};
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let x = f.new_input(8, Address::new(reg, 0x38));
        let ze = f.new_op(OpCode::IntZext, seq, vec![x]);
        let zeo = f.new_output_unique(ze, 16);
        let magic = f.new_const(16, 0x948b0fcd6e9e0653);
        let mu = f.new_op(OpCode::IntMult, seq, vec![zeo, magic]);
        let muo = f.new_output_unique(mu, 16);
        let off = f.new_const(4, 8);
        let sp = f.new_op(OpCode::Subpiece, seq, vec![muo, off]);
        let mulhi = f.new_output_unique(sp, 8);
        let sb = f.new_op(OpCode::IntSub, seq, vec![x, mulhi]);
        let sbo = f.new_output_unique(sb, 8);
        let one = f.new_const(8, 1);
        let inr = f.new_op(OpCode::IntRight, seq, vec![sbo, one]);
        let inro = f.new_output_unique(inr, 8);
        let ad = f.new_op(OpCode::IntAdd, seq, vec![mulhi, inro]);
        let ado = f.new_output_unique(ad, 8);
        let six = f.new_const(8, 6);
        let op = f.new_op(OpCode::IntRight, seq, vec![ado, six]);
        f.new_output(op, 8, Address::new(reg, 0));
        f.set_blocks(vec![BlockBasic { ops: vec![ze, mu, sp, sb, inr, ad, op], ..Default::default() }]);

        let mut pool = ActionPool::new("p").with(RuleDivOpt);
        pool.apply(&mut f);
        // (mulhi + ((x - mulhi) >> 1)) >> 6  with magic 0x948b...  =>  x / 0x51
        assert_eq!(f.op(op).code(), OpCode::IntDiv);
        assert_eq!(f.op(op).input(0), Some(x));
        let dc = f.op(op).input(1).unwrap();
        assert!(f.vn(dc).is_constant() && f.vn(dc).constant_value() == 0x51);
    }

    #[test]
    fn recovers_signed_mod_power_of_two() {
        use crate::decompile::action::{Action, ActionPool};
        use crate::decompile::space::{Address, SpaceManager};
        use crate::decompile::{BlockBasic, Funcdata, SeqNum};
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let x = f.new_input(8, Address::new(reg, 0x38));
        // corr = x >>u 63  (the sign bit as 0/1)
        let sh = f.new_const(8, 0x3f);
        let corr = f.new_op(OpCode::IntRight, seq, vec![x, sh]);
        let corro = f.new_output_unique(corr, 8);
        // ((x + corr) & 1) - corr   ⇒   x % 2
        let add = f.new_op(OpCode::IntAdd, seq, vec![x, corro]);
        let addo = f.new_output_unique(add, 8);
        let off0 = f.new_const(4, 0);
        let subp = f.new_op(OpCode::Subpiece, seq, vec![addo, off0]);
        let subpo = f.new_output_unique(subp, 4);
        let mask = f.new_const(4, 1);
        let and = f.new_op(OpCode::IntAnd, seq, vec![subpo, mask]);
        let ando = f.new_output_unique(and, 4);
        let ze = f.new_op(OpCode::IntZext, seq, vec![ando]);
        let zeo = f.new_output_unique(ze, 8);
        let op = f.new_op(OpCode::IntSub, seq, vec![zeo, corro]);
        f.new_output(op, 8, Address::new(reg, 0));
        f.set_blocks(vec![BlockBasic { ops: vec![corr, add, subp, and, ze, op], ..Default::default() }]);

        ActionPool::new("p").with(RuleSignMod2nOpt).apply(&mut f);
        assert_eq!(f.op(op).code(), OpCode::IntSrem);
        assert_eq!(f.op(op).input(0), Some(x));
        let dc = f.op(op).input(1).unwrap();
        assert!(f.vn(dc).is_constant() && f.vn(dc).constant_value() == 2);
    }

    #[test]
    fn recovers_signed_mod_2_division_form() {
        use crate::decompile::action::{Action, ActionPool};
        use crate::decompile::space::{Address, SpaceManager};
        use crate::decompile::{BlockBasic, Funcdata, SeqNum};
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let x = f.new_input(8, Address::new(reg, 0x38));
        // x - ((x + (x >>u 63)) & -2)  ⇒  x % 2  (the division form)
        let sh = f.new_const(8, 0x3f);
        let corr = f.new_op(OpCode::IntRight, seq, vec![x, sh]);
        let corro = f.new_output_unique(corr, 8);
        let add = f.new_op(OpCode::IntAdd, seq, vec![corro, x]);
        let addo = f.new_output_unique(add, 8);
        let mask = f.new_const(8, (-2i64) as u64);
        let and = f.new_op(OpCode::IntAnd, seq, vec![addo, mask]);
        let ando = f.new_output_unique(and, 8);
        let op = f.new_op(OpCode::IntSub, seq, vec![x, ando]);
        f.new_output(op, 8, Address::new(reg, 0));
        f.set_blocks(vec![BlockBasic { ops: vec![corr, add, and, op], ..Default::default() }]);

        ActionPool::new("p").with(RuleSignMod2nOpt2).apply(&mut f);
        assert_eq!(f.op(op).code(), OpCode::IntSrem);
        assert_eq!(f.op(op).input(0), Some(x));
        let dc = f.op(op).input(1).unwrap();
        assert!(f.vn(dc).is_constant() && f.vn(dc).constant_value() == 2);
    }

    #[test]
    fn recovers_simple_unsigned_division() {
        use crate::decompile::action::{Action, ActionPool};
        use crate::decompile::space::{Address, SpaceManager};
        use crate::decompile::{BlockBasic, Funcdata, SeqNum};
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let x = f.new_input(4, Address::new(reg, 0x38));
        // (zext(x) * 0xAAAAAAAB) >> 33  ⇒  x / 3  (the simple unsigned form, no add-correction)
        let ze = f.new_op(OpCode::IntZext, seq, vec![x]);
        let zeo = f.new_output_unique(ze, 8);
        let magic = f.new_const(8, 0xAAAAAAAB);
        let mu = f.new_op(OpCode::IntMult, seq, vec![zeo, magic]);
        let muo = f.new_output_unique(mu, 8);
        let off = f.new_const(4, 4); // SUBPIECE byte offset 4 ⇒ >> 32
        let sp = f.new_op(OpCode::Subpiece, seq, vec![muo, off]);
        let spo = f.new_output_unique(sp, 4);
        let sh = f.new_const(4, 1); // >> 1  ⇒  total n = 33
        let op = f.new_op(OpCode::IntRight, seq, vec![spo, sh]);
        f.new_output(op, 4, Address::new(reg, 0));
        f.set_blocks(vec![BlockBasic { ops: vec![ze, mu, sp, op], ..Default::default() }]);

        ActionPool::new("p").with(RuleDivOpt).apply(&mut f);
        assert_eq!(f.op(op).code(), OpCode::IntDiv);
        assert_eq!(f.op(op).input(0), Some(x));
        let dc = f.op(op).input(1).unwrap();
        assert!(f.vn(dc).is_constant() && f.vn(dc).constant_value() == 3);
    }

    #[test]
    fn divtermadd_reassembles_add_correction() {
        use crate::decompile::space::{Address, SpaceManager};
        use crate::decompile::{BlockBasic, Funcdata, SeqNum};
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // root = SUBPIECE(zext(V)*magic, 8)  [keeps the high 8 bytes; n = 8*8 = 64]; V is 8 bytes.
        let v = f.new_input(8, Address::new(reg, 0x38));
        let ze = f.new_op(OpCode::IntZext, seq, vec![v]);
        let zeo = f.new_output_unique(ze, 16);
        let magic = f.new_const(16, 0xAAAAAAAB);
        let mu = f.new_op(OpCode::IntMult, seq, vec![zeo, magic]);
        let muo = f.new_output_unique(mu, 16);
        let off = f.new_const(4, 8);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![muo, off]);
        let subo = f.new_output_unique(sub, 8);
        // add-correction term:  sub_out + V
        let add = f.new_op(OpCode::IntAdd, seq, vec![subo, v]);
        f.new_output(add, 8, Address::new(reg, 0));
        f.set_blocks(vec![BlockBasic { ops: vec![ze, mu, sub, add], ..Default::default() }]);

        assert_eq!(RuleDivTermAdd.apply_op(sub, &mut f), 1);
        // add rewritten to SUBPIECE( (zext(V)*(magic+2^64)) >> 64, 0 ).
        assert_eq!(f.op(add).code(), OpCode::Subpiece);
        let z = f.op(add).input(1).unwrap();
        assert!(f.vn(z).is_constant() && f.vn(z).constant_value() == 0);
        let shift = f.vn(f.op(add).input(0).unwrap()).def.unwrap();
        assert_eq!(f.op(shift).code(), OpCode::IntRight);
        let shamt = f.op(shift).input(1).unwrap();
        assert!(f.vn(shamt).is_constant() && f.vn(shamt).constant_value() == 64);
        let newmult = f.vn(f.op(shift).input(0).unwrap()).def.unwrap();
        assert_eq!(f.op(newmult).code(), OpCode::IntMult);
        assert_eq!(f.op(newmult).input(0), Some(zeo)); // reuses zext(V)
        // The new 128-bit constant magic+2^64 is materialized as PIECE(hi=1, lo=magic).
        let nc = f.vn(f.op(newmult).input(1).unwrap()).def.unwrap();
        assert_eq!(f.op(nc).code(), OpCode::Piece);
        let hi = f.op(nc).input(0).unwrap();
        let lo = f.op(nc).input(1).unwrap();
        assert!(f.vn(hi).is_constant() && f.vn(hi).constant_value() == 1);
        assert!(f.vn(lo).is_constant() && f.vn(lo).constant_value() == 0xAAAAAAAB);
    }

    #[test]
    fn divtermadd2_reassembles_shift_correction() {
        use crate::decompile::space::{Address, SpaceManager};
        use crate::decompile::{BlockBasic, Funcdata, SeqNum};
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // W = SUBPIECE(zext(V)*magic, 8)  (V 8 bytes, mult 16 bytes; n = 8*(16-8) = 64).
        let v = f.new_input(8, Address::new(reg, 0x38));
        let ze = f.new_op(OpCode::IntZext, seq, vec![v]);
        let zeo = f.new_output_unique(ze, 16);
        let magic = f.new_const(16, 0xAAAAAAAB);
        let mu = f.new_op(OpCode::IntMult, seq, vec![zeo, magic]);
        let muo = f.new_output_unique(mu, 16);
        let off = f.new_const(4, 8);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![muo, off]);
        let w = f.new_output_unique(sub, 8);
        // V - W  =  V + (W * -1)
        let negone = f.new_const(8, 0xFFFF_FFFF_FFFF_FFFF);
        let neg = f.new_op(OpCode::IntMult, seq, vec![w, negone]);
        let nego = f.new_output_unique(neg, 8);
        let diff = f.new_op(OpCode::IntAdd, seq, vec![v, nego]);
        let diffo = f.new_output_unique(diff, 8);
        // op = (V - W) >> 1   [rule root]
        let one = f.new_const(8, 1);
        let op = f.new_op(OpCode::IntRight, seq, vec![diffo, one]);
        let opo = f.new_output_unique(op, 8);
        // final:  W + ((V - W) >> 1)
        let fin = f.new_op(OpCode::IntAdd, seq, vec![w, opo]);
        f.new_output(fin, 8, Address::new(reg, 0));
        f.set_blocks(vec![BlockBasic {
            ops: vec![ze, mu, sub, neg, diff, op, fin],
            ..Default::default()
        }]);

        assert_eq!(RuleDivTermAdd2.apply_op(op, &mut f), 1);
        // fin rewritten to SUBPIECE( (zext(V)*(magic+2^64)) >> 65, 0 ).
        assert_eq!(f.op(fin).code(), OpCode::Subpiece);
        let z0 = f.op(fin).input(1).unwrap();
        assert!(f.vn(z0).is_constant() && f.vn(z0).constant_value() == 0);
        let shift = f.vn(f.op(fin).input(0).unwrap()).def.unwrap();
        assert_eq!(f.op(shift).code(), OpCode::IntRight);
        let shamt = f.op(shift).input(1).unwrap();
        assert!(f.vn(shamt).is_constant() && f.vn(shamt).constant_value() == 65); // n + 1
        let newmult = f.vn(f.op(shift).input(0).unwrap()).def.unwrap();
        assert_eq!(f.op(newmult).code(), OpCode::IntMult);
        assert_eq!(f.op(newmult).input(0), Some(zeo));
    }
}
