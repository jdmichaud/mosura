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

/// A constant, possibly zero/sign-extended (Ghidra `Varnode::isConstantExtended`) — the
/// reciprocal multiplier.
fn is_constant_extended(f: &Funcdata, v: VarnodeId) -> Option<u128> {
    if f.vn(v).is_constant() {
        return Some(f.vn(v).constant_value() as u128);
    }
    let d = f.vn(v).def?;
    if matches!(f.op(d).code(), OpCode::IntZext | OpCode::IntSext) {
        let inner = f.op(d).input(0)?;
        if f.vn(inner).is_constant() {
            return Some(f.vn(inner).constant_value() as u128);
        }
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
}
