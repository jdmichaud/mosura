//! Recovery of division/remainder by a constant from the compiler's magic-number
//! multiply, a port of Ghidra's `RuleDivOpt` family (`ruleaction.cc`). Optimizing
//! compilers turn `x / C` into `(x * magic) >> n` (plus correction terms); this
//! reverses it back to `x / C`.
//!
//! The arithmetic core, `calc_divisor`, is a faithful port of
//! `RuleDivOpt::calcDivisor`: it computes `2^n / (y-1)` and *validates* that the
//! magic-multiply is exactly division for every `x` in range — returning 0 otherwise.
//! That self-validation is what makes the recovery sound: we only rewrite to a
//! division when the optimization provably holds. Ghidra's 128-bit helpers
//! (`subtract128`/`add128` are modular) map directly onto Rust `u128`.

use super::cfg::Funcdata;
use super::ssa::{Def, Ssa};
use crate::sleigh::pcode::{opcode_name, PArg};

/// A recovered division: `x / divisor`. `x` is the SSA def of the numerand, ready to
/// feed the expression builder; `divisor` is the recovered constant; `consumed` are the
/// intermediate ops (multiply, mulhi, add-back, shifts) the division replaces — they
/// must not be separately named or emitted.
pub struct DivForm {
    pub x: Def,
    pub divisor: u64,
    pub consumed: Vec<usize>,
}

/// The set of all ops consumed by a recovered division anywhere in the function. Such
/// ops produce no output (the division renders in their place), so the explicit-temp
/// pass must not name them.
pub fn consumed_ops(fd: &Funcdata, ssa: &Ssa) -> std::collections::HashSet<usize> {
    let mut set = std::collections::HashSet::new();
    for i in 0..fd.ops.len() {
        if matches!(op_name(fd, i), "INT_RIGHT" | "INT_SRIGHT") {
            if let Some(df) = recover_div(fd, ssa, i) {
                set.extend(df.consumed);
            }
        }
    }
    set
}

fn op_name(fd: &Funcdata, i: usize) -> &'static str {
    opcode_name(fd.ops[i].op.opcode)
}

/// The constant value of op `i`'s input `pos`, if it is a constant.
fn const_in(fd: &Funcdata, i: usize, pos: usize) -> Option<u128> {
    match fd.ops[i].op.ins.get(pos) {
        Some(PArg::Var(v)) if v.is_const() => Some(v.offset as u128),
        _ => None,
    }
}

/// Follow `COPY` ops to the first non-copy reaching def of `d`.
fn fold_copy(fd: &Funcdata, ssa: &Ssa, mut d: Def) -> Def {
    while let Def::Op(i) = d {
        if op_name(fd, i) == "COPY" {
            match ssa.uses.get(&(i, 0)) {
                Some(&nd) => d = nd,
                None => break,
            }
        } else {
            break;
        }
    }
    d
}

/// The reaching def of op `i`'s input `pos`, with `COPY`s folded away.
fn operand(fd: &Funcdata, ssa: &Ssa, i: usize, pos: usize) -> Option<Def> {
    ssa.uses.get(&(i, pos)).map(|&d| fold_copy(fd, ssa, d))
}

/// Evaluate a small constant expression (a literal, a `COPY` of one, or an `INT_AND`
/// of two constants — x86 masks shift counts with `& 0x3f`). Used for shift amounts.
fn eval_const(fd: &Funcdata, ssa: &Ssa, d: Def) -> Option<u128> {
    match d {
        Def::Op(i) => match op_name(fd, i) {
            "COPY" => operand(fd, ssa, i, 0).and_then(|nd| eval_const(fd, ssa, nd)),
            "INT_AND" => {
                let a = const_in(fd, i, 0)?;
                let b = const_in(fd, i, 1)?;
                Some(a & b)
            }
            _ => None,
        },
        _ => None,
    }
}

/// A shift/operand amount that may be a direct constant input or a computed constant
/// (e.g. the x86 `count & 0x3f` masking).
fn const_amount(fd: &Funcdata, ssa: &Ssa, op: usize, pos: usize) -> Option<u128> {
    if let Some(c) = const_in(fd, op, pos) {
        return Some(c);
    }
    eval_const(fd, ssa, ssa.uses.get(&(op, pos)).copied()?)
}

/// Strip `COPY`/`INT_ZEXT`/`INT_SEXT` from `d`, returning the underlying def. If the
/// chain bottoms out at a constant, return it (this is the magic multiplier); also
/// report whether a sign extension was crossed.
fn ext_base(fd: &Funcdata, ssa: &Ssa, mut d: Def) -> (Def, Option<u128>, bool) {
    let mut sext = false;
    while let Def::Op(i) = d {
        let n = op_name(fd, i);
        if n == "COPY" || n == "INT_ZEXT" || n == "INT_SEXT" {
            if n == "INT_SEXT" {
                sext = true;
            }
            if let Some(c) = const_in(fd, i, 0) {
                return (d, Some(c), sext);
            }
            match ssa.uses.get(&(i, 0)) {
                Some(&nd) => d = nd,
                None => return (d, None, sext),
            }
        } else {
            return (d, None, sext);
        }
    }
    (d, None, sext)
}

/// Recognize the compiler's magic-number division at the op `root` and recover the
/// divisor. Handles the 64-bit "add-back" form that gcc/clang emit and that Ghidra
/// recovers via `RuleDivTermAdd2` + `RuleDivOpt`:
///
/// ```text
///   (W + ((X - W) >> 1)) >> s     where  W = SUBPIECE(zext(X) * magic, hb)
/// ```
///
/// By the `RuleDivTermAdd2` identity this equals `(X*(magic + 2^n)) >> (n+1+s)` with
/// `n = 8*hb`, so the divisor is `calc_divisor(n+1+s, magic+2^n, xsize)`. Returns
/// `None` if the shape doesn't match or the magic-multiply isn't a valid division.
pub fn recover_div(fd: &Funcdata, ssa: &Ssa, root: usize) -> Option<DivForm> {
    // root: (.) >> s  — the outer right shift
    if !matches!(op_name(fd, root), "INT_RIGHT" | "INT_SRIGHT") {
        return None;
    }
    let s = const_amount(fd, ssa, root, 1)?;
    let add = operand(fd, ssa, root, 0).and_then(|d| as_named(fd, d, "INT_ADD"))?;

    // INT_ADD(W, (X - W) >> 1) — try both operand orders
    for (wpos, spos) in [(0usize, 1usize), (1, 0)] {
        let Some(w) = operand(fd, ssa, add, wpos) else { continue };
        let Some(shr) = operand(fd, ssa, add, spos).and_then(|d| as_named(fd, d, "INT_RIGHT")) else { continue };
        // inner shift must be exactly >> 1 (unsigned)
        if const_amount(fd, ssa, shr, 1) != Some(1) {
            continue;
        }
        let Some(sub) = operand(fd, ssa, shr, 0).and_then(|d| as_named(fd, d, "INT_SUB")) else { continue };
        // INT_SUB(X, W) — the subtracted value must be the same W
        if operand(fd, ssa, sub, 1) != Some(w) {
            continue;
        }
        // W = SUBPIECE(prod, hb) — the high half of the 128-bit product
        let Def::Op(wop) = w else { continue };
        if op_name(fd, wop) != "SUBPIECE" {
            continue;
        }
        let hb = const_in(fd, wop, 1)?; // truncation in bytes
        let prod = operand(fd, ssa, wop, 0).and_then(|d| as_named(fd, d, "INT_MULT"))?;

        // INT_MULT(ext(X), magic): one operand strips to a constant, the other to X
        let (a, b) = (operand(fd, ssa, prod, 0)?, operand(fd, ssa, prod, 1)?);
        let (ba, ma, sa) = ext_base(fd, ssa, a);
        let (bb, mb, sb) = ext_base(fd, ssa, b);
        let (magic, x_mul, sext_mul) = match (ma, mb) {
            (Some(m), None) => (m, bb, sb),
            (None, Some(m)) => (m, ba, sa),
            _ => continue,
        };
        // the numerand of the multiply and of the subtraction must be the same value
        let (x_sub, _, sext_sub) = ext_base(fd, ssa, operand(fd, ssa, sub, 0)?);
        if x_sub != x_mul {
            continue;
        }

        let n = 8 * (hb as u64); // truncation in bits
        let y = magic.wrapping_add(1u128 << n); // magic + 2^n
        let total_shift = n + 1 + (s as u64);
        let x_bits = fd.ops[sub].op.ins.first().and_then(PArg::as_var).map_or(64, |v| 8 * v.size);
        let signed = sext_mul || sext_sub;
        let xsize = if signed { x_bits.saturating_sub(1) } else { x_bits };

        let divisor = calc_divisor(total_shift, y, xsize);
        if divisor == 0 {
            continue;
        }
        // the numerand to print is the value the subtraction reads
        let x = ssa.uses.get(&(sub, 0)).copied()?;
        return Some(DivForm { x, divisor, consumed: vec![root, add, shr, sub, wop, prod] });
    }
    None
}

/// Map a `Def` to its op index iff that op has the given name.
fn as_named(fd: &Funcdata, d: Def, name: &str) -> Option<usize> {
    match d {
        Def::Op(i) if op_name(fd, i) == name => Some(i),
        _ => None,
    }
}

/// Recover the divisor of an optimized division: given the multiplicative coefficient
/// `y` (up to 128 bits) and the total right-shift `n`, return `2^n / (y-1)`, or 0 if
/// the magic-multiply is not a valid division for all `x` of `xsize` bits.
/// Port of `RuleDivOpt::calcDivisor` (ruleaction.cc:8139).
pub fn calc_divisor(n: u64, y: u128, xsize: u32) -> u64 {
    if n > 127 || xsize > 64 {
        return 0; // not enough precision
    }
    if y <= 1 {
        return 0; // boundary cases y <= 1 are the wrong form
    }
    let y = y - 1; // y = y - 1
    let power: u128 = 1u128 << n; // power = 2^n
    let mut q = power / y;
    let mut r = power % y;
    if (q >> 64) != 0 {
        return 0; // result is bigger than 64 bits
    }
    if y < q {
        return 0;
    }
    let mut diff: u64 = 0;
    if r >= q {
        // y may be 1 too big, giving a q that is 1 smaller than the correct value;
        // adjust to the bigger q and the remainder for the smaller y. (subtract128 and
        // add128 are modular — the wrapping is load-bearing here.)
        q = q.wrapping_add(1);
        r = r.wrapping_sub(y);
        r = r.wrapping_add(q);
        if r >= q {
            return 0;
        }
        diff = q as u64; // using a y that is off by one adds extra error
    }
    // The optimization holds if the maximum value of x times (q - r) is < 2^n.
    let maxx: u64 = if xsize == 64 { 0 } else { 1u64 << xsize };
    let maxx = maxx.wrapping_sub(1); // maximum possible x value
    diff = diff.wrapping_add((q as u64).wrapping_sub(r as u64)); // diff += q - r
    let denom = diff as u128;
    if denom == 0 {
        return 0; // Ghidra throws on divide-by-0 here; treat as no match
    }
    let tmp = power / denom;
    if (tmp >> 64) != 0 {
        return q as u64; // tmp is bigger than 2^64 > maxx
    }
    if (tmp as u64) <= maxx {
        return 0;
    }
    q as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_textbook_unsigned_divisors() {
        // GCC magic-number sequences for 32-bit unsigned division: (x * magic) >> n,
        // hand-verified against the 2^n/(y-1) recovery.
        assert_eq!(calc_divisor(33, 0xAAAAAAAB, 32), 3); // ÷3
        assert_eq!(calc_divisor(34, 0xCCCCCCCD, 32), 5); // ÷5
    }

    #[test]
    fn recovers_divopt_addback_form() {
        // The 64-bit add-back form `(W + ((X-W)>>1)) >> s` with W = mulhi(X, magic)
        // normalizes (RuleDivTermAdd2) to `(X * (magic + 2^64)) >> (64 + 1 + s)`; here
        // s = 6 so n = 71. Magic constants and divisors are from the divopt datatest as
        // decompiled by Ghidra — the ground truth for this recovery.
        for (magic, divisor) in [
            (0x948b0fcd6e9e0653u128, 0x51u64),
            (0x702e05c0b81702e1, 0x59),
            (0x6816816816816817, 0x5b),
        ] {
            assert_eq!(calc_divisor(71, magic + (1u128 << 64), 64), divisor, "magic {magic:#x}");
        }
    }

    #[test]
    fn rejects_non_divisions() {
        assert_eq!(calc_divisor(0, 2, 32), 0); // no shift
        assert_eq!(calc_divisor(33, 1, 32), 0); // y <= 1
        assert_eq!(calc_divisor(200, 0xAAAAAAAB, 32), 0); // n out of range
        assert_eq!(calc_divisor(33, 0xAAAAAAAB, 70), 0); // xsize out of range
    }
}
