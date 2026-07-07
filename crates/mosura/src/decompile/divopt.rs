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

/// Recover division by a constant (Ghidra's `RuleDivOpt`, ruleaction.cc): recognize the
/// multiply-by-reciprocal form the compiler emits and rewrite it to `x / d` (unsigned) or `x s/ d`
/// (signed). The add-correction and shift-correction terms are reassembled upstream by
/// [`RuleDivTermAdd`]/[`RuleDivTermAdd2`] before this rule's [`find_form`] recognizes the result.
pub struct RuleDivOpt;

impl Rule for RuleDivOpt {
    fn name(&self) -> &str {
        "divopt"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece, OpCode::IntRight, OpCode::IntSright]
    }
    fn apply_op(&mut self, op: OpId, f: &mut Funcdata) -> u32 {
        find_form_apply(op, f)
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

/// Ghidra `RuleDivOpt::findForm` (ruleaction.cc:8051): detect the multiply-by-reciprocal division
/// rooted at `op` (a shift or a SUBPIECE). Returns `(resvn, n, y, xsize, extopc)` — the numerand
/// varnode, total truncation `n`, multiplicative constant `y`, numerand bit-width `xsize`, and the
/// extension opcode (`INT_ZEXT` for unsigned, `INT_SEXT` for signed; a numerand with no explicit
/// extension is reported as `INT_ZEXT`). The divisor is `calc_divisor(n, y, xsize)`.
fn find_form(f: &Funcdata, op: OpId) -> Option<(VarnodeId, i64, u128, i64, OpCode)> {
    let mut cur = op;
    let root = f.op(cur).code();
    // Optional leading shift contributes its amount to `n`. `shiftopc = None` is Ghidra's CPUI_MAX
    // sentinel (the SUBPIECE-rooted case with no leading shift).
    let (mut n, shiftopc): (i64, Option<OpCode>) = match root {
        OpCode::IntRight | OpCode::IntSright => {
            let vn = f.op(cur).input(0)?;
            if !f.vn(vn).is_written() {
                return None;
            }
            let cvn = f.op(cur).input(1)?;
            if !f.vn(cvn).is_constant() {
                return None;
            }
            let n = f.vn(cvn).constant_value() as i64;
            cur = f.vn(vn).def?;
            (n, Some(root))
        }
        OpCode::Subpiece => (0, None),
        _ => return None,
    };
    // Optional SUBPIECE keeping the high bits.
    if f.op(cur).code() == OpCode::Subpiece {
        let c = f.vn(f.op(cur).input(1)?).constant_value() as i64;
        let invn = f.op(cur).input(0)?;
        if !f.vn(invn).is_written() {
            return None;
        }
        if f.vn(f.op(cur).output?).size as i64 + c != f.vn(invn).size as i64 {
            return None; // must keep the high bits
        }
        n += 8 * c;
        cur = f.vn(invn).def?;
    }
    if f.op(cur).code() != OpCode::IntMult {
        return None; // there MUST be an INT_MULT
    }
    // in(0) must be written; the constant multiplier and the numerand can be in either slot.
    let mut invn = f.op(cur).input(0)?;
    if !f.vn(invn).is_written() {
        return None;
    }
    let y: u128;
    if let Some(yy) = is_constant_extended(f, invn) {
        y = yy;
        invn = f.op(cur).input(1)?;
        if !f.vn(invn).is_written() {
            return None;
        }
    } else if let Some(yy) = is_constant_extended(f, f.op(cur).input(1)?) {
        y = yy;
    } else {
        return None; // there MUST be a constant
    }
    let ext = f.vn(invn).def?;
    let mut extopc = f.op(ext).code();
    let out_size = f.vn(f.op(op).output?).size as i64;
    let xsize: i64;
    if extopc != OpCode::IntSext {
        let nzmask = if extopc == OpCode::IntZext {
            f.vn(f.op(ext).input(0)?).get_nzmask()
        } else {
            f.vn(invn).get_nzmask()
        };
        xsize = 64 - nzmask.leading_zeros() as i64;
        if xsize == 0 {
            return None;
        }
        if xsize > 4 * f.vn(invn).size as i64 {
            return None;
        }
    } else {
        xsize = f.vn(f.op(ext).input(0)?).size as i64 * 8;
    }
    let resvn: VarnodeId;
    if extopc == OpCode::IntZext || extopc == OpCode::IntSext {
        let extvn = f.op(ext).input(0)?;
        if f.vn(extvn).is_free() {
            return None;
        }
        resvn = if f.vn(invn).size as i64 == out_size { invn } else { extvn };
    } else {
        extopc = OpCode::IntZext; // treat as unsigned extension
        resvn = invn;
    }
    // Signed mismatch: the extension bits are all truncated, so `op`'s signedness doesn't matter.
    let mismatch = (extopc == OpCode::IntZext && shiftopc == Some(OpCode::IntSright))
        || (extopc == OpCode::IntSext && shiftopc == Some(OpCode::IntRight));
    if mismatch && 8 * out_size - n != xsize {
        return None;
    }
    Some((resvn, n, y, xsize, extopc))
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

/// Ghidra `RuleDivOpt::moveSignBitExtraction` (ruleaction.cc:8192): repoint any sign-bit extraction
/// `firstVn >> (8*|firstVn|-1)` / `firstVn s>> ...` (allowing the value to be COPYed around, and the
/// shift amount to arrive via COPY or masked INT_AND) onto `replaceVn`, so the added and subtracted
/// sign corrections of the recovered signed division share a varnode and cancel.
fn move_sign_bit_extraction(f: &mut Funcdata, first_vn: VarnodeId, replace_vn: VarnodeId) {
    let mut test_list: Vec<VarnodeId> = vec![first_vn];
    if f.vn(first_vn).is_written() {
        let d = f.vn(first_vn).def.unwrap();
        if f.op(d).code() == OpCode::IntSright {
            // The same sign bit could be extracted from the previous shifted version.
            test_list.push(f.op(d).input(0).unwrap());
        }
    }
    let mut i = 0;
    while i < test_list.len() {
        let vn = test_list[i];
        i += 1;
        for op in f.vn(vn).descend.clone() {
            let opc = f.op(op).code();
            if opc == OpCode::IntRight || opc == OpCode::IntSright {
                let mut const_vn = f.op(op).input(1).unwrap();
                if f.vn(const_vn).is_written() {
                    let const_op = f.vn(const_vn).def.unwrap();
                    if f.op(const_op).code() == OpCode::Copy {
                        const_vn = f.op(const_op).input(0).unwrap();
                    } else if f.op(const_op).code() == OpCode::IntAnd {
                        let cv = f.op(const_op).input(0).unwrap();
                        let other_vn = f.op(const_op).input(1).unwrap();
                        if !f.vn(other_vn).is_constant() {
                            continue;
                        }
                        // getOffset() == constant_value() (== loc.offset) for any varnode.
                        if f.vn(cv).constant_value()
                            != (f.vn(cv).constant_value() & f.vn(other_vn).constant_value())
                        {
                            continue;
                        }
                        const_vn = cv;
                    }
                }
                if f.vn(const_vn).is_constant() {
                    let sa = f.vn(first_vn).size * 8 - 1;
                    if sa as u64 == f.vn(const_vn).constant_value() {
                        f.op_set_input(op, 0, replace_vn);
                    }
                }
            } else if opc == OpCode::Copy {
                test_list.push(f.op(op).output.unwrap());
            }
        }
    }
}

/// Apply [`find_form`] (Ghidra `RuleDivOpt::applyOp`, ruleaction.cc:8277): rewrite the matched form
/// to `x / d` (unsigned) or `(x s/ d) + (x s>> (w-1))` (signed — the sign correction cancels the
/// stranded `- (x s>> (w-1))` term once `RuleSub2Add`/`RuleCollectTerms` run). Inserts a width
/// extension/truncation when the numerand is narrower/wider than the output.
fn find_form_apply(op: OpId, f: &mut Funcdata) -> u32 {
    let Some((mut in_vn, n, y, xsize, ext_opc)) = find_form(f, op) else { return 0 };
    if check_form_overlap(f, op) {
        return 0;
    }
    let xsize = if ext_opc == OpCode::IntSext { xsize - 1 } else { xsize }; // one less bit for signbit
    let divisor = calc_divisor(n as u32, y, xsize as u32);
    if divisor == 0 {
        return 0;
    }
    let mut op = op;
    let mut out_size = f.vn(f.op(op).output.unwrap()).size;

    if f.vn(in_vn).size < out_size {
        // Need an extension to reach the final size.
        let in_ext = f.new_op_before_sized(op, ext_opc, vec![in_vn], out_size);
        in_vn = f.op(in_ext).output.unwrap();
    } else if f.vn(in_vn).size > out_size {
        // Need a truncation to reach the final size: a new op holds the INT_DIV / INT_SDIV:INT_ADD,
        // and the original op becomes a truncating SUBPIECE of it.
        let in_size = f.vn(in_vn).size;
        let newop = f.new_op_before_sized(op, OpCode::IntAdd, vec![in_vn, in_vn], in_size);
        let res_vn = f.op(newop).output.unwrap();
        f.op_set_opcode(op, OpCode::Subpiece);
        let zero = f.new_const(4, 0);
        f.op_set_all_input(op, &[res_vn, zero]);
        op = newop;
        out_size = in_size;
    }
    if ext_opc == OpCode::IntZext {
        // Unsigned division.
        let dc = f.new_const(out_size, divisor);
        f.op_set_all_input(op, &[in_vn, dc]);
        f.op_set_opcode(op, OpCode::IntDiv);
    } else {
        // Signed division: `(x s/ d) + (x s>> (w-1))`.
        let out_vn = f.op(op).output.unwrap();
        move_sign_bit_extraction(f, out_vn, in_vn);
        let dc = f.new_const(out_size, divisor);
        let divop = f.new_op_before_sized(op, OpCode::IntSdiv, vec![in_vn, dc], out_size);
        let newout = f.op(divop).output.unwrap();
        let sac = f.new_const(out_size, (out_size * 8 - 1) as u64);
        let sgnop = f.new_op_before_sized(op, OpCode::IntSright, vec![in_vn, sac], out_size);
        let sgnvn = f.op(sgnop).output.unwrap();
        f.op_set_all_input(op, &[newout, sgnvn]);
        f.op_set_opcode(op, OpCode::IntAdd);
    }
    1
}

/// Recover modulo from `x - (x / d) * d` ⇒ `x % d` (Ghidra's `RuleModOpt`, ruleaction.cc:8603).
/// Rooted at the recovered INT_DIV/INT_SDIV, it walks forward to the `(x/d) * (-d)` multiply and
/// the `x + (x/d)*(-d)` add — the additive shape the subtraction takes once [`super::rules::RuleSub2Add`]
/// has run — and rewrites that add into `x % d`. The `-d` factor is matched either as the
/// literal 2's-complement constant or as an `INT_2COMP` of the divisor.
pub struct RuleModOpt;

impl Rule for RuleModOpt {
    fn name(&self) -> &str {
        "modopt"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntDiv, OpCode::IntSdiv]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let x = data.op(op).input(0).unwrap();
        let div = data.op(op).input(1).unwrap();
        let outvn = data.op(op).output.unwrap();
        for multop in data.vn(outvn).descend.clone() {
            if data.op(multop).code() != OpCode::IntMult {
                continue;
            }
            let mut div2 = data.op(multop).input(1).unwrap();
            if div2 == outvn {
                div2 = data.op(multop).input(0).unwrap();
            }
            // Check that div is the 2's-complement of div2.
            if data.vn(div2).is_constant() {
                if !data.vn(div).is_constant() {
                    continue;
                }
                let mask = super::nzmask::calc_mask(data.vn(div2).size);
                if (((data.vn(div2).constant_value() ^ mask).wrapping_add(1)) & mask)
                    != data.vn(div).constant_value()
                {
                    continue;
                }
            } else {
                if !data.vn(div2).is_written() {
                    continue;
                }
                let d2def = data.vn(div2).def.unwrap();
                if data.op(d2def).code() != OpCode::Int2comp {
                    continue;
                }
                if data.op(d2def).input(0) != Some(div) {
                    continue;
                }
            }
            let outvn2 = data.op(multop).output.unwrap();
            for addop in data.vn(outvn2).descend.clone() {
                if data.op(addop).code() != OpCode::IntAdd {
                    continue;
                }
                let mut lvn = data.op(addop).input(0).unwrap();
                if lvn == outvn2 {
                    lvn = data.op(addop).input(1).unwrap();
                }
                if lvn != x {
                    continue;
                }
                data.op_set_input(addop, 0, x);
                if data.vn(div).is_constant() {
                    let dc = data.new_const(data.vn(div).size, data.vn(div).constant_value());
                    data.op_set_input(addop, 1, dc);
                } else {
                    data.op_set_input(addop, 1, div);
                }
                let newcode = if data.op(op).code() == OpCode::IntDiv {
                    OpCode::IntRem
                } else {
                    OpCode::IntSrem
                };
                data.op_set_opcode(addop, newcode);
                return 1;
            }
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

// ===========================================================================
// Signed-division / division-chain cluster (Ghidra `ruleaction.cc`, oppool1 @5599-5605).
// De-fusion Task #9/#20: these are faithful ports landed HELD (defined-but-unwired). They
// compose with the faithful ADD-normalized div form that only appears once RuleSub2Add moves
// into the main pool (Stage 2), so they are inert on the corpus until then. Unit-tested here.
// ===========================================================================

/// Ghidra `RuleSignMod2nOpt::checkSignExtraction` (ruleaction.cc:8758): if `out_vn` is the
/// sign-bit replication `res s>> (8*|res|-1)`, return `res`; else `None`.
fn check_sign_extraction(f: &Funcdata, out_vn: VarnodeId) -> Option<VarnodeId> {
    if !f.vn(out_vn).is_written() {
        return None;
    }
    let sign_op = f.vn(out_vn).def.unwrap();
    if f.op(sign_op).code() != OpCode::IntSright {
        return None;
    }
    let const_vn = f.op(sign_op).input(1).unwrap();
    if !f.vn(const_vn).is_constant() {
        return None;
    }
    let val = f.vn(const_vn).constant_value();
    let res_vn = f.op(sign_op).input(0).unwrap();
    let insize = f.vn(res_vn).size;
    if val != (insize * 8 - 1) as u64 {
        return None;
    }
    Some(res_vn)
}

/// Ghidra `RuleSignDiv2` (ruleaction.cc:8339, INT_SRIGHT): convert the sign-corrected halving
/// form back into a division — `(V + -1*(V s>> (8|V|-1))) s>> 1  =>  V s/ 2`.
pub struct RuleSignDiv2;

impl Rule for RuleSignDiv2 {
    fn name(&self) -> &str {
        "signdiv2"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSright]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let in1 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_constant() || data.vn(in1).constant_value() != 1 {
            return 0;
        }
        let addout = data.op(op).input(0).unwrap();
        if !data.vn(addout).is_written() {
            return 0;
        }
        let addop = data.vn(addout).def.unwrap();
        if data.op(addop).code() != OpCode::IntAdd {
            return 0;
        }
        let mut found = None;
        for i in 0..2 {
            let multout = data.op(addop).input(i).unwrap();
            if !data.vn(multout).is_written() {
                continue;
            }
            let multop = data.vn(multout).def.unwrap();
            if data.op(multop).code() != OpCode::IntMult {
                continue;
            }
            let mc = data.op(multop).input(1).unwrap();
            if !data.vn(mc).is_constant()
                || data.vn(mc).constant_value() != super::nzmask::calc_mask(data.vn(mc).size)
            {
                continue;
            }
            let shiftout = data.op(multop).input(0).unwrap();
            if !data.vn(shiftout).is_written() {
                continue;
            }
            let shiftop = data.vn(shiftout).def.unwrap();
            if data.op(shiftop).code() != OpCode::IntSright {
                continue;
            }
            let sc = data.op(shiftop).input(1).unwrap();
            if !data.vn(sc).is_constant() {
                continue;
            }
            let n = data.vn(sc).constant_value();
            let a = data.op(shiftop).input(0).unwrap();
            if Some(a) != data.op(addop).input(1 - i) {
                continue;
            }
            if n != (8 * data.vn(a).size - 1) as u64 || data.vn(a).is_free() {
                continue;
            }
            found = Some(a);
            break;
        }
        let Some(a) = found else {
            return 0;
        };
        data.op_set_input(op, 0, a);
        let two = data.new_const(data.vn(a).size, 2);
        data.op_set_input(op, 1, two);
        data.op_set_opcode(op, OpCode::IntSdiv);
        1
    }
}

/// Ghidra `RuleDivChain` (ruleaction.cc:8392, INT_DIV/INT_SDIV): collapse two consecutive
/// divisions — `(x / c1) / c2  =>  x / (c1*c2)` (with the unsigned `x >> sa` first-shift case),
/// guarded against overflow and against reuse of the intermediate result.
pub struct RuleDivChain;

impl Rule for RuleDivChain {
    fn name(&self) -> &str {
        "divchain"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntDiv, OpCode::IntSdiv]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let opc2 = data.op(op).code();
        let const_vn2 = data.op(op).input(1).unwrap();
        if !data.vn(const_vn2).is_constant() {
            return 0;
        }
        let vn = data.op(op).input(0).unwrap();
        if !data.vn(vn).is_written() {
            return 0;
        }
        let div_op = data.vn(vn).def.unwrap();
        let opc1 = data.op(div_op).code();
        if opc1 != opc2 && (opc2 != OpCode::IntDiv || opc1 != OpCode::IntRight) {
            return 0;
        }
        let const_vn1 = data.op(div_op).input(1).unwrap();
        if !data.vn(const_vn1).is_constant() {
            return 0;
        }
        // If the intermediate result is used elsewhere, don't apply — collapsing would interfere
        // with the modulo rules (Ghidra: `vn->loneDescend() == 0`).
        if data.vn(vn).descend.len() != 1 {
            return 0;
        }
        let sz = data.vn(vn).size;
        let val1: u64 = if opc1 == opc2 {
            data.vn(const_vn1).constant_value()
        } else {
            // Unsigned case with INT_RIGHT: val1 = 1 << sa
            let sa = data.vn(const_vn1).constant_value();
            1u64.checked_shl(sa as u32).unwrap_or(0)
        };
        let base_vn = data.op(div_op).input(0).unwrap();
        if data.vn(base_vn).is_free() {
            return 0;
        }
        let val2 = data.vn(const_vn2).constant_value();
        let mask = super::nzmask::calc_mask(sz);
        let resval = val1.wrapping_mul(val2) & mask;
        if resval == 0 {
            return 0;
        }
        let mut v1 = val1;
        let mut v2 = val2;
        if super::nzmask::signbit_negative(v1, sz) {
            v1 = v1.wrapping_neg() & mask;
        }
        if super::nzmask::signbit_negative(v2, sz) {
            v2 = v2.wrapping_neg() & mask;
        }
        let bitcount = super::nzmask::mostsigbit_set(v1) + super::nzmask::mostsigbit_set(v2) + 2;
        if opc2 == OpCode::IntDiv && bitcount > (sz * 8) as i32 {
            return 0; // Unsigned overflow
        }
        if opc2 == OpCode::IntSdiv && bitcount > (sz * 8) as i32 - 2 {
            return 0; // Signed overflow
        }
        data.op_set_input(op, 0, base_vn);
        let rc = data.new_const(sz, resval);
        data.op_set_input(op, 1, rc);
        1
    }
}

/// Ghidra `RuleSignNearMult` (ruleaction.cc:8533, INT_AND): recover a rounded division —
/// `(V + (V s>> 0x1f)>>(32-n)) & (-1<<n)  =>  (V s/ 2^n) * 2^n`.
pub struct RuleSignNearMult;

impl Rule for RuleSignNearMult {
    fn name(&self) -> &str {
        "signnearmult"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if !data.vn(data.op(op).input(1).unwrap()).is_constant() {
            return 0;
        }
        let in0 = data.op(op).input(0).unwrap();
        if !data.vn(in0).is_written() {
            return 0;
        }
        let addop = data.vn(in0).def.unwrap();
        if data.op(addop).code() != OpCode::IntAdd {
            return 0;
        }
        let mut idx = 2;
        let (mut shiftvn, mut unshiftop) = (None, None);
        for i in 0..2 {
            let sv = data.op(addop).input(i).unwrap();
            if !data.vn(sv).is_written() {
                continue;
            }
            let uso = data.vn(sv).def.unwrap();
            if data.op(uso).code() == OpCode::IntRight {
                if !data.vn(data.op(uso).input(1).unwrap()).is_constant() {
                    continue;
                }
                shiftvn = Some(sv);
                unshiftop = Some(uso);
                idx = i;
                break;
            }
        }
        if idx == 2 {
            return 0;
        }
        let (shiftvn, unshiftop) = (shiftvn.unwrap(), unshiftop.unwrap());
        let x = data.op(addop).input(1 - idx).unwrap();
        if data.vn(x).is_free() {
            return 0;
        }
        let n0 = data.vn(data.op(unshiftop).input(1).unwrap()).constant_value() as i64;
        if n0 <= 0 {
            return 0;
        }
        let n = data.vn(shiftvn).size as i64 * 8 - n0;
        if n <= 0 {
            return 0;
        }
        let mask0 = super::nzmask::calc_mask(data.vn(shiftvn).size);
        let mask = (mask0 << n as u32) & mask0;
        if mask != data.vn(data.op(op).input(1).unwrap()).constant_value() {
            return 0;
        }
        let sgnvn = data.op(unshiftop).input(0).unwrap();
        if !data.vn(sgnvn).is_written() {
            return 0;
        }
        let sshiftop = data.vn(sgnvn).def.unwrap();
        if data.op(sshiftop).code() != OpCode::IntSright {
            return 0;
        }
        if !data.vn(data.op(sshiftop).input(1).unwrap()).is_constant() {
            return 0;
        }
        if data.op(sshiftop).input(0) != Some(x) {
            return 0;
        }
        let val = data.vn(data.op(sshiftop).input(1).unwrap()).constant_value();
        if val != (8 * data.vn(x).size - 1) as u64 {
            return 0;
        }
        let pow = 1u64 << n as u32;
        let xsize = data.vn(x).size;
        let powc1 = data.new_const(xsize, pow);
        let newdiv = data.new_op_before_sized(op, OpCode::IntSdiv, vec![x, powc1], xsize);
        let divvn = data.op(newdiv).output.unwrap();
        data.op_set_opcode(op, OpCode::IntMult);
        let powc2 = data.new_const(xsize, pow);
        data.op_set_input(op, 0, divvn);
        data.op_set_input(op, 1, powc2);
        1
    }
}

/// Ghidra `RuleSignMod2Opt` (ruleaction.cc:8776, INT_AND): a specialized `RuleSignMod2nOpt` —
/// `(V - sign)&1 + sign  =>  V s% 2` where `sign = V s>> (8|V|-1)`. The INT_AND may be performed
/// on a truncated result then re-extended (the `trunc` path).
pub struct RuleSignMod2Opt;

impl Rule for RuleSignMod2Opt {
    fn name(&self) -> &str {
        "signmod2opt"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let const_vn = data.op(op).input(1).unwrap();
        if !data.vn(const_vn).is_constant() || data.vn(const_vn).constant_value() != 1 {
            return 0;
        }
        let add_out = data.op(op).input(0).unwrap();
        if !data.vn(add_out).is_written() {
            return 0;
        }
        let add_op = data.vn(add_out).def.unwrap();
        if data.op(add_op).code() != OpCode::IntAdd {
            return 0;
        }
        let mut mult_slot = 2;
        let mut mult_op = None;
        for slot in 0..2 {
            let vn = data.op(add_op).input(slot).unwrap();
            if !data.vn(vn).is_written() {
                continue;
            }
            let mo = data.vn(vn).def.unwrap();
            if data.op(mo).code() != OpCode::IntMult {
                continue;
            }
            let cvn = data.op(mo).input(1).unwrap();
            if !data.vn(cvn).is_constant() {
                continue;
            }
            // Check for INT_MULT by -1
            if data.vn(cvn).constant_value() == super::nzmask::calc_mask(data.vn(cvn).size) {
                mult_slot = slot;
                mult_op = Some(mo);
                break;
            }
        }
        if mult_slot > 1 {
            return 0;
        }
        let mult_op = mult_op.unwrap();
        let mut base = match check_sign_extraction(data, data.op(mult_op).input(0).unwrap()) {
            Some(b) => b,
            None => return 0,
        };
        let mut other_base = data.op(add_op).input(1 - mult_slot).unwrap();
        let mut trunc = false;
        if base != other_base {
            if !data.vn(base).is_written() || !data.vn(other_base).is_written() {
                return 0;
            }
            let sub_op = data.vn(base).def.unwrap();
            if data.op(sub_op).code() != OpCode::Subpiece {
                return 0;
            }
            let trunc_amt = data.vn(data.op(sub_op).input(1).unwrap()).constant_value();
            // Must truncate all but the high part
            if trunc_amt + data.vn(base).size as u64
                != data.vn(data.op(sub_op).input(0).unwrap()).size as u64
            {
                return 0;
            }
            base = data.op(sub_op).input(0).unwrap();
            let sub_op2 = data.vn(other_base).def.unwrap();
            if data.op(sub_op2).code() != OpCode::Subpiece {
                return 0;
            }
            if data.vn(data.op(sub_op2).input(1).unwrap()).constant_value() != 0 {
                return 0;
            }
            other_base = data.op(sub_op2).input(0).unwrap();
            if other_base != base {
                return 0;
            }
            trunc = true;
        }
        if data.vn(base).is_free() {
            return 0;
        }
        let mut and_out = data.op(op).output.unwrap();
        if trunc {
            if data.vn(and_out).descend.len() != 1 {
                return 0;
            }
            let ext_op = data.vn(and_out).descend[0];
            if data.op(ext_op).code() != OpCode::IntZext {
                return 0;
            }
            and_out = data.op(ext_op).output.unwrap();
        }
        for &root_op in &data.vn(and_out).descend.clone() {
            if data.op(root_op).code() != OpCode::IntAdd {
                continue;
            }
            let slot = if data.op(root_op).input(0) == Some(and_out) { 0 } else { 1 };
            if check_sign_extraction(data, data.op(root_op).input(1 - slot).unwrap()) != Some(base) {
                continue;
            }
            data.op_set_opcode(root_op, OpCode::IntSrem);
            data.op_set_input(root_op, 0, base);
            let two = data.new_const(data.vn(base).size, 2);
            data.op_set_input(root_op, 1, two);
            return 1;
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signdiv2_recovers_signed_halving() {
        // (V + -1*(V s>> 63)) s>> 1  =>  V s/ 2
        use crate::decompile::space::{Address, SpaceManager};
        use crate::decompile::{BlockBasic, Funcdata, SeqNum};
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let x = f.new_input(8, Address::new(reg, 0x38));
        let sh = f.new_const(8, 0x3f);
        let sr = f.new_op(OpCode::IntSright, seq, vec![x, sh]);
        let sro = f.new_output_unique(sr, 8);
        let negone = f.new_const(8, super::super::nzmask::calc_mask(8));
        let mult = f.new_op(OpCode::IntMult, seq, vec![sro, negone]);
        let multo = f.new_output_unique(mult, 8);
        let add = f.new_op(OpCode::IntAdd, seq, vec![multo, x]);
        let addo = f.new_output_unique(add, 8);
        let one = f.new_const(8, 1);
        let op = f.new_op(OpCode::IntSright, seq, vec![addo, one]);
        f.new_output_unique(op, 8);
        f.set_blocks(vec![BlockBasic { ops: vec![sr, mult, add, op], ..Default::default() }]);

        assert_eq!(RuleSignDiv2.apply_op(op, &mut f), 1);
        assert_eq!(f.op(op).code(), OpCode::IntSdiv);
        assert_eq!(f.op(op).input(0), Some(x));
        let dc = f.op(op).input(1).unwrap();
        assert!(f.vn(dc).is_constant() && f.vn(dc).constant_value() == 2);
    }

    #[test]
    fn modopt_recovers_modulo_from_add_form() {
        // x + (x s/ 3) * -3   =>   x s% 3   (the post-Sub2Add additive shape; rooted at the SDIV)
        use crate::decompile::space::{Address, SpaceManager};
        use crate::decompile::{BlockBasic, Funcdata, SeqNum};
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let x = f.new_input(8, Address::new(reg, 0x38));
        let three = f.new_const(8, 3);
        let div = f.new_op(OpCode::IntSdiv, seq, vec![x, three]);
        let divo = f.new_output_unique(div, 8);
        let negthree = f.new_const(8, (-3i64) as u64);
        let mult = f.new_op(OpCode::IntMult, seq, vec![divo, negthree]);
        let multo = f.new_output_unique(mult, 8);
        let add = f.new_op(OpCode::IntAdd, seq, vec![x, multo]);
        f.new_output(add, 8, Address::new(reg, 0));
        f.set_blocks(vec![BlockBasic { ops: vec![div, mult, add], ..Default::default() }]);

        assert_eq!(RuleModOpt.apply_op(div, &mut f), 1);
        assert_eq!(f.op(add).code(), OpCode::IntSrem);
        assert_eq!(f.op(add).input(0), Some(x));
        let dc = f.op(add).input(1).unwrap();
        assert!(f.vn(dc).is_constant() && f.vn(dc).constant_value() == 3);
    }

    #[test]
    fn divchain_collapses_two_signed_divisions() {
        // (x s/ 3) s/ 5  =>  x s/ 15
        use crate::decompile::space::{Address, SpaceManager};
        use crate::decompile::{BlockBasic, Funcdata, SeqNum};
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let x = f.new_input(8, Address::new(reg, 0x38));
        let c1 = f.new_const(8, 3);
        let div1 = f.new_op(OpCode::IntSdiv, seq, vec![x, c1]);
        let div1o = f.new_output_unique(div1, 8);
        let c2 = f.new_const(8, 5);
        let op = f.new_op(OpCode::IntSdiv, seq, vec![div1o, c2]);
        f.new_output_unique(op, 8);
        f.set_blocks(vec![BlockBasic { ops: vec![div1, op], ..Default::default() }]);

        assert_eq!(RuleDivChain.apply_op(op, &mut f), 1);
        assert_eq!(f.op(op).code(), OpCode::IntSdiv);
        assert_eq!(f.op(op).input(0), Some(x));
        let dc = f.op(op).input(1).unwrap();
        assert!(f.vn(dc).is_constant() && f.vn(dc).constant_value() == 15);
        // reuse guard: a second descendant on the intermediate blocks the fold
        assert_eq!(RuleDivChain.apply_op(op, &mut f), 0);
    }

    #[test]
    fn signnearmult_recovers_rounded_division() {
        // (V + (V s>> 31)>>30) & 0xfffffffc  =>  (V s/ 4) * 4   (size 4, n=2)
        use crate::decompile::space::{Address, SpaceManager};
        use crate::decompile::{BlockBasic, Funcdata, SeqNum};
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let x = f.new_input(4, Address::new(reg, 0x38));
        let sh31 = f.new_const(4, 31);
        let sr = f.new_op(OpCode::IntSright, seq, vec![x, sh31]);
        let sro = f.new_output_unique(sr, 4);
        let n0c = f.new_const(4, 30);
        let unshift = f.new_op(OpCode::IntRight, seq, vec![sro, n0c]);
        let unsho = f.new_output_unique(unshift, 4);
        let add = f.new_op(OpCode::IntAdd, seq, vec![unsho, x]);
        let addo = f.new_output_unique(add, 4);
        let maskc = f.new_const(4, 0xfffffffc);
        let op = f.new_op(OpCode::IntAnd, seq, vec![addo, maskc]);
        f.new_output_unique(op, 4);
        f.set_blocks(vec![BlockBasic { ops: vec![sr, unshift, add, op], ..Default::default() }]);

        assert_eq!(RuleSignNearMult.apply_op(op, &mut f), 1);
        assert_eq!(f.op(op).code(), OpCode::IntMult);
        let divvn = f.op(op).input(0).unwrap();
        let divop = f.vn(divvn).def.unwrap();
        assert_eq!(f.op(divop).code(), OpCode::IntSdiv);
        assert_eq!(f.op(divop).input(0), Some(x));
        assert!(f.vn(f.op(divop).input(1).unwrap()).constant_value() == 4);
        assert!(f.vn(f.op(op).input(1).unwrap()).constant_value() == 4);
    }

    #[test]
    fn signmod2opt_recovers_signed_mod_2() {
        // ((V - sign) & 1) + sign  =>  V s% 2,  sign = V s>> 63
        use crate::decompile::space::{Address, SpaceManager};
        use crate::decompile::{BlockBasic, Funcdata, SeqNum};
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let v = f.new_input(8, Address::new(reg, 0x38));
        let sh63 = f.new_const(8, 0x3f);
        let sign = f.new_op(OpCode::IntSright, seq, vec![v, sh63]);
        let signo = f.new_output_unique(sign, 8);
        let negone = f.new_const(8, super::super::nzmask::calc_mask(8));
        let mult = f.new_op(OpCode::IntMult, seq, vec![signo, negone]);
        let multo = f.new_output_unique(mult, 8);
        let add = f.new_op(OpCode::IntAdd, seq, vec![multo, v]);
        let addo = f.new_output_unique(add, 8);
        let one = f.new_const(8, 1);
        let and = f.new_op(OpCode::IntAnd, seq, vec![addo, one]);
        let ando = f.new_output_unique(and, 8);
        let root = f.new_op(OpCode::IntAdd, seq, vec![ando, signo]);
        f.new_output_unique(root, 8);
        f.set_blocks(vec![BlockBasic { ops: vec![sign, mult, add, and, root], ..Default::default() }]);

        assert_eq!(RuleSignMod2Opt.apply_op(and, &mut f), 1);
        assert_eq!(f.op(root).code(), OpCode::IntSrem);
        assert_eq!(f.op(root).input(0), Some(v));
        let dc = f.op(root).input(1).unwrap();
        assert!(f.vn(dc).is_constant() && f.vn(dc).constant_value() == 2);
    }

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
    fn recovers_signed_division_via_findform() {
        // `SUBPIECE(sext(x) * 0x55555556, 4)` (x is 4 bytes)  =>  `(x s/ 3) + (x s>> 31)`
        // (the signed find_form/applyOp path: the sign correction is emitted so the stranded
        // `- (x s>> 31)` cancels once RuleSub2Add/RuleCollectTerms run). calc_divisor(32, magic, 31).
        use crate::decompile::space::{Address, SpaceManager};
        use crate::decompile::{BlockBasic, Funcdata, SeqNum};
        assert_eq!(calc_divisor(32, 0x55555556, 31), 3, "signed /3 magic must recover");
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let x = f.new_input(4, Address::new(reg, 0x38));
        let se = f.new_op(OpCode::IntSext, seq, vec![x]);
        let seo = f.new_output_unique(se, 8);
        let magic = f.new_const(8, 0x55555556);
        let mu = f.new_op(OpCode::IntMult, seq, vec![seo, magic]);
        let muo = f.new_output_unique(mu, 8);
        let off = f.new_const(4, 4);
        let op = f.new_op(OpCode::Subpiece, seq, vec![muo, off]); // keeps the high 4 bytes = mulhi
        f.new_output(op, 4, Address::new(reg, 0));
        f.set_blocks(vec![BlockBasic { ops: vec![se, mu, op], ..Default::default() }]);

        assert_eq!(find_form_apply(op, &mut f), 1);
        // op rewritten to INT_ADD( x s/ 3, x s>> 31 ).
        assert_eq!(f.op(op).code(), OpCode::IntAdd);
        let divvn = f.op(op).input(0).unwrap();
        let divop = f.vn(divvn).def.unwrap();
        assert_eq!(f.op(divop).code(), OpCode::IntSdiv);
        assert_eq!(f.op(divop).input(0), Some(x));
        assert_eq!(f.vn(f.op(divop).input(1).unwrap()).constant_value(), 3);
        let sgnvn = f.op(op).input(1).unwrap();
        let sgnop = f.vn(sgnvn).def.unwrap();
        assert_eq!(f.op(sgnop).code(), OpCode::IntSright);
        assert_eq!(f.op(sgnop).input(0), Some(x));
        assert_eq!(f.vn(f.op(sgnop).input(1).unwrap()).constant_value(), 31);
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
