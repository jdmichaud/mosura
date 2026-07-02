//! Simplification rules — ports of Ghidra's `ruleaction.cc` `Rule`s, applied to a fixpoint
//! by an [`ActionPool`](super::action::ActionPool). This is the start of P2; more rules
//! slot in the same way Ghidra's pool grows.

use super::action::Rule;
use super::block::BlockId;
use super::funcdata::Funcdata;
use super::op::{OpId, SeqNum};
use super::opcode::OpCode;
use super::varnode::VarnodeId;

fn mask(v: u64, size: u32) -> u64 {
    if size >= 8 {
        v
    } else {
        v & ((1u64 << (8 * size)) - 1)
    }
}

fn sext(v: u64, size: u32) -> u64 {
    if size == 0 || size >= 8 {
        v
    } else {
        let sh = 64 - 8 * size;
        (((v << sh) as i64) >> sh) as u64
    }
}

/// Evaluate an op whose inputs are all constants, mirroring the (parity-validated) p-code
/// semantics in `sleigh::emu`. Returns the masked result, or `None` for ops that are not
/// purely-functional constant computations (memory, control flow, markers).
pub fn eval_const(opcode: OpCode, inputs: &[(u64, u32)], out_size: u32) -> Option<u64> {
    use OpCode::*;
    let a = |i: usize| inputs.get(i).map_or(0, |&(v, s)| mask(v, s));
    let sa = |i: usize| inputs.get(i).map_or(0, |&(v, s)| sext(v, s));
    let res: u64 = match opcode {
        Copy => a(0),
        IntAdd => a(0).wrapping_add(a(1)),
        IntSub => a(0).wrapping_sub(a(1)),
        IntMult => a(0).wrapping_mul(a(1)),
        IntAnd => a(0) & a(1),
        IntOr => a(0) | a(1),
        IntXor => a(0) ^ a(1),
        IntLeft => a(0).checked_shl(a(1) as u32).unwrap_or(0),
        IntRight => a(0).checked_shr(a(1) as u32).unwrap_or(0),
        IntSright => (sa(0) >> (a(1) as u32).min(63)) as u64,
        IntNegate => !a(0),
        Int2comp => a(0).wrapping_neg(),
        IntZext => a(0),
        IntSext => sa(0),
        Subpiece => a(0).checked_shr(a(1).saturating_mul(8) as u32).unwrap_or(0),
        IntEqual => (a(0) == a(1)) as u64,
        IntNotequal => (a(0) != a(1)) as u64,
        IntLess => (a(0) < a(1)) as u64,
        IntLessequal => (a(0) <= a(1)) as u64,
        IntSless => ((sa(0) as i64) < (sa(1) as i64)) as u64,
        IntSlessequal => ((sa(0) as i64) <= (sa(1) as i64)) as u64,
        BoolNegate => (a(0) == 0) as u64,
        BoolAnd => (a(0) & 1) & (a(1) & 1),
        BoolOr => (a(0) & 1) | (a(1) & 1),
        BoolXor => (a(0) & 1) ^ (a(1) & 1),
        Popcount => a(0).count_ones() as u64,
        Lzcount => a(0).leading_zeros() as u64,
        _ => return None, // LOAD/STORE/branches/calls/markers: not const-foldable
    };
    Some(mask(res, out_size))
}

/// Collapse an op whose inputs are all constants — a port of Ghidra's `RuleCollapseConstants`
/// (`ruleaction.cc`). The op is rewritten *in place* as `out = COPY <collapsed const>` (link the
/// new constant as input 0, drop the rest, change the opcode to COPY), rather than replacing every
/// use of `out`. RulePropagateCopy then propagates the COPY everywhere it is allowed; its marker
/// guard deliberately leaves the COPY in place where a constant must not be folded into a
/// MULTIEQUAL/INDIRECT. That is what lets an addrtied stack store survive as a renderable
/// `xStack_NN = const` feeding the across-call INDIRECT (instead of the constant vanishing into it).
/// (Ghidra computes the same value via per-op `OpBehavior::evaluate`; the IR is identical.)
pub struct RuleConstFold;

impl Rule for RuleConstFold {
    fn name(&self) -> &str {
        "constfold"
    }
    fn oplist(&self) -> Vec<OpCode> {
        Vec::new() // every op; eval_const screens out the non-foldable ones
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let code = data.op(op).code();
        // A COPY of a constant is already in the collapsed `out = COPY const` form (Ghidra leaves it
        // for RulePropagateCopy/dead-code); re-collapsing it would loop, so skip it.
        if code == OpCode::Copy {
            return 0;
        }
        let Some(out) = data.op(op).output else { return 0 };
        let inrefs = data.op(op).inrefs.clone();
        if inrefs.is_empty() {
            return 0;
        }
        let mut inputs = Vec::with_capacity(inrefs.len());
        for v in &inrefs {
            let vn = data.vn(*v);
            if !vn.is_constant() {
                return 0;
            }
            inputs.push((vn.constant_value(), vn.size));
        }
        let out_size = data.vn(out).size;
        let Some(val) = eval_const(code, &inputs, out_size) else { return 0 };
        // Rewrite in place as `out = COPY const` (Ghidra `RuleCollapseConstants`): unlink the old
        // constant inputs, link the collapsed constant as input 0, become a COPY.
        let c = data.new_const(out_size, val);
        for slot in (1..inrefs.len()).rev() {
            data.op_remove_input(op, slot);
        }
        data.op_set_input(op, 0, c);
        data.op_set_opcode(op, OpCode::Copy);
        1
    }
}

/// `x OP x` identities — a port of Ghidra's `RuleTrivialArith`. With both inputs the same
/// varnode, comparisons/booleans collapse to a constant and `x & x`/`x | x` collapse to
/// `x`; the op becomes a COPY.
pub struct RuleTrivialArith;

impl Rule for RuleTrivialArith {
    fn name(&self) -> &str {
        "trivialarith"
    }
    fn oplist(&self) -> Vec<OpCode> {
        use OpCode::*;
        vec![
            IntNotequal, IntSless, IntLess, BoolXor, IntEqual, IntSlessequal, IntLessequal,
            IntXor, IntAnd, IntOr, BoolAnd, BoolOr,
        ]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        use OpCode::*;
        let o = data.op(op);
        if o.num_inputs() != 2 || o.input(0) != o.input(1) {
            return 0; // only the syntactically-identical case (CSE-match is RuleSelectCse)
        }
        let out_size = o.output.map_or(1, |v| data.vn(v).size);
        // the constant the op collapses to, or None to keep input 0 (`x & x` → x)
        let cval: Option<(u32, u64)> = match o.code() {
            IntNotequal | IntSless | IntLess | BoolXor => Some((1, 0)),
            IntEqual | IntSlessequal | IntLessequal => Some((1, 1)),
            IntXor => Some((out_size, 0)),
            IntAnd | IntOr | BoolAnd | BoolOr => None,
            _ => return 0,
        };
        data.op_remove_input(op, 1);
        data.op_set_opcode(op, Copy);
        if let Some((sz, v)) = cval {
            let c = data.new_const(sz, v);
            data.op_set_input(op, 0, c);
        }
        1
    }
}

/// Move a constant to the second input of a commutative op (Ghidra's `RuleTermOrder`), so
/// the identity/collapse rules can assume the constant is in slot 1.
pub struct RuleTermOrder;

impl Rule for RuleTermOrder {
    fn name(&self) -> &str {
        "termorder"
    }
    fn oplist(&self) -> Vec<OpCode> {
        use OpCode::*;
        vec![
            IntEqual, IntNotequal, IntAdd, IntCarry, IntScarry, IntXor, IntAnd, IntOr,
            IntMult, BoolXor, BoolAnd, BoolOr, FloatEqual, FloatNotequal, FloatAdd, FloatMult,
        ]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let in0 = data.op(op).input(0).unwrap();
        let in1 = data.op(op).input(1).unwrap();
        if data.vn(in0).is_constant() && !data.vn(in1).is_constant() {
            data.op_swap_input(op, 0, 1);
            return 1;
        }
        0
    }
}

/// Identity elements (Ghidra's `RuleIdentityEl`): `x+0`, `x^0`, `x|0` → `x`; `x*1` → `x`;
/// `x*0` → `0`. Assumes the constant is in slot 1 (`RuleTermOrder`).
pub struct RuleIdentityEl;

impl Rule for RuleIdentityEl {
    fn name(&self) -> &str {
        "identityel"
    }
    fn oplist(&self) -> Vec<OpCode> {
        use OpCode::*;
        vec![IntAdd, IntXor, IntOr, BoolXor, BoolOr, IntMult]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let in1 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_constant() {
            return 0;
        }
        let val = data.vn(in1).constant_value();
        let code = data.op(op).code();
        if val == 0 && code != OpCode::IntMult {
            data.op_set_opcode(op, OpCode::Copy);
            data.op_remove_input(op, 1);
            return 1;
        }
        if code != OpCode::IntMult {
            return 0;
        }
        match val {
            1 => {
                data.op_set_opcode(op, OpCode::Copy);
                data.op_remove_input(op, 1);
                1
            }
            0 => {
                data.op_set_opcode(op, OpCode::Copy);
                data.op_remove_input(op, 0); // keep the constant 0
                1
            }
            _ => 0,
        }
    }
}

/// Shift identities (Ghidra's `RuleTrivialShift`): `x << 0` → `x`; a logical shift by ≥ the
/// operand width → `0` (an arithmetic right shift by ≥ width is left alone).
pub struct RuleTrivialShift;

impl Rule for RuleTrivialShift {
    fn name(&self) -> &str {
        "trivialshift"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntLeft, OpCode::IntRight, OpCode::IntSright]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let in1 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_constant() {
            return 0;
        }
        let val = data.vn(in1).constant_value();
        if val != 0 {
            let in0_size = data.vn(data.op(op).input(0).unwrap()).size;
            if val < 8 * in0_size as u64 || data.op(op).code() == OpCode::IntSright {
                return 0;
            }
            let zero = data.new_const(in0_size, 0);
            data.op_set_input(op, 0, zero);
        }
        data.op_remove_input(op, 1);
        data.op_set_opcode(op, OpCode::Copy);
        1
    }
}

/// `RuleShift2Mult` (Ghidra): `V << c` → `V * 2^c`, but only when the shift is involved in an
/// arithmetic expression (its operand's def, or one of its uses, is INT_ADD/INT_SUB/INT_MULT) — so
/// a left-shift that is really a scaled multiply joins the surrounding arithmetic and combines:
/// `(q * 0xf) << 2` → `q * 0xf * 4` → (RuleMultMult) `q * 0x3c`, which `RuleModOpt` can then fold.
/// A shift by ≥ 32 is left alone (anything that big is unlikely to be an arithmetic multiply).
pub struct RuleShift2Mult;

impl Rule for RuleShift2Mult {
    fn name(&self) -> &str {
        "shift2mult"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntLeft]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let in1 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_constant() {
            return 0;
        }
        let val = data.vn(in1).constant_value();
        if val >= 32 {
            return 0; // arbitrary (Ghidra): bigger is probably not an arithmetic multiply
        }
        // Involved in arithmetic? the shifted operand's def, or any use of the result.
        let is_arith = |c: OpCode| matches!(c, OpCode::IntAdd | OpCode::IntSub | OpCode::IntMult);
        let in0 = data.op(op).input(0).unwrap();
        let input_arith = data.vn(in0).def.is_some_and(|d| is_arith(data.op(d).code()));
        let out = data.op(op).output;
        let desc_arith =
            out.is_some_and(|o| data.vn(o).descend.iter().any(|&d| is_arith(data.op(d).code())));
        if !input_arith && !desc_arith {
            return 0;
        }
        let out_size = data.vn(out.unwrap()).size;
        let nc = data.new_const(out_size, 1u64 << val);
        data.op_set_input(op, 1, nc);
        data.op_set_opcode(op, OpCode::IntMult);
        1
    }
}

/// Express `vn` as `(base, coefficient)` — Ghidra's `getMultCoeff`: `base * c` for an
/// `INT_MULT` by a constant, `base * 2^k` for an `INT_LEFT` by a constant (so a shift-add
/// like `(x<<2)+x` collects to `x*5`), else `(vn, 1)`. Assumes `RuleTermOrder` put the
/// constant in slot 1.
fn as_term(data: &Funcdata, vn: VarnodeId) -> (VarnodeId, i64) {
    if let Some(def) = data.vn(vn).def {
        let o = data.op(def);
        if o.num_inputs() == 2 {
            if let Some(c) = o.input(1) {
                if data.vn(c).is_constant() {
                    let cv = data.vn(c).constant_value();
                    match o.code() {
                        OpCode::IntMult => return (o.input(0).unwrap(), cv as i64),
                        OpCode::IntLeft if cv < 63 => return (o.input(0).unwrap(), 1i64 << cv),
                        _ => {}
                    }
                }
            }
        }
    }
    (vn, 1)
}

/// Collect like additive terms (Ghidra's `RuleCollectTerms`, binary form): `a*c1 + a*c2`
/// → `a*(c1+c2)` (covering `a + a` → `a*2` and `a*c + a` → `a*(c+1)`). Deeper additive
/// trees collapse pairwise as the pool iterates to fixpoint. The full N-ary tree gather is
/// the remaining generalization.
pub struct RuleCollectTerms;

impl Rule for RuleCollectTerms {
    fn name(&self) -> &str {
        "collectterms"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAdd, OpCode::IntSub]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let (bx, cx) = as_term(data, data.op(op).input(0).unwrap());
        let (by, cy) = as_term(data, data.op(op).input(1).unwrap());
        if bx != by {
            return 0;
        }
        // a*cx ± a*cy  →  a*(cx ± cy)
        let combined = if data.op(op).code() == OpCode::IntSub {
            cx.wrapping_sub(cy)
        } else {
            cx.wrapping_add(cy)
        };
        let out_size = data.vn(data.op(op).output.unwrap()).size;
        match combined {
            0 => {
                let z = data.new_const(out_size, 0);
                data.op_set_opcode(op, OpCode::Copy);
                data.op_set_all_input(op, &[z]);
            }
            1 => {
                data.op_set_opcode(op, OpCode::Copy);
                data.op_set_all_input(op, &[bx]);
            }
            c => {
                let coef = data.new_const(out_size, c as u64);
                data.op_set_opcode(op, OpCode::IntMult);
                data.op_set_all_input(op, &[bx, coef]);
            }
        }
        1
    }
}

/// Copy propagation (Ghidra's `RulePropagateCopy`): if an op reads `vn` where
/// `vn = COPY(invn)`, read `invn` directly. The COPY's output loses this use and dead-code
/// removes it. Applied to every op. (Skips propagating a constant *into* a marker so phis
/// keep their structure; the addrtied/addrforce guards await those flags.)
pub struct RulePropagateCopy;

impl Rule for RulePropagateCopy {
    fn name(&self) -> &str {
        "propagatecopy"
    }
    fn oplist(&self) -> Vec<OpCode> {
        Vec::new() // every op
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        for i in 0..data.op(op).num_inputs() {
            let vn = data.op(op).input(i).unwrap();
            let Some(def) = data.vn(vn).def else { continue };
            if data.op(def).code() != OpCode::Copy {
                continue;
            }
            let invn = data.op(def).input(0).unwrap();
            if invn == vn || data.vn(invn).is_free() {
                continue; // self-copy, or source not heritage-known
            }
            if data.op(op).is_marker() && data.vn(invn).is_constant() {
                continue; // don't fold a constant into a MULTIEQUAL/INDIRECT
            }
            data.op_set_input(op, i, invn);
            return 1;
        }
        0
    }
}

fn is_const0(data: &Funcdata, v: VarnodeId) -> bool {
    data.vn(v).is_constant() && data.vn(v).constant_value() == 0
}

/// Whether two varnodes denote the same value — the same id, or equal-valued constants.
/// (Constants aren't interned, so distinct constant varnodes can share a value; Ghidra's
/// `*vn` comparison treats them as equal.)
fn same_value(data: &Funcdata, a: VarnodeId, b: VarnodeId) -> bool {
    a == b || {
        let (va, vb) = (data.vn(a), data.vn(b));
        va.is_constant() && vb.is_constant() && va.size == vb.size
            && va.constant_value() == vb.constant_value()
    }
}

/// Does `xvn` compute `avn - bvn`? Directly as `INT_SUB(avn, bvn)`, or as `INT_ADD(avn, c)`
/// with `c` the (constant) negation of `bvn`.
fn subtract_matches(data: &Funcdata, xvn: VarnodeId, avn: VarnodeId, bvn: VarnodeId) -> bool {
    let Some(def) = data.vn(xvn).def else { return false };
    let o = data.op(def);
    if o.num_inputs() != 2 || !same_value(data, o.input(0).unwrap(), avn) {
        return false;
    }
    match o.code() {
        OpCode::IntSub => same_value(data, o.input(1).unwrap(), bvn),
        OpCode::IntAdd => {
            let Some(c) = o.input(1) else { return false };
            if !data.vn(c).is_constant() || !data.vn(bvn).is_constant() {
                return false;
            }
            let size = data.vn(xvn).size;
            let mask = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
            data.vn(c).constant_value().wrapping_add(data.vn(bvn).constant_value()) & mask == 0
        }
        _ => false,
    }
}

/// Simplify signed comparisons built from `INT_SBORROW` (Ghidra's `RuleSborrow`). The x86
/// signed-compare flag idiom `sborrow(V,W) != ((V-W) s< 0)` is exactly `V s< W` (and the
/// `0 s< (V-W)` / `INT_EQUAL` variants give the swapped operands and `s<=`); also
/// `sborrow(V,0) => false`.
pub struct RuleSborrow;

impl Rule for RuleSborrow {
    fn name(&self) -> &str {
        "sborrow"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSborrow]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let avn = data.op(op).input(0).unwrap();
        let bvn = data.op(op).input(1).unwrap();
        if is_const0(data, bvn) {
            let z = data.new_const(1, 0);
            data.op_set_opcode(op, OpCode::Copy);
            data.op_set_all_input(op, &[z]);
            return 1;
        }
        let Some(svn) = data.op(op).output else { return 0 };
        for compop in data.vn(svn).descend.clone() {
            let cc = data.op(compop).code();
            if (cc != OpCode::IntEqual && cc != OpCode::IntNotequal) || data.op(compop).num_inputs() != 2 {
                continue;
            }
            let (i0, i1) = (data.op(compop).input(0).unwrap(), data.op(compop).input(1).unwrap());
            let cvn = if i0 == svn { i1 } else { i0 };
            let Some(signdef) = data.vn(cvn).def else { continue };
            if data.op(signdef).code() != OpCode::IntSless || data.op(signdef).num_inputs() != 2 {
                continue;
            }
            let (s0, s1) = (data.op(signdef).input(0).unwrap(), data.op(signdef).input(1).unwrap());
            let zside = if is_const0(data, s0) {
                0
            } else if is_const0(data, s1) {
                1
            } else {
                continue;
            };
            let xvn = if zside == 0 { s1 } else { s0 };
            if !subtract_matches(data, xvn, avn, bvn) {
                continue;
            }
            // NOTEQUAL ⇒ V s< W (avn at 1-zside); EQUAL ⇒ V s<= W (avn at zside)
            let (newcode, slot_a) = if cc == OpCode::IntNotequal {
                (OpCode::IntSless, 1 - zside)
            } else {
                (OpCode::IntSlessequal, zside)
            };
            let mut inputs = [avn; 2];
            inputs[slot_a] = avn;
            inputs[1 - slot_a] = bvn;
            data.op_set_opcode(compop, newcode);
            data.op_set_all_input(compop, &inputs);
            return 1;
        }
        0
    }
}

/// Compare against zero through a subtraction (Ghidra's `RuleEqual2Zero`): `(a - b) == 0`
/// → `a == b`, and `(a + c) == 0` → `a == -c` for a constant `c` (likewise INT_NOTEQUAL).
/// Normalises the flag-derived equality so [`RuleLessEqual`] can match it against the less.
pub struct RuleEqual2Zero;

impl Rule for RuleEqual2Zero {
    fn name(&self) -> &str {
        "equal2zero"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntEqual, OpCode::IntNotequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let (i0, i1) = (data.op(op).input(0).unwrap(), data.op(op).input(1).unwrap());
        let other = if is_const0(data, i1) {
            i0
        } else if is_const0(data, i0) {
            i1
        } else {
            return 0;
        };
        let Some(def) = data.vn(other).def else { return 0 };
        if data.op(def).num_inputs() != 2 {
            return 0;
        }
        let (a, b) = (data.op(def).input(0).unwrap(), data.op(def).input(1).unwrap());
        match data.op(def).code() {
            OpCode::IntSub => {
                data.op_set_all_input(op, &[a, b]);
                1
            }
            OpCode::IntAdd if data.vn(b).is_constant() => {
                let size = data.vn(b).size;
                let neg = data.vn(b).constant_value().wrapping_neg();
                let nc = data.new_const(size, neg);
                data.op_set_all_input(op, &[a, nc]);
                1
            }
            _ => 0,
        }
    }
}

/// Combine a less-than and an equality into less-than-or-equal (Ghidra's `RuleLessEqual`):
/// `V < W || V == W` → `V <= W`, and `V < W || V != W` → `V != W`. Handles signed and
/// unsigned, operands in either order. This collapses the x86 `jle`/`jbe` flag idiom (the
/// `ZF || (SF != OF)` pair) into a single comparison.
pub struct RuleLessEqual;

impl Rule for RuleLessEqual {
    fn name(&self) -> &str {
        "lessequal"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::BoolOr]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let i0 = data.op(op).input(0).unwrap();
        let i1 = data.op(op).input(1).unwrap();
        let code_of = |v: VarnodeId| data.vn(v).def.map(|d| data.op(d).code());
        let is_less = |c: Option<OpCode>| matches!(c, Some(OpCode::IntLess | OpCode::IntSless));
        let is_eq = |c: Option<OpCode>| matches!(c, Some(OpCode::IntEqual | OpCode::IntNotequal));
        let (less_v, equal_v) = if is_less(code_of(i0)) && is_eq(code_of(i1)) {
            (i0, i1)
        } else if is_less(code_of(i1)) && is_eq(code_of(i0)) {
            (i1, i0)
        } else {
            return 0;
        };
        let less_op = data.vn(less_v).def.unwrap();
        let equal_op = data.vn(equal_v).def.unwrap();
        if data.op(less_op).num_inputs() != 2 || data.op(equal_op).num_inputs() != 2 {
            return 0;
        }
        let (l0, l1) = (data.op(less_op).input(0).unwrap(), data.op(less_op).input(1).unwrap());
        let (e0, e1) = (data.op(equal_op).input(0).unwrap(), data.op(equal_op).input(1).unwrap());
        let matches = (same_value(data, l0, e0) && same_value(data, l1, e1))
            || (same_value(data, l0, e1) && same_value(data, l1, e0));
        if !matches {
            return 0;
        }
        if data.op(equal_op).code() == OpCode::IntNotequal {
            // V < W || V != W  =>  V != W
            let eqout = data.op(equal_op).output.unwrap();
            data.op_set_opcode(op, OpCode::Copy);
            data.op_set_all_input(op, &[eqout]);
        } else {
            let newcode = if data.op(less_op).code() == OpCode::IntSless {
                OpCode::IntSlessequal
            } else {
                OpCode::IntLessequal
            };
            data.op_set_opcode(op, newcode);
            data.op_set_all_input(op, &[l0, l1]);
        }
        1
    }
}

/// `RuleSelectCse` (`ruleaction.cc`): common-subexpression elimination over the duplicated
/// ops that heritage's read-size normalization (and div-correction) produce — `SUBPIECE` and
/// `INT_SRIGHT`. Two siblings reading the same varnode with depth-1 functional equality (same
/// opcode, equal operands) collapse to one, so later rules (signed-compare idioms, `x&x`,
/// `x^x`) see the *same* varnode instead of two equal-but-distinct copies.
pub struct RuleSelectCse;

impl Rule for RuleSelectCse {
    fn name(&self) -> &str {
        "selectcse"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece, OpCode::IntSright]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (Some(vn), Some(out), Some(parent)) =
            (data.op(op).input(0), data.op(op).output, data.op(op).parent)
        else {
            return 0;
        };
        let opc = data.op(op).code();
        for other in data.vn(vn).descend.clone() {
            if other == op || data.op(other).code() != opc || data.op(other).parent != Some(parent) {
                continue;
            }
            let Some(other_out) = data.op(other).output else { continue };
            // Ghidra `PcodeOp::isCseMatch` (op.cc): outputs must be the same size. Two SUBPIECEs
            // reading the same varnode at the same offset but truncating to different widths (an
            // x86 AL vs EAX sub-register read) are NOT the same value and must not be merged —
            // merging one into the other yields a size-inconsistent op. (mosura's other CSE path,
            // `cse_find_in_block` via `functional_equality_level0`, already guards on size.)
            if data.vn(out).size != data.vn(other_out).size {
                continue;
            }
            // depth-1 functional equality: same operands (same varnode or same constant value)
            if data.op(op).num_inputs() != data.op(other).num_inputs() {
                continue;
            }
            let eq = (0..data.op(op).num_inputs())
                .all(|i| same_value(data, data.op(op).input(i).unwrap(), data.op(other).input(i).unwrap()));
            if !eq {
                continue;
            }
            // keep the earlier op in the block; repoint the later's uses and destroy it
            let pos = |o: OpId| data.block(parent).ops.iter().position(|&x| x == o).unwrap_or(usize::MAX);
            let (keep_out, kill, kill_out) =
                if pos(op) <= pos(other) { (out, other, other_out) } else { (other_out, op, out) };
            for u in data.vn(kill_out).descend.clone() {
                for slot in 0..data.op(u).num_inputs() {
                    if data.op(u).input(slot) == Some(kill_out) {
                        data.op_set_input(u, slot, keep_out);
                    }
                }
            }
            data.op_destroy(kill);
            return 1;
        }
        0
    }
}

/// `RuleSubExtComm` (`ruleaction.cc`): push a `SUBPIECE` through a `ZEXT`/`SEXT`. When the
/// piece never reaches the extended bits (`out_size + subcut <= invn_size`) it is a piece of
/// the pre-extension value directly — and when it exactly covers that value it collapses to a
/// `COPY`. This cancels the `SUBPIECE(ZEXT(reg:4))` round-trips that heritage's sub-register
/// canonicalization introduces (the bulk of the IR-op gap vs Ghidra).
pub struct RuleSubExtComm;

impl Rule for RuleSubExtComm {
    fn name(&self) -> &str {
        "subextcomm"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (Some(base), Some(cut_v), Some(out)) =
            (data.op(op).input(0), data.op(op).input(1), data.op(op).output)
        else {
            return 0;
        };
        let Some(subcut) = data.vn(cut_v).is_constant().then(|| data.vn(cut_v).constant_value()) else {
            return 0;
        };
        let Some(extop) = data.vn(base).def else { return 0 };
        let ec = data.op(extop).code();
        if !matches!(ec, OpCode::IntZext | OpCode::IntSext) {
            return 0;
        }
        let Some(invn) = data.op(extop).input(0) else { return 0 };
        if data.vn(invn).is_constant() {
            return 0;
        }
        let out_size = data.vn(out).size as u64;
        let in_size = data.vn(invn).size as u64;
        if out_size + subcut <= in_size {
            // the piece never touches the extended bits — it's a piece of `invn` directly
            data.op_set_input(op, 0, invn);
            if in_size == out_size {
                data.op_remove_input(op, 1);
                data.op_set_opcode(op, OpCode::Copy);
            }
            return 1;
        }
        // reaching into the extension at a nonzero offset needs a fresh SUBPIECE op (Ghidra
        // splits it); leave those alone. At offset 0 the result is just `ext(invn)`.
        if subcut != 0 {
            return 0;
        }
        data.op_remove_input(op, 1);
        data.op_set_opcode(op, ec);
        data.op_set_input(op, 0, invn);
        1
    }
}

/// `RuleHumptyDumpty` (`ruleaction.cc:5214`): simplify break-and-rejoin —
/// `concat(sub(V,c), sub(V,0)) => V`, and the partial variant `concat(sub(V,c), sub(V,d)) =>
/// sub(V,d)`. This rejoins the SUBPIECE pieces that heritage refinement (`refine_overlaps`) splits
/// an overlapping SIMD/sub-register write into — the high `PIECE` input is `sub(V,c)`, the low is
/// `sub(V,d)`, and when they tile `V` exactly the whole thing collapses back to `V`.
pub struct RuleHumptyDumpty;

impl Rule for RuleHumptyDumpty {
    fn name(&self) -> &str {
        "humptydumpty"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Piece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        // PIECE in0 is the most-significant ("put together") part, in1 the least.
        let (Some(vn1), Some(vn2)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        let (Some(sub1), Some(sub2)) = (data.vn(vn1).def, data.vn(vn2).def) else {
            return 0;
        };
        if data.op(sub1).code() != OpCode::Subpiece || data.op(sub2).code() != OpCode::Subpiece {
            return 0;
        }
        let (Some(root), Some(root2)) = (data.op(sub1).input(0), data.op(sub2).input(0)) else {
            return 0;
        };
        if root != root2 {
            return 0; // pieces of the same whole
        }
        let (Some(pos1v), Some(pos2v)) = (data.op(sub1).input(1), data.op(sub2).input(1)) else {
            return 0;
        };
        if !data.vn(pos1v).is_constant() || !data.vn(pos2v).is_constant() {
            return 0;
        }
        let pos1 = data.vn(pos1v).constant_value();
        let pos2 = data.vn(pos2v).constant_value();
        let size1 = data.vn(vn1).size as u64;
        let size2 = data.vn(vn2).size as u64;
        if pos1 != pos2 + size2 {
            return 0; // pieces do not match up
        }
        if pos2 == 0 && size1 + size2 == data.vn(root).size as u64 {
            // pieced together the whole thing → COPY(root)
            data.op_remove_input(op, 1);
            data.op_set_input(op, 0, root);
            data.op_set_opcode(op, OpCode::Copy);
        } else {
            // pieced together a larger part of the whole → SUBPIECE(root, pos2)
            let pos2_size = data.vn(pos2v).size;
            data.op_set_input(op, 0, root);
            let c = data.new_const(pos2_size, pos2);
            data.op_set_input(op, 1, c);
            data.op_set_opcode(op, OpCode::Subpiece);
        }
        1
    }
}

/// `RuleDumptyHump` (`ruleaction.cc:5265`): simplify join-then-break — `sub(concat(V,W), c)` draws
/// from whichever piece the slice falls in: `sub(concat(V,W), 0) => W`, `sub(concat(V,W), |W|) => V`,
/// or `sub(V, c)` for an interior slice. This is what cleans up a SUBPIECE (or a cast, a low slice)
/// taken of a PIECE that heritage refinement built — e.g. `(uint4)CONCAT(hi, value) => value` for a
/// SIMD scalar move through a vector register.
pub struct RuleDumptyHump;

impl Rule for RuleDumptyHump {
    fn name(&self) -> &str {
        "dumptyhump"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(base) = data.op(op).input(0) else { return 0 };
        let Some(pieceop) = data.vn(base).def else { return 0 };
        if data.op(pieceop).code() != OpCode::Piece {
            return 0;
        }
        let Some(offv) = data.op(op).input(1) else { return 0 };
        if !data.vn(offv).is_constant() {
            return 0;
        }
        let mut offset = data.vn(offv).constant_value();
        let outsize = data.vn(data.op(op).output.unwrap()).size as u64;
        // PIECE in0 = high part, in1 = low part.
        let (Some(vn1), Some(vn2)) = (data.op(pieceop).input(0), data.op(pieceop).input(1)) else {
            return 0;
        };
        let v2size = data.vn(vn2).size as u64;
        let vn = if offset < v2size {
            // the slice draws from the low piece
            if offset + outsize > v2size {
                return 0; // ... and also from the high piece — can't simplify
            }
            vn2
        } else {
            offset -= v2size; // offset relative to the high piece
            vn1
        };
        if data.vn(vn).is_free() && !data.vn(vn).is_constant() {
            return 0;
        }
        if offset == 0 && outsize == data.vn(vn).size as u64 {
            // eliminate SUBPIECE and PIECE altogether → COPY(vn)
            data.op_remove_input(op, 1);
            data.op_set_input(op, 0, vn);
            data.op_set_opcode(op, OpCode::Copy);
        } else {
            // eliminate the PIECE, adjust the SUBPIECE offset → SUBPIECE(vn, offset)
            data.op_set_input(op, 0, vn);
            let c = data.new_const(4, offset);
            data.op_set_input(op, 1, c);
        }
        1
    }
}

/// `a & a`, `a | a` → `a`; `a ^ a`, `a - a` → `0` (one varnode). Ghidra's identity folds; with
/// CSE merging duplicate `SUBPIECE`s, `SUBPIECE(x) ^ SUBPIECE(x)` becomes `s ^ s` → `0`.
pub struct RuleIdempotent;

impl Rule for RuleIdempotent {
    fn name(&self) -> &str {
        "idempotent"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd, OpCode::IntOr, OpCode::BoolAnd, OpCode::BoolOr, OpCode::IntXor, OpCode::IntSub]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 || data.op(op).input(0) != data.op(op).input(1) {
            return 0;
        }
        let a = data.op(op).input(0).unwrap();
        let out_size = data.vn(data.op(op).output.unwrap()).size;
        let to_zero = matches!(data.op(op).code(), OpCode::IntXor | OpCode::IntSub);
        let repl = if to_zero { data.new_const(out_size, 0) } else { a };
        data.op_set_opcode(op, OpCode::Copy);
        data.op_set_all_input(op, &[repl]);
        1
    }
}

/// Fold a chained constant multiply: `(x * c1) * c2` → `x * (c1*c2)`. Ghidra normalises
/// multiplies this way; it also lets `(x/6)*3*2` collapse to `(x/6)*6` so the modulo form
/// is recognised.
pub struct RuleMultMult;

impl Rule for RuleMultMult {
    fn name(&self) -> &str {
        "multmult"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntMult]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let (a, b) = (data.op(op).input(0).unwrap(), data.op(op).input(1).unwrap());
        for (inner_v, c2_v) in [(a, b), (b, a)] {
            if !data.vn(c2_v).is_constant() {
                continue;
            }
            let c2 = data.vn(c2_v).constant_value();
            let Some(inner) = data.vn(inner_v).def else { continue };
            if data.op(inner).code() != OpCode::IntMult || data.op(inner).num_inputs() != 2 {
                continue;
            }
            let (i0, i1) = (data.op(inner).input(0).unwrap(), data.op(inner).input(1).unwrap());
            for (x, c1_v) in [(i0, i1), (i1, i0)] {
                if data.vn(c1_v).is_constant() {
                    let size = data.vn(data.op(op).output.unwrap()).size;
                    let prod = data.new_const(size, data.vn(c1_v).constant_value().wrapping_mul(c2));
                    data.op_set_all_input(op, &[x, prod]);
                    return 1;
                }
            }
        }
        0
    }
}

/// `RuleBoolNegate`: a negated comparison is the complementary comparison —
/// `!(a == b)` → `a != b`, `!(a < b)` → `b <= a`, etc. Comparisons are 0/1, so the rewrite
/// is exact; it un-nests negations the structurer can't reach (inside `BOOL_AND`/`BOOL_OR`).
pub struct RuleBoolNegate;

impl Rule for RuleBoolNegate {
    fn name(&self) -> &str {
        "boolnegate"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::BoolNegate]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(cmp) = data.op(op).input(0).and_then(|v| data.vn(v).def) else { return 0 };
        let (flipped, swap) = match data.op(cmp).code() {
            OpCode::IntEqual => (OpCode::IntNotequal, false),
            OpCode::IntNotequal => (OpCode::IntEqual, false),
            OpCode::IntLess => (OpCode::IntLessequal, true),
            OpCode::IntLessequal => (OpCode::IntLess, true),
            OpCode::IntSless => (OpCode::IntSlessequal, true),
            OpCode::IntSlessequal => (OpCode::IntSless, true),
            _ => return 0,
        };
        let (a, b) = (data.op(cmp).input(0).unwrap(), data.op(cmp).input(1).unwrap());
        data.op_set_opcode(op, flipped);
        let ins = if swap { [b, a] } else { [a, b] };
        data.op_set_all_input(op, &ins);
        1
    }
}

/// Ghidra `PcodeOp::booloutput` — the opcodes whose output is a 1-bit boolean value (the `TypeOp`
/// constructors that set `PcodeOp::booloutput`, typeop.cc): the integer/float comparisons, the
/// carry/borrow flag ops, and the `BOOL_*` / `FLOAT_NAN` ops.
fn is_booloutput(opc: OpCode) -> bool {
    use OpCode::*;
    matches!(
        opc,
        IntEqual
            | IntNotequal
            | IntLess
            | IntLessequal
            | IntSless
            | IntSlessequal
            | IntCarry
            | IntScarry
            | IntSborrow
            | BoolNegate
            | BoolXor
            | BoolAnd
            | BoolOr
            | FloatEqual
            | FloatNotequal
            | FloatLess
            | FloatLessequal
            | FloatNan
    )
}

/// Ghidra `Varnode::isBooleanValue` (varnode.cc:942) + `PcodeOp::isCalculatedBool` (op.hh:211): a
/// written Varnode holds a boolean iff its defining op produces a 1-bit boolean output. Ghidra's
/// `isCalculatedBool` is `(calculated_bool | booloutput) != 0`; mosura does not track the dynamic
/// `calculated_bool` flag, so we test the static `booloutput` opcode set ([`is_booloutput`]). For an
/// unwritten Varnode Ghidra returns true only for a typelocked 1-byte `bool` input when type
/// recovery is on (`useAnnotation`); the simplification pool runs before type recovery starts, so we
/// mirror the `false` result there.
fn is_boolean_value(data: &Funcdata, vn: VarnodeId) -> bool {
    let v = data.vn(vn);
    if !v.is_written() {
        return false;
    }
    is_booloutput(data.op(v.def.unwrap()).code())
}

/// Ghidra `RuleLogic2Bool` (ruleaction.cc:3118): convert a logical (bitwise) operator on boolean
/// inputs to the boolean operator — `V & W => V && W`, `V | W => V || W`, `V ^ W => V != W` (BOOL_XOR).
/// Both inputs must be booleans ([`is_boolean_value`]); a constant `0`/`1` on the second input also
/// counts (a larger constant rules it out). The rewrite is exact (booleans are 0/1) and lets the
/// structurer and downstream bool rules see `||`/`&&` instead of the bit-smeared flag web.
pub struct RuleLogic2Bool;

impl Rule for RuleLogic2Bool {
    fn name(&self) -> &str {
        "logic2bool"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd, OpCode::IntOr, OpCode::IntXor]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (Some(in0), Some(in1)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        if !is_boolean_value(data, in0) {
            return 0;
        }
        if data.vn(in1).is_constant() {
            if data.vn(in1).constant_value() > 1 {
                return 0;
            }
        } else if !is_boolean_value(data, in1) {
            return 0;
        }
        let bool_opc = match data.op(op).code() {
            OpCode::IntAnd => OpCode::BoolAnd,
            OpCode::IntOr => OpCode::BoolOr,
            OpCode::IntXor => OpCode::BoolXor,
            _ => return 0,
        };
        data.op_set_opcode(op, bool_opc);
        1
    }
}

/// Ghidra `Varnode::loneDescend` (varnode.cc): the single op reading `vn`, or `None` if it has
/// zero or more than one reader. (Descendant lists are kept exact by the op-mutation helpers, so a
/// rewritten-away or removed reader no longer counts.)
fn lone_descend(data: &Funcdata, vn: VarnodeId) -> Option<OpId> {
    let d = &data.vn(vn).descend;
    (d.len() == 1).then(|| d[0])
}

/// Ghidra `RuleOrCompare` (ruleaction.cc:10785): simplify an `INT_OR` that feeds only
/// comparisons against constant 0.
///   - `(V | W) == 0`  =>  `(V == 0) && (W == 0)`
///   - `(V | W) != 0`  =>  `(V != 0) || (W != 0)`
///
/// Fires only when every use of the OR output is an `==`/`!=` whose second input is the constant 0,
/// and both `V` and `W` are in SSA form (not free). Each such compare is rewritten into a
/// BOOL_AND / BOOL_OR of the two per-operand compares. This breaks a bit-packed
/// `(a*2 | b<<7) != 0` flag-smear into the independent comparisons — the foundation for recovering
/// `a || b` (with [`RuleShiftCompare`], [`RuleZextEliminate`], [`RuleBooleanNegate`]).
pub struct RuleOrCompare;

impl Rule for RuleOrCompare {
    fn name(&self) -> &str {
        "orcompare"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntOr]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(outvn) = data.op(op).output else { return 0 };
        let descend = data.vn(outvn).descend.clone();
        // hasCompares: at least one use, and every use is `==`/`!=` against constant 0
        if descend.is_empty() {
            return 0;
        }
        for &comp in &descend {
            let opc = data.op(comp).code();
            if opc != OpCode::IntEqual && opc != OpCode::IntNotequal {
                return 0;
            }
            let Some(c) = data.op(comp).input(1) else { return 0 };
            if !is_const0(data, c) {
                return 0;
            }
        }
        let (Some(v), Some(w)) = (data.op(op).input(0), data.op(op).input(1)) else { return 0 };
        // make sure V and W are in SSA form
        if data.vn(v).is_free() || data.vn(w).is_free() {
            return 0;
        }
        let (vsize, wsize) = (data.vn(v).size, data.vn(w).size);
        for comp in descend {
            let opc = data.op(comp).code();
            let pc = data.op(comp).seqnum.pc;
            let zero_v = data.new_const(vsize, 0);
            let zero_w = data.new_const(wsize, 0);
            let uniq = data.num_ops() as u32;
            let eq_v = data.new_op(opc, SeqNum { pc, uniq }, vec![v, zero_v]);
            let eq_v_out = data.new_output_unique(eq_v, 1);
            let uniq = data.num_ops() as u32;
            let eq_w = data.new_op(opc, SeqNum { pc, uniq }, vec![w, zero_w]);
            let eq_w_out = data.new_output_unique(eq_w, 1);
            // make sure the comparisons' output is already defined (inserted before the compare)
            data.op_insert_before(eq_v, comp);
            data.op_insert_before(eq_w, comp);
            // INT_EQUAL becomes BOOL_AND; INT_NOTEQUAL becomes BOOL_OR
            let conn = if opc == OpCode::IntEqual { OpCode::BoolAnd } else { OpCode::BoolOr };
            data.op_set_opcode(comp, conn);
            data.op_set_all_input(comp, &[eq_v_out, eq_w_out]);
        }
        1
    }
}

/// Ghidra `RuleShiftCompare` (ruleaction.cc:2044): strip a shift/scale from a comparison when it
/// loses no information.
///   - `V >> c == d`  =>  `V == (d << c)` (and likewise `V / 2^k`)
///   - `V << c == d`  =>  `V == (d >> c)`, or — if the left-shift would lose high bits — an
///     `(V & mask) == (d >> c)` (and likewise `V * 2^k`)
///
/// Works on both `INT_EQUAL` and `INT_NOTEQUAL`. The non-zero mask of the shifted value
/// ([`Varnode::get_nzmask`]) is what proves no information is lost. This collapses the
/// `(a==10)*2 == 0` / `(b==0x14)<<7 == 0` forms that `RuleOrCompare` leaves behind into bare
/// `(a==10) == 0` / `(b==0x14) == 0` compares.
pub struct RuleShiftCompare;

impl Rule for RuleShiftCompare {
    fn name(&self) -> &str {
        "shiftcompare"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntEqual, OpCode::IntNotequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (Some(shiftvn), Some(constvn)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        if !data.vn(constvn).is_constant() {
            return 0;
        }
        if !data.vn(shiftvn).is_written() {
            return 0;
        }
        let shiftop = data.vn(shiftvn).def.unwrap();
        let opc = data.op(shiftop).code();
        let Some(savn) = data.op(shiftop).input(1) else { return 0 };
        let (isleft, sa): (bool, u32) = match opc {
            OpCode::IntLeft => {
                if !data.vn(savn).is_constant() {
                    return 0;
                }
                (true, data.vn(savn).constant_value() as u32)
            }
            OpCode::IntRight => {
                if !data.vn(savn).is_constant() {
                    return 0;
                }
                // A right shift is a likely shift out of a bitfield, which we want to keep — only
                // apply when we know we will eliminate the shifted variable.
                if lone_descend(data, shiftvn) != Some(op) {
                    return 0;
                }
                (false, data.vn(savn).constant_value() as u32)
            }
            OpCode::IntMult => {
                if !data.vn(savn).is_constant() {
                    return 0;
                }
                let val = data.vn(savn).constant_value();
                let s = val.trailing_zeros();
                if (val >> s) != 1 {
                    return 0; // not multiplying by a power of 2
                }
                (true, s)
            }
            OpCode::IntDiv => {
                if !data.vn(savn).is_constant() {
                    return 0;
                }
                let val = data.vn(savn).constant_value();
                let s = val.trailing_zeros();
                if (val >> s) != 1 {
                    return 0; // not dividing by a power of 2
                }
                if lone_descend(data, shiftvn) != Some(op) {
                    return 0;
                }
                (false, s)
            }
            _ => return 0,
        };
        if sa == 0 {
            return 0;
        }
        let mainvn = data.op(shiftop).input(0).unwrap();
        if data.vn(mainvn).is_free() {
            return 0;
        }
        if data.vn(mainvn).size > 8 {
            return 0; // uintb is 64-bit (Ghidra's `sizeof(uintb)` guard)
        }
        let constval = data.vn(constvn).constant_value();
        let nzmask = data.vn(mainvn).get_nzmask();
        let shiftsize = data.vn(shiftvn).size;
        let constsize = data.vn(constvn).size;
        let smask = super::nzmask::calc_mask(shiftsize);
        let newconst: u64;
        if isleft {
            newconst = constval >> sa;
            if (newconst << sa) != constval {
                return 0; // information lost in constval
            }
            let tmp = (nzmask << sa) & smask;
            if (tmp >> sa) != nzmask {
                // information is lost in main: replace the LEFT with an AND mask. This must be the
                // lone use of the shift.
                if lone_descend(data, shiftvn) != Some(op) {
                    return 0;
                }
                let sa2 = 8 * shiftsize - sa;
                let m = 1u64.checked_shl(sa2).unwrap_or(0).wrapping_sub(1);
                let newmask = data.new_const(constsize, m);
                let pc = data.op(op).seqnum.pc;
                let uniq = data.num_ops() as u32;
                let newop = data.new_op(OpCode::IntAnd, SeqNum { pc, uniq }, vec![mainvn, newmask]);
                let newtmp = data.new_output_unique(newop, constsize);
                data.op_insert_before(newop, shiftop);
                let nc = data.new_const(constsize, newconst);
                data.op_set_input(op, 0, newtmp);
                data.op_set_input(op, 1, nc);
                return 1;
            }
        } else {
            if ((nzmask >> sa) << sa) != nzmask {
                return 0; // information is lost in main
            }
            newconst = (constval << sa) & smask;
            if (newconst >> sa) != constval {
                return 0; // information is lost in constval
            }
        }
        let nc = data.new_const(constsize, newconst);
        data.op_set_input(op, 0, mainvn);
        data.op_set_input(op, 1, nc);
        1
    }
}

/// Ghidra `RuleZextEliminate` (ruleaction.cc:2471): eliminate an `INT_ZEXT` in a comparison when
/// the constant operand loses no non-zero bits.
///   - `zext(V) == c`  =>  `V == c`   (and `!=`, `<`, `<=`)
///
/// The zero-extension must be the lone use of the comparison's input. This drops the
/// `zext(a==10) == 0` widening that `RuleShiftCompare` exposes, leaving `(a==10) == 0`.
pub struct RuleZextEliminate;

impl Rule for RuleZextEliminate {
    fn name(&self) -> &str {
        "zexteliminate"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntEqual, OpCode::IntNotequal, OpCode::IntLess, OpCode::IntLessequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (Some(in0), Some(in1)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        let is_zext = |d: &Funcdata, v: VarnodeId| {
            d.vn(v).is_written() && d.op(d.vn(v).def.unwrap()).code() == OpCode::IntZext
        };
        // vn1 is the ZEXTed input, vn2 the other; prefer slot 1 (Ghidra checks getIn(1) first).
        let (vn1, vn2, zextslot, otherslot) = if is_zext(data, in1) {
            (in1, in0, 1usize, 0usize)
        } else if is_zext(data, in0) {
            (in0, in1, 0usize, 1usize)
        } else {
            return 0;
        };
        if !data.vn(vn2).is_constant() {
            return 0;
        }
        let zext = data.vn(vn1).def.unwrap();
        let zin = data.op(zext).input(0).unwrap();
        if !data.vn(zin).is_heritage_known() {
            return 0;
        }
        if lone_descend(data, vn1) != Some(op) {
            return 0; // extension must not be used for anything else
        }
        let smallsize = data.vn(zin).size;
        let val = data.vn(vn2).constant_value();
        // is the zero extension unnecessary? (the constant fits in the small width)
        if smallsize < 8 && (val >> (8 * smallsize)) != 0 {
            return 0;
        }
        let newvn = data.new_const(smallsize, val);
        data.op_set_input(op, zextslot, zin);
        data.op_set_input(op, otherslot, newvn);
        1
    }
}

/// Ghidra `RuleBooleanNegate` (ruleaction.cc:2937): simplify a comparison of a boolean value with
/// `false`/`true`.
///   - `V == false`  =>  `!V`        `V == true`   =>  `V`
///   - `V != false`  =>  `V`         `V != true`   =>  `!V`
///
/// The compared value must be a boolean ([`is_boolean_value`]) and the constant must be 0 or 1. The
/// op is rewritten in place as a BOOL_NEGATE or COPY. This collapses the `(a==10) == 0` form (left
/// by [`RuleZextEliminate`]) into `!(a==10)` — which [`RuleBoolNegate`] then renders as the
/// complementary `a != 10`, so a De-Morgan'd `BOOL_AND` prints as `a || b`.
pub struct RuleBooleanNegate;

impl Rule for RuleBooleanNegate {
    fn name(&self) -> &str {
        "booleannegate"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntNotequal, OpCode::IntEqual]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let opc = data.op(op).code();
        let (Some(subbool), Some(constvn)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        if !data.vn(constvn).is_constant() {
            return 0;
        }
        let val = data.vn(constvn).constant_value();
        if val != 0 && val != 1 {
            return 0;
        }
        let mut negate = opc == OpCode::IntNotequal;
        if val == 0 {
            negate = !negate;
        }
        if !is_boolean_value(data, subbool) {
            return 0;
        }
        data.op_remove_input(op, 1); // remove the constant
        data.op_set_input(op, 0, subbool); // keep the original boolean parameter
        data.op_set_opcode(op, if negate { OpCode::BoolNegate } else { OpCode::Copy });
        1
    }
}

/// Ghidra `RuleShiftPiece` (ruleaction.cc:3753): convert a "shift and add" into a PIECE (CONCAT).
///   `(ext(V) << 8*|W|) {INT_OR|INT_XOR|INT_ADD} ext(W)  =>  CONCAT(V, W)`
/// where the high operand is zero/sign-extended and shifted left by exactly the low operand's bit
/// width. If the extension is wider than the concatenation, the PIECE is re-extended (ZEXT/SEXT).
/// Also folds the CDQ:IDIV self-sign-extension form
///   `(zext(SUB(big,0) s>> (|low|*8-1)) << |low|*8) + zext(SUB(big,0))  =>  sext(SUB(big,0))`.
/// This collapses bit-packed struct assembly (piecestruct's `(a<<0x10)|b` → `CONCAT22(a,b)`).
pub struct RuleShiftPiece;

impl Rule for RuleShiftPiece {
    fn name(&self) -> &str {
        "shiftpiece"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntOr, OpCode::IntXor, OpCode::IntAdd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (Some(a0), Some(a1)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        if !data.vn(a0).is_written() || !data.vn(a1).is_written() {
            return 0;
        }
        let mut shiftop = data.vn(a0).def.unwrap();
        let mut zextloop = data.vn(a1).def.unwrap();
        // The INT_LEFT input is the high piece; if it is the other operand, swap.
        if data.op(shiftop).code() != OpCode::IntLeft {
            if data.op(zextloop).code() != OpCode::IntLeft {
                return 0;
            }
            std::mem::swap(&mut shiftop, &mut zextloop);
        }
        let Some(sav) = data.op(shiftop).input(1) else { return 0 };
        if !data.vn(sav).is_constant() {
            return 0;
        }
        let hiv = data.op(shiftop).input(0).unwrap();
        if !data.vn(hiv).is_written() {
            return 0;
        }
        let zexthiop = data.vn(hiv).def.unwrap();
        let hicode = data.op(zexthiop).code();
        if hicode != OpCode::IntZext && hicode != OpCode::IntSext {
            return 0;
        }
        let vn1 = data.op(zexthiop).input(0).unwrap(); // pre-extension high value
        if data.vn(vn1).is_constant() {
            if data.vn(vn1).size < 8 {
                return 0; // let ZEXT of a small constant collapse naturally
            }
        } else if data.vn(vn1).is_free() {
            return 0;
        }
        let sa = data.vn(sav).constant_value() as u32;
        let vn1_size = data.vn(vn1).size;
        let concatsize = sa + 8 * vn1_size;
        let out = data.op(op).output.unwrap();
        let out_size = data.vn(out).size;
        if out_size * 8 < concatsize {
            return 0;
        }
        if data.op(zextloop).code() != OpCode::IntZext {
            // CDQ:IDIV special case: the high piece is the sign-extension `SUB(big,0) s>> (sz*8-1)`
            // of the low piece, so the whole expression is a sign-extension of the low part.
            if !data.vn(vn1).is_written() {
                return 0;
            }
            let rshift = data.vn(vn1).def.unwrap();
            if data.op(rshift).code() != OpCode::IntSright {
                return 0;
            }
            let Some(rsav) = data.op(rshift).input(1) else { return 0 };
            if !data.vn(rsav).is_constant() {
                return 0;
            }
            let vn2 = data.op(rshift).input(0).unwrap();
            if !data.vn(vn2).is_written() {
                return 0;
            }
            let subop = data.vn(vn2).def.unwrap();
            if data.op(subop).code() != OpCode::Subpiece {
                return 0; // SUBPIECE connects the high and low parts
            }
            let Some(subc) = data.op(subop).input(1) else { return 0 };
            if !(data.vn(subc).is_constant() && data.vn(subc).constant_value() == 0) {
                return 0; // must be the low part
            }
            let bigvn = data.op(zextloop).output.unwrap();
            if data.op(subop).input(0) != Some(bigvn) {
                return 0; // verify the link through SUBPIECE with the low part
            }
            let rsa = data.vn(rsav).constant_value() as u32;
            let vn2_size = data.vn(vn2).size;
            if rsa != vn2_size * 8 - 1 {
                return 0; // arithmetic shift must copy the sign bit through the whole high part
            }
            if (data.vn(bigvn).get_nzmask() >> sa) != 0 {
                return 0; // the original most significant bytes must be zero
            }
            if sa != 8 * vn2_size {
                return 0;
            }
            data.op_set_opcode(op, OpCode::IntSext);
            data.op_set_input(op, 0, vn2);
            data.op_remove_input(op, 1);
            return 1;
        }
        let vn2 = data.op(zextloop).input(0).unwrap(); // low value
        if data.vn(vn2).is_free() {
            return 0;
        }
        let vn2_size = data.vn(vn2).size;
        if sa != 8 * vn2_size {
            return 0;
        }
        if concatsize == out_size * 8 {
            data.op_set_opcode(op, OpCode::Piece);
            data.op_set_input(op, 0, vn1);
            data.op_set_input(op, 1, vn2);
        } else {
            // Extension is wider than the concatenation: build the PIECE, then re-extend it.
            let pc = data.op(op).seqnum.pc;
            let uniq = data.num_ops() as u32;
            let newop = data.new_op(OpCode::Piece, SeqNum { pc, uniq }, vec![vn1, vn2]);
            let newout = data.new_output_unique(newop, concatsize / 8);
            data.op_insert_before(newop, op);
            data.op_set_opcode(op, hicode);
            data.op_remove_input(op, 1);
            data.op_set_input(op, 0, newout);
        }
        1
    }
}

/// Ghidra `RuleAndMask` (ruleaction.cc:302): collapse an unnecessary `INT_AND`.
///   - `V & W  =>  0`  when `nzm(V) & nzm(W) == 0` (the AND can produce no nonzero bit)
///   - `V & c  =>  V`  when the constant `c` covers every nonzero bit of `V` (`nzm(V) & c == nzm(V)`)
/// Uses the non-zero mask to prove the mask is a no-op (e.g. `(uint)char_val & 0xff => char_val`).
/// (Ghidra's third arm — `nzm & getConsume() == 0` — needs per-bit consume tracking, which mosura's
/// whole-varnode dead-code analysis does not model, so it is omitted; that arm only ever removes
/// *more*.)
pub struct RuleAndMask;

impl Rule for RuleAndMask {
    fn name(&self) -> &str {
        "andmask"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        // Re-check the live shape: the pool dispatches on a cached opcode that an earlier rule this
        // pass may have rewritten away from INT_AND.
        if data.op(op).code() != OpCode::IntAnd || data.op(op).num_inputs() != 2 {
            return 0;
        }
        let Some(out) = data.op(op).output else { return 0 };
        let size = data.vn(out).size;
        if size > 8 {
            return 0; // uintb is 64-bit
        }
        let (i0, i1) = (data.op(op).input(0).unwrap(), data.op(op).input(1).unwrap());
        let mask1 = data.vn(i0).get_nzmask();
        let andmask = if mask1 == 0 { 0 } else { mask1 & data.vn(i1).get_nzmask() };
        let vn = if andmask == 0 {
            data.new_const(size, 0)
        } else if andmask == mask1 {
            if !data.vn(i1).is_constant() {
                return 0;
            }
            i0 // the AND keeps every nonzero bit of input(0)
        } else {
            return 0;
        };
        if !data.vn(vn).is_heritage_known() {
            return 0;
        }
        data.op_set_opcode(op, OpCode::Copy);
        data.op_remove_input(op, 1);
        data.op_set_input(op, 0, vn);
        1
    }
}

/// Ghidra `RuleAndZext` (ruleaction.cc:1696): convert `INT_AND` to `INT_ZEXT` where the mask keeps
/// exactly the low bytes of a sign-extension or concatenation:
///   - `sext(X) & mask  =>  zext(X)`   (mask == all-ones over `|X|` bytes)
///   - `concat(Y, X) & mask  =>  zext(X)`
/// This drops the `movsx`+`and` idiom for a packed byte (`(int)char_val & 0xff => (uint)char_val`),
/// exposing the bare extension that [`RuleShiftPiece`] needs to fold the byte into a CONCAT.
pub struct RuleAndZext;

impl Rule for RuleAndZext {
    fn name(&self) -> &str {
        "andzext"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (Some(i0), Some(cvn1)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        if !data.vn(cvn1).is_constant() {
            return 0;
        }
        if !data.vn(i0).is_written() {
            return 0;
        }
        let otherop = data.vn(i0).def.unwrap();
        let rootvn = match data.op(otherop).code() {
            OpCode::IntSext => data.op(otherop).input(0).unwrap(),
            OpCode::Piece => data.op(otherop).input(1).unwrap(), // little-endian low part
            _ => return 0,
        };
        let mask = super::nzmask::calc_mask(data.vn(rootvn).size);
        if mask != data.vn(cvn1).constant_value() {
            return 0;
        }
        if data.vn(rootvn).is_free() {
            return 0;
        }
        if data.vn(rootvn).size > 8 {
            return 0;
        }
        data.op_set_opcode(op, OpCode::IntZext);
        data.op_remove_input(op, 1);
        data.op_set_input(op, 0, rootvn);
        1
    }
}

/// Ghidra `RuleSlessToLess` (ruleaction.cc:2530): convert a signed comparison to an unsigned one when
/// both operands are provably non-negative — `V s< W  =>  V < W` (and `s<=` → `<=`). The non-zero
/// mask proves the sign bit is clear on each operand, so the signed and unsigned orderings agree.
pub struct RuleSlessToLess;

impl Rule for RuleSlessToLess {
    fn name(&self) -> &str {
        "slesstoless"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSless, OpCode::IntSlessequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        // An earlier rule this pass may have rewritten `op` while the pool's cached opcode stayed
        // INT_SLESS/INT_SLESSEQUAL (the pool dispatches on the stale code). Re-check the live shape.
        let new_op = match data.op(op).code() {
            OpCode::IntSless => OpCode::IntLess,
            OpCode::IntSlessequal => OpCode::IntLessequal,
            _ => return 0,
        };
        let vn = data.op(op).input(0).unwrap();
        let sz = data.vn(vn).size;
        if super::nzmask::signbit_negative(data.vn(vn).get_nzmask(), sz) {
            return 0;
        }
        let vn1 = data.op(op).input(1).unwrap();
        if super::nzmask::signbit_negative(data.vn(vn1).get_nzmask(), sz) {
            return 0;
        }
        data.op_set_opcode(op, new_op);
        1
    }
}

/// Ghidra `RulePopcountBoolXor::getBooleanResult` (ruleaction.cc:10399): follow the boolean bit at
/// `bit_pos` back through the shift/extend/concat/mask operations that combined it, returning the
/// single boolean Varnode that produces it. Returns `(None, const_res)`, where `const_res` is 0/1 if
/// the bit resolves to a constant and `-1` when no unique boolean Varnode can be isolated.
fn popcount_boolean_result(
    data: &Funcdata,
    mut vn: VarnodeId,
    mut bit_pos: i32,
) -> (Option<VarnodeId>, i32) {
    let mut mask: u64 = 1u64.checked_shl(bit_pos as u32).unwrap_or(0);
    loop {
        if data.vn(vn).is_constant() {
            let const_res =
                (data.vn(vn).constant_value().checked_shr(bit_pos as u32).unwrap_or(0) & 1) as i32;
            return (None, const_res);
        }
        if !data.vn(vn).is_written() {
            return (None, -1);
        }
        if bit_pos == 0 && data.vn(vn).size == 1 && data.vn(vn).get_nzmask() == mask {
            return (Some(vn), -1);
        }
        let def = data.vn(vn).def.unwrap();
        match data.op(def).code() {
            OpCode::IntAnd => {
                let i1 = data.op(def).input(1).unwrap();
                if !data.vn(i1).is_constant() {
                    return (None, -1);
                }
                vn = data.op(def).input(0).unwrap();
            }
            OpCode::IntXor | OpCode::IntOr => {
                let vn0 = data.op(def).input(0).unwrap();
                let vn1 = data.op(def).input(1).unwrap();
                if data.vn(vn0).get_nzmask() & mask != 0 {
                    if data.vn(vn1).get_nzmask() & mask != 0 {
                        return (None, -1); // no unique path to the bit
                    }
                    vn = vn0;
                } else if data.vn(vn1).get_nzmask() & mask != 0 {
                    vn = vn1;
                } else {
                    return (None, -1);
                }
            }
            OpCode::IntZext | OpCode::IntSext => {
                vn = data.op(def).input(0).unwrap();
                if bit_pos >= data.vn(vn).size as i32 * 8 {
                    return (None, -1);
                }
            }
            OpCode::Subpiece => {
                let sa = data.vn(data.op(def).input(1).unwrap()).constant_value() as i32 * 8;
                bit_pos += sa;
                mask = mask.checked_shl(sa as u32).unwrap_or(0);
                vn = data.op(def).input(0).unwrap();
            }
            OpCode::Piece => {
                let vn0 = data.op(def).input(0).unwrap(); // high half
                let vn1 = data.op(def).input(1).unwrap(); // low half
                let sa = data.vn(vn1).size as i32 * 8;
                if bit_pos >= sa {
                    vn = vn0;
                    bit_pos -= sa;
                    mask = mask.checked_shr(sa as u32).unwrap_or(0);
                } else {
                    vn = vn1;
                }
            }
            OpCode::IntLeft => {
                let vn1 = data.op(def).input(1).unwrap();
                if !data.vn(vn1).is_constant() {
                    return (None, -1);
                }
                let sa = data.vn(vn1).constant_value() as i32;
                if sa > bit_pos {
                    return (None, -1);
                }
                bit_pos -= sa;
                mask = mask.checked_shr(sa as u32).unwrap_or(0);
                vn = data.op(def).input(0).unwrap();
            }
            OpCode::IntRight | OpCode::IntSright => {
                let vn1 = data.op(def).input(1).unwrap();
                if !data.vn(vn1).is_constant() {
                    return (None, -1);
                }
                let sa = data.vn(vn1).constant_value() as i32;
                vn = data.op(def).input(0).unwrap();
                bit_pos += sa;
                if bit_pos >= data.vn(vn).size as i32 * 8 {
                    return (None, -1);
                }
                mask = mask.checked_shl(sa as u32).unwrap_or(0);
            }
            _ => return (None, -1),
        }
    }
}

/// Ghidra `RulePopcountBoolXor` (ruleaction.cc:10273): reduce a POPCOUNT parity check over shifted
/// booleans to the boolean(s) themselves:
///   - `popcount(b1 << #pos) & 1              =>  b1`
///   - `popcount((b1 << #pos1) | (b2 << #pos2)) & 1  =>  b1 ^ b2`
/// The `& 1` masks the low bit (parity), and the non-zero mask of the POPCOUNT input has one or two
/// set bits, each traced back to a boolean by [`popcount_boolean_result`].
pub struct RulePopcountBoolXor;

impl Rule for RulePopcountBoolXor {
    fn name(&self) -> &str {
        "popcountboolxor"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Popcount]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        // Guard against an earlier rule this pass having rewritten `op` (the pool dispatches on the
        // cached opcode, which may be a stale CPUI_POPCOUNT).
        if data.op(op).code() != OpCode::Popcount {
            return 0;
        }
        let Some(out) = data.op(op).output else { return 0 };
        for base_op in data.vn(out).descend.clone() {
            if data.op(base_op).code() != OpCode::IntAnd {
                continue;
            }
            let Some(tmp_vn) = data.op(base_op).input(1) else { continue };
            if !data.vn(tmp_vn).is_constant() {
                continue;
            }
            if data.vn(tmp_vn).constant_value() != 1 {
                continue; // masking 1 bit means we are checking parity of the POPCOUNT input
            }
            if data.vn(tmp_vn).size != 1 {
                continue; // must be boolean-sized output
            }
            let in_vn = data.op(op).input(0).unwrap();
            if !data.vn(in_vn).is_written() {
                return 0;
            }
            let nzm = data.vn(in_vn).get_nzmask();
            let count = nzm.count_ones();
            if count == 1 {
                let least_pos = super::nzmask::leastsigbit_set(nzm);
                let (b1, _) = popcount_boolean_result(data, in_vn, least_pos);
                let Some(b1) = b1 else { continue };
                // Recognized  popcount( b1 << #pos ) & 1  →  COPY(b1)
                data.op_set_opcode(base_op, OpCode::Copy);
                data.op_remove_input(base_op, 1);
                data.op_set_input(base_op, 0, b1);
                return 1;
            }
            if count == 2 {
                let pos0 = super::nzmask::leastsigbit_set(nzm);
                let pos1 = super::nzmask::mostsigbit_set(nzm);
                let (b1, const_res0) = popcount_boolean_result(data, in_vn, pos0);
                if b1.is_none() && const_res0 != 1 {
                    continue;
                }
                let (b2, const_res1) = popcount_boolean_result(data, in_vn, pos1);
                if b2.is_none() && const_res1 != 1 {
                    continue;
                }
                if b1.is_none() && b2.is_none() {
                    continue;
                }
                let b1 = b1.unwrap_or_else(|| data.new_const(1, 1));
                let b2 = b2.unwrap_or_else(|| data.new_const(1, 1));
                // Recognized  popcount( b1 << #pos1 | b2 << #pos2 ) & 1  →  b1 ^ b2
                data.op_set_opcode(base_op, OpCode::IntXor);
                data.op_set_input(base_op, 0, b1);
                data.op_set_input(base_op, 1, b2);
                return 1;
            }
        }
        0
    }
}

/// Ghidra `RuleOrCollapse` (ruleaction.cc:384): `V | c  =>  c` when every bit not set in the
/// constant `c` is also provably 0 in `V` (`nzm(V) | c == c`) — the OR turns on no bit that `c`
/// does not already have, so the result is just `c`.
pub struct RuleOrCollapse;

impl Rule for RuleOrCollapse {
    fn name(&self) -> &str {
        "orcollapse"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntOr]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::IntOr {
            return 0;
        }
        let Some(out) = data.op(op).output else { return 0 };
        if data.vn(out).size > 8 {
            return 0; // matches Ghidra's `size > sizeof(uintb)` guard
        }
        let Some(cvn) = data.op(op).input(1) else { return 0 };
        if !data.vn(cvn).is_constant() {
            return 0;
        }
        let mask = data.vn(data.op(op).input(0).unwrap()).get_nzmask();
        let val = data.vn(cvn).constant_value();
        if (mask | val) != val {
            return 0; // input(0) could turn on other bits
        }
        data.op_set_opcode(op, OpCode::Copy);
        data.op_remove_input(op, 0); // keep the constant
        1
    }
}

/// Ghidra `RuleXorCollapse` (ruleaction.cc:4050): eliminate an INT_XOR inside an equality compare —
///   - `(V ^ W) == 0   =>  V == W`      (move the term to the other side)
///   - `(V ^ c) == d   =>  V == (c ^ d)`
/// Works for INT_EQUAL and INT_NOTEQUAL.
pub struct RuleXorCollapse;

impl Rule for RuleXorCollapse {
    fn name(&self) -> &str {
        "xorcollapse"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntEqual, OpCode::IntNotequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let code = data.op(op).code();
        if code != OpCode::IntEqual && code != OpCode::IntNotequal {
            return 0;
        }
        let cvn = data.op(op).input(1).unwrap();
        if !data.vn(cvn).is_constant() {
            return 0;
        }
        let xin = data.op(op).input(0).unwrap();
        let Some(xorop) = data.vn(xin).def else { return 0 };
        if data.op(xorop).code() != OpCode::IntXor {
            return 0;
        }
        if lone_descend(data, xin).is_none() {
            return 0; // the XOR output must have exactly one use
        }
        let coeff1 = data.vn(cvn).constant_value();
        let xorvn = data.op(xorop).input(1).unwrap();
        let xor0 = data.op(xorop).input(0).unwrap();
        if data.vn(xor0).is_free() {
            return 0; // this will be propagated
        }
        if !data.vn(xorvn).is_constant() {
            if coeff1 != 0 || data.vn(xorvn).is_free() {
                return 0;
            }
            data.op_set_input(op, 1, xorvn); // move the term to the other side
            data.op_set_input(op, 0, xor0);
            return 1;
        }
        let coeff2 = data.vn(xorvn).constant_value();
        if coeff2 == 0 {
            return 0;
        }
        let constvn = data.new_const(data.vn(cvn).size, coeff1 ^ coeff2);
        data.op_set_input(op, 1, constvn);
        data.op_set_input(op, 0, xor0);
        1
    }
}

/// Ghidra `RuleHighOrderAnd` (ruleaction.cc:1196): simplify an INT_AND with a high-order mask
/// (`0xff..00`) applied to an aligned INT_ADD — `(V + c) & 0xfff0  =>  V + (c & 0xfff0)` when `V` is
/// already zero in the masked-off low bits (`nzm(V) & mask == nzm(V)`). Also the nested aligned form
/// `((V + c) + W) & 0xfff0  =>  (V + (c & 0xfff0)) + W`.
pub struct RuleHighOrderAnd;

impl Rule for RuleHighOrderAnd {
    fn name(&self) -> &str {
        "highorderand"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::IntAnd {
            return 0;
        }
        let cvn1 = data.op(op).input(1).unwrap();
        if !data.vn(cvn1).is_constant() {
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
        let mut val = data.vn(cvn1).constant_value();
        let size = data.vn(cvn1).size;
        // Mask must have the form 0b11..0..0 (a run of high bits set, low bits clear).
        if (val.wrapping_sub(1) | val) != super::nzmask::calc_mask(size) {
            return 0;
        }
        let cvn2 = data.op(addop).input(1).unwrap();
        if data.vn(cvn2).is_constant() {
            let xalign = data.op(addop).input(0).unwrap();
            if data.vn(xalign).is_free() {
                return 0;
            }
            let mask1 = data.vn(xalign).get_nzmask();
            if (mask1 & val) != mask1 {
                return 0; // input(0) must be unaffected by the AND
            }
            data.op_set_opcode(op, OpCode::IntAdd);
            data.op_set_input(op, 0, xalign);
            val &= data.vn(cvn2).constant_value();
            let c = data.new_const(size, val);
            data.op_set_input(op, 1, c);
            return 1;
        }
        // Nested form: the AND's INT_ADD combines an already-aligned term with another INT_ADD.
        let addout = data.op(addop).output.unwrap();
        if lone_descend(data, addout) != Some(op) {
            return 0;
        }
        for i in 0..2 {
            let zerovn = data.op(addop).input(i).unwrap();
            if (data.vn(zerovn).get_nzmask() & val) != data.vn(zerovn).get_nzmask() {
                continue; // zerovn must be unaffected by the AND
            }
            let nonzerovn = data.op(addop).input(1 - i).unwrap();
            if !data.vn(nonzerovn).is_written() {
                continue;
            }
            let addop2 = data.vn(nonzerovn).def.unwrap();
            if data.op(addop2).code() != OpCode::IntAdd {
                continue;
            }
            if lone_descend(data, nonzerovn) != Some(addop) {
                continue;
            }
            let cvn2 = data.op(addop2).input(1).unwrap();
            if !data.vn(cvn2).is_constant() {
                continue;
            }
            let xalign = data.op(addop2).input(0).unwrap();
            if (data.vn(xalign).get_nzmask() & val) != data.vn(xalign).get_nzmask() {
                continue;
            }
            val &= data.vn(cvn2).constant_value();
            let c = data.new_const(size, val);
            data.op_set_input(addop2, 1, c);
            data.op_remove_input(op, 1);
            data.op_set_opcode(op, OpCode::Copy);
            return 1;
        }
        0
    }
}

/// Ghidra `RuleNotDistribute` (ruleaction.cc:1147): distribute a BOOL_NEGATE over a short-circuit
/// boolean — De Morgan: `!(V && W)  =>  !V || !W` and `!(V || W)  =>  !V && !W`.
///
/// Faithful port (see the unit test), but **not wired into [`default_rule_pool`]** yet: the trace
/// diff shows mosura fires it 7× on `nan` where Ghidra fires it only 3×, because mosura's ucomisd
/// flag-tangle is still unsimplified upstream (the known `nan` gap) so its boolean graph has more
/// `!(BOOL_AND/OR)` sites than Ghidra's — over-applying De Morgan there diverges from Ghidra's C
/// (nan 0.378→0.308). Wire it once the `nan` flag-simplification (**Task #4**) makes the two graphs
/// match; the rule itself is correct. (Confirmed by measurement after Ghidra's per-op rule priority
/// landed [Task #7, `c88ff35`]: the over-fire is unchanged at 7×-vs-3×, so priority was never the
/// blocker — this is an upstream graph-shape divergence, Task #4.)
pub struct RuleNotDistribute;

impl Rule for RuleNotDistribute {
    fn name(&self) -> &str {
        "notdistribute"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::BoolNegate]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::BoolNegate {
            return 0;
        }
        let inv = data.op(op).input(0).unwrap();
        let Some(compop) = data.vn(inv).def else { return 0 };
        let opc = match data.op(compop).code() {
            OpCode::BoolAnd => OpCode::BoolOr,
            OpCode::BoolOr => OpCode::BoolAnd,
            _ => return 0,
        };
        // BOOL_AND/BOOL_OR operands are boolean (size 1), so new_op_before's input(0)-derived
        // output size is 1 (Ghidra's newUniqueOut(1,...)).
        let (c0, c1) = (data.op(compop).input(0).unwrap(), data.op(compop).input(1).unwrap());
        let neg1 = data.new_op_before(op, OpCode::BoolNegate, vec![c0]);
        let out1 = data.op(neg1).output.unwrap();
        let neg2 = data.new_op_before(op, OpCode::BoolNegate, vec![c1]);
        let out2 = data.op(neg2).output.unwrap();
        data.op_set_opcode(op, opc);
        data.op_set_input(op, 0, out1);
        data.op_append_input(op, out2);
        1
    }
}

/// Ghidra `RuleAndCompare` (ruleaction.cc:1745): push an INT_AND mask through an INT_ZEXT/SUBPIECE
/// inside a compare-against-zero, widening the AND to the base value:
///   - `zext(V) & c == 0   =>  V & (c & mask) == 0`
///   - `sub(V, k) & d == 0  =>  V & (d << k*8) == 0`
/// Works for INT_EQUAL and INT_NOTEQUAL.
///
/// Faithful port (unit-tested), but **not wired into [`default_rule_pool`]** yet: the trace diff
/// shows mosura fires it where Ghidra does not (e.g. 3× on forloop_varused vs Ghidra's 0×, regressing
/// it 0.984→0.970). Ghidra's per-op rule priority landed (**Task #7**, `c88ff35`) and the over-fire is
/// UNCHANGED — so priority was not the blocker. The real cause (trace-diff Ghidra-only list): Ghidra
/// fires `addmultcollapse`/`sub2add` in its MAIN rule loop, while mosura runs them in a separate
/// `ptrarith_pool`, so mosura's intermediate graph reaches an `(V&mask)==0` shape Ghidra never has.
/// Wire it once those rules run in the main loop (**Task #8**).
pub struct RuleAndCompare;

impl Rule for RuleAndCompare {
    fn name(&self) -> &str {
        "andcompare"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntEqual, OpCode::IntNotequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let code = data.op(op).code();
        if code != OpCode::IntEqual && code != OpCode::IntNotequal {
            return 0;
        }
        let cmpc = data.op(op).input(1).unwrap();
        if !data.vn(cmpc).is_constant() || data.vn(cmpc).constant_value() != 0 {
            return 0;
        }
        let andvn = data.op(op).input(0).unwrap();
        if !data.vn(andvn).is_written() {
            return 0;
        }
        let andop = data.vn(andvn).def.unwrap();
        if data.op(andop).code() != OpCode::IntAnd {
            return 0;
        }
        let andc = data.op(andop).input(1).unwrap();
        if !data.vn(andc).is_constant() {
            return 0;
        }
        let subvn = data.op(andop).input(0).unwrap();
        if !data.vn(subvn).is_written() {
            return 0;
        }
        let subop = data.vn(subvn).def.unwrap();
        let base_const = data.vn(andc).constant_value();
        let (basevn, andconst) = match data.op(subop).code() {
            OpCode::Subpiece => {
                let bv = data.op(subop).input(0).unwrap();
                if data.vn(bv).size > 8 {
                    return 0;
                }
                let off = data.vn(data.op(subop).input(1).unwrap()).constant_value();
                (bv, base_const.checked_shl((off * 8) as u32).unwrap_or(0))
            }
            OpCode::IntZext => {
                let bv = data.op(subop).input(0).unwrap();
                (bv, base_const & super::nzmask::calc_mask(data.vn(bv).size))
            }
            _ => return 0,
        };
        if base_const == super::nzmask::calc_mask(data.vn(andvn).size) {
            return 0; // degenerate AND
        }
        if data.vn(basevn).is_free() {
            return 0;
        }
        let bsize = data.vn(basevn).size;
        let constvn = data.new_const(bsize, andconst);
        // New wider AND(basevn, constvn), then compare it against 0.
        let newop = data.new_op_before(andop, OpCode::IntAnd, vec![basevn, constvn]);
        let newout = data.op(newop).output.unwrap();
        let zero = data.new_const(bsize, 0);
        data.op_set_input(op, 0, newout);
        data.op_set_input(op, 1, zero);
        1
    }
}

/// Ghidra `RuleZextShiftZext` (ruleaction.cc:4865): fold redundant INT_ZEXT —
///   - `zext(zext(V))       =>  zext(V)`
///   - `zext(zext(V) << c)  =>  zext(V) << c`   (widen once, at the outer width, when `c` keeps all bits)
pub struct RuleZextShiftZext;

impl Rule for RuleZextShiftZext {
    fn name(&self) -> &str {
        "zextshiftzext"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntZext]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::IntZext {
            return 0;
        }
        let invn = data.op(op).input(0).unwrap();
        if !data.vn(invn).is_written() {
            return 0;
        }
        let shiftop = data.vn(invn).def.unwrap();
        if data.op(shiftop).code() == OpCode::IntZext {
            // ZEXT(ZEXT(a))  =>  ZEXT(a)  — only when the inner zext is used solely here.
            let vn = data.op(shiftop).input(0).unwrap();
            if data.vn(vn).is_free() || lone_descend(data, invn) != Some(op) {
                return 0;
            }
            data.op_set_input(op, 0, vn);
            return 1;
        }
        if data.op(shiftop).code() != OpCode::IntLeft {
            return 0;
        }
        let shsa = data.op(shiftop).input(1).unwrap();
        if !data.vn(shsa).is_constant() {
            return 0;
        }
        let shin0 = data.op(shiftop).input(0).unwrap();
        if !data.vn(shin0).is_written() {
            return 0;
        }
        let zext2op = data.vn(shin0).def.unwrap();
        if data.op(zext2op).code() != OpCode::IntZext {
            return 0;
        }
        let rootvn = data.op(zext2op).input(0).unwrap();
        if data.vn(rootvn).is_free() {
            return 0;
        }
        let sa = data.vn(shsa).constant_value();
        let z2out = data.op(zext2op).output.unwrap();
        if sa > 8 * (data.vn(z2out).size as u64 - data.vn(rootvn).size as u64) {
            return 0; // shift might lose bits off the top
        }
        let outsize = data.vn(data.op(op).output.unwrap()).size;
        // newzext = ZEXT(rootvn) at the outer width; op becomes  newzext << sa.
        let newop = data.new_op_before_sized(op, OpCode::IntZext, vec![rootvn], outsize);
        let newout = data.op(newop).output.unwrap();
        data.op_set_opcode(op, OpCode::IntLeft);
        data.op_set_input(op, 0, newout);
        let sac = data.new_const(4, sa);
        data.op_append_input(op, sac);
        1
    }
}

/// Ghidra `RuleSubZext` (ruleaction.cc:5039): simplify INT_ZEXT of a truncation —
///   - `zext( sub(V, 0) )      =>  V & mask`
///   - `zext( sub(V, k) )      =>  (V >> k*8) & mask`
///   - `zext( sub(V, k) >> d )  =>  (V >> (k*8+d)) & mask`
/// where the truncate-then-extend returns to `V`'s original width (`|sub base| == |zext out|`).
///
/// Faithful port (unit-tested), but **not wired into [`default_rule_pool`]** yet: the trace diff
/// shows mosura over-fires it on piecestruct and rewrites `zext(byte)` forms that [`RuleShiftPiece`]
/// needs to fold into CONCAT — broadly regressing the corpus (piecestruct itself 0.889→0.736). With
/// Ghidra's per-op rule priority now in place (**Task #7**, `c88ff35`) it still over-fires 31×-vs-26×,
/// so priority was not the blocker. Root cause (Ghidra's own trace on piecestruct): Ghidra fires
/// subzext 26× *alongside* subvar 20× + piece2zext 19× + andmask 27× — its SubVariableFlow subsystem
/// consumes the extra IntZext forms mosura's SubZext hits. Wire it once SubVariableFlow lands
/// (**Task #9**).
pub struct RuleSubZext;

impl Rule for RuleSubZext {
    fn name(&self) -> &str {
        "subzext"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntZext]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::IntZext {
            return 0;
        }
        let subvn = data.op(op).input(0).unwrap();
        if !data.vn(subvn).is_written() {
            return 0;
        }
        let subop = data.vn(subvn).def.unwrap();
        let outsize = data.vn(data.op(op).output.unwrap()).size;
        match data.op(subop).code() {
            OpCode::Subpiece => {
                let basevn = data.op(subop).input(0).unwrap();
                if data.vn(basevn).is_free() {
                    return 0;
                }
                if data.vn(basevn).size != outsize || data.vn(basevn).size > 8 {
                    return 0; // truncating then extending to a different width
                }
                let basesize = data.vn(basevn).size;
                let subc = data.op(subop).input(1).unwrap();
                if data.vn(subc).constant_value() != 0 {
                    // Truncating from the middle: turn the SUBPIECE into a shift of the full value.
                    if lone_descend(data, subvn) != Some(op) {
                        return 0;
                    }
                    let newvn = data.new_unique(basesize);
                    let right_val = data.vn(subc).constant_value() * 8;
                    let rc = data.new_const(data.vn(subc).size, right_val);
                    data.op_set_input(op, 0, newvn);
                    data.op_set_opcode(subop, OpCode::IntRight);
                    data.op_set_input(subop, 1, rc);
                    data.op_set_output(subop, newvn);
                } else {
                    data.op_set_input(op, 0, basevn); // bypass the truncation entirely
                }
                let mask = super::nzmask::calc_mask(data.vn(subvn).size);
                let constvn = data.new_const(basesize, mask);
                data.op_set_opcode(op, OpCode::IntAnd);
                data.op_append_input(op, constvn);
                1
            }
            OpCode::IntRight => {
                let shiftop = subop;
                let shc = data.op(shiftop).input(1).unwrap();
                if !data.vn(shc).is_constant() {
                    return 0;
                }
                let midvn = data.op(shiftop).input(0).unwrap();
                if !data.vn(midvn).is_written() {
                    return 0;
                }
                let subop2 = data.vn(midvn).def.unwrap();
                if data.op(subop2).code() != OpCode::Subpiece {
                    return 0;
                }
                let basevn = data.op(subop2).input(0).unwrap();
                if data.vn(basevn).is_free() {
                    return 0;
                }
                if data.vn(basevn).size != outsize || data.vn(basevn).size > 8 {
                    return 0;
                }
                if lone_descend(data, midvn) != Some(shiftop) || lone_descend(data, subvn) != Some(op)
                {
                    return 0;
                }
                let basesize = data.vn(basevn).size;
                let mut val = super::nzmask::calc_mask(data.vn(midvn).size);
                let sa = data.vn(shc).constant_value();
                val = val.checked_shr(sa as u32).unwrap_or(0);
                let total = sa + data.vn(data.op(subop2).input(1).unwrap()).constant_value() * 8;
                let newvn = data.new_unique(basesize);
                let tc = data.new_const(data.vn(shc).size, total);
                data.op_set_input(op, 0, newvn);
                data.op_set_input(shiftop, 0, basevn); // shift the full value
                data.op_set_input(shiftop, 1, tc); // by the combined amount
                data.op_set_output(shiftop, newvn);
                let constvn = data.new_const(basesize, val);
                data.op_set_opcode(op, OpCode::IntAnd);
                data.op_append_input(op, constvn);
                1
            }
            _ => 0,
        }
    }
}

/// Ghidra `RulePiece2Zext` (ruleaction.cc:219): concatenation with a zero high part is a zero
/// extension — `concat(#0, W)  =>  zext(W)`.
///
/// Faithful port (unit-tested), **not wired into [`default_rule_pool`]** (lead ruled it stays held):
/// the trace diff shows it CONVERGES on floatcast (mosura 4× = Ghidra 4×, floatcast 0.796→0.840) and
/// helps nan/varcross, but OVER-fires by one on floatconv (mosura 2× vs Ghidra 1×, floatconv
/// 0.578→0.512) for a net corpus of only ≈+0.0001. Ghidra's per-op rule priority landed (**Task #7**,
/// `c88ff35`) and the floatconv over-fire is UNCHANGED — so priority was not the blocker; it is the
/// same SubVariableFlow gap as [`RuleSubZext`]. Wire it once that lands (**Task #9**). Not wired for
/// the marginal net gain — that would be gauge-chasing with a real floatconv regression.
pub struct RulePiece2Zext;

impl Rule for RulePiece2Zext {
    fn name(&self) -> &str {
        "piece2zext"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Piece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::Piece {
            return 0;
        }
        let cvn = data.op(op).input(0).unwrap(); // most-significant half
        if !data.vn(cvn).is_constant() || data.vn(cvn).constant_value() != 0 {
            return 0;
        }
        data.op_remove_input(op, 0);
        data.op_set_opcode(op, OpCode::IntZext);
        1
    }
}

/// Ghidra `RuleLessEqual2Zero` (ruleaction.cc:5601): simplify INT_LESSEQUAL against an extremal
/// constant (0 or all-ones), which an unsigned `<=` makes trivially true or an equality:
///   - `0 <= V     =>  true`      - `V <= 0     =>  V == 0`
///   - `mask <= V  =>  mask == V`  - `V <= mask  =>  true`
pub struct RuleLessEqual2Zero;

impl Rule for RuleLessEqual2Zero {
    fn name(&self) -> &str {
        "lessequal2zero"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntLessequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::IntLessequal {
            return 0;
        }
        let lvn = data.op(op).input(0).unwrap();
        let rvn = data.op(op).input(1).unwrap();
        if data.vn(lvn).is_constant() {
            let lv = data.vn(lvn).constant_value();
            if lv == 0 {
                data.op_set_opcode(op, OpCode::Copy); // 0 <= V is always true
                data.op_remove_input(op, 1);
                let one = data.new_const(1, 1);
                data.op_set_input(op, 0, one);
                return 1;
            } else if lv == super::nzmask::calc_mask(data.vn(lvn).size) {
                data.op_set_opcode(op, OpCode::IntEqual); // only -1 satisfies mask <= V
                return 1;
            }
        } else if data.vn(rvn).is_constant() {
            let rv = data.vn(rvn).constant_value();
            if rv == 0 {
                data.op_set_opcode(op, OpCode::IntEqual); // only 0 satisfies V <= 0
                return 1;
            } else if rv == super::nzmask::calc_mask(data.vn(rvn).size) {
                data.op_set_opcode(op, OpCode::Copy); // V <= mask is always true
                data.op_remove_input(op, 1);
                let one = data.new_const(1, 1);
                data.op_set_input(op, 0, one);
                return 1;
            }
        }
        0
    }
}

/// Ghidra `RuleShiftBitops` (ruleaction.cc:490): when a shift/truncate/multiply discards all the
/// non-zero bits of one side of an inner logical/arithmetic op, drop that side:
///   - `(V & 0xf000) << 4  =>  #0 << 4`    (AND/MULT: the surviving side is 0 → whole thing 0)
///   - `(V + 0xf000) << 4  =>  V << 4`     (ADD/XOR/OR: the discarded addend contributes nothing)
/// The outer op is INT_LEFT/INT_RIGHT/SUBPIECE/INT_MULT (by a power of two).
pub struct RuleShiftBitops;

impl Rule for RuleShiftBitops {
    fn name(&self) -> &str {
        "shiftbitops"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntLeft, OpCode::IntRight, OpCode::Subpiece, OpCode::IntMult]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let code = data.op(op).code();
        // The pool dispatches on a cached opcode a prior rule may have rewritten (e.g. INT_MULT→COPY);
        // re-check the live opcode is one of our binary target ops before reading input(1).
        if !matches!(
            code,
            OpCode::IntLeft | OpCode::IntRight | OpCode::Subpiece | OpCode::IntMult
        ) {
            return 0;
        }
        let constvn = data.op(op).input(1).unwrap();
        if !data.vn(constvn).is_constant() {
            return 0;
        }
        let vn = data.op(op).input(0).unwrap();
        if !data.vn(vn).is_written() || data.vn(vn).size > 8 {
            return 0;
        }
        let cval = data.vn(constvn).constant_value();
        let (sa, leftshift) = match code {
            OpCode::IntLeft => (cval as u32, true),
            OpCode::IntRight => (cval as u32, false),
            OpCode::Subpiece => (cval as u32 * 8, false),
            OpCode::IntMult => {
                let s = super::nzmask::leastsigbit_set(cval);
                if s == -1 {
                    return 0;
                }
                (s as u32, true)
            }
            _ => return 0,
        };
        let bitop = data.vn(vn).def.unwrap();
        match data.op(bitop).code() {
            OpCode::IntAnd | OpCode::IntOr | OpCode::IntXor => {}
            OpCode::IntMult | OpCode::IntAdd if leftshift => {}
            _ => return 0,
        }
        let outmask = super::nzmask::calc_mask(data.vn(data.op(op).output.unwrap()).size);
        let ninput = data.op(bitop).num_inputs();
        let mut found = None;
        for i in 0..ninput {
            let nzm0 = data.vn(data.op(bitop).input(i).unwrap()).get_nzmask();
            let nzm = if leftshift {
                nzm0.checked_shl(sa).unwrap_or(0)
            } else {
                nzm0.checked_shr(sa).unwrap_or(0)
            };
            if (nzm & outmask) == 0 {
                found = Some(i);
                break;
            }
        }
        let Some(i) = found else { return 0 };
        match data.op(bitop).code() {
            OpCode::IntMult | OpCode::IntAnd => {
                let zero = data.new_const(data.vn(vn).size, 0); // result is zero
                data.op_set_input(op, 0, zero);
            }
            OpCode::IntAdd | OpCode::IntXor | OpCode::IntOr => {
                let other = data.op(bitop).input(1 - i).unwrap();
                if !data.vn(other).is_heritage_known() {
                    return 0;
                }
                data.op_set_input(op, 0, other);
            }
            _ => return 0,
        }
        1
    }
}

/// Ghidra `RuleHumptyOr` (ruleaction.cc:5332): recombine masked pieces OR'd together —
/// `(V & W) | (V & X)  =>  V & (W|X)`, and when `W|X` covers every bit of `V`, `=> V`.
pub struct RuleHumptyOr;

impl Rule for RuleHumptyOr {
    fn name(&self) -> &str {
        "humptyor"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntOr]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::IntOr {
            return 0;
        }
        let vn1 = data.op(op).input(0).unwrap();
        let vn2 = data.op(op).input(1).unwrap();
        if !data.vn(vn1).is_written() || !data.vn(vn2).is_written() {
            return 0;
        }
        let and1 = data.vn(vn1).def.unwrap();
        let and2 = data.vn(vn2).def.unwrap();
        if data.op(and1).code() != OpCode::IntAnd || data.op(and2).code() != OpCode::IntAnd {
            return 0;
        }
        // a is the operand common to both ANDs; b, c are the respective other operands.
        let mut a = data.op(and1).input(0).unwrap();
        let mut b = data.op(and1).input(1).unwrap();
        let mut c = data.op(and2).input(0).unwrap();
        let d = data.op(and2).input(1).unwrap();
        if a == c {
            c = d;
        } else if a == d {
            // c already the non-matching operand of and2
        } else if b == c {
            b = a;
            a = c;
            c = d;
        } else if b == d {
            b = a;
            a = d;
        } else {
            return 0;
        }
        if data.vn(b).is_constant() && data.vn(c).is_constant() {
            let totalbits = data.vn(b).constant_value() | data.vn(c).constant_value();
            if totalbits == super::nzmask::calc_mask(data.vn(a).size) {
                data.op_set_opcode(op, OpCode::Copy); // every bit of `a` is covered
                data.op_remove_input(op, 1);
                data.op_set_input(op, 0, a);
            } else {
                data.op_set_opcode(op, OpCode::IntAnd);
                let nc = data.new_const(data.vn(a).size, totalbits);
                data.op_set_input(op, 0, a);
                data.op_set_input(op, 1, nc);
            }
        } else {
            if !data.vn(b).is_heritage_known() || !data.vn(c).is_heritage_known() {
                return 0;
            }
            let amask = data.vn(a).get_nzmask();
            // RuleAndDistribute would reverse us if either side shares no bits with `a`.
            if (data.vn(b).get_nzmask() & amask) == 0 || (data.vn(c).get_nzmask() & amask) == 0 {
                return 0;
            }
            let new_or = data.new_op_before(op, OpCode::IntOr, vec![b, c]);
            let or_vn = data.op(new_or).output.unwrap();
            data.op_set_input(op, 0, a);
            data.op_set_input(op, 1, or_vn);
            data.op_set_opcode(op, OpCode::IntAnd);
        }
        1
    }
}

/// Ghidra `RuleAndPiece` (ruleaction.cc:1640): when an INT_AND masks a PIECE and one half of the
/// PIECE is entirely masked off, collapse it — `V & concat(W,X)  =>  zext(X)` (high part masked off)
/// or `V & concat(W,X)  =>  V & concat(#0,X)` (low part masked off), by the non-zero masks.
pub struct RuleAndPiece;

impl Rule for RuleAndPiece {
    fn name(&self) -> &str {
        "andpiece"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::IntAnd {
            return 0;
        }
        let size = data.vn(data.op(op).output.unwrap()).size;
        let full = super::nzmask::calc_mask(size);
        let mut chosen: Option<(usize, OpCode, VarnodeId, VarnodeId)> = None; // (i, opc, high, low)
        for i in 0..2 {
            let piecevn = data.op(op).input(i).unwrap();
            if !data.vn(piecevn).is_written() {
                continue;
            }
            let pieceop = data.vn(piecevn).def.unwrap();
            if data.op(pieceop).code() != OpCode::Piece {
                continue;
            }
            let othervn = data.op(op).input(1 - i).unwrap();
            let othermask = data.vn(othervn).get_nzmask();
            if othermask == full || othermask == 0 {
                continue; // full: no-op; zero: RuleAndMask handles it
            }
            let highvn = data.op(pieceop).input(0).unwrap();
            let lowvn = data.op(pieceop).input(1).unwrap();
            if !data.vn(highvn).is_heritage_known() || !data.vn(lowvn).is_heritage_known() {
                continue;
            }
            let maskhigh = data.vn(highvn).get_nzmask();
            let masklow = data.vn(lowvn).get_nzmask();
            let lowbits = data.vn(lowvn).size * 8;
            if (maskhigh & othermask.checked_shr(lowbits).unwrap_or(0)) == 0 {
                if maskhigh == 0 && data.vn(highvn).is_constant() {
                    continue; // RulePiece2Zext handles this
                }
                chosen = Some((i, OpCode::IntZext, highvn, lowvn));
                break;
            } else if (masklow & othermask) == 0 {
                if data.vn(lowvn).is_constant() {
                    continue; // nothing to do
                }
                chosen = Some((i, OpCode::Piece, highvn, lowvn));
                break;
            }
        }
        let Some((i, opc, highvn, lowvn)) = chosen else { return 0 };
        let newvn = if opc == OpCode::IntZext {
            // PIECE(high, low) & mask  =>  ZEXT(low)  (high part is masked off)
            let newop = data.new_op_before_sized(op, OpCode::IntZext, vec![lowvn], size);
            data.op(newop).output.unwrap()
        } else {
            // low part masked off: PIECE(high, low)  =>  PIECE(high, #0)
            let zero = data.new_const(data.vn(lowvn).size, 0);
            let newop = data.new_op_before_sized(op, OpCode::Piece, vec![highvn, zero], size);
            data.op(newop).output.unwrap()
        };
        data.op_set_input(op, i, newvn);
        1
    }
}

/// Ghidra `RuleAndDistribute` (ruleaction.cc:1254): distribute an INT_AND through an INT_OR when it
/// simplifies — `(A|B) & C  =>  (A&C) | (B&C)`, gated on the non-zero masks so a term cancels or
/// becomes trivial.
///
/// Faithful port (unit-tested; guards verified byte-for-byte against ruleaction.cc), but **not wired
/// into [`default_rule_pool`]** — it is the mirror image of [`RuleHumptyOr`] and the pool HANGS: a
/// real inverse cycle `humptyor → termorder → anddistribute → humptyor` on the byte-mask form
/// `(X&k1)|(X&k2)`. Ghidra's per-op rule priority landed (**Task #7**, `c88ff35`) and it STILL hangs,
/// so priority is not the fix (the two rules are on different opcodes — INT_OR vs INT_AND — so
/// priority never orders them against each other). Root cause (verified via Ghidra's own trace, which
/// fires anddistribute/humptyor 0× on piecestruct): Ghidra never reaches this form because its
/// SubVariableFlow dissolves the byte-packing first; and even if it arose, Ghidra's fresh nzmasks let
/// the higher-priority [`RuleAndMask`] collapse the intermediate `X & 0xff` identity. mosura's
/// freshly-created OR varnode carries a stale full nzmask, so AndMask can't break the cycle. PRIMARY
/// blocker = **Task #9** (SubVariableFlow — makes the cycle form never arise, the same fix as SubZext /
/// Piece2Zext); **Task #10** (nzmask refreshed mid-pool) is a secondary safety-net that would let
/// AndMask break the cycle if the form ever did arise. Do NOT wire it alongside RuleHumptyOr before then.
pub struct RuleAndDistribute;

impl Rule for RuleAndDistribute {
    fn name(&self) -> &str {
        "anddistribute"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).code() != OpCode::IntAnd {
            return 0;
        }
        let size = data.vn(data.op(op).output.unwrap()).size;
        if size > 8 {
            return 0;
        }
        let fullmask = super::nzmask::calc_mask(size);
        let mut chosen: Option<(usize, VarnodeId, VarnodeId, VarnodeId)> = None; // (i, o0, o1, other)
        for i in 0..2 {
            let othervn = data.op(op).input(1 - i).unwrap();
            if !data.vn(othervn).is_heritage_known() {
                continue;
            }
            let orvn = data.op(op).input(i).unwrap();
            let Some(orop) = data.vn(orvn).def else { continue };
            if data.op(orop).code() != OpCode::IntOr {
                continue;
            }
            let o0 = data.op(orop).input(0).unwrap();
            let o1 = data.op(orop).input(1).unwrap();
            if !data.vn(o0).is_heritage_known() || !data.vn(o1).is_heritage_known() {
                continue;
            }
            let othermask = data.vn(othervn).get_nzmask();
            if othermask == 0 || othermask == fullmask {
                continue;
            }
            let ormask1 = data.vn(o0).get_nzmask();
            let ormask2 = data.vn(o1).get_nzmask();
            // Distribute only when it makes a term cancel (mask disjoint) or, for a constant mask,
            // become trivial (mask covers the term). Otherwise distributing gains nothing.
            let beneficial = (ormask1 & othermask) == 0
                || (ormask2 & othermask) == 0
                || (data.vn(othervn).is_constant()
                    && ((ormask1 & othermask) == ormask1 || (ormask2 & othermask) == ormask2));
            if beneficial {
                chosen = Some((i, o0, o1, othervn));
                break;
            }
        }
        let Some((_i, o0, o1, othervn)) = chosen else { return 0 };
        let and1 = data.new_op_before(op, OpCode::IntAnd, vec![o0, othervn]);
        let v1 = data.op(and1).output.unwrap();
        let and2 = data.new_op_before(op, OpCode::IntAnd, vec![o1, othervn]);
        let v2 = data.op(and2).output.unwrap();
        // Ghidra replaces both inputs (slots 0 and 1) regardless of which held the OR.
        data.op_set_input(op, 0, v1);
        data.op_set_input(op, 1, v2);
        data.op_set_opcode(op, OpCode::IntOr);
        1
    }
}

/// Ghidra `RuleOrMask` (ruleaction.cc:284): `V | mask  =>  mask` when the constant operand has every
/// bit of the output set. An OR can only set bits, so an all-ones constant determines the result
/// regardless of `V`; the op collapses to a COPY of the constant. (switchmulti's `extraout_R8 | -1`
/// → `-1`, which also drops the dead `extraout_R8`.)
pub struct RuleOrMask;

impl Rule for RuleOrMask {
    fn name(&self) -> &str {
        "ormask"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntOr]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(out) = data.op(op).output else { return 0 };
        let size = data.vn(out).size;
        if size as usize > 8 {
            return 0; // matches Ghidra's `size > sizeof(uintb)` guard
        }
        let Some(c) = data.op(op).input(1) else { return 0 };
        if !data.vn(c).is_constant() {
            return 0;
        }
        let allones = mask(u64::MAX, size);
        if mask(data.vn(c).constant_value(), size) != allones {
            return 0;
        }
        data.op_set_opcode(op, OpCode::Copy);
        data.op_set_all_input(op, &[c]);
        1
    }
}

/// Merge `(x != c) && (x ≤ c)` into the strict comparison `x < c` (and the swapped /
/// signed forms): the disequality removes the equality case from `≤`. A range collapse
/// Ghidra applies so a span check reads as one comparison rather than a `&&` of two.
pub struct RuleRangeAnd;

impl Rule for RuleRangeAnd {
    fn name(&self) -> &str {
        "rangeand"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::BoolAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (i0, i1) = (data.op(op).input(0), data.op(op).input(1));
        let (Some(i0), Some(i1)) = (i0, i1) else { return 0 };
        for (ne_v, le_v) in [(i0, i1), (i1, i0)] {
            let (Some(ne), Some(le)) = (data.vn(ne_v).def, data.vn(le_v).def) else { continue };
            if data.op(ne).code() != OpCode::IntNotequal {
                continue;
            }
            let strict = match data.op(le).code() {
                OpCode::IntLessequal => OpCode::IntLess,
                OpCode::IntSlessequal => OpCode::IntSless,
                _ => continue,
            };
            let (na, nb) = (data.op(ne).input(0).unwrap(), data.op(ne).input(1).unwrap());
            let (la, lb) = (data.op(le).input(0).unwrap(), data.op(le).input(1).unwrap());
            // the `!=` must be on the same pair as the `<=` (either order)
            let same = (same_value(data, na, la) && same_value(data, nb, lb))
                || (same_value(data, na, lb) && same_value(data, nb, la));
            if !same {
                continue;
            }
            data.op_set_opcode(op, strict);
            data.op_set_all_input(op, &[la, lb]);
            return 1;
        }
        0
    }
}

/// Ghidra `RuleSub2Add` (`ruleaction.cc:4012`, the "analysis" group): eliminate INT_SUB —
/// `V - W  =>  V + W * -1`. `getOpList` is `{INT_SUB}` and it fires *unconditionally* on every
/// subtraction (not scoped to a pointer base). The canonical additive form lets the
/// pointer-arithmetic / division rules reason about a single shape; the cleanup pool
/// (`RuleMultNegOne`/`Rule2Comp2Sub`/`RuleAddUnsigned`) turns the non-pointer results back into
/// `V - W` so the printer renders subtractions. A frame `RSP - c` becomes `INT_ADD(RSP, -c)`, which
/// the printer recognises as a stack-local address (`&Stack_c`).
pub struct RuleSub2Add;

impl Rule for RuleSub2Add {
    fn name(&self) -> &str {
        "sub2add"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSub]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn = data.op(op).input(1).unwrap(); // the value being subtracted (W)
        let size = data.vn(vn).size;
        // newop = INT_MULT(W, calc_mask(size)) — i.e. W * -1 — inserted just before op.
        let negone = data.new_const(size, mask(!0, size));
        let newop = data.new_op_before(op, OpCode::IntMult, vec![vn, negone]);
        let newvn = data.op(newop).output.unwrap();
        data.op_set_input(op, 1, newvn); // replace W's reference with the product
        data.op_set_opcode(op, OpCode::IntAdd);
        1
    }
}

/// Ghidra `RuleAddMultCollapse` (`ruleaction.cc`, the "analysis" group): collapse constants in an
/// additive or multiplicative expression. Forms:
///  - `((V + c) + d)  =>  V + (c+d)`
///  - `((V * c) * d)  =>  V * (c*d)`
///  - `((stackbase + c1) + othervn) + c0  =>  (stackbase + (c0+c1)) + othervn`
///
/// The simple form flattens a chained stack-frame base — `(RSP + -8) + -0x70 => RSP + -0x78` — so a
/// multi-level frame escape resolves to a single offset. (The equate/symbol bookkeeping in Ghidra
/// does not apply: mosura models no equate symbols. The spacebase form needs an `isSpacebase()`
/// input, which mosura does not yet flag, so it is dormant — ported for faithfulness.)
pub struct RuleAddMultCollapse;

impl Rule for RuleAddMultCollapse {
    fn name(&self) -> &str {
        "addmultcollapse"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAdd, OpCode::IntMult]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let opc = data.op(op).code();
        // The pool dispatches on a snapshot opcode; an earlier rule may have already rewritten this
        // op (e.g. RuleConstFold → COPY). Re-check the live shape before touching inputs.
        if !matches!(opc, OpCode::IntAdd | OpCode::IntMult) || data.op(op).num_inputs() != 2 {
            return 0;
        }
        // The constant is in c0 (input 1, after RuleTermOrder); the other input is `sub`.
        let c0 = data.op(op).input(1).unwrap();
        if !data.vn(c0).is_constant() {
            return 0;
        }
        let sub = data.op(op).input(0).unwrap();
        if !data.vn(sub).is_written() {
            return 0;
        }
        let subop = data.vn(sub).def.unwrap();
        if data.op(subop).code() != opc {
            return 0; // must be the exact same operation one level down
        }
        let c1 = data.op(subop).input(1).unwrap();
        if !data.vn(c1).is_constant() {
            // ((stackbase + c1) + othervn) + c0  =>  (stackbase + (c0+c1)) + othervn — collapse two
            // constant offsets even with an extra term AND a multiply-used intermediate sum.
            if opc != OpCode::IntAdd {
                return 0;
            }
            for i in 0..2 {
                let othervn = data.op(subop).input(i).unwrap();
                if data.vn(othervn).is_constant() || data.vn(othervn).is_free() {
                    continue;
                }
                let sub2 = data.op(subop).input(1 - i).unwrap();
                if !data.vn(sub2).is_written() {
                    continue;
                }
                let baseop = data.vn(sub2).def.unwrap();
                if data.op(baseop).code() != OpCode::IntAdd {
                    continue;
                }
                let c1b = data.op(baseop).input(1).unwrap();
                if !data.vn(c1b).is_constant() {
                    continue;
                }
                let basevn = data.op(baseop).input(0).unwrap();
                // only for a base pointer (this adds a new add op, so guard it tightly)
                if !data.vn(basevn).is_spacebase() || !data.vn(basevn).is_input() {
                    continue;
                }
                let size = data.vn(c0).size;
                let val = mask(
                    data.vn(c0).constant_value().wrapping_add(data.vn(c1b).constant_value()),
                    size,
                );
                let newvn = data.new_const(size, val);
                let newop = data.new_op_before(op, OpCode::IntAdd, vec![basevn, newvn]);
                let newout = data.op(newop).output.unwrap();
                data.op_set_input(op, 0, newout);
                data.op_set_input(op, 1, othervn);
                return 1;
            }
            return 0;
        }
        let sub2 = data.op(subop).input(0).unwrap();
        if data.vn(sub2).is_free() {
            return 0;
        }
        let size = data.vn(c0).size;
        let (v0, v1) = (data.vn(c0).constant_value(), data.vn(c1).constant_value());
        let val = match opc {
            OpCode::IntAdd => v0.wrapping_add(v1),
            OpCode::IntMult => v0.wrapping_mul(v1),
            _ => return 0,
        };
        let newvn = data.new_const(size, mask(val, size));
        data.op_set_input(op, 1, newvn); // c0 => c0+c1 (or c0*c1)
        data.op_set_input(op, 0, sub2); // sub => sub2
        1
    }
}

/// Ghidra `RuleMultNegOne` (`ruleaction.cc`): `a * -1  =>  -a` (an `INT_2COMP`). The cleanup
/// counterpart of `RuleSub2Add` for the non-constant case: a subtraction `V - W` canonicalised to
/// `V + W*-1` has its `W*-1` reduced to `INT_2COMP(W)` here, which `Rule2Comp2Sub` then folds into
/// `V - W`.
pub struct RuleMultNegOne;

impl Rule for RuleMultNegOne {
    fn name(&self) -> &str {
        "multnegone"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntMult]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(constvn) = data.op(op).input(1) else { return 0 };
        let cvn = data.vn(constvn);
        if !cvn.is_constant() || cvn.constant_value() != mask(!0, cvn.size) {
            return 0;
        }
        data.op_set_opcode(op, OpCode::Int2comp);
        data.op_remove_input(op, 1);
        1
    }
}

/// Ghidra `RuleAddUnsigned` (`ruleaction.cc`): a cleanup that converts `V + 0xff...` to
/// `V - 0x00...` when the additive constant reads as an unsigned integer whose top quarter of bits
/// are all ones (i.e. it is "really" a small negative). mosura does not type bare constants (they
/// stay `undefined<N>`, never `TYPE_UINT`), so this is dormant on the current lattice — ported
/// faithfully so it activates once constant typing lands. (The equate-symbol and enum guards in
/// Ghidra do not apply: mosura models neither.)
pub struct RuleAddUnsigned;

impl Rule for RuleAddUnsigned {
    fn name(&self) -> &str {
        "addunsigned"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAdd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(constvn) = data.op(op).input(1) else { return 0 };
        let cvn = data.vn(constvn);
        if !cvn.is_constant() {
            return 0;
        }
        // getTypeReadFacing(op): the committed type of the constant. Only a plain unsigned integer
        // qualifies (Ghidra also excludes char-printing types, which mosura never assigns here).
        if !matches!(cvn.get_type(), super::types::Datatype::Uint(_)) {
            return 0;
        }
        let size = cvn.size;
        let val = cvn.constant_value();
        let m = mask(!0, size);
        let sa = size * 6; // 1/4 less than the full bit-size
        let quarter = (m >> sa) << sa;
        if (val & quarter) != quarter {
            return 0; // the first quarter of bits must all be 1's
        }
        let negated = val.wrapping_neg() & m;
        data.op_set_opcode(op, OpCode::IntSub);
        let cnew = data.new_const(size, negated);
        data.op_set_input(op, 1, cnew);
        1
    }
}

/// Ghidra `Rule2Comp2Sub` (`ruleaction.cc`): `V + -W  =>  V - W`. Folds an `INT_2COMP` feeding an
/// `INT_ADD` into a single `INT_SUB`, completing the round-trip of a non-constant subtraction that
/// `RuleSub2Add`/`RuleMultNegOne` canonicalised.
pub struct Rule2Comp2Sub;

impl Rule for Rule2Comp2Sub {
    fn name(&self) -> &str {
        "twocomp2sub"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Int2comp]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(out) = data.op(op).output else { return 0 };
        // loneDescend: the single op that reads the 2COMP output (none if 0 or >1 uses).
        let descend = &data.vn(out).descend;
        if descend.len() != 1 {
            return 0;
        }
        let addop = descend[0];
        if data.op(addop).code() != OpCode::IntAdd {
            return 0;
        }
        let w = data.op(op).input(0).unwrap(); // the value being negated
        if data.op(addop).input(0) == Some(out) {
            // the 2COMP result is in slot 0 — move the other addend down to slot 0
            let other = data.op(addop).input(1).unwrap();
            data.op_set_input(addop, 0, other);
        }
        data.op_set_input(addop, 1, w);
        data.op_set_opcode(addop, OpCode::IntSub);
        data.op_destroy(op); // completely remove the 2COMP
        1
    }
}

/// Ghidra's commutative p-code opcodes (`TypeOp` ctors that set `PcodeOp::commutative`). The
/// functional-equality matcher uses this to try the swapped operand ordering.
fn is_commutative(opc: OpCode) -> bool {
    use OpCode::*;
    matches!(
        opc,
        IntEqual | IntNotequal | IntAdd | IntCarry | IntScarry | IntXor | IntAnd | IntOr | IntMult
            | BoolXor | BoolAnd | BoolOr | FloatEqual | FloatNotequal | FloatAdd | FloatMult
    )
}

/// Ghidra `functionalEqualityLevel0` (expression.cc): the one-level comparison.
///   - `0`  ⇒ `vn1` and `vn2` must hold the same value,
///   - `-1` ⇒ they definitely don't, and
///   - `1`  ⇒ same-value-ness depends on the ops writing them.
fn functional_equality_level0(data: &Funcdata, vn1: VarnodeId, vn2: VarnodeId) -> i32 {
    if vn1 == vn2 {
        return 0;
    }
    let a = data.vn(vn1);
    let b = data.vn(vn2);
    if a.size != b.size {
        return -1;
    }
    if a.is_constant() {
        if b.is_constant() {
            return if a.constant_value() == b.constant_value() { 0 } else { -1 };
        }
        return -1;
    }
    if a.is_free() || b.is_free() {
        return -1;
    }
    1
}

/// Ghidra `functionalEqualityLevel` (expression.cc): try to determine whether `vn1` and `vn2`
/// hold the same value. Returns `0` (do), `-1` (don't / can't tell), or `>0` (contingent on
/// further varnode pairs). Both call sites here (and Ghidra's) only test the `== 0` case, so —
/// unlike Ghidra — we don't thread the contingent pairs back out; the recursion structure that
/// decides whether `0` is reachable is reproduced exactly.
fn functional_equality_level(data: &Funcdata, vn1: VarnodeId, vn2: VarnodeId) -> i32 {
    let testval = functional_equality_level0(data, vn1, vn2);
    if testval != 1 {
        return testval;
    }
    if !data.vn(vn1).is_written() || !data.vn(vn2).is_written() {
        return -1; // Did not find at least one level of match
    }
    let op1 = data.vn(vn1).def.unwrap();
    let op2 = data.vn(vn2).def.unwrap();
    let opc = data.op(op1).code();
    if opc != data.op(op2).code() {
        return -1;
    }
    let mut num = data.op(op1).num_inputs();
    if num != data.op(op2).num_inputs() {
        return -1;
    }
    if data.op(op1).is_marker() {
        return -1;
    }
    if data.op(op2).is_call() {
        return -1;
    }
    if opc == OpCode::Load {
        // Assume two loads produce the same result only if address + instruction match.
        if data.op(op1).seqnum.pc != data.op(op2).seqnum.pc {
            return -1;
        }
    }
    if num >= 3 {
        if opc != OpCode::Ptradd {
            return -1;
        }
        let e1 = data.op(op1).input(2).unwrap();
        let e2 = data.op(op2).input(2).unwrap();
        if data.vn(e1).constant_value() != data.vn(e2).constant_value() {
            return -1; // elsize constant must be equal
        }
        num = 2; // otherwise treat as having 2 inputs
    }
    let r1: Vec<VarnodeId> = (0..num).map(|i| data.op(op1).input(i).unwrap()).collect();
    let r2: Vec<VarnodeId> = (0..num).map(|i| data.op(op2).input(i).unwrap()).collect();

    let testval = functional_equality_level0(data, r1[0], r2[0]);
    if testval == 0 {
        // A match locks in this comparison ordering.
        if num == 1 {
            return 0;
        }
        let t = functional_equality_level0(data, r1[1], r2[1]);
        if t == 0 {
            return 0;
        }
        if t < 0 {
            return -1;
        }
        return 1; // match contingent on the second pair (res1[0]=res1[1], res2[0]=res2[1])
    }
    if num == 1 {
        return testval;
    }
    let testval2 = functional_equality_level0(data, r1[1], r2[1]);
    if testval2 == 0 {
        return testval; // locks in this ordering
    }
    let unmatchsize = if testval == 1 && testval2 == 1 { 2 } else { -1 };
    if !is_commutative(opc) {
        return unmatchsize;
    }
    // unmatchsize is 2 or -1 here on a commutative operator; try flipping.
    let comm1 = functional_equality_level0(data, r1[0], r2[1]);
    let comm2 = functional_equality_level0(data, r1[1], r2[0]);
    if comm1 == 0 && comm2 == 0 {
        return 0;
    }
    if comm1 < 0 || comm2 < 0 {
        return unmatchsize;
    }
    if comm1 == 0 {
        return 1; // leftover unmatch is res1[1]/res2[0]
    }
    if comm2 == 0 {
        return 1; // leftover unmatch is res1[0]/res2[1]
    }
    2 // both contingent (callers only test == 0, so the preferred ordering is immaterial)
}

/// Ghidra `functionalEquality` (expression.cc): are `vn1` and `vn2` provably the same value?
fn functional_equality(data: &Funcdata, vn1: VarnodeId, vn2: VarnodeId) -> bool {
    functional_equality_level(data, vn1, vn2) == 0
}

/// Ghidra `BlockBasic::earliestUse`: the earliest op in `block` that reads `vid`. We order ops by
/// their position in the block's op list (mosura's faithful analogue of Ghidra's `SeqNum` order).
fn earliest_use(data: &Funcdata, vid: VarnodeId, block: BlockId) -> Option<OpId> {
    let blk_ops = &data.block(block).ops;
    let mut best: Option<(usize, OpId)> = None;
    for &user in &data.vn(vid).descend {
        if data.op(user).parent != Some(block) {
            continue;
        }
        let Some(pos) = blk_ops.iter().position(|&o| o == user) else { continue };
        if best.is_none_or(|(bp, _)| pos < bp) {
            best = Some((pos, user));
        }
    }
    best.map(|(_, o)| o)
}

/// Ghidra `Funcdata::cseFindInBlock`: find an op in `block` (other than `op`, at or before
/// `earliest`) that reads `vid` and whose output is functionally equal to `op`'s output — i.e.
/// `op`'s computation already exists there. Block-list position stands in for `SeqNum` order.
fn cse_find_in_block(
    data: &Funcdata,
    op: OpId,
    vid: VarnodeId,
    block: BlockId,
    earliest: Option<OpId>,
) -> Option<OpId> {
    let blk_ops = &data.block(block).ops;
    let earliest_pos = earliest.and_then(|e| blk_ops.iter().position(|&o| o == e));
    let outvn1 = data.op(op).output?;
    for &res in &data.vn(vid).descend {
        if res == op {
            continue;
        }
        if data.op(res).parent != Some(block) {
            continue;
        }
        let Some(res_pos) = blk_ops.iter().position(|&o| o == res) else { continue };
        if let Some(ep) = earliest_pos {
            if ep < res_pos {
                continue; // must occur earlier than (or at) earliest
            }
        }
        let Some(outvn2) = data.op(res).output else { continue };
        if functional_equality_level(data, outvn1, outvn2) == 0 {
            return Some(res);
        }
    }
    None
}

/// Ghidra `RuleMultiCollapse` (ruleaction.cc): collapse a MULTIEQUAL whose inputs all trace to the
/// same value. A varnode that recurs in a loop (the phi reaching itself) is skipped — treated as
/// equal to every other branch. Inputs may match by *absolute* equality (same varnode) or by
/// *functional* equality (a `functionalEquality` computation, e.g. two `COPY const`); nested
/// MULTIEQUAL branches get one last chance by expanding their inputs into the match list. On the
/// functional-equality path, each collapsed op is rewritten to recompute the matched expression
/// (reusing an existing in-block copy when one dominates, via `cseFindInBlock`).
pub struct RuleMultiCollapse;

impl Rule for RuleMultiCollapse {
    fn name(&self) -> &str {
        "multicollapse"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Multiequal]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let num0 = data.op(op).num_inputs();
        // Everything must be heritaged before collapse.
        for i in 0..num0 {
            let inp = data.op(op).input(i).unwrap();
            if !data.vn(inp).is_heritage_known() {
                return 0;
            }
        }

        let mut func_eq = false; // start assuming absolute equality of branches
        let mut nofunc = false; // functional equalities initially allowed
        let mut defcopyr: Option<VarnodeId> = None;
        let mut matchlist: Vec<VarnodeId> =
            (0..num0).map(|i| data.op(op).input(i).unwrap()).collect();

        // Find the base branch to match: the first input not written by a MULTIEQUAL.
        let is_multi_written = |data: &Funcdata, v: VarnodeId| -> bool {
            let vn = data.vn(v);
            vn.is_written() && vn.def.is_some_and(|d| data.op(d).code() == OpCode::Multiequal)
        };
        for &copyr in &matchlist {
            if !is_multi_written(data, copyr) {
                defcopyr = Some(copyr);
                break;
            }
        }

        let mut success = true;
        let outvn = data.op(op).output.unwrap();
        data.vn_mut(outvn).set_mark();
        let mut skiplist: Vec<VarnodeId> = vec![outvn];
        let mut j = 0;
        while j < matchlist.len() {
            let copyr = matchlist[j];
            j += 1;
            if data.vn(copyr).is_mark() {
                continue; // a varnode we've seen — a loop recurrence; treat as equal, skip it
            }
            match defcopyr {
                None => {
                    // This is now the defining branch; all others must match it.
                    defcopyr = Some(copyr);
                    let vn = data.vn(copyr);
                    if vn.is_written() {
                        if vn.def.is_some_and(|d| data.op(d).code() == OpCode::Multiequal) {
                            nofunc = true; // MULTIEQUAL cannot match by functional equality
                        }
                    } else {
                        nofunc = true; // unwritten cannot match by functional equality
                    }
                }
                Some(dc) if dc == copyr => continue, // a matching branch
                Some(dc) if !nofunc && functional_equality(data, dc, copyr) => {
                    func_eq = true; // now matching by functional equality
                    continue;
                }
                Some(_) if is_multi_written(data, copyr) => {
                    // The non-matching branch is a MULTIEQUAL — give it one last chance and add
                    // its inputs to the list of things to match.
                    let newop = data.vn(copyr).def.unwrap();
                    skiplist.push(copyr);
                    data.vn_mut(copyr).set_mark();
                    let nin = data.op(newop).num_inputs();
                    for i in 0..nin {
                        matchlist.push(data.op(newop).input(i).unwrap());
                    }
                }
                Some(_) => {
                    success = false; // a non-matching branch
                    break;
                }
            }
        }

        // `defcopyr` is always set for a real MULTIEQUAL (≥1 non-self input); guard the
        // pathological all-self-loop case rather than unwrap-panic.
        if let (true, Some(defc)) = (success, defcopyr) {
            for &copyr in &skiplist {
                data.vn_mut(copyr).clear_mark();
                let cur_op = data.vn(copyr).def.unwrap(); // Ghidra: op = copyr->getDef()
                if func_eq {
                    // Functional equality: recompute the matched expression at this location.
                    let parent = data.op(cur_op).parent.unwrap();
                    let earliest = earliest_use(data, copyr, parent);
                    let newop = data.vn(defc).def.unwrap(); // copy newop (defcopyr's def)
                    let nin = data.op(newop).num_inputs();
                    let mut substitute: Option<OpId> = None;
                    for i in 0..nin {
                        let invn = data.op(newop).input(i).unwrap();
                        if !data.vn(invn).is_constant() {
                            // Has newop already been copied in this block?
                            substitute = cse_find_in_block(data, newop, invn, parent, earliest);
                            break;
                        }
                    }
                    if let Some(sub) = substitute {
                        // Already copied — reuse that copy's output.
                        let sub_out = data.op(sub).output.unwrap();
                        data.total_replace(copyr, sub_out);
                        data.op_destroy(cur_op);
                    } else {
                        // Otherwise create a copy by rewriting cur_op into newop's computation.
                        let needsreinsert = data.op(cur_op).code() == OpCode::Multiequal;
                        let parms: Vec<VarnodeId> =
                            (0..nin).map(|i| data.op(newop).input(i).unwrap()).collect();
                        data.op_set_all_input(cur_op, &parms);
                        let newcode = data.op(newop).code();
                        data.op_set_opcode(cur_op, newcode);
                        if needsreinsert {
                            // No longer a MULTIEQUAL — move it out of the leading-MULTIEQUAL region.
                            let bl = data.op(cur_op).parent.unwrap();
                            data.op_uninsert(cur_op);
                            data.op_insert_begin(cur_op, bl);
                        }
                    }
                } else {
                    // Absolute equality: replace all refs to copyr with defcopyr.
                    data.total_replace(copyr, defc);
                    data.op_destroy(cur_op);
                }
            }
            return 1;
        }

        for &copyr in &skiplist {
            data.vn_mut(copyr).clear_mark();
        }
        0
    }
}

/// Ghidra `RulePositiveDiv` (ruleaction.cc:7799; getOpList 7792): signed division of positive
/// values is unsigned division. If the sign bit of both the numerator and denominator of a signed
/// division (or remainder) is known-zero — proven via the non-zero mask ([`Varnode::get_nzmask`]) —
/// convert `INT_SDIV`/`INT_SREM` to the unsigned `INT_DIV`/`INT_REM`.
pub struct RulePositiveDiv;

impl Rule for RulePositiveDiv {
    fn name(&self) -> &str {
        "positivediv"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSdiv, OpCode::IntSrem]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(out) = data.op(op).output else { return 0 };
        let mut sa = data.vn(out).size;
        if sa > 8 {
            return 0; // Ghidra: sa > sizeof(uintb)
        }
        sa = sa * 8 - 1;
        let in0 = data.op(op).input(0).unwrap();
        if ((data.vn(in0).get_nzmask() >> sa) & 1) != 0 {
            return 0; // Input 0 may be negative
        }
        let in1 = data.op(op).input(1).unwrap();
        if ((data.vn(in1).get_nzmask() >> sa) & 1) != 0 {
            return 0; // Input 1 may be negative
        }
        let opc = if data.op(op).code() == OpCode::IntSdiv {
            OpCode::IntDiv
        } else {
            OpCode::IntRem
        };
        data.op_set_opcode(op, opc);
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::action::{Action, ActionPool};
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::{Funcdata, SeqNum};

    fn fd() -> (Funcdata, Address) {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        (Funcdata::new("t", Address::new(ram, 0), spaces), Address::new(ram, 0))
    }

    #[test]
    fn const_fold_basics() {
        assert_eq!(eval_const(OpCode::IntAnd, &[(0x2, 4), (0x1f, 4)], 4), Some(0x2));
        assert_eq!(eval_const(OpCode::IntAdd, &[(40, 4), (2, 4)], 4), Some(42));
        assert_eq!(eval_const(OpCode::IntSext, &[(0xff, 1)], 4), Some(0xffffffff));
        assert_eq!(eval_const(OpCode::IntZext, &[(0xff, 1)], 4), Some(0xff));
        assert_eq!(eval_const(OpCode::Subpiece, &[(0x1122334455667788, 8), (4, 4)], 4), Some(0x11223344));
        assert_eq!(eval_const(OpCode::Load, &[(0, 8)], 4), None);
    }

    #[test]
    fn const_fold_collapses_in_place_then_propagates() {
        let (mut f, ram) = fd();
        // out = INT_AND #2 #0x1f ; user = INT_ADD out #1
        let c2 = f.new_const(4, 2);
        let c1f = f.new_const(4, 0x1f);
        let seq = SeqNum { pc: ram, uniq: 0 };
        let and = f.new_op(OpCode::IntAnd, seq, vec![c2, c1f]);
        let out = f.new_output(and, 4, Address::new(f.spaces.by_name("register").unwrap(), 0));
        let c1 = f.new_const(4, 1);
        let add = f.new_op(OpCode::IntAdd, seq, vec![out, c1]);
        f.new_output(add, 4, Address::new(f.spaces.by_name("register").unwrap(), 8));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![and, add], ..Default::default() }]);

        // Ghidra `RuleCollapseConstants`: the AND is rewritten in place as `out = COPY #2` (not
        // propagated). The ADD still reads `out`; propagation is RulePropagateCopy's job.
        ActionPool::new("p").with(RuleConstFold).apply(&mut f);
        assert_eq!(f.op(and).code(), OpCode::Copy);
        assert_eq!(f.op(and).num_inputs(), 1);
        let and_in0 = f.op(and).input(0).unwrap();
        assert!(f.vn(and_in0).is_constant() && f.vn(and_in0).constant_value() == 2);
        assert_eq!(f.op(add).input(0), Some(out), "ADD still reads the COPY output, not the constant");

        // With RulePropagateCopy the constant reaches the ADD and the now-unused COPY output dies.
        ActionPool::new("p").with(RulePropagateCopy).apply(&mut f);
        let add_in0 = f.op(add).input(0).unwrap();
        assert!(f.vn(add_in0).is_constant() && f.vn(add_in0).constant_value() == 2);
        assert!(f.vn(out).descend.is_empty(), "COPY output no longer used after propagation");
    }

    #[test]
    fn trivial_arith_x_and_x() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let x = f.new_input(4, Address::new(reg, 0x10));
        let seq = SeqNum { pc: ram, uniq: 0 };
        let op = f.new_op(OpCode::IntAnd, seq, vec![x, x]);
        f.new_output(op, 4, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op], ..Default::default() }]);

        let mut pool = ActionPool::new("p").with(RuleTrivialArith);
        pool.apply(&mut f);
        // x & x  →  COPY x
        assert_eq!(f.op(op).code(), OpCode::Copy);
        assert_eq!(f.op(op).num_inputs(), 1);
        assert_eq!(f.op(op).input(0), Some(x));
    }

    #[test]
    fn termorder_then_identity_collapses_zero_add() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let x = f.new_input(4, Address::new(reg, 0x10));
        let zero = f.new_const(4, 0);
        let seq = SeqNum { pc: ram, uniq: 0 };
        let op = f.new_op(OpCode::IntAdd, seq, vec![zero, x]); // 0 + x (const in slot 0)
        f.new_output(op, 4, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op], ..Default::default() }]);

        let mut pool = ActionPool::new("p").with(RuleTermOrder).with(RuleIdentityEl);
        pool.apply(&mut f);
        // 0 + x  →  x + 0  →  COPY x
        assert_eq!(f.op(op).code(), OpCode::Copy);
        assert_eq!(f.op(op).input(0), Some(x));
    }

    #[test]
    fn mult_zero_and_shift_overflow_go_to_zero() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let x = f.new_input(4, Address::new(reg, 0x10));
        let seq = SeqNum { pc: ram, uniq: 0 };
        let z = f.new_const(4, 0);
        let m = f.new_op(OpCode::IntMult, seq, vec![x, z]); // x * 0
        f.new_output(m, 4, Address::new(reg, 0));
        let big = f.new_const(4, 64);
        let s = f.new_op(OpCode::IntLeft, seq, vec![x, big]); // x << 64
        f.new_output(s, 4, Address::new(reg, 8));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![m, s], ..Default::default() }]);

        let mut pool = ActionPool::new("p").with(RuleIdentityEl).with(RuleTrivialShift);
        pool.apply(&mut f);
        for op in [m, s] {
            assert_eq!(f.op(op).code(), OpCode::Copy);
            let in0 = f.op(op).input(0).unwrap();
            assert!(f.vn(in0).is_constant() && f.vn(in0).constant_value() == 0);
        }
    }

    #[test]
    fn collect_terms_a_plus_a2_is_a3() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let a = f.new_input(8, Address::new(reg, 0x38));
        let two = f.new_const(8, 2);
        let seq = SeqNum { pc: ram, uniq: 0 };
        let m = f.new_op(OpCode::IntMult, seq, vec![a, two]); // a * 2
        let mout = f.new_output(m, 8, Address::new(uniq, 0x100));
        let add = f.new_op(OpCode::IntAdd, seq, vec![a, mout]); // a + a*2
        f.new_output(add, 8, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![m, add], ..Default::default() }]);

        let mut pool = ActionPool::new("p").with(RuleTermOrder).with(RuleCollectTerms);
        pool.apply(&mut f);
        // a + a*2  →  a*3
        assert_eq!(f.op(add).code(), OpCode::IntMult);
        assert_eq!(f.op(add).input(0), Some(a));
        let c = f.op(add).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 3);
    }

    #[test]
    fn lessequal_collapses_jle_idiom() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let seq = SeqNum { pc: ram, uniq: 0 };
        // ZF: (a - b) == 0   (a distinct zero/constant, as the lifter emits)
        let sub = f.new_op(OpCode::IntSub, seq, vec![a, b]);
        let subout = f.new_output(sub, 4, Address::new(uniq, 0x100));
        let zero = f.new_const(4, 0);
        let eq = f.new_op(OpCode::IntEqual, seq, vec![subout, zero]);
        let eqout = f.new_output(eq, 1, Address::new(uniq, 0x200));
        // SF != OF, already collapsed by RuleSborrow to: a s< b
        let sl = f.new_op(OpCode::IntSless, seq, vec![a, b]);
        let slout = f.new_output(sl, 1, Address::new(uniq, 0x300));
        // jle = ZF || (SF != OF)
        let or = f.new_op(OpCode::BoolOr, seq, vec![eqout, slout]);
        f.new_output(or, 1, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![sub, eq, sl, or],
            ..Default::default()
        }]);

        let mut pool = ActionPool::new("p").with(RuleEqual2Zero).with(RuleLessEqual);
        pool.apply(&mut f);
        // (a - b == 0) || (a s< b)  =>  a s<= b
        assert_eq!(f.op(or).code(), OpCode::IntSlessequal);
        assert_eq!(f.op(or).input(0), Some(a));
        assert_eq!(f.op(or).input(1), Some(b));
    }

    #[test]
    fn boolnegate_flips_equal() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let a = f.new_input(4, Address::new(reg, 0x10));
        let nine = f.new_const(4, 9);
        let seq = SeqNum { pc: ram, uniq: 0 };
        let eq = f.new_op(OpCode::IntEqual, seq, vec![a, nine]);
        let eqout = f.new_output(eq, 1, Address::new(uniq, 0x100));
        let neg = f.new_op(OpCode::BoolNegate, seq, vec![eqout]);
        f.new_output(neg, 1, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![eq, neg], ..Default::default() }]);
        ActionPool::new("p").with(RuleBoolNegate).apply(&mut f);
        // !(a == 9)  =>  a != 9
        assert_eq!(f.op(neg).code(), OpCode::IntNotequal);
        assert_eq!(f.op(neg).input(0), Some(a));
    }

    #[test]
    fn logic2bool_converts_int_or_of_booleans() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let nine = f.new_const(4, 9);
        let ten = f.new_const(4, 10);
        // two comparisons (booloutput) feed an INT_OR — nan's `(a==9) | (b==10)` flag web
        let c1 = f.new_op(OpCode::IntEqual, seq, vec![a, nine]);
        let c1o = f.new_output(c1, 1, Address::new(uniq, 0x100));
        let c2 = f.new_op(OpCode::IntEqual, seq, vec![b, ten]);
        let c2o = f.new_output(c2, 1, Address::new(uniq, 0x200));
        let or = f.new_op(OpCode::IntOr, seq, vec![c1o, c2o]);
        f.new_output(or, 1, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![c1, c2, or], ..Default::default() }]);
        ActionPool::new("p").with(RuleLogic2Bool).apply(&mut f);
        assert_eq!(f.op(or).code(), OpCode::BoolOr, "INT_OR of two comparisons becomes BOOL_OR");
    }

    #[test]
    fn logic2bool_leaves_nonboolean_int_or() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // INT_OR of two plain register reads (not booleans) must not be rewritten.
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let or = f.new_op(OpCode::IntOr, seq, vec![a, b]);
        f.new_output(or, 4, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![or], ..Default::default() }]);
        ActionPool::new("p").with(RuleLogic2Bool).apply(&mut f);
        assert_eq!(f.op(or).code(), OpCode::IntOr, "INT_OR of non-booleans is unchanged");
    }

    #[test]
    fn ormask_collapses_or_with_allones() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(8, Address::new(reg, 0x10));
        let allones = f.new_const(8, u64::MAX); // -1
        let or = f.new_op(OpCode::IntOr, seq, vec![a, allones]);
        f.new_output(or, 8, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![or], ..Default::default() }]);
        ActionPool::new("p").with(RuleOrMask).apply(&mut f);
        assert_eq!(f.op(or).code(), OpCode::Copy, "V | -1 collapses to COPY -1");
        assert_eq!(f.op(or).input(0), Some(allones));
    }

    #[test]
    fn ormask_leaves_partial_mask() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(8, Address::new(reg, 0x10));
        let partial = f.new_const(8, 0xff); // not every bit set
        let or = f.new_op(OpCode::IntOr, seq, vec![a, partial]);
        f.new_output(or, 8, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![or], ..Default::default() }]);
        ActionPool::new("p").with(RuleOrMask).apply(&mut f);
        assert_eq!(f.op(or).code(), OpCode::IntOr, "a partial mask does not collapse the OR");
    }

    #[test]
    fn selectcse_merges_duplicate_subpieces() {
        use crate::decompile::{BlockBasic, BlockId};
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let r = f.new_input(8, Address::new(reg, 0x8));
        let seq = SeqNum { pc: ram, uniq: 0 };
        // two distinct SUBPIECE(r, 0):4 — what heritage's read-size normalization produces
        let z1 = f.new_const(8, 0);
        let s1 = f.new_op(OpCode::Subpiece, seq, vec![r, z1]);
        let s1o = f.new_output(s1, 4, Address::new(uniq, 0x100));
        let z2 = f.new_const(8, 0);
        let s2 = f.new_op(OpCode::Subpiece, seq, vec![r, z2]);
        let s2o = f.new_output(s2, 4, Address::new(uniq, 0x200));
        let x = f.new_op(OpCode::IntXor, seq, vec![s1o, s2o]);
        f.new_output(x, 4, Address::new(reg, 0));
        f.set_blocks(vec![BlockBasic { ops: vec![s1, s2, x], ..Default::default() }]);
        for op in [s1, s2, x] {
            f.op_mut(op).parent = Some(BlockId(0));
        }
        ActionPool::new("p").with(RuleSelectCse).with(RuleIdempotent).apply(&mut f);
        // CSE collapses the duplicate SUBPIECEs, so the xor becomes `s ^ s` → 0
        assert_eq!(f.op(x).code(), OpCode::Copy);
        assert!(f.vn(f.op(x).input(0).unwrap()).is_constant());
    }

    #[test]
    fn rangeand_merges_disequality_into_strict() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let x = f.new_input(4, Address::new(reg, 0x10));
        let c = f.new_const(4, 9);
        let seq = SeqNum { pc: ram, uniq: 0 };
        let ne = f.new_op(OpCode::IntNotequal, seq, vec![x, c]);
        let neout = f.new_output(ne, 1, Address::new(uniq, 0x100));
        let le = f.new_op(OpCode::IntSlessequal, seq, vec![c, x]); // 9 <= x
        let leout = f.new_output(le, 1, Address::new(uniq, 0x200));
        let and = f.new_op(OpCode::BoolAnd, seq, vec![neout, leout]);
        f.new_output(and, 1, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![ne, le, and], ..Default::default() }]);
        ActionPool::new("p").with(RuleRangeAnd).apply(&mut f);
        // (x != 9) && (9 s<= x)  =>  9 s< x
        assert_eq!(f.op(and).code(), OpCode::IntSless);
        assert_eq!(f.op(and).input(0), Some(c));
        assert_eq!(f.op(and).input(1), Some(x));
    }

    #[test]
    fn sborrow_collapses_to_signed_less() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let seq = SeqNum { pc: ram, uniq: 0 };
        let sb = f.new_op(OpCode::IntSborrow, seq, vec![a, b]); // sborrow(a,b)
        let sbout = f.new_output(sb, 1, Address::new(uniq, 0x100));
        let sub = f.new_op(OpCode::IntSub, seq, vec![a, b]); // a - b
        let subout = f.new_output(sub, 4, Address::new(uniq, 0x200));
        let zero = f.new_const(4, 0);
        let sl = f.new_op(OpCode::IntSless, seq, vec![subout, zero]); // (a-b) s< 0
        let slout = f.new_output(sl, 1, Address::new(uniq, 0x300));
        let ne = f.new_op(OpCode::IntNotequal, seq, vec![sbout, slout]); // sborrow != (a-b s< 0)
        f.new_output(ne, 1, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![sb, sub, sl, ne],
            ..Default::default()
        }]);

        let mut pool = ActionPool::new("p").with(RuleSborrow);
        pool.apply(&mut f);
        // sborrow(a,b) != ((a-b) s< 0)  →  a s< b
        assert_eq!(f.op(ne).code(), OpCode::IntSless);
        assert_eq!(f.op(ne).input(0), Some(a));
        assert_eq!(f.op(ne).input(1), Some(b));
    }

    #[test]
    fn shift_add_collects_to_mult() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let a = f.new_input(8, Address::new(reg, 0x38));
        let two = f.new_const(8, 2);
        let seq = SeqNum { pc: ram, uniq: 0 };
        let sh = f.new_op(OpCode::IntLeft, seq, vec![a, two]); // a << 2  (== a*4)
        let shout = f.new_output(sh, 8, Address::new(uniq, 0x100));
        let add = f.new_op(OpCode::IntAdd, seq, vec![shout, a]); // (a<<2) + a
        f.new_output(add, 8, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![sh, add], ..Default::default() }]);

        let mut pool = ActionPool::new("p").with(RuleTermOrder).with(RuleCollectTerms);
        pool.apply(&mut f);
        // (a<<2) + a  →  a*5  (the lea-as-multiply Ghidra recovers)
        assert_eq!(f.op(add).code(), OpCode::IntMult);
        assert_eq!(f.op(add).input(0), Some(a));
        let c = f.op(add).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 5);
    }

    #[test]
    fn propagate_copy_threads_through() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let a = f.new_input(4, Address::new(reg, 0x38));
        let seq = SeqNum { pc: ram, uniq: 0 };
        let cp = f.new_op(OpCode::Copy, seq, vec![a]); // c = COPY a
        let c = f.new_output(cp, 4, Address::new(uniq, 0x100));
        let b = f.new_input(4, Address::new(reg, 0x30));
        let add = f.new_op(OpCode::IntAdd, seq, vec![c, b]); // c + b
        f.new_output(add, 4, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![cp, add], ..Default::default() }]);

        let mut pool = ActionPool::new("p").with(RulePropagateCopy);
        pool.apply(&mut f);
        // the ADD now reads `a` directly; the COPY's output is no longer used
        assert_eq!(f.op(add).input(0), Some(a));
        assert!(f.vn(c).descend.is_empty());
    }

    #[test]
    fn addmultcollapse_flattens_nested_constant_add() {
        // `(V + c) + d  =>  V + (c+d)` — the chained stack-frame base collapse.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let v = f.new_input(8, Address::new(reg, 0x20));
        let c = f.new_const(8, 0xfffffffffffffff8); // -8
        let seq = SeqNum { pc: ram, uniq: 0 };
        let inner = f.new_op(OpCode::IntAdd, seq, vec![v, c]); // V + -8
        let iout = f.new_output(inner, 8, Address::new(uniq, 0x100));
        let d = f.new_const(8, 0xffffffffffffff70); // -0x90
        let outer = f.new_op(OpCode::IntAdd, seq, vec![iout, d]); // (V + -8) + -0x90
        f.new_output(outer, 8, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![inner, outer], ..Default::default() }]);

        ActionPool::new("p").with(RuleAddMultCollapse).apply(&mut f);
        // V + -0x98: the two constant offsets are summed and the intermediate add is bypassed
        assert_eq!(f.op(outer).code(), OpCode::IntAdd);
        assert_eq!(f.op(outer).input(0), Some(v));
        let c2 = f.op(outer).input(1).unwrap();
        assert!(f.vn(c2).is_constant());
        assert_eq!(f.vn(c2).constant_value(), 0xffffffffffffff68); // -8 + -0x90 = -0x98
    }

    #[test]
    fn sub2add_canonicalises_then_cleanup_round_trips() {
        // RuleSub2Add turns `V - W` into `V + (W * -1)`; the cleanup pool then restores `V - W`.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let v = f.new_input(4, Address::new(reg, 0x30));
        let w = f.new_input(4, Address::new(reg, 0x38));
        let seq = SeqNum { pc: ram, uniq: 0 };
        let sub = f.new_op(OpCode::IntSub, seq, vec![v, w]); // V - W
        f.new_output(sub, 4, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![sub], ..Default::default() }]);

        ActionPool::new("p").with(RuleSub2Add).apply(&mut f);
        // V + (W * -1): the op is now INT_ADD; input 1 is W * -1
        assert_eq!(f.op(sub).code(), OpCode::IntAdd);
        assert_eq!(f.op(sub).input(0), Some(v));
        let prod = f.op(sub).input(1).unwrap();
        let mul = f.vn(prod).def.unwrap();
        assert_eq!(f.op(mul).code(), OpCode::IntMult);
        assert_eq!(f.op(mul).input(0), Some(w));
        let c = f.op(mul).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 0xffffffff);

        // cleanup restores the subtraction
        ActionPool::new("c").with(RuleMultNegOne).with(Rule2Comp2Sub).apply(&mut f);
        assert_eq!(f.op(sub).code(), OpCode::IntSub);
        assert_eq!(f.op(sub).input(0), Some(v));
        assert_eq!(f.op(sub).input(1), Some(w));
    }

    #[test]
    fn multnegone_then_2comp2sub_reconstructs_subtraction() {
        // `V + (W * -1)` — the canonical form RuleSub2Add leaves for a non-constant subtraction —
        // is reduced to `INT_2COMP(W)` then folded into `V - W`.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let v = f.new_input(4, Address::new(reg, 0x30));
        let w = f.new_input(4, Address::new(reg, 0x38));
        let seq = SeqNum { pc: ram, uniq: 0 };
        let neg1 = f.new_const(4, 0xffffffff);
        let mul = f.new_op(OpCode::IntMult, seq, vec![w, neg1]); // W * -1
        let mout = f.new_output(mul, 4, Address::new(uniq, 0x100));
        let add = f.new_op(OpCode::IntAdd, seq, vec![v, mout]); // V + (W*-1)
        f.new_output(add, 4, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![mul, add], ..Default::default() }]);

        let mut pool = ActionPool::new("p").with(RuleMultNegOne).with(Rule2Comp2Sub);
        pool.apply(&mut f);
        // V - W: the INT_MULT became INT_2COMP and was absorbed into the now-INT_SUB
        assert_eq!(f.op(add).code(), OpCode::IntSub);
        assert_eq!(f.op(add).input(0), Some(v));
        assert_eq!(f.op(add).input(1), Some(w));
        assert!(f.op(mul).is_dead());
    }

    // --- RuleMultiCollapse ------------------------------------------------

    /// Two identical branches: `out = MULTIEQUAL(a, a)` collapses to `a` (absolute equality).
    #[test]
    fn multicollapse_absolute_equality() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let a = f.new_input(4, Address::new(reg, 0x10));
        let seq = SeqNum { pc: ram, uniq: u32::MAX };
        let op = f.new_op(OpCode::Multiequal, seq, vec![a, a]);
        let out = f.new_output(op, 4, Address::new(reg, 0x20));
        let user = f.new_op(OpCode::Copy, SeqNum { pc: ram, uniq: 1 }, vec![out]);
        f.new_output(user, 4, Address::new(reg, 0x28));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op, user], ..Default::default() }]);

        assert_eq!(RuleMultiCollapse.apply_op(op, &mut f), 1);
        assert!(f.op(op).is_dead(), "the MULTIEQUAL is destroyed");
        assert_eq!(f.op(user).input(0), Some(a), "the use now reads a directly");
    }

    /// A value that recurs unchanged in a loop — `out = MULTIEQUAL(a, out)` — collapses to `a`:
    /// the self-referential branch is skipped as a recurrence, leaving only `a`.
    #[test]
    fn multicollapse_loop_recurrence() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let a = f.new_input(4, Address::new(reg, 0x10));
        let seq = SeqNum { pc: ram, uniq: u32::MAX };
        let op = f.new_op(OpCode::Multiequal, seq, vec![a, a]); // 2nd input fixed up below
        let out = f.new_output(op, 4, Address::new(reg, 0x20));
        f.op_set_input(op, 1, out); // the phi reaches itself (loop back-edge)
        let user = f.new_op(OpCode::Copy, SeqNum { pc: ram, uniq: 1 }, vec![out]);
        f.new_output(user, 4, Address::new(reg, 0x28));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op, user], ..Default::default() }]);

        assert_eq!(RuleMultiCollapse.apply_op(op, &mut f), 1);
        assert!(f.op(op).is_dead());
        assert_eq!(f.op(user).input(0), Some(a));
    }

    /// CORRECTNESS GUARD: distinct values must NOT be merged. `MULTIEQUAL(a, b)` with two
    /// different inputs returns 0 (no change) and the MULTIEQUAL survives.
    #[test]
    fn multicollapse_keeps_distinct_values() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let seq = SeqNum { pc: ram, uniq: u32::MAX };
        let op = f.new_op(OpCode::Multiequal, seq, vec![a, b]);
        let out = f.new_output(op, 4, Address::new(reg, 0x20));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op], ..Default::default() }]);

        assert_eq!(RuleMultiCollapse.apply_op(op, &mut f), 0, "distinct branches do not collapse");
        assert!(!f.op(op).is_dead());
        assert_eq!(f.op(op).code(), OpCode::Multiequal);
        assert_eq!(f.op(op).input(0), Some(a));
        assert_eq!(f.op(op).input(1), Some(b));
        assert!(!f.vn(out).is_mark(), "the traversal mark is cleared on the failure path");
    }

    /// Functional equality: two branches that each `COPY` the same constant collapse, with the
    /// MULTIEQUAL rewritten in place into that `COPY const` (the recompute path, no `cseFindInBlock`
    /// hit because the operand is constant).
    #[test]
    fn multicollapse_functional_equality_copy_const() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let off = 0x20;
        // Two separate `COPY #5` ops feeding the phi from two predecessor blocks.
        let c5a = f.new_const(4, 5);
        let copy_a = f.new_op(OpCode::Copy, SeqNum { pc: ram, uniq: 1 }, vec![c5a]);
        let va = f.new_output(copy_a, 4, Address::new(reg, off));
        let c5b = f.new_const(4, 5);
        let copy_b = f.new_op(OpCode::Copy, SeqNum { pc: ram, uniq: 2 }, vec![c5b]);
        let vb = f.new_output(copy_b, 4, Address::new(reg, off));
        // Three blocks: the two defs, then the merge holding the MULTIEQUAL.
        f.set_blocks(vec![
            crate::decompile::BlockBasic { ops: vec![copy_a], ..Default::default() },
            crate::decompile::BlockBasic { ops: vec![copy_b], ..Default::default() },
            crate::decompile::BlockBasic::default(),
        ]);
        let merge = crate::decompile::BlockId(2);
        let op = f.new_multiequal(merge, reg, off, 4, 2);
        f.op_set_input(op, 0, va);
        f.op_set_input(op, 1, vb);
        let out = f.op(op).output.unwrap();
        let user = f.new_op(OpCode::Copy, SeqNum { pc: ram, uniq: 3 }, vec![out]);
        f.new_output(user, 4, Address::new(reg, 0x30));
        f.op_insert_begin(user, merge);

        assert_eq!(RuleMultiCollapse.apply_op(op, &mut f), 1);
        // The MULTIEQUAL became `out = COPY #5` (alive, recomputed), and the use still reads it.
        assert!(!f.op(op).is_dead());
        assert_eq!(f.op(op).code(), OpCode::Copy);
        let in0 = f.op(op).input(0).unwrap();
        assert!(f.vn(in0).is_constant() && f.vn(in0).constant_value() == 5);
        assert_eq!(f.op(user).input(0), Some(out), "use still reads the collapsed value");
        // and it now sits after the (now absent) leading MULTIEQUALs, i.e. ahead of the user.
        assert!(f.block(merge).ops.contains(&op));
    }

    // --- RuleSlessToLess (ruleaction.cc:2530) ---------------------------------

    #[test]
    fn sless_to_less_when_both_operands_nonnegative() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // ta = a & 0x7f ; tb = b & 0x7f  → both provably non-negative (nzm has the sign bit clear).
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let m1 = f.new_const(4, 0x7f);
        let and_a = f.new_op(OpCode::IntAnd, seq, vec![a, m1]);
        let ta = f.new_output_unique(and_a, 4);
        let m2 = f.new_const(4, 0x7f);
        let and_b = f.new_op(OpCode::IntAnd, seq, vec![b, m2]);
        let tb = f.new_output_unique(and_b, 4);
        let sless = f.new_op(OpCode::IntSless, seq, vec![ta, tb]);
        f.new_output_unique(sless, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![and_a, and_b, sless],
            ..Default::default()
        }]);

        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        assert_eq!(f.vn(ta).get_nzmask(), 0x7f, "masked value proves the sign bit is clear");

        ActionPool::new("p").with(RuleSlessToLess).apply(&mut f);
        // Ghidra RuleSlessToLess: both operands non-negative ⇒ INT_SLESS → INT_LESS.
        assert_eq!(f.op(sless).code(), OpCode::IntLess);
    }

    #[test]
    fn sless_to_less_declines_when_sign_bit_possible() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // Plain 4-byte inputs: nzm is the full mask, so the sign bit may be set → rule must not fire.
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let sless = f.new_op(OpCode::IntSless, seq, vec![a, b]);
        f.new_output_unique(sless, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![sless],
            ..Default::default()
        }]);

        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        ActionPool::new("p").with(RuleSlessToLess).apply(&mut f);
        assert_eq!(f.op(sless).code(), OpCode::IntSless, "sign bit may be set ⇒ stays signed");
    }

    // --- RulePopcountBoolXor (ruleaction.cc:10273) ----------------------------

    #[test]
    fn popcount_bool_xor_single_bit_to_copy() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // b1 = (a == b)  → boolean, nzm 1
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let eq = f.new_op(OpCode::IntEqual, seq, vec![a, b]);
        let b1 = f.new_output_unique(eq, 1);
        // s = zext(b1) << 6   → a single set bit at position 6
        let z = f.new_op(OpCode::IntZext, seq, vec![b1]);
        let zo = f.new_output_unique(z, 8);
        let sh6 = f.new_const(4, 6);
        let sh = f.new_op(OpCode::IntLeft, seq, vec![zo, sh6]);
        let so = f.new_output_unique(sh, 8);
        // p = popcount(s) ; and = p & 1   (parity check of the one shifted boolean)
        let pc = f.new_op(OpCode::Popcount, seq, vec![so]);
        let po = f.new_output_unique(pc, 1);
        let one = f.new_const(1, 1);
        let and = f.new_op(OpCode::IntAnd, seq, vec![po, one]);
        f.new_output_unique(and, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![eq, z, sh, pc, and],
            ..Default::default()
        }]);

        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        assert_eq!(f.vn(so).get_nzmask(), 0x40, "single boolean bit at position 6");

        ActionPool::new("p").with(RulePopcountBoolXor).apply(&mut f);
        // Ghidra RulePopcountBoolXor: popcount(b1 << 6) & 1  →  COPY(b1).
        assert_eq!(f.op(and).code(), OpCode::Copy);
        assert_eq!(f.op(and).num_inputs(), 1);
        assert_eq!(f.op(and).input(0), Some(b1));
    }

    #[test]
    fn popcount_bool_xor_two_bits_to_xor() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let c = f.new_input(4, Address::new(reg, 0x20));
        let d = f.new_input(4, Address::new(reg, 0x28));
        // b1 = (a == b) ; b2 = (c == d)
        let eq1 = f.new_op(OpCode::IntEqual, seq, vec![a, b]);
        let b1 = f.new_output_unique(eq1, 1);
        let eq2 = f.new_op(OpCode::IntEqual, seq, vec![c, d]);
        let b2 = f.new_output_unique(eq2, 1);
        // o = (zext(b1) << 6) | (zext(b2) << 2)  → set bits at positions 6 and 2
        let z1 = f.new_op(OpCode::IntZext, seq, vec![b1]);
        let z1o = f.new_output_unique(z1, 8);
        let z2 = f.new_op(OpCode::IntZext, seq, vec![b2]);
        let z2o = f.new_output_unique(z2, 8);
        let sh6 = f.new_const(4, 6);
        let s1 = f.new_op(OpCode::IntLeft, seq, vec![z1o, sh6]);
        let s1o = f.new_output_unique(s1, 8);
        let sh2 = f.new_const(4, 2);
        let s2 = f.new_op(OpCode::IntLeft, seq, vec![z2o, sh2]);
        let s2o = f.new_output_unique(s2, 8);
        let or = f.new_op(OpCode::IntOr, seq, vec![s1o, s2o]);
        let oo = f.new_output_unique(or, 8);
        // p = popcount(o) ; and = p & 1
        let pc = f.new_op(OpCode::Popcount, seq, vec![oo]);
        let po = f.new_output_unique(pc, 1);
        let one = f.new_const(1, 1);
        let and = f.new_op(OpCode::IntAnd, seq, vec![po, one]);
        f.new_output_unique(and, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![eq1, eq2, z1, z2, s1, s2, or, pc, and],
            ..Default::default()
        }]);

        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        assert_eq!(f.vn(oo).get_nzmask(), 0x44, "two boolean bits at positions 2 and 6");

        ActionPool::new("p").with(RulePopcountBoolXor).apply(&mut f);
        // Ghidra RulePopcountBoolXor: popcount((b1 << 6) | (b2 << 2)) & 1  →  b1 ^ b2.
        assert_eq!(f.op(and).code(), OpCode::IntXor);
        let ins = [f.op(and).input(0).unwrap(), f.op(and).input(1).unwrap()];
        assert!(ins.contains(&b1) && ins.contains(&b2), "XOR of the two booleans");
    }

    // --- RuleOrCollapse (ruleaction.cc:384) -----------------------------------

    #[test]
    fn or_collapse_when_operand_bits_subset_of_const() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // t = a & 0x0f  (nzm 0x0f) ; t | 0x0f  →  0x0f  (OR turns on no new bit)
        let a = f.new_input(4, Address::new(reg, 0x10));
        let m = f.new_const(4, 0x0f);
        let and = f.new_op(OpCode::IntAnd, seq, vec![a, m]);
        let t = f.new_output_unique(and, 4);
        let c = f.new_const(4, 0x0f);
        let or = f.new_op(OpCode::IntOr, seq, vec![t, c]);
        f.new_output_unique(or, 4);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![and, or],
            ..Default::default()
        }]);
        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        ActionPool::new("p").with(RuleOrCollapse).apply(&mut f);
        assert_eq!(f.op(or).code(), OpCode::Copy);
        assert_eq!(f.op(or).num_inputs(), 1);
        let in0 = f.op(or).input(0).unwrap();
        assert!(f.vn(in0).is_constant() && f.vn(in0).constant_value() == 0x0f);
    }

    // --- RuleXorCollapse (ruleaction.cc:4050) ---------------------------------

    #[test]
    fn xor_collapse_folds_const_into_compare() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // (v ^ 5) == 3   →   v == (5 ^ 3 = 6)
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c5 = f.new_const(4, 0x5);
        let xor = f.new_op(OpCode::IntXor, seq, vec![v, c5]);
        let t = f.new_output_unique(xor, 4);
        let d3 = f.new_const(4, 0x3);
        let eq = f.new_op(OpCode::IntEqual, seq, vec![t, d3]);
        f.new_output_unique(eq, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![xor, eq],
            ..Default::default()
        }]);
        ActionPool::new("p").with(RuleXorCollapse).apply(&mut f);
        assert_eq!(f.op(eq).code(), OpCode::IntEqual);
        assert_eq!(f.op(eq).input(0), Some(v));
        let d = f.op(eq).input(1).unwrap();
        assert!(f.vn(d).is_constant() && f.vn(d).constant_value() == 0x6);
    }

    // --- RuleHighOrderAnd (ruleaction.cc:1196) --------------------------------

    #[test]
    fn high_order_and_pushes_mask_into_add_const() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // xalign = b & 0xf0  (nzm 0xf0, low 4 bits clear → unaffected by & 0xfff0)
        let b = f.new_input(2, Address::new(reg, 0x10));
        let m = f.new_const(2, 0xf0);
        let anda = f.new_op(OpCode::IntAnd, seq, vec![b, m]);
        let xalign = f.new_output_unique(anda, 2);
        let c2 = f.new_const(2, 0x1234);
        let add = f.new_op(OpCode::IntAdd, seq, vec![xalign, c2]);
        let addout = f.new_output_unique(add, 2);
        let mask = f.new_const(2, 0xfff0);
        let and = f.new_op(OpCode::IntAnd, seq, vec![addout, mask]);
        f.new_output_unique(and, 2);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![anda, add, and],
            ..Default::default()
        }]);
        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        ActionPool::new("p").with(RuleHighOrderAnd).apply(&mut f);
        // (xalign + 0x1234) & 0xfff0  →  xalign + (0x1234 & 0xfff0 = 0x1230)
        assert_eq!(f.op(and).code(), OpCode::IntAdd);
        assert_eq!(f.op(and).input(0), Some(xalign));
        let c = f.op(and).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 0x1230);
    }

    // --- RuleNotDistribute (ruleaction.cc:1147) — ported + held (see the rule's doc comment) --

    #[test]
    fn not_distribute_de_morgan() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // neg = !(v && w)   →   !v || !w
        let v = f.new_input(1, Address::new(reg, 0x10));
        let w = f.new_input(1, Address::new(reg, 0x18));
        let and = f.new_op(OpCode::BoolAnd, seq, vec![v, w]);
        let andout = f.new_output_unique(and, 1);
        let neg = f.new_op(OpCode::BoolNegate, seq, vec![andout]);
        f.new_output_unique(neg, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![and, neg],
            ..Default::default()
        }]);
        assert_eq!(RuleNotDistribute.apply_op(neg, &mut f), 1);
        assert_eq!(f.op(neg).code(), OpCode::BoolOr);
        let (i0, i1) = (f.op(neg).input(0).unwrap(), f.op(neg).input(1).unwrap());
        let d0 = f.vn(i0).def.unwrap();
        let d1 = f.vn(i1).def.unwrap();
        assert_eq!(f.op(d0).code(), OpCode::BoolNegate);
        assert_eq!(f.op(d1).code(), OpCode::BoolNegate);
        assert_eq!(f.op(d0).input(0), Some(v));
        assert_eq!(f.op(d1).input(0), Some(w));
    }

    // --- RuleZextShiftZext (ruleaction.cc:4865) — wired -----------------------

    #[test]
    fn zext_shift_zext_collapses_double_zext() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // zext(zext(V:2 -> 4) -> 8)  =>  zext(V:2 -> 8)
        let v = f.new_input(2, Address::new(reg, 0x10));
        let z1 = f.new_op(OpCode::IntZext, seq, vec![v]);
        let z1o = f.new_output_unique(z1, 4);
        let z2 = f.new_op(OpCode::IntZext, seq, vec![z1o]);
        f.new_output_unique(z2, 8);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![z1, z2],
            ..Default::default()
        }]);
        ActionPool::new("p").with(RuleZextShiftZext).apply(&mut f);
        assert_eq!(f.op(z2).code(), OpCode::IntZext);
        assert_eq!(f.op(z2).input(0), Some(v));
    }

    #[test]
    fn zext_shift_zext_pulls_shift_outside() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // zext( zext(V:1 -> 4) << 8 )  =>  zext(V:1 -> 8) << 8   (8 <= 8*(4-1), keeps bits)
        let v = f.new_input(1, Address::new(reg, 0x10));
        let z1 = f.new_op(OpCode::IntZext, seq, vec![v]);
        let z1o = f.new_output_unique(z1, 4);
        let sh = f.new_const(4, 8);
        let shl = f.new_op(OpCode::IntLeft, seq, vec![z1o, sh]);
        let shlo = f.new_output_unique(shl, 4);
        let z2 = f.new_op(OpCode::IntZext, seq, vec![shlo]);
        f.new_output_unique(z2, 8);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![z1, shl, z2],
            ..Default::default()
        }]);
        ActionPool::new("p").with(RuleZextShiftZext).apply(&mut f);
        // z2 is now  ZEXT(v):8 << 8
        assert_eq!(f.op(z2).code(), OpCode::IntLeft);
        let nz = f.op(z2).input(0).unwrap();
        let nzdef = f.vn(nz).def.unwrap();
        assert_eq!(f.op(nzdef).code(), OpCode::IntZext);
        assert_eq!(f.op(nzdef).input(0), Some(v));
        assert_eq!(f.vn(nz).size, 8);
        let c = f.op(z2).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 8);
    }

    // --- RuleAndCompare (ruleaction.cc:1745) — ported + held ------------------

    #[test]
    fn and_compare_widens_mask_through_zext() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // (zext(V:2 -> 4) & 0x1ff) == 0   =>   (V & 0x1ff) == 0
        let v = f.new_input(2, Address::new(reg, 0x10));
        let z = f.new_op(OpCode::IntZext, seq, vec![v]);
        let zo = f.new_output_unique(z, 4);
        let c = f.new_const(4, 0x1ff);
        let and = f.new_op(OpCode::IntAnd, seq, vec![zo, c]);
        let ando = f.new_output_unique(and, 4);
        let zero = f.new_const(4, 0);
        let eq = f.new_op(OpCode::IntEqual, seq, vec![ando, zero]);
        f.new_output_unique(eq, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![z, and, eq],
            ..Default::default()
        }]);
        assert_eq!(RuleAndCompare.apply_op(eq, &mut f), 1);
        assert_eq!(f.op(eq).code(), OpCode::IntEqual);
        let a0 = f.op(eq).input(0).unwrap();
        let d = f.vn(a0).def.unwrap();
        assert_eq!(f.op(d).code(), OpCode::IntAnd);
        assert_eq!(f.op(d).input(0), Some(v));
        let dc = f.op(d).input(1).unwrap();
        assert!(f.vn(dc).is_constant() && f.vn(dc).constant_value() == 0x1ff && f.vn(dc).size == 2);
        let z1 = f.op(eq).input(1).unwrap();
        assert!(f.vn(z1).is_constant() && f.vn(z1).constant_value() == 0);
    }

    // --- RuleSubZext (ruleaction.cc:5039) — ported + held ---------------------

    #[test]
    fn sub_zext_low_truncation_becomes_and_mask() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // zext( sub(V:4, 0):2 -> 4 )  =>  V & 0xffff
        let v = f.new_input(4, Address::new(reg, 0x10));
        let off0 = f.new_const(4, 0);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![v, off0]);
        let subo = f.new_output_unique(sub, 2);
        let z = f.new_op(OpCode::IntZext, seq, vec![subo]);
        f.new_output_unique(z, 4);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![sub, z],
            ..Default::default()
        }]);
        assert_eq!(RuleSubZext.apply_op(z, &mut f), 1);
        assert_eq!(f.op(z).code(), OpCode::IntAnd);
        assert_eq!(f.op(z).input(0), Some(v));
        let m = f.op(z).input(1).unwrap();
        assert!(f.vn(m).is_constant() && f.vn(m).constant_value() == 0xffff);
    }

    #[test]
    fn sub_zext_mid_truncation_becomes_shift_and_mask() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // zext( sub(V:4, 2):2 -> 4 )  =>  (V >> 16) & 0xffff
        let v = f.new_input(4, Address::new(reg, 0x10));
        let off2 = f.new_const(4, 2);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![v, off2]);
        let subo = f.new_output_unique(sub, 2);
        let z = f.new_op(OpCode::IntZext, seq, vec![subo]);
        f.new_output_unique(z, 4);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![sub, z],
            ..Default::default()
        }]);
        assert_eq!(RuleSubZext.apply_op(z, &mut f), 1);
        assert_eq!(f.op(z).code(), OpCode::IntAnd);
        let sh = f.op(z).input(0).unwrap();
        let shd = f.vn(sh).def.unwrap();
        assert_eq!(f.op(shd).code(), OpCode::IntRight);
        assert_eq!(f.op(shd).input(0), Some(v));
        let sa = f.op(shd).input(1).unwrap();
        assert!(f.vn(sa).is_constant() && f.vn(sa).constant_value() == 16);
        let m = f.op(z).input(1).unwrap();
        assert!(f.vn(m).is_constant() && f.vn(m).constant_value() == 0xffff);
    }

    // --- RulePiece2Zext (ruleaction.cc:219) — ported, wiring pending (see doc comment) --

    #[test]
    fn piece2zext_zero_high_becomes_zext() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // concat(#0:2, W:2) : 4  =>  zext(W)
        let w = f.new_input(2, Address::new(reg, 0x10));
        let hi0 = f.new_const(2, 0);
        let piece = f.new_op(OpCode::Piece, seq, vec![hi0, w]);
        f.new_output_unique(piece, 4);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![piece],
            ..Default::default()
        }]);
        assert_eq!(RulePiece2Zext.apply_op(piece, &mut f), 1);
        assert_eq!(f.op(piece).code(), OpCode::IntZext);
        assert_eq!(f.op(piece).num_inputs(), 1);
        assert_eq!(f.op(piece).input(0), Some(w));
    }

    // --- RuleLessEqual2Zero (ruleaction.cc:5601) — wired ----------------------

    #[test]
    fn lessequal2zero_v_le_zero_is_equal() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // V <= 0  =>  V == 0
        let v = f.new_input(4, Address::new(reg, 0x10));
        let zero = f.new_const(4, 0);
        let le = f.new_op(OpCode::IntLessequal, seq, vec![v, zero]);
        f.new_output_unique(le, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![le],
            ..Default::default()
        }]);
        ActionPool::new("p").with(RuleLessEqual2Zero).apply(&mut f);
        assert_eq!(f.op(le).code(), OpCode::IntEqual);
        assert_eq!(f.op(le).input(0), Some(v));
    }

    #[test]
    fn lessequal2zero_zero_le_v_is_true() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // 0 <= V  =>  true  (COPY #1)
        let zero = f.new_const(4, 0);
        let v = f.new_input(4, Address::new(reg, 0x10));
        let le = f.new_op(OpCode::IntLessequal, seq, vec![zero, v]);
        f.new_output_unique(le, 1);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![le],
            ..Default::default()
        }]);
        ActionPool::new("p").with(RuleLessEqual2Zero).apply(&mut f);
        assert_eq!(f.op(le).code(), OpCode::Copy);
        assert_eq!(f.op(le).num_inputs(), 1);
        let c = f.op(le).input(0).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 1);
    }

    // --- RuleShiftBitops (ruleaction.cc:490) — wired --------------------------

    #[test]
    fn shift_bitops_and_shifted_away_becomes_zero() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // (V & 0xf000) << 4  in 2 bytes: 0xf000<<4 clears → result 0 → op input(0) = #0
        let v = f.new_input(2, Address::new(reg, 0x10));
        let m = f.new_const(2, 0xf000);
        let and = f.new_op(OpCode::IntAnd, seq, vec![v, m]);
        let ando = f.new_output_unique(and, 2);
        let sh4 = f.new_const(4, 4);
        let shl = f.new_op(OpCode::IntLeft, seq, vec![ando, sh4]);
        f.new_output_unique(shl, 2);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![and, shl],
            ..Default::default()
        }]);
        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        ActionPool::new("p").with(RuleShiftBitops).apply(&mut f);
        assert_eq!(f.op(shl).code(), OpCode::IntLeft);
        let in0 = f.op(shl).input(0).unwrap();
        assert!(f.vn(in0).is_constant() && f.vn(in0).constant_value() == 0);
    }

    #[test]
    fn shift_bitops_add_drops_shifted_out_addend() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // (V + 0xf000) << 4  in 2 bytes: the 0xf000 addend shifts out → V << 4
        let v = f.new_input(2, Address::new(reg, 0x10));
        let c = f.new_const(2, 0xf000);
        let add = f.new_op(OpCode::IntAdd, seq, vec![v, c]);
        let addo = f.new_output_unique(add, 2);
        let sh4 = f.new_const(4, 4);
        let shl = f.new_op(OpCode::IntLeft, seq, vec![addo, sh4]);
        f.new_output_unique(shl, 2);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![add, shl],
            ..Default::default()
        }]);
        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        ActionPool::new("p").with(RuleShiftBitops).apply(&mut f);
        assert_eq!(f.op(shl).code(), OpCode::IntLeft);
        assert_eq!(f.op(shl).input(0), Some(v));
    }

    // --- RuleHumptyOr (ruleaction.cc:5332) — wired ----------------------------

    #[test]
    fn humpty_or_full_cover_becomes_copy() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // (V & 0xff00) | (V & 0x00ff)  =>  V
        let v = f.new_input(2, Address::new(reg, 0x10));
        let m1 = f.new_const(2, 0xff00);
        let and1 = f.new_op(OpCode::IntAnd, seq, vec![v, m1]);
        let a1o = f.new_output_unique(and1, 2);
        let m2 = f.new_const(2, 0x00ff);
        let and2 = f.new_op(OpCode::IntAnd, seq, vec![v, m2]);
        let a2o = f.new_output_unique(and2, 2);
        let or = f.new_op(OpCode::IntOr, seq, vec![a1o, a2o]);
        f.new_output_unique(or, 2);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![and1, and2, or],
            ..Default::default()
        }]);
        ActionPool::new("p").with(RuleHumptyOr).apply(&mut f);
        assert_eq!(f.op(or).code(), OpCode::Copy);
        assert_eq!(f.op(or).input(0), Some(v));
    }

    #[test]
    fn humpty_or_partial_cover_becomes_and() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // (V & 0xf000) | (V & 0x000f)  =>  V & 0xf00f
        let v = f.new_input(2, Address::new(reg, 0x10));
        let m1 = f.new_const(2, 0xf000);
        let and1 = f.new_op(OpCode::IntAnd, seq, vec![v, m1]);
        let a1o = f.new_output_unique(and1, 2);
        let m2 = f.new_const(2, 0x000f);
        let and2 = f.new_op(OpCode::IntAnd, seq, vec![v, m2]);
        let a2o = f.new_output_unique(and2, 2);
        let or = f.new_op(OpCode::IntOr, seq, vec![a1o, a2o]);
        f.new_output_unique(or, 2);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![and1, and2, or],
            ..Default::default()
        }]);
        ActionPool::new("p").with(RuleHumptyOr).apply(&mut f);
        assert_eq!(f.op(or).code(), OpCode::IntAnd);
        assert_eq!(f.op(or).input(0), Some(v));
        let c = f.op(or).input(1).unwrap();
        assert!(f.vn(c).is_constant() && f.vn(c).constant_value() == 0xf00f);
    }

    // --- RuleAndPiece (ruleaction.cc:1640) — wired ----------------------------

    #[test]
    fn and_piece_high_masked_becomes_zext() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // concat(W:1, X:1) & 0xff : the 0xff masks off the high byte => AND(zext(X), 0xff)
        let high = f.new_input(1, Address::new(reg, 0x10));
        let low = f.new_input(1, Address::new(reg, 0x18));
        let piece = f.new_op(OpCode::Piece, seq, vec![high, low]);
        let pc = f.new_output_unique(piece, 2);
        let mask = f.new_const(2, 0xff);
        let and = f.new_op(OpCode::IntAnd, seq, vec![pc, mask]);
        f.new_output_unique(and, 2);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![piece, and],
            ..Default::default()
        }]);
        crate::decompile::pipeline::ActionNonzeroMask.apply(&mut f);
        ActionPool::new("p").with(RuleAndPiece).apply(&mut f);
        // the PIECE input of the AND is now a ZEXT(low)
        assert_eq!(f.op(and).code(), OpCode::IntAnd);
        let in0 = f.op(and).input(0).unwrap();
        let d = f.vn(in0).def.unwrap();
        assert_eq!(f.op(d).code(), OpCode::IntZext);
        assert_eq!(f.op(d).input(0), Some(low));
    }

    // --- RuleAndDistribute (ruleaction.cc:1254) — ported + held (see doc comment) --

    #[test]
    fn and_distribute_when_term_cancels() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // (0xff00 | B) & 0x00ff  =>  (0xff00 & 0x00ff) | (B & 0x00ff)   [first term's mask cancels]
        let a = f.new_const(2, 0xff00);
        let b = f.new_input(2, Address::new(reg, 0x10));
        let or = f.new_op(OpCode::IntOr, seq, vec![a, b]);
        let oro = f.new_output_unique(or, 2);
        let c = f.new_const(2, 0x00ff);
        let and = f.new_op(OpCode::IntAnd, seq, vec![oro, c]);
        f.new_output_unique(and, 2);
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![or, and],
            ..Default::default()
        }]);
        assert_eq!(RuleAndDistribute.apply_op(and, &mut f), 1);
        assert_eq!(f.op(and).code(), OpCode::IntOr);
        let (i0, i1) = (f.op(and).input(0).unwrap(), f.op(and).input(1).unwrap());
        let d0 = f.vn(i0).def.unwrap();
        let d1 = f.vn(i1).def.unwrap();
        assert_eq!(f.op(d0).code(), OpCode::IntAnd);
        assert_eq!(f.op(d1).code(), OpCode::IntAnd);
        assert_eq!(f.op(d0).input(0), Some(a)); // A & C
        assert_eq!(f.op(d1).input(0), Some(b)); // B & C
    }

    // --- RulePositiveDiv (ruleaction.cc:7799) ---

    #[test]
    fn positive_div_of_nonnegative_becomes_unsigned() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // num = x & 0x7fffffff  (sign bit provably 0 via nz mask) ; den = 3 (positive const)
        let x = f.new_input(4, Address::new(reg, 0x10));
        let m = f.new_const(4, 0x7fffffff);
        let and = f.new_op(OpCode::IntAnd, seq, vec![x, m]);
        let num = f.new_output_unique(and, 4);
        let three = f.new_const(4, 3);
        let sdiv = f.new_op(OpCode::IntSdiv, seq, vec![num, three]);
        f.new_output(sdiv, 4, Address::new(reg, 0));
        let srem = f.new_op(OpCode::IntSrem, seq, vec![num, three]);
        f.new_output(srem, 4, Address::new(reg, 8));
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![and, sdiv, srem],
            ..Default::default()
        }]);
        let dom = crate::decompile::dominator::compute(&f);
        crate::decompile::nzmask::calc_nzmask(&mut f, &dom);
        // Both operands provably non-negative  =>  SDIV→DIV, SREM→REM.
        assert_eq!(RulePositiveDiv.apply_op(sdiv, &mut f), 1);
        assert_eq!(f.op(sdiv).code(), OpCode::IntDiv);
        assert_eq!(RulePositiveDiv.apply_op(srem, &mut f), 1);
        assert_eq!(f.op(srem).code(), OpCode::IntRem);
    }

    #[test]
    fn positive_div_skips_possibly_negative() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // Raw 4-byte input has a full nz mask (sign bit may be set)  =>  rule must not fire.
        let x = f.new_input(4, Address::new(reg, 0x10));
        let three = f.new_const(4, 3);
        let sdiv = f.new_op(OpCode::IntSdiv, seq, vec![x, three]);
        f.new_output(sdiv, 4, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![sdiv],
            ..Default::default()
        }]);
        let dom = crate::decompile::dominator::compute(&f);
        crate::decompile::nzmask::calc_nzmask(&mut f, &dom);
        assert_eq!(RulePositiveDiv.apply_op(sdiv, &mut f), 0);
        assert_eq!(f.op(sdiv).code(), OpCode::IntSdiv);
    }
}
