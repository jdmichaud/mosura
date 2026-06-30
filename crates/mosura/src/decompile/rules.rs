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
}
