//! Simplification rules — ports of Ghidra's `ruleaction.cc` `Rule`s, applied to a fixpoint
//! by an [`ActionPool`](super::action::ActionPool). This is the start of P2; more rules
//! slot in the same way Ghidra's pool grows.

use super::action::Rule;
use super::funcdata::Funcdata;
use super::op::OpId;
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
        Subpiece => a(0) >> (a(1) * 8),
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

/// Fold an op whose inputs are all constants into its constant value, propagating it to
/// the op's uses. (Ghidra computes the same constants via per-op `OpBehavior::evaluate`;
/// the resulting IR is identical.)
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
        let c = data.new_const(out_size, val);
        data.total_replace(out, c);
        data.mark_dead(op);
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
        vec![OpCode::IntAdd]
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
        let out_size = data.vn(data.op(op).output.unwrap()).size;
        match cx.wrapping_add(cy) {
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
    fn const_fold_rule_propagates() {
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

        let mut pool = ActionPool::new("p").with(RuleConstFold);
        pool.apply(&mut f);

        // the AND folded to #2 and propagated: ADD now reads the constant 2, AND is dead
        assert!(f.op(and).is_dead());
        let add_in0 = f.op(add).input(0).unwrap();
        assert!(f.vn(add_in0).is_constant() && f.vn(add_in0).constant_value() == 2);
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
}
