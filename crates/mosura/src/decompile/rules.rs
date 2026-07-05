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
        // Floating-point ops fold via IEEE arithmetic on the host `f64` (Ghidra's per-op
        // `OpBehaviorFloat*::evaluate`, which likewise round-trips through the host float): decode
        // each operand at its own width, compute, re-encode at the output width. `0.0 / 0.0` folds
        // to a NaN pattern, exactly as Ghidra collapses the division to a constant.
        FloatAdd | FloatSub | FloatMult | FloatDiv | FloatNeg | FloatAbs | FloatSqrt
        | FloatFloat2float | FloatInt2float | FloatTrunc | FloatEqual | FloatNotequal | FloatLess
        | FloatLessequal | FloatNan => {
            let insz = |i: usize| inputs.get(i).map_or(1, |&(_, s)| s);
            let raw = |i: usize| inputs.get(i).map_or(0, |&(v, _)| v);
            let fin = |i: usize| super::float::to_host(raw(i), insz(i));
            let enc = |h: f64| super::float::encode(h, out_size);
            match opcode {
                FloatAdd => enc(fin(0) + fin(1)),
                FloatSub => enc(fin(0) - fin(1)),
                FloatMult => enc(fin(0) * fin(1)),
                FloatDiv => enc(fin(0) / fin(1)),
                FloatNeg => enc(-fin(0)),
                FloatAbs => enc(fin(0).abs()),
                FloatSqrt => enc(fin(0).sqrt()),
                FloatFloat2float => enc(fin(0)),
                FloatInt2float => enc(sa(0) as i64 as f64),
                FloatTrunc => fin(0) as i64 as u64,
                FloatEqual => (fin(0) == fin(1)) as u64,
                FloatNotequal => (fin(0) != fin(1)) as u64,
                FloatLess => (fin(0) < fin(1)) as u64,
                FloatLessequal => (fin(0) <= fin(1)) as u64,
                FloatNan => fin(0).is_nan() as u64,
                _ => unreachable!(),
            }
        }
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

/// Ghidra `RuleEarlyRemoval` (`ruleaction.cc:25`, oppool1's first rule): destroy any non-call op
/// whose output is dead — no readers, not auto-live — right inside the rule pool. This is Ghidra's
/// per-op early dead-code removal; keeping the graph clean mid-pool (rather than only at the heavier
/// `ActionDeadCode` sweeps) changes which later rules fire (a `loneDescend`/`hasNoDescend` check sees
/// the pruned graph). Applies to every opcode (empty oplist).
pub struct RuleEarlyRemoval;

impl Rule for RuleEarlyRemoval {
    fn name(&self) -> &str {
        "earlyremoval"
    }
    fn oplist(&self) -> Vec<OpCode> {
        Vec::new() // every op
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).is_call() {
            return 0; // functions are automatically consumed
        }
        // Ghidra also guards `op->isIndirectSource()`; mosura's INDIRECTs are 1-input with no iop
        // back-reference (Task #10), so no op is an indirect source — the guard is vacuous here.
        let Some(out) = data.op(op).output else {
            return 0; // no output (side-effecting op: STORE/BRANCH/RETURN) — keep
        };
        // Ghidra's `isPersist` guard here is commented out because its persist globals stay alive
        // through descendants (block-end copies). mosura instead keeps a written `ram` global alive
        // as a live-out root in `deadcode::dead_code` (not via SSA descendants), so the guard is
        // load-bearing here: without it the pool early-removes a global store that is dead in SSA but
        // a real side effect. mosura flags globals `persist` only after type recovery, so use the
        // `ram`-space proxy — exactly `dead_code`'s persistent live-out predicate.
        if data.spaces.by_name("ram") == Some(data.vn(out).loc.space) {
            return 0;
        }
        if !data.vn(out).descend.is_empty() {
            return 0; // output still has readers
        }
        if data.vn(out).is_auto_live() {
            return 0; // addrforce / autolive_hold — exempt
        }
        // Ghidra: `if doesDeadcode(spc) && !deadRemovalAllowedSeen(spc) return 0`. mosura heritages
        // every dead-code space to completion before the pool runs, so dead removal is always allowed
        // by pool time; the guard never blocks, so it reduces to an unconditional destroy here.
        data.op_destroy(op);
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
        // Ghidra `RulePropagateCopy::applyOp` (ruleaction.cc:3933): `if (op->isReturnCopy()) return 0;`.
        // `TypeOpReturn` sets `return_copy` as a default opflag (typeop.cc:878), so every CPUI_RETURN
        // op is a "return copy" — copies are never propagated into a RETURN's inputs, keeping the
        // returned register in place. (mosura has no globals-holding markReturnCopy COPY yet — the
        // heritage.cc:1686 case — so `isReturnCopy` ≡ the RETURN op here.)
        if data.op(op).code() == OpCode::Return {
            return 0;
        }
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

/// Does `xvn` compute `avn + bvn`? Directly as `INT_ADD(avn, bvn)` in either operand order — the
/// additive-sum counterpart of [`subtract_matches`] used by [`RuleScarry`]. (Ghidra uses the general
/// `AddExpression::gatherTwoTermsAdd`/`gatherTwoTermsRoot` equivalence; this is the direct-def subset,
/// matching mosura's simplified `subtract_matches`.)
fn add_matches(data: &Funcdata, xvn: VarnodeId, avn: VarnodeId, bvn: VarnodeId) -> bool {
    let Some(def) = data.vn(xvn).def else { return false };
    let o = data.op(def);
    if o.code() != OpCode::IntAdd || o.num_inputs() != 2 {
        return false;
    }
    let (i0, i1) = (o.input(0).unwrap(), o.input(1).unwrap());
    (same_value(data, i0, avn) && same_value(data, i1, bvn))
        || (same_value(data, i0, bvn) && same_value(data, i1, avn))
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

/// Simplify signed comparisons built from `INT_SCARRY` (Ghidra's `RuleScarry`) — the additive
/// sibling of [`RuleSborrow`]. Trivial `scarry(V,0) => false`. Otherwise, when one operand is a
/// constant `c`, the flag idiom comparing `scarry(V,c)` against the sign of `V + c`
/// (`INT_SLESS` vs 0) is a signed compare of `V` against `-c`: `INT_NOTEQUAL => V s< -c`,
/// `INT_EQUAL => V s<= -c` (with the `0 s< (V+c)` variant giving the swapped operands). The rule
/// requires a constant operand and skips the integer minimum (whose negation is a no-op).
pub struct RuleScarry;

impl Rule for RuleScarry {
    fn name(&self) -> &str {
        "scarry"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntScarry]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        if data.op(op).num_inputs() != 2 {
            return 0;
        }
        let mut avn = data.op(op).input(0).unwrap();
        let mut bvn = data.op(op).input(1).unwrap();
        // Trivial: either operand is const 0 → the sum never carries.
        if is_const0(data, avn) || is_const0(data, bvn) {
            let z = data.new_const(1, 0);
            data.op_set_opcode(op, OpCode::Copy);
            data.op_set_all_input(op, &[z]);
            return 1;
        }
        // One side must be constant; swap so `bvn` holds it. Skip the integer minimum — negating it
        // is a no-op, so the `-c` rewrite would be wrong.
        if !data.vn(bvn).is_constant() {
            if !data.vn(avn).is_constant() {
                return 0;
            }
            std::mem::swap(&mut avn, &mut bvn);
            let size = data.vn(bvn).size;
            let mask = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
            let intmin = mask ^ (mask >> 1);
            if intmin == data.vn(bvn).constant_value() {
                return 0;
            }
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
            if !add_matches(data, xvn, avn, bvn) {
                continue;
            }
            let size = data.vn(bvn).size;
            let mask = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
            let newval = data.vn(bvn).constant_value().wrapping_neg() & mask;
            let newc = data.new_const(size, newval);
            let mut inputs = [avn; 2];
            // NOTEQUAL ⇒ V s< -c (avn at 1-zside); EQUAL ⇒ V s<= -c (avn at zside).
            if cc == OpCode::IntNotequal {
                data.op_set_opcode(compop, OpCode::IntSless);
                inputs[1 - zside] = avn;
                inputs[zside] = newc;
            } else {
                data.op_set_opcode(compop, OpCode::IntSlessequal);
                inputs[zside] = avn;
                inputs[1 - zside] = newc;
            }
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
/// Ghidra's `RuleBoolNegate` supports the signed and floating-point comparison variants too — the
/// float ones flip the `ucomisd`-derived `!(a <= b)` into `b < a` (matching Ghidra) once
/// `RuleIgnoreNan`/`RuleFloatRange` have collapsed the NaN-guarded web.
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
            OpCode::FloatEqual => (OpCode::FloatNotequal, false),
            OpCode::FloatNotequal => (OpCode::FloatEqual, false),
            OpCode::FloatLess => (OpCode::FloatLessequal, true),
            OpCode::FloatLessequal => (OpCode::FloatLess, true),
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
/// Ghidra `RuleFloatRange` (`ruleaction.cc`): collapse two floating-point comparisons of the same
/// operands, combined by a boolean op, into one comparison — `(a < b) || (a == b)` → `a <= b`, and
/// `(a <= b) && (a != b)` → `a < b`. This is what turns the `ucomisd` flag idiom (mosura lifts it
/// to a `BOOL_OR`/`BOOL_AND` of separate `FLOAT_LESS`/`FLOAT_EQUAL`/`FLOAT_NOTEQUAL` compares) into
/// a single `<=`/`<`, as Ghidra prints.
pub struct RuleFloatRange;

impl Rule for RuleFloatRange {
    fn name(&self) -> &str {
        "floatrange"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::BoolAnd, OpCode::BoolOr]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn1 = data.op(op).input(0).unwrap();
        if !data.vn(vn1).is_written() {
            return 0;
        }
        let vn2 = data.op(op).input(1).unwrap();
        if !data.vn(vn2).is_written() {
            return 0;
        }
        // cmp1 must be the LESS/LESSEQUAL operator; cmp2 is the "other". Swap if it started reversed.
        let mut cmp1 = data.vn(vn1).def.unwrap();
        let mut cmp2 = data.vn(vn2).def.unwrap();
        let mut opccmp1 = data.op(cmp1).code();
        if opccmp1 != OpCode::FloatLess && opccmp1 != OpCode::FloatLessequal {
            cmp1 = data.vn(vn2).def.unwrap();
            cmp2 = data.vn(vn1).def.unwrap();
            opccmp1 = data.op(cmp1).code();
        }
        let opc_op = data.op(op).code();
        let resultopc = match opccmp1 {
            OpCode::FloatLess
                if data.op(cmp2).code() == OpCode::FloatEqual && opc_op == OpCode::BoolOr =>
            {
                OpCode::FloatLessequal
            }
            OpCode::FloatLessequal
                if data.op(cmp2).code() == OpCode::FloatNotequal && opc_op == OpCode::BoolAnd =>
            {
                OpCode::FloatLess
            }
            _ => return 0,
        };

        // Make sure both operators are comparing the same two things.
        let mut slot1 = 0usize;
        let mut nvn1 = data.op(cmp1).input(0).unwrap();
        if data.vn(nvn1).is_constant() {
            slot1 = 1;
            nvn1 = data.op(cmp1).input(1).unwrap();
            if data.vn(nvn1).is_constant() {
                return 0;
            }
        }
        if data.vn(nvn1).is_free() {
            return 0;
        }
        let cvn1 = data.op(cmp1).input(1 - slot1).unwrap();
        let slot2 = if nvn1 == data.op(cmp2).input(0).unwrap() {
            0
        } else if nvn1 == data.op(cmp2).input(1).unwrap() {
            1
        } else {
            return 0;
        };
        let matchvn = data.op(cmp2).input(1 - slot2).unwrap();
        if data.vn(cvn1).is_constant() {
            if !data.vn(matchvn).is_constant() {
                return 0;
            }
            if data.vn(matchvn).constant_value() != data.vn(cvn1).constant_value() {
                return 0;
            }
        } else if cvn1 != matchvn {
            return 0;
        } else if data.vn(cvn1).is_free() {
            return 0;
        }

        // Collapse the two comparisons into one.
        data.op_set_opcode(op, resultopc);
        data.op_set_input(op, slot1, nvn1);
        if data.vn(cvn1).is_constant() {
            let (sz, val) = (data.vn(cvn1).size, data.vn(cvn1).constant_value());
            let c = data.new_const(sz, val);
            data.op_set_input(op, 1 - slot1, c);
        } else {
            data.op_set_input(op, 1 - slot1, cvn1);
        }
        1
    }
}

/// Ghidra `RuleFloatCast` (`ruleaction.cc`, oppool1 @5634 "floatprecision"): replace
/// `(casttosmall)(casttobig)V` with the identity or a single cast. Matches a `FLOAT_FLOAT2FLOAT`
/// or `FLOAT_TRUNC` whose input is itself defined by a `FLOAT_FLOAT2FLOAT` or `FLOAT_INT2FLOAT`,
/// and rewrites the op in place to consume the inner cast's source directly, dropping the
/// redundant intermediate conversion.
pub struct RuleFloatCast;

impl Rule for RuleFloatCast {
    fn name(&self) -> &str {
        "floatcast"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::FloatFloat2float, OpCode::FloatTrunc]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn1 = data.op(op).input(0).unwrap();
        if !data.vn(vn1).is_written() {
            return 0;
        }
        let castop = data.vn(vn1).def.unwrap();
        let opc2 = data.op(castop).code();
        if opc2 != OpCode::FloatFloat2float && opc2 != OpCode::FloatInt2float {
            return 0;
        }
        let opc1 = data.op(op).code();
        let vn2 = data.op(castop).input(0).unwrap();
        let insize1 = data.vn(vn1).size;
        let insize2 = data.vn(vn2).size;
        let outsize = data.vn(data.op(op).output.unwrap()).size;

        if data.vn(vn2).is_free() {
            return 0; // Don't propagate free
        }

        if opc2 == OpCode::FloatFloat2float && opc1 == OpCode::FloatFloat2float {
            if insize1 > outsize {
                // op is superfluous
                data.op_set_input(op, 0, vn2);
                if outsize == insize2 {
                    data.op_set_opcode(op, OpCode::Copy); // We really have the identity
                }
                return 1;
            } else if insize2 < insize1 {
                // Convert two increases -> one combined increase
                data.op_set_input(op, 0, vn2);
                return 1;
            }
        } else if opc2 == OpCode::FloatInt2float && opc1 == OpCode::FloatFloat2float {
            // Convert integer straight into final float size
            data.op_set_input(op, 0, vn2);
            data.op_set_opcode(op, OpCode::FloatInt2float);
            return 1;
        } else if opc2 == OpCode::FloatFloat2float && opc1 == OpCode::FloatTrunc {
            // Convert float straight into final integer
            data.op_set_input(op, 0, vn2);
            return 1;
        }

        0
    }
}

/// The input slot at which `vn` is read by `op` (Ghidra `PcodeOp::getSlot`).
fn slot_of(data: &Funcdata, op: OpId, vn: VarnodeId) -> usize {
    data.op(op).inrefs.iter().position(|&v| v == vn).unwrap_or(0)
}

/// Ghidra `TypeOp::isFloatingPointOp` — the p-code ops whose `TypeOp` is a floating-point one.
fn is_float_op(opc: OpCode) -> bool {
    use OpCode::*;
    matches!(
        opc,
        FloatEqual | FloatNotequal | FloatLess | FloatLessequal | FloatNan | FloatAdd | FloatSub
            | FloatMult | FloatDiv | FloatNeg | FloatAbs | FloatSqrt | FloatInt2float
            | FloatFloat2float | FloatTrunc | FloatCeil | FloatFloor | FloatRound
    )
}

/// Ghidra `RuleIgnoreNan::checkBackForCompare`: does the boolean `root` come from a floating-point
/// comparison of `float_var` (directly, or one level down a BOOL_AND/OR, through an optional
/// BOOL_NEGATE)?
fn check_back_for_compare(float_var: VarnodeId, root: VarnodeId, data: &Funcdata) -> bool {
    if !data.vn(root).is_written() {
        return false;
    }
    let mut def1 = data.vn(root).def.unwrap();
    if !data.op(def1).is_bool_output() {
        return false;
    }
    if data.op(def1).code() == OpCode::BoolNegate {
        let vn = data.op(def1).input(0).unwrap();
        if !data.vn(vn).is_written() {
            return false;
        }
        def1 = data.vn(vn).def.unwrap();
    }
    if is_float_op(data.op(def1).code()) {
        if data.op(def1).num_inputs() != 2 {
            return false;
        }
        return functional_equality(data, float_var, data.op(def1).input(0).unwrap())
            || functional_equality(data, float_var, data.op(def1).input(1).unwrap());
    }
    let opc = data.op(def1).code();
    if opc != OpCode::BoolAnd && opc != OpCode::BoolOr {
        return false;
    }
    for i in 0..2 {
        let vn = data.op(def1).input(i).unwrap();
        if !data.vn(vn).is_written() {
            continue;
        }
        let def2 = data.vn(vn).def.unwrap();
        if !data.op(def2).is_bool_output() || !is_float_op(data.op(def2).code()) {
            continue;
        }
        if data.op(def2).num_inputs() != 2 {
            continue;
        }
        if functional_equality(data, float_var, data.op(def2).input(0).unwrap())
            || functional_equality(data, float_var, data.op(def2).input(1).unwrap())
        {
            return true;
        }
    }
    false
}

/// Ghidra `RuleIgnoreNan::isAnotherNan`: is `vn` (possibly through a BOOL_NEGATE) another
/// `FLOAT_NAN`, so the NaN-check chain continues one level deeper?
fn is_another_nan(vn: VarnodeId, data: &Funcdata) -> bool {
    if !data.vn(vn).is_written() {
        return false;
    }
    let mut op = data.vn(vn).def.unwrap();
    if data.op(op).code() == OpCode::BoolNegate {
        let vn2 = data.op(op).input(0).unwrap();
        if !data.vn(vn2).is_written() {
            return false;
        }
        op = data.vn(vn2).def.unwrap();
    }
    data.op(op).code() == OpCode::FloatNan
}

/// Ghidra `RuleIgnoreNan::testForComparison`: at a boolean use `op` of the NaN result, if the other
/// operand is a comparison of `float_var` the NaN check is redundant — rewrite `op` to drop it
/// (BOOL_OR/AND → a COPY of the comparison; INT_EQUAL/NOTEQUAL → fold the NaN slot to a constant).
/// Returns the output to keep descending through when the other operand is itself another NaN check.
/// The `CPUI_CBRANCH` case (a NaN guard spread across two branches) is deferred.
fn test_for_comparison(
    float_var: VarnodeId,
    op: OpId,
    slot: usize,
    match_code: OpCode,
    count: &mut i32,
    data: &mut Funcdata,
) -> Option<VarnodeId> {
    let opc = data.op(op).code();
    if opc == match_code {
        let vn = data.op(op).input(1 - slot).unwrap();
        if check_back_for_compare(float_var, vn, data) {
            data.op_set_opcode(op, OpCode::Copy);
            data.op_remove_input(op, 1);
            data.op_set_input(op, 0, vn);
            *count += 1;
        } else if is_another_nan(vn, data) {
            return data.op(op).output;
        }
    } else if opc == OpCode::IntEqual || opc == OpCode::IntNotequal {
        let vn = data.op(op).input(1 - slot).unwrap();
        if check_back_for_compare(float_var, vn, data) {
            let val = if match_code == OpCode::BoolOr { 0 } else { 1 };
            let c = data.new_const(1, val);
            data.op_set_input(op, slot, c);
            *count += 1;
        }
    }
    // (Ghidra's CPUI_CBRANCH branch — a NaN guard split across two CBRANCHes — is deferred.)
    None
}

/// Ghidra `RuleIgnoreNan` (`ruleaction.cc`, oppool1 @5635 "floatprecision"): a `NAN(x)` check OR'd
/// (or, negated, AND'd) with a comparison of the same `x` is redundant — the ordered comparison
/// already handles the unordered/NaN case — so drop the NaN check. This dissolves the `ucomisd`
/// NaN-guard idiom, letting [`RuleFloatRange`] then collapse the bare ordered compares.
pub struct RuleIgnoreNan;

impl Rule for RuleIgnoreNan {
    fn name(&self) -> &str {
        "ignorenan"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::FloatNan]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        // (mosura has no `nan_ignore_all` architecture flag — that always-false branch is skipped.)
        let float_var = data.op(op).input(0).unwrap();
        if data.vn(float_var).is_free() {
            return 0;
        }
        let out1 = data.op(op).output.unwrap();
        let mut count = 0;
        // Snapshot each descend list before mutating — a rewrite changes the live descend edges.
        for bool_read1 in data.vn(out1).descend.clone() {
            let (match_code, out2) = if data.op(bool_read1).code() == OpCode::BoolNegate {
                (OpCode::BoolAnd, data.op(bool_read1).output)
            } else {
                let slot = slot_of(data, bool_read1, out1);
                let o2 = test_for_comparison(float_var, bool_read1, slot, OpCode::BoolOr, &mut count, data);
                (OpCode::BoolOr, o2)
            };
            let Some(out2) = out2 else { continue };
            for bool_read2 in data.vn(out2).descend.clone() {
                let slot = slot_of(data, bool_read2, out2);
                let Some(out3) = test_for_comparison(float_var, bool_read2, slot, match_code, &mut count, data)
                else {
                    continue;
                };
                for bool_read3 in data.vn(out3).descend.clone() {
                    let slot = slot_of(data, bool_read3, out3);
                    test_for_comparison(float_var, bool_read3, slot, match_code, &mut count, data);
                }
            }
        }
        if count > 0 {
            1
        } else {
            0
        }
    }
}

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

// ---------------------------------------------------------------------------
// SubVariableFlow driving rules — Ghidra `subflow.cc:1547-1721`. Each spots a
// seed (a wide Varnode from which only a narrow logical sub-value is used),
// builds a `SubvariableFlow`, then `do_trace()` + `do_replacement()` to shrink
// the flow. `aggressive` is always false — mosura has no `Varnode::isPtrFlow`.
// (RuleSubvarSext deferred — its sign-extension tracer is still a Stage-4 stub.)
// ---------------------------------------------------------------------------

/// Ghidra `RuleSubvarAnd` (subflow.cc:1553): `V & c` where the AND output is consumed exactly by the
/// constant mask `c` and the low bit is live — the AND is pulling a narrow field out of `V`.
pub struct RuleSubvarAnd;

impl Rule for RuleSubvarAnd {
    fn name(&self) -> &str {
        "subvar_and"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let in1 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_constant() {
            return 0;
        }
        let vn = data.op(op).input(0).unwrap();
        let outvn = data.op(op).output.unwrap();
        let consume = data.vn(outvn).get_consume();
        if consume != data.vn(in1).constant_value() {
            return 0;
        }
        if (consume & 1) == 0 {
            return 0;
        }
        let cmask: u64 = if consume == 1 {
            1
        } else {
            let mut cm = super::nzmask::calc_mask(data.vn(vn).size) >> 8;
            while cm != 0 {
                if cm == consume {
                    break;
                }
                cm >>= 8;
            }
            cm
        };
        if cmask == 0 {
            return 0;
        }
        if data.vn(outvn).descend.is_empty() {
            return 0;
        }
        let mut subflow = super::subvarflow::SubvariableFlow::new(data, vn, cmask, false, false, false);
        if !subflow.do_trace() {
            return 0;
        }
        subflow.do_replacement();
        1
    }
}

/// Ghidra `RuleSubvarSubpiece` (subflow.cc:1590): a SUBPIECE truncation whose full input is only ever
/// consumed within the truncated field — seed the flow with `mask = calc_mask(outsize) << 8*sa`.
pub struct RuleSubvarSubpiece;

impl Rule for RuleSubvarSubpiece {
    fn name(&self) -> &str {
        "subvar_subpiece"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn = data.op(op).input(0).unwrap();
        let outvn = data.op(op).output.unwrap();
        let flowsize = data.vn(outvn).size;
        let sa_c = data.vn(data.op(op).input(1).unwrap()).constant_value();
        if flowsize as u64 + sa_c > 8 {
            return 0; // mask must fit in u64 precision (Ghidra: > sizeof(uintb))
        }
        let sa = sa_c as u32;
        let mask = super::nzmask::calc_mask(flowsize) << (8 * sa);
        let aggressive = false; // Ghidra: outvn->isPtrFlow(); mosura has no isPtrFlow
        if !aggressive {
            if (data.vn(vn).get_consume() & mask) != data.vn(vn).get_consume() {
                return 0;
            }
            if data.vn(outvn).descend.is_empty() {
                return 0;
            }
        }
        // Vector-register inputs truncated to the used lanes — let the flow handle the 8-byte case.
        let big = flowsize >= 8 && data.vn(vn).is_input() && lone_descend(data, vn) == Some(op);
        let mut subflow = super::subvarflow::SubvariableFlow::new(data, vn, mask, aggressive, false, big);
        if !subflow.do_trace() {
            return 0;
        }
        subflow.do_replacement();
        1
    }
}

/// Ghidra `RuleSubvarCompZero` (subflow.cc:1628): a single-bit equality test `(V & bit) == 0` — trace
/// the one live bit out of `V` (guarded so it looks like a status-flag bit, not a wide field).
pub struct RuleSubvarCompZero;

impl Rule for RuleSubvarCompZero {
    fn name(&self) -> &str {
        "subvar_compzero"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntNotequal, OpCode::IntEqual]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let in1 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_constant() {
            return 0;
        }
        let vn = data.op(op).input(0).unwrap();
        let mask = data.vn(vn).get_nzmask();
        let bitnum = super::nzmask::leastsigbit_set(mask);
        if bitnum == -1 {
            return 0;
        }
        if (mask >> (bitnum as u32)) != 1 {
            return 0; // only one bit active
        }
        let off = data.vn(in1).constant_value();
        if off != mask && off != 0 {
            return 0; // the active bit must be the one being tested
        }
        let outvn = data.op(op).output.unwrap();
        if data.vn(outvn).descend.is_empty() {
            return 0;
        }
        // Basic check that the stream the bit is pulled from is not fully consumed (status-reg heuristic).
        if data.vn(vn).is_written() {
            let andop = data.vn(vn).def.unwrap();
            let Some(vn0) = data.op(andop).input(0) else {
                return 0;
            };
            match data.op(andop).code() {
                OpCode::IntAnd | OpCode::IntOr | OpCode::IntRight => {
                    if data.vn(vn0).is_constant() {
                        return 0;
                    }
                    let mask0 = data.vn(vn0).get_consume() & data.vn(vn0).get_nzmask();
                    let wholemask = super::nzmask::calc_mask(data.vn(vn0).size) & mask0;
                    if (wholemask & 0xff) == 0xff {
                        return 0;
                    }
                    if (wholemask & 0xff00) == 0xff00 {
                        return 0;
                    }
                }
                _ => {}
            }
        }
        let mut subflow = super::subvarflow::SubvariableFlow::new(data, vn, mask, false, false, false);
        if !subflow.do_trace() {
            return 0;
        }
        subflow.do_replacement();
        1
    }
}

/// Ghidra `RuleSubvarShift` (subflow.cc:1686): a single bit pulled from a 1-byte value by `V >> sa` —
/// trace that bit out of `V`.
pub struct RuleSubvarShift;

impl Rule for RuleSubvarShift {
    fn name(&self) -> &str {
        "subvar_shift"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntRight]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn = data.op(op).input(0).unwrap();
        if data.vn(vn).size != 1 {
            return 0;
        }
        let in1 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_constant() {
            return 0;
        }
        let sa = data.vn(in1).constant_value() as u32;
        let mask = data.vn(vn).get_nzmask();
        let shifted = mask.checked_shr(sa).unwrap_or(0);
        if shifted != 1 {
            return 0; // pulling out a single bit
        }
        let mask = shifted.checked_shl(sa).unwrap_or(0);
        let outvn = data.op(op).output.unwrap();
        if data.vn(outvn).descend.is_empty() {
            return 0;
        }
        let mut subflow = super::subvarflow::SubvariableFlow::new(data, vn, mask, false, false, false);
        if !subflow.do_trace() {
            return 0;
        }
        subflow.do_replacement();
        1
    }
}

/// Ghidra `RuleSubvarZext` (subflow.cc:1710): the output of `INT_ZEXT(v)` is a narrow value padded to
/// a wide register — trace the logical `v`-width value forward. This is the rule that narrows a
/// zero-extension-padded return (`RAX:8 = ZEXT(v:4)` → `return v:4`, via `try_return_pull`).
pub struct RuleSubvarZext;

impl Rule for RuleSubvarZext {
    fn name(&self) -> &str {
        "subvar_zext"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntZext]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn = data.op(op).output.unwrap();
        let invn = data.op(op).input(0).unwrap();
        let mask = super::nzmask::calc_mask(data.vn(invn).size);
        let mut subflow = super::subvarflow::SubvariableFlow::new(data, vn, mask, false, false, false);
        if !subflow.do_trace() {
            return 0;
        }
        subflow.do_replacement();
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
/// are all ones (i.e. it is "really" a small negative). Now that `ActionInferTypes` commits a type
/// onto constant varnodes, a constant read in unsigned context reads as `TYPE_UINT` and this rule
/// fires as in Ghidra. (The equate-symbol and enum guards in Ghidra do not apply: mosura models
/// neither.)
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
                // An unwritten (constant/free) base branch cannot be recomputed by functional
                // equality, so mark `nofunc` — the same guard the None-branch applies below — or the
                // `func_eq` collapse path would dereference its (nonexistent) def. Ghidra reaches the
                // first loop only for a written non-MULTIEQUAL base; a constant base arises once
                // `consume::never_consumed` folds a MULTIEQUAL input to 0 and the now-dead marker has
                // not yet been swept (Ghidra removes it in the same combined ActionDeadCode pass).
                if !data.vn(copyr).is_written() {
                    nofunc = true;
                }
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

/// Ghidra `RuleAndCommute` (ruleaction.cc:1532; doc at 1520): commute `INT_AND` with `INT_LEFT` /
/// `INT_RIGHT`: `(V << c) & d  =>  (V & (d >> c)) << c` (and the right-shift dual). This makes sense
/// when `c` is constant and the shift has no other use, or when the mask is likely to cancel with a
/// specific `INT_OR` / `PIECE` feeding the shift. The constant-mask guard on the `INT_LEFT` fast
/// path is required: without it (Ghidra's comment at 1577) the commute would loop forever.
pub struct RuleAndCommute;

impl Rule for RuleAndCommute {
    fn name(&self) -> &str {
        "andcommute"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntAnd]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(out) = data.op(op).output else { return 0 };
        let size = data.vn(out).size;
        if size > 8 {
            return 0; // FIXME: uintb should be arbitrary precision (Ghidra's `size > sizeof(uintb)`)
        }
        let fullmask = super::nzmask::calc_mask(size);

        // Ghidra breaks out of the 2-iteration loop with (opc, savn, othervn, orvn) captured; if it
        // falls through both operands (`i == 2`) it returns 0.
        let mut matched: Option<(OpCode, VarnodeId, VarnodeId, VarnodeId)> = None;
        for i in 0..2usize {
            let shiftvn = data.op(op).input(i).unwrap();
            let Some(shiftop) = data.vn(shiftvn).def else { continue };
            let opc = data.op(shiftop).code();
            if opc != OpCode::IntLeft && opc != OpCode::IntRight {
                continue;
            }
            let savn = data.op(shiftop).input(1).unwrap();
            if !data.vn(savn).is_constant() {
                continue;
            }
            let sa = data.vn(savn).constant_value() as u32;

            let othervn = data.op(op).input(1 - i).unwrap();
            if !data.vn(othervn).is_heritage_known() {
                continue;
            }
            let mut othermask = data.vn(othervn).get_nzmask();
            // Check if the AND is only zeroing bits which are already zeroed by the shift, in which
            // case `andmask` takes care of it; otherwise compute the mask as it will be after the
            // commute.
            // `sa` is a constant shift amount that may exceed the value width (e.g. a degenerate
            // `#0x0 >> #0xffffffff` a prior fold left behind). Ghidra shifts a `uintb` by `(int4)sa`
            // with raw C++ `>>`/`<<`; on the x86-64 oracle that masks the count mod 64, so mosura uses
            // `wrapping_shr`/`wrapping_shl` (identical to `>>`/`<<` for `sa < 64`) to match rather than
            // panic on the Rust debug shift-overflow check.
            if opc == OpCode::IntRight {
                if fullmask.wrapping_shr(sa) == othermask {
                    continue;
                }
                othermask = othermask.wrapping_shl(sa);
            } else {
                // NOTE: ported verbatim — Ghidra's source is `((fullmask<<sa)&&fullmask)` with a
                // logical `&&` (an apparent Ghidra typo for bitwise `&`); kept faithful.
                if ((((fullmask.wrapping_shl(sa)) != 0) && (fullmask != 0)) as u64) == othermask {
                    continue;
                }
                othermask = othermask.wrapping_shr(sa);
            }
            if othermask == 0 {
                continue; // Handled by andmask
            }
            if othermask == fullmask {
                continue;
            }

            let orvn = data.op(shiftop).input(0).unwrap();
            if opc == OpCode::IntLeft && data.vn(othervn).is_constant() {
                // `(v & #c) << #sa` is preferred to `(v << #sa) & #(c << sa)` because the mask is
                // right-justified. NOTE: the constant-mask check above is what stops an infinite
                // transform loop. If the shift has no other use, always commute.
                if lone_descend(data, shiftvn) == Some(op) {
                    matched = Some((opc, savn, othervn, orvn));
                    break;
                }
            }

            if !data.vn(orvn).is_written() {
                continue;
            }
            let orop = data.vn(orvn).def.unwrap();
            let orcode = data.op(orop).code();
            // Ghidra breaks (commutes) as soon as any operand's non-zero bits cancel against
            // `othermask`; the individual `break`s combine into this single predicate (all reads,
            // no side effects, so evaluating them all is equivalent to Ghidra's short-circuit).
            let commute = if orcode == OpCode::IntOr {
                let a0 = data.op(orop).input(0).unwrap();
                let a1 = data.op(orop).input(1).unwrap();
                let ormask1 = data.vn(a0).get_nzmask();
                let ormask2 = data.vn(a1).get_nzmask();
                (ormask1 & othermask) == 0
                    || (ormask2 & othermask) == 0
                    || (data.vn(othervn).is_constant()
                        && ((ormask1 & othermask) == ormask1 || (ormask2 & othermask) == ormask2))
            } else if orcode == OpCode::Piece {
                let lowvn = data.op(orop).input(1).unwrap(); // Low part of piece
                let highvn = data.op(orop).input(0).unwrap(); // High part
                let ormask1 = data.vn(lowvn).get_nzmask();
                let lowsize = data.vn(lowvn).size;
                let ormask2 = data.vn(highvn).get_nzmask() << (lowsize * 8);
                (ormask1 & othermask) == 0 || (ormask2 & othermask) == 0
            } else {
                continue;
            };
            if commute {
                matched = Some((opc, savn, othervn, orvn));
                break;
            }
            // OR/PIECE present but nothing cancels — Ghidra falls through to the next operand.
        }

        let Some((opc, savn, othervn, orvn)) = matched else {
            return 0;
        };

        // Do the commute.
        let opp = if opc == OpCode::IntLeft { OpCode::IntRight } else { OpCode::IntLeft };
        let newop1 = data.new_op_before_sized(op, opp, vec![othervn, savn], size);
        let newvn1 = data.op(newop1).output.unwrap();
        let newop2 = data.new_op_before_sized(op, OpCode::IntAnd, vec![orvn, newvn1], size);
        let newvn2 = data.op(newop2).output.unwrap();
        data.op_set_input(op, 0, newvn2);
        data.op_set_input(op, 1, savn);
        data.op_set_opcode(op, opc);
        1
    }
}

/// Ghidra `RuleShiftAnd` (`ruleaction.cc`, oppool1 @5582 "analysis"): a left/right shift — or a
/// power-of-two `INT_MULT`, treated as a left shift — applied to `(V & mask)` drops the AND to a
/// COPY when, after the same shift is applied to `mask` and to V's non-zero mask, the surviving
/// mask bits already cover every possibly-nonzero bit of V (`(mask & nzm) == nzm`). The AND was
/// redundant given V's non-zero mask, so `V & mask` becomes just `V`.
pub struct RuleShiftAnd;

impl Rule for RuleShiftAnd {
    fn name(&self) -> &str {
        "shiftand"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntRight, OpCode::IntLeft, OpCode::IntMult]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let cvn = data.op(op).input(1).unwrap();
        if !data.vn(cvn).is_constant() {
            return 0;
        }
        let shiftin = data.op(op).input(0).unwrap();
        if !data.vn(shiftin).is_written() {
            return 0;
        }
        let andop = data.vn(shiftin).def.unwrap();
        if data.op(andop).code() != OpCode::IntAnd {
            return 0;
        }
        if lone_descend(data, shiftin) != Some(op) {
            return 0;
        }
        let maskvn = data.op(andop).input(1).unwrap();
        if !data.vn(maskvn).is_constant() {
            return 0;
        }
        let mut mask = data.vn(maskvn).constant_value();
        let invn = data.op(andop).input(0).unwrap();
        if data.vn(invn).is_free() {
            return 0;
        }

        let mut opc = data.op(op).code();
        // For a shift the count is the constant directly; for INT_MULT only a power-of-two constant
        // is really a shift (Ghidra `leastsigbit_set` == the sole set bit).
        let sa: u32;
        if opc == OpCode::IntRight || opc == OpCode::IntLeft {
            sa = data.vn(cvn).constant_value() as u32;
        } else {
            let lsb = super::nzmask::leastsigbit_set(data.vn(cvn).constant_value());
            if lsb <= 0 {
                return 0;
            }
            if (1u64 << (lsb as u32)) != data.vn(cvn).constant_value() {
                return 0;
            }
            sa = lsb as u32;
            opc = OpCode::IntLeft; // Treat INT_MULT as INT_LEFT
        }

        let mut nzm = data.vn(invn).get_nzmask();
        let fullmask = super::nzmask::calc_mask(data.vn(invn).size);
        // Ghidra shifts `uintb` masks with raw C++ `>>`/`<<`; on the x86-64 oracle that masks the
        // count mod 64, so `wrapping_shr`/`wrapping_shl` matches (see [`RuleAndCommute`]).
        if opc == OpCode::IntRight {
            nzm = nzm.wrapping_shr(sa);
            mask = mask.wrapping_shr(sa);
        } else {
            nzm = nzm.wrapping_shl(sa) & fullmask;
            mask = mask.wrapping_shl(sa) & fullmask;
        }
        if (mask & nzm) != nzm {
            return 0;
        }
        // AND effectively does nothing, so change it to a COPY.
        data.op_set_opcode(andop, OpCode::Copy);
        data.op_remove_input(andop, 1);
        1
    }
}

/// Ghidra `RuleConcatCommute` (`ruleaction.cc`, oppool1 @5578 "analysis"): commute a PIECE with a
/// bitwise `INT_AND`/`INT_OR`/`INT_XOR` on one of its inputs, pulling the concatenation inside so a
/// later rule can act on the whole value:
///   - `concat(V & c, W)  =>  concat(V,W) & (c<<8|W| | mask(|W|))`
///   - `concat(V, W | c)  =>  concat(V,W) | c`
/// The mask/offset bookkeeping keeps the low `lo` (or high `hi`) lane untouched by the widened op.
pub struct RuleConcatCommute;

impl Rule for RuleConcatCommute {
    fn name(&self) -> &str {
        "concatcommute"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Piece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let Some(out) = data.op(op).output else { return 0 };
        let outsz = data.vn(out).size;
        if outsz > 8 {
            return 0; // FIXME: precision problem for constants (Ghidra's `outsz > sizeof(uintb)`)
        }
        for i in 0..2usize {
            let vn = data.op(op).input(i).unwrap();
            if !data.vn(vn).is_written() {
                continue;
            }
            let logicop = data.vn(vn).def.unwrap();
            let opc = data.op(logicop).code();
            // Gate on the opcode BEFORE reading getIn(1): only INT_OR/XOR/AND are guaranteed binary.
            if opc != OpCode::IntOr && opc != OpCode::IntXor && opc != OpCode::IntAnd {
                continue;
            }
            let cvn = data.op(logicop).input(1).unwrap();
            let hi;
            let lo;
            let val: u64;
            if opc == OpCode::IntOr || opc == OpCode::IntXor {
                if !data.vn(cvn).is_constant() {
                    continue;
                }
                let mut v = data.vn(cvn).constant_value();
                if i == 0 {
                    hi = data.op(logicop).input(0).unwrap();
                    lo = data.op(op).input(1).unwrap();
                    v <<= 8 * data.vn(lo).size;
                } else {
                    hi = data.op(op).input(0).unwrap();
                    lo = data.op(logicop).input(0).unwrap();
                }
                val = v;
            } else {
                // opc == OpCode::IntAnd
                if !data.vn(cvn).is_constant() {
                    continue;
                }
                let mut v = data.vn(cvn).constant_value();
                if i == 0 {
                    hi = data.op(logicop).input(0).unwrap();
                    lo = data.op(op).input(1).unwrap();
                    v <<= 8 * data.vn(lo).size;
                    v |= super::nzmask::calc_mask(data.vn(lo).size);
                } else {
                    hi = data.op(op).input(0).unwrap();
                    lo = data.op(logicop).input(0).unwrap();
                    v |= super::nzmask::calc_mask(data.vn(hi).size) << (8 * data.vn(lo).size);
                }
                val = v;
            }
            if data.vn(hi).is_free() {
                continue;
            }
            if data.vn(lo).is_free() {
                continue;
            }
            // Create the earlier concat(hi, lo), then rewrite this op into the bitwise op over it.
            let newconcat = data.new_op_before_sized(op, OpCode::Piece, vec![hi, lo], outsz);
            let newvn = data.op(newconcat).output.unwrap();
            let c = data.new_const(outsz, val);
            data.op_set_opcode(op, opc);
            data.op_set_input(op, 0, newvn);
            data.op_set_input(op, 1, c);
            return 1;
        }
        0
    }
}

/// Ghidra `RuleConcatZext` (`ruleaction.cc`, oppool1 @5579 "analysis"): pull a zero-extension out of
/// a concatenation — `concat(zext(V), W)  =>  zext(concat(V,W))`. The concat of the *unextended* V
/// with W is built first (a smaller PIECE), then the original op becomes the single ZEXT of it.
pub struct RuleConcatZext;

impl Rule for RuleConcatZext {
    fn name(&self) -> &str {
        "concatzext"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Piece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let mut hi = data.op(op).input(0).unwrap();
        if !data.vn(hi).is_written() {
            return 0;
        }
        let zextop = data.vn(hi).def.unwrap();
        if data.op(zextop).code() != OpCode::IntZext {
            return 0;
        }
        hi = data.op(zextop).input(0).unwrap();
        let lo = data.op(op).input(1).unwrap();
        if data.vn(hi).is_free() {
            return 0;
        }
        if data.vn(lo).is_free() {
            return 0;
        }
        // Create the earlier concat(hi, lo) out of the unextended hi and lo...
        let sz = data.vn(hi).size + data.vn(lo).size;
        let newconcat = data.new_op_before_sized(op, OpCode::Piece, vec![hi, lo], sz);
        let newvn = data.op(newconcat).output.unwrap();
        // ...then change the original op into a ZEXT of it.
        data.op_remove_input(op, 1);
        data.op_set_input(op, 0, newvn);
        data.op_set_opcode(op, OpCode::IntZext);
        1
    }
}

/// Ghidra `RuleZextCommute` (`ruleaction.cc`, oppool1 @5580 "analysis"): commute INT_ZEXT with
/// INT_RIGHT — `zext(V) >> W  =>  zext(V >> W)`. The shift moves onto the unextended value (the
/// high zeros of the zext carry no information for a logical right shift), then a single ZEXT.
pub struct RuleZextCommute;

impl Rule for RuleZextCommute {
    fn name(&self) -> &str {
        "zextcommute"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntRight]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let zextvn = data.op(op).input(0).unwrap();
        if !data.vn(zextvn).is_written() {
            return 0;
        }
        let zextop = data.vn(zextvn).def.unwrap();
        if data.op(zextop).code() != OpCode::IntZext {
            return 0;
        }
        let zextin = data.op(zextop).input(0).unwrap();
        if data.vn(zextin).is_free() {
            return 0;
        }
        let savn = data.op(op).input(1).unwrap();
        if !data.vn(savn).is_constant() && data.vn(savn).is_free() {
            return 0;
        }
        // New (earlier) shift of the unextended value, then this op becomes the ZEXT of it.
        let sz = data.vn(zextin).size;
        let newop = data.new_op_before_sized(op, OpCode::IntRight, vec![zextin, savn], sz);
        let newout = data.op(newop).output.unwrap();
        data.op_remove_input(op, 1);
        data.op_set_input(op, 0, newout);
        data.op_set_opcode(op, OpCode::IntZext);
        1
    }
}

/// Ghidra `RuleConcatZero` (`ruleaction.cc`, oppool1 @5595 "analysis"): simplify concatenation with
/// zero — `concat(V, 0)  =>  zext(V) << c`, where `c = 8 * |0-operand|` bits.
pub struct RuleConcatZero;

impl Rule for RuleConcatZero {
    fn name(&self) -> &str {
        "concatzero"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Piece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let lo = data.op(op).input(1).unwrap();
        if !data.vn(lo).is_constant() {
            return 0;
        }
        if data.vn(lo).constant_value() != 0 {
            return 0;
        }
        let sa = (8 * data.vn(lo).size) as u64;
        let highvn = data.op(op).input(0).unwrap();
        let outsz = data.vn(data.op(op).output.unwrap()).size;
        // New ZEXT of the high part, then this op becomes the left shift.
        let newop = data.new_op_before_sized(op, OpCode::IntZext, vec![highvn], outsz);
        let outvn = data.op(newop).output.unwrap();
        let c = data.new_const(4, sa);
        data.op_set_opcode(op, OpCode::IntLeft);
        data.op_set_input(op, 0, outvn);
        data.op_set_input(op, 1, c);
        1
    }
}

/// Ghidra `RuleConcatLeftShift` (`ruleaction.cc`, oppool1 @5596 "analysis"): simplify concatenation
/// of an extended, byte-aligned, top-justified value —
/// `concat(V, zext(W) << c)  =>  concat( concat(V,W), 0)` — when `zext(W) << c` places W exactly at
/// the most-significant boundary (`c/8 + |W| == |zext(W)|`).
pub struct RuleConcatLeftShift;

impl Rule for RuleConcatLeftShift {
    fn name(&self) -> &str {
        "concatleftshift"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Piece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn2 = data.op(op).input(1).unwrap();
        if !data.vn(vn2).is_written() {
            return 0;
        }
        let shiftop = data.vn(vn2).def.unwrap();
        if data.op(shiftop).code() != OpCode::IntLeft {
            return 0;
        }
        let shiftamt = data.op(shiftop).input(1).unwrap();
        if !data.vn(shiftamt).is_constant() {
            return 0; // Must be a constant shift
        }
        let mut sa = data.vn(shiftamt).constant_value();
        if (sa & 7) != 0 {
            return 0; // Not a multiple of 8
        }
        let tmpvn = data.op(shiftop).input(0).unwrap();
        if !data.vn(tmpvn).is_written() {
            return 0;
        }
        let zextop = data.vn(tmpvn).def.unwrap();
        if data.op(zextop).code() != OpCode::IntZext {
            return 0;
        }
        let b = data.op(zextop).input(0).unwrap();
        if data.vn(b).is_free() {
            return 0;
        }
        let vn1 = data.op(op).input(0).unwrap();
        if data.vn(vn1).is_free() {
            return 0;
        }
        sa /= 8; // bits to bytes
        if sa + data.vn(b).size as u64 != data.vn(tmpvn).size as u64 {
            return 0; // Must shift to most sig boundary
        }
        let newout_sz = data.vn(vn1).size + data.vn(b).size;
        let newop = data.new_op_before_sized(op, OpCode::Piece, vec![vn1, b], newout_sz);
        let newout = data.op(newop).output.unwrap();
        let outsz = data.vn(data.op(op).output.unwrap()).size;
        let c = data.new_const(outsz - newout_sz, 0);
        data.op_set_input(op, 0, newout);
        data.op_set_input(op, 1, c);
        1
    }
}

/// Ghidra `RuleDoubleSub` (`ruleaction.cc`, oppool1 @5542 "analysis"): collapse chained SUBPIECE —
/// `sub( sub(V,c), d)  =>  sub(V, c+d)` — skipping the intermediate truncation.
pub struct RuleDoubleSub;

impl Rule for RuleDoubleSub {
    fn name(&self) -> &str {
        "doublesub"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vn = data.op(op).input(0).unwrap();
        if !data.vn(vn).is_written() {
            return 0;
        }
        let op2 = data.vn(vn).def.unwrap();
        if data.op(op2).code() != OpCode::Subpiece {
            return 0;
        }
        // SUBPIECE's truncation offset (input 1) is always a constant.
        let offset1 = data.vn(data.op(op).input(1).unwrap()).constant_value();
        let offset2 = data.vn(data.op(op2).input(1).unwrap()).constant_value();
        let base = data.op(op2).input(0).unwrap();
        data.op_set_input(op, 0, base); // Skip middleman
        let c = data.new_const(4, offset1 + offset2);
        data.op_set_input(op, 1, c);
        1
    }
}

/// Ghidra `RuleDoubleShift` (`ruleaction.cc`, oppool1 @5543 "analysis"): combine or cancel chained
/// INT_LEFT/INT_RIGHT (INT_MULT by a power of two counts as a left shift). Same direction combines
/// the shift amounts (`(V<<c)<<d => V<<(c+d)`, or COPY 0 if it shifts the whole word out); equal
/// opposite shifts become a mask (`(V<<c)>>c => V & mask`).
pub struct RuleDoubleShift;

impl Rule for RuleDoubleShift {
    fn name(&self) -> &str {
        "doubleshift"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntLeft, OpCode::IntRight, OpCode::IntMult]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let in1 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_constant() {
            return 0;
        }
        let secvn = data.op(op).input(0).unwrap();
        if !data.vn(secvn).is_written() {
            return 0;
        }
        let secop = data.vn(secvn).def.unwrap();
        let mut opc2 = data.op(secop).code();
        if opc2 != OpCode::IntLeft && opc2 != OpCode::IntRight && opc2 != OpCode::IntMult {
            return 0;
        }
        let secop_in1 = data.op(secop).input(1).unwrap();
        if !data.vn(secop_in1).is_constant() {
            return 0;
        }
        let mut opc1 = data.op(op).code();
        let size = data.vn(secvn).size;
        let secop_in0 = data.op(secop).input(0).unwrap();
        if !data.vn(secop_in0).is_heritage_known() {
            return 0;
        }

        let sa1: i32;
        if opc1 == OpCode::IntMult {
            let val = data.vn(in1).constant_value();
            let lsb = super::nzmask::leastsigbit_set(val);
            if val.wrapping_shr(lsb as u32) != 1 {
                return 0; // Not multiplying by a power of 2
            }
            sa1 = lsb;
            opc1 = OpCode::IntLeft;
        } else {
            sa1 = data.vn(in1).constant_value() as i32;
        }
        let sa2: i32;
        if opc2 == OpCode::IntMult {
            let val = data.vn(secop_in1).constant_value();
            let lsb = super::nzmask::leastsigbit_set(val);
            if val.wrapping_shr(lsb as u32) != 1 {
                return 0; // Not multiplying by a power of 2
            }
            sa2 = lsb;
            opc2 = OpCode::IntLeft;
        } else {
            sa2 = data.vn(secop_in1).constant_value() as i32;
        }

        if opc1 == opc2 {
            if sa1 + sa2 < 8 * size as i32 {
                let c = data.new_const(4, (sa1 + sa2) as u32 as u64);
                data.op_set_opcode(op, opc1);
                data.op_set_input(op, 0, secop_in0);
                data.op_set_input(op, 1, c);
            } else {
                let c = data.new_const(size, 0);
                data.op_set_opcode(op, OpCode::Copy);
                data.op_set_input(op, 0, c);
                data.op_remove_input(op, 1);
            }
        } else if sa1 == sa2 && size <= 8 {
            // The u64 mask shift matches Ghidra's x86-64 masked-count shift (see RuleAndCommute).
            let mut mask = super::nzmask::calc_mask(size);
            if opc1 == OpCode::IntLeft {
                // A left shift is likely a multiply; don't collapse to AND if the intermediate is reused.
                if lone_descend(data, secvn).is_none() {
                    return 0;
                }
                mask = mask.wrapping_shl(sa1 as u32) & mask;
            } else {
                mask = mask.wrapping_shr(sa1 as u32) & mask;
            }
            let c = data.new_const(size, mask);
            data.op_set_opcode(op, OpCode::IntAnd);
            data.op_set_input(op, 0, secop_in0);
            data.op_set_input(op, 1, c);
        } else {
            return 0;
        }
        1
    }
}

/// Ghidra `RuleDoubleArithShift` (`ruleaction.cc`, oppool1 @5544 "analysis"): combine two sequential
/// signed right shifts — `(x s>> c) s>> d  =>  x s>> saturate(c + d)` — saturating the total shift at
/// the point the sign bit has filled the whole result (division optimization produces these chains).
pub struct RuleDoubleArithShift;

impl Rule for RuleDoubleArithShift {
    fn name(&self) -> &str {
        "doublearithshift"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntSright]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let const_d = data.op(op).input(1).unwrap();
        if !data.vn(const_d).is_constant() {
            return 0;
        }
        let shiftin = data.op(op).input(0).unwrap();
        if !data.vn(shiftin).is_written() {
            return 0;
        }
        let shift2op = data.vn(shiftin).def.unwrap();
        if data.op(shift2op).code() != OpCode::IntSright {
            return 0;
        }
        let const_c = data.op(shift2op).input(1).unwrap();
        if !data.vn(const_c).is_constant() {
            return 0;
        }
        let in_vn = data.op(shift2op).input(0).unwrap();
        if data.vn(in_vn).is_free() {
            return 0;
        }
        let max = data.vn(data.op(op).output.unwrap()).size as i32 * 8 - 1; // Maximum possible shift.
        let mut sa =
            data.vn(const_c).constant_value() as i32 + data.vn(const_d).constant_value() as i32;
        if sa <= 0 {
            return 0; // Something is wrong
        }
        if sa > max {
            sa = max; // Shift amount has saturated
        }
        data.op_set_input(op, 0, in_vn);
        let c = data.new_const(4, sa as u64);
        data.op_set_input(op, 1, c);
        1
    }
}

/// Ghidra `RuleConcatShift` (`ruleaction.cc`, oppool1 @5545 "analysis"): a right shift that discards
/// the least-significant component of a concatenation cancels it — `concat(V,W) >> c  =>  ext(V)`,
/// zero-extension for INT_RIGHT and sign-extension for INT_SRIGHT. Any residual shift beyond `|W|`
/// is re-applied to the extended most-significant part.
pub struct RuleConcatShift;

impl Rule for RuleConcatShift {
    fn name(&self) -> &str {
        "concatshift"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntRight, OpCode::IntSright]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let in1 = data.op(op).input(1).unwrap();
        if !data.vn(in1).is_constant() {
            return 0;
        }
        let shiftin = data.op(op).input(0).unwrap();
        if !data.vn(shiftin).is_written() {
            return 0;
        }
        let concat = data.vn(shiftin).def.unwrap();
        if data.op(concat).code() != OpCode::Piece {
            return 0;
        }
        let mut sa = data.vn(in1).constant_value() as i64;
        let leastsize = data.vn(data.op(concat).input(1).unwrap()).size as i64 * 8;
        if sa < leastsize {
            return 0; // Does the shift throw away the least significant part?
        }
        let mainin = data.op(concat).input(0).unwrap();
        if data.vn(mainin).is_free() {
            return 0;
        }
        sa -= leastsize;
        let extcode = if data.op(op).code() == OpCode::IntRight {
            OpCode::IntZext
        } else {
            OpCode::IntSext
        };
        if sa == 0 {
            // Exact cancellation: the shift becomes a plain extension of the most-significant part.
            data.op_remove_input(op, 1);
            data.op_set_opcode(op, extcode);
            data.op_set_input(op, 0, mainin);
        } else {
            // Extend the most-significant part, then apply the residual shift.
            let sz = data.vn(shiftin).size;
            let extop = data.new_op_before_sized(op, extcode, vec![mainin], sz);
            let newvn = data.op(extop).output.unwrap();
            data.op_set_input(op, 0, newvn);
            let c = data.new_const(data.vn(in1).size, sa as u64);
            data.op_set_input(op, 1, c);
        }
        1
    }
}

/// Ghidra `RuleSignForm` (`ruleaction.cc`, oppool1 @5597 "analysis"): normalize a sign extraction —
/// `sub(sext(V), c)  =>  V s>> (8*|V|-1)` — when the SUBPIECE takes a byte at or above V's width (so
/// it is extracting the replicated sign bit of the extension).
pub struct RuleSignForm;

impl Rule for RuleSignForm {
    fn name(&self) -> &str {
        "signform"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::Subpiece]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let sextout = data.op(op).input(0).unwrap();
        if !data.vn(sextout).is_written() {
            return 0;
        }
        let sextop = data.vn(sextout).def.unwrap();
        if data.op(sextop).code() != OpCode::IntSext {
            return 0;
        }
        let a = data.op(sextop).input(0).unwrap();
        let c = data.vn(data.op(op).input(1).unwrap()).constant_value(); // SUBPIECE byte offset
        if (c as i64) < data.vn(a).size as i64 {
            return 0;
        }
        if data.vn(a).is_free() {
            return 0;
        }
        data.op_set_input(op, 0, a);
        let n = (8 * data.vn(a).size - 1) as u64;
        let cn = data.new_const(4, n);
        data.op_set_input(op, 1, cn);
        data.op_set_opcode(op, OpCode::IntSright);
        1
    }
}

/// Ghidra `RuleTrivialBool` (`ruleaction.cc`, oppool1 @5523 "analysis"): simplify a boolean op with a
/// constant operand — `V&&false=>false`, `V&&true=>V`, `V||false=>V`, `V||true=>true`,
/// `V^^true=>!V`, `V^^false=>V`.
pub struct RuleTrivialBool;

impl Rule for RuleTrivialBool {
    fn name(&self) -> &str {
        "trivialbool"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::BoolAnd, OpCode::BoolOr, OpCode::BoolXor]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let vnconst = data.op(op).input(1).unwrap();
        if !data.vn(vnconst).is_constant() {
            return 0;
        }
        let val = data.vn(vnconst).constant_value();
        let (opc, vn) = match data.op(op).code() {
            OpCode::BoolXor => {
                let opc = if val == 1 { OpCode::BoolNegate } else { OpCode::Copy };
                (opc, data.op(op).input(0).unwrap())
            }
            OpCode::BoolAnd => {
                if val == 1 {
                    (OpCode::Copy, data.op(op).input(0).unwrap())
                } else {
                    (OpCode::Copy, data.new_const(1, 0)) // Copy false
                }
            }
            OpCode::BoolOr => {
                if val == 1 {
                    (OpCode::Copy, data.new_const(1, 1)) // Copy true
                } else {
                    (OpCode::Copy, data.op(op).input(0).unwrap())
                }
            }
            _ => return 0,
        };
        data.op_remove_input(op, 1);
        data.op_set_opcode(op, opc);
        data.op_set_input(op, 0, vn);
        1
    }
}

/// Ghidra `RuleLess2Zero` (`ruleaction.cc`, oppool1 @5573 "analysis"): simplify INT_LESS against
/// extremal constants — `0 < V => 0 != V`, `V < 0 => false`, `-1(max) < V => false`,
/// `V < -1(max) => V != -1`.
pub struct RuleLess2Zero;

impl Rule for RuleLess2Zero {
    fn name(&self) -> &str {
        "less2zero"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntLess]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let lvn = data.op(op).input(0).unwrap();
        let rvn = data.op(op).input(1).unwrap();
        if data.vn(lvn).is_constant() {
            if data.vn(lvn).constant_value() == 0 {
                // All values except 0 are greater -> NOT_EQUAL
                data.op_set_opcode(op, OpCode::IntNotequal);
                return 1;
            } else if data.vn(lvn).constant_value() == super::nzmask::calc_mask(data.vn(lvn).size) {
                // max < V is always false
                let z = data.new_const(1, 0);
                data.op_set_opcode(op, OpCode::Copy);
                data.op_remove_input(op, 1);
                data.op_set_input(op, 0, z);
                return 1;
            }
        } else if data.vn(rvn).is_constant() {
            if data.vn(rvn).constant_value() == 0 {
                // V < 0 is always false
                let z = data.new_const(1, 0);
                data.op_set_opcode(op, OpCode::Copy);
                data.op_remove_input(op, 1);
                data.op_set_input(op, 0, z);
                return 1;
            } else if data.vn(rvn).constant_value() == super::nzmask::calc_mask(data.vn(rvn).size) {
                // All values except max are less -> NOT_EQUAL
                data.op_set_opcode(op, OpCode::IntNotequal);
                return 1;
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
    fn subvar_zext_rule_narrows_a_zext_fed_return() {
        // RuleSubvarZext on `RAX:8 = ZEXT(u:4)` feeding a RETURN narrows the return to the 4-byte
        // logical value (via SubvariableFlow::try_return_pull) — the twodim-class int4 return fix.
        let (mut f, _) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let u = f.new_input(4, Address::new(reg, 0x10));
        let op_z = f.new_op(OpCode::IntZext, seq, vec![u]);
        let rax = f.new_output(op_z, 8, Address::new(reg, 0x0));
        let retaddr = f.new_input(8, Address::new(reg, 0x288));
        let ret = f.new_op(OpCode::Return, seq, vec![retaddr, rax]);
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op_z, ret], ..Default::default() }]);
        for op in f.block(BlockId(0)).ops.clone() {
            f.op_mut(op).parent = Some(BlockId(0));
        }
        assert_eq!(RuleSubvarZext.apply_op(op_z, &mut f), 1);
        assert_eq!(f.vn(f.op(ret).input(1).unwrap()).size, 4);
    }

    #[test]
    fn subvar_subpiece_rule_dissolves_a_truncation() {
        // p:1 = SUBPIECE(y:4 = a & 0xff, 0), used narrowly (STORE). RuleSubvarSubpiece seeds the flow
        // on y with mask 0xff; the SUBPIECE becomes a COPY of the 1-byte logical value.
        let (mut f, _) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let c = f.new_const(4, 0xff);
        let op0 = f.new_op(OpCode::IntAnd, seq, vec![a, c]);
        let y = f.new_output(op0, 4, Address::new(reg, 0x20));
        let z0 = f.new_const(4, 0);
        let op1 = f.new_op(OpCode::Subpiece, seq, vec![y, z0]);
        let p = f.new_output(op1, 1, Address::new(reg, 0x28));
        let sid = f.new_const(8, ram.0 as u64);
        let ptr = f.new_input(8, Address::new(reg, 0x30));
        let store = f.new_op(OpCode::Store, seq, vec![sid, ptr, p]);
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op0, op1, store], ..Default::default() }]);
        for op in f.block(BlockId(0)).ops.clone() {
            f.op_mut(op).parent = Some(BlockId(0));
        }
        assert_eq!(RuleSubvarSubpiece.apply_op(op1, &mut f), 1);
        assert_eq!(f.op(op1).code(), OpCode::Copy);
    }

    // The firing path of the remaining 3 driving rules is covered end-to-end by the 20 SubvariableFlow
    // trace unit tests + the corpus; here we pin each rule's seed guard (the part unique to the wrapper).

    #[test]
    fn subvar_and_rule_needs_a_constant_mask() {
        // RuleSubvarAnd seeds only on `V & c` (constant mask); a non-constant second operand → no-op.
        let (mut f, _) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18)); // non-constant
        let op = f.new_op(OpCode::IntAnd, seq, vec![a, b]);
        f.new_output(op, 4, Address::new(reg, 0x20));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op], ..Default::default() }]);
        assert_eq!(RuleSubvarAnd.apply_op(op, &mut f), 0);
    }

    #[test]
    fn subvar_compzero_rule_needs_a_single_bit() {
        // RuleSubvarCompZero seeds only when the tested value has a single live bit; a full 4-byte
        // value (nzmask many bits) → no-op.
        let (mut f, _) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let z = f.new_const(4, 0);
        let op = f.new_op(OpCode::IntEqual, seq, vec![v, z]);
        f.new_output(op, 1, Address::new(reg, 0x20));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op], ..Default::default() }]);
        assert_eq!(RuleSubvarCompZero.apply_op(op, &mut f), 0);
    }

    #[test]
    fn subvar_shift_rule_needs_a_byte_source() {
        // RuleSubvarShift seeds only when the shifted value is exactly 1 byte; a 4-byte shift → no-op.
        let (mut f, _) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let v = f.new_input(4, Address::new(reg, 0x10));
        let sa = f.new_const(4, 2);
        let op = f.new_op(OpCode::IntRight, seq, vec![v, sa]);
        f.new_output(op, 4, Address::new(reg, 0x20));
        f.set_blocks(vec![crate::decompile::BlockBasic { ops: vec![op], ..Default::default() }]);
        assert_eq!(RuleSubvarShift.apply_op(op, &mut f), 0);
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

    // --- RuleAndCommute (ruleaction.cc:1532) ---

    #[test]
    fn and_commute_left_const_lonedescend() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // (V << 8) & 0xff00   =>   (V & (0xff00 >> 8)) << 8   [the INT_LEFT const fast path]
        let v = f.new_input(2, Address::new(reg, 0x10));
        let sa = f.new_const(4, 8);
        let sh = f.new_op(OpCode::IntLeft, seq, vec![v, sa]);
        let shvn = f.new_output_unique(sh, 2);
        let mask = f.new_const(2, 0xff00);
        let and = f.new_op(OpCode::IntAnd, seq, vec![shvn, mask]);
        f.new_output(and, 2, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![sh, and],
            ..Default::default()
        }]);

        assert_eq!(RuleAndCommute.apply_op(and, &mut f), 1);
        // The AND op is now the outer INT_LEFT by the same shift amount.
        assert_eq!(f.op(and).code(), OpCode::IntLeft);
        let outer_sa = f.op(and).input(1).unwrap();
        assert!(f.vn(outer_sa).is_constant() && f.vn(outer_sa).constant_value() == 8);
        // Its shifted value is `V & (0xff00 >> 8)`.
        let inner_and = f.vn(f.op(and).input(0).unwrap()).def.unwrap();
        assert_eq!(f.op(inner_and).code(), OpCode::IntAnd);
        assert_eq!(f.op(inner_and).input(0), Some(v));
        let inner_shift = f.vn(f.op(inner_and).input(1).unwrap()).def.unwrap();
        assert_eq!(f.op(inner_shift).code(), OpCode::IntRight);
        let masked_const = f.op(inner_shift).input(0).unwrap();
        assert!(f.vn(masked_const).is_constant() && f.vn(masked_const).constant_value() == 0xff00);
    }

    #[test]
    fn and_commute_skips_plain_and() {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = SeqNum { pc: ram, uniq: 0 };
        // Neither operand is a shift  =>  rule must not fire.
        let v = f.new_input(4, Address::new(reg, 0x10));
        let w = f.new_input(4, Address::new(reg, 0x18));
        let and = f.new_op(OpCode::IntAnd, seq, vec![v, w]);
        f.new_output(and, 4, Address::new(reg, 0));
        f.set_blocks(vec![crate::decompile::BlockBasic {
            ops: vec![and],
            ..Default::default()
        }]);
        assert_eq!(RuleAndCommute.apply_op(and, &mut f), 0);
        assert_eq!(f.op(and).code(), OpCode::IntAnd);
    }

    #[test]
    fn early_removal_destroys_a_dead_output_keeps_live_and_global() {
        // RuleEarlyRemoval: an op whose unique output has no readers is destroyed; one whose output
        // is read is kept; a written `ram` global is kept (the persist live-out guard).
        let (mut f, _) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let uniq = f.spaces.by_name("unique").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x14));

        // dead: unique output with no descendants → removed.
        let dead = f.new_op(OpCode::IntAdd, seq, vec![a, b]);
        let _dead_out = f.new_output(dead, 4, Address::new(uniq, 0x100));
        assert_eq!(RuleEarlyRemoval.apply_op(dead, &mut f), 1);
        assert!(f.op(dead).is_dead());

        // live: output read by a STORE sink → kept.
        let live = f.new_op(OpCode::IntAdd, seq, vec![a, b]);
        let live_out = f.new_output(live, 4, Address::new(uniq, 0x108));
        let sid = f.new_const(8, ram.0 as u64);
        let ptr = f.new_input(8, Address::new(reg, 0x30));
        let _store = f.new_op(OpCode::Store, seq, vec![sid, ptr, live_out]);
        assert_eq!(RuleEarlyRemoval.apply_op(live, &mut f), 0);
        assert!(!f.op(live).is_dead());

        // ram global: written to a global (ram) address, no SSA reader → kept by the persist guard.
        let glob = f.new_op(OpCode::IntAdd, seq, vec![a, b]);
        let _glob_out = f.new_output(glob, 4, Address::new(ram, 0x601030));
        assert_eq!(RuleEarlyRemoval.apply_op(glob, &mut f), 0);
        assert!(!f.op(glob).is_dead());
    }

    #[test]
    fn scarry_trivial_and_comparison_rewrite() {
        // Trivial: SCARRY(a, 0) → COPY 0.
        let (mut f, _) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let c0 = f.new_const(4, 0);
        let triv = f.new_op(OpCode::IntScarry, seq, vec![a, c0]);
        let _to = f.new_output(triv, 1, Address::new(reg, 0x200));
        assert_eq!(RuleScarry.apply_op(triv, &mut f), 1);
        assert_eq!(f.op(triv).code(), OpCode::Copy);

        // Comparison: `scarry(a, 5) != (0 s< (a + 5))` → a signed compare of `a` against `-5`.
        let c5 = f.new_const(4, 5);
        let sc = f.new_op(OpCode::IntScarry, seq, vec![a, c5]);
        let sc_out = f.new_output(sc, 1, Address::new(reg, 0x208));
        let sum = f.new_op(OpCode::IntAdd, seq, vec![a, c5]);
        let sum_out = f.new_output(sum, 4, Address::new(reg, 0x20c));
        let z = f.new_const(4, 0);
        let sless = f.new_op(OpCode::IntSless, seq, vec![z, sum_out]); // 0 s< (a+5)
        let sless_out = f.new_output(sless, 1, Address::new(reg, 0x210));
        let ne = f.new_op(OpCode::IntNotequal, seq, vec![sc_out, sless_out]);
        let _ne_out = f.new_output(ne, 1, Address::new(reg, 0x218));
        assert_eq!(RuleScarry.apply_op(sc, &mut f), 1);
        // The compare is rewritten to INT_SLESS between `a` and the constant `-5` (0xfffffffb).
        assert_eq!(f.op(ne).code(), OpCode::IntSless);
        let (n0, n1) = (f.op(ne).input(0).unwrap(), f.op(ne).input(1).unwrap());
        let has_a = n0 == a || n1 == a;
        let negc = 5u64.wrapping_neg() & 0xffff_ffff;
        let has_negc = f.vn(n0).is_constant() && f.vn(n0).constant_value() == negc
            || f.vn(n1).is_constant() && f.vn(n1).constant_value() == negc;
        assert!(has_a && has_negc, "compare is `a` vs `-5`");
    }

    #[test]
    fn float_cast_collapses_stacked_casts() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // (float)(double)x, exact narrow back to the source size → identity COPY of x.
        let x4 = f.new_input(4, Address::new(r, 0x10));
        let up = f.new_op(OpCode::FloatFloat2float, seq, vec![x4]);
        let up8 = f.new_output(up, 8, Address::new(r, 0x20));
        let down = f.new_op(OpCode::FloatFloat2float, seq, vec![up8]);
        let _d4 = f.new_output(down, 4, Address::new(r, 0x28));
        assert_eq!(RuleFloatCast.apply_op(down, &mut f), 1);
        assert_eq!(f.op(down).code(), OpCode::Copy);
        assert_eq!(f.op(down).input(0).unwrap(), x4);

        // Superfluous narrow but NOT back to the source size → stays FLOAT2FLOAT, skips the middle
        // cast (insize1 > outsize, outsize != insize2). 10-byte x87 long double → 8 here.
        let y4 = f.new_input(4, Address::new(r, 0x30));
        let up10 = f.new_op(OpCode::FloatFloat2float, seq, vec![y4]);
        let up10o = f.new_output(up10, 10, Address::new(r, 0x40));
        let down8 = f.new_op(OpCode::FloatFloat2float, seq, vec![up10o]);
        let _d8 = f.new_output(down8, 8, Address::new(r, 0x50));
        assert_eq!(RuleFloatCast.apply_op(down8, &mut f), 1);
        assert_eq!(f.op(down8).code(), OpCode::FloatFloat2float);
        assert_eq!(f.op(down8).input(0).unwrap(), y4);

        // (float)(double)(int)n → int straight into the final float size: op becomes INT2FLOAT of n.
        let n4 = f.new_input(4, Address::new(r, 0x60));
        let i2f = f.new_op(OpCode::FloatInt2float, seq, vec![n4]);
        let i2f8 = f.new_output(i2f, 8, Address::new(r, 0x68));
        let narrow = f.new_op(OpCode::FloatFloat2float, seq, vec![i2f8]);
        let _nf4 = f.new_output(narrow, 4, Address::new(r, 0x70));
        assert_eq!(RuleFloatCast.apply_op(narrow, &mut f), 1);
        assert_eq!(f.op(narrow).code(), OpCode::FloatInt2float);
        assert_eq!(f.op(narrow).input(0).unwrap(), n4);

        // trunc((double)z) → float straight into the final integer: op stays TRUNC of the small float.
        let z4 = f.new_input(4, Address::new(r, 0x80));
        let zup = f.new_op(OpCode::FloatFloat2float, seq, vec![z4]);
        let zup8 = f.new_output(zup, 8, Address::new(r, 0x88));
        let trunc = f.new_op(OpCode::FloatTrunc, seq, vec![zup8]);
        let _t4 = f.new_output(trunc, 4, Address::new(r, 0x90));
        assert_eq!(RuleFloatCast.apply_op(trunc, &mut f), 1);
        assert_eq!(f.op(trunc).code(), OpCode::FloatTrunc);
        assert_eq!(f.op(trunc).input(0).unwrap(), z4);

        // Input not defined by a float cast (FLOAT_ADD) → no match.
        let a = f.new_input(8, Address::new(r, 0xa0));
        let b = f.new_input(8, Address::new(r, 0xa8));
        let add = f.new_op(OpCode::FloatAdd, seq, vec![a, b]);
        let add8 = f.new_output(add, 8, Address::new(r, 0xb0));
        let nomatch = f.new_op(OpCode::FloatFloat2float, seq, vec![add8]);
        let _nm4 = f.new_output(nomatch, 4, Address::new(r, 0xb8));
        assert_eq!(RuleFloatCast.apply_op(nomatch, &mut f), 0);
        assert_eq!(f.op(nomatch).code(), OpCode::FloatFloat2float);
    }

    #[test]
    fn shift_and_drops_redundant_mask() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // (v & 0xff00) >> 8, with v's non-zero bits confined to 0xff00: after the shift the mask
        // (0xff) covers all of v's possibly-nonzero bits (0xff), so the AND is redundant → COPY.
        let v = f.new_input(4, Address::new(r, 0x10));
        f.vn_mut(v).nzm = 0xff00;
        let m = f.new_const(4, 0xff00);
        let c8 = f.new_const(4, 8);
        let and = f.new_op(OpCode::IntAnd, seq, vec![v, m]);
        let ando = f.new_output(and, 4, Address::new(r, 0x18));
        let sh = f.new_op(OpCode::IntRight, seq, vec![ando, c8]);
        let _o = f.new_output(sh, 4, Address::new(r, 0x20));
        assert_eq!(RuleShiftAnd.apply_op(sh, &mut f), 1);
        assert_eq!(f.op(and).code(), OpCode::Copy);
        assert_eq!(f.op(and).inrefs.len(), 1);

        // INT_MULT by a power of two (16) is treated as a left shift by 4; nzm 0x0f, mask 0x0f →
        // after `<< 4` mask 0xf0 covers nzm 0xf0 → redundant AND → COPY.
        let v2 = f.new_input(4, Address::new(r, 0x30));
        f.vn_mut(v2).nzm = 0x0f;
        let m2 = f.new_const(4, 0x0f);
        let c16 = f.new_const(4, 16);
        let and2 = f.new_op(OpCode::IntAnd, seq, vec![v2, m2]);
        let and2o = f.new_output(and2, 4, Address::new(r, 0x38));
        let mul = f.new_op(OpCode::IntMult, seq, vec![and2o, c16]);
        let _o2 = f.new_output(mul, 4, Address::new(r, 0x40));
        assert_eq!(RuleShiftAnd.apply_op(mul, &mut f), 1);
        assert_eq!(f.op(and2).code(), OpCode::Copy);

        // No fire: mask 0x0f does NOT cover the bits v can set (nzm 0xff) after `<< 4`.
        let v3 = f.new_input(4, Address::new(r, 0x50));
        f.vn_mut(v3).nzm = 0xff;
        let m3 = f.new_const(4, 0x0f);
        let c4 = f.new_const(4, 4);
        let and3 = f.new_op(OpCode::IntAnd, seq, vec![v3, m3]);
        let and3o = f.new_output(and3, 4, Address::new(r, 0x58));
        let shl = f.new_op(OpCode::IntLeft, seq, vec![and3o, c4]);
        let _o3 = f.new_output(shl, 4, Address::new(r, 0x60));
        assert_eq!(RuleShiftAnd.apply_op(shl, &mut f), 0);
        assert_eq!(f.op(and3).code(), OpCode::IntAnd);

        // No fire: INT_MULT by a non-power-of-two (3) is not a shift.
        let v4 = f.new_input(4, Address::new(r, 0x70));
        f.vn_mut(v4).nzm = 0x0f;
        let m4 = f.new_const(4, 0x0f);
        let c3 = f.new_const(4, 3);
        let and4 = f.new_op(OpCode::IntAnd, seq, vec![v4, m4]);
        let and4o = f.new_output(and4, 4, Address::new(r, 0x78));
        let mul3 = f.new_op(OpCode::IntMult, seq, vec![and4o, c3]);
        let _o4 = f.new_output(mul3, 4, Address::new(r, 0x80));
        assert_eq!(RuleShiftAnd.apply_op(mul3, &mut f), 0);
        assert_eq!(f.op(and4).code(), OpCode::IntAnd);
    }

    #[test]
    fn concat_commute_pulls_concat_inside() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // concat(V, W | c)  =>  concat(V,W) | c   (i==1 branch, no shift of the constant).
        let vv = f.new_input(2, Address::new(r, 0x10));
        let ww = f.new_input(2, Address::new(r, 0x18));
        let c = f.new_const(2, 0x0055);
        let orop = f.new_op(OpCode::IntOr, seq, vec![ww, c]);
        let oro = f.new_output(orop, 2, Address::new(r, 0x20));
        let pc = f.new_op(OpCode::Piece, seq, vec![vv, oro]);
        let _po = f.new_output(pc, 4, Address::new(r, 0x28));
        assert_eq!(RuleConcatCommute.apply_op(pc, &mut f), 1);
        assert_eq!(f.op(pc).code(), OpCode::IntOr);
        let inner = f.op(pc).input(0).unwrap();
        let idef = f.vn(inner).def.unwrap();
        assert_eq!(f.op(idef).code(), OpCode::Piece);
        assert_eq!(f.op(idef).input(0).unwrap(), vv);
        assert_eq!(f.op(idef).input(1).unwrap(), ww);
        let cst = f.op(pc).input(1).unwrap();
        assert!(f.vn(cst).is_constant() && f.vn(cst).constant_value() == 0x0055);

        // concat(V & c, W)  =>  concat(V,W) & ((c << 8|W|) | mask(|W|))   (i==0 branch).
        let v2 = f.new_input(1, Address::new(r, 0x30));
        let w2 = f.new_input(1, Address::new(r, 0x38));
        let c2 = f.new_const(1, 0x0f);
        let andop = f.new_op(OpCode::IntAnd, seq, vec![v2, c2]);
        let ando = f.new_output(andop, 1, Address::new(r, 0x40));
        let pc2 = f.new_op(OpCode::Piece, seq, vec![ando, w2]);
        let _po2 = f.new_output(pc2, 2, Address::new(r, 0x48));
        assert_eq!(RuleConcatCommute.apply_op(pc2, &mut f), 1);
        assert_eq!(f.op(pc2).code(), OpCode::IntAnd);
        let cst2 = f.op(pc2).input(1).unwrap();
        // low byte (W) fully kept = 0xff; high byte (V) keeps low nibble = 0x0f << 8 = 0xf00.
        assert!(f.vn(cst2).is_constant() && f.vn(cst2).constant_value() == 0x0fff);
    }

    #[test]
    fn concat_zext_pulls_zext_out() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // concat(zext(V), W)  =>  zext(concat(V,W)).
        let vv = f.new_input(2, Address::new(r, 0x10));
        let ww = f.new_input(2, Address::new(r, 0x18));
        let ze = f.new_op(OpCode::IntZext, seq, vec![vv]);
        let zeo = f.new_output(ze, 4, Address::new(r, 0x20));
        let pc = f.new_op(OpCode::Piece, seq, vec![zeo, ww]);
        let _po = f.new_output(pc, 6, Address::new(r, 0x28));
        assert_eq!(RuleConcatZext.apply_op(pc, &mut f), 1);
        assert_eq!(f.op(pc).code(), OpCode::IntZext);
        assert_eq!(f.op(pc).inrefs.len(), 1);
        let inner = f.op(pc).input(0).unwrap();
        let idef = f.vn(inner).def.unwrap();
        assert_eq!(f.op(idef).code(), OpCode::Piece);
        assert_eq!(f.op(idef).input(0).unwrap(), vv);
        assert_eq!(f.op(idef).input(1).unwrap(), ww);
        // the inner concat is the unextended width |V|+|W| = 4, not the 6-byte output.
        assert_eq!(f.vn(inner).size, 4);

        // No fire: high input not defined by a ZEXT.
        let a = f.new_input(4, Address::new(r, 0x30));
        let b = f.new_input(2, Address::new(r, 0x38));
        let pc2 = f.new_op(OpCode::Piece, seq, vec![a, b]);
        let _po2 = f.new_output(pc2, 6, Address::new(r, 0x40));
        assert_eq!(RuleConcatZext.apply_op(pc2, &mut f), 0);
        assert_eq!(f.op(pc2).code(), OpCode::Piece);
    }

    #[test]
    fn zext_commute_moves_shift_under_zext() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // zext(V) >> 8  =>  zext(V >> 8).
        let vv = f.new_input(2, Address::new(r, 0x10));
        let ze = f.new_op(OpCode::IntZext, seq, vec![vv]);
        let zeo = f.new_output(ze, 4, Address::new(r, 0x18));
        let c8 = f.new_const(4, 8);
        let shr = f.new_op(OpCode::IntRight, seq, vec![zeo, c8]);
        let _o = f.new_output(shr, 4, Address::new(r, 0x20));
        assert_eq!(RuleZextCommute.apply_op(shr, &mut f), 1);
        assert_eq!(f.op(shr).code(), OpCode::IntZext);
        assert_eq!(f.op(shr).inrefs.len(), 1);
        let inner = f.op(shr).input(0).unwrap();
        let idef = f.vn(inner).def.unwrap();
        assert_eq!(f.op(idef).code(), OpCode::IntRight);
        assert_eq!(f.op(idef).input(0).unwrap(), vv);
        assert_eq!(f.vn(inner).size, 2); // shift is on the unextended width
    }

    #[test]
    fn concat_zero_becomes_zext_shift() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // concat(V, 0) => zext(V) << 16  (the zero operand is 2 bytes = 16 bits).
        let vv = f.new_input(2, Address::new(r, 0x10));
        let z = f.new_const(2, 0);
        let pc = f.new_op(OpCode::Piece, seq, vec![vv, z]);
        let _po = f.new_output(pc, 4, Address::new(r, 0x18));
        assert_eq!(RuleConcatZero.apply_op(pc, &mut f), 1);
        assert_eq!(f.op(pc).code(), OpCode::IntLeft);
        let sh = f.op(pc).input(1).unwrap();
        assert!(f.vn(sh).is_constant() && f.vn(sh).constant_value() == 16);
        let zx = f.op(pc).input(0).unwrap();
        assert_eq!(f.op(f.vn(zx).def.unwrap()).code(), OpCode::IntZext);

        // No fire: low part not the zero constant.
        let a = f.new_input(2, Address::new(r, 0x30));
        let b = f.new_const(2, 5);
        let pc2 = f.new_op(OpCode::Piece, seq, vec![a, b]);
        let _po2 = f.new_output(pc2, 4, Address::new(r, 0x38));
        assert_eq!(RuleConcatZero.apply_op(pc2, &mut f), 0);
    }

    #[test]
    fn concat_left_shift_refactors_to_nested_concat() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // concat(V, zext(W) << 16) => concat(concat(V,W), 0), when zext(W)<<16 top-justifies W.
        let vv = f.new_input(2, Address::new(r, 0x10)); // V
        let ww = f.new_input(2, Address::new(r, 0x18)); // W
        let ze = f.new_op(OpCode::IntZext, seq, vec![ww]);
        let zeo = f.new_output(ze, 4, Address::new(r, 0x20)); // zext(W), 4 bytes
        let c16 = f.new_const(4, 16); // 16 bits = 2 bytes; 2 + |W|(2) == 4 = |zext(W)|
        let shl = f.new_op(OpCode::IntLeft, seq, vec![zeo, c16]);
        let shlo = f.new_output(shl, 4, Address::new(r, 0x28));
        let pc = f.new_op(OpCode::Piece, seq, vec![vv, shlo]);
        let _po = f.new_output(pc, 6, Address::new(r, 0x30));
        assert_eq!(RuleConcatLeftShift.apply_op(pc, &mut f), 1);
        assert_eq!(f.op(pc).code(), OpCode::Piece);
        let inner = f.op(pc).input(0).unwrap();
        let idef = f.vn(inner).def.unwrap();
        assert_eq!(f.op(idef).code(), OpCode::Piece);
        assert_eq!(f.op(idef).input(0).unwrap(), vv);
        assert_eq!(f.op(idef).input(1).unwrap(), ww);
        assert_eq!(f.vn(inner).size, 4); // |V|+|W|
        let lo = f.op(pc).input(1).unwrap();
        assert!(f.vn(lo).is_constant() && f.vn(lo).constant_value() == 0 && f.vn(lo).size == 2);
    }

    #[test]
    fn double_sub_collapses_chained_subpiece() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // sub(sub(V, 2), 1) => sub(V, 3).
        let v = f.new_input(8, Address::new(r, 0x10));
        let c2 = f.new_const(4, 2);
        let inner = f.new_op(OpCode::Subpiece, seq, vec![v, c2]);
        let innero = f.new_output(inner, 4, Address::new(r, 0x18));
        let c1 = f.new_const(4, 1);
        let outer = f.new_op(OpCode::Subpiece, seq, vec![innero, c1]);
        let _o = f.new_output(outer, 2, Address::new(r, 0x20));
        assert_eq!(RuleDoubleSub.apply_op(outer, &mut f), 1);
        assert_eq!(f.op(outer).input(0).unwrap(), v);
        let off = f.op(outer).input(1).unwrap();
        assert!(f.vn(off).is_constant() && f.vn(off).constant_value() == 3);
    }

    #[test]
    fn double_shift_combines_cancels_saturates() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // Same direction: (V << 2) << 3 => V << 5.
        let v = f.new_input(4, Address::new(r, 0x10));
        let c2 = f.new_const(4, 2);
        let inner = f.new_op(OpCode::IntLeft, seq, vec![v, c2]);
        let innero = f.new_output(inner, 4, Address::new(r, 0x18));
        let c3 = f.new_const(4, 3);
        let outer = f.new_op(OpCode::IntLeft, seq, vec![innero, c3]);
        let _o = f.new_output(outer, 4, Address::new(r, 0x20));
        assert_eq!(RuleDoubleShift.apply_op(outer, &mut f), 1);
        assert_eq!(f.op(outer).code(), OpCode::IntLeft);
        assert_eq!(f.op(outer).input(0).unwrap(), v);
        assert_eq!(f.vn(f.op(outer).input(1).unwrap()).constant_value(), 5);

        // Opposite equal shifts: (V << 3) >> 3 => V & 0x1fffffff.
        let v2 = f.new_input(4, Address::new(r, 0x30));
        let c3b = f.new_const(4, 3);
        let l = f.new_op(OpCode::IntLeft, seq, vec![v2, c3b]);
        let lo = f.new_output(l, 4, Address::new(r, 0x38));
        let c3c = f.new_const(4, 3);
        let rgt = f.new_op(OpCode::IntRight, seq, vec![lo, c3c]);
        let _ro = f.new_output(rgt, 4, Address::new(r, 0x40));
        assert_eq!(RuleDoubleShift.apply_op(rgt, &mut f), 1);
        assert_eq!(f.op(rgt).code(), OpCode::IntAnd);
        assert_eq!(f.op(rgt).input(0).unwrap(), v2);
        assert_eq!(f.vn(f.op(rgt).input(1).unwrap()).constant_value(), 0x1fff_ffff);

        // Same direction shifting the whole word out: (V << 20) << 20 => COPY 0.
        let v3 = f.new_input(4, Address::new(r, 0x50));
        let c20 = f.new_const(4, 20);
        let s1 = f.new_op(OpCode::IntLeft, seq, vec![v3, c20]);
        let s1o = f.new_output(s1, 4, Address::new(r, 0x58));
        let c20b = f.new_const(4, 20);
        let s2 = f.new_op(OpCode::IntLeft, seq, vec![s1o, c20b]);
        let _s2o = f.new_output(s2, 4, Address::new(r, 0x60));
        assert_eq!(RuleDoubleShift.apply_op(s2, &mut f), 1);
        assert_eq!(f.op(s2).code(), OpCode::Copy);
        assert_eq!(f.vn(f.op(s2).input(0).unwrap()).constant_value(), 0);
    }

    #[test]
    fn double_arith_shift_saturates_signed() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // (x s>> 2) s>> 3 => x s>> 5.
        let x = f.new_input(4, Address::new(r, 0x10));
        let c2 = f.new_const(4, 2);
        let inner = f.new_op(OpCode::IntSright, seq, vec![x, c2]);
        let innero = f.new_output(inner, 4, Address::new(r, 0x18));
        let c3 = f.new_const(4, 3);
        let outer = f.new_op(OpCode::IntSright, seq, vec![innero, c3]);
        let _o = f.new_output(outer, 4, Address::new(r, 0x20));
        assert_eq!(RuleDoubleArithShift.apply_op(outer, &mut f), 1);
        assert_eq!(f.op(outer).input(0).unwrap(), x);
        assert_eq!(f.vn(f.op(outer).input(1).unwrap()).constant_value(), 5);

        // Saturates at |out|*8 - 1 = 31 for a 4-byte result: (x s>> 20) s>> 20 => x s>> 31.
        let y = f.new_input(4, Address::new(r, 0x30));
        let c20 = f.new_const(4, 20);
        let s1 = f.new_op(OpCode::IntSright, seq, vec![y, c20]);
        let s1o = f.new_output(s1, 4, Address::new(r, 0x38));
        let c20b = f.new_const(4, 20);
        let s2 = f.new_op(OpCode::IntSright, seq, vec![s1o, c20b]);
        let _s2o = f.new_output(s2, 4, Address::new(r, 0x40));
        assert_eq!(RuleDoubleArithShift.apply_op(s2, &mut f), 1);
        assert_eq!(f.vn(f.op(s2).input(1).unwrap()).constant_value(), 31);
    }

    #[test]
    fn concat_shift_cancels_least_part() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // Exact cancel: concat(V, W) >> 16 => zext(V)  (|W| = 2 bytes = 16 bits).
        let v = f.new_input(2, Address::new(r, 0x10));
        let w = f.new_input(2, Address::new(r, 0x18));
        let pc = f.new_op(OpCode::Piece, seq, vec![v, w]);
        let pco = f.new_output(pc, 4, Address::new(r, 0x20));
        let c16 = f.new_const(4, 16);
        let sh = f.new_op(OpCode::IntRight, seq, vec![pco, c16]);
        let _o = f.new_output(sh, 4, Address::new(r, 0x28));
        assert_eq!(RuleConcatShift.apply_op(sh, &mut f), 1);
        assert_eq!(f.op(sh).code(), OpCode::IntZext);
        assert_eq!(f.op(sh).inrefs.len(), 1);
        assert_eq!(f.op(sh).input(0).unwrap(), v);

        // Residual: concat(V, W) >> 24 => zext(V) >> 8.
        let v2 = f.new_input(2, Address::new(r, 0x30));
        let w2 = f.new_input(2, Address::new(r, 0x38));
        let pc2 = f.new_op(OpCode::Piece, seq, vec![v2, w2]);
        let pc2o = f.new_output(pc2, 4, Address::new(r, 0x40));
        let c24 = f.new_const(4, 24);
        let sh2 = f.new_op(OpCode::IntRight, seq, vec![pc2o, c24]);
        let _o2 = f.new_output(sh2, 4, Address::new(r, 0x48));
        assert_eq!(RuleConcatShift.apply_op(sh2, &mut f), 1);
        assert_eq!(f.op(sh2).code(), OpCode::IntRight);
        assert_eq!(f.vn(f.op(sh2).input(1).unwrap()).constant_value(), 8);
        let ext = f.op(sh2).input(0).unwrap();
        assert_eq!(f.op(f.vn(ext).def.unwrap()).code(), OpCode::IntZext);
        assert_eq!(f.op(f.vn(ext).def.unwrap()).input(0).unwrap(), v2);

        // Signed shift extends via SEXT: concat(V, W) s>> 16 => sext(V).
        let v3 = f.new_input(2, Address::new(r, 0x50));
        let w3 = f.new_input(2, Address::new(r, 0x58));
        let pc3 = f.new_op(OpCode::Piece, seq, vec![v3, w3]);
        let pc3o = f.new_output(pc3, 4, Address::new(r, 0x60));
        let c16b = f.new_const(4, 16);
        let sh3 = f.new_op(OpCode::IntSright, seq, vec![pc3o, c16b]);
        let _o3 = f.new_output(sh3, 4, Address::new(r, 0x68));
        assert_eq!(RuleConcatShift.apply_op(sh3, &mut f), 1);
        assert_eq!(f.op(sh3).code(), OpCode::IntSext);
        assert_eq!(f.op(sh3).input(0).unwrap(), v3);

        // No fire: shift smaller than the least part (8 < 16) keeps some of W.
        let v4 = f.new_input(2, Address::new(r, 0x70));
        let w4 = f.new_input(2, Address::new(r, 0x78));
        let pc4 = f.new_op(OpCode::Piece, seq, vec![v4, w4]);
        let pc4o = f.new_output(pc4, 4, Address::new(r, 0x80));
        let c8 = f.new_const(4, 8);
        let sh4 = f.new_op(OpCode::IntRight, seq, vec![pc4o, c8]);
        let _o4 = f.new_output(sh4, 4, Address::new(r, 0x88));
        assert_eq!(RuleConcatShift.apply_op(sh4, &mut f), 0);
        assert_eq!(f.op(sh4).code(), OpCode::IntRight);
    }

    #[test]
    fn sign_form_normalizes_sext_subpiece() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // sub(sext(V), 4) => V s>> 31  (V is 4 bytes; the SUBPIECE takes the sign-extension bytes).
        let v = f.new_input(4, Address::new(r, 0x10));
        let sx = f.new_op(OpCode::IntSext, seq, vec![v]);
        let sxo = f.new_output(sx, 8, Address::new(r, 0x18));
        let c4 = f.new_const(4, 4);
        let sub = f.new_op(OpCode::Subpiece, seq, vec![sxo, c4]);
        let _o = f.new_output(sub, 4, Address::new(r, 0x20));
        assert_eq!(RuleSignForm.apply_op(sub, &mut f), 1);
        assert_eq!(f.op(sub).code(), OpCode::IntSright);
        assert_eq!(f.op(sub).input(0).unwrap(), v);
        assert_eq!(f.vn(f.op(sub).input(1).unwrap()).constant_value(), 31);

        // No fire: SUBPIECE offset below V's width still lands inside V, not the sign extension.
        let v2 = f.new_input(4, Address::new(r, 0x30));
        let sx2 = f.new_op(OpCode::IntSext, seq, vec![v2]);
        let sx2o = f.new_output(sx2, 8, Address::new(r, 0x38));
        let c2 = f.new_const(4, 2);
        let sub2 = f.new_op(OpCode::Subpiece, seq, vec![sx2o, c2]);
        let _o2 = f.new_output(sub2, 4, Address::new(r, 0x40));
        assert_eq!(RuleSignForm.apply_op(sub2, &mut f), 0);
        assert_eq!(f.op(sub2).code(), OpCode::Subpiece);
    }

    #[test]
    fn trivial_bool_folds_constant_operand() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let mut addr = 0x10u64;
        // Build `V <bop> const` and return the op id.
        let mut mk = |f: &mut Funcdata, bop: OpCode, k: u64| -> (VarnodeId, OpId) {
            let v = f.new_input(1, Address::new(r, addr));
            let c = f.new_const(1, k);
            let o = f.new_op(bop, seq, vec![v, c]);
            f.new_output(o, 1, Address::new(r, addr + 8));
            addr += 0x10;
            (v, o)
        };

        // V && false => false (COPY 0);  V && true => V.
        let (_v, o) = mk(&mut f, OpCode::BoolAnd, 0);
        assert_eq!(RuleTrivialBool.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::Copy);
        assert!(f.vn(f.op(o).input(0).unwrap()).is_constant() && f.vn(f.op(o).input(0).unwrap()).constant_value() == 0);
        let (v, o) = mk(&mut f, OpCode::BoolAnd, 1);
        assert_eq!(RuleTrivialBool.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::Copy);
        assert_eq!(f.op(o).input(0).unwrap(), v);

        // V || false => V;  V || true => true (COPY 1).
        let (v, o) = mk(&mut f, OpCode::BoolOr, 0);
        assert_eq!(RuleTrivialBool.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::Copy);
        assert_eq!(f.op(o).input(0).unwrap(), v);
        let (_v, o) = mk(&mut f, OpCode::BoolOr, 1);
        assert_eq!(RuleTrivialBool.apply_op(o, &mut f), 1);
        assert!(f.vn(f.op(o).input(0).unwrap()).is_constant() && f.vn(f.op(o).input(0).unwrap()).constant_value() == 1);

        // V ^^ true => !V (BOOL_NEGATE);  V ^^ false => V.
        let (v, o) = mk(&mut f, OpCode::BoolXor, 1);
        assert_eq!(RuleTrivialBool.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::BoolNegate);
        assert_eq!(f.op(o).input(0).unwrap(), v);
        let (v, o) = mk(&mut f, OpCode::BoolXor, 0);
        assert_eq!(RuleTrivialBool.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::Copy);
        assert_eq!(f.op(o).input(0).unwrap(), v);
    }

    #[test]
    fn less2zero_folds_extremal_constants() {
        let (mut f, _) = fd();
        let r = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let mut a = 0x10u64;
        let mut less = |f: &mut Funcdata, l: Option<u64>, rr: Option<u64>| -> OpId {
            let lv = match l {
                Some(k) => f.new_const(4, k),
                None => f.new_input(4, Address::new(r, a)),
            };
            let rv = match rr {
                Some(k) => f.new_const(4, k),
                None => f.new_input(4, Address::new(r, a + 8)),
            };
            let o = f.new_op(OpCode::IntLess, seq, vec![lv, rv]);
            f.new_output(o, 1, Address::new(r, a + 0x10));
            a += 0x20;
            o
        };
        let max = 0xffff_ffffu64;

        // 0 < V  =>  0 != V
        let o = less(&mut f, Some(0), None);
        assert_eq!(RuleLess2Zero.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::IntNotequal);

        // max < V  =>  false
        let o = less(&mut f, Some(max), None);
        assert_eq!(RuleLess2Zero.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::Copy);
        assert!(f.vn(f.op(o).input(0).unwrap()).is_constant() && f.vn(f.op(o).input(0).unwrap()).constant_value() == 0);

        // V < 0  =>  false
        let o = less(&mut f, None, Some(0));
        assert_eq!(RuleLess2Zero.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::Copy);
        assert!(f.vn(f.op(o).input(0).unwrap()).is_constant() && f.vn(f.op(o).input(0).unwrap()).constant_value() == 0);

        // V < max  =>  V != max
        let o = less(&mut f, None, Some(max));
        assert_eq!(RuleLess2Zero.apply_op(o, &mut f), 1);
        assert_eq!(f.op(o).code(), OpCode::IntNotequal);

        // V < 5  =>  no fire
        let o = less(&mut f, None, Some(5));
        assert_eq!(RuleLess2Zero.apply_op(o, &mut f), 0);
        assert_eq!(f.op(o).code(), OpCode::IntLess);
    }
}
