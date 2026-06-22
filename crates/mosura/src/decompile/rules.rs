//! Simplification rules — ports of Ghidra's `ruleaction.cc` `Rule`s, applied to a fixpoint
//! by an [`ActionPool`](super::action::ActionPool). This is the start of P2; more rules
//! slot in the same way Ghidra's pool grows.

use super::action::Rule;
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;

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
}
