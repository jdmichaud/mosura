//! Port of the `RuleOrPredicate` half of Ghidra's `condexe.cc` — the rule that recognizes a
//! short-circuit `||` written as two conditionally-zeroed values OR'd together, plus the
//! `MultiPredicate` helper it uses to describe each half.
//!
//! `ActionConditionalExecution` (the other, larger half of condexe.cc) is still unported; this file
//! is deliberately just the rule and its helper. The heavy lifting the rule depends on —
//! `BooleanMatch::evaluate`, which decides whether two conditions are the same, complementary, or
//! uncorrelated — already lives in [`super::expression`], ported for `RuleOrCompare`.

use super::block::BlockId;
use super::dominator::Dominators;
use super::expression::{self, BooleanMatch};
use super::funcdata::Funcdata;
use super::op::{OpId, SeqNum};
use super::opcode::OpCode;
use super::varnode::VarnodeId;

/// Ghidra `BooleanExpressionMatch` (expression.hh:96): are the conditions of two CBRANCHes
/// correlated, and if so, are they anti-correlated? A thin wrapper over
/// [`expression::evaluate`](super::expression::evaluate) that folds each CBRANCH's `boolean_flip`
/// into the answer.
///
/// Ghidra's `maxDepth` is 1 (expression.cc:218) — one level of BOOL_AND/BOOL_OR/BOOL_XOR structure
/// is compared, no deeper. `getMultiSlot()` is a hardcoded `-1` in this class (expression.hh:101),
/// so the caller's `getMultiSlot() != -1` test can never reject; it is kept at the call site as a
/// comment rather than as dead code.
struct BooleanExpressionMatch {
    /// Ghidra `matchflip`: the compared CBRANCH keys on the opposite boolean value of the root.
    match_flip: bool,
}

impl BooleanExpressionMatch {
    const MAX_DEPTH: i32 = 1;

    /// Ghidra `BooleanExpressionMatch::verifyCondition` (expression.cc:220).
    fn verify_condition(data: &Funcdata, op: OpId, iop: OpId) -> Option<Self> {
        let (Some(a), Some(b)) = (data.op(op).input(1), data.op(iop).input(1)) else {
            return None;
        };
        let res = expression::evaluate(data, a, b, Self::MAX_DEPTH);
        if res == BooleanMatch::Uncorrelated {
            return None;
        }
        let mut match_flip = res == BooleanMatch::Complementary;
        if data.op(op).is_boolean_flip() {
            match_flip = !match_flip;
        }
        if data.op(iop).is_boolean_flip() {
            match_flip = !match_flip;
        }
        Some(BooleanExpressionMatch { match_flip })
    }
}

/// Ghidra `RuleOrPredicate::MultiPredicate` (ruleaction.hh): one half of the `||` pattern — a
/// 2-input MULTIEQUAL where one incoming path supplies a literal zero and the other supplies a real
/// value, together with the CBRANCH that chose between them.
#[derive(Default)]
struct MultiPredicate {
    /// The MULTIEQUAL itself.
    op: Option<OpId>,
    /// Which of its two slots carries the zero.
    zero_slot: usize,
    /// The value arriving on the other path.
    other_vn: Option<VarnodeId>,
    /// The incoming block that supplies the zero.
    zero_block: Option<BlockId>,
    /// The conditional block that chose between the two paths.
    cond_block: Option<BlockId>,
    /// That block's CBRANCH.
    cbranch: Option<OpId>,
    /// Whether the CBRANCH's *true* edge is the one that sets zero.
    zero_path_is_true: bool,
}

impl MultiPredicate {
    /// Ghidra `discoverZeroSlot` (condexe.cc:509): is `vn` produced by a 2-branch MULTIEQUAL, one
    /// side of which is a COPY of the constant zero?
    fn discover_zero_slot(&mut self, data: &Funcdata, vn: VarnodeId) -> bool {
        if !data.vn(vn).is_written() {
            return false;
        }
        let op = data.vn(vn).def.unwrap();
        self.op = Some(op);
        if data.op(op).code() != OpCode::Multiequal || data.op(op).num_inputs() != 2 {
            return false;
        }
        for zero_slot in 0..2 {
            let Some(tmpvn) = data.op(op).input(zero_slot) else { continue };
            if !data.vn(tmpvn).is_written() {
                continue;
            }
            let copyop = data.vn(tmpvn).def.unwrap();
            if data.op(copyop).code() != OpCode::Copy {
                continue; // MULTIEQUAL must have a COPY input
            }
            let Some(zerovn) = data.op(copyop).input(0) else { continue };
            if !data.vn(zerovn).is_constant() || data.vn(zerovn).constant_value() != 0 {
                continue; // which copies #0
            }
            let Some(other) = data.op(op).input(1 - zero_slot) else { continue };
            if data.vn(other).is_free() {
                return false;
            }
            self.zero_slot = zero_slot;
            self.other_vn = Some(other); // store off the varnode from the other path
            return true;
        }
        false
    }

    /// Ghidra `discoverCbranch` (condexe.cc:539): find the single CBRANCH whose two out-edges
    /// correspond to the MULTIEQUAL's two in-edges — the branch that decides whether zero flows in.
    fn discover_cbranch(&mut self, data: &Funcdata) -> bool {
        let op = self.op.expect("discoverZeroSlot ran first");
        let Some(base_block) = data.op(op).parent else { return false };
        let ins = &data.block(base_block).in_edges;
        if ins.len() != 2 {
            return false;
        }
        let zero_block = ins[self.zero_slot];
        let other_block = ins[1 - self.zero_slot];
        self.zero_block = Some(zero_block);
        let cond_block = match data.block(zero_block).out_edges.len() {
            1 => {
                if data.block(zero_block).in_edges.len() != 1 {
                    return false;
                }
                data.block(zero_block).in_edges[0]
            }
            2 => zero_block,
            _ => return false,
        };
        if data.block(cond_block).out_edges.len() != 2 {
            return false;
        }
        match data.block(other_block).out_edges.len() {
            1 => {
                if data.block(other_block).in_edges.len() != 1
                    || cond_block != data.block(other_block).in_edges[0]
                {
                    return false;
                }
            }
            2 => {
                if cond_block != other_block {
                    return false;
                }
            }
            _ => return false,
        }
        self.cond_block = Some(cond_block);
        let Some(&cbranch) = data.block(cond_block).ops.last() else { return false };
        if data.op(cbranch).code() != OpCode::Cbranch {
            return false;
        }
        self.cbranch = Some(cbranch);
        true
    }

    /// Ghidra `discoverPathIsTrue` (condexe.cc:572): does the condition block's *true* edge flow to
    /// the block that sets zero? Ghidra's edge convention is `getFalseOut() == getOut(0)` and
    /// `getTrueOut() == getOut(1)` (block.hh:299).
    fn discover_path_is_true(&mut self, data: &Funcdata) {
        let cond_block = self.cond_block.expect("discoverCbranch ran first");
        let zero_block = self.zero_block.expect("discoverCbranch ran first");
        let outs = &data.block(cond_block).out_edges;
        let true_out = outs.get(1).copied();
        let false_out = outs.first().copied();
        self.zero_path_is_true = if true_out == Some(zero_block) {
            true
        } else if false_out == Some(zero_block) {
            false
        } else {
            // condBlock must BE zeroBlock: true if the "true" path does not override the zero set.
            let parent = self.op.and_then(|o| data.op(o).parent);
            true_out == parent
        };
    }

    /// Ghidra `discoverConditionalZero` (condexe.cc:590): verify the CBRANCH's condition is exactly
    /// `vn == 0` or `vn != 0`, and normalize [`zero_path_is_true`](Self::zero_path_is_true) so that
    /// `true` means "a zero `vn` sends execution to where the MULTIEQUAL is set to zero".
    fn discover_conditional_zero(&mut self, data: &Funcdata, vn: VarnodeId) -> bool {
        let cbranch = self.cbranch.expect("discoverCbranch ran first");
        let Some(boolvn) = data.op(cbranch).input(1) else { return false };
        if !data.vn(boolvn).is_written() {
            return false;
        }
        let compareop = data.vn(boolvn).def.unwrap();
        match data.op(compareop).code() {
            OpCode::IntNotequal => self.zero_path_is_true = !self.zero_path_is_true,
            OpCode::IntEqual => {}
            _ => return false,
        }
        let (Some(a1), Some(a2)) = (data.op(compareop).input(0), data.op(compareop).input(1)) else {
            return false;
        };
        // Verify one side of the compare is vn ...
        let zerovn = if a1 == vn {
            a2
        } else if a2 == vn {
            a1
        } else {
            return false;
        };
        // ... and the other is the constant zero.
        if !data.vn(zerovn).is_constant() || data.vn(zerovn).constant_value() != 0 {
            return false;
        }
        if data.op(cbranch).is_boolean_flip() {
            self.zero_path_is_true = !self.zero_path_is_true;
        }
        true
    }
}

/// Ghidra `PcodeOp::compareOrder` (op.cc:397): which of two ops happens first — within a block by
/// sequence order, across blocks by dominance. Returns `-1` if `op` is first, `1` if `bop` is,
/// `0` if neither dominates the other.
fn compare_order(data: &Funcdata, dom: &Dominators, op: OpId, bop: OpId) -> i32 {
    let (pa, pb) = (data.op(op).parent, data.op(bop).parent);
    if pa == pb {
        let (sa, sb) = (data.op(op).seqnum, data.op(bop).seqnum);
        let key = |s: SeqNum| (s.pc.offset, s.uniq);
        return if key(sa) < key(sb) { -1 } else { 1 };
    }
    let (Some(pa), Some(pb)) = (pa, pb) else { return 0 };
    let common =
        super::condconst::find_common_block(dom, &[pa.0 as usize, pb.0 as usize]);
    if common == pa.0 as usize {
        return -1;
    }
    if common == pb.0 as usize {
        return 1;
    }
    0
}

/// Ghidra `RuleOrPredicate` (condexe.cc:617, oppool1 slot :5631): recover a short-circuit `||` from
/// the conditionally-zeroed form a compiler emits for it.
///
/// ```text
///   tmp1 = cond ? val1 : 0;
///   tmp2 = cond ? 0 : val2;
///   res  = tmp1 | tmp2;          =>   res = cond ? val1 : val2
/// ```
///
/// Each operand of the OR is described by a [`MultiPredicate`]. Both must be zeroed on *different*
/// paths — either off the same CBRANCH taking different edges, or off two CBRANCHes whose
/// conditions [`BooleanExpressionMatch`] proves are complementary — after which the OR collapses to
/// a single MULTIEQUAL merging the two real values, and becomes a COPY of it.
///
/// The `checkSingle` variant handles the case where only one operand has the MULTIEQUAL form: then
/// the other operand must itself be the value being tested against zero, and the MULTIEQUAL simply
/// takes it on the zero path.
pub struct RuleOrPredicate;

impl RuleOrPredicate {
    /// Ghidra `RuleOrPredicate::checkSingle` (condexe.cc:638): the alternate form
    /// `tmp1 = (val2 == 0) ? val1 : 0; result = tmp1 | val2`, where `other` plays the role of
    /// `val2` — so the zero path can simply take `other` instead.
    fn check_single(
        data: &mut Funcdata,
        vn: VarnodeId,
        branch: &mut MultiPredicate,
        op: OpId,
    ) -> u32 {
        if data.vn(vn).is_free() {
            return 0;
        }
        if !branch.discover_cbranch(data) {
            return 0;
        }
        let multi = branch.op.unwrap();
        let Some(multi_out) = data.op(multi).output else { return 0 };
        // Must be only one use of the MULTIEQUAL, because we rewrite it.
        if data.lone_descend(multi_out) != Some(op) {
            return 0;
        }
        branch.discover_path_is_true(data);
        if !branch.discover_conditional_zero(data, vn) {
            return 0;
        }
        if branch.zero_path_is_true {
            return 0; // the true condition (vn == 0) must not go to the zero set
        }
        data.op_set_input(multi, branch.zero_slot, vn);
        data.op_remove_input(op, 1);
        data.op_set_opcode(op, OpCode::Copy);
        data.op_set_input(op, 0, multi_out);
        1
    }
}

impl super::action::Rule for RuleOrPredicate {
    fn name(&self) -> &str {
        "orpredicate"
    }
    fn oplist(&self) -> Vec<OpCode> {
        vec![OpCode::IntOr, OpCode::IntXor]
    }
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
        let (Some(in0), Some(in1)) = (data.op(op).input(0), data.op(op).input(1)) else {
            return 0;
        };
        let mut branch0 = MultiPredicate::default();
        let mut branch1 = MultiPredicate::default();
        let test0 = branch0.discover_zero_slot(data, in0);
        let test1 = branch1.discover_zero_slot(data, in1);
        if !test0 && !test1 {
            return 0;
        }
        if !test0 {
            // branch1 has the MULTIEQUAL form, branch0 does not.
            return Self::check_single(data, in0, &mut branch1, op);
        }
        if !test1 {
            return Self::check_single(data, in1, &mut branch0, op);
        }
        if !branch0.discover_cbranch(data) || !branch1.discover_cbranch(data) {
            return 0;
        }
        if branch0.cond_block == branch1.cond_block {
            if branch0.zero_block == branch1.zero_block {
                return 0; // the zero sets must be along different paths
            }
        } else {
            // Different CBRANCHes: they must share the condition, and the two zero sets must sit on
            // complementary paths.
            let (Some(cb0), Some(cb1)) = (branch0.cbranch, branch1.cbranch) else { return 0 };
            let Some(condmarker) = BooleanExpressionMatch::verify_condition(data, cb0, cb1) else {
                return 0;
            };
            // Ghidra also tests `condmarker.getMultiSlot() != -1`, which this class hardcodes to
            // -1 (expression.hh:101), so the test can never reject.
            branch0.discover_path_is_true(data);
            branch1.discover_path_is_true(data);
            let mut final_bool = branch0.zero_path_is_true == branch1.zero_path_is_true;
            if condmarker.match_flip {
                final_bool = !final_bool;
            }
            if final_bool {
                return 0; // one path hits both zero sets; they must be on different paths
            }
        }
        let (Some(op0), Some(op1)) = (branch0.op, branch1.op) else { return 0 };
        let dom = super::dominator::compute(data);
        let order = compare_order(data, &dom, op0, op1);
        if order == 0 {
            return 0; // can this happen?
        }
        // True if the non-zero setting of branch0 flows through slot 0.
        let (final_block, slot0_sets_branch0) = if order < 0 {
            // branch1 happens after
            (data.op(op1).parent, branch1.zero_slot == 0)
        } else {
            (data.op(op0).parent, branch0.zero_slot == 1)
        };
        let Some(final_block) = final_block else { return 0 };
        let (Some(other0), Some(other1)) = (branch0.other_vn, branch1.other_vn) else {
            return 0;
        };
        let inputs =
            if slot0_sets_branch0 { vec![other0, other1] } else { vec![other1, other0] };
        let pc = data.op(op).seqnum.pc;
        let uniq = data.num_ops() as u32;
        let new_multi = data.new_op(OpCode::Multiequal, SeqNum { pc, uniq }, inputs);
        let size = data.vn(other0).size;
        let newvn = data.new_output_unique(new_multi, size);
        data.op_insert_begin(new_multi, final_block);
        data.op_remove_input(op, 1);
        data.op_set_input(op, 0, newvn);
        data.op_set_opcode(op, OpCode::Copy);
        1
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::action::Rule;
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::BlockBasic;

    fn fd() -> (Funcdata, Address) {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        (Funcdata::new("t", Address::new(ram, 0), spaces), Address::new(ram, 0))
    }

    /// The shape RuleOrPredicate folds — one condition, each value zeroed on the opposite path:
    ///
    /// ```text
    ///        b0: if (c == 0) ...        out_edges [b1 (false), b2 (true)]
    ///   b1: a = val1 ; z1 = 0     b2: z2 = 0 ; b = val2
    ///        b3: m0 = MULTIEQUAL(val1, #0)      <- zero on the b2 path
    ///            m1 = MULTIEQUAL(#0, val2)      <- zero on the b1 path
    ///            res = m0 | m1
    /// ```
    fn or_predicate_shape() -> (Funcdata, OpId, VarnodeId, VarnodeId) {
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        // b0: the condition `c == 0`.
        let c = f.new_input(4, Address::new(reg, 0x8));
        let zero4 = f.new_const(4, 0);
        let cmp = f.new_op(OpCode::IntEqual, seq(0), vec![c, zero4]);
        let cond = f.new_output_unique(cmp, 1);
        let dest = f.new_const(8, 0x100);
        let cbr = f.new_op(OpCode::Cbranch, seq(1), vec![dest, cond]);
        // b1: the real value for branch0, and the zero for branch1.
        let val1 = f.new_input(4, Address::new(reg, 0x10));
        let cp_v1 = f.new_op(OpCode::Copy, seq(2), vec![val1]);
        let v1 = f.new_output_unique(cp_v1, 4);
        let k0a = f.new_const(4, 0);
        let cp_z1 = f.new_op(OpCode::Copy, seq(3), vec![k0a]);
        let z1 = f.new_output_unique(cp_z1, 4);
        // b2: the zero for branch0, and the real value for branch1.
        let k0b = f.new_const(4, 0);
        let cp_z0 = f.new_op(OpCode::Copy, seq(4), vec![k0b]);
        let z0 = f.new_output_unique(cp_z0, 4);
        let val2 = f.new_input(4, Address::new(reg, 0x18));
        let cp_v2 = f.new_op(OpCode::Copy, seq(5), vec![val2]);
        let v2 = f.new_output_unique(cp_v2, 4);
        // b3: the two MULTIEQUALs and the OR. Input order follows in_edges [b1, b2].
        let m0 = f.new_op(OpCode::Multiequal, seq(6), vec![v1, z0]);
        let m0_out = f.new_output_unique(m0, 4);
        let m1 = f.new_op(OpCode::Multiequal, seq(7), vec![z1, v2]);
        let m1_out = f.new_output_unique(m1, 4);
        let or = f.new_op(OpCode::IntOr, seq(8), vec![m0_out, m1_out]);
        f.new_output_unique(or, 4);
        let blocks = vec![
            BlockBasic {
                ops: vec![cmp, cbr],
                in_edges: vec![],
                out_edges: vec![BlockId(1), BlockId(2)],
            },
            BlockBasic {
                ops: vec![cp_v1, cp_z1],
                in_edges: vec![BlockId(0)],
                out_edges: vec![BlockId(3)],
            },
            BlockBasic {
                ops: vec![cp_z0, cp_v2],
                in_edges: vec![BlockId(0)],
                out_edges: vec![BlockId(3)],
            },
            BlockBasic {
                ops: vec![m0, m1, or],
                in_edges: vec![BlockId(1), BlockId(2)],
                out_edges: vec![],
            },
        ];
        for (bi, blk) in blocks.iter().enumerate() {
            for &opid in &blk.ops {
                f.op_mut(opid).parent = Some(BlockId(bi as u32));
            }
        }
        f.set_blocks(blocks);
        (f, or, v1, v2)
    }

    #[test]
    fn or_predicate_folds_two_conditional_zeros() {
        // Both halves are zeroed on opposite paths of one CBRANCH, so the OR collapses to a COPY
        // of a single MULTIEQUAL merging the two real values (condexe.cc:654).
        let (mut f, or, v1, v2) = or_predicate_shape();
        assert_eq!(RuleOrPredicate.apply_op(or, &mut f), 1);
        assert_eq!(f.op(or).code(), OpCode::Copy);
        assert_eq!(f.op(or).num_inputs(), 1);
        let merged = f.op(or).input(0).unwrap();
        let multi = f.vn(merged).def.unwrap();
        assert_eq!(f.op(multi).code(), OpCode::Multiequal);
        assert_eq!(f.op(multi).num_inputs(), 2);
        let ins: Vec<_> = (0..2).map(|i| f.op(multi).input(i).unwrap()).collect();
        assert!(ins.contains(&v1) && ins.contains(&v2), "merges the two real values, not the zeros");
    }

    #[test]
    fn or_predicate_declines_when_both_zeros_share_a_path() {
        // Both MULTIEQUALs take their zero from the SAME incoming edge, so one path hits both zero
        // sets and the result is not a `||` — Ghidra's "zero sets must be along different paths".
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let c = f.new_input(4, Address::new(reg, 0x8));
        let zero4 = f.new_const(4, 0);
        let cmp = f.new_op(OpCode::IntEqual, seq(0), vec![c, zero4]);
        let cond = f.new_output_unique(cmp, 1);
        let dest = f.new_const(8, 0x100);
        let cbr = f.new_op(OpCode::Cbranch, seq(1), vec![dest, cond]);
        // b1 carries BOTH real values ...
        let val1 = f.new_input(4, Address::new(reg, 0x10));
        let cp_v1 = f.new_op(OpCode::Copy, seq(2), vec![val1]);
        let v1 = f.new_output_unique(cp_v1, 4);
        let val2 = f.new_input(4, Address::new(reg, 0x18));
        let cp_v2 = f.new_op(OpCode::Copy, seq(3), vec![val2]);
        let v2 = f.new_output_unique(cp_v2, 4);
        // ... and b2 carries BOTH zeros.
        let k0a = f.new_const(4, 0);
        let cp_z0 = f.new_op(OpCode::Copy, seq(4), vec![k0a]);
        let z0 = f.new_output_unique(cp_z0, 4);
        let k0b = f.new_const(4, 0);
        let cp_z1 = f.new_op(OpCode::Copy, seq(5), vec![k0b]);
        let z1 = f.new_output_unique(cp_z1, 4);
        let m0 = f.new_op(OpCode::Multiequal, seq(6), vec![v1, z0]);
        let m0_out = f.new_output_unique(m0, 4);
        let m1 = f.new_op(OpCode::Multiequal, seq(7), vec![v2, z1]);
        let m1_out = f.new_output_unique(m1, 4);
        let or = f.new_op(OpCode::IntOr, seq(8), vec![m0_out, m1_out]);
        f.new_output_unique(or, 4);
        let blocks = vec![
            BlockBasic {
                ops: vec![cmp, cbr],
                in_edges: vec![],
                out_edges: vec![BlockId(1), BlockId(2)],
            },
            BlockBasic {
                ops: vec![cp_v1, cp_v2],
                in_edges: vec![BlockId(0)],
                out_edges: vec![BlockId(3)],
            },
            BlockBasic {
                ops: vec![cp_z0, cp_z1],
                in_edges: vec![BlockId(0)],
                out_edges: vec![BlockId(3)],
            },
            BlockBasic {
                ops: vec![m0, m1, or],
                in_edges: vec![BlockId(1), BlockId(2)],
                out_edges: vec![],
            },
        ];
        for (bi, blk) in blocks.iter().enumerate() {
            for &opid in &blk.ops {
                f.op_mut(opid).parent = Some(BlockId(bi as u32));
            }
        }
        f.set_blocks(blocks);
        assert_eq!(RuleOrPredicate.apply_op(or, &mut f), 0);
        assert_eq!(f.op(or).code(), OpCode::IntOr);
    }

    #[test]
    fn or_predicate_declines_without_a_zero_arm() {
        // Neither operand is a conditionally-zeroed MULTIEQUAL.
        let (mut f, ram) = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let seq = |u: u32| SeqNum { pc: ram, uniq: u };
        let a = f.new_input(4, Address::new(reg, 0x10));
        let b = f.new_input(4, Address::new(reg, 0x18));
        let or = f.new_op(OpCode::IntOr, seq(0), vec![a, b]);
        f.new_output_unique(or, 4);
        f.set_blocks(vec![BlockBasic { ops: vec![or], ..Default::default() }]);
        f.op_mut(or).parent = Some(BlockId(0));
        assert_eq!(RuleOrPredicate.apply_op(or, &mut f), 0);
    }
}
