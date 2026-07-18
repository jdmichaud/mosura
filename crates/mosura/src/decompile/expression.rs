//! Port of Ghidra's `expression.cc` — the `BooleanMatch` classifier: static methods for
//! determining if two boolean expressions are the *same* or *complementary*.

use super::funcdata::Funcdata;
use super::nzmask::signbit_negative;
use super::op::OpId;
use super::opcode::{get_booleanflip, OpCode};
use super::varnode::VarnodeId;

/// Ghidra `BooleanMatch` correlation classes (expression.hh:84).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BooleanMatch {
    /// Pair always hold the same value
    Same,
    /// Pair always hold complementary values
    Complementary,
    /// Pair values are uncorrelated
    Uncorrelated,
}

/// Ghidra `BooleanMatch::varnodeSame` (expression.cc:93): do the given Varnodes hold the same
/// value, possibly as constants.
fn varnode_same(data: &Funcdata, a: VarnodeId, b: VarnodeId) -> bool {
    if a == b {
        return true;
    }
    if data.vn(a).is_constant() && data.vn(b).is_constant() {
        return data.vn(a).constant_value() == data.vn(b).constant_value();
    }
    false
}

/// Ghidra `BooleanMatch::sameOpComplement` (expression.cc:57): test if two operations with the
/// same opcode produce complementary boolean values. This only tests for cases where the opcode
/// is INT_LESS or INT_SLESS and one of the inputs is constant (the scenario `x < 9` vs `8 < x`).
fn same_op_complement(data: &Funcdata, bin1op: OpId, bin2op: OpId) -> bool {
    let opcode = data.op(bin1op).code();
    if opcode == OpCode::IntSless || opcode == OpCode::IntLess {
        let mut constslot = 0;
        if data.vn(data.op(bin1op).input(1).unwrap()).is_constant() {
            constslot = 1;
        }
        if !data.vn(data.op(bin1op).input(constslot).unwrap()).is_constant() {
            return false;
        }
        if !data.vn(data.op(bin2op).input(1 - constslot).unwrap()).is_constant() {
            return false;
        }
        if !varnode_same(
            data,
            data.op(bin1op).input(1 - constslot).unwrap(),
            data.op(bin2op).input(constslot).unwrap(),
        ) {
            return false;
        }
        let mut val1 = data.vn(data.op(bin1op).input(constslot).unwrap()).constant_value();
        let mut val2 = data.vn(data.op(bin2op).input(1 - constslot).unwrap()).constant_value();
        if constslot != 0 {
            std::mem::swap(&mut val1, &mut val2);
        }
        if val1.wrapping_add(1) != val2 {
            return false;
        }
        if val2 == 0 && opcode == OpCode::IntLess {
            return false; // Corner case for unsigned
        }
        if opcode == OpCode::IntSless {
            // Corner case for signed
            let sz = data.vn(data.op(bin1op).input(constslot).unwrap()).size;
            if signbit_negative(val2, sz) && !signbit_negative(val1, sz) {
                return false;
            }
        }
        return true;
    }
    false
}

/// Ghidra `BooleanMatch::evaluate` (expression.cc:111): determine if two boolean Varnodes hold
/// related values. The values may be the *same*, or opposite of each other (*complementary*);
/// otherwise the values are *uncorrelated*. The trees constructing each Varnode are examined up
/// to a maximum `depth`; if this is exceeded *uncorrelated* is returned.
pub(crate) fn evaluate(data: &Funcdata, vn1: VarnodeId, vn2: VarnodeId, depth: i32) -> BooleanMatch {
    if vn1 == vn2 {
        return BooleanMatch::Same;
    }
    let op1: Option<OpId>;
    let opc1: Option<OpCode>;
    if data.vn(vn1).is_written() {
        let o = data.vn(vn1).def.unwrap();
        let c = data.op(o).code();
        if c == OpCode::BoolNegate {
            let res = evaluate(data, data.op(o).input(0).unwrap(), vn2, depth);
            // Flip same <-> complementary result
            return match res {
                BooleanMatch::Same => BooleanMatch::Complementary,
                BooleanMatch::Complementary => BooleanMatch::Same,
                BooleanMatch::Uncorrelated => BooleanMatch::Uncorrelated,
            };
        }
        op1 = Some(o);
        opc1 = Some(c);
    } else {
        op1 = None; // Don't give up before checking if op2 is BOOL_NEGATE
        opc1 = None; // Ghidra: CPUI_MAX
    }
    let op2: OpId;
    let opc2: OpCode;
    if data.vn(vn2).is_written() {
        let o = data.vn(vn2).def.unwrap();
        let c = data.op(o).code();
        if c == OpCode::BoolNegate {
            let res = evaluate(data, vn1, data.op(o).input(0).unwrap(), depth);
            // Flip same <-> complementary result
            return match res {
                BooleanMatch::Same => BooleanMatch::Complementary,
                BooleanMatch::Complementary => BooleanMatch::Same,
                BooleanMatch::Uncorrelated => BooleanMatch::Uncorrelated,
            };
        }
        op2 = o;
        opc2 = c;
    } else {
        return BooleanMatch::Uncorrelated;
    }
    let Some(op1) = op1 else {
        return BooleanMatch::Uncorrelated;
    };
    let opc1 = opc1.unwrap();
    if !data.op(op1).is_bool_output() || !data.op(op2).is_bool_output() {
        return BooleanMatch::Uncorrelated;
    }
    if depth != 0
        && (opc1 == OpCode::BoolAnd || opc1 == OpCode::BoolOr || opc1 == OpCode::BoolXor)
    {
        if (opc2 == OpCode::BoolAnd || opc2 == OpCode::BoolOr || opc2 == OpCode::BoolXor)
            && (opc1 == opc2
                || (opc1 == OpCode::BoolAnd && opc2 == OpCode::BoolOr)
                || (opc1 == OpCode::BoolOr && opc2 == OpCode::BoolAnd))
            {
                let mut pair1 = evaluate(
                    data,
                    data.op(op1).input(0).unwrap(),
                    data.op(op2).input(0).unwrap(),
                    depth - 1,
                );
                let pair2: BooleanMatch;
                if pair1 == BooleanMatch::Uncorrelated {
                    // Try other possible pairing (commutative op)
                    pair1 = evaluate(
                        data,
                        data.op(op1).input(0).unwrap(),
                        data.op(op2).input(1).unwrap(),
                        depth - 1,
                    );
                    if pair1 == BooleanMatch::Uncorrelated {
                        return BooleanMatch::Uncorrelated;
                    }
                    pair2 = evaluate(
                        data,
                        data.op(op1).input(1).unwrap(),
                        data.op(op2).input(0).unwrap(),
                        depth - 1,
                    );
                } else {
                    pair2 = evaluate(
                        data,
                        data.op(op1).input(1).unwrap(),
                        data.op(op2).input(1).unwrap(),
                        depth - 1,
                    );
                }
                if pair2 == BooleanMatch::Uncorrelated {
                    return BooleanMatch::Uncorrelated;
                }
                if opc1 == opc2 {
                    if pair1 == BooleanMatch::Same && pair2 == BooleanMatch::Same {
                        return BooleanMatch::Same;
                    } else if opc1 == OpCode::BoolXor {
                        if pair1 == BooleanMatch::Complementary
                            && pair2 == BooleanMatch::Complementary
                        {
                            return BooleanMatch::Same;
                        }
                        return BooleanMatch::Complementary;
                    }
                } else {
                    // Must be CPUI_BOOL_AND and CPUI_BOOL_OR
                    if pair1 == BooleanMatch::Complementary && pair2 == BooleanMatch::Complementary
                    {
                        return BooleanMatch::Complementary; // De Morgan's Law
                    }
                }
            }
    } else {
        // Two boolean output ops, compare them directly
        if opc1 == opc2 {
            let mut same_op = true;
            let num_inputs = data.op(op1).num_inputs();
            for i in 0..num_inputs {
                if !varnode_same(
                    data,
                    data.op(op1).input(i).unwrap(),
                    data.op(op2).input(i).unwrap(),
                ) {
                    same_op = false;
                    break;
                }
            }
            if same_op {
                return BooleanMatch::Same;
            }
            if same_op_complement(data, op1, op2) {
                return BooleanMatch::Complementary;
            }
            return BooleanMatch::Uncorrelated;
        }
        // Check if the binary ops are complements of one another
        let slot1 = 0;
        let mut slot2 = 0;
        let Some((flipped, reorder)) = get_booleanflip(opc2) else {
            return BooleanMatch::Uncorrelated;
        };
        if opc1 != flipped {
            return BooleanMatch::Uncorrelated;
        }
        if reorder {
            slot2 = 1;
        }
        if !varnode_same(
            data,
            data.op(op1).input(slot1).unwrap(),
            data.op(op2).input(slot2).unwrap(),
        ) {
            return BooleanMatch::Uncorrelated;
        }
        if !varnode_same(
            data,
            data.op(op1).input(1 - slot1).unwrap(),
            data.op(op2).input(1 - slot2).unwrap(),
        ) {
            return BooleanMatch::Uncorrelated;
        }
        return BooleanMatch::Complementary;
    }
    BooleanMatch::Uncorrelated
}
