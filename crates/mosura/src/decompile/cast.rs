//! Cast decisions — a port of Ghidra's `CastStrategyC` (`cast.cc`). After type inference
//! ([`super::infertypes`]) settles each value's type, an op still *requires* a particular type of
//! each operand; where the value's type and the required type disagree in a way C would not
//! silently reconcile, a `(type)` cast must be rendered. [`cast_standard`] is that decision —
//! Ghidra's `castStandard`, the generic rule shared by almost every op's `getInputCast`.
//!
//! Ghidra realises casts as inserted `CPUI_CAST` ops (`ActionSetCasts`); mosura's [`super::printc`]
//! applies the same decision at render time (as it already does for SUBPIECE/SEXT casts), so this
//! module is just the decision, not an IR pass. Ported for the primitive lattice; typedef/enum/
//! struct/variable-length refinements are deferred with the aggregate types they concern.

use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::types::{type_order, Datatype};

/// Ghidra `TypeOp::getInputCast` for op `op`'s input `slot`: the type the operand must be cast to,
/// or `None` if its committed type already satisfies the op. Reads the in-pipeline committed
/// `Varnode::ty` (authoritative after Stage 0's final `ActionInferTypes`), so it works both at
/// render time (printc) and as the `ActionSetCasts` insertion decision. The op-specific arms mirror
/// the `getInputCast` overrides (comparisons force signedness, shifts carry the shift's sign, SEXT
/// wants a signed input, div/rem force their sign, and the base arithmetic/logic default casts a
/// pointer/float fed to an integral op); everything else is transparent.
pub fn input_cast(f: &Funcdata, op: OpId, slot: usize) -> Option<Datatype> {
    let o = f.op(op);
    let in_vn = o.input(slot)?;
    let cur = f.vn(in_vn).get_type();
    let sz = f.vn(in_vn).size;
    match o.code() {
        OpCode::IntSless | OpCode::IntSlessequal => cast_standard(&Datatype::Int(sz), &cur, true, true),
        OpCode::IntLess | OpCode::IntLessequal => cast_standard(&Datatype::Uint(sz), &cur, true, false),
        OpCode::IntSext => cast_standard(&Datatype::Int(sz), &cur, true, false),
        OpCode::IntSdiv | OpCode::IntSrem => cast_standard(&Datatype::Int(sz), &cur, true, true),
        OpCode::IntDiv | OpCode::IntRem => cast_standard(&Datatype::Uint(sz), &cur, true, true),
        OpCode::IntEqual | OpCode::IntNotequal => {
            let t0 = f.vn(o.input(0)?).get_type();
            let t1 = f.vn(o.input(1)?).get_type();
            let req = if type_order(&t1, &t0) == std::cmp::Ordering::Less { t1 } else { t0 };
            cast_standard(&req, &cur, false, false)
        }
        OpCode::IntRight if slot == 0 => cast_standard(&Datatype::Uint(sz), &cur, true, true),
        OpCode::IntSright if slot == 0 => cast_standard(&Datatype::Int(sz), &cur, true, true),
        OpCode::IntAnd | OpCode::IntOr | OpCode::IntXor | OpCode::IntNegate => {
            cast_standard(&Datatype::Uint(sz), &cur, false, true)
        }
        OpCode::IntSub | OpCode::IntMult | OpCode::Int2comp => {
            cast_standard(&Datatype::Int(sz), &cur, false, true)
        }
        _ => None,
    }
}

/// Ghidra `CastStrategyC::arithmeticOutputStandard` (cast.cc): the "natural" C type an arithmetic
/// op produces — the most specific ([`type_order`]) of its input read-facing types (a `bool` input
/// counts as an `int` of its width). This is the *token* type `ActionSetCasts::castOutput` compares
/// against the value's committed type: when propagation has relayed a pointer backward onto an
/// integer arithmetic result (the pointercmp `param_1 + 8` = int8 result flooded to `xunknown1 *`
/// by the loop phi), the token stays int and the committed type is the pointer, so a `CPUI_CAST`
/// splits them — the faithful mechanism that renders `(xunknown1 *)(param_1 + 8)`.
pub fn arithmetic_output_standard(f: &Funcdata, op: OpId) -> Datatype {
    let o = f.op(op);
    let mut res1 = f.vn(o.input(0).unwrap()).get_type();
    if matches!(res1, Datatype::Bool) {
        res1 = Datatype::Int(res1.size()); // treat boolean as if cast to an integer
    }
    for i in 1..o.num_inputs() {
        let res2 = f.vn(o.input(i).unwrap()).get_type();
        if matches!(res2, Datatype::Bool) {
            continue;
        }
        if type_order(&res2, &res1) == std::cmp::Ordering::Less {
            res1 = res2; // res2 is more specific
        }
    }
    res1
}

/// Ghidra `TypeOp::getOutputToken` (typeop.cc:282) and its overrides: the data-type an op's output
/// naturally has "as would be assigned by a C compiler parsing a grammar containing this op". Read
/// by [`super::setcasts`]'s `castOutput` and compared to the value's committed type; a mismatch
/// inserts a `CPUI_CAST` on the def side.
///
/// The ops whose token can differ from the committed type — the arithmetic/logic ops (their token
/// is [`arithmetic_output_standard`], recomputed from the *inputs* so it ignores a back-relayed
/// pointer), the shifts (input 0's type), `COPY` (its input's type — the assignment cast lever),
/// `LOAD` (the pointed-to type), and `PTRADD` (its base pointer) — are ported here. Every other op's
/// token equals its committed output type in the primitive lattice (Ghidra's base
/// `outputTypeLocal`, which inference already settled onto the output), so it needs no output cast;
/// the deferred output-cast cases (a pointer/float-returning `CALL`, `PTRSUB` `downChain`,
/// `SUBPIECE`/`PIECE` composite tokens) come with the aggregate lattice.
pub fn output_token(f: &Funcdata, op: OpId) -> Datatype {
    let o = f.op(op);
    let out = o.output.unwrap();
    match o.code() {
        // TypeOpCopy::getOutputToken — cast to the input's read-facing type (the E1010 assignment cast)
        OpCode::Copy => f.vn(o.input(0).unwrap()).get_type(),
        // arithmeticOutputStandard (typeop.cc:1175/1326/1388/1402/1416/1449/1482/1625)
        OpCode::IntAdd
        | OpCode::IntSub
        | OpCode::IntMult
        | OpCode::Int2comp
        | OpCode::IntNegate
        | OpCode::IntXor
        | OpCode::IntAnd
        | OpCode::IntOr => arithmetic_output_standard(f, op),
        // shifts: input 0's type, bool→int (typeop.cc:1518/1558/1608)
        OpCode::IntLeft | OpCode::IntRight | OpCode::IntSright => {
            let mut res1 = f.vn(o.input(0).unwrap()).get_type();
            if matches!(res1, Datatype::Bool) {
                res1 = Datatype::Int(res1.size());
            }
            res1
        }
        // TypeOpLoad::getOutputToken (typeop.cc:472): the pointer's pointee when it matches the
        // output size, else the output's own type (a cast will reconcile the size mismatch).
        OpCode::Load => {
            let ct = f.vn(o.input(1).unwrap()).get_type();
            if let Datatype::Pointer(_, pt) = &ct {
                if pt.size() == f.vn(out).size {
                    return (**pt).clone();
                }
            }
            f.vn(out).get_type()
        }
        // TypeOpPtradd::getOutputToken (typeop.cc:2244): cast to the base pointer's type
        OpCode::Ptradd => f.vn(o.input(0).unwrap()).get_type(),
        // base TypeOp::getOutputToken = outputTypeLocal: inference already settled this onto the
        // output, so token == committed → no cast (the deferred composite/call cases noted above).
        _ => f.vn(out).get_type(),
    }
}

/// Ghidra `CastStrategyC::castStandard`: the data-type `curtype` must be cast to so an op can
/// consume it as `reqtype`, or `None` if C needs no cast.
///
/// `care_uint_int` forces a cast across a signed/unsigned mismatch — set by the signed and
/// unsigned comparisons (so a `undefined`/`uint` value compared signed prints `(int)x`), cleared
/// for plain arithmetic (which reconciles int/uint silently). `care_ptr_uint` forces a cast
/// between a uint and a pointer of the same width.
pub fn cast_standard(
    reqtype: &Datatype,
    curtype: &Datatype,
    care_uint_int: bool,
    care_ptr_uint: bool,
) -> Option<Datatype> {
    use Datatype::*;
    if curtype == reqtype {
        return None; // types are equal, no cast required
    }
    if matches!(curtype, Void) {
        return Some(reqtype.clone()); // from `void` (a dereferenced void*) we must cast
    }
    // Descend through matching pointer levels; below the pointer, signedness always matters.
    let mut reqbase = reqtype;
    let mut curbase = curtype;
    let mut isptr = false;
    let mut care_uint_int = care_uint_int;
    while let (Pointer(_, rp), Pointer(_, cp)) = (reqbase, curbase) {
        reqbase = rp;
        curbase = cp;
        care_uint_int = true;
        isptr = true;
    }
    if reqbase == curbase {
        return None;
    }
    if matches!(reqbase, Void) || matches!(curbase, Void) {
        return None; // don't cast to or from a void pointer
    }
    if reqbase.size() != curbase.size() {
        return Some(reqtype.clone()); // always cast a change in size
    }
    match reqbase {
        Unknown(_) => None, // anything is acceptable as undefined
        Uint(_) => {
            let acceptable = if !care_uint_int {
                matches!(curbase, Unknown(_) | Int(_) | Uint(_) | Bool)
            } else {
                matches!(curbase, Uint(_) | Bool) || (isptr && matches!(curbase, Unknown(_)))
            };
            if acceptable {
                return None;
            }
            if !care_ptr_uint && matches!(curbase, Pointer(..)) {
                return None;
            }
            Some(reqtype.clone())
        }
        Int(_) => {
            let acceptable = if !care_uint_int {
                matches!(curbase, Unknown(_) | Int(_) | Uint(_) | Bool)
            } else {
                matches!(curbase, Int(_) | Bool) || (isptr && matches!(curbase, Unknown(_)))
            };
            if acceptable {
                None
            } else {
                Some(reqtype.clone())
            }
        }
        // bool / float / pointer required: a differing same-size type always casts
        _ => Some(reqtype.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_compare_casts_undefined_and_uint_but_not_int() {
        // INT_SLESS requires int (care_uint_int=true): undefined4 and uint4 operands cast.
        assert_eq!(
            cast_standard(&Datatype::Int(4), &Datatype::Unknown(4), true, true),
            Some(Datatype::Int(4))
        );
        assert_eq!(
            cast_standard(&Datatype::Int(4), &Datatype::Uint(4), true, true),
            Some(Datatype::Int(4))
        );
        // an already-signed operand needs no cast
        assert_eq!(cast_standard(&Datatype::Int(4), &Datatype::Int(4), true, true), None);
    }

    #[test]
    fn arithmetic_reconciles_signedness_silently() {
        // care_uint_int=false: int/uint/undefined are mutually acceptable, no cast.
        assert_eq!(cast_standard(&Datatype::Int(4), &Datatype::Unknown(4), false, true), None);
        assert_eq!(cast_standard(&Datatype::Int(4), &Datatype::Uint(4), false, true), None);
        assert_eq!(cast_standard(&Datatype::Uint(4), &Datatype::Int(4), false, true), None);
    }

    #[test]
    fn size_change_always_casts_and_float_int_casts() {
        assert_eq!(
            cast_standard(&Datatype::Int(8), &Datatype::Int(4), false, true),
            Some(Datatype::Int(8))
        );
        // an int op fed a float value casts (float ∉ the int-acceptable set)
        assert_eq!(
            cast_standard(&Datatype::Int(4), &Datatype::Float(4), false, true),
            Some(Datatype::Int(4))
        );
    }
}
