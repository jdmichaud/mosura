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

use super::types::Datatype;

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
