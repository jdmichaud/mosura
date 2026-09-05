//! Cast decisions — a port of Ghidra's `CastStrategyC` (`cast.cc`). After type inference
//! ([`super::infertypes`]) settles each value's type, an op still *requires* a particular type of
//! each operand; where the value's type and the required type disagree in a way C would not
//! silently reconcile, a `(type)` cast must be rendered. [`cast_standard`] is that decision —
//! Ghidra's `castStandard`, the generic rule shared by almost every op's `getInputCast`.
//!
//! Ghidra realises casts as inserted `CPUI_CAST` ops (`ActionSetCasts`); mosura's [`super::printc`]
//! applies the same decision at render time (as it already does for SUBPIECE/SEXT casts), so this
//! module is just the decision, not an IR pass.
//!
//! ⚠️ The tail of this paragraph used to bundle four deferrals into one clause — "typedef/enum/
//! struct/variable-length refinements are deferred with the aggregate types they concern" — which
//! is the shape that let a sibling note in `setcasts.rs` survive being wrong about all four of ITS
//! items. Split, with what is actually true of each as of `9f1c577`:
//!
//!   - **typedef** — no `Datatype` variant. `castStandard`'s two `getTypedef()` descent loops
//!     (cast.cc) are unreachable and unported. Revival: a typedef variant.
//!   - **enum** — no `Datatype` variant. Ghidra treats an enum as TYPE_UINT/TYPE_INT in every
//!     `castStandard` branch, so its absence changes no decision today. Revival: an enum variant.
//!   - **struct** — ⚠️ **THE VARIANT IS NOT ABSENT, BUT IT IS UNINHABITED.** `Datatype::Struct(size,
//!     fields)` has existed since `154b022` (2026-06-25), so the original "no struct metatype" was
//!     false when written. But **nothing in the tree ever CONSTRUCTS one**: every occurrence across
//!     `types.rs`, `varmap.rs`, `ptrarith.rs`, `setcasts.rs` and this file is a consumer — a
//!     `matches!`, a match arm, a field read. Measured consequence: **0 of 37 corpus SUBPIECEs and
//!     0 of 1704 the subject SUBPIECEs have a struct-typed input.** So every `TypeStruct::*` port is inert
//!     until struct types are PRODUCED, not merely declarable. Union is absent outright.
//!   - **variable-length** — no `is_variable_length` anywhere in `decompile/`, so `castStandard`'s
//!     `isVariableLength() && isptr && hasSameVariableBase()` escape (cast.cc:336) is unported and
//!     a size change there always casts. Revival: the flag, with `hasSameVariableBase`.

use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::merge::high_type_read_facing;
use super::types::{type_order, Datatype};

/// Ghidra `TypeOp::getInputCast` for op `op`'s input `slot`: the type the operand must be cast to,
/// or `None` if its committed type already satisfies the op. Reads the in-pipeline committed
/// `Varnode::ty` (authoritative after Stage 0's final `ActionInferTypes`), so it works both at
/// render time (printc) and as the `ActionSetCasts` insertion decision. The op-specific arms mirror
/// the `getInputCast` overrides (comparisons force signedness, shifts carry the shift's sign, SEXT
/// wants a signed input, div/rem force their sign, and the integral logic ops require uint/int).
///
/// ⚠️ THE `_` ARM IS GHIDRA'S BASE `TypeOp::getInputCast` (typeop.cc:295), NOT "no cast". It used to
/// answer `None` — "everything else is transparent" — and that is the opposite of what Ghidra
/// asserts: a `TypeOp` uses the base unless it *declares* an override, and of the 25 that do, only
/// `TypeOpCpoolref`/`TypeOpNew` override it to "never needs casting" (typeop.hh:867/878). The
/// placeholder came in with the first cast commit (`79f5406`, which wired only the comparisons) and
/// was never a decision about the other ops. What it cost, measured READ-ONLY before it was changed:
/// **3 casts over the 79 x86-64 datatests and 693 over the subject's 1303 functions** — and every one of
/// the 693 is the same shape, a POINTER operand consumed by integer arithmetic and needing `(int4)`.
/// (To re-derive: make this arm `{ let r = super::infertypes::input_type_local(f, op, slot);
/// if let Some(c) = cast_standard(&r, &cur, false, true) { eprintln!("BASECAST {:?} slot={slot}
/// req={r:?} cur={cur:?} -> {c:?}", o.code()); } None }` and re-run the emit — it evaluates the
/// rule and prints without casting.) All three corpus specimens were checked against
/// `oracle/capture --c` (the C++ decompiler — the right oracle for a rendering question) and Ghidra
/// emits every one of them:
///   - `pointerrel`  `fStack_18 = (float4)piStack_10[-1] + fStack_18;`   FLOAT_ADD slot 0
///   - `partialsplit` `*(xunknown4 *)((int8)puVar3 + 8) = 0;`             INT_ADD   slot 0
///   - `stackstring`  `func_0x00101000((int8)&xStack_20 + 4);`            INT_ADD   slot 0
/// Ghidra `CastStrategy::IntPromotionCode` (cast.hh:48). C promotes sub-int integers to
/// `int` before arithmetic; these codes describe how an expression IS or WILL BE affected,
/// and the `checkIntPromotion*` predicates below decide when that promotion forces a cast
/// the plain type-reconciliation of [`cast_standard`] would not print. The measured stake
/// (the subject's `FUN_00048478`): `SEXT(x << 5)` with a 2-byte `x` must render
/// `(int4)(int2)(param_1 << 5)` — the `(int2)` re-truncation is what makes the C compute
/// the IR's 2-byte shift under ANSI promotion; without it the recompiled code promotes
/// FIRST (`MOVSX` before `SHL`) and both the bytes AND the value diverge.
pub const NO_PROMOTION: i32 = -1;
pub const UNKNOWN_PROMOTION: i32 = 0;
pub const UNSIGNED_EXTENSION: i32 = 1;
pub const SIGNED_EXTENSION: i32 = 2;
pub const EITHER_EXTENSION: i32 = 3;
// `CastStrategy::promoteSize` is `TypeFactory::getSizeOfInt` — per-target, read from
// [`Funcdata::size_of_int`]. It was a `const 4` here; see that method for why a constant is
// wrong on any target whose `int` is not 4 bytes (x86-16 among the vendored cspecs).

/// Ghidra `CastStrategyC::localExtensionType` (cast.cc:139): how the value would naturally
/// extend, judged from local properties only.
fn local_extension_type(f: &Funcdata, v: super::varnode::VarnodeId) -> i32 {
    let natural = match high_type_read_facing(f, v) {
        Datatype::Uint(_) | Datatype::Bool | Datatype::Unknown(_) => UNSIGNED_EXTENSION,
        Datatype::Int(_) | Datatype::Char => SIGNED_EXTENSION,
        _ => return UNKNOWN_PROMOTION,
    };
    let vn = f.vn(v);
    if vn.is_constant() {
        // high bit clear: the value reads the same under either extension
        if !signbit_negative(vn.constant_value(), vn.size) {
            return EITHER_EXTENSION;
        }
        return natural;
    }
    if vn.is_explicit() {
        return natural;
    }
    let Some(d) = vn.def else { return UNKNOWN_PROMOTION };
    let defop = f.op(d);
    if defop.is_bool_output() {
        return EITHER_EXTENSION;
    }
    match defop.code() {
        OpCode::Cast | OpCode::Load => natural,
        c if c == OpCode::Call || c == OpCode::Callind || c == OpCode::Callother => natural,
        OpCode::IntAnd => {
            // masking with a positive constant: extension-agnostic
            if let Some(m) = defop.input(1) {
                let mvn = f.vn(m);
                if mvn.is_constant() {
                    if !signbit_negative(mvn.constant_value(), mvn.size) {
                        return EITHER_EXTENSION;
                    }
                    return natural;
                }
            }
            UNKNOWN_PROMOTION
        }
        _ => UNKNOWN_PROMOTION,
    }
}

/// Ghidra `signbit_negative` (address.cc): the value's high bit, at its own width.
fn signbit_negative(val: u64, size: u32) -> bool {
    if size == 0 || size > 8 {
        return false;
    }
    (val >> (size * 8 - 1)) & 1 == 1
}

/// Ghidra `CastStrategyC::intPromotionType` (cast.cc:178): the promotion code of the whole
/// expression defining `v`, recursing one level through the defining op.
pub fn int_promotion_type(f: &Funcdata, v: super::varnode::VarnodeId) -> i32 {
    let vn = f.vn(v);
    if vn.size >= f.size_of_int() {
        return NO_PROMOTION;
    }
    if vn.is_constant() {
        return local_extension_type(f, v);
    }
    if vn.is_explicit() {
        return NO_PROMOTION;
    }
    let Some(d) = vn.def else { return UNKNOWN_PROMOTION };
    let o = f.op(d);
    let ext = |slot: usize| o.input(slot).map_or(UNKNOWN_PROMOTION, |x| local_extension_type(f, x));
    match o.code() {
        OpCode::IntAnd => {
            // either side provably zero-extending makes the AND zero-extended
            if ext(1) & UNSIGNED_EXTENSION != 0 || ext(0) & UNSIGNED_EXTENSION != 0 {
                return UNSIGNED_EXTENSION;
            }
            UNKNOWN_PROMOTION
        }
        OpCode::IntRight => {
            let val = ext(0);
            if val & UNSIGNED_EXTENSION != 0 {
                return val;
            }
            UNKNOWN_PROMOTION
        }
        OpCode::IntSright => {
            let val = ext(0);
            if val & SIGNED_EXTENSION != 0 {
                return val;
            }
            UNKNOWN_PROMOTION
        }
        OpCode::IntXor | OpCode::IntOr | OpCode::IntDiv | OpCode::IntRem => {
            if ext(0) & UNSIGNED_EXTENSION == 0 || ext(1) & UNSIGNED_EXTENSION == 0 {
                return UNKNOWN_PROMOTION;
            }
            UNSIGNED_EXTENSION
        }
        OpCode::IntSdiv | OpCode::IntSrem => {
            if ext(0) & SIGNED_EXTENSION == 0 || ext(1) & SIGNED_EXTENSION == 0 {
                return UNKNOWN_PROMOTION;
            }
            SIGNED_EXTENSION
        }
        OpCode::IntNegate | OpCode::Int2comp => {
            if ext(0) & SIGNED_EXTENSION != 0 {
                return SIGNED_EXTENSION;
            }
            UNKNOWN_PROMOTION
        }
        OpCode::IntAdd | OpCode::IntSub | OpCode::IntLeft | OpCode::IntMult => UNKNOWN_PROMOTION,
        _ => NO_PROMOTION,
    }
}

/// Ghidra `CastStrategyC::checkIntPromotionForCompare` (cast.cc:107).
fn check_int_promotion_for_compare(f: &Funcdata, op: OpId, slot: usize) -> bool {
    let o = f.op(op);
    let Some(vn) = o.input(slot) else { return false };
    let ext1 = int_promotion_type(f, vn);
    if ext1 == NO_PROMOTION {
        return false;
    }
    if ext1 == UNKNOWN_PROMOTION {
        return true; // promotion happens and we don't know its sign: cast required
    }
    let Some(other) = o.input(1 - slot) else { return false };
    let ext2 = int_promotion_type(f, other);
    if ext1 & ext2 != 0 {
        return false; // a shared extension: those bits are not the determining factor
    }
    if ext2 == NO_PROMOTION {
        return false; // both sides end up extended the same way
    }
    true
}

/// Ghidra `CastStrategyC::checkIntPromotionForExtension` (cast.cc:126).
fn check_int_promotion_for_extension(f: &Funcdata, op: OpId) -> bool {
    let o = f.op(op);
    let Some(vn) = o.input(0) else { return false };
    let ext = int_promotion_type(f, vn);
    if ext == NO_PROMOTION {
        return false;
    }
    if ext == UNKNOWN_PROMOTION {
        return true;
    }
    // an explicit extension matching the promotion's own sign is redundant
    if ext & UNSIGNED_EXTENSION != 0 && o.code() == OpCode::IntZext {
        return false;
    }
    if ext & SIGNED_EXTENSION != 0 && o.code() == OpCode::IntSext {
        return false;
    }
    true
}

pub fn input_cast(f: &Funcdata, op: OpId, slot: usize) -> Option<Datatype> {
    let o = f.op(op);
    let in_vn = o.input(slot)?;
    let cur = high_type_read_facing(f, in_vn);
    let sz = f.vn(in_vn).size;
    match o.code() {
        // The comparison/shift/divide arms consult the integer-promotion predicates FIRST —
        // Ghidra's per-op `getInputCast` overrides (typeop.cc:939/:1003/:1027..., :1550,
        // :1592, :1645-:1705) return the required type OUTRIGHT when promotion would change
        // the compared/extended/shifted value, forcing the truncating cast that
        // `cast_standard` alone would not print.
        OpCode::IntSless | OpCode::IntSlessequal => {
            if check_int_promotion_for_compare(f, op, slot) {
                return Some(Datatype::base_int(sz));
            }
            cast_standard(&Datatype::base_int(sz), &cur, true, true)
        }
        OpCode::IntLess | OpCode::IntLessequal => {
            if check_int_promotion_for_compare(f, op, slot) {
                return Some(Datatype::Uint(sz));
            }
            cast_standard(&Datatype::Uint(sz), &cur, true, false)
        }
        OpCode::IntSext => {
            if check_int_promotion_for_extension(f, op) {
                return Some(Datatype::base_int(sz));
            }
            cast_standard(&Datatype::base_int(sz), &cur, true, false)
        }
        OpCode::IntSdiv | OpCode::IntSrem => {
            let promo = int_promotion_type(f, in_vn);
            if promo != NO_PROMOTION && promo & SIGNED_EXTENSION == 0 {
                return Some(Datatype::base_int(sz));
            }
            cast_standard(&Datatype::base_int(sz), &cur, true, true)
        }
        OpCode::IntDiv | OpCode::IntRem => {
            let promo = int_promotion_type(f, in_vn);
            if promo != NO_PROMOTION && promo & UNSIGNED_EXTENSION == 0 {
                return Some(Datatype::Uint(sz));
            }
            cast_standard(&Datatype::Uint(sz), &cur, true, true)
        }
        OpCode::IntEqual | OpCode::IntNotequal => {
            let t0 = high_type_read_facing(f, o.input(0)?);
            let t1 = high_type_read_facing(f, o.input(1)?);
            let req = if type_order(&t1, &t0) == std::cmp::Ordering::Less { t1 } else { t0 };
            if check_int_promotion_for_compare(f, op, slot) {
                return Some(req);
            }
            cast_standard(&req, &cur, false, false)
        }
        OpCode::IntRight if slot == 0 => {
            let promo = int_promotion_type(f, in_vn);
            if promo != NO_PROMOTION && promo & UNSIGNED_EXTENSION == 0 {
                return Some(Datatype::Uint(sz));
            }
            cast_standard(&Datatype::Uint(sz), &cur, true, true)
        }
        OpCode::IntSright if slot == 0 => {
            let promo = int_promotion_type(f, in_vn);
            if promo != NO_PROMOTION && promo & SIGNED_EXTENSION == 0 {
                return Some(Datatype::base_int(sz));
            }
            cast_standard(&Datatype::base_int(sz), &cur, true, true)
        }
        OpCode::IntAnd | OpCode::IntOr | OpCode::IntXor | OpCode::IntNegate => {
            cast_standard(&Datatype::Uint(sz), &cur, false, true)
        }
        OpCode::IntSub | OpCode::IntMult | OpCode::Int2comp => {
            cast_standard(&Datatype::base_int(sz), &cur, false, true)
        }
        // ── Ghidra overrides `getInputCast` to "Never needs casting" (typeop.hh:867/878) ──
        OpCode::Cpoolref | OpCode::New => None,

        // ── Ghidra DOES declare a `getInputCast` override for these and it is NOT ported. They
        // must not fall through to the base arm: the base is not their rule, so applying it would
        // invent a behaviour rather than defer one. One line, one revival condition — port the
        // named override and delete the opcode from this arm.
        //   COPY          typeop.cc:397   (the assignment cast)
        //   LOAD / STORE  typeop.cc:440/520 (pointer-vs-pointee reconciliation)
        //   INT_ZEXT      typeop.cc:1131
        //   FLOAT_INT2FLOAT typeop.cc (TypeOpFloatInt2Float, typeop.hh:711)
        //   PIECE / SUBPIECE typeop.hh:779/794
        //   PTRADD / PTRSUB  typeop.hh:820/833  (deferred with their refits, see setcasts.rs)
        //   SEGMENTOP     typeop.hh:854
        OpCode::Copy
        | OpCode::Load
        | OpCode::Store
        | OpCode::IntZext
        | OpCode::FloatInt2float
        | OpCode::Piece
        | OpCode::Subpiece
        | OpCode::Ptradd
        | OpCode::Ptrsub
        | OpCode::Segmentop => None,

        // ── These DO use the base `getInputCast`, but they also override `getInputLocal`, and
        // mosura's [`super::infertypes::input_type_local`] does not model those overrides — it
        // answers the `TypeOp` default (`xunknown<size>`) for all of them. Feeding the base arm a
        // required type we know to be wrong would be an invention with a cast attached, so they are
        // held here instead. It is INERT today (an `xunknown` requirement casts nothing, so this arm
        // and the base arm agree on current output); it is listed so that fixing `op_meta` does not
        // silently switch these on. Revival condition: port the named `getInputLocal`, then move the
        // opcode down to the base arm.
        //   CBRANCH   typeop.cc:TypeOpCbranch::getInputLocal — slot 1 is BOOL, slot 0 a `code *`
        //   CALLIND   TypeOpCallind::getInputLocal — slot 0 is a `code *`
        //   CALLOTHER TypeOpCallother::getInputLocal — per-userop table, not modelled
        //   RETURN    TypeOpReturn::getInputLocal — the enclosing prototype's output type
        //   INDIRECT  TypeOpIndirect::getInputLocal — slot 1 is a `code *`
        //   INSERT / EXTRACT — Ghidra's metatypes are (UNKNOWN,INT) / (INT,INT) (typeop.cc), which
        //     `op_meta` lacks entirely; x86 never lifts either, so this is unmeasurable here.
        // (CALL is deliberately NOT in this list: `TypeOpCall::getInputLocal` returns a parameter
        // type only when that parameter is TYPE-LOCKED, and mosura models no type-locked call
        // prototypes, so its fallback to `TypeOp::getInputLocal` is the whole reachable behaviour —
        // the same argument already documented for `output_token`'s CALL arm.)
        // CALLIND is NOT here: `TypeOpCallind` declares `getInputLocal` but no `getInputCast`
        // (typeop.hh:326-332), so Ghidra uses the BASE `TypeOp::getInputCast` — cast whenever the
        // target's actual type differs from the `code *` local. Listing it here meant "no cast
        // ever", which is why printc had to hardcode one; now the cast appears only where the
        // type system asks for it.
        OpCode::Cbranch
        | OpCode::Callother
        | OpCode::Return
        | OpCode::Indirect
        | OpCode::Insert
        | OpCode::Extract => None,

        // ── the base `TypeOp::getInputCast` (typeop.cc:295) ──
        // INT_ADD, INT_LEFT, INT_SBORROW/SCARRY/CARRY, the FLOAT ops, BOOL ops, CALL, CAST and the
        // shifts' slot ≠ 0 (whose overrides delegate here explicitly, typeop.cc:1555/1597).
        _ => {
            // `if (vn->isAnnotation()) return (Datatype *)0;` (typeop.cc:298) — an annotation
            // carries no dataflow, so it never takes a cast. Ghidra tests this in the base only,
            // which is exactly this arm.
            if f.vn(in_vn).is_annotation() {
                return None;
            }
            cast_standard(&super::infertypes::input_type_local(f, op, slot), &cur, false, true)
        }
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
    let mut res1 = high_type_read_facing(f, o.input(0).unwrap());
    if matches!(res1, Datatype::Bool) {
        res1 = Datatype::base_int(res1.size()); // treat boolean as if cast to an integer
    }
    for i in 1..o.num_inputs() {
        let res2 = high_type_read_facing(f, o.input(i).unwrap());
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
/// `outputTypeLocal`, which inference already settled onto the output), so it needs no output cast.
///
/// ⚠️ THIS SENTENCE USED TO READ: "the deferred output-cast cases (a pointer/float-returning `CALL`,
/// `PTRSUB` `downChain`, `SUBPIECE`/`PIECE` composite tokens) come with the aggregate lattice."
/// **Two of its three items were already ported, in this very function**, and the sentence kept
/// being true-looking because examining any one item left it standing — the same bundling failure
/// as the four-item note in `setcasts.rs`, from the same commit (`c11f25e`). Split, one item per
/// line, each with its own status:
///
///   - `CALL` / `CALLIND` — **PORTED** (`d07680c`). See the arm below; it is what lets a call result
///     take a cast at all, and it needed no aggregate lattice.
///   - `SUBPIECE` / `PIECE` — **PORTED** (`844d5b1`, typeop.cc:2142/2063). Arms below.
///   - `PTRSUB` `downChain` — **genuinely still open**, and it is the only one of the three that was
///     ever about the aggregate lattice: `TypeOpPtrsub::getOutputToken` walks into a composite to
///     name the field being addressed, and there is no composite metatype here.
///     *Revival condition:* a struct/union metatype in [`Datatype`] makes this portable; until then
///     a `PTRSUB` output takes no cast. Note this is NOT the same question as the `ActionSetCasts`
///     PTRSUB **refit**, which is gated on the `ScopeLocal` symbol query instead — two different
///     PTRSUB deferrals with two different reasons, deliberately not bundled.
pub fn output_token(f: &Funcdata, op: OpId) -> Datatype {
    let o = f.op(op);
    let out = o.output.unwrap();
    match o.code() {
        // TypeOpCopy::getOutputToken — cast to the input's read-facing type (the E1010 assignment cast)
        OpCode::Copy => high_type_read_facing(f, o.input(0).unwrap()),
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
            let mut res1 = high_type_read_facing(f, o.input(0).unwrap());
            if matches!(res1, Datatype::Bool) {
                res1 = Datatype::base_int(res1.size());
            }
            res1
        }
        // TypeOpLoad::getOutputToken (typeop.cc:472): the pointer's pointee when it matches the
        // output size, else the output's own type (a cast will reconcile the size mismatch).
        OpCode::Load => {
            let ct = high_type_read_facing(f, o.input(1).unwrap());
            if let Datatype::Pointer(_, pt) = &ct {
                if pt.size() == f.vn(out).size {
                    return (**pt).clone();
                }
            }
            f.vn(out).get_type()
        }
        // TypeOpPtradd::getOutputToken (typeop.cc:2244): cast to the base pointer's type
        OpCode::Ptradd => high_type_read_facing(f, o.input(0).unwrap()),
        // TypeOpSubpiece::getOutputToken (typeop.cc:2142) — "SUBPIECE prints as cast to whatever its
        // output is": the token IS the output's own variable type, so `castOutput`'s
        // `tokenct == outHighType` short-circuit is satisfied and a SUBPIECE never takes an output
        // cast. Only an `unknown` output falls back, to `int` of the output's size.
        //
        // ⚠️ CORRECTION (additive — the original claim is kept so the error is legible). This read:
        // "The leading `findTruncation` arm ... is inapplicable: mosura's `Datatype` has no struct or
        // union metatype, so no truncation can ever be found. Deferred with the aggregate lattice."
        // **THE PREMISE WAS FALSE WHEN IT WAS WRITTEN.** `Datatype::Struct(size, fields)` landed in
        // `154b022` on 2026-06-25; this comment was written in `844d5b1` on 2026-07-27, a month
        // later, and `Datatype::Struct` is already consumed by ptrarith.rs, setcasts.rs and
        // varmap.rs. What is genuinely absent is UNION — there is no `Datatype::Union` variant.
        //
        // ⚠️ SECOND CORRECTION, AND IT IS OF THE FIRST ONE. The paragraph above went on to say "its
        // struct half rests on a lattice we have", and that was MY over-correction: it read the
        // EXISTENCE OF A VARIANT as the existence of a lattice. The census has now been run and the
        // answer is the opposite.
        //
        //   1. Does the struct path need union? **NO.** `TypeStruct::findTruncation` (type.cc:1624)
        //      is a pure field lookup — `getFieldIter` binary-searches the field containing the
        //      offset, then rejects when `newoff + sz` spans past that field's end. The union
        //      versions (`TypeUnion` :2185, `TypePartialUnion` :2440) are separate virtual overrides
        //      on separate classes. So the original "struct OR union" framing was wrong twice over.
        //   2. What is its reach? **ZERO.** 0 of 37 corpus SUBPIECEs and 0 of 1704 the subject SUBPIECEs
        //      have a struct-typed input 0.
        //   3. Why zero? **`Datatype::Struct` IS NEVER CONSTRUCTED.** Declared at types.rs:42 and
        //      read in five modules, but nothing anywhere builds one. The variant is UNINHABITED.
        //
        // So the deferral STANDS, now for a measured reason rather than a false one: porting
        // `findTruncation` would be inert. **Revival condition: something must PRODUCE a
        // `Datatype::Struct`** — struct type recovery, or a symbol table supplying composite types.
        // Re-check in one command: `grep -rn "Datatype::Struct(" src/decompile/` and look for a
        // constructor rather than a `matches!`/match-arm/field-read.
        //
        // The general lesson, which cost this session a wrong claim in two landed commits: **a
        // declared variant is not an inhabited lattice.** See AGENT.md.
        OpCode::Subpiece => {
            let dt = high_type_read_facing(f, out);
            if matches!(dt, Datatype::Unknown(_)) {
                Datatype::base_int(f.vn(out).size)
            } else {
                dt
            }
        }
        // TypeOpPiece::getOutputToken (typeop.cc:2063) — the same shape: "PIECE casts to uint or int,
        // based on output". The output's own variable type when it is integral, else `uint` of the
        // output's size (an unknown or pointer output).
        OpCode::Piece => {
            let dt = high_type_read_facing(f, out);
            if dt.is_int_meta() || matches!(dt, Datatype::Uint(_)) {
                dt
            } else {
                Datatype::Uint(f.vn(out).size)
            }
        }
        // `TypeOpCall`/`TypeOpCallind` have NO `getOutputToken` override, so their token is the base
        // `TypeOp::getOutputToken` = `PcodeOp::outputTypeLocal` = `TypeOpCall::getOutputLocal`
        // (typeop.cc:720, `TypeOpCallind` :776): the call prototype's return type when that prototype
        // is OUTPUT-LOCKED, otherwise `TypeOp::getOutputLocal` (:261) = `undefined<size>`. mosura
        // models no output-locked call prototypes, so only the unlocked arm is reachable and the
        // token is simply the op-local type.
        //
        // This is what lets a call result take a cast at all. `castOutput` compares the token with
        // the value's variable type, and `castStandard` accepts `undefined` where an int/uint is
        // required but not where a pointer or float is (cast.cc:339-391) — so an integral call result
        // stays bare while `pVar6 = func_0x0007803f();` becomes `pVar6 = (int4 *)func_0x0007803f();`,
        // as Ghidra renders it. the subject's FUN_000729cd fails E1010 on exactly this.
        //
        // CALLOTHER is deliberately NOT included: its Ghidra token consults the userop's own
        // `getOutputLocal` (typeop.cc:865), a per-userop table mosura does not model, so claiming
        // `undefined` for it would assert a model that has not been ported.
        OpCode::Call | OpCode::Callind => super::infertypes::output_type_local(f, op),
        // base TypeOp::getOutputToken = outputTypeLocal: inference already settled this onto the
        // output, so token == committed → no cast (the deferred composite cases noted above).
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
    // ⚠️ EVERY TEST BELOW IS A METATYPE TEST IN GHIDRA (`getMetatype()`), so it must go through
    // [`Datatype::is_int_meta`] rather than matching the `Int` variant. `char` is a `TYPE_INT`
    // (`TypeChar` is a `TypeBase(1,TYPE_INT,…)`, type.hh:356) but a separate mosura variant, so a
    // variant match silently drops it into the catch-all and casts where Ghidra does not. That is
    // what emitted `(char)(x == 0) * '\x02'` for Ghidra's `(x == 0) * '\x02'`: `reqbase` was `char`,
    // `curbase` was `bool`, and Ghidra's TYPE_INT arm returns "no cast" for a boolean (cast.cc:372).
    match reqbase {
        Unknown(_) => None, // anything is acceptable as undefined
        Uint(_) => {
            let acceptable = if !care_uint_int {
                curbase.is_int_meta() || matches!(curbase, Unknown(_) | Uint(_) | Bool)
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
        t if t.is_int_meta() => {
            let acceptable = if !care_uint_int {
                curbase.is_int_meta() || matches!(curbase, Unknown(_) | Uint(_) | Bool)
            } else {
                curbase.is_int_meta() || matches!(curbase, Bool) || (isptr && matches!(curbase, Unknown(_)))
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

    /// `char` is a TYPE_INT (type.hh:356), so every metatype test in `cast_standard` must accept it
    /// on BOTH sides. Matching the `Int` variant instead sent `char` to the catch-all and cast where
    /// Ghidra does not — the `(char)(x == 0) * '\x02'` on `orcompare`.
    #[test]
    fn char_is_type_int_on_both_sides() {
        // reqbase `char`, curbase `bool`: Ghidra's TYPE_INT arm returns no cast (cast.cc:372).
        assert_eq!(cast_standard(&Datatype::Char, &Datatype::Bool, true, true), None);
        assert_eq!(cast_standard(&Datatype::Char, &Datatype::Bool, false, true), None);
        // reqbase `char`, curbase a same-size signed int: still TYPE_INT vs TYPE_INT, no cast.
        assert_eq!(cast_standard(&Datatype::Char, &Datatype::Int(1), true, true), None);
        // curbase `char` where the requirement is TYPE_INT — the other direction of the same test.
        assert_eq!(cast_standard(&Datatype::Int(1), &Datatype::Char, true, true), None);
        // ... and where the requirement is TYPE_UINT, which cares: `char` is INT, so it DOES cast
        // when signedness matters and does not when it doesn't (cast.cc:345/354).
        assert_eq!(cast_standard(&Datatype::Uint(1), &Datatype::Char, false, true), None);
        assert_eq!(
            cast_standard(&Datatype::Uint(1), &Datatype::Char, true, true),
            Some(Datatype::Uint(1))
        );
        // A size change still always casts, char or not (cast.cc:337).
        assert_eq!(
            cast_standard(&Datatype::Int(4), &Datatype::Char, true, true),
            Some(Datatype::Int(4))
        );
    }

    /// The two shapes the base `TypeOp::getInputCast` (typeop.cc:295) newly reaches, as
    /// `castStandard` sees them. Both were verified end-to-end against `oracle/capture --c`:
    /// FLOAT_ADD on an `int4` load is `pointerrel`'s `(float4)piStack_10[-1]`, and INT_ADD on a
    /// pointer is `stackstring`'s `(int8)&xStack_20` — the single class behind all 693 the subject
    /// firings. `care_uint_int=false, care_ptr_uint=true` are the base's fixed arguments.
    #[test]
    fn base_input_cast_casts_pointer_to_int_and_int_to_float() {
        // FLOAT_ADD requires float; an int operand is not acceptable (the `_` arm, cast.cc:391).
        assert_eq!(
            cast_standard(&Datatype::Float(4), &Datatype::Int(4), false, true),
            Some(Datatype::Float(4))
        );
        // INT_ADD requires int; a same-size POINTER is not in the TYPE_INT acceptable set
        // (cast.cc:372 lists UNKNOWN/INT/UINT/BOOL only), so it casts.
        assert_eq!(
            cast_standard(&Datatype::base_int(8), &Datatype::Pointer(8, Box::new(Datatype::Unknown(8))), false, true),
            Some(Datatype::base_int(8))
        );
        // ...and the guard that keeps the other 3300+ pointer-free INT_ADDs bare: an int/uint/
        // undefined operand reconciles silently, so this arm did NOT flood the corpus with casts.
        assert_eq!(cast_standard(&Datatype::base_int(4), &Datatype::Uint(4), false, true), None);
        assert_eq!(cast_standard(&Datatype::base_int(4), &Datatype::Unknown(4), false, true), None);
        // An `xunknown` REQUIREMENT accepts anything — this is why the ops whose `getInputLocal`
        // override mosura does not model stay inert even though they reach the base rule.
        assert_eq!(
            cast_standard(&Datatype::Unknown(4), &Datatype::Pointer(4, Box::new(Datatype::Int(1))), false, true),
            None
        );
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
