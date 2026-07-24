# Decompiler bug report: pointer/float fed to an integral op is not cast (FIXED)

**Owner: decompiler track (`master`). Status: FIXED** (this commit). Surfaced by the WAR2
recompilation-parity survey (docs/war2-function-status.md) as the E1079/E1080/E1036 COMPILE_FAIL
classes. Class **(A) GENERAL** per the differential-triage methodology (task #4): compiler-independent,
proven with a gcc reproducer against full-analysis Ghidra.

## Symptom

The emitted C for many WAR2 functions used a pointer-typed (or float-typed) value directly as an
operand of an integral C operator, which `wcc386` rejects:

```
E1079: Expression must be integral       e.g.  uVar4 = pVar2 & -4;      (pointer in bitwise &)
E1080: Expression must be arithmetic     e.g.  uVar6 = -param_4;        (negation of a pointer)
E1036: Right operand of '-' is a pointer e.g.  x = *p - p;              (pointer subtracted)
```

Survey counts @ `b4ac8f4`/`04d0165`: E1079 ×33, E1080 ×12, E1036 ×3.

## Root cause — the generic arithmetic/logical ops never asked for an input cast

`PrintC::get_input_cast` (`src/decompile/printc.rs`) is mosura's render-time port of Ghidra's
`TypeOp::getInputCast`. It wired only the ops that *override* `getInputCast` in Ghidra
(comparisons, SEXT, the divides/remainders, equality, the right shifts) and let **every other op
fall through to `None`** — with a comment claiming arithmetic/logic ops "effectively never cast in
the primitive lattice." That is true for the int/uint/undefined primitives, but **wrong for a
pointer or float operand**: Ghidra's *base* `TypeOp::getInputCast` (which those ops inherit) casts
them.

```
Datatype *TypeOp::getInputCast(const PcodeOp *op,int4 slot,const CastStrategy *castStrategy) const {
  Datatype *reqtype = op->inputTypeLocal(slot);
  Datatype *curtype = vn->getHighTypeReadFacing(op);
  return castStrategy->castStandard(reqtype,curtype,false,true);   // care_uint_int=false, care_ptr_uint=TRUE
}
```

`care_ptr_uint=true` is exactly what forces the cast of a same-width pointer to the required
integral type. The ops that hit this base default (they do **not** override `getInputCast` in
`typeop.hh`) include `INT_AND`/`INT_OR`/`INT_XOR`/`INT_NEGATE` (input metatype `TYPE_UINT`) and
`INT_ADD`/`INT_SUB`/`INT_MULT`/`INT_2COMP`/`INT_LEFT` (input metatype `TYPE_INT`) — metatypes read
straight from the `TypeOpBinary`/`TypeOpUnary` constructors in `typeop.cc`.

## Differential grounding (instrument-first, class-A GENERAL)

A gcc-x86-64 reproducer (`scratchpad/repro/gtype.c`) with the three shapes, decompiled by mosura and
by full-analysis Ghidra (`analyzeHeadless`) on the **identical binary**:

| shape | Ghidra | mosura (pre-fix) | mosura (post-fix) |
|---|---|---|---|
| `p` deref'd then masked | `(ulong)((uint)param_1 & 0xf) + *param_1` | `(param_1 & 0xfU) + *param_1` | `((uint8)param_1 & 0xf) + *param_1` |
| `*p - (long)p` | `*param_1 - (long)param_1` | `*param_1 - param_1` | `*param_1 - (int8)param_1` |

Ghidra inserts the cast; mosura did not. The fix makes mosura insert it (the residual `(uint)` vs
`(uint8)` width difference is an x86-64 8-byte-pointer subpiece detail; for WAR2's 32-bit pointers
both render `(uint)`). Compiler-independent → fixed in the general path, not scoped to Watcom.

## The fix

Add the base-`getInputCast` default to `get_input_cast` for the non-overriding arithmetic/logical
ops: `cast_standard(reqtype, cur, false, true)` with `reqtype = Uint(sz)` for the logical ops and
`Int(sz)` for the arithmetic ones. Transparent for the primitive lattice (int/uint/undefined
reconcile silently, so no corpus churn); casts pointer/float operands as Ghidra does.

Brick 1 lands the pointer-arith set most directly tied to the WAR2 classes: `INT_AND`, `INT_OR`,
`INT_XOR`, `INT_NEGATE`, `INT_SUB`, `INT_MULT`, `INT_2COMP`. `INT_ADD`/`INT_LEFT` are held for a
separate measurement (INT_ADD interacts with PTRADD conversion and is very common; staged to isolate
any corpus effect).

## Corpus / verification

- Corpus avg 0.9513 → 0.9516; only `impliedfield` moved (0.938 → 0.954, toward-oracle: mosura now
  emits `(int4)fVar1 * param_1`, the float→int cast Ghidra also emits). 59 fixtures byte-identical,
  zero regressions.
- Suite 559/0 (+ the new `pointer_in_integral_op_is_cast` regression), clippy 0.

## WAR2 re-measure (clean-vs-clean, same methodology)

Full survey EMIT + wcc386 (dosemu2) + wardiff over all 1286 functions, `obj/` cleaned before each
compile (the original 137 baseline had minor stale-object undercounting; a clean pre-fix re-measure
is 139). Per-class COMPILE_FAIL:

| Error | pre-fix | post-fix | Δ |
|---|---|---|---|
| E1079 must be integral | 33 | 11 | **−22** |
| E1080 must be arithmetic | 12 | 5 | **−7** |
| E1036 pointer subtract | 3 | 0 | **−3** |
| E1052 void (ceiling) | 34 | 35 | +1 |
| E1029 pointer-to | 19 | 17 | −2 |
| E1010 / E1045 / E1081 (secondary) | 30 | 34 | +4 |
| others | 8 | 10 | +2 |
| **total COMPILE_FAIL** | **139** | **112** | **−27** |

The fix removes the pointer-in-op error in ≈32 functions; 27 then compile fully (→ MISMATCH), and a
handful expose a *secondary* type error behind it (a deeper class such as E1010/E1045), so they stay
COMPILE_FAIL in a different bucket rather than regress. Zero functions that compiled before now fail.
(The clean pre-fix run also showed 6 `returned None` that decompile fine in the post-fix run — EMIT
nondeterminism, unrelated to this render-time change and outside the COMPILE_FAIL bucket.)

## Not fixed here — E1052 is an honest ceiling

E1052 ×34 (`iVar = (*(code *)p)();`, a void-typed indirect-call result assigned to an integer) is
**not** decompiler-reachable: full-analysis Ghidra emits the identical construct on the reproducer,
and that construct fails to compile under gcc too (`void value not ignored as it ought to be`, the
same class as wcc386 E1052). Recovering the callee's return type needs deep prototype analysis;
mosura already matches Ghidra here.
