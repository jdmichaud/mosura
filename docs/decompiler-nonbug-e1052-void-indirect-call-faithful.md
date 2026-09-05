# Verified-faithful (NOT a bug): a void-typed indirect-call result, exactly like Ghidra

**Status: VERIFIED FAITHFUL — do not "fix".** This reclassifies the subject survey's largest
COMPILE_FAIL class (`E1052 Expression has void type`, ~34) out of the actionable type-inference set.
The premise that a faithful type-inference port could make `iVar = (*(code *)p)();` compile is FALSE,
proven against full-analysis `analyzeHeadless` — Ghidra emits the identical uncompilable construct.

## The symptom

the subject functions of the shape `iVar8 = (*(code *)ptr)();` — the result of an indirect call through an
opaque (memory-loaded, no recoverable prototype) code pointer is assigned to an integer variable.
`wcc386` rejects it:

```
E1052: Expression has void type
```

because `code` is `typedef void (*code)(void)` — the call expression is void, and a void value
cannot be assigned. It was suspected to be a mosura type-inference gap (a missing return type or a
missing cast on the call result).

## The oracle answer (full-analysis Ghidra 12.0.3, `analyzeHeadless`, x86-64)

Reproducer `indirect_use` (`scratchpad/repro/gtype.c`): an indirect call through a value loaded from
memory, result tested in a loop. Decompiled by BOTH mosura and full-analysis Ghidra on the identical
binary:

```c
// Ghidra (analyzeHeadless):
void indirect_use(undefined8 *param_1) {
  long lVar1;
  do {
    lVar1 = (*(code *)*param_1)();   // <-- void call assigned to `long`, same as mosura
    param_1 = param_1 + 1;
  } while (lVar1 == 0);
  return;
}
```

mosura emits the byte-identical construct. **Full-analysis Ghidra does not type the return either** —
`TypeOpCallind::getOutputLocal` (typeop.cc) returns the default output type only when the call is
`isOutputLocked()`; for an opaque indirect call the input(0) code pointer is the GENERIC `TypeCode`
(void return, `getInputLocal` → `getTypePointer(size, getTypeCode(), …)`), so the rendered call is
void. Recovering the callee's return type would need a concrete prototype the binary does not carry.

And Ghidra's OWN output does not compile — gcc on Ghidra's exact text:

```
error: void value not ignored as it ought to be
    lVar1 = (*(code *)*param_1)();
```

the same class as wcc386's E1052. So the construct is non-compilable in BOTH decompilers'
output — it is a property of the input (an opaque indirect call whose result is used), not a mosura
defect.

## Consequence

Making mosura emit compilable C here would require either (a) recovering the callee return type
(deep, per-target prototype analysis Ghidra also lacks for these) or (b) a non-faithful emitter cast
of a void expression — both forbidden by the porting mandate (mosura would **beat** full-analysis
Ghidra = a non-faithful extension). **mosura is already faithful here; the untyped return is an
honest DECOMPILER ceiling, not a bug.**

If per-target indirect-callee prototype recovery is ever built (a deep foundation, well beyond the
type-inference/cast bricks), some of these could become typed — but that is a beat-Ghidra capability,
not a faithful port, and is out of scope for task #1.

## ⚠️ CORRECTION (2026-07-29): faithful ≠ uncompilable — E1052 is NOT a COMPILE_FAIL ceiling

The verdict above was over-extended into "these functions must stay COMPILE_FAIL". That does not
follow, and it caused 47 functions to be parked twice.

"Do not fix" binds the **decompiler**. `prelude.h` is not the decompiler — it is *our* compile-support
header, written by `crates/mosura/examples/corpus_emit.rs`'s `PRELUDE` constant, and it exists
precisely to make Ghidra-shaped C compilable under Watcom C89. It declared `typedef void (*code)();`,
so the faithful text `iVar9 = (*(code *)p)();` was rejected as E1052. Declaring `typedef int
(*code)();` compiles the identical, unchanged decompiler output. The decompiler's untyped-return
ceiling is real; it just never implied an uncompilable *harness*.

How the double-park happened, and the mechanization that stops it recurring: the typedef was
hand-edited in the GENERATED `<subject-survey>/prelude.h`, measured (COMPILE_FAIL 75 → 29, E1052 47 → 0)
and written up in commit `26db108` — but the `PRELUDE` constant that *generates* that file was never
changed. The next EMIT restored `void`, the next compile produced 74 E1052 lines in
`dos/WCCOUT.TXT`, and the 47 fresh COMPILE_FAILs were re-adjudicated against *this document* as
"verified faithful, expected". The sampled specimen `000115d8`
(`iVar9 = (*(code *)(*((xunknown4 *)(iVar1 + -0x10))))();`) is indeed this construct — the
adjudication was right about the construct and wrong about the conclusion.

Now: the typedef is fixed at the source; `corpus_emit --prelude-only <dir>` regenerates the header
without a re-emit; `compile.sh` records `prelude_sha=` in `.compile-complete`; and `compare.py`
stamps it into `results.tsv`'s header and refuses to score if `prelude.h` moved since the compile.
No COMPILE_FAIL number can be attributed to a prelude the run did not use.

**Standing distinction: a verified-faithful RENDER is a decompiler ceiling. Whether that render
COMPILES is a separate axis owned by the prelude/extern declarations, and it is legitimately
fixable.** (Same two-axes rule as `variablepiece-extended-cover`: FAITHFUL and COMPILABLE are
separate axes.) Before filing any COMPILE_FAIL class as a ceiling, ask which axis it is on.
