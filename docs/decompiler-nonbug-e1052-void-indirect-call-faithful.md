# Verified-faithful (NOT a bug): a void-typed indirect-call result, exactly like Ghidra

**Status: VERIFIED FAITHFUL — do not "fix".** This reclassifies the WAR2 survey's largest
COMPILE_FAIL class (`E1052 Expression has void type`, ~34) out of the actionable type-inference set.
The premise that a faithful type-inference port could make `iVar = (*(code *)p)();` compile is FALSE,
proven against full-analysis `analyzeHeadless` — Ghidra emits the identical uncompilable construct.

## The symptom

WAR2 functions of the shape `iVar8 = (*(code *)ptr)();` — the result of an indirect call through an
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
Ghidra = a non-faithful extension). **mosura is already faithful; E1052 is an honest CEILING, not a
bug.** These ~34 functions are reclassified OUT of the actionable COMPILE_FAIL set: the true
remaining actionable count after Brick 1 (clean COMPILE_FAIL 112) is **112 − 35 E1052 = 77**.

If per-target indirect-callee prototype recovery is ever built (a deep foundation, well beyond the
type-inference/cast bricks), some of these could become typed — but that is a beat-Ghidra capability,
not a faithful port, and is out of scope for task #1.
