# Verified-faithful (NOT a bug): mosura drops a bare call-result return, exactly like Ghidra

**Status: VERIFIED FAITHFUL — do not "fix".** This closes the WAR2 remediation Stage 3 target
(cross-function propagation to capture dropped returns / retire `extraout_`). The premise that
Ghidra captures a bare call-result return is FALSE, proven against full-analysis `analyzeHeadless`.

## The question

WAR2 functions of the shape `func_0x...(); return;` (a call whose result is not obviously used,
then a bare `return`) were suspected to be a mosura defect — that Ghidra would render
`return func();` and mosura drops it. Task #3 was scoped to recover that via cross-function
callee-prototype propagation.

## The oracle answer (full-analysis Ghidra 12.0.3, `analyzeHeadless`, x86:LE:64)

Minimal fixture `oracle/ground-truth-notes/barecall.bin` — A@0x100000 = `call B; ret`,
B@0x100010 = `mov eax,42; ret`:

```
undefined8 FUN_00100010(void) { return 0x2a; }          // callee: recovers a NON-void return
void      FUN_00100000(void) { FUN_00100010(); return; } // caller: DROPS the result, bare return
```

**Full-analysis Ghidra drops the bare call-result return** — the caller is `void`, calls the
callee, discards the result. This is byte-identical to what mosura emits and to what the isolated
Ghidra oracle (`oracle/capture --c`) emits. mosura is faithful in all three (isolated Ghidra,
full-analysis Ghidra, mosura).

Why: the RETURN's register candidate traces to `def = CALL`, and `ancestorOpUse` returns false for
a CALL ("a call is never a good indication of a single op use", funcdata_varnode.cc:70-72 ==
mosura recover.rs:473). The caller's own output recovers `void` and the value is dropped — in
Ghidra and mosura alike. Note the callee IS recovered non-void; that does not change the caller.

The two cases Ghidra DOES capture are already matched by mosura and are separate mechanisms:
- **Used result** (`call B; add eax,1; ret`) → `iVar1 = B(); return iVar1+1;` — captured by both
  isolated Ghidra and mosura (the downstream use forces the call output).
- **Bare tail-call** (`jmp B`) → Ghidra makes the caller a **thunk** inheriting B's signature
  (`thunk_FUN_...`), not a return-capture. Fixture `oracle/ground-truth-notes/tailcall.bin`.
  (WAR2's 3 `thunk`-classed MISMATCHes are this shape — a separate concern.)

## Consequence for Stage 3

Building cross-function propagation to emit `return func();` here would make mosura **beat**
full-analysis Ghidra = a non-faithful extension, forbidden by the porting mandate. **Stage 3 as
scoped is CLOSED: mosura is already faithful.** The faithful `funcLinkOutput` isOutputLocked half
built during Stage 3 (branch `stage3-trial-lifecycle`) is byte-neutral but its only consumer (the
return-side) is non-faithful, so it stays UNMERGED (inert scaffolding — per the d51 lesson, do not
land corpus-inert scaffolding).

## What remains for the WAR2 recompilation gap (NOT this target)

The residual `extraout_` reads (93 after Stage 1) are a mix of genuine killed-by-call reads
(faithful) and possible effect-model/regalloc divergence — each needs its OWN per-case
`analyzeHeadless` diff before any change (specimen: `FUN_00051b2d`, whose TU
`war2_survey <exe> <out> --only 0x51b2d` prints read-only). That is a scoped investigation,
distinct from the (non-faithful) bare-return target closed here. The dominant remaining WAR2
mismatch driver is codegen/register-allocation, and the COMPILE_FAIL tail is the C-cluster
type-inference foundation (task #4) — both deep, both user investment calls.
