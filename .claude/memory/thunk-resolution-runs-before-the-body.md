---
name: thunk-resolution-runs-before-the-body
description: "A jump-only entry is a THUNK and Ghidra creates a function at its target BEFORE storing the thunk's body — the ORDER is the mechanism; run it after the walk and every thunk vetoes its own target."
metadata:
  node_type: memory
  type: project
---

A function whose entry is a lone unconditional jump is a **thunk**, and Ghidra creates a function
at its target through a path that has nothing to do with `SharedReturnAnalysisCmd`:

```
CreateFunctionCmd.createFunction     :365   "check for a thunk first"
CreateFunctionCmd.fixupFunctionBody  :667   same check, before func.setBody
  -> resolveThunk                    :494
  -> CreateThunkFunctionCmd.getThunkedAddr  :548
  -> getSimpleFlow                          :815   (non-conditional jump, or terminal call,
  -> getReferencedFunction                  :319-375   with exactly ONE non-indirect flow)
       ... new CreateFunctionCmd(referencedFunctionAddr).applyTo(program)
```

⭐ **THE ORDER IS THE MECHANISM, not an implementation detail.** Both call sites run the check
while the thunk's own body is still *unstored*, so `getFunctionContaining(thunkedAddr)` cannot see
the target as already owned. Port it *after* the body walk and every thunk vetoes its own target —
the veto looks like a faithful guard firing, and the whole mechanism silently produces nothing.
Hence `thunk::resolve_thunks` runs at the **top** of `compute_function_bodies` (mosura's
whole-program stand-in for `fixupFunctionBody`). Landed `69cf941`, gate `55531a3`, module
`crates/mosura/src/analysis/analyzers/thunk.rs`.

**Why:** the subject's entry `0x601f8` is `EB 76` — a short jump over the inline Watcom copyright banner
(`analysis/loader/watcom.rs`) — and `0x601f8 + 2 + 0x76 = 0x60270` exactly. Ghidra creates
`FUN_00060270`; mosura's body walk followed the `jmp`, swallowed the target, and the overlap
refusal then declined it forever. ⚠️ **Shared return cannot be the mechanism there**: the span
between source and target is a *string*, so no function entry lies in it and
`assumeContiguousFunctions`' forward arm (`destAddr >= functionAfterSrc`) does not fire in Ghidra
either. Reaching for `SharedReturnAnalyzer` because the shape is "a jump that lands in another
function's body" is the wrong suspect — check `getSimpleFlow` first when the jump source is itself
a function ENTRY.

**How to apply:**
- Only the `getSimpleFlow` fast path is ported. The multi-instruction side-effect walk (`:598-648`),
  `getThunkedExternalFunctionAddress`, `resolveComputableFlow` and `getFirstBlockJumpCall` are not —
  so the subset can only *under*-report a thunk, never invent one. The thunk *relationship*
  (`setThunkedFunction`, name/signature inheritance) is also unmodelled; the body walk stops at the
  new function on its own, so the thunk's body comes out as just its jump.
- `getFlows()` (`InstructionDB.java:289`) is flow refs **minus `INDIRECTION`**, deduplicated into a
  SET, and `getSimpleFlow` needs exactly one. That is what keeps PLT `jmp *[GOT]` stubs from
  firing — measured: `function_parity` / `function_body_parity` / `reference_parity` all green.
- ⚠️ **It moves FID.** FID hashes function bodies, so a thunk that stops swallowing its target
  changes the ingested record set: `fid_database_drift` went from 1 drifting database to 4. That
  test was ALREADY RED at `a4081da` (`watcom-ow2-x86-32`, 3043/4593), so the widening is not
  attributable as a clean regression — regenerating the committed databases is lead-gated.

Related: [[shared-return-cursor-cache-is-semantic]], (subject-profile note `tailjmp-mve`),
[[oracle-same-question-not-just-same-tool]], [[generated-artifact-drift]].
