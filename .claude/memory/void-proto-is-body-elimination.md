---
name: void-proto-is-body-elimination
description: "void_proto is usually not a printing defect — the body was deleted as dead code because the return register was not recognized, and the prototype collapsed after it"
metadata:
  type: project
---

**⭐ `void_proto` (the smell that dominates every top-5 WAR2 mismatch cluster) is, for the
non-default-convention population, the SYMPTOM of whole-body dead-code elimination — not a
prototype-printing bug. Fix the body, and the prototype follows.**

**Measured 2026-08-11** on `oracle/ground-truth/regout.watcom-x86-32`, `bump_` @ `0x08048106`,
whose actual body is `add ebx,eax ; ret` (`parm caller [ebx] [eax] value [ebx]`):

```c
void FUN_08048106(void)
{
  return;
}
```

The chain, in order — each step is correct given the last, which is why it is invisible:
1. the default model does not list EBX as return storage, so nothing consumes the ADD's result;
2. the ADD is therefore dead and is removed;
3. with it go the only reads of EBX and EAX, so the function has no input varnodes left;
4. `recover_input_params` (fspec.rs:1178) finds no trials → the prototype is `(void)`.

**This explains the 5-byte `void FUN(void){ return; }` rows in the survey.** The user flagged them
as implausible — "don't seem like a function warcraft2 would need" — and was right: they are not
stubs, they are functions whose ENTIRE BODY was eliminated. Any census that reads them as trivial
functions is miscounting the defect. Same root as the plan's open finding "non-default register
conventions silently lose instructions" (FUN_00074744 and siblings).

**THE FIX is the machinery already built for [[caller-evidence-prototypes]], turned inward.**
`callee_effects` (analysis/decompiler.rs) already recovers a function's `overwrites` (written, not
restored) and `reads` (read before written) from its own body — for `bump_` exactly `value [ebx]`
and `parm caller [ebx] [eax]`. Today that evidence is recorded on the CALLER's `CallSpec` and used
only at call sites. Applied to a function while decompiling ITSELF it gives:
- `recover_input_params` a real input list (via `recovered_input_list`, already written+tested), and
- EBX as live output storage, so the ADD is not dead and the body survives.

Order matters: the OUTPUT half must land first. Fixing only the input list recovers a prototype for
a function whose body has already been deleted — right signature, empty body, still wrong bytes.

Related: [[caller-evidence-prototypes]], [[war2-byte-exact-campaign]],
[[watcall-killedbycall-too-aggressive]], [[goal-is-the-binary-not-ghidra]],
[[gate-what-you-measured-not-what-you-guessed]].
