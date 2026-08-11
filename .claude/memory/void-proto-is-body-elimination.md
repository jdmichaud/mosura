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

**THE PASS-THROUGH ARGUMENT GAP (found 2026-08-11 via the `regmodify` MVE).** `f(x){ g(x); }`
loses the argument: mosura emits `func_0xNNN()`, Ghidra emits `func_0xNNN(param_2)`. Verified
pre-existing (identical with `MOSURA_CALLEE_EFFECTS=0`), so it is not from the callee-effects work.

Mechanism, read from Ghidra's source rather than guessed: `AncestorRealistic::execute`
(funcdata_varnode.cc:2205) returns false when the trial varnode `isInput()`, with the comment
"failure here doesn't necessarily mean further analysis won't still declare this a parameter".
`fillin_map` only marks ACTIVE trials used, so the trial dies there in BOTH tools — the argument
must come from somewhere else. `ActionDefaultParams` (coreaction.cc:2311) is the candidate: when a
call spec has no model it does `fc->copy(otherfunc->getFuncProto())`, copying the CALLEE'S OWN
recovered prototype into the call site. That is the same shape as [[caller-evidence-prototypes]]'s
per-call model, which is why that work unblocks this port (TODO task #14).

⚠️ NOT YET SETTLED: in the oracle run the callee sat OUTSIDE the imported range, so Ghidra had no
`otherfunc` and still emitted the argument — so trials produced it there by some path not yet
identified. Do not implement on the ActionDefaultParams story until a trace names the mechanism;
[[trace-diff-first-not-fifth]]. Three root causes were guessed and retracted earlier the same day.

Note while reading: Ghidra guards that early return with `if (!trial->hasCondExeEffect())`
(fspec.hh:221). mosura has no `condexe_effect` flag at all, so the guard is INERT rather than
mis-ported — it can only matter once conditional-execution marking is ported.

Related: [[caller-evidence-prototypes]], [[war2-byte-exact-campaign]],
[[watcall-killedbycall-too-aggressive]], [[goal-is-the-binary-not-ghidra]],
[[gate-what-you-measured-not-what-you-guessed]].
