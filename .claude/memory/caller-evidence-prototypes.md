---
name: caller-evidence-prototypes
description: Per-call prototype model (CallSpec.overwrites + .reads) landed at 54ef51f; still gated on the both-input-and-output register representation
metadata: 
  node_type: memory
  type: project
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-08-11T10:46:41.416Z
---

**SOLVED and UN-GATED (`22537a3`→HEAD). `CallSpec` carries both prototype halves — `overwrites`
(written, not restored) and `reads` (read before written) — recovered from the callee's own body,
and the call's input AND output storage are built from them.**

**Why:** every call-site query — effects, input trials, output trials — used to go through
`f.proto_model`, the CALLER's single model. A callee whose convention differs could only be
patched one query site at a time, which does not compose. That was the `be4cfdc` blocker.
Ghidra's `FuncCallSpecs : FuncProto` owns both parameter lists; this is that object.

Three consumers now ask the CALL, not the caller's model:
- `guard_calls` — a recovered overwrite is killedbycall at that site.
- `recover::recovered_output_list` — those registers become the call's OUTPUT storage, in a
  SECOND `derive_output_map` stage that runs only when the default `<output>` yielded no used
  trial. Staged, not merged, because `firstOnly` (fspec.cc:1649) admits one entry per storage
  class — EBX would be suppressed by EAX for sharing TYPECLASS_GENERAL even where EAX is dead.
  Staging also keeps the default path bit-identical, so the corpus cannot move.
- `check_input_trial_use` — vetoes an argument trial for a register the callee never reads.

Measured on the `regout` MVE (reproduces WAR2 FUN_00074744):

```
gated off   pxVar1 = pxRam08049070; func_0x08048106(param_2); *pxVar1 = param_1;
enabled     pxVar1 = (xunknown1 *)func_0x08048106(param_2);   *pxVar1 = param_1;
```

The store goes through the call's RESULT instead of the caller's stale pre-call pointer — wrong
code on both sides of one call before this. The veto took the same call from 5 spurious
arguments to 1.

**THE REMAINING GAP — measured, and smaller than it first looked.** The source passes TWO
arguments (`parm caller [ebx] [eax]`) and EBX is dropped. Instrumenting the trials at
`build_input_from_trials` gives EBX `used=false active=false defnouse=false` — the INACTIVE
branch of `check_input_trial_use`, i.e. `ancestor_op_use` found the value is not used SOLELY to
feed this call. **THE BUG THAT KEPT IT GATED, and the lesson.** Three successive readings called it a
representational impossibility (a register cannot be both argument and return). All three were
wrong and were retracted. Pass-correlating the verdicts showed `check_input_trial_use` marks EBX
**ACTIVE**; `fillin_map`'s definitely-not-used chain rule (fspec.rs:498-511) cleared it afterwards
— a fully-`dnu` exclusion group latches `seendefnouse` and marks every LATER trial inactive. The
first implementation suppressed EDX (a veto) in the middle of watcall's EAX/EDX/EBX/ECX sequence,
and the latch took EBX down with it. **The defect was in the fix, not in the representation.**

The cure is structural: `recovered_input_list` REPLACES the model's input list with the callee's
own, so the recovered registers are CONSECUTIVE groups and the faithful chain rule has nothing to
fire on. The veto is retired — a register outside the recovered list simply has no entry to be a
trial for. `resource_start` must be `[0, len]`, not `[0]`: `separate_sections` (fspec.rs:393)
indexes `[1]`.

Lesson, at cost: I advanced three unmeasured root causes in a row before instrumenting. Each was
plausible from reading source. The pass-correlated print settled it in one run. **Instrument
first** — [[gate-what-you-measured-not-what-you-guessed]], [[trace-diff-first-not-fifth]].

Ruled out by measurement along the way: it is NOT the argument veto (EAX and EBX both
`vetoed=false`; only ECX/EDX/stack are vetoed), NOT the call's output shadowing the input (the
call still has `out=None` at that point), and NOT `guard_calls`' `isAssignment` skip
(heritage.cc:1453 — removing it does not restore the argument). An earlier reading of this gap
called for a "designed representation"; that too was unverified.

**GATED** by `callee_register_return_is_recovered_with_its_argument` (ground_truth_parity, 24
tests now), against `expected/regout.use_.c` — a reference proven byte-faithful by
`verify-expected.py` (22b). VERIFIED IT CAN FAIL: `MOSURA_CALLEE_EFFECTS=0` turns it RED. That
needed one comparator fix — `mask()` covered `a1` (mov eax,[abs32]) but not `8b1d`, the modrm form
used whenever the destination is not EAX; same relocation argument, same mask.

Same subsystem unblocks task #14 (`ActionDefaultParams`).

Related: [[war2-byte-exact-campaign]], [[watcall-killedbycall-too-aggressive]],
[[subregister-write-not-merged]], [[war2-pragmatism-over-faithfulness]],
[[mve-first-then-solve-the-mve]].
