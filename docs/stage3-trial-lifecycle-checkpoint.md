# Stage 3 checkpoint — persistent per-CALL output trial lifecycle (`FuncCallSpecs::activeoutput`)

**Status: GROUNDED, build not started. Owner: remediation (subject-profile note) (decompiler agent).**
This doc is the warm-resume anchor: it holds the complete Ghidra mechanism, mosura's current
state, the crux, the prior-attempt lessons, and the brick plan. Read it before writing any code.

## Goal

Retire the 473-function `extraout_`/`unaff_` reg-artifact MISMATCH class (the subject survey) + the
D4-residual bare-return + P6, by giving every CALL its own **persistent output-trial lifecycle**,
so `uVar = FUN_...()` is captured even when the function's own RETURN doesn't use the value. This
RETIRES the D5 `resolve_call_output` post-heritage local scan (`recover.rs:913`) once the faithful
lifecycle covers it — prove with the corpus + the `deepchain` ground-truth (`oracle/ground-truth/
deepchain.gcc-x86-64`) + `is_even`/`is_odd`.

## The crux (why the D5 local scan is insufficient — NOT re-derivable by tweaking it)

`resolve_call_output` marks a call-output trial **active iff `!descend.is_empty()`** (recover.rs:955).
But the function's `ActionReturnRecovery` (`resolve_return`) runs FIRST (mainloop) and faithfully
prunes the RETURN's use of the call-result register — Ghidra `ancestorOpUse` rejects an indirect
creation (`funcdata_varnode.cc:1936`, `if(def->isIndirectCreation()) return false`), and mosura's
`ancestor_op_use` (recover.rs:419) mirrors it. Once the RETURN's use is pruned, the call's RAX
INDIRECT-creation has **no descendants** → the local scan marks the trial inactive → the call
output is never built → the value renders as `extraout_RAX` / a dropped return.

Ghidra does NOT gate on descendants. `FuncCallSpecs::checkOutputTrialUse` (fspec.cc:5661) marks a
trial active iff its INDIRECT-creation varnode **still EXISTS** (`collectOutputTrialVarnodes`,
fspec.cc:5536, sets `trialvn[i]` to the surviving creation; `trialvn[i] != null → markActive`,
never `markNoUse`). It builds the call output from that creation regardless of the RETURN. On the
NEXT `actfullloop` round the mainloop's `ActionReturnRecovery` then sees a real CALL output (no
longer an indirect creation) and `ancestorOpUse` ACCEPTS it, so the RETURN keeps its use. The
lifecycle is inherently **multi-pass**: build-the-call-output (round N tail) → return-sees-it
(round N+1 mainloop).

Confirmed by the prior d51 investigation (memory: menu-E re-verdict): the bounded 2-brick attempt
(guard_calls possibleout flag + is_realistic input-isIndirectZero) was **corpus-inert and reverted**
because it left `resolve_call_output`'s local descend-gate in place. The real fix is the persistent
`activeoutput` trial that lives independent of the RETURN's use — NOT a tweak to the local scan.

## Ghidra's mechanism (the port surface), in lifecycle order

| Phase | Ghidra | Where |
|---|---|---|
| **Seed** | `funcLinkOutput`: for a call whose output is NOT locked, `fc->initActiveOutput()` sets `isoutputactive=true`. (Locked → build the output varnode directly + extension.) | coreaction.cc:1571 |
| **Register** | `Heritage::guardCalls`: for each call with `isOutputActive()`, a register range with `characterizeAsOutput != no_containment` (and not `contained_by`) → `active->registerTrial(transAddr,size)`, `possibleoutput=true`; then the `killedbycall` INDIRECT creation is made with the `possibleoutput` flag (`newIndirectCreation(...,possibleoutput)`). | heritage.cc:1469-1484, :1522 |
| **`possibleoutput` flag** | `newIndirectCreation(op,addr,sz,possibleout)`: output vn always gets `Varnode::indirect_creation`; the **input const gets it only if `!possibleout`**. This is the one bit distinguishing a pure clobber from an output candidate. | funcdata_op.cc:707-723 |
| **Evaluate (multi-pass)** | `ActionActiveReturn::apply` (actfullloop TAIL, repeats): for each call `isOutputActive()` → `checkOutputTrialUse` (collect surviving creations, mark active-iff-exists) → `deriveOutputMap` → `buildOutputFromTrials` (reassemble pieces, create the CALL output) → `clearActiveOutput`. | coreaction.cc (ActionActiveReturn), fspec.cc:5661/5770/5536 |

Action order (coreaction.cc:5490-5688): actmainloop { Heritage:5492 · **ActionActiveParam:5499** (call inputs) · **ActionReturnRecovery:5500** (function return, prunes) · DeadCode:5503 · … } then actfullloop tail { DeadCode:5682 · … · **ActionActiveReturn:5688** (call outputs) } — and actfullloop is `rule_repeatapply`.

## mosura's current state

- `Funcdata::active_output: Option<ParamActive>` = the **function's** return trials (recover.rs
  `setup_active_output`/`resolve_return`). `Funcdata::active_inputs: HashMap<OpId,ParamActive>` =
  **per-call argument** trials (recover.rs `setup_active_input`/`resolve_call_args`).
- **MISSING: a per-call OUTPUT `ParamActive`** (Ghidra `FuncCallSpecs::activeoutput`). Its stand-in
  is `resolve_call_output` (recover.rs:913), a post-heritage local backward-INDIRECT scan that
  registers trials on a throwaway `ParamActive` and gates activity on `!descend.is_empty()`.
- Pipeline (pipeline.rs): `ActionResolveCalls` (:565, before fullloop) = `resolve_return +
  resolve_call_args`. `ActionActiveReturn` (:713, fullloop tail) = `resolve_call_output`. Ordering
  already matches Ghidra; the fullloop already repeats. The gap is the activity criterion +
  persistence, not the placement.
- `ParamActive`/`ParamTrial` machinery is largely ported (fspec.rs:772+): registerTrial, sortTrials,
  markActive/Inactive/NoUse/Used, deriveOutputMap (via `derive_output_map` recover.rs), and
  `build_call_output_from_trials`. Reusable for the persistent version.

## Brick plan (each brick: instrument → faithful port → gate corpus BYTE-IDENTICAL or STOP+report → commit)

- **Brick 0 (READ-ONLY, do first):** trace `deepchain`/`is_even` through the pipeline; capture the
  exact moment the RAX creation's `descend` empties (which action) and confirm the creation still
  EXISTS at `resolve_call_output` time (held or not-yet-dead). This decides whether Brick 2 needs the
  `possibleoutput`-holds-across-deadcode piece. `scripts/trace-diff.sh` + eprintln probes on the
  creation's varnode id.
- **Brick 1 — per-call `activeoutput` container + seed.** Add `Funcdata::call_active_output:
  HashMap<OpId,ParamActive>` + an `is_output_active` set; seed it (funcLinkOutput analog) for each
  unlocked call. Register the output trials in `guard_calls` (heritage) instead of the post-heritage
  local scan, keyed to the call — mirroring how `active_inputs` is registered. Mark the INDIRECT
  creation with the `possibleoutput` bit (input-const flag). *Likely corpus-neutral scaffolding — do
  NOT commit alone if inert (d51 lesson); fold into Brick 2 so the first commit is non-inert.*
- **Brick 2 — evaluate on creation-EXISTS, not descend.** Rewrite `resolve_call_output` (or its
  replacement) to mark a trial active iff its registered creation survived to this point
  (Ghidra `checkOutputTrialUse`: `trialvn[i] != null`), NOT `!descend.is_empty()`. This is the
  behavioral change that captures the return. GATE HARD: it will likely move the corpus (call
  outputs appear where they were dropped) — STOP + report delta+cause to lead; do not self-approve.
- **Brick 3 — dead-code correctness.** Ensure genuinely-dead killedbycall creations (no use, not a
  real output) are removed by ActionDeadCode BEFORE evaluate, so creation-EXISTS ⇒ genuine output
  (avoid over-recovering every clobber as an output). Verify the `possibleoutput` flag's dead-code
  liveness matches Ghidra (a possible-output creation is held as a candidate; a pure clobber dies).
- **Brick 4 — retire D5 local scan.** Once Bricks 1–3 cover it, delete the `resolve_call_output`
  backward-scan body; prove byte-parity on corpus + deepchain + is_even/is_odd. Re-measure the subject
  (extraout_ 93 → target lower; MISMATCH reg-artifact class).

## Brick 0 finding (DONE, read-only trace @ ca4532e tree)

Instrumented `resolve_call_output` on the `tailcall.gcc-x86-64` repro (is_even @0x401000 tail-calls
is_odd @0x401020). Current mosura output drops the return: `func_0x00401020(param_1 + -1); return;`
(bare `return;` in a non-void function). At `resolve_call_output` time the call `call@0x401013` has
`has_output=false` and its **immediately-preceding op is `INT_ADD`, NOT an INDIRECT creation** — i.e.
the RAX INDIRECT-creation is **already GONE**. So the backward-INDIRECT scan finds nothing and builds
no output.

Conclusion: the creation is **deadcode-removed before `resolve_call_output`**, because
`resolve_return` (mainloop, runs first) prunes the RETURN's RAX use too eagerly (ancestorOpUse rejects
the indirect creation) and the now-useless creation dies in the next DeadCode. Ghidra avoids this via
(a) the persistent `activeoutput` trial registered in guardCalls keeping the creation as a
`possibleoutput` candidate held across DeadCode, and/or (b) the FUNCTION return recovery deferring its
reject across passes (`ParamActive` maxpass/numpasses) until the CALL output is built and the RETURN
then traces to a real call output (ancestorOpUse ACCEPTS a non-indirect-creation). **The fix is NOT a
local-scan activity-criterion tweak — the creation must be kept alive (possibleoutput held) and/or the
return-recovery reject deferred, i.e. the persistent multi-pass lifecycle.** This raises the priority
of Brick 3 (creation liveness) and adds a return-recovery-deferral dimension.

## Brick 0b finding (DONE, read-only) — WHY the creation is orphaned: `resolve_return` commits too early

Traced the two mosura↔Ghidra mis-alignments that orphan the RAX creation:

1. **`resolve_return` commits its prune in ONE shot, before the fullloop.** `RETURN_MAXPASS=0`
   (recover.rs:544), so after a single `finish_pass` the function's `active_output` is
   `fully_checked` → `build_return_output` runs → removes the RAX input from the RETURN
   (`op_remove_input`, recover.rs:648) since its trial fails `return_trial_kept` (ancestorOpUse
   rejects the indirect creation — faithful). AND `ActionResolveCalls` (pipeline.rs:565) runs
   `resolve_return` ONCE **before** the `fullloop`. So the prune commits before the fullloop even
   starts. The orphaned creation then dies in the fullloop's DeadCode, before `ActionActiveReturn`
   (fullloop tail) can see it. → **is_even: `func_0x...(); return;`.**
2. **Ghidra's `ActionReturnRecovery` is INSIDE the repeating `actmainloop` (:5500), multi-pass and
   deferred.** It does NOT commit `buildReturnOutput` until `isFullyChecked()` (numpasses > maxpass),
   and it runs every mainloop pass across every fullloop round. Meanwhile `ActionActiveReturn`
   (:5688, fullloop tail) BUILDS each call's output from its persistent `activeoutput` trial in an
   EARLY round — **before** the function-return recovery finalizes. Once the call output exists, the
   RETURN's RAX traces to a real CALL output (no longer an indirect creation) → `ancestorOpUse`
   ACCEPTS it → the RAX trial is kept → the RETURN keeps its input. Order: build-call-output (round N)
   → return-keeps-it (round N+1).

**Net:** the fix is the entangled multi-pass ordering — (a) each CALL gets a persistent `activeoutput`
trial registered in `guardCalls` (so the call output is built by `ActionActiveReturn` independent of
the RETURN's local scan), and (b) the function-return recovery must not commit its prune before the
call outputs are built (either place `resolve_return` inside the mainloop with a deferring maxpass, or
otherwise sequence the call-output build before the return commit). Both are needed — deferring the
return alone still leaves `resolve_call_output` a post-hoc local scan with no persistent creation to
find; the persistent call `activeoutput` alone still gets its creation pruned early by the return.

## Open questions (resolve during Brick 1)

1. ~~Does deadcode keep the RAX creation alive? NO (Brick 0). WHY? resolve_return commits too early
   (Brick 0b).~~ Both ANSWERED.
2. Minimal faithful sequencing: does moving `resolve_return` into the mainloop (Ghidra :5500) with a
   deferring maxpass + registering the persistent call `activeoutput` in `guardCalls` suffice, or is
   an explicit possibleoutput-holds-through-DeadCode needed too? Decide by building Brick 1 (persistent
   call activeoutput + guardCalls registration) FIRST and re-tracing is_even before touching
   `resolve_return`'s placement/maxpass.
2. `deriveOutputMap`/`build_call_output_from_trials` already exist — do they need changes for the
   persistent path, or only the trial-registration + activity-criterion move?
3. Interaction with the two-trial `findPreexistingWhole` piece-reassembly (task6) — must be preserved.

## Gates (every brick)

Corpus `cargo test --release --test decompile_corpus` BYTE-IDENTICAL (0.9513/57) or STOP+report to
lead (no self-approve on fixture moves); `cargo test --release` green; `cargo clippy --all-targets`
0; then the subject re-measure + doc update. A revert of newly-written code is a process failure — Brick 0
instrumentation must confirm the mechanism before Brick 2's code lands.
