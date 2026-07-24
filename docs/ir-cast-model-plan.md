# IR-CAST-op model — staged rewrite plan (branch `ir-cast-model` off e9c0655)

Owner: war2-arraytype. PLAN-FIRST (lead gates this before any code). Funds the convergence foundation
(E1010 + E1045 + E1029 + partialsplit): replace mosura's print-time cast-decision + print-time
re-inference with Ghidra's IR-CAST-op model, where `ActionSetCasts` inserts real `CPUI_CAST` ops that
**block type propagation**, and printc renders them.

## Why (the pinned crux, task #10)

pointercmp: the INT_ADD result `param_1+8` gets committed type `Pointer(8,Unknown(1))` because the loop
phi relays its pointer type BACKWARD onto the arithmetic result. Ghidra blocks this with a real IR CAST
(`RAX = (cast) u0x10000008`, `u0x10000008 = RDI + 8` = int8) — `TypeOpCast` has NO `propagateType`
override, so it inherits the base no-op and the pointer never crosses it. mosura has no IR CAST node
(cast.rs = "just the decision, not an IR pass"; printc casts at render time), so nothing blocks the
back-relay → no mismatch survives → no render-cast can fire. FAITHFUL FIX = port the IR-CAST-op model.

## Branch / merge discipline

- Branch `ir-cast-model` off `e9c0655`. **Master stays byte-identical/green throughout.**
- Each stage committed green ON THE BRANCH; the branch corpus WILL be broken mid-rewrite (expected).
- MERGE GATE (lead): branch coherent AND corpus byte-identical-or-toward-oracle WHOLE (pointercmp/
  pointerrel/E1010 toward-oracle, zero wrong-code, zero regressions vs master). No per-commit gate.

## Stages (each names its Ghidra touchpoints; sizing is rough, multi-session)

### Stage 0 — Retire print-time re-inference (HARD PREREQUISITE, zero-gauge) — LARGEST
mosura runs type inference TWICE: in-pipeline `infertypes::infer_types` (commits `Varnode::ty` during
the mainloop) AND a second full pass `infertypes::infer(f, &locks)` at RENDER time (printc.rs:1884),
whose result backs `type_of` (printc.rs:202/209). The print-time pass exists because the in-pipeline
committed types were not authoritative for rendering (HighVariable resolution, constant typing, param
locks). An inserted IR CAST perturbs this render-time re-inference at compare sites (the block recorded
in [[actionsetcasts-campaign]] Brick-2 / [[printc-structuring-adaptation-conflicts]]) — so it must go
FIRST.
- 0a: Make in-pipeline `ActionInferTypes` (+ the HighVariable resolution `merge`/`hv` currently done
  INSIDE `infer`) the authoritative final type source: run it as the final pipeline type pass and
  persist the per-varnode + HighVariable-resolved type onto the varnode / a committed map printc reads.
- 0b: Switch printc `type_of` (printc.rs:202) to read the committed types; delete the render-time
  `infer(f,&locks)` call (printc.rs:1884). Keep the print-time cast decisions (`cast_operand`/
  `get_input_cast`) for now — they consume committed types instead of re-inferred.
- 0c: Reconcile the churn — committed in-pipeline types will differ from render-time re-inferred at some
  fixtures (constants, locks, resolution order). Fix the in-pipeline inference to produce what printc
  needs. Gate: branch corpus stabilizes to the pre-Stage-0 output (byte-identical where the two passes
  already agreed; understood deltas elsewhere).
- Touchpoints: printc.rs:1884/202/209, infertypes.rs `infer` vs `infer_types` (the `merge`/`hv` block
  moves in-pipeline), pipeline.rs action ordering.
- **DEPTH-VALVE WATCH:** if 0a reveals the authoritative in-pipeline type needs the PERSISTENT
  HighVariable model (mosura resolves types per-`merge()`-call, not a persistent HighVariable) as a hard
  prerequisite → STOP at 0a's plan and report. This is the most likely place the rewrite escalates again.

### Stage 1 — Add the `CPUI_CAST` op + `TypeOpCast` — SMALL
- Add `OpCode::Cast` (opcode.rs:8). `TypeOpCast` (Ghidra typeop.cc:2209, `"(cast)"`): NO `propagate_type`
  arm (infertypes.rs `propagate_type` returns `None` for `Cast` → inherits the base no-op → BLOCKS
  propagation, the faithful mechanism). `op_meta` = (Unknown, Unknown). print_raw = `(cast)`.
- Touchpoints: opcode.rs, infertypes.rs `op_meta`/`propagate_type`, funcdata op display.

### Stage 2 — `ActionSetCasts` inserts CAST ops in-pipeline — MEDIUM-LARGE
- Port `ActionSetCasts::apply` (coreaction.cc:2722) + `castInput` (2655) + `castOutput` (2532) +
  `resolveUnion` (2490, union-only — can stub initially). For each op input slot, `getInputCast` (the
  logic currently in printc.rs:509, MOVES to this IR action) returns a required type; if non-null,
  insert a `CPUI_CAST` op via `op_insert_before` (funcdata.rs:387, = `opInsertBefore`) + a new unique
  varnode carrying the required type. `castOutput` casts the def side. The CAST output type is fixed →
  blocks propagation (Stage 1).
- Run as a pipeline action AFTER `ActionInferTypes` (Ghidra's mainloop slot).
- Touchpoints: coreaction.cc:2722/2655/2532, new `setcasts.rs` action, printc `get_input_cast`→moved.

### Stage 3 — printc renders CAST ops; retire cast-at-print — MEDIUM
- printc renders `OpCode::Cast` as `(type)expr` (Ghidra `PrintC::opCast`). REMOVE the print-time cast
  decisions (`cast_operand`/`get_input_cast` render-time wrapping, printc.rs:621/509) — casts now come
  from IR CAST ops only. `markExplicitUnsigned` (printc.rs:571) stays (it's not a CAST).
- Touchpoints: printc.rs render (`emit_basic`/`cast_operand`), the new opCast arm.

## Sizing / sequencing
Stage 0 dominates (zero-gauge, the risk). Stages 1–3 are a standard op port once Stage 0 lands. Value
(pointercmp/pointerrel/E1010 toward-oracle) appears only after Stage 2+3 on the branch. No incremental
toward-oracle gate before then — that is the all-or-nothing property already escalated + funded.

## Stage 0a VERDICT (2026-07-24, agent war2-arraytype) — PROCEED; persistent HighVariable NOT required

Grounded 0a empirically (probe reverted): compared, over the WHOLE datatest corpus, the print-time
re-inference (`infer(f,&locks)`, printc.rs:1884) against the in-pipeline committed `Varnode::ty`
(populated by `infer_types`, which broadcasts the HighVariable-RESOLVED type to every member varnode).

RESULT: **371 mismatches / 54320 varnodes = 0.6% (99.4% CONSISTENT).** Worst fixtures ~3-6%
(floatcast 9/258, floatconv 4/108, heapstring 2/35, revisit 14/250). Mismatch CATEGORIES (all small,
understandable — NOT a persistent-HighVariable gap):
- committed=Int(N) vs reinf=Unknown(N) (majority): committed is MORE refined (accumulated over mainloop
  iterations vs the single print-time pass) — switching to committed is generally TOWARD-oracle.
- Bool vs Unknown(1) (both directions): boolean-value typing.
- committed=Pointer(Spacebase) vs reinf=Unknown(8): the RSP spacebase-lock version varnodes.
- committed=Unknown(4) vs reinf=Float(4): a few float-typed values (the reverse — committed less refined).

⇒ VERDICT: **PROCEED.** The committed `Varnode::ty` is a viable AUTHORITATIVE per-varnode type source; it
is 99.4% consistent with the re-inference AND `infer_types` already broadcasts the HighVariable-resolved
type to all members, so committed ≈ `high->getType()` WITHOUT a persistent HighVariable object. The depth
valve does NOT trigger at 0a. The 0.6% mismatch is the zero-gauge churn to reconcile in 0c (mostly
toward-oracle; the few committed-less-refined cases — Float, some Bool — are the ones to watch).
DEPTH-VALVE risk shifts to Stage 2 (ActionSetCasts inserts CAST varnodes → the graph needs re-merge +
re-resolution; whether that stays coherent without a persistent HighVariable is the Stage-2 watch, not 0a).
NEXT: 0b — switch printc `type_of` to `Varnode::ty`, delete the render-time `infer()`, measure branch churn.

## Stage 0b DONE + 0c scope (2026-07-24, branch) — type_of reads committed Varnode::ty

0b: printc `type_of` now returns `self.f.vn(v).get_type()` (the committed in-pipeline type) instead of
the render-time re-inference (`self.types` retained but unread — the `infer()` call removal is the 0b/0c
cleanup, deferred to avoid churn during measurement). Build green.

BRANCH CORPUS: 0.9517 (e9c0655) → **0.9512** (−0.0005, expected mid-rewrite; gate is at MERGE). Movers
(per-fixture): **pointerrel 0.951→0.937 (−0.014)**, **revisit 0.894→0.875 (−0.019)**; pointercmp /
partialsplit / heapstring / floatconv UNCHANGED. The two movers are exactly the 0a REVERSE-mismatch cases
(committed LESS refined than re-inference): pointerrel had `reinf=Float(4) committed=Unknown(4)` +
`reinf=Bool committed=Unknown(1)`; revisit had the highest mismatch rate (14/250). So the committed
in-pipeline types are NOT yet fully at the print-time fixpoint for a few Float/Bool varnodes.

0c SCOPE: reconcile the churn — make the in-pipeline `infer_types` commit the more-refined Float/Bool
types the print-time pass reached (likely: the in-pipeline pass runs at an earlier mainloop state / fewer
iterations than the single print-time pass; the fix is to ensure the FINAL committed types match the
print-time fixpoint — e.g. a final infer_types pass, or find the float/bool refinement the print-time
pass applies that the committed lacks). Small + bounded (2 fixtures, Float+Bool categories). Then remove
the dead `infer()` call. THEN Stage 1 (CPUI_CAST op).

## Stage 0 COMPLETE (2026-07-24, branch) — BYTE-IDENTICAL to master

0c landed: a final `ActionInferTypes` pass at the tail of `universal_action()` (pipeline.rs, after the
merge phase) commits the settled-graph type fixpoint. printc's render-time `infer()`/`locks`/`types`
field are REMOVED — `type_of` reads committed `Varnode::ty` only.

RESULT: corpus **0.9517/57 — BYTE-IDENTICAL to master (e9c0655)**, suite 495/0, clippy 0. The
zero-gauge foundation turned out corpus-NEUTRAL: the final in-pipeline infer pass reproduces exactly what
the render-time re-inference computed (pointerrel/revisit churn fully recovered). The print-time
re-inference is retired; the in-pipeline committed types are authoritative for the printer — the
prerequisite for Stage 1-3 (IR CAST ops can now be inserted in-pipeline without perturbing a second pass).

NEXT: Stage 1 — add `OpCode::Cast` + `TypeOpCast` (no propagate_type → blocks back-relay).

## Stage 1 — mostly PRE-EXISTING scaffolding (2026-07-24, branch)

DISCOVERY: `OpCode::Cast = 64` (opcode.rs), `name()="CAST"`, the printc `render_op` Cast arm
(printc.rs:949, renders `(type)operand`), and consume-analysis transparency (recover.rs:342) ALL already
exist as byte-neutral scaffolding (printc comment: "mosura will begin inserting these in the
ActionSetCasts port... until then no rule creates one"). So Stage 1 (op node) + Stage 3's RENDER half are
already present. Added: explicit `propagate_type(Cast) => None` (infertypes.rs) documenting the
propagation-BLOCK (Ghidra TypeOpCast has no propagateType → the back-relay stop, the pointercmp/E1010
crux). Byte-identical (0.9517/57 — no Cast ops exist yet).

⇒ REMAINING = Stage 2 ONLY: `ActionSetCasts` inserts CAST ops in-pipeline (coreaction.cc:2722 apply /
2655 castInput / 2532 castOutput), MOVING the getInputCast logic from printc.rs:509 into the IR action;
insert via `op_insert_before` + a unique varnode carrying the required type; run after ActionInferTypes.
Then Stage 3's REMOVE half: delete the print-time cast_operand/get_input_cast wrapping (printc.rs:621/509)
so casts come only from IR CAST ops (else double-casts). The Cast RENDER already works.
STAGE 2 IS THE CORE REMAINING WORK — a fresh action port, differential-gated on pointercmp/pointerrel/E1010.

## Stage 2 PORT PLAN (grounded 2026-07-24; the core remaining work) — for warm-resume

Ghidra `ActionSetCasts` (coreaction.cc): a new mosura in-pipeline action `setcasts.rs`, run AFTER the
final `ActionInferTypes` (Stage 0c) — it needs settled types. Structure:

- `apply` (coreaction.cc:2722): iterate basic blocks in DOMINANCE order, ops in block order; skip
  `notPrinted` + existing CAST. Per op: (PTRADD/PTRSUB refit — opUndoPtradd / →COPY/INT_ADD, can defer);
  for each input slot `resolveUnion` (union-only, stub) + `castInput`; LOAD/STORE `checkPointerIssues`
  (defer); then `castOutput`.
- `castInput(op,slot)` (coreaction.cc:2655) — THE CORE:
  - `ct = getInputCast(op,slot)` — MOVE mosura's `printc::get_input_cast` (printc.rs:509) here verbatim
    (it already returns the right required type; it just needs to run in-pipeline reading `Varnode::ty`).
  - `ct==null` → markExplicitUnsigned/LongSize (mosura's `mark_explicit_unsigned` — a print concern;
    can stay in printc for now, NOT part of castInput's IR change).
  - CONSTANT operand → `vn.update_type(ct)` (the literal adopts the type; NO CAST op) — matches mosura's
    existing "constants aren't wrapped" print rule.
  - already-CAST input → reuse/retype (double-cast guard).
  - else INSERT: `newop=new_op(Cast,[vnin]); vnout=new_unique_out(size); vnout.update_type(ct);
    vnout.set_implied(); op.set_input(slot, vnout); op_insert_before(newop, op)`. (Ghidra
    coreaction.cc:2702-2712 — the CAST comes BEFORE the op in block order.)
- `castOutput` (coreaction.cc:2532): the def-side cast (assignment/store output) — port after castInput.

COORDINATION WITH STAGE 3 (critical — do together or the corpus double-casts): once castInput inserts IR
CASTs, printc's render-time cast wrapping (`cast_operand` printc.rs:621 calling `get_input_cast`) must be
REMOVED so operands aren't cast twice (the IR CAST already renders via printc.rs:949). Net: `get_input_cast`
MOVES from a print-time wrap to the IR insertion; `cast_operand` becomes a plain operand render.

GATE: first corpus-MOVING stage. Expect pointercmp/pointerrel/E1010 toward-oracle (the INT_ADD result now
holds int8 + a CAST to the pointer, blocking the back-relay via Stage-1's propagate_type(Cast)=None).
Differential per-fixture; wrong-code hard-block; report delta to lead. Then this branch is merge-candidate.

## ⚠️ LEAD CRUX FINDING (2026-07-24, agent rate-limited) — the tail-slot Stage-2 plan is INSUFFICIENT; corrects a load-bearing premise

Empirically + Ghidra-source verified before implementing Stage 2:

1. mosura OVER-PROPAGATES (typeprobe on pointercmp, post-pipeline): the `param_1+8` INT_ADD has **inputs=[Int(8),Int(8)] but output=Pointer(8,Unknown(1))**. The pointer is relayed BACKWARD from the loop phi (TypeOpMulti/COPY relay) onto the arithmetic result. So at the TAIL (where the plan slots setcasts), the ADD result is ALREADY Pointer == the pointer var it's assigned to → NO type divergence → castInput/castOutput find NOTHING to cast → **tail-slot setcasts does NOT fix pointercmp/E1010** (the flagship case).

2. Ghidra keeps that ADD result **int8** (oracle renders `(xunknown1*)(param_1+8)` = a cast FROM int8 TO pointer).

3. DECISIVE: Ghidra's `ActionSetCasts` is DEAD-LAST (coreaction.cc:5735, after actfullloop + ActionNameVars), with **NO ActionInferTypes after it**. So the inserted CAST canNOT block propagation via re-inference. ⇒ The agent's premise "the IR CAST blocks the back-relay" is WRONG for Ghidra's ordering. Ghidra's ADD stays int8 during INFERENCE ITSELF (propagation-meet rules), and the cast is PURELY a RENDER of the pre-existing int8→pointer mismatch.

4. ⇒ REFRAME: the IR-cast rewrite (Stage 0-1, byte-identical) is a valid RENDER-faithfulness improvement (real CAST nodes vs print-time wrapping) but by itself does NOT fix E1010. The actual E1010/pointercmp lever is mosura's TYPE-PROPAGATION MEET: mosura lets a MULTIEQUAL's pointer relay OVERRIDE an INT_ADD's computed int output; Ghidra does NOT. Relevant Ghidra: TypeOpIntAdd::propagateType (`inslot==-1 → "Don't propagate pointer types this direction"`, typeop.cc) + TypeOpMulti::propagateType (relays freely) + the Datatype meet/typeOrder that keeps the locally-int ADD output int despite the phi relay. mosura's meet (infertypes.rs:311 `type_order(newtype, cur)==Less → commit`) apparently lets Pointer beat Int here where Ghidra keeps Int.

NEXT (agent warm-resume): resolve WHY Ghidra's meet keeps the INT_ADD output int8 despite the free MULTIEQUAL pointer relay — compare mosura's infertypes meet/edge application against Ghidra's updateType + typeOrder for the ptr-vs-int-add-output case. That faithful propagation fix is the E1010 lever; setcasts (render) then casts the resulting int8→pointer mismatch. Stage 2 as "insert casts at the tail" alone is NOT the fix. Master untouched e9c0655; branch Stage 0-1 committed byte-identical.

## Stage 2 LANDED (2026-07-24, branch) — the crux finding's "insufficient" premise was itself WRONG; castOutput uses the INPUT-derived token, so it DOES render pointercmp

The crux finding's point (1) — "at the tail the ADD result is ALREADY Pointer → castOutput finds nothing" — is INCORRECT. `castOutput` (coreaction.cc:2541) does NOT compare the output varnode's committed type against itself; it computes `getOutputToken`, which for arithmetic is `CastStrategyC::arithmeticOutputStandard` — the token type recomputed from the INPUT read-facing types (int8 here), NOT the over-propagated output. It then `castStandard(committed_pointer, token_int8)` → non-null → inserts a `CPUI_CAST(pointer←int8)`. So the render-only cast fires WITHOUT fixing the propagation over-relay. **pointercmp now renders EXACTLY the oracle `(xunknown1 *)(param_1 + 8)` and `(xunknown1 *)(param_1 + 0x18)`; scored 1.0000.** The propagation-meet fix (crux point 4) is therefore NOT required for E1010's render — it is a separate, deeper correctness question about the committed type itself.

WHAT LANDED (`setcasts.rs` = Ghidra `ActionSetCasts`, run last after the Stage-0c final ActionInferTypes):
- `cast_output` (coreaction.cc:2532) + `cast_input` (2655), input casts first ("output may depend on input", 2757). `castInput` MOVED the operand cast from printc's render-time `cast_operand` into IR CAST ops; printc Stage 3 (`cast_operand`) now renders plain operands + keeps only the constant `markExplicitUnsigned` U-suffix.
- `arithmetic_output_standard` + `output_token` = Ghidra `getOutputToken` overrides (cast.rs), all verified against typeop.cc (shift token = input0 read-facing, bool→int; COPY = input type; etc.).
- is-implied = `merge::implied_classification` (the ActionMarkImplied classifier at its pre-setcasts slot), bounds-safe.
- **PROBE GATE (critical adaptation):** build.rs runs an INTERNAL switch-resolution `decompile` on a `partial` clone (`table_recovery_probe`) whose graph `recover_staged` reads to extract the jumptable. setcasts is render-only and casting the switch-index def under-recovers the table (ifswitch/switchind collapsed to a raw CALLIND). Gated OFF under `table_recovery_probe`, exactly like the late branch-orientation (structure.rs:3035). Switches recovered again.

RESULT (datatest sweep, structural similarity vs oracle --c):
- WINS: **pointercmp 0.9333→1.0000** (flagship), **pointerrel 0.9510→0.9655** (toward-oracle). floatcast/ifswitch/switchind/switchhide intact (probe gate + castInput-first).
- REGRESSIONS (all valid C — ZERO wrong-code; double-cast/`(cast)`-literal/undefined scan clean): **heapstring 0.898→0.833, stackstring 0.933→0.895, partialmerge 0.970→0.941, switchloop 0.969→0.959.** avg 0.9517→0.9507 (net −0.001).
- Suite 495/0 + all integration green, clippy 0.

ROOT CAUSE of the 4 regressions = **the faithful casts SURFACE pre-existing non-Ghidra divergences, amplified because printc RE-CLASSIFIES explicit/implied at PRINT time (AFTER the casts) whereas Ghidra FREEZES ActionMarkImplied BEFORE ActionSetCasts (5720 vs 5735).** Per-fixture:
- partialmerge: mosura types the global `int4`, oracle types it `xunknown8` — a TYPE-INFERENCE divergence. Given mosura's int4 global, `iRam = (int4)param_1` is the CORRECT truncation cast (baseline was UNDER-casting — missing it). Ghidra casts the READ instead (`(int4)xRam`). Faithful; not a cast bug.
- heapstring: oracle REUSES `param_1`'s storage for the loaded pointer (`param_1 = (xunknown8*)*param_1`) — a register-reuse MERGE mosura lacks. Without it the 2-use CAST is impliable (≤ max_implied_ref) and inlined twice.
- switchloop/stackstring: the print-time explicit/implied recompute is perturbed by the inserted casts (temp materialization uVar2/bVar1; array-vs-scalar stack slot) — the **Stage-2 depth-valve the plan flagged** ("ActionSetCasts inserts CAST varnodes → the graph needs re-merge + re-resolution ... the Stage-2 watch").

⇒ DEPTH-VALVE HIT (as predicted). The perturbation-class (switchloop/stackstring, partially heapstring) is the ANALOGUE of Stage 0's retirement, one level up: retire printc's print-time explicit/implied RE-CLASSIFICATION by FREEZING `ActionMarkImplied` in-pipeline before setcasts (set the IMPLIED flag; printc reads it). That reconciliation carries the same churn risk Stage 0c did (must match the current recompute byte-for-byte on the 57 already-matching fixtures) and touches merge/HighVariable — a foundation move. The type/merge divergences (partialmerge global type, heapstring register reuse) are SEPARATE deep foundations. NONE is a cast-port mis-port — the port is verified faithful to coreaction.cc/cast.cc/typeop.cc.

MERGE-GATE STATUS: flagship + pointerrel toward-oracle, zero wrong-code, but 4 fixtures move AWAY (violating "every mover toward-oracle"). Held for LEAD merge-gate decision: (A) land the faithful cast port now and open the freeze-classification + type/merge divergences as follow-ons, or (B) freeze the classification on-branch first (reconciliation-risky) before proposing merge. Committed green on branch for warm-resume either way.

## Stage 2.5 FREEZE LANDED (2026-07-24, branch) — LEAD chose (B); net TOWARD-ORACLE, merge-gate SATISFIED

Ported Ghidra `ActionMarkExplicit`/`ActionMarkImplied` (coreaction.cc:5719-5720) as a real in-pipeline
pass `merge::ActionMarkImplied` that SETS the EXPLICIT/IMPLIED flag on every varnode, on the FINAL
pre-cast graph, run just before `ActionSetCasts` (matching Ghidra's 5720 < 5735 ordering). printc's
`is_explicit` now READS the frozen flag for the cast-sensitive TRAILING chain (written/marker/use-count
+ checkImpliedCover) instead of recomputing it at print time (after the casts). The leading chain
(constant/input/addrtied + SUBPIECE-of-addrtied copymarker) is CAST-INVARIANT so it stays computed in
printc in its original order — its `Some(false)` copymarker case must short-circuit before `high_ram_off`
(revisit's `iRam.._2_2_`); freezing it too was the one reconciliation churn caught + fixed.

RESULT: corpus **0.9517 (baseline) → 0.9527 — NET TOWARD-ORACLE (+0.0010)**, suite 495/0 + integration
green, clippy 0. Per-fixture vs baseline:
- WINS: pointercmp 0.933→1.000, pointerrel 0.951→0.966, **heapstring 0.898→0.941** (the freeze RESTORED
  the 2-use CAST as a NAMED `pVar1 = (xunknown8 *)*param_1`, near-oracle `param_1 = (xunknown8 *)*param_1`).
  switchloop + revisit recovered to baseline (revisit was the fixed churn).
- RESIDUAL (2, both valid C, ZERO wrong-code, CONFIRMED pre-existing-surfaced — NOT cast/freeze bugs):
  **partialmerge 0.970→0.941** — mosura types the global `int4`, oracle `xunknown8`; given int4 the
  `iRam = (int4)param_1` truncation cast is CORRECT (baseline UNDER-cast); a TYPE-INFERENCE divergence.
  **stackstring 0.933→0.895** — array-vs-scalar stack-slot typing (`axStack_20[8]` vs oracle `xStack_20`);
  the `(int8)&xStack_20` cast mosura emits is present in the oracle too (castInput faithful).
- Anomaly scan (double-cast / `(cast)` literal / `undefined` / `))(`) = 2 false positives (indproto,
  switchmulti: valid `(*(code *)x)()` computed calls; indproto scores 1.000). ZERO wrong-code confirmed.

⇒ MERGE-GATE (lead's criteria: net toward-oracle/neutral + zero wrong-code + residuals pre-existing) is
SATISFIED. The two residuals are pre-existing type/merge foundations (global int-vs-unknown inference;
register-reuse merge / stack array-vs-scalar typing), independent of the cast port. Recommend MERGE to
master + open those two as separate deep follow-ons.
