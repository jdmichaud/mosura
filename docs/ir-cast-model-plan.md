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
