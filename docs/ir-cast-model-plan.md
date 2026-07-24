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
