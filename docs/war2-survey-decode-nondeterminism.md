# war2_survey `--le` decode non-determinism (harness bug, NOT the decompiler)

## Symptom
The `war2_survey` full-survey emit (`cargo run --release --example war2_survey -- WAR2.EXE <dir>`)
decodes a handful of functions (~4 of 1286) in the WRONG address-size mode — 16-bit real-mode
(SEGMENTOP, `*segment(seg,off)`, `xunknown2`) instead of 32-bit protected-mode (`*(xunknown4 *)(...)`).
A 16-bit-decoded function emits `*segment(...)` (an undeclared C intrinsic) → Watcom **E1029**
"Expression must be 'pointer to ...'" → COMPILE_FAIL. The SET of affected functions changes
run-to-run, so the survey's per-run COMPILE_FAIL total jitters by a few.

## Why it is NOT the decompiler
The decompiler (type inference, ActionSetCasts, printc) runs AFTER disassembly — it cannot change
instruction decode or address-size. Proof: the canonical single-function path
`dumpwar2 <va>` (= `analysis::decompiler::decompile_function`) renders every affected function as
32-bit compilable C, **identically on any commit** (verified base e9c0655 == branch ir-cast-model for
FUN_00029870/000299d0/0002a03c). Only the `war2_survey` `--le` whole-program path produces the 16-bit
form, and only intermittently.

## Root (hypothesis)
`war2_survey` loads via `analyze_le_file` and decodes all 1286 functions with SHARED whole-program
flow/discovery state. A function's decode mode (16 vs 32-bit) appears to depend on how/when it is
first reached during that shared discovery, which is order-sensitive (likely HashMap iteration
order) → non-deterministic across runs. Pre-existing; affects base and branch surveys equally.

## Practical guidance
- The `war2_survey` COMPILE_FAIL total is a ±few-noisy metric. For a real before/after, compare
  per-CLASS counts and confirm individual "regressions" with `dumpwar2 <va>` (canonical, deterministic)
  before attributing them to a decompiler change.
- Fix (future): make the `--le` survey decode deterministic (stable discovery order / per-function
  address-size from the LE object table, not shared flow state).
