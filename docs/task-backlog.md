# Task backlog (backup)

Snapshot of the working task list, in case the task tracker is reset. Status as of the
current checkpoint. Decompiler stages are D0–D6; the `Port …` items are the concrete
Ghidra subsystems still to port to close the datatest gap.

Corpus status at this snapshot: **0.605 avg structural similarity vs Ghidra, 51/62
x86-64 datatests decompiled, 16 ≥0.70.** Suite: 33 tests / 16 groups green, 254/254
disasm parity. Ratchet: `crates/mosura/tests/datatest_score.rs` (avg ≥0.59, ≥0.70 ≥15,
decompiled ≥50).

## Decompiler stages

| # | Task | Status |
|---|------|--------|
| 9  | D0a: Structured p-code IR (PcodeOp/Varnode) | ✅ completed |
| 10 | D0b: Funcdata + CFG (basic blocks + edges) | ✅ completed |
| 11 | D1: SSA / heritage (dominators, phi, renaming) | ✅ completed |
| 12 | D2: dead code + simplification rules | ✅ completed |
| 13 | D3: variable merge + initial type recovery | 🟡 in_progress (pointers + uint done; full TypeFactory is #21) |
| 14 | D4: control-flow structuring | ✅ completed |
| 15 | D5: C emission (PrintC) + structural comparator | ✅ completed |
| 16 | D6: iterate decompiler to datatest parity | 🟡 in_progress (measurement harness + several iterations done) |

## Ports (close the datatest gap — faithful reimplementations of Ghidra logic)

| # | Task | Status | Notes |
|---|------|--------|-------|
| 17 | Port PrintC integer formatting (hex vs decimal) | ✅ completed | `most_natural_base` + `val≤10→decimal` (printc.cc); matches Ghidra |
| 18 | Port HighVariable/CSE temp-variable naming | ⬜ pending | **NEXT.** Name a multiply-used value instead of recomputing it (threedim recomputes a LOAD twice; Ghidra names it once). Touches the build_expr core — do carefully |
| 19 | Port return-type / void analysis | ✅ completed | `void_def` + two-pass rebuild with empty live-out |
| 20 | Port parameter/argument count from cspec convention | ✅ completed | main issue (multi-function chunks) fixed via reachable-block restriction; precise cspec arg-count is a possible later refinement |
| 21 | Port TypeFactory + ActionInferTypes (data types) | ⬜ pending | **LARGE.** Central type subsystem: int1/2/4/8, uint, xunknown/undefined widths, type propagation. Biggest remaining differentiator (mosura is int-everything) |
| 22 | Port float support (ops, types, emulation) | ⬜ pending | **LARGE.** No float support today; floatprint/floatcast/floatconv/longdouble/nan/mixfloatint score 0.13–0.52. FLOAT_* p-code, float types, emulation/printing |
| 23 | Port switch / jumptable recovery | ⬜ pending | **LARGE.** No switch recovery; switchind/switchhide/ifswitch score low. Ghidra jumptable analysis (BRANCHIND target recovery) + switch structuring |

## Recommended order to resume

1. **#18 CSE/temp-variables** (moderate, next).
2. **#21 types** (largest single corpus lever — every var/param shows `int` vs Ghidra's typed output).
3. **#22 floats**, **#23 switches** (unlock the currently near-zero float/switch datatests).

Full per-port implementation notes and gotchas are in the auto-memory:
`~/.claude/projects/-home-jd-mosura/memory/mosura-project.md`.
