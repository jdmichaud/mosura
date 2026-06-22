# TODO

What remains for mosura. Per-item implementation notes and gotchas live in
`.claude/memory/mosura-project.md`. How to work on this project: see `AGENT.md`.

## Status

Decompiler corpus: **0.615 avg structural similarity to Ghidra, 51/62 x86-64 datatests
decompiled, 17 ≥ 0.70.** `cargo test` green; **254/254 disasm/p-code parity**; datatest
ratchet in `crates/mosura/tests/datatest_score.rs` (avg ≥ 0.61, good ≥ 16).

## Decompiler stages (D0–D6)

- [x] D0 — structured p-code IR + CFG
- [x] D1 — SSA / heritage (dominators, dominance frontiers, Cytron renaming)
- [x] D2 — dead code + simplification rules
- [~] D3 — variable merge + types (pointers + `uint` done; full type system is below)
- [x] D4 — control-flow structuring (`?:`, if/else, do-while, while/for with bodies)
- [x] D5 — C emission (PrintC) + structural comparator
- [~] D6 — datatest parity (measurement harness + several iterations done; ongoing)

## Ports remaining (close the datatest gap)

Each is a faithful reimplementation of the matching Ghidra subsystem — read the C++,
don't invent heuristics (see `AGENT.md`).

- [ ] **Type system** (large) — port `TypeFactory` + `ActionInferTypes`: int1/2/4/8,
      `uint`, `xunknown`/`undefined` widths, type propagation. Biggest single lever
      (mosura is int-everything today).
- [ ] **Floats** (large) — no float support yet (floatprint/floatcast/floatconv/
      longdouble/nan/mixfloatint score 0.13–0.52). `FLOAT_*` p-code, float types,
      emulation, printing.
- [ ] **Switch / jumptable recovery** (large) — no switch recovery (switchind/switchhide/
      ifswitch score low). Ghidra jumptable analysis (`BRANCHIND` target recovery) +
      switch-statement structuring.

## Recommended order

1. Type system (largest corpus lever, next).
2. Floats, then switches.

## Done recently (reference)

CSE / explicit-temp naming (Ghidra `ActionMarkExplicit`: a value with >2 descendants,
or 2 with >2 duplicated terminals, becomes a named temp; spacebase/stack-pointer values
excluded; straight-line path only so far — `twodim` 0.60→0.76, corpus 0.605→0.615);
PrintC integer-base formatting (hex vs decimal); return-type / void analysis;
multi-function chunk handling (restrict to entry-reachable blocks); `LOAD` → `*(ptr)`.
