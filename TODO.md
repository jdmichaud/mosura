# TODO

What remains for mosura. Per-item implementation notes and gotchas live in
`.claude/memory/mosura-project.md`. How to work on this project: see `AGENT.md`.

## Status

Decompiler corpus: **0.619 avg structural similarity to Ghidra, 51/62 x86-64 datatests
decompiled, 18 ≥ 0.70.** `cargo test` green; **254/254 disasm/p-code parity**; datatest
ratchet in `crates/mosura/tests/datatest_score.rs` (avg ≥ 0.615, good ≥ 17).

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

- [ ] **Type system** (large, multi-session) — port `TypeFactory` + `ActionInferTypes`:
      the `Datatype` lattice, type propagation, int1/2/4/8 / `uint` widths, pointers,
      arrays. Biggest single lever (mosura is int-everything today). **Phased plan in
      [`docs/type-system-plan.md`](docs/type-system-plan.md)** — note the comparator
      erases type *names*, so the structural payoffs are array indexing (T2) and casts
      (T3); the array-vs-scalar typing is inference-driven and *must* be ported (a
      heuristic regresses divopt). First score win is T2, after the T0/T1 foundation.
- [~] **Division/remainder by constant** — `decomp::divrecover` ports
      `RuleDivOpt::calcDivisor` + the unsigned add-back (`RuleDivTermAdd2`), **signed**
      division (SEXT + sign-correction), and the `x % C` modulo idiom (AST rule +
      multiply association). divopt 0.59→0.78, modulo 0.43→0.46. Remaining: the
      shift-strength-reduced multiples (÷60/÷100 use `x<<k`), the `(x>>k)*m` /
      bare-`x*m`-SUBPIECE division forms, and modulo2's signed-mod-by-power-of-2 idiom.
      **NOTE: modulo's score is now array-indexing-bound** (`*(p+8)` vs `p[1]`).
- [ ] **Array/pointer indexing** (`p[i]` vs `*(p + i*sz)`) — the highest *structural*
      lever the comparator rewards: appears in twodim/threedim/divopt/modulo/offsetarray/
      nestedoffset/… Needs pointer element-size inference (part of the type system) to
      divide the byte offset by the element width. Would compound with all the above.
- [~] **Floats** (large) — `FLOAT_*` ops now render as C operators + `ABS`/`SQRT`/`NAN`
      intrinsics (`build_op`); nan 0.33→0.36. But the float datatests are blocked on the
      hard parts: **XMM register modeling** (float params in XMM0-7 stride 0x40, float
      return in XMM0 — mosura's int-only param map returns `void` for mixfloatint),
      **SSE packing** (CONCAT44/SUB16xx for floatcast/floatconv), **globals**
      (floatprint stores to absolute `ram` addresses), and the unordered-compare /
      NAN idioms. Each substantial; floats remain a large multi-feature effort.
- [ ] **Switch / jumptable recovery** (large) — no switch recovery (switchind/switchhide/
      ifswitch score low). Ghidra jumptable analysis (`BRANCHIND` target recovery) +
      switch-statement structuring.

## Recommended order

1. Type system (largest corpus lever, next).
2. Floats, then switches.

## Done recently (reference)

Signed division + `x % C` modulo recovery (`recover_signed_div` + AST modulo idiom +
multiply association; modulo 0.43→0.46, array-index-bound aggregate flat at 0.619);
Division-by-constant recovery (`decomp::divrecover`: `calcDivisor` 128-bit port +
unsigned add-back recogniser → `x / C`; divopt 0.59→0.78, corpus 0.615→0.619);
CSE / explicit-temp naming (Ghidra `ActionMarkExplicit`: a value with >2 descendants,
or 2 with >2 duplicated terminals, becomes a named temp; spacebase/stack-pointer values
excluded; straight-line path only so far — `twodim` 0.60→0.76, corpus 0.605→0.615);
PrintC integer-base formatting (hex vs decimal); return-type / void analysis;
multi-function chunk handling (restrict to entry-reachable blocks); `LOAD` → `*(ptr)`.
