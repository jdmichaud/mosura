# TODO

What remains for mosura. Per-item implementation notes and gotchas live in
`.claude/memory/mosura-project.md`. How to work on this project: see `AGENT.md`.

## Status

Decompiler corpus: **0.746 avg structural similarity to Ghidra, 51/62 x86-64 datatests
decompiled, 33 ≥ 0.70.** `cargo test` green; **254/254 disasm/p-code parity**; datatest
ratchet in `crates/mosura/tests/datatest_score.rs` (avg ≥ 0.74, good ≥ 32).

## Decompiler stages (D0–D6)

- [x] D0 — structured p-code IR + CFG
- [x] D1 — SSA / heritage (dominators, dominance frontiers, Cytron renaming)
- [x] D2 — dead code + simplification rules
- [~] D3 — variable merge + types (pointers + `uint` done; full type system is below).
      **Varnode-overlap: XMM done** (`ssa::loc_key` merges XMM 4-vs-8-byte → mixfloatint
      0.53→0.74, floatprint 0.79→0.90, floatconv ↑). GP overlap (EAX/RAX, 64-bit DIV
      `EDX:EAX`) still exact-size — a wider GP rule perturbs call-arg recovery (net
      negative); needs Ghidra's byte-level coverage to do safely.
- [x] D4 — control-flow structuring (`?:`, if/else, do-while, while/for with bodies)
- [x] D5 — C emission (PrintC) + structural comparator
- [~] D6 — datatest parity (measurement harness + several iterations done; ongoing)

## Ports remaining (close the datatest gap)

Each is a faithful reimplementation of the matching Ghidra subsystem — read the C++,
don't invent heuristics (see `AGENT.md`).

- [~] **Type system** (large, multi-session) — port `TypeFactory` + `ActionInferTypes`.
      **Phased plan + status in [`docs/type-system-plan.md`](docs/type-system-plan.md)**:
      **T0 ✅ done** (`decomp::types` — the `Datatype` lattice + `type_order`); T1
      propagation skeleton not started; **T2 array indexing ⛔ prototyped → measured
      net-negative → reverted** (it types divopt's param as the pointer it is, but
      Ghidra types it scalar — the comparator penalises being *more correct*; needs T1
      to gate it); T3 casts / T4 widths / T5 structs not started. NOTE the comparator
      erases type *names*, so the structural payoff is modest (casts) to negative
      (array indexing) — smaller than first assumed.
- [~] **Division/remainder by constant** — `decomp::divrecover` ports
      `RuleDivOpt::calcDivisor` + the unsigned add-back (`RuleDivTermAdd2`), **signed**
      division (SEXT + sign-correction), and the `x % C` modulo idiom (AST rule +
      multiply association). divopt 0.59→0.78, modulo 0.43→0.46. Remaining: the
      shift-strength-reduced multiples (÷60/÷100 use `x<<k`), the `(x>>k)*m` /
      bare-`x*m`-SUBPIECE division forms, and modulo2's signed-mod-by-power-of-2 idiom.
      **NOTE: modulo's score is now array-indexing-bound** (`*(p+8)` vs `p[1]`, which is
      type-system T2 above — gated behind T1, only 5/62 datatests, regresses divopt).
- [~] **Floats** — **phased plan + status in [`docs/floats-plan.md`](docs/floats-plan.md)**.
      `FLOAT_*` operators ✅; **F1 ✅** (XMM params + 8-byte float return — floatcast
      0.23→0.51); **F4 ✅** (global writes — floatprint 0.19→0.79, convert/displayformat
      →1.00). Remaining: F2 float constants, F3 NAN-comparison fold (`nan` 0.34), F5 SSE
      packing, and mixfloatint's 4-byte return (needs the D3 overlap fix).
- [~] **Switch / jumptable recovery** — **S1–S3 ✅ DONE** (`decomp::jumptable` + S2 CFG
      edges in `build_image` + S3 `Stmt::Switch`): ifswitch 0.36→0.88, switchind
      0.46→0.62. **Plan + status in [`docs/switches-plan.md`](docs/switches-plan.md)**.
      Remaining: S4 variants, switch-in-loop (switchmulti/switchloop), the spurious
      stale-RSP case-call arg, and the dropped mis-aligned case (needs recursive disasm
      at jump targets).

## Recommended order

1. Switch finish: **S4** variants + **switch-in-loop** (switchmulti/switchloop) + recursive
   disasm at jump targets (the dropped mis-aligned case).
2. Float remainders (F2 constants, F3 NAN-fold, F5 SSE packing).
3. GP varnode-overlap via Ghidra's byte-level coverage (unlocks the 64-bit DIV `EDX:EAX`)
   — needs the coverage model so it doesn't perturb call-arg recovery.
4. Type system T1→ (large; modest comparator payoff — lower priority than it looks).

## Done recently (reference)

Floats F4 — global writes (`block_stmts` emits `ram_X = value`; convert/displayformat
→1.00, floatprint 0.19→0.79, corpus 0.637→0.684, 20→25 ≥0.70); Floats F1 — XMM params +
8-byte float return (floatcast 0.23→0.51, corpus 0.622→0.637); type-system T0 — the
`Datatype` lattice (`decomp::types`); loop-body CSE (a loop variable whose new value also
appears in a body statement — a load that is stored and carried — is emitted once and
referenced; threedim 0.65→0.76, corpus 0.619→0.622, 18→20 ≥0.70); FLOAT_* operators
(build_op → `+`/`<`/`NAN()`…);
Signed division + `x % C` modulo recovery (`recover_signed_div` + AST modulo idiom +
multiply association; modulo 0.43→0.46, array-index-bound aggregate flat at 0.619);
Division-by-constant recovery (`decomp::divrecover`: `calcDivisor` 128-bit port +
unsigned add-back recogniser → `x / C`; divopt 0.59→0.78, corpus 0.615→0.619);
CSE / explicit-temp naming (Ghidra `ActionMarkExplicit`: a value with >2 descendants,
or 2 with >2 duplicated terminals, becomes a named temp; spacebase/stack-pointer values
excluded; straight-line path only so far — `twodim` 0.60→0.76, corpus 0.605→0.615);
PrintC integer-base formatting (hex vs decimal); return-type / void analysis;
multi-function chunk handling (restrict to entry-reachable blocks); `LOAD` → `*(ptr)`.
