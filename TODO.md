# TODO — faithful port of Ghidra's decompiler to Rust

**The plan: [`docs/port-plan.md`](docs/port-plan.md).** How to work: [`AGENT.md`](AGENT.md).
Per-feature notes/gotchas: `.claude/memory/mosura-project.md`.

## Direction (read this first)

The objective is to **translate Ghidra's decompiler (C++ → Rust)**, validated against
Ghidra's **intermediate IR, exactly, stage by stage** — not to maximize a final-C
similarity score. The prior similarity-score chase rewarded approximations and punished
faithfulness, and the approximations don't compose. We are re-founding the decompiler
core on Ghidra's actual data model + `Action`/`Rule` pipeline. See `port-plan.md` §0–§3
for the full rationale and architecture.

## Status

- **SLEIGH engine:** done — bytes → instructions + raw p-code, **254/254 disasm/p-code
  parity** (6 arches). Keep. Never regress.
- **Decompiler prototype** (`src/decomp/`): an approximation. Corpus **0.756 avg
  structural similarity, 51/62 x86-64 datatests decompiled, 34 ≥ 0.70**. This is now a
  **coarse secondary gauge**, kept running while the faithful pipeline is built; **not a
  gate** (the `datatest_score` ratchet must never again block a faithful change).
- **Faithful pipeline** (`src/decompile/`, new): not started — P0 below.

## Phases (faithful port — detail in `port-plan.md` §4)

- [~] **P0 — Foundation** (in progress)
  - [ ] Extend `oracle/capture` to dump Ghidra's **per-phase IR** via `decomp_dbg`
        (post-heritage SSA tree, post-types, post-merge, structured blocks, C).
  - [~] `Varnode`/`PcodeOp`/`BlockBasic`/`Funcdata` **graph** data model — **core done**
        in `src/decompile/` (`opcode`/`space`/`varnode`/`op`/`block`/`funcdata`): the
        arena+index Varnode graph with Ghidra's flag set, `OpCode` (CPUI_*), `SpaceManager`,
        create/wire methods, `print_raw`. `BlockBasic` is a stub (CFG built in P1/P7).
  - [x] Build a `Funcdata` from the SLEIGH lifter's raw p-code (`build.rs::raw_funcdata`)
        — produces faithful Ghidra-shaped raw p-code (`output = OPCODE inputs`); graph
        consistency tested on real functions.
  - [ ] `Action`/`Rule` framework skeleton + one trivial action wired through.
  - [ ] `tests/ir_parity.rs` — structural-exact IR diff vs Ghidra (the new gate).
- [ ] **P1 — Heritage** (`heritage.cc`): real SSA + `guard`/`refinement`
      (`normalizeReadSize`/`WriteSize`), MULTIEQUAL/INDIRECT placement, addrtied.
      *Subsumes the entire overlap/CONCAT/phi-leak family — they become consequences.*
- [ ] **P2 — Rule pool** (`ActionPool` + `ruleaction.cc` rules).
- [ ] **P3 — Dead code** (`ActionDeadCode`).
- [ ] **P4 — Types** (`TypeFactory` + `ActionInferTypes`).
- [ ] **P5 — Merge** (`Merge`/`HighVariable`/`Cover` — variable recovery).
- [ ] **P6 — Prototypes** (`FuncProto`/`ParamActive`/`AncestorRealistic` — call-arg/return).
- [ ] **P7 — Structuring** (`BlockGraph::collapse`).
- [ ] **P8 — PrintC** (`printc.cc`) → C-exact parity.

Gate at every phase: mosura's IR matches Ghidra's IR on the datatests before moving on.
Retire the corresponding prototype code as each phase lands.

## Prototype findings worth carrying forward (from the approximation era)

These were the *symptoms* that motivate the faithful port; all are subsumed by P1–P6.
Detailed grounding (Ghidra source refs + why each approximation was net-negative) is in
`.claude/memory/mosura-project.md`.

- **Varnode overlap** (EAX/RAX, XMM 4-vs-8, 64-bit DIV `EDX:EAX`) → **P1 Heritage
  refinement** (`normalizeReadSize`/`WriteSize`). The XMM-only `loc_key` hack and the
  net-negative global-canonical attempt are both retired by faithful heritage.
- **CONCAT struct-packing** (piecestruct/concatsplit) → also **P1 refinement** (a wide
  read of adjacent narrow writes is assembled via PIECE; there are no PIECE ops in the
  raw p-code — heritage reconstructs them).
- **`phi_N` leaks** (nan/elseif) → **P1** (the `Live` args are heritage artifacts of the
  approximate SSA) + **P5 Merge** (surviving MULTIEQUALs become named HighVariables).
- **Call-arg over-counting** (indproto/deindirect2/piecestruct) → **P6** (`ParamActive` +
  `AncestorRealistic` + `forceInactiveChain`).
- **Types / array indexing / casts** (`*(p+8)` vs `p[1]`) → **P4 Types**.
- **Switch / division / floats** — the prototype's `jumptable`/`divrecover`/float handling
  are real Ghidra-grounded ports (`jumptable.cc`, `RuleDivOpt`, `FLOAT_*`); fold them into
  the faithful pipeline as the corresponding rules/actions (P2/P7) rather than re-deriving.

## Superseded docs (history)

`decompiler-plan.md`, `floats-plan.md`, `switches-plan.md`, `type-system-plan.md` describe
the approximation-era feature work. Kept for reference; the live plan is `port-plan.md`.
