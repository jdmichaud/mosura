# Working on mosura

mosura is a CLI **port of Ghidra's logic** (not its UI) in Rust: a SLEIGH disassembler
+ p-code lifter, a p-code interpreter, and a decompiler. Ghidra is the golden oracle —
mosura's output is validated against it.

**Master plan: [`docs/port-plan.md`](docs/port-plan.md). Live status: [`TODO.md`](TODO.md).**

## The one principle: port, don't reinvent — and validate on the IR

This is a **translation** of Ghidra's decompiler (C++ → Rust), not "build something whose
output merely looks similar." Ghidra's C++ is the reference and it is correct (it passes
its own datatests 599/599). When something is wrong or missing, **read Ghidra's source
and reimplement the algorithm faithfully** — do not invent heuristics or approximations.
Cases that feel "ambiguous" (is a function void? what width is an argument? hex or
decimal?) are decided by concrete code in Ghidra; find it and port it.

**Validate against Ghidra's intermediate IR, exactly, stage by stage** — not a fuzzy
final-C similarity score. Hard lesson (see `port-plan.md` §0): optimizing the
token-skeleton similarity score rewards approximations that coincidentally match Ghidra's
tokens and *punishes* faithful algorithms that produce correct-but-different output — it
optimizes *away* from Ghidra, and approximations don't compose. Mirror Ghidra's data
model and `Action`/`Rule` pipeline so faithfulness *is* the metric.

- Ghidra source (pinned to tag `Ghidra_12.0.3_build`): `../ghidra`
- Decompiler core to port: `../ghidra/Ghidra/Features/Decompiler/src/decompile/cpp`
  (e.g. `coreaction.cc`, `printc.cc`, `printlanguage.cc`, `funcdata*.cc`, `type.cc`,
  `jumptable.cc`).

## Layout

```
<workspace>/
  ghidra/   pinned Ghidra source — the reference oracle (do not bump casually)
  mosura/   this project
```

- `crates/mosura/src/sleigh/` — SLEIGH engine (`sla` loader, `engine`, `emu`) + p-code IR.
  **Done, keep, never regress.**
- `crates/mosura/src/decompile/` — **the faithful port (new work)**: Ghidra's data model
  + `Action`/`Rule` pipeline, mirroring `decompile/cpp` file/class names. See `port-plan.md`.
- `crates/mosura/src/decomp/` — the **prototype** decompiler (`cfg`/`ssa`/`simplify`/
  `cprint`/`jumptable`/`divrecover`/`ccompare`). An approximation; kept running as a coarse
  gauge, retired stage-by-stage as the faithful pipeline supersedes it. Don't extend it.
- `oracle/capture.cc` — offline oracle tool, built by `scripts/setup-oracle.sh`.
- `goldens/` — committed disasm / p-code goldens.

## The oracle

`scripts/setup-oracle.sh` (needs the pinned `ghidra/` + a C++ toolchain) builds
`oracle/capture`:

- `oracle/capture <ghidra-src> <fixture.xml>` — dumps disasm + raw p-code.
- `oracle/capture <ghidra-src> <fixture.xml> --c` — dumps **Ghidra's own decompiled C**.
- **P0 work** (`port-plan.md`): extend `capture` to drive `decomp_dbg` to each action
  breakpoint and dump Ghidra's **per-phase IR** (post-heritage SSA tree via `Funcdata::
  printRaw`, post-types, post-merge, the structured block tree) — the per-stage oracle for
  `tests/ir_parity.rs`.

Rebuild after editing `capture.cc`:

```sh
CPP=../ghidra/Ghidra/Features/Decompiler/src/decompile/cpp
g++ -std=c++11 -I"$CPP" -O2 -o oracle/capture oracle/capture.cc \
  -Wl,--whole-archive "$CPP/libdecomp_dbg.a" -Wl,--no-whole-archive -lbfd -lz
```

## Verification (the quality bar)

Every change is verified; never ship semantically-wrong output.

- `cargo test --workspace` — must stay green.
- **`tests/disasm_golden.rs` — 254/254 disasm/p-code parity must NEVER regress.**
- **`tests/ir_parity.rs` (the gate for the faithful port)** — diffs mosura's IR against
  Ghidra's IR at each pipeline stage (post-heritage SSA tree, post-types, post-merge,
  structured blocks, C), **structurally exact**. A phase isn't done until its IR-parity
  is green on the datatests. This is the real port metric; faithfulness *is* the score.
- `tests/datatest_score.rs` — the token-skeleton structural-similarity score over the
  x86-64 datatests. **Demoted to a coarse secondary gauge of overall progress — never a
  gate.** It must not be allowed to block a faithful change (that was the trap). Don't
  ratchet it as a hard threshold anymore; read it as a rough trend.
- `tests/decomp_emit.rs` — exact-output tests for function classes the prototype handles
  (kept while the prototype runs).

Loop for porting a phase: read the Ghidra source for that component → translate it
faithfully into `src/decompile/` (mirroring Ghidra's file/class names) → diff mosura's
IR vs Ghidra's IR at that stage until exact → retire the corresponding prototype code →
record gotchas in memory.

## Conventions

- Respect agreed plan/design decisions; if a decision needs changing, ask first.
- Keep the disasm engine data-driven — no per-instruction or per-arch special-casing.
- Match Ghidra where it is the port target (formatting, structure, types); prefer
  faithfulness over "nicer" output.
- Commit/push only when asked.

## Pointers

- **Master plan: `docs/port-plan.md`.** Live status / phase checklist: `TODO.md`.
- Detailed per-feature notes and gotchas: `.claude/memory/mosura-project.md` (also the
  live auto-memory).
- Superseded (approximation-era, kept for history): `docs/decompiler-plan.md`,
  `floats-plan.md`, `switches-plan.md`, `type-system-plan.md`.
