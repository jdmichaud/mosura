# Working on mosura

mosura is a CLI **port of Ghidra's logic** (not its UI) in Rust: a SLEIGH disassembler
+ p-code lifter, a p-code interpreter, and a decompiler. Ghidra is the golden oracle —
mosura's output is validated against it.

## The one principle: port, don't reinvent

This is a port. Ghidra's C++ is the reference and it is correct (it passes its own
datatests 599/599). When something is wrong or missing, **read Ghidra's source and
reimplement the algorithm faithfully** — do not invent heuristics or approximations.
Cases that feel "ambiguous" (is a function void? what width is an argument? hex or
decimal?) are decided by concrete code in Ghidra; find it and port it.

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
- `crates/mosura/src/decomp/` — decompiler: `cfg`, `ssa`, `simplify`, `cprint`
  (emission), `ccompare` (structural comparator).
- `oracle/capture.cc` — offline oracle tool, built by `scripts/setup-oracle.sh`.
- `goldens/` — committed disasm / p-code goldens.

## The oracle

`scripts/setup-oracle.sh` (needs the pinned `ghidra/` + a C++ toolchain) builds
`oracle/capture`:

- `oracle/capture <ghidra-src> <fixture.xml>` — dumps disasm + raw p-code.
- `oracle/capture <ghidra-src> <fixture.xml> --c` — dumps **Ghidra's own decompiled C**
  (the reference for the decompiler comparator).

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
- `tests/datatest_score.rs` — scores mosura's C against Ghidra's over the real x86-64
  decompiler datatests (via `capture --c` + the structural comparator). Ratchet the
  asserted thresholds (avg / ≥0.70 count / decompiled count) **up** as coverage grows;
  never loosen them.
- `tests/decomp_emit.rs` — exact-output tests for the function classes mosura handles.

Loop for porting a decompiler feature: diff mosura vs `capture --c` on a datatest to
find the gap → read Ghidra's code for that gap → port it → re-measure the corpus →
add/extend a test → bump the ratchet.

## Conventions

- Respect agreed plan/design decisions; if a decision needs changing, ask first.
- Keep the disasm engine data-driven — no per-instruction or per-arch special-casing.
- Match Ghidra where it is the port target (formatting, structure, types); prefer
  faithfulness over "nicer" output.
- Commit/push only when asked.

## Pointers

- Remaining work: `TODO.md`.
- Detailed per-feature notes and gotchas: `.claude/memory/mosura-project.md` (also the
  live auto-memory).
