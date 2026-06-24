# Capturing the auto-analysis oracle (A0)

The analysis port validates mosura against the **converged `Program` state** of
Ghidra's auto-analysis (plan `docs/analysis-port-plan.md` §3). This is the analog
of `oracle/capture` for the decompiler, but the oracle is Ghidra's Java analysis
pipeline, not the C++ decompiler — so the capture mechanism differs.

## What a snapshot is

A normalized, line-oriented text view of the converged program, committed under
`goldens/analysis/<name>.snapshot` and parsed by `crate::analysis::snapshot`. v1
records the **loaded memory map** (`block`) and **recovered functions** (`func`)
— the facts the loader (A2) and disassembly/function-discovery (A4) must
reproduce. Later phases extend it with `entrypoint` / `sym` / `data` / `ref`
sections (the parser ignores unknown prefixes, so old goldens keep working).

## Corpus

`oracle/analysis-corpus/` — tiny real ELFs, built by `build.sh` and **committed**
(so goldens are toolchain-stable). `freestanding.elf` is `-nostdlib` (clean,
reviewable: just our functions); `basic.elf` is dynamically linked (realistic:
CRT + PLT thunks + `EXTERNAL`).

## Capture backends

### Today: GhidraMCP (live, faithful 12.0.3)

`analyzeHeadless` is **not runnable** from the source tree as-is — it needs a
packaged distribution (`gradle buildGhidra`). Until that exists, capture via the
**GhidraMCP headless server**, which runs against the pinned build
(`-Dghidra.home=<Ghidra_12.0.3_build tree>`), so its output is genuine 12.0.3:

1. `load_program(file=<abs path to corpus .elf>)`
2. `run_analysis(program=<name>)`
3. dump + normalize into the v1 format:
   - `get_metadata` → header (`lang`, `compiler`, `base`, endian, addr size)
   - `list_segments` → `block <start> <end> <name>` (loaded ranges only; skip the
     `::`-addressed file-overlay blocks — `.comment`, `.symtab`, …)
   - `list_functions` → `func <entry> <name>`
4. write `goldens/analysis/<name>.snapshot`; commit it with the binary.

### Target: analyzeHeadless (offline, per-analyzer staging)

Once `gradle buildGhidra` has produced a distribution, prefer a `-postScript`
GhidraScript that walks the `Program` and writes the v1 snapshot — fully offline
(no running server) and able to enable/disable individual analyzers via a
`-preScript`, which A4/A5 need for stage-by-stage gating. This file should grow
that script when the distribution lands.

## Harness

`crates/mosura/tests/analysis_parity.rs` parses each golden, runs
`analysis::analyze_binary` (Unimplemented today), and ratchets
`EXPECTED_ANALYSIS_PASS` (0 now) toward full corpus parity as A1–A4 land.
