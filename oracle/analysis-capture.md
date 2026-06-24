# Capturing the auto-analysis oracle (A0)

The analysis port validates mosura against the **converged `Program` state** of Ghidra's
auto-analysis (plan `docs/analysis-port-plan.md` §3) — the analog of `oracle/capture` for
the decompiler, but the oracle is Ghidra's Java analysis pipeline, not the C++ decompiler.

## What a snapshot is

A normalized, line-oriented text view of the converged program, committed under
`goldens/analysis/<name>.snapshot` and parsed by `crate::analysis::snapshot`. v1 records
the **loaded memory map** (`block`) and **recovered functions** (`func`) — the facts the
loader (A2) and disassembly/function-discovery (A4) must reproduce. Later phases extend it
(`entrypoint` / `sym` / `data` / `ref` + function body ranges); the parser ignores unknown
prefixes, so old goldens keep working.

## Corpus

`oracle/analysis-corpus/` — tiny real ELFs, built by `build.sh` and **committed** (so
goldens are toolchain-stable). `freestanding.elf` is `-nostdlib` (clean, reviewable: just
our functions); `basic.elf` is dynamically linked (realistic: CRT + PLT thunks + `EXTERNAL`).

## Reproducing from scratch (fresh environment)

```sh
# 0. Workspace layout: <ws>/ghidra is a clone of the Ghidra repo at tag Ghidra_12.0.3_build;
#    <ws>/mosura is this project. (git -C ghidra describe --tags  =>  Ghidra_12.0.3_build)

# 1. Build the C++ decompiler oracle (decomp_dbg, sleigh_opt, .sla, …) used by the decompiler port.
mosura/scripts/setup-oracle.sh

# 2. Build a runnable Ghidra DISTRIBUTION (so analyzeHeadless works — the source clone alone
#    refuses with "Cannot launch from repo"). Idempotent; ~6 min first time.
mosura/scripts/build-ghidra-dist.sh        # -> <ghidra>/build/dist/ghidra_*_DEV/support/analyzeHeadless

# 3. (Re)generate the analysis goldens from that distribution.
mosura/scripts/capture-analysis.sh         # -> goldens/analysis/*.snapshot

# 4. Gate.
cargo test -p mosura --test analysis_parity
```

Order note: step 1 drops un-headered oracle binaries into Ghidra's `src/decompile/cpp/`,
which would trip Ghidra's own `ip` (license-header) task. `build-ghidra-dist.sh` moves those
generated artifacts aside for the build and restores them, so step 1↔2 order is safe — but
building the dist on a pristine clone is cleanest.

## Oracle backend: analyzeHeadless (primary)

`scripts/capture-analysis.sh` runs `analyzeHeadless` with the `DumpAnalysisSnapshot.java`
post-script (`oracle/ghidra_scripts/`) over each corpus binary. It walks the `Program` and
emits the v1 snapshot. Offline, version-pinned, and able to run under a controlled analyzer
set (a `-preScript`) for the per-stage gating A4/A5 will need. One-binary invocation:

```sh
DIST=<ghidra>/build/dist/ghidra_12.0.3_DEV
"$DIST/support/analyzeHeadless" <proj_dir> tmp -import <binary> \
  -scriptPath oracle/ghidra_scripts -postScript DumpAnalysisSnapshot.java <out.snapshot> -deleteProject
```

Two environment gotchas (handled by the scripts; documented here so they aren't
rediscovered):
- **Locale.** Gradle's SBOM step (during `assembleDistribution`) expands every jar; the
  jgrapht jar contains a class named `Sørensen…` (non-ASCII). If the JVM's `sun.jnu.encoding`
  is ASCII (it can be even when `LANG=…UTF-8`), expansion dies "Cannot expand ZIP". The build
  must run under a UTF-8 locale (`LC_ALL=C.UTF-8`).
- **`ip` pollution.** See the order note above.

## Oracle backend: GhidraMCP (secondary / cross-check)

If a GhidraMCP server is running against the same pinned build (`-Dghidra.home=<the clone>`),
its output is genuine 12.0.3 and can cross-check the headless capture (this is how the first
goldens were taken, before the distribution was built). Steps: `load_program(file)` →
`run_analysis(program)` → dump `get_metadata` (header), `list_segments` (loaded blocks only —
skip the `::`-addressed file-overlay blocks), `list_functions` (`func`), normalize to v1.
The headless and MCP captures have been verified **identical** for the current corpus.

## Harness

`crates/mosura/tests/analysis_parity.rs` parses each golden, runs `analysis::analyze_binary`
(Unimplemented today), and ratchets `EXPECTED_ANALYSIS_PASS` (0 now) toward full corpus
parity as A1–A4 land.
