# How to run the WAR2 recompilation re-measure (agent reference)

The measurement that classifies every WAR2.EXE function by recompilation fidelity
(EXACT / RELOC_EXACT / MISMATCH / COMPILE_FAIL / DECOMPILE_FAIL). Run it whenever a decompiler
change might move WAR2's COMPILE_FAIL count — it is the payoff proof for compile-fail work.

The harness lives OUTSIDE the repo in `/home/jd/projects/mosura/war2-survey/` (uncommitted driver
scripts). The in-repo half is the EMIT example `crates/mosura/examples/war2_survey.rs`.

## Prerequisites
- Build the branch/HEAD you want to measure (the EMIT uses the current mosura decompiler).
- `dosemu2` must work (there is a `dosemu2` skill — invoke it if unsure). Watcom 10.0a lives at
  `/home/jd/projects/warcraft2-re/tmp/watcom-experiments/watcom_10.0a/WATCOM`.
- `warcraft2-re` must be present (`/home/jd/projects/warcraft2-re/tools/wardiff`, `.../postlink.py`).

## The three stages — run in order

### 1. EMIT (decompile all 1286 functions → C + manifest)
The compile/compare scripts are HARD-CODED to `ROOT=/home/jd/projects/mosura/war2-survey`, so the
EMIT must write INTO that dir (it regenerates `raw/`, `src/`, `manifest.tsv` in place). Save the
prior `results.tsv` first if you want a before/after.

```
cd /home/jd/projects/mosura/mosura
cp /home/jd/projects/mosura/war2-survey/results.tsv /home/jd/projects/mosura/war2-survey/results.prev.tsv 2>/dev/null || true
cargo run --release --example war2_survey -- /home/jd/WAR2.EXE /home/jd/projects/mosura/war2-survey
```
Takes ~6 min. Produces `war2-survey/{raw,src}/*.c` + `manifest.tsv` (1286 rows).

### 2. COMPILE (⚠️ CLEAN obj/ FIRST — the #1 gotcha)
`compile.sh` does NOT clean `obj/` between runs; stale `.OBJ` from a prior run silently mask new
COMPILE_FAILs → a WRONG (undercounted) number. ALWAYS:

```
rm -f /home/jd/projects/mosura/war2-survey/obj/*.OBJ /home/jd/projects/mosura/war2-survey/obj/*.obj
cd /home/jd/projects/mosura/war2-survey && bash compile.sh --      # `--` = all stems in src/
```
One dosemu session drives a BAT loop compiling `src/NNNNN.C → obj/NNNNN.OBJ` with wcc386
(`-4r -fpi87 -s -of+ -onatx` for framed fns / `-4r -fpi87 -s -onat` frameless, chosen per the
original prologue in `manifest.tsv`), then postlinks the redundant `89 ec` epilogue. The wcc386 log
lands in `dos/WCCOUT.TXT` (compare.py reads it for the first-error class per function).

### 3. COMPARE (classify + write results.tsv)
```
cd /home/jd/projects/mosura/war2-survey && python3 compare.py
```
Diffs each `obj/NNNNN.OBJ` against the original WAR2.EXE bytes via warcraft2-re `wardiff` (LE +
OMF-FIXUPP reloc masking), writes `results.tsv`, prints the per-status summary.

## Reading the result / the delta
```
# distribution:
awk -F'\t' '!/^#/ && $4!="status" {c[$4]++} END {for(s in c) print s, c[s]}' war2-survey/results.tsv
# COMPILE_FAIL by wcc386 error class (E1010/E1029/E1063/…):
awk -F'\t' '$4=="COMPILE_FAIL"{e=$5; sub(/:.*/,"",e); c[e]++} END {for(x in c) print c[x], x}' war2-survey/results.tsv | sort -rn
# before/after delta: diff the class counts vs results.prev.tsv
```
Baselines for reference: post-Stage-1 = 229 COMPILE_FAIL; post-Brick-1 (pointer casts) clean = 112;
DECOMPILE_FAIL = 0 since the Stage-0 panic fix. Total = 1286.

## Wrong-code scan (required when new functions compile)
When a change makes functions newly COMPILE, confirm none compiles to WRONG bytes: a function that
was COMPILE_FAIL and is now MISMATCH with a very low byte-match, or EXACT/RELOC that regressed, is
suspect. Cross-check a sample against `oracle/capture --c` / analyzeHeadless. Faithful casts must
not turn a right-but-uncompilable function into a wrong-but-compilable one.

## ⚠️ Trust the survey path before quoting its numbers

Three separate harness defects have made survey numbers wrong or unattributable. Two are fixed; one
is open. Check the open one before a re-measure is used as evidence.

1. **Decode non-determinism — FIXED** (`74cb0ae`). The whole-program `--le` survey re-read the SLEIGH
   specs per function over a network mount; a failed `.pspec` read silently yielded addrsize=0
   (16-bit real mode) and phantom `segment(...)` compile-fails, so per-run COMPILE_FAIL jittered.
   `lang::load_cached` now resolves each language once per process and fails loudly on a spec-read
   error. Detail: `docs/war2-survey-decode-nondeterminism.md`.
2. **Synthesized-declaration gap — FIXED** (`a1d3e98`). `war2_survey.rs` declared an `extraout_`/
   `unaff_`/`in_`/`Ram` identifier as a pointer only when it appeared *indexed* (`ident[`), never
   when *dereferenced* (`*ident`), producing phantom `E1029: Expression must be 'pointer to ...'`
   against a decompiler that had typed the varnode a pointer correctly.
3. **STALE EXAMPLE BINARY — not a harness defect; a measurement mistake.** An apparent
   survey-vs-canonical disagreement (`FUN_00070f4d`'s compare operand rendering as a pointer under
   `war2_survey` and as an integer under `dumpwar2`, same binary and same commit) was neither path
   being wrong: **`cargo build --release` does NOT rebuild `examples/`.** Running
   `./target/release/examples/war2_survey` directly after a lib-only rebuild executes the *previous*
   decompiler, while `cargo run --release --example dumpwar2` rebuilds first. The two dumps came
   from different code. Verified: touch a decompiler source, `cargo build --release` recompiles the
   lib and leaves every `target/release/examples/*` mtime unchanged. With both rebuilt the two paths
   agree exactly.

   **Always invoke the EMIT as `cargo run --release --example war2_survey ...`** (as the Stage 1
   command above does) — never the bare binary. Same for `dumpwar2`/`dumpc` when comparing against a
   just-changed decompiler.

## Notes
- The scripts' `ROOT` is hard-coded — either EMIT into `war2-survey/` (recommended) or edit `ROOT`
  in `compile.sh`+`compare.py` to a fresh dir.
- Don't commit the survey working dir or `war2-survey/*` (it's outside the repo, deliberately).
- `results.prefix.tsv` / `results.postfix.tsv` in the dir are historical Brick-1 before/after runs.
