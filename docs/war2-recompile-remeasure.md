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

## The reference: the FIXUP-APPLIED image, not the raw on-disk bytes

`compare.py` scores each object against the **LE-fixup-applied** bytes at the original base — the
same bytes mosura decompiled (`load_le` applies LE fixups, `cbd6295`). The manifest's `orig_hex`
column is exactly those bytes, written by the EMIT from the loaded image, so it is the reference.

This replaced `wardiff.LEBinary.slice_at_linear`, which returns the **raw on-disk** bytes. For any
operand carrying an LE fixup the two differ by the image-base delta (+0x80000 for WAR2.EXE), and
neither side of that comparison carried a fixup record at such a site, so the RELOC_EXACT masking
never fired and a byte-perfect recompile scored MISMATCH. Worked example: `FUN_0005f84c`
(`mov eax,0x88d0c; ret`) compiles to `b8 0c 8d 08 00 c3`, identical to the loaded original, and the
raw slice reads `b8 0c 8d 00 00 c3` — it was scored `MISMATCH @+3`. The fix was worth +3 EXACT on
its own; quoting an EXACT count without saying which reference produced it is meaningless.

Definitions in force:

- **EXACT** — identical to the fixup-applied image. A bare literal equal to the LOADED value is
  EXACT *at this base*; that is the definition, not a concession.
- **RELOC_EXACT** — differs only at sites that are fixups on **both** sides: an LE relocation in the
  original (read from the LE fixup table via `wardiff.LEBinary.fixup_byte_set_in_range`, never
  inferred from which bytes the relocation happened to change — a 4-byte relocation whose delta
  leaves a byte untouched is still one site) **and** a wcc386 `FIXUPP` in the candidate
  (`seg.mask`). A candidate-only or original-only fixup masks nothing.
- A bare literal that is wrong outside such a site stays **MISMATCH**.
- Masked-site counts are printed per function; no mask is ever silent.

The emitter-side follow-up is to render a relocated operand as a symbol reference so wcc386 emits a
`FIXUPP` and the masking fires on both sides — that is what makes the recompiled object
relocatable like the original.

### Trailing alignment padding is not the function

`orig_len` in the manifest is the distance to the next function, so it includes whatever the linker
used to align the next entry. Watcom 10.0a pads with `8b c0` (`mov eax,eax`, the classic 2-byte NOP)
as well as 0x90/0xcc/0x00. Those bytes sit AFTER the `ret`, are unreachable, and are not the
function — comparing against them makes a byte-perfect recompile fail on length alone. `compare.py`
trims a trailing run of them from the ORIGINAL slice (never into or past the terminating `ret`, so
an `8b c0` reached by control flow is untouched) and prints `padtrim=Nb` whenever it does.

Worked example: `FUN_00065ed0/ed8/ee0` each have `orig_len=8` (`a1 xx xx 08 00 c3 8b c0`) and
compile to the *identical* 6-byte object as their `orig_len=6` neighbour `FUN_00065ee8`, which
scored RELOC_EXACT while they scored `len cand=6 orig=8`. Worth +3 RELOC_EXACT, with no decompiler
change: the output was already byte-perfect.

### Two mechanizations (procedure that no longer depends on vigilance)

- **`.compile-complete` sentinel.** `compile.sh` copies its objects back to `obj/` only at the END,
  so the object count climbs from 0 and any wait predicate keyed on it fires early. That raced
  `compare.py` twice — once producing an absurd distribution, once a plausible one, and the
  plausible one is the dangerous version. `compile.sh` now removes the sentinel when a run starts
  and writes it (with `ok`/`fail`/`objects`/`stems`/`finished`) when it completes; `compare.py`
  refuses to run without it and hard-fails if `obj/` disagrees with the recorded count.
- **Comparator identity in the artifact.** `compare.py` prints a `COMPARATOR` string and writes it
  as the first line of `results.tsv`, naming the reference and the fixup rules in force. Restoring a
  stale `compare.py` from a backup silently reverted the fixup-table fix once and was caught only by
  domain knowledge; now every artifact self-identifies and a stale comparator announces itself.
  Bump the string on any definition change.

### The `code` typedef in `prelude.h`

⚠️ **`prelude.h` is GENERATED** — from the `PRELUDE` constant in
`crates/mosura/examples/war2_survey.rs`, rewritten by every EMIT. Edit the constant, never the file;
`cargo run --release --example war2_survey -- --prelude-only <survey-dir>` regenerates the header in
seconds without a 6-minute re-emit. This paragraph previously described a hand-edit to the generated
file: the next EMIT reverted it, the 47 E1052 failures returned, and they were re-adjudicated as a
decompiler ceiling before the drift was found. `compile.sh` now records `prelude_sha=` in
`.compile-complete`, `compare.py` stamps it into `results.tsv`'s header and refuses to score if
`prelude.h` moved since the compile — so a COMPILE_FAIL number can no longer be attributed to a
prelude the run did not use.

`prelude.h` declares `typedef int (*code)();`. It was `void (*code)()`, which cost 46 functions.
mosura renders an indirect call the way Ghidra does, `(*(code *)(ptr))()`; with a void-returning
`code` that expression has type void, so the moment return-value recovery started producing
`iVar9 = (*(code *)(...))();` every such caller failed with `E1052: Expression has void type`
(plus `E1010` behind it). Ghidra's own C has the same shape and does not compile either — the
prelude exists precisely to make it compilable, and a void callee was simply the wrong choice once
the value is used. Measured at `6e1b113`: COMPILE_FAIL **75 -> 29**, E1052 47 -> 0, with the
byte-clean count unchanged at 5 EXACT + 4 RELOC_EXACT. Remaining classes are E1079 (10), E1018 (9),
E1010 (4), E1029 (2), and one each of E1090/E1081/E1080/E1063.

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

### ⚠️ The class counts are FIRST-ERROR-PER-FUNCTION, not errors-present

wcc386 stops at a function's first error, so `results.tsv`'s error class is **the first error in that
function**, not the set of its errors. Every per-class count is therefore conditional on no *earlier*
class growing — and when one class grows it silently HIDES others. This is not a footnote on the
measurement; it is a different measurement than "how many functions have error X".

Worked example (2026-07-30). The isolated A3 delta showed `E1018` (undefined label) going 11 → 7,
which reads as "four labels fixed". Checking each function: **one** was genuinely fixed (`00064d7b`)
and **three were MASKED** by a new earlier `E1011 spacebase` — `00051298`, `0006529f` and `00068902`
all still carry their undefined labels. The real delta was −1, not −4. `E1011` had grown by 56 that
round, which is exactly what buried them.

**Rule: a SOURCE SCAN is authoritative for any class we track; the ladder is a coarse total that
answers only "can it compile".** Give each tracked class a source predicate where one is expressible:

| class | source predicate |
| --- | --- |
| undefined labels (`E1018`) | `scripts/war2-wrongcode-scan.py` — and prefer the stronger `reached == cfg` invariant it is a subset of |
| `spacebase` type leak (`E1011`) | `grep -l 'spacebase' src/*.c` |
| synthesized non-C widths (`E1011`) | grep for `uint6`/`int6`/`uint10`/`uint12`/`uint20`/`xunknown12` |
| undeclared stack locals (`E1011`) | declared-vs-used diff over `[xaiupf]Stack_<hex>` per file |

Same family as the manifest-idx trap and the reference-sides trap: state what the predicate literally
tests. A count you cannot reproduce from source is a count that can move without the defect moving.

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
3. **PREMATURE COMPARE — check the summary line, not the object count.** `compile.sh` copies its
   objects back to `obj/` only at the END of the dosemu session, so `ls obj/*.OBJ | wc -l` is 0 for
   most of the run and then climbs quickly. Waiting on "obj count > 0" and then running `compare.py`
   scored 179 of 1303 objects and printed a meaningless `0 EXACT / 713 MISMATCH / 590 COMPILE_FAIL`.
   **Wait for the `compiled ok=N fail=M` line in compile.sh's own output** before running compare.

4. **MANIFEST INDEX SHIFT across emits.** The EMIT regenerates `manifest.tsv`; if function discovery
   changed, the row count changes (1286 -> 1303 after `6e1b113`) and every `idx` after the first
   inserted function shifts. A before/after that reads `src.base/{idx}.c` against the CURRENT
   manifest silently compares different functions — it produced a bogus "-1212 calls across 359
   functions" (true answer: -1 in 1 function) and a bogus "226 deficit functions" (true answer: 92).
   Key each `.c` by the `FUN_xxxxxxxx` in its own column-0 definition line, or snapshot the manifest
   next to the `src` copy. To score an older emit, synthesize its manifest by mapping
   `src.base/{idx}.c -> va -> the current manifest's row` (`orig_len`/`orig_hex` come from the
   binary, so they are identical per VA in either emit).

5. **STALE EXAMPLE BINARY — not a harness defect; a measurement mistake.** An apparent
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
