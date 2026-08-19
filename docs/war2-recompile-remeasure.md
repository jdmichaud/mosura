# Running the WAR2 recompile tooling

How to drive the three in-repo tools that answer, per function: **does the C mosura emits, compiled
by the original toolchain and relinked at the original's address, reproduce the original's bytes?**

This is a usage reference. For what the current numbers are, what is broken and what to work on
next, see [`byte-exact-status.md`](byte-exact-status.md); for why the pipeline is shaped this way,
[`byte-exact-architecture.md`](byte-exact-architecture.md).

## Prerequisites

- `dosemu2` working (there is a `dosemu2` skill).
- Watcom 10.0a at `/home/jd/projects/warcraft2-re/tmp/watcom-experiments/watcom_10.0a/WATCOM`.
- Build the tree you want to measure — the emit uses the current decompiler.
- Put the build target on **local disk**; the project mount is sshfs and far slower:
  `export CARGO_TARGET_DIR=/data/<you>-target`

## The three tools

```sh
OUT=/data/be2/run1                       # local disk; never inside a worktree
WAT=/home/jd/projects/warcraft2-re/tmp/watcom-experiments/watcom_10.0a/WATCOM
EX=$CARGO_TARGET_DIR/release/examples
```

### 1. `war2_survey` — emit

```sh
$EX/war2_survey <war2.exe> <out_dir> [--arms '<θ>;<θ>...'] [--only <va>,...] [--force]
$EX/war2_survey /home/jd/WAR2.EXE $OUT
```

Decompiles every function and writes one standalone compilable `.c` each, plus `manifest.tsv`.
Takes about a minute and a half. Artifacts are stamped with the commit that produced them
(`src.<stamp>/`, `raw.<stamp>/`, `manifest.<stamp>.tsv`) with the bare names as symlinks; re-emitting
at the same clean commit refuses unless `--force`.

- `--only <va>[,<va>...]` is a **read-only probe**: it prints the TU for those functions to stdout
  and writes nothing, so it is safe while a real emit is running.
- `--arms '<θ>;<θ>...'` emits several renderings in one pass — decompiling is θ-independent and is
  essentially the whole cost, so extra arms are nearly free. Arm 0 goes to `src/`; each further arm
  to `src-<tag>/`, where `<tag>` is the vector with `=` replaced by `-`. So
  `--arms 'default;return-width=storage'` gives `src/` and `src-return-width-storage/`.
  What may legitimately be an arm is defined in `decompile::emit::EmitChoices`.

### 2. `recompile_check` — compile, relink, verify

```sh
$EX/recompile_check <binary> <manifest> <src-dir> <flags-file> <watcom-dir> \
    [--only <idx|0xva>,...] [--cache <dir>] [--verbose] [--out <tsv>] [--divergences <tsv>]

$EX/recompile_check /home/jd/WAR2.EXE $OUT/manifest.tsv $OUT/src recover $WAT \
    --cache /data/be2/cache --out $OUT/verdicts.tsv --divergences $OUT/div.tsv
```

Compiles each TU with Watcom under dosemu2, symbolically relinks the object to the original's
address, aligns the two instruction streams and classifies every difference. About eight minutes
cold; seconds once the cache is warm — the cache is keyed on source content, so it survives
re-emits and is worth sharing across runs.

`recover` as `<flags-file>` means "read each function's build flags from its own prologue", which is
the general path since another binary has no flags table. Pass a file instead to override.

`--only` takes a manifest index, a `0x`-prefixed VA, or a function name; with `--verbose` it prints
the full aligned instruction diff for those functions, which is the fastest way to see what a single
function is doing wrong.

### 3. `recompile_select` — pick the winning arm per function

```sh
$EX/recompile_select <tag>=<verdicts.tsv>:<srcdir> ... [--out <tsv>] [--out-src <dir>]

# run stage 2 once per arm first, then:
$EX/recompile_select \
    recovered=$OUT/v-recovered.tsv:$OUT/src \
    storage=$OUT/v-storage.tsv:$OUT/src-return-width-storage \
    --out $OUT/selected.tsv --out-src $OUT/selected-src
```

Only useful with `--arms`. Picks, per function, the first arm that reassembles **exactly**, and with
`--out-src` materializes the winning sources as a directory you can actually recompile. Arms are
tried left to right, so put the reference rendering first.

## The union (arms + per-function selection)

The canonical measurement is THREE selection inputs — the reference rendering, the RECOVERED
tree, and the one still-searched arm — selected per function on the byte verdict (reference
first):

    war2_survey <exe> <out> --arms 'default;local-width=storage' --recovered <out>/recovered
    recompile_check <exe> <out>/manifest.tsv <out>/src        recover <WATCOM> --cache <cache> --out <sbNN>.tsv
    recompile_check <exe> <out>/manifest.tsv <out>/recovered  recover <WATCOM> --cache <cache> --out <sbNN>-rec.tsv
    recompile_check <exe> <out>/manifest.tsv <out>/src-shift-mask-hardware+local-width-storage recover <WATCOM> --cache <cache> --out <sbNN>-lw.tsv
    recompile_select default=<sbNN>.tsv:<out>/src rec=<sbNN>-rec.tsv:<out>/recovered \
                     lw=<sbNN>-lw.tsv:<out>/src-shift-mask-hardware+local-width-storage \
                     --out <sbNN>-select.tsv --out-src <out>/union
    recompile_check <exe> <out>/manifest.tsv <out>/union recover <WATCOM> --cache <cache> --out <sbNN>-union.tsv

**Arm 2 (compare-form + return-split + cond-form as a blanket per-function arm) is RETIRED
(2026-08-18):** the recovered tree makes the same choices per site and took over its whole
contribution but ONE function (`00097`), whose winning difference is a single comparison
spelled `0 <= x` vs `-1 < x` against a register-computed value — no immediate exists in the
original's compare, so the immediate-readout evidence rule correctly abstains. Revival path
for that residual: extend `complement_compares_from_evidence` to read the original's `Jcc`
mnemonic at no-immediate sites. The retirement drops 792 marginal TU compiles per cold
remeasure. The AXES remain in `decompile::emit` — the recovered decisions render through
them per site.

The `--recovered` tree is the FIELD emission — per-site choices decided from the original's
own instructions by the target profile (`buildconfig::*_from_evidence`), no compiler in the
loop. It participates in the dev-time selection because per-site decisions win mixed-want
functions no per-function arm can (sb66: +2 EXACT over the three-arm union), and standalone
it IS what a field `mosura recompile` would ship (sb65: 643 EXACT / 0.3986 WGSS).

The union verdict is taken from the MATERIALIZED tree's own recompile (the last step),
never by joining verdict files. Trap (measured): `--out-src` must land INSIDE the survey
tree (`<out>/union`) — `recompile_check` resolves `../prelude.h` from the source dir, and
a union dir beside the tree compiles every unit against a missing prelude (2,622
COMPILE_FAILs that look like a catastrophe and are a path bug).

## Reading the output

`--out` is one row per function: `idx va name verdict bytes primary sim equal orig_n cand_n
classes`, where verdict is `EXACT` / `SAME_CODE` (same program, different encodings) /
`SAME_SHAPE` (same computation, different registers or constants) / `MISMATCH` /
`COMPILE_FAIL` / `EMIT_FAIL` (no source was emitted) / `OBJ_ERROR`. `equal`/`orig_n`/`cand_n`
are the aligner's instruction counts; rows without a candidate (the last three verdicts)
carry `0 / orig_n / 0` so the global similarity is recomputable from the file alone:

    global sim = Σ equal / Σ max(orig_n, cand_n)

the fraction of the corpus's instructions that recompile identically, instruction-weighted so
a function weighs what it is worth in code. The run prints it under `=== global similarity ===`
next to the unweighted per-function mean (more sensitive to small-function progress). Both are
trend diagnostics between verdict transitions, not targets — the verdicts stay the ground
truth.

`--divergences` is one row per individual difference, and is what to work from:

| col | field | col | field |
| --- | --- | --- | --- |
| 0 | `idx` | 7 | `cand_n` (candidate stream length) |
| 1 | `fn_va` | 8 / 9 | `orig_mn` / `cand_mn` (mnemonics) |
| 2 | `class` | 10 / 11 | `orig_regs` / `cand_regs` (`off:size`) |
| 3 | `addr` | 12 / 13 | `orig_text` / `cand_text` |
| 4 / 5 | `oi` / `ci` (stream positions, `-1` if absent) | | |
| 6 | `orig_n` | | |

Classes: `missing` (the candidate computes LESS — a wrong-code bug), `extra`, `regalloc`,
`immediate`, `operand-form`, `selection`, `branch-target`, `encoding`, and `layout-shift`.

**Filter `layout-shift` out of any census.** It is derived — the same instruction, moved because
something upstream changed size — and it never indicates a cause.

## Environment knobs

| variable | effect |
| --- | --- |
| `MOSURA_PROTO_PASS=1` | whole-program callee prototype recovery before the emit |
| `MOSURA_ARG_DEBUG=1` | per-call argument trials, with the full CALL input list |
| `MOSURA_OPACTION=<action>` | rule/action trace; `<action>` or `1` for all |
| `MOSURA_RAW_IR=1` | post-pipeline IR alongside the C (with `--only`) |
| `MOSURA_EFFECTS_DEBUG=1` | what prototype was propagated to each call |

To find which action changed an op, `awk` for the nearest preceding `DEBUG n: <action>` header above
the changed op in the `MOSURA_OPACTION` trace.

## Gotchas that have cost real time

- `--only` is read-only, but with `MOSURA_PROTO_PASS=1` it still runs the whole-program prototype
  pass first, so debug output covers **every** function. Filter on the call address.
- **`git checkout` reverts the source and leaves the built binary.** Every measurement here runs
  binaries by path (`$EX/war2_survey`), not through `cargo run`, so nothing rebuilds them for you.
  Revert a change, forget the rebuild, and the next emit silently carries the reverted behaviour.
  This produced a 60-function error: three source-level checks — `git status`, `git grep HEAD`, a
  full diff of every changed file — all agreed the tree was clean while the binary disagreed, which
  is exactly the confidence that makes it dangerous. Compare `stat` on the binary against the source
  before trusting a measurement, or rebuild unconditionally.
- `pgrep -f recompile_check` matches your own wait-loop shell. Use `pgrep -x`.
- Two runs' manifests may number functions differently. Join on the **VA** column, never on `idx`.
- A backgrounded `nohup ... &` inside a tool call can be killed at session teardown; use the
  harness's own background mode for anything long.

## Superseded

Earlier revisions drove an out-of-repo harness in `/home/jd/projects/mosura/war2-survey/`
(`compile.sh`, `compare.py`, `wardiff`, `postlink.py`) across three shell processes.
`recompile_check` replaced it by doing compile, relink, align and score in one program, because
splitting the stages let the emit, the objects and the manifest drift apart.

`war2-survey/` remains the historical record and the store for `ghidra-all.txt` (Ghidra's own
decompilation of WAR2, used as an oracle). It is no longer the measurement path, and its
`RELOC_EXACT` verdict no longer exists — relocations are resolved and verified, not masked.
