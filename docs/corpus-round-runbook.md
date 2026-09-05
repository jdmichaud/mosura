# Running a corpus round

How to answer, per function of a subject binary: **does the C mosura emits, compiled by the
original toolchain and relinked at the original's address, reproduce the original's bytes?**

This is a usage reference for the `mosura` command line (the product; `docs/product/architecture.md`).
For what the current numbers are and what to work on next, see
[`byte-exact-status.md`](byte-exact-status.md); for why the pipeline is shaped this way,
[`byte-exact-architecture.md`](byte-exact-architecture.md). The rules for quoting a number are in
[`measurement-rules.md`](measurement-rules.md) (§9 the one WGSS, §10 the identity gate).

## Prerequisites

- `dosemu2` working (there is a `dosemu2` skill) and Watcom 10.0a installed (the `watcom.install`
  key of `dev-config.toml` names the WATCOM directory on this machine).
- Build the tree you want to measure — the emit uses the current decompiler:
  `CARGO_TARGET_DIR=/data/<you>-target cargo build --release -p mosura-cli` (a local disk; the
  project mount is sshfs and far slower). Every command below is `$M = $CARGO_TARGET_DIR/release/mosura`.
- A session directory on local disk, never inside a worktree: `-S /data/be2/<session>` (~100 MB per
  program plus ~40 MB per emission). `df -h /data` first — the floor is 4 GB.

## One-time session setup

```sh
S=/data/be2/session
$M -S $S add <subject.exe>                       # content-addressed input
$M -S $S analyze --loader le                     # the native LE view; cached by content + options
$M -S $S toolchain add watcom --spec watcom-10.0a-dos --install <WATCOM dir>
$M -S $S config set compile.cache=/data/be2/cache # reuse the shared compile cache IN PLACE (never copy it)
$M -S $S round import tb --verdicts /data/be2/tb-rec.tsv --divergences /data/be2/tb-div.tsv \
        --manifest /data/be2/tb/manifest.tsv     # the baseline series as a round
```

`toolchain add` records the CHOICE (the spec) in the session config and the LOCATION in the machine
config (`~/.config/mosura/config.toml`, or `--config <file>`); the library never reads the machine
file. `mosura toolchain specs` lists the specs; `mosura toolchain check watcom` compiles one unit
through the compiler — the explicit liveness probe.

## The round

```sh
$M -S $S round run f9 --toolchain watcom --baseline f8 \
    --gates <subject-profile>/corpus-gates.tsv --label "what changed"
$M -S $S round compare f8 f9
```

`round run` is the whole measurement in one operation: the recovered emission (every function's
translation unit, then the caller-side callee-pragma post-pass — `program.emit`, cached by the
program's passes and the emit options), the text gates 1–6 over the TUs, one compile batch
(cached on source content, so an unchanged function is free; locked per install directory, so
two rounds can never share a dosemu session), the symbolic relink and instruction alignment of
every candidate, the verdict rows, the verdict gates 7–8 against `--baseline` (no EXACT lost, no
new failure verdict; every other down is listed under the WGSS delta) — all stored under
`rounds/f9/` as `verdicts`, `divergences`, `gates` and `manifest` tables. The command exits 1 when
a gate fails; the tables stay as the evidence. `round show f9` prints the manifest: the build id,
the stage fingerprints, the program/passes/emission keys, the toolchain identity, the ARMS STAMP
(the rendering policy — what `# arms:` was), the options tag, the census, WGSS structural and
byte-strict, units compiled/cached/fresh.

`round compare a b` joins the two rounds BY ADDRESS (never by row order): the census of each,
every verdict flip, every similarity mover, the net and the insn-weighted delta (= ΔWGSS over the
rows both rounds hold), membership drift. `round list` is the census of every round.

Repeat until stable (`round run f9b --baseline f9`): the second run must report every unit cached
and `round compare f9 f9b` must show 0 flips and 0 movers. A round that crossed an ENOSPC is VOID.

### The smoke run (before a full round)

```sh
$M -S $S round run smoke-1 --toolchain watcom --scope list \
    --scope-file <subject-profile>/smoke.expected.tsv --expect <subject-profile>/smoke.expected.tsv
```

The pinned sentinels compile and every one must keep its expected verdict (gate 9, smoke drift);
a partial round skips gates 4–6 audibly. Drift in either direction fails the run: diagnose before
spending a full round.

### One function

```sh
$M -S $S recompile 0x<va>|<name> --toolchain watcom [--verbose]   # emit → compile → verify; exit 1 unless EXACT
$M -S $S emit 0x<va>                                               # the TU alone
$M -S $S decompile 0x<va> [--as raw]                               # the C / the post-pipeline IR
$M -S $S verify 0x<va> <object.obj>                                # an object you compiled yourself
```

`--verbose` prints the aligned instruction diff (`=` equal, `~` differs with its class, `-`
missing, `+` extra). `recompile <fn>` uses the program's whole emission when the session holds one
(the post-passed TU the round measured), else the function's own TU — the survey's `--only` probe.

## The identity gate (a change that must move nothing)

```sh
$M -S $S emit --all --out /data/be2/<cand>
diff -rq /data/be2/<base>/recovered /data/be2/<cand> | wc -l     # must print 0
$M -S $S round show <round> --format tsv | grep '^arms'           # the arms stamp, identical
```

No compiler is involved (measurement rules §10). The files are named by the emit index
(`NNNNN.c`) like the survey's `recovered/` tree, so an old tree diffs directly.

## Reading the output

`round show f9 --table verdicts` (or `round export f9 --out f9-rec.tsv`, the legacy 11-column
TSV with the `SIM=structural` stamp): one row per function, `idx va name verdict bytes primary sim
equal orig_n cand_n classes`, where verdict is `EXACT` / `SAME_CODE` (same program, different
encodings) / `SAME_SHAPE` (same computation, different registers or constants) / `MISMATCH` /
`COMPILE_FAIL` / `EMIT_FAIL` (no translation unit — the decompile failed) / `OBJ_ERROR`. Rows
without a candidate carry `0 / orig_n / 0`, so the census is recomputable from the table alone:

    WGSS = Σ orig_n·sim / Σ orig_n       (the one canonical census, measurement rules §9)

`round show f9 --table divergences` (or `round export f9 --divergences f9-div.tsv`) is one row per
individual difference, and is what to work from:

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

The census scripts (`scripts/corpus-*.py`) read the exported legacy TSVs.

## Knobs

Every knob is an option key (`mosura ops`, `mosura schema option_registry`): `-o key=value` on any
command, or the typed sugar. `emit --arms-off a,b` / `-o emit.arms-off=…` and `-o knobs.off=…`
switch a render arm or a pipeline switch off (one name space on the command line: `--arms-off
cmp-sign,proto-pass`); the arms stamp records it. `--debug <topics>` selects diagnostic topics
(`debug.*` keys never enter a cache key). The emission models Ghidra's STANDALONE global-scope
context unless `-o decompile.global-scope=application` says otherwise (the binary is the emitter's
oracle; the application context's anchored forms cost EXACTs, measured).

The suite has one plan-closure test: `arm_enabled_emit_passes_wherever_plain_passes_in_the_32bit_column`
(tests/ground_truth_recompile_arms.rs, the gcc ground-truth oracle over the arm-enabled emit). It is
`#[ignore]`d, so the per-commit iteration suite does not run it; the closure suite at the end of a
plan runs it alone with `cargo test --release --test ground_truth_recompile_arms -- --ignored`, as
does any commit that changes what it tests: the gt oracle, the emit plan or an arm (JD, 2026-08-28).

## Gotchas that have cost real time

- **`git checkout` reverts the source and leaves the built binary.** Every measurement runs the
  release `mosura` by path; nothing rebuilds it for you. Rebuild unconditionally before measuring.
- A round measures the emission its options select: a different `-o` set is a different emission
  (and a different passes set). `round show` records the options tag and the arms stamp — read
  them before comparing two rounds.
- Join on the **VA**, never on `idx` (two emissions may number functions differently).
  `round compare` does; the legacy TSVs sort by va before a `diff`.
- A backgrounded `nohup ... &` inside a tool call can be killed at session teardown; use the
  harness's own background mode for anything long.
- `rounds/<name>` is never overwritten: pick a new name for every run.

## Superseded

The 2026-08/09 series was driven by three examples (`corpus_emit`, `recompile_check`,
`corpus_gates`) and three scripts (`corpus-round.sh`, `corpus-smoke.sh`, `corpus-verdicts.sh`),
retired 2026-09-05 at verdict-equivalence: one CLI round reproduced the baseline table
`/data/be2/tb-rec.tsv` row for row (`docs/product/plan-wp7-2026-09-05.md` §3 P3). Their
functions live on as operations (`program.emit`, `round.run`, `round.compare`, `round.gates`);
their output formats are the legacy export. Earlier still, an out-of-repo harness
(`compile.sh`, `compare.py`, `wardiff`, `postlink.py`) across three shell processes was replaced
by `recompile_check` because splitting the stages let the emit, the objects and the manifest drift
apart — the reason the round is now ONE operation over ONE store. The union of arms and the
per-function selection (`recompile_select`) were retired 2026-08-18: the recovered emission
dominates the reference rendering (zero functions where the reference is EXACT and the recovered
tree is not), so selection adds nothing; `--arms` stays an investigation tool in the emit axes.
