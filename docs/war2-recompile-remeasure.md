# How to re-measure WAR2 byte-exactness

The measurement that asks, per function: **does the C mosura emits, compiled by the original
toolchain and relinked at the original's address, reproduce the original's bytes?**

Everything is in-repo and in-process. Three programs, no shell glue between them — that is
deliberate, and it is why a re-measure is reproducible (see *Superseded* at the end).

## Prerequisites

- `dosemu2` working (there is a `dosemu2` skill).
- Watcom 10.0a at `/home/jd/projects/warcraft2-re/tmp/watcom-experiments/watcom_10.0a/WATCOM`.
- Build the tree you want to measure — the EMIT uses the current decompiler.
- Put the build target on **local disk**: the project mount is sshfs and ~16x slower.
  `export CARGO_TARGET_DIR=/data/<you>-target`

## The three stages

```sh
OUT=/data/be2/run1                       # anywhere on local disk; never inside a worktree
WAT=/home/jd/projects/warcraft2-re/tmp/watcom-experiments/watcom_10.0a/WATCOM
EX=$CARGO_TARGET_DIR/release/examples

# 1. EMIT — decompile every function, one standalone compilable .c each, plus a manifest.
#    ~75 s for 3023 functions.
$EX/war2_survey /home/jd/WAR2.EXE $OUT

# 2. COMPILE + VERIFY — Watcom under dosemu2, symbolic relink, instruction align, byte verdict.
#    ~8 min cold; seconds when the cache is warm (keyed on source content, so it survives re-emits).
$EX/recompile_check /home/jd/WAR2.EXE $OUT/manifest.tsv $OUT/src recover $WAT \
    --cache /data/be2/cache --out $OUT/verdicts.tsv --divergences $OUT/div.tsv

# 3. SELECT (only with --arms) — per function, the rendering that reassembles exactly,
#    written out as a source tree you can actually recompile.
$EX/recompile_select a=$OUT/a.tsv:$OUT/src b=$OUT/b.tsv:$OUT/src-b --out sel.tsv --out-src sel-src
```

`recover` in stage 2 means "read each function's build flags from its own prologue" rather than
from a table — the general path, since a second binary has no table.

## Reading the output

Per-function verdict (`--out`): `EXACT` / `SAME_CODE` (same program, different encodings) /
`SAME_SHAPE` (same computation, different registers or constants) / `MISMATCH` / `COMPILE_FAIL`.

Per-divergence rows (`--divergences`) are the thing to actually work from — one row per difference,
with class, both mnemonics, both register sets, stream position, both renderings. Classes:
`missing` (we compute LESS — a wrong-code bug), `extra`, `regalloc`, `immediate`, `operand-form`,
`selection`, `branch-target`, `encoding`, and `layout-shift`.

`layout-shift` is **derived** — same instruction, moved because something upstream changed size. It
never heads a work-list. Filter it out of any census.

## Sizing a fix BEFORE writing it

The only number that predicts anything is: **how many functions would become divergence-FREE if
this cause were eliminated.** Not "how many functions show this symptom" — that number is always
large and means nothing.

```sh
# marginal value of a cause, from the divergence table
python3 - <<'PY'
import collections
rows=collections.defaultdict(list)
for i,l in enumerate(open('div.tsv')):
    if i and l.split('\t')[2]!='layout-shift': rows[l.split('\t')[0]].append(l.split('\t'))
solo=[f for f,rs in rows.items() if rs and all(<your predicate>(r) for r in rs)]
print(len(solo))
PY
```

Calibration: `ret-n` marginal value said 13 and the fix delivered 11. The register-parameter
widening was sized by a grep over our own signatures at 313 and delivered 1 — see the rejected-fix
note in `byte-exact-status.md`.

## Invariants — do not undo these

- **The reference is the fixup-applied image**, not raw on-disk bytes. `load_le` applies LE fixups;
  a literal equal to the LOADED value is EXACT at this base, and that is the definition. Comparing
  against the raw slice made byte-perfect functions score MISMATCH.
- **Relocations are RESOLVED and verified to the same target, never masked.** Masking would pass a
  candidate that calls the wrong function. The permissive count (identical only outside relocation
  sites) is reported separately and is currently 0.
- **Padding is trimmed semantically, not by byte pattern.** `recompile::trim_padding` drops trailing
  instructions that are no-ops *however spelled* — Watcom's `8b c0` (`mov eax,eax`) as well as
  `90`/`cc`/`00`, and `xchg r,r` on other toolchains.
- **`postlink` is gone and stays gone.** It rewrote `89 ec` out of the compiler's output so bytes
  would match, making every verdict on a framed function a claim about the patch.

## Gotchas that have cost real time

- `--only <va>` is a read-only probe, but with `MOSURA_PROTO_PASS=1` it still runs the whole-program
  prototype pass first, so `MOSURA_ARG_DEBUG` output covers **every** function. Filter on the call
  address.
- `pgrep -f recompile_check` matches your own wait-loop shell. Use `pgrep -x`.
- Two runs' manifests may number functions differently. Join on the **VA** column, never on `idx`.
- A backgrounded `nohup ... &` inside a tool call can be killed at session teardown; use the
  harness's own background mode for anything long.

## Useful knobs

- `--arms 'default;return-width=storage'` — emit several renderings in ONE pass (decompiling is
  θ-independent and is essentially the whole cost). Arm 0 is the ordinary `src/`; each further arm
  gets `src-<tag>/`. See `decompile::emit::EmitChoices` for what an emission axis may and may not be.
- `MOSURA_PROTO_PASS=1` — whole-program callee prototype recovery before the emit.
- `MOSURA_ARG_DEBUG=1` — per-call argument trials, with the full CALL input list.
- `MOSURA_OPACTION=<action>` — rule/action trace; `awk` for the `DEBUG n: <action>` header above a
  changed op to name what changed it.

## Superseded

Earlier revisions of this document drove an out-of-repo harness in
`/home/jd/projects/mosura/war2-survey/` (`compile.sh`, `compare.py`, `wardiff`, `postlink.py`) across
three shell processes. That is replaced by `recompile_check`, which does emit-independent compile,
relink, align and score in one program — because splitting the stages let the emit, the objects and
the manifest drift apart, which silently invalidated batteries more than once.

`war2-survey/` remains useful as the historical record and as the store for `ghidra-all.txt`
(Ghidra's own decompilation of WAR2, used as an oracle). It is no longer the measurement path, and
its `RELOC_EXACT` verdict no longer exists: relocations are resolved, not masked.
