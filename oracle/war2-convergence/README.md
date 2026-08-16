# WAR2 source-form convergence — working state

Preserved state from hand-converging `FUN_0006c6f0` (WAR2.EXE @ `0x6c6f0`, 1,963 bytes, 536
instructions) toward byte-exact recompilation. The knowledge extracted from it is in
[`docs/byte-exact-source-forms.md`](../../docs/byte-exact-source-forms.md); this directory is the
raw material, kept because re-deriving it is a session of work.

**It is not byte-exact.** Best structural state reached: **177 of 536 instructions matching
exactly** (peak 184 with declaration-order tuning), from 27 at the start. The entry region is
byte-exact through `0x6c74a`, the candidate has exactly the original's 536 instructions, and the
residue is register allocation — see the plateau analysis in the doc.

## Files

| file | what it is |
| --- | --- |
| `FUN_0006c6f0.c` | the hand-converged source at its best structural state (177 matched) |
| `climb.py` | declaration-order hill-climber, scored on matched instruction rows |
| `probe.sh` | one-iteration probe: prints verdict, divergence classes, and the first N real divergences |

`FUN_0006c6f0.c` carries roughly forty reconstructions verified line-by-line against the
disassembly: all nine call sites with their arguments and calling conventions, the address-taken
local buffer, two restored `switch` statements, relocated blocks matching the original's layout
order, integer division (the emitted version had an `int8`/double cast that produced x87 code),
and a `volatile` parameter reproducing the original's per-use stack re-reads.

## Resuming

The loop needs an emit tree to sit in (for the manifest and prelude) — any `war2_survey` output
directory works. Point a scratch source dir at it, drop this `.c` in as the function's index, and
probe:

```sh
# 1. emit a tree (or reuse one)
war2_survey /path/to/WAR2.EXE /scratch/sb

# 2. scratch source dir, prelude alongside it as the compile stage expects
mkdir -p /scratch/exp/src && cp /scratch/sb/prelude.h /scratch/exp/
cp oracle/war2-convergence/FUN_0006c6f0.c /scratch/exp/src/<idx>.c   # idx = this function's manifest index

# 3. one probe (~1s warm)
recompile_check /path/to/WAR2.EXE /scratch/sb/manifest.tsv /scratch/exp/src recover \
    "$WATCOM" --cache /scratch/cache --only <idx> --verbose \
  | awk '/^  0006/{n++} END{print "matched:", n}'
```

Ground truth for reading the original is a plain disassembly of the function's bytes, taken from
the manifest's `orig_hex` column:

```sh
objdump -D -b binary -m i386 --adjust-vma=0x6c6f0 f.bin
```

`climb.py` has the check invocation and paths at the top; point them at your scratch dirs before
running. It hill-climbs the declaration block only — the general search over statement forms is
sketched in the doc's last section and does not exist yet.

## Two things that will bite

* **Score on matched rows, not similarity.** Similarity mixes divergence classes and moved ±0.01
  on changes worth 10 rows.
* **Do structure first, tune declaration order last.** Any structural edit re-rolls register
  allocation and invalidates the tuning — the 184 peak dropped to 172 on the next structural
  change, which is expected, not a regression.
