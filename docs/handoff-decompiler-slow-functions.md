# Handoff: the two functions that dominate every WAR2 analysis run

**Status 2026-08-10 @`41ffc82`.** Round 1 of this handoff was acted on and worked — thank you.
This is round 2, with the analysis-side costs now removed so the remaining number is clean.

## Round 1 outcome (closed)

Handed off `0007a5b0` / `000793e0` / `00051298` as 140.2s of a 196.3s run. The decompiler track
landed `8e4de5a` + `df93e00` + `eb90e1a` (HighVariable membership indexing / `VariablePieces`).

Measured by the analysis track, not taken on report:

| | before | after |
|---|---|---|
| `analysis_parity` suite | 203.13s | **106.48s** (1.9x) |
| `0007a5b0` | 71.63s | **20.09s** |
| `000793e0` | 55.43s | **14.40s** |
| `00051298` | 13.14s | **0.29s** |

`00051298` is done — it is now noise. The other two are not.

## Round 2: they are now 63% of the whole run

WAR2 LE (`analyze_le_file`), `MOSURA_ANALYSIS_TRACE=1`, per-analyzer:

```
analyzer                        invocations   addrs delivered   seconds
Decompiler Switch                        93           387,841      69.9
Constant Propagation                     95           387,841      20.4
Disassembly                             294             9,072       7.1
Create Address Tables                   108        22,405,165       5.6
...
TOTAL                                  1101        25,235,222     111.1
```

`Decompiler Switch` is a thin loop — `find_locations`, `decompile_function` per entry, read back
jump tables. Of its 69.9s, **69.0s is two `decompile_function` calls, each made twice**:

```
000793e0   14.40s  x2  =  28.8s
0007a5b0   20.09s  x2  =  40.2s
                          69.0s   of   111.1s   =  62%
the other 24 decompilations   <0.3s each
```

⚠️ **The double decompile is CORRECT — do not "fix" it.** I checked: the second pass is driven by
*different* computed-jump sites, which only exist because the first pass disassembled the switch
case targets and revealed more switches:

```
pass 1:  locs=[..., 795d5, 7a7d5, ...]                             -> fns=[..., 793e0, 7a5b0, ...]
pass 2:  locs=[797e4, 79900, 79a20, 79b41, 7a9a4, 7aac0, 7abe0, 7ad01] -> fns=[793e0, 7a5b0]
```

Ghidra's `DecompilerSwitchAnalyzer` de-duplicates into a `HashSet<Function>` **within** one
`added()` call only (DecompilerSwitchAnalyzer.java:106-108), so it re-analyses across sets exactly
as we do. The work is real; the per-call cost is the problem.

## What the analysis side has already removed, so the number above is clean

Everything that was analysis-layer cost is gone, and none of it was in your lane:

- `90dd655` — constant propagation asked for a 16-byte window and kept one instruction of ~5.
- `41ffc82` — `ReferenceManager::refs_from`/`refs_to` were linear scans of a `Vec` of >20k
  references, and `get_function_body` calls `refs_from` **once per instruction**. Indexing them by
  source and destination took `analysis_parity` **243.58s -> 146.58s**, and the WAR2 LE run
  197.8s -> 111.1s. Measured cause: `refresh_function_bodies` was 98.0s of the run while the
  constant propagation it serves was 1.0s.

So the 69.0s below is not hiding any analysis-layer defect behind it.

## The ask

Profile `decompile_function` on **`0007a5b0`** (20.09s) and **`000793e0`** (14.40s) on the WAR2 LE
image. They are ~20-40x more expensive than any other function in the binary, which suggests a
super-linear structure rather than a constant factor — the same shape `df93e00` already found once
in `HighVariable` membership.

Reproduce with:

```
cargo build --release --example over_decode
MOSURA_ANALYSIS_TRACE=1 ./target/release/examples/over_decode ~/WAR2.EXE --le
```

`perf` is now usable on this machine (`kernel.perf_event_paranoid=1`):

```
perf record -e cpu-clock:u -F 299 -g -o /tmp/p.data -- ./target/release/examples/over_decode ~/WAR2.EXE --le
perf report -i /tmp/p.data --stdio --sort symbol
```

⚠️ **Rebuild between configuration switches and check the build exit code.** Two measurements in
this session were invalidated by running a stale `target/release/...` binary after a `git revert`,
once because the build had actually failed and the previous binary ran silently.

## Value

Halving these two takes the WAR2 analysis run from ~111s to ~76s, and every verification run in the
project with it. There is nothing else above 8s.
