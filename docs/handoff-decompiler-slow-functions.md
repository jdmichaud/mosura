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

## Round 2 addendum: the attributed profile (2026-08-10, `perf` call-graph, WAR2 LE)

`perf record -e cpu-clock:u -F 299 --call-graph dwarf,4096`, whole run, `--no-children`. This is
where the 69.0s actually goes — you should not have to re-derive it:

```
 7.52%  core::hash::BuildHasher::hash_one
          6.07%  decompile::build::raw_funcdata_flow_image_overrides
            6.07%  ActionGroup::apply
              5.10%  mergesnip::ActionMergeRequired::apply
                3.17%  hashbrown::map::HashMap::insert
 4.99%  core::hash::BuildHasher::hash_one   (second inlining site, same path)
          3.82%  raw_funcdata_flow_image_overrides -> ActionMergeRequired::apply
 4.70%  decompile::cover::op_index
          3.79%  raw_funcdata_flow_image_overrides -> ActionMergeRequired::apply  2.76%
 3.78%  decompile::cover::cover_of
          2.88%  raw_funcdata_flow_image_overrides
            2.77%  merge::ActionMergeMarkerTrim::apply -> merge::merge_op -> merge::trim_slot 2.28%
 3.31%  hashbrown::map::HashMap::insert          2.73% under ActionMergeRequired
 3.26%  hashbrown::raw::RawTable::reserve_rehash 2.73% under ActionMergeRequired
 3.23%  core::hash::sip::Hasher::write          2.44% under ActionGroup::apply
 2.16%  decompile::mergesnip::merge_required
```

**~27% of the entire run is `mergesnip::merge_required` + `merge::trim_slot` + `cover`.** Two
concrete observations, offered as leads not conclusions:

1. **The hashing is the single biggest line and it is all `ActionMergeRequired`.** `hash_one` +
   `HashMap::insert` + `reserve_rehash` + `sip::write` under that one action is ~10% of the run.
   `reserve_rehash` at 2.7% means the maps are being **grown repeatedly** — a `with_capacity`, or
   reusing one map across calls instead of allocating per call, may be most of it. The default
   `SipHash` is also doing real work here; these keys look like small integer/varnode ids, where a
   cheap hasher is the usual answer.
2. **`cover::op_index` at 4.70%** is called from the same action. If it is a linear scan to find an
   op's index within a block, that is the same defect class as `refs_from` was on our side — an
   index would remove it.

⚠️ Both are guesses from symbol names; I did not read `decompile/` beyond what `perf` named, since
it is your lane. The measurement is solid, the two suggestions are not.

## Round 2 outcome (closed 2026-08-10, decompiler track)

Both leads in the addendum were real, and both are retired:

1. **The hashing was the `op_positions` map.** `merge_required` rebuilt a
   `HashMap<OpId, (usize,usize)>` of every op **per group varnode**, and every `op_index`
   call SipHash-probed it. Op ids are arena indices, so the map is now a flat vector
   (`cover::OpPositions`), `merge_required` rebuilds it only after a snip actually mutates,
   and the `Cover`/liveness sets use a fast integer hash.
2. **`cover::op_index` was not a linear scan** — the 4.7% was the SipHash probing above.
   The real linear-scan analogue was one level up: `trim_slot` rebuilt **every cover in the
   function** per trim, where only the covers touching the one mutated block can change
   (`refresh_covers`).

Measured on the same WAR2 LE run, identical `perf` config, analysis output byte-identical:
Decompiler Switch **69.6s → 25.6s**, traced total **94.4s → 50.4s**. The remaining profile
is flat; the largest single item is back in the analysis lane —
`ReferenceManager::remove`'s hit path (retain + full endpoint-index rebuild per removal,
~5.6% with its frees, under `flow_constants`).

## Why this now blocks the analysis track's own target

Stated target: `analysis_parity` back to **106.48s**, the pre-channel baseline, so the faithful
INSTRUCTION channel costs nothing net. Current **144.71s**. The analysis side has taken it 243.58s
-> 144.71s and its editable surface is now ~5% of the profile (FID 2.58% plus allocator traffic) —
`sleigh/` is another ~10% but is also not ours. **The remaining 38.2s cannot come from our lane.**
