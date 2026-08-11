---
name: live-status
description: "The project's current live status — branch pointers, corpus/suite/byte-clean numbers, gauge command and gauge input locations."
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-10T18:57:52.953Z
---

Moved out of MEMORY.md 2026-08-06 (the index is a hook list; this is its detail). Every number
here is STALE unless @sha==HEAD — see [[numbers-stale-unless-sha-stamped]].

## Live status — `master` @ `8b528d6` (2026-08-10), WAR2 perf wave landed, suite FULLY green

Perf round 2 on WAR2 LANDED, 4 commits `c47130c`..`8b528d6`: dense `cover::OpPositions` +
in-tree FxHash + `merge_required` position-rebuild-on-mutation-only (`c47130c`), the
`refresh_covers` one-block trim filter (`79b9843`), docs (`5e648a2`). WAR2 LE end-to-end
94.4s → 50.4s under identical perf-record conditions (Decompiler Switch 69.6 → 25.6s),
analysis output byte-identical at every step; `analysis_parity` 82.9s (handoff target was
106.5s); corpus **0.9569, 58/60 unchanged**; clippy adds nothing (2 pre-existing warnings
remain: thunk.rs `MAX_INSN_LEN`, a merge.rs test unused var). `8b528d6` regenerated all 85
FID databases — the `979bf4b`/`16edaf6` hasher change had left `fid_database_drift` RED at
HEAD (verified pre-existing by stash-rerun); WAR2 output unmoved by the regen. Workspace
suite 39/39 binaries green @`8b528d6`. Next measured perf leads: docs/perf-log.md top
section (ReferenceManager::remove tombstones ~5.6%, sleigh decode ~11%).

## Previous — `master` @ `a4081da` (2026-08-09), `analysis-port` fast-forwarded onto it

**The FID identification arc LANDED on master**, 4 commits `b678279`..`3889dfa`, T1 green on the
master worktree (549 lib tests, clippy 0, corpus avg **0.9569, 58/60**).

- `b678279` — ported Ghidra's `OmfLoader.processRelocations`: **WAR2 120 → 130 named**, nothing
  lost; hash parity vs Ghidra unchanged **308/320**. All 85 databases regenerated. See
  [[unlinked-zero-field-changes-the-decode]].
- `fba99de` — Watcom recall gate from a self-compiled probe (**no WAR2**): 38 names, red on the
  pre-fix databases. See [[self-referential-gates-prove-nothing]].
- `c676964` — Borland gate (small + large models, precision scored against the LINKER MAP) which
  immediately caught a 16-bit regression in `b678279`. See [[synthetic-layout-needs-range-guards]].
- `3889dfa` — a stalled heritage alias probe now fails conservatively.

Databases: **85**, regenerate with `./scripts/rebuild-fid-db.sh` (`-n` to check inputs only).
- `0fe543a` — **heritage non-termination FIXED**: a duplicated CFG edge left one phi slot unwired
  forever. See [[duplicate-edge-needs-the-reverse-index]].
- `a4081da` — **task #8 CLOSED**: `branchRemoveInternal`/`blockRemoveInternal` no longer patch a
  DESTROYED MULTIEQUAL (Ghidra's `opDestroy` removes it from the block; ours leaves it marked
  dead with no inputs). Open Watcom `signl.c` decompiles instead of being skipped.

⚠️ Neither decompiler fix is visible to the corpus (byte-identical): no x86-64 datatest has a
duplicated edge. Their unit tests are the only coverage and both were verified to FAIL without
the fix. The old "overlapping unaligned stack locations" story for #8 is disproven —
see [[gate-what-you-measured-not-what-you-guessed]].

## Historical — `master` @ `1ac5a6d`, work continued on `heritage-spacebase-land` @ `17666ad`
**Heritage core COMPLETE and battery-green, and ON MASTER** — Stage A + Stage B + the spacebase
(stack-trial) half, 8 commits `08ca850`..`1ac5a6d`, fast-forwarded onto master 2026-07-30 (c2950da
was an ancestor; nothing lost, reversible by moving the pointer back).
corpus **0.9534, 58/60**; suite **fully green** (21/21 targets, 0 failures); clippy 0. Headline **12
byte-clean** (5 EXACT + 7 RELOC_EXACT of 1303). Absolute deficit **5 fns / 10 calls**.

**⭐ 2026-07-30, `heritage-spacebase-land` @ `17666ad`: THE STRUCTURED GRAPH IS A LIST, NOT A ROOT**
(see [[structured-graph-is-a-list-not-a-root]]). `PrintC::emitBlockGraph`'s loop + `BlockGoto`'s
carrier ported. **reached==cfg 10 fns / 45 lost blocks → 0/0** (the project's strongest gate is clean
across all 1303 for the first time) · undefined-label 18 → 0 · falls-off-end 1 → 0 · absolute call
deficit 5 fns/10 calls → **1 fn/4 calls with the EMITTER layer at 0** (00079130 is the lone genuine
recovery gap) · 0 functions lose a call · COMPILE_FAIL 102 → 95 · corpus 0.9534/58 unchanged ·
suite 496/0 · clippy 0. ⚠️ **byte-clean UNMOVED at 15 with an identical member set** — no multi-block
function became byte-exact, so that milestone is still open. Next: the call-site-vs-callee prototype
disagreement (task #5 follow-on 1, blast radius = every WAR2 call).

**Wave 1 of the retirement track is underway on `heritage-spacebase-land`:** A3 (hardcoded RSP →
cspec `<stackpointer>`) LANDED `9439fcf` — full battery green, and the placeholder subsystem went
live on x86-32 at **3820 recovered SPACEBASE input trials** (was a structural zero), 98.1%
placeholder resolution, with ZERO call-graph movement. The patch's old held call-drop was CURED by
the heritage core. Next: G1 the alias clone-probe, then F1.
`stageb-spacebase-trials` @62f7812 is a STALE mid-series pointer, deliberately left in place.

## Analysis lane — `analysis-port` @ `fa6794d` (2026-08-06), function DISCOVERY

Separate lane from the decompiler status above; do not conflate the numbers.

**WAR2 function discovery: 3018 functions; 2108 of the tracker's 2120 = 99.4%; 12 missing; 3 entries
inside a tracker body (unchanged, the known secondary entries).** Was 2900 / 2078 / 42 at `556cdb3`.
The jump is `be85c85` — the above-function guard vetoed on ADJACENCY where Ghidra tests
FALL-THROUGH, so a prologue after a `pop…pop; ret` was refused. Gated locally at `4665c2b`
(see [[decoded-not-in-function-needs-address-table]]).

**The 900 not-in-tracker entries are corroborated, not just consistent:** bodies ending in a
terminator, measured against the expert-verified set as a control — **2118: 99.7%, 900: 99.9%**,
indistinguishable. The shape-distribution argument alone was near-circular (the pattern set keys on
shape). Corroborates they are FUNCTIONS; says nothing about boundary correctness.

⭐ **The biggest open gap: a THIRD prologue family — callee-saves with NO frame setup**
(`56 57 83 ec 10`), 7 of the remaining 12. It is `wcc386`'s **default**, since `-of+` is what turns
the frame pointer ON — so it is missing from every default-built Watcom binary, not just WAR2.
Precision is the whole difficulty and is unmeasurable on WAR2; needs a self-compiled fixture.

Compiler-version axis **CLOSED** across 9.01 → 10.0a → 10.6 → 11.0 → OW2: no release changes the
entry shape. Floppy-set installs (7.0/8.5a/9.01/9.5b) work via `INSTALL.EXE` under dosemu — recipe
and its three traps in `docs/watcom-codegen-fingerprint.md`; needs `~/.dosemurc` with
`$_lredir_paths`. See [[watcom-901-anchor-inversion]].

Gauge = `cargo test --test decompile_corpus -- --nocapture`. `cargo xtask baseline` REGENERATES
goldens (leaves 15 untracked x86_64 disasm goldens — don't commit). Gauge inputs live in
`war2-survey/`, NEVER a session scratchpad: Ghidra per-function sweep `ghidra-all.txt` (1286 fns,
not yet extended to the 17 new); durable emission bases `src.landed-c0ac350` (post-land, diff
everything against this) and `src.stageB-08ca850` (pre-land). analyzeHeadless oracle at
/data/tools/ghidra_12.0.3_PUBLIC/build/dist/ghidra_12.0.3_DEV/support/; native ow2 at
~/tools/open-watcom/binl.

**Open:** `FUN_00077dcb` has not recovered its Stage-B-lost call (re-check first in wave 1) · 467 of
1303 WAR2 functions changed their C at the land with zero call movement — documented in
docs/war2-function-status.md so it is not misattributed later.
