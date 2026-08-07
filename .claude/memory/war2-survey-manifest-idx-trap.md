---
name: war2-survey-manifest-idx-trap
description: "WAR2 survey before/after diffs MUST key on the FUN_ name inside each .c, never on the manifest idx — the EMIT regenerates manifest.tsv and the idx->VA mapping shifts."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-29T13:04:18.382Z
---

Every WAR2 survey before/after comparison must key each emitted `.c` by the `FUN_xxxxxxxx` in its
own column-0 definition line — **never** by the manifest `idx`.

**Why:** the EMIT stage (`cargo run --release --example war2_survey`) REGENERATES
`war2-survey/manifest.tsv` in place. When a decompiler change alters function discovery the row
count changes (1286 -> 1303 on 2026-07-29, after `6e1b113` recovered 4 more jump tables), and every
`idx` after the first inserted function shifts. A diff that reads `src.base/{idx}.c` against the
CURRENT manifest is then comparing different functions.

**How to apply:** scan each `.c` for the first column-0, non-`extern` line ending in `)` that
contains `FUN_([0-9a-f]{8})` — that is the file's own function. Build `{va: count}` maps on both
sides and intersect. Alternatively snapshot `manifest.tsv` next to the `src` copy and use the
matching one for each side. `scripts/war2-absolute-gauge.py` is safe when run against its own
contemporaneous manifest, but its `--list-deficits` output re-read later is NOT.

It produced two wrong numbers in one session before being caught: a bogus "-1212 calls lost across
359 functions" (the true answer was -1 in 1 function) and a bogus "226 base deficit functions" (the
true answer was 92). Both looked catastrophic and both were pure index misalignment. See
[[absolute-vs-differential-wrongcode]] and [[measurement-determinism-first]].
