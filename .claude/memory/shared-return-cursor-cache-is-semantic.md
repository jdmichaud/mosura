---
name: shared-return-cursor-cache-is-semantic
description: "SharedReturnAnalysisCmd's functionBefore/AfterSrc \"caches\" change the answer — dropping them over-creates functions; and mosura's whole-program invocation is the remaining divergence."
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-05T10:46:28.865Z
---

`SharedReturnAnalysisCmd.applyTo`'s `functionAfterSrc` / `functionBeforeSrc` look like lookup
caches. They are **not** an optimisation. `functionBeforeSrc` is re-queried only once the
ascending walk has passed `functionAfterSrc`; while frozen it holds the function-before of an
EARLIER address, always ≤ a fresh query, so `destAddr < functionBeforeSrc` fails where a fresh
query would pass. Ported verbatim in `crates/mosura/src/analysis/analyzers/shared_return.rs`
(commit `c86a78e`, 2026-08-05).

**Why:** re-querying freshly each time invented the subject functions at three shared epilogues
(0x51e12 / 0x53254 / 0x78039) that Ghidra does not create. Verified by running Ghidra's OWN
`SharedReturnAnalysisCmd(wholeProgram, true, false)` from a headless script: **1944 → 1944**
functions, none created. That is the way to settle "would Ghidra do X?" for any analysis command —
call the command directly rather than reasoning about the analyzer's event scheduling.

**How to apply:** the remaining known divergence is **invocation granularity**. mosura calls the
command ONCE with `set` = every function (`analysis::shared_return_pass`); Ghidra calls it per
newly-created function (it is a `FUNCTION_ANALYZER`), so the cursors re-prime constantly. That is
why the subject's `FUN_00067f40` is still not recovered — its fresh `function_before(0x69032)` = 0x68f25
passes the test, but the carried cursor declines it. Fixing it means making shared-return a
scheduled analyzer inside `AutoAnalysisManager` — blocked on its dependency on `plt_linear_sweep`
+ `compute_function_bodies` running first. Do NOT "fix" it by dropping the cursors; that trades
one recovered function for three false positives.

Related: [[reftype-is-post-override-not-the-instruction]], (subject-profile note `tailjmp-mve`).
