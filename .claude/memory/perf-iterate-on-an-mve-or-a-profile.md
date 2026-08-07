---
name: perf-iterate-on-an-mve-or-a-profile
description: USER RULE 2026-08-07 — iterate on performance with a small MVE or a profiler, never by timing-out the big test. A cap below every hypothesis answers nothing.
metadata:
  type: feedback
---

**⭐ USER RULE, 2026-08-07: for performance, iterate on a small MVE or a PROFILE. Run the full
uncapped test only once, at the end.**

⚠️ **A capped probe is informative only if the cap sits BETWEEN the competing hypotheses.**
2026-08-07: `le_war2_analysis` was ~880 s; a fix might plausibly bring it to ~250 s. A **150 s cap
times out in both cases** — "no improvement" and "3× faster" are indistinguishable. That probe's
answer was fixed before it ran. It is [[could-it-have-come-out-otherwise]] applied to a
*measurement of myself*, and it wasted a full iteration.

**Use instead, in order:**

1. **A small MVE that exhibits the same scaling.** The defect was quadratic in function count — so
   build a synthetic input with N functions, run at N and 2N and 4N, and read the curve in seconds.
   The MVE-first rule (AGENTS.md directive 6) is not only for correctness; a perf hypothesis is a
   hypothesis and needs an example that can refute it fast.
2. **A profiler.** `perf record` / `perf report` names where the time goes in ONE run, instead of
   binary-searching wall clock over many. "Which function dominates" is a better question than
   "is the total under N seconds", and it is one run rather than five.
3. **Only then**, the full uncapped run — once, to confirm the real number on the real input.

**The general form:** capped probes ([[probe-with-timeouts-dont-wait-for-runs]]) are for **threshold**
questions where you know the threshold discriminates — "does it still build", "does this test still
pass", "is this under the old value". They are useless for **magnitude** questions on a long-running
input. Pick the instrument to fit the question, and check the cap actually separates the answers
before spending the run.

Related: [[could-it-have-come-out-otherwise]], [[mve-first-then-solve-the-mve]],
[[fast-iteration-skip-the-whole-binary-tests]], [[mosura-perf-worktree]].
