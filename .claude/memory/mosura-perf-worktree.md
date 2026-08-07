---
name: mosura-perf-worktree
description: "Perf work (2026-07-02) merged into master at 6f62b45 — 3x loop iteration, byte-neutral; worktree and branch removed; tooling docs in README + docs/perf-log.md"
metadata: 
  node_type: memory
  type: project
  originSessionId: a75244f9-b292-4392-bc38-faa8a7320e59
---

The 2026-07-02 performance work is MERGED into `master` (HEAD `6f62b45`); the `perf-work`
branch and `mosura-perf` worktree were deleted. Loop iteration (rebuild + suite) went
~75s → ~25s, decompile pipeline ~17× faster over the corpus, all byte-neutral (corpus
avg 0.8649/54 unchanged).

**Why:** the Ghidra-port loop was bottlenecked on mosura execution; these numbers are
the new baseline for spotting future perf regressions.

**How to apply:** perf history + next candidates (ActionPool per-round re-sort, heritage
alias probe, mold/lld install) live in `docs/perf-log.md`; usage of the instrumentation
(`MOSURA_PERF=1`, `examples/perf_corpus`, `build/oracle-cache/`, `speccache`) is in the
README. The dev profile is now `debug = "line-tables-only"` + `opt-level = 1` — set
`debug = 2` locally for a debugger session.
