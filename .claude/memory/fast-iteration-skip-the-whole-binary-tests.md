---
name: fast-iteration-skip-the-whole-binary-tests
description: The inner loop is 13x faster by skipping four whole-binary tests — 367s to 27s. Caching analysis across tests does NOT help; cargo already runs them in parallel and the cost is one long test per binary.
metadata:
  type: reference
---

**⭐ THE INNER LOOP IS 13× FASTER. Measured 2026-08-07.**

```sh
# FAST ITERATION — ~27 s total, covers 40 of the 46 tests in these two binaries
cargo test --release --test analysis_parity      -- --skip le_subjects --skip pe_mz
cargo test --release --test ground_truth_parity  -- --skip ground_truth_parity

# PRE-COMMIT — the full pass, ~10 min, ALWAYS before landing
GHIDRA_SRC=/home/jd/projects/mosura/ghidra cargo test --release --workspace > /tmp/suite.log 2>&1
```

Measured, each with everything else unchanged:

```
analysis_parity          223.01 s  ->  11.18 s   (skip 3 whole-binary tests; 21 still run)
ground_truth_parity      143.74 s  ->  16.37 s   (skip 1 corpus-wide test;  19 still run)
                         ------              -----
                         ~367 s        ~27 s
```

**The cost is concentrated in four tests, each of which analyzes a real program end to end:**
`le_subjects_analysis`, `pe_mz_convergence_parity`, `pe_robustness_cnv` (already `#[ignore]`d as
"slow (~140 s)"), and the corpus-wide `ground_truth_parity`. Everything else is fast.

⚠️ **CACHING ANALYSIS ACROSS TESTS DOES NOT HELP WALL CLOCK — measured and nearly wrong about it.**
Four tests in `analysis_parity` each looped over the same corpus, so every binary was analyzed 4×.
Adding a process-level memo took 230 s → 223 s: **noise.** Cargo already runs tests in parallel
threads, so the redundant loops were overlapping, not stacking, and the duration is set by the
SLOWEST SINGLE TEST, not by total work. The memo is kept (it saves CPU on a 5-core box where tests
contend) but it is not the lever, and it must not be cited as one.

⛔ **Do NOT `#[ignore]` the slow tests to make the default suite fast.** That hides them behind
"0 failed", which is the reporting trap already recorded — the ignored tests are exactly what
measures residual defects. Skip them **at the command line during iteration**; never weaken the
committed gate.

⚠️ Report as *"N pass, 0 unexpected failures, K known-red gates skipped by design"* — never
"0 failed" — whenever anything is ignored or skipped.

Related: [[redirect-output-then-read-the-file]], [[measurement-determinism-first]].
