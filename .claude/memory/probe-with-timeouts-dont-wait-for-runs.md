---
name: probe-with-timeouts-dont-wait-for-runs
description: USER RULE 2026-08-07 — run tests partially and kill them with a timeout. A capped run that dies has still answered the question; you rarely need a run to complete.
metadata:
  type: feedback
---

**⭐ USER RULE, 2026-08-07: GO FASTER — run it partially and kill it with a timeout.**

You almost never need a run to *complete* to learn what you need.

**The technique:**
- **Cap every run** (`timeout N`). A run that dies at the cap has still answered *"is it under N?"* —
  which is usually the whole question.
- **Threshold questions are yes/no.** Verifying a perf fix does not need the final number:
  ```sh
  timeout 120 cargo test --release --test analysis_parity -- le_war2 > /tmp/t.log 2>&1
  #   completes -> fixed (was ~880 s)      times out -> still slow
  ```
  Bisect only if the actual figure matters: 120 → 240 → 480. **Three capped runs beat one uncapped
  one**, because each is a decision rather than a wait.
- **Narrow to the one test that matters** (`-- <name>`) while iterating, never the whole binary.
- **Kill the moment the signal is unambiguous.** The tail of a run whose answer you already have is
  pure cost.
- **Use the cheapest tool that fails**: `cargo check` answers "does it build" in seconds; you do not
  need `cargo test` to reach the tests to learn it does not compile.
- Still redirect to a file and grep it ([[redirect-output-then-read-the-file]]) — a killed run's
  partial output is just as readable and is the only copy you get.

⚠️ **Two things this does NOT license:**
1. **A capped run is a PROBE, not a GATE.** The pre-land full suite still runs to completion, once.
2. **Never report a capped run as a pass.** Say *"completed under N s"* or *"still exceeded N s"* —
   never "green". Same discipline as never saying "0 failed" when tests are ignored.

**Context:** a single WAR2 analysis is ~4 min (~15 min while the 4.1× regression stands), the
workspace suite ~10 min. Waiting out full runs to learn one bit was the dominant cost of the
2026-08-07 session, and the user stopped it twice.

Related: [[fast-iteration-skip-the-whole-binary-tests]], [[redirect-output-then-read-the-file]].
