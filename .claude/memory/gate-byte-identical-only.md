---
name: gate-byte-identical-only
description: The self-approve lane is strictly byte-IDENTICAL corpus; ANY fixture movement (even a positive +0.003) is a corpus-mover and must be gated with the lead before landing.
metadata: 
  node_type: memory
  type: feedback
  originSessionId: c0fe6b35-0fb2-4ed2-90d8-ec93de63680c
---

The self-approve (land-without-asking) lane is **strictly byte-IDENTICAL corpus** — every fixture unchanged. The moment ANY fixture score moves, even a single positive one (e.g. the neverConsumed fold's `loopcomment +0.003`, everything else identical), it is a **corpus-mover** and must be **gated**: report delta + cause to the lead and wait for go BEFORE landing.

**Why:** the lead drew the line at byte-identical, not "net-neutral or positive." A positive-only move is harmless in outcome but still crosses the gate boundary; treating it as self-approvable erodes the discipline that keeps corpus changes reviewed. (Lead correction, 2026-07-04, after I self-approved `68a059e` as "byte-neutral" when loopcomment had moved +0.003.)

**How to apply:** before self-approving, diff per-fixture vs baseline. If the diff is empty → self-approve + one-line report. If ANY line moved (±), even up → gate it (report delta + cause, wait for go). See [[port-all-faithful-rules]] (faithful ports are still authoritative; the gate is about the *landing lane*, not whether the port is correct).
