---
name: respect-plan-decisions
description: Process rule — agreed plan decisions must be respected; ask approval before changing any of them
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 460f11fa-22cb-4107-bb63-ef3dbb108516
---

When a decision has been made in the plan, it must be respected. If a change to any agreed decision seems warranted, **stop and ask for the user's approval first** — do not deviate unilaterally.

**Why:** I drifted to bringing the SLEIGH engine up on 6502 when x86-64 was the agreed first arch (decision #4, by dataset count), and I'd been treating a `.sla`-decoder approach as fine when decision #5 says to port the SLEIGH compiler and consume `.slaspec` directly. Both are deviations I made without asking.

**How to apply:** Before changing arch order, the SLEIGH strategy, scope, comparison approach, or any other recorded decision in `mosura/docs/testing-baseline.md` §9 (or elsewhere), surface it explicitly and get approval. Proceeding on plan-aligned work is fine; changing the plan is not, without sign-off. See [[mosura-project]].
