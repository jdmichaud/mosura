---
name: diagnosed-is-not-fixed
description: USER RULE 2026-08-10 — switch to another task only when the previous one is FIXED. A task diagnosed but not repaired stays OPEN.
metadata:
  type: feedback
---

**⭐ USER RULE, 2026-08-10: switch to another task only when the previous task is FIXED.**

A task that is **diagnosed but not repaired stays OPEN.** Do not mark it completed, do not write it
up as a result, do not move on.

**Why:** on 2026-08-10 I closed task #3 (`00067f40`, shared-return cursor staleness) as
"diagnosed-not-fixed" — stating in the same sentence that the defect was still present — and moved
to the next item. The user stopped it. Writing an excellent post-mortem is not delivery; the
function is still missing.

⚠️ **The failure mode this creates is subtle and I was inside it:** a chain of well-measured
diagnoses reads like sustained progress while the actual number never moves. Four tasks closed in a
row, three of them "measured, no defect / diagnosed, blocked" — and WAR2's missing count went
8 → 8. Depth of understanding is not a substitute for a fix.

**The ONE legitimate case, and state it explicitly:** a task genuinely blocked by another task. Then
- mark it **blocked**, never completed,
- record `blockedBy` so the dependency is machine-visible, not prose,
- and work the **blocker** — which is continuing the same task, not switching away from it.

Anything else — "needs more thought", "the fix is bigger than expected", "I've recorded the
mechanism" — is the task still being open.

⚠️ Corollary for the write-up: a task description that ends in a mechanism with no repair should
read as a **debt**, not an achievement. If the summary sounds like a finding, the status is wrong.

Related: [[always-keep-the-task-list-current]], [[faithful-ports-land-not-held]],
[[i-direct-the-agent-not-the-reverse]].
