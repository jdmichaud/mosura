---
name: always-keep-the-task-list-current
description: "USER RULE 2026-08-07 — the task list is always up to date. Update it as state changes, not when asked."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-07T08:09:12.450Z
---

**⭐ USER RULE, 2026-08-07: ALWAYS KEEP THE TASK LIST UP TO DATE.**

The task list is the shared source of truth for what is happening. It is updated **as state
changes**, never as a batch when the user asks for it.

**Update immediately when:**
- work starts (`in_progress`) or finishes (`completed`) — including work *I* do, not just the agent's;
- an agent is stopped or dies — set its task back to `pending` and say what, if anything, survived;
- a premise turns out to be wrong — rewrite the description, do not leave a wrong task standing;
- a measurement lands — put the number in the task, since a task carrying a stale number is worse
  than one carrying none;
- a task becomes blocked or unblocked — maintain `blockedBy` as dependencies actually change;
- new work is discovered — create it then, while the context is fresh, not later from memory.

**Why:** on 2026-08-07 the list went stale in several ways at once — #1 sat `in_progress` after both
halves had landed, #7 sat `in_progress` after the agent was stopped with nothing committed, #6's
baselines were superseded, and #10's justification had been measured away. The user had to ask for
an update. A stale list means my status answers are inferred rather than read, which is the same
failure as [[i-direct-the-agent-not-the-reverse]] in another register.

⚠️ Corollary: **descriptions carry the evidence, not just the intent.** A task whose premise was
refuted must say so, with the measurement — otherwise the next session re-derives the same wrong
lead. Several tasks this week were rewritten in place for exactly this reason and the rewrites were
the most valuable part of the list.

Related: [[i-direct-the-agent-not-the-reverse]], [[redirect-output-then-read-the-file]],
[[numbers-stale-unless-sha-stamped]].
