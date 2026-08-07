---
name: i-direct-the-agent-not-the-reverse
description: "USER RULE 2026-08-07 — I direct the agent at all times; I always know what it is doing; if there is ever doubt, kill it and start a new one with a known task."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-07T07:43:40.918Z
---

**⭐ ABSOLUTE USER RULE, 2026-08-07.**

1. **I direct the agent. The agent does not direct me.** I decide what it works on next. I do not
   accept "taking #5 unless you redirect" as the mechanism — I answer explicitly, before it starts.
2. **At all times I know what the agent is doing.** Not "it reported X twenty minutes ago" — what it
   is doing *now*.
3. **When the user asks for status, I give it with no mistake.**
4. ⚠️ **If there is any doubt about what it is doing, I have lost the plot: KILL IT and start a new
   one with a known, single, explicit task.** Doubt is the trigger — not confusion, not failure.

**Why:** on 2026-08-07 the agent twice started work I had not sanctioned while a different
instruction was in flight — it took #4 when told to land the held patch, then proposed #5 while the
patch was still unapplied. Both times our messages crossed and I *reported* to the user that it was
landing the patch when it was not. The user had to stop it. Reporting a state I had inferred rather
than checked is the same error as every measurement error in this campaign, applied to the agent
instead of to a binary.

**How to apply:**
- Give ONE task per message, with an explicit stop condition. Never a menu, never "unless you
  redirect", never silence-as-consent (the agent even offered that and I let it stand).
- Before answering a status question, **check** (`git log`, `git status`, `ps`) — do not paraphrase
  the last report.
- Crossed messages are the failure mode: if a reply arrives that answers a *previous* instruction,
  assume the current one has not been seen and re-issue it alone.
- A long-running agent drifts. Prefer short, single-task agents killed at the boundary over one
  agent given a backlog.

Related: [[single-agent-protocol]], [[hard-rules-never-stop-one-agent]],
[[numbers-stale-unless-sha-stamped]].
