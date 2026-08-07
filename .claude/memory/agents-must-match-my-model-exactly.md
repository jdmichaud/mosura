---
name: agents-must-match-my-model-exactly
description: "USER RULE 2026-08-07 — every sub-agent runs the exact same model, name and version, as the lead. Currently Opus 5 (claude-opus-5[1m]). Verify, never assume."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-07T08:22:52.107Z
---

**⭐ USER RULE, 2026-08-07: sub-agents run the EXACT SAME MODEL as me — same name AND version.**

Currently that is **Opus 5**, exact id `claude-opus-5[1m]`.

**How:** pass `model: "opus"` explicitly on every `Agent` spawn. Never omit it — an agent that
inherits the default silently ran as **Opus 4.8** earlier in this project, which the user caught and
objected to.

⚠️ **Verify, do not assume.** The spawn result does not report which build it bound to, and the tier
name (`opus`) is not a version. Ask the agent to quote its exact model id **verbatim from its own
system prompt** — not its impression of it — and relay that. It should read:

> You are powered by the model named Opus 5 (1M context). The exact model ID is `claude-opus-5[1m]`.

If it reports anything else, or cannot find it stated, **kill it and respawn** rather than continue
on a model mismatch.

**Why it matters:** a weaker agent produces work that looks the same in a report and is not the same
in the artifact — and this project's whole method is that reports are checked against artifacts. A
model mismatch is an unmeasured variable sitting underneath every measurement the agent takes.

Related: [[i-direct-the-agent-not-the-reverse]], [[single-agent-protocol]].
