---
name: hard-rules-never-stop-one-agent
description: "THREE ABSOLUTE user rules (2026-07-24) — never stop; exactly one agent, remove-before-create"
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-25T07:48:13.495Z
---

THREE ABSOLUTE RULES (user, 2026-07-24, stated with strong emphasis — non-negotiable, supersede any inclination to pause/consolidate/ask):

**Rule 1 — NEVER STOP.** Do not end a turn in an idle/parked/"waiting for you" state. Always have work in flight. Do not consolidate-and-wait, do not "I'll stop here", do not offer to bank. Keep the campaign moving.

**Rule 2 — If you WANT to stop, you DON'T.** The urge to pause (context feels long, "we're done", "safe stopping point") is exactly when to keep going. Override it.

**Rule 3 — EXACTLY ONE AGENT; REMOVE-BEFORE-CREATE.** Never launch an agent if one already exists — EVEN IF IT IS IDLE / rate-limited. The sequence is ALWAYS: (1) TaskStop the existing agent, THEN (2) spawn the new one. Never two in parallel (they collide on the shared working tree). Before every Agent spawn, confirm zero agents exist (stop the current one first).

Related: [[single-agent-protocol]] (this hardens it), [[dont-stop-take-first-option]] (rule 1/2 harden it). Token-cost is NOT a reason to stop on my own initiative (the user cares about progress, not about idling to save tokens) — but DO minimize wasteful tool calls / verbosity.

**THE ONE OVERRIDE (2026-07-24):** an EXPLICIT user instruction to stop wins over rules 1/2 — e.g. "stop once this task is done, we won't have the budget to go further." When the user says that: finish the named unit, tell the agent to stand down (do NOT let it claim the next task), give one consolidated report, and stop. Do not invent budget concerns myself; only an explicit user stop-instruction ends the loop.
