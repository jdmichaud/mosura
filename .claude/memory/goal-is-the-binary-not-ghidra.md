---
name: goal-is-the-binary-not-ghidra
description: USER FRAMING (2026-07-28) — the target is byte-exactness with the ORIGINAL BINARY; Ghidra-faithfulness is the METHOD, and the corpus gauge is a diagnostic, never the scoreboard
metadata:
  type: feedback
---

**USER, 2026-07-28: "we are aiming at exactness with the binary, not with what Ghidra produces."**

**Why:** it was already implicit (CLAUDE.md: *"the corpus is a diagnostic, not the target"*) but stating it changes PRIORITIZATION, because several items had been closed on Ghidra-parity reasoning that does not survive the goal test.

**How to apply — the three-layer split:**
1. **METHOD = port Ghidra faithfully.** Unchanged and non-negotiable. It is how we get correct semantics without inventing heuristics; every wrong-code class closed in this campaign came from porting a real mechanism, and every invented shortcut refused would have cost us. Do NOT read this framing as licence for unfaithful decompiler changes.
2. **GOAL = the original bytes.** The scoreboard is the WAR2 recompile — EXACT count, byte-match, band shape. The corpus gauge (mosura vs `oracle/capture --c`) is a DIAGNOSTIC and must never be optimized for its own sake.
3. **WHERE THEY CONFLICT, THE BINARY WINS — resolved at the right LAYER.** Never by unfaithful decompiler hacks; instead by EMITTER/HARNESS work (template: `._0_1_` → `*(uint1 *)((char *)&base + off)`, `cd76111`), or by porting MORE Ghidra where Ghidra is right.

**⚠️ CONCRETE CONSEQUENCE — re-examine every "verified-faithful ceiling".** Items filed as closed because *"Ghidra emits the identical construct and it fails too"* (E1052, ~35 fns; the bare-call-return class) **no longer close under the goal test: matching Ghidra's failure is not success.** If a function cannot compile it cannot be byte-exact, and "Ghidra is equally stuck" is an EXPLANATION, not a RESOLUTION. Those become emitter/harness targets in the same class as the `._0_1_` fix. "Ghidra does it too" ends the FAITHFULNESS question, not the GOAL question.

Also: classification labels (e.g. `cause_guess()`) should describe distance from **the original bytes**, not distance from Ghidra. And per [[self-compiled-ground-truth]], where Ghidra and a known-good self-compiled ground truth disagree, the ground truth wins.

Related: [[war2-byte-exact-campaign]] · [[war2-stackpointer-rootcause]] · [[faithful-ports-land-not-held]] · [[direction-faithful-port]].
