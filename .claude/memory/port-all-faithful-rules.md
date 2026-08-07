---
name: port-all-faithful-rules
description: "Port EVERY faithful Ghidra rule; never \"decline\" one for being corpus-neutral. The corpus is a diagnostic, not the target."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: c0fe6b35-0fb2-4ed2-90d8-ec93de63680c
---

Port EVERY faithful Ghidra rule. NEVER "decline" a rule because it is corpus-neutral / shows no gain on the 60-fixture set — that is gauge-chasing, the thing the user banned. The corpus is a DIAGNOSTIC, not the target.

- "No speculative dead code" applies to INVENTING heuristics, NOT to porting an existing Ghidra rule — a faithful port is documented + correct-by-construction, never "speculative."
- Precedent: RuleMultiCollapse (`1b8326f`) and RuleLogic2Bool (`6ea3dcc`) landed CORPUS-NEUTRAL as faithful IR-alignment. So is RuleAndMask/RuleSlessToLess/RulePopcountBoolXor (folded into the #3 batch after this correction).
- For a rule with NO corpus firing site: port it AND add a targeted UNIT TEST that constructs the firing input directly (e.g. a synthetic POPCOUNT op-graph) asserting it matches Ghidra — so the port is verified without a corpus fixture. Strictly better than declining.
- The ONLY legitimate "not yet" is a rule genuinely BLOCKED on a subsystem mosura lacks → that's "blocked," not "declined."
- A faithful port is AUTHORITATIVE and stays even if it dips the corpus. A faithful port that seems to regress means some OTHER non-Ghidra code (invented heuristic / approximation / mis-port / still-missing faithful piece) is wrong — change THAT so Ghidra's logic composes; never the faithful port. Only non-Ghidra code is ever in question. (Stated in CLAUDE.md.)
- NO adaptation is grandfathered (user directive, 2026-07-02): any deviation from Ghidra's actual logic/structure — however previously "accepted" (recover.rs INDIRECTs, refine_overlaps/normalize_* laned-scoping, fused RuleDivOpt, etc.) — is CANCELED the moment it blocks a faithful port; replace it with Ghidra's real structure. Past approval never protects an approximation. Faithful cross-language translations that preserve behavior are fine — they ARE the port. This retires the old "USER MAY RE-RULE / justified adaptation" hedges in older memories.
- INSTRUMENT FIRST, hypothesize second (user feedback 2026-07-04, after 4 consecutive wrong source-reading premises on the return-width hunt): when asking "which Ghidra mechanism produces X?", run the trace-diff/oracle FIRST so the firing evidence NAMES the mechanism (one trace pinned RuleSubvarZext instantly after 4 wrong guesses), then read source to understand it. Empirics before theories — even read-only premise checks cost tokens when chained on guesses.
- NEW code is ALWAYS a faithful port, never a hypothesis to measure-then-revert. GROUND read-only until the PREMISE is verified (this is Ghidra's ACTUAL mechanism for the goal AND it produces this result in mosura's pipeline) BEFORE writing code. Reverting is ONLY for pre-existing non-Ghidra adaptations; a revert of NEWLY-written code is a PROCESS FAILURE (non-faithful code was generated → "only port Ghidra" broken) — stop + investigate, never routine. Precedent: P6-2 guardReturns was implemented on an unverified premise (that mosura's return write wasn't already 8-wide, so guardReturns could narrow it — FALSE) then reverted; the failure was GENERATING it, not the revert.

**Why:** the mission is a faithful Ghidra port (see [[direction-faithful-port]]); a rule Ghidra keeps is useful in the general case and will matter on inputs beyond our small test set, even when invisible on it.

**How to apply:** when batching rule ports, filter by "faithful + portable," never by "moves the corpus." Land neutral ones as IR-fidelity; unit-test the unexercised ones. The #9 rule-trace diff exists partly to SURFACE which rules Ghidra fires that mosura doesn't, so the gap is seen, not guessed.
