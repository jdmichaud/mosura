---
name: invention-inventory-empty
description: "All 3 invented rules retired 2026-07-31; trace-names.py's ADAPTATION list is EMPTY and is now the standing check that the pool never grows another."
metadata: 
  node_type: memory
  type: project
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-31T00:29:55.078Z
---

As of `147adaf` (branch `heritage-spacebase-land`), **`scripts/trace-names.py` reports an empty
ADAPTATION list** — all 148 mosura Rule/Action classes correspond to a Ghidra class. Remaining
non-1:1 relations are declared and justified: 1 MERGE, 3 SPLIT, 1 PARTIAL, 143 SAME, 4 pure naming
pairs. **That empty list is the invariant to hold**; a rule naming no Ghidra class is what the pool
must not grow again, and the audit is the check.

Retired: `RuleMultMult` (5c9afe2, duplicate of RuleAddMultCollapse minus its size mask),
`RuleIdempotent` (9c4bd10, subsumed by RuleTrivialArith except INT_SUB, which Ghidra declines by
decision — `case CPUI_INT_SUB:` is commented out at ruleaction.cc:2394), `RuleRangeAnd` (147adaf,
a hand-rolled special case of RuleRangeMeld's CircleRange merge).

**The method, which is the transferable part:** the name-map audit NAMES the candidate → check
whether mosura ALREADY ports Ghidra's real mechanism, because then the fix is a **deletion** (a
fixed invention is still an invention) → an invariant or byte-level instrument measures reach PER
FUNCTION → **file the prediction before measuring, and say what a miss would mean**. All four
predictions landed exactly; that is what separates "retirement complete" from "retirement
effective". See [[invention-worse-at-its-own-job]] and [[trace-diff-keys-mechanism]].

**Two gate lessons from the arc:**
- *Prove redundancy, don't argue it.* Restricting RuleIdempotent's oplist to only its divergent
  opcode and showing 0 of 1303 WAR2 functions moved is what established that the faithful rule
  covered the rest — reading the two rules side by side would only have suggested it.
- *Gate economy, stated explicitly.* When the emitted C is byte-identical for every function AND the
  manifest is byte-identical, results.tsv, the absolute call gauge, the wrong-code scan and the cast
  census are unchanged BY CONSTRUCTION (all are functions of those two artifacts), so the dosemu2
  compile stage can be skipped. Say so in the commit; never use it when anything moved.

Left behind deliberately, as follow-ons inside the FAITHFUL rule rather than beside it: mosura's
`RuleTrivialArith` accepts only syntactically identical inputs (Ghidra also accepts `isCseMatch`)
and lacks the four FLOAT_* comparison opcodes of Ghidra's oplist.
