---
name: trace-diff-first-not-fifth
description: "Run scripts/trace-diff.sh FIRST on any \"why doesn't mosura produce Ghidra's X\" — four instrument passes were spent inside a rule Ghidra never fires."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-29T18:34:14.411Z
---

On the piecestruct width question (task #6 B-4, 2026-07-29) I chained instruments through mosura's
FAILING path — heritage guard ranges, then `SubvariableFlow::do_trace` exit paths, then the
`setReplacement` consume gate, then the declines ordered by pass. Each pass was clean and each
conclusion was true. Then `scripts/trace-diff.sh piecestruct`, run fifth, showed that
**`subvar_and` fires ZERO times in Ghidra on that fixture** — neither side uses it. Four passes of
correct analysis, none of it load-bearing.

What the trace named instead, in one command: `andmask` (ghidra 27 / mosura 28) and `subzext`
(26 / 19) both missing at the SAME seven addresses, plus a 4-firing `subvar_zext` deficit — and
`shiftpiece` EQUAL at 4/4, so the rule the hard test is named after was never the missing one.

**Why:** starting from mosura's failing rule assumes mosura is attempting Ghidra's mechanism. When
that assumption is wrong, every downstream instrument measures the wrong machine correctly. The
trace answers "which mechanism does Ghidra actually use" directly, and it is one command.

**How to apply:** for any "why doesn't mosura produce Ghidra's X", run `scripts/trace-diff.sh
<fixture>` BEFORE reading source or instrumenting mosura's path. Let the firing evidence NAME the
rule, then read that rule's source. This is already AGENT.md rule 5 and a task #3 standing rule —
the failure was not knowing it, it was not reaching for it first.
Related: [[rule-trace-diff-tool]], [[faithful-type-of-wrong-ir]], [[measurement-determinism-first]].
