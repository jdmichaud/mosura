---
name: could-it-have-come-out-otherwise
description: "Before measuring, ask whether the result could have come out the other way — a predicate with a fixed answer looks like evidence and measures nothing"
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-08-05T09:27:56.532Z
---

**Before running any measurement, ask: could this have come out the other way?** If no, it is
not a check — it is a restatement of its own inputs wearing the costume of evidence.

**Why:** this failure produced four separate wrong conclusions on 2026-08-05 alone, in both
directions (mine and the agent's), and each one *looked* like a result:

1. **A tautological question.** I asked the agent to decide whether the 29 missed for-loops were
   bugs by checking "does Ghidra also emit a `while` there?" The missed set is *defined* as
   `ghidra_fors - mosura_fors`, so Ghidra emits a `for` in all 29 by construction. The answer was
   fixed before any file was opened.
2. **Equal totals across a real change.** The agent's first use-before-def detector counted the
   DECLARATION as a read, flagged 1072 of 1303 functions, and returned an *identical total* on
   four different images. It looked stable while measuring nothing.
3. **Set identity inferred from equal counts.** "The 40 missed for-loops ARE the 40 false
   comma-whiles" — equal totals, never checked for membership. Real intersection: 12.
4. **Reading an artifact mid-write.** I quoted manifest row counts from a file the emit was still
   writing, and "verified" a consumer against them.

**How to apply:** state, before running it, what the *other* outcome would look like. If you
cannot describe a concrete result that would falsify the claim, redesign the measurement. Then
check set MEMBERSHIP rather than totals ([[gauge-counting-traps]]), measure ABSOLUTELY rather
than differentially ([[absolute-vs-differential-wrongcode]]), and confirm the artifact is
finished before reading it ([[war2-survey-artifacts-stamped]]).

This is the *pre-flight* half; the equal-totals rule (now `docs/measurement-rules.md` §6) is the
*post-hoc* half — it catches a broken predicate after the run is spent, this catches it before.

**Corollary, learned the same day:** a generalisation drawn from one observation is the same
defect in explanation form. I wrote into `loopcomma.c` that "a global has no register phi, so no
`for` is formed"; Ghidra recovers `for` loops over plain globals — ram is heritaged — and five
WAR2 functions prove it. The MVE's *effect* was real and its gate re-proves it every run; only my
*mechanism* was invented. **When an MVE depends on an effect, state the effect as observed and
mark the cause unestablished** unless it is verified, because the next editor reasons from what
the file says. See [[mve-first-then-solve-the-mve]].
