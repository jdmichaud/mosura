---
name: gate-what-you-measured-not-what-you-guessed
description: A debug dump that omits one field invented a whole wrong root cause; and a faithful-looking port written on a hypothesis still has to be reverted
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 6a216fa6-e69f-4b20-b0bf-429f1307092c
  modified: 2026-08-09T08:46:38.234Z
---

**⭐ 2026-08-09, task #8.** Two mistakes in one investigation, both worth not repeating.

**1. The dump that omitted a field invented a root cause.** `Loc` in `heritage.rs` is
`(space, offset, SIZE)`. My first dump printed `(l.0, l.1, has_free)` — space, offset, flag —
silently dropping the size. Offsets 512/514/518/519/523 with no sizes *look* like overlapping
unaligned accesses, and that story went into the task description, a memory file and a commit
message before anything checked it. Printing the sizes showed all five are **1-byte reads AND
1-byte writes**, non-overlapping, no size mismatch at all. The real mechanism is
`guard_calls` re-adding an INDIRECT per (range, call) every pass — 5 locations x 2 calls = the
observed +10 ops/pass.

**How to apply:** when dumping a keyed structure, print the WHOLE key. A partial key does not
produce a partial answer, it produces a confident wrong one. Sibling of
[[address-equality-is-not-op-equality]].

**2. A faithful-looking port written on a hypothesis is still a guess.** Our `refine_overlaps` is
gated to laned XMM registers while Ghidra's gate is space-agnostic (`placeMultiequals`,
heritage.cc:2610 — `size > 4 && max < size`, `max` = maximum WRITE size per `collect`). Retiring
that adaptation is legitimate *on its own merits*, so generalizing it felt like a faithful port.
But I wrote it to fix task #8, and it does not: every one of those ranges is 1 byte with a 1-byte
write, so `size > 4` is false and Ghidra would skip them too. T1 was green and the corpus
byte-identical — which proved only that it is inert on x86-64 datatests, not that it is right for
the 16-bit and FID paths it would newly touch.

**Reverted.** CLAUDE.md's rule is that new code must be a faithful port grounded READ-ONLY until
the premise is verified — *including* that it truly produces the result in our pipeline. Green
gates are not that verification when the change is inert on them. Still a real candidate: recorded
in task #8 as a known adaptation with the evidence that it is NOT this bug's cause.

Related: [[could-it-have-come-out-otherwise]], [[trace-diff-first-not-fifth]],
[[measurement-determinism-first]].
