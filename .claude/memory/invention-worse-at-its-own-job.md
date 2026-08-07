---
name: invention-worse-at-its-own-job
description: "An invented rule was WORSE than Ghidra's real one at the very fixture it was added for — check the justifying fixture first when retiring an adaptation."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-30T23:44:37.234Z
---

`RuleMultMult` (mosura invention, `(x*c1)*c2` → `x*(c1*c2)`) was justified in its own doc comment by
the `modulo` fixture: "it also lets `(x/6)*3*2` collapse to `(x/6)*6` so the modulo form is
recognised." Deleting it moved `modulo` **0.965 → 0.997** — the single fixture that moved in the
whole corpus, and it moved UP. Ghidra's faithful `RuleAddMultCollapse` already did the same fold,
correctly, and was already registered in the same pool.

**Why:** an adaptation is written to make one case work and is then never re-measured against the
faithful rule that lands later. It survives on its origin story. Here the invention differed from
the real rule by dropping the size mask (bare `wrapping_mul` at u64 vs Ghidra's
`evaluateBinary` = `(in1*in2) & calc_mask(sizeout)`), so it emitted a 1-byte constant holding
`0xfe01` — an IR invariant violation in 136 of 1303 WAR2 functions.

**How to apply:** when retiring an adaptation, (a) look for a faithful rule that already covers it
before writing any replacement — the fix is often a pure DELETION, and patching the invention
instead keeps an invention alive; (b) **measure the fixture the adaptation was justified by, and
expect it to improve, not degrade** — if the justification still holds you will see it there first;
(c) file the reach prediction BEFORE measuring (here: "136 → near 0, else a second unmasked site
exists" — it went to exactly 0, which is what proved the retirement complete).

Instrument that found it: the ADAPTATION list from [[trace-diff-keys-mechanism]] named the
candidate; `MOSURA_CONSTCHECK=1` (an INVARIANT check — constant varnodes whose value cannot fit
their own size) measured its reach per function.

Related: [[port-all-faithful-rules]], [[faithful-ports-land-not-held]], [[gate-byte-identical-only]].
