---
name: cast-census-is-per-line
description: "cast-census.py reads PER LINE, so it cannot see a cast at end-of-line — mosura-vs-Ghidra cast counts are systematically biased because Ghidra wraps and mosura does not"
metadata: 
  node_type: memory
  type: reference
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-08-03T18:02:34.639Z
---

`scripts/cast-census.py` counts with `for line in path.read_text().splitlines()`, and its position
test is a **lookahead for the start of an operand**. A cast that ends a line therefore has no
operand on that line and **is not counted**.

**This voided a whole task premise.** "threedim: mosura 8 vs oracle 6" was carried as one of only
two cast divergences on the corpus and drove a task assignment. Ghidra wraps `*(xunknown4 *)` at
end-of-line twice in `threedim`; mosura does not wrap at all. Re-censused as **whole strings** both
sides give **8 and 8 with the identical cast multiset**. There was never a cast difference.

⇒ **The delta between two MOSURA emits is sound** — that is the script's documented job and the
9031 anchor is fine. **A mosura-vs-GHIDRA cast count is systematically biased**, always in the same
direction (Ghidra under-counts), because Ghidra's pretty-printer wraps and mosura's emitter does
not. Never quote one as a divergence without re-running whole-file.

The re-check, which is two lines: iterate `CAST.finditer(text)` over `read_text()` instead of per
line, keeping the same `KEYWORD` and preceding-character filters, and compare the resulting token
lists — not just the totals. Comparing the multisets is what proved the counts were identical
rather than coincidentally equal.

Two general rules this bought, both already in the index in other clothes: an instrument's
**tokenization** is part of its definition, not an implementation detail
([[numbers-stale-unless-sha-stamped]] is about time, this is about form); and a difference between
two tools is not a defect until you have checked that the INSTRUMENT sees both sides the same way
([[gauge-counting-traps]], [[oracle-same-question-not-just-same-tool]]).

Not fixed in the tree: fixing it would move the 9031 anchor and void every delta measured against
it, so it was left alone and documented instead. See [[base-getinputcast-was-the-catchall]].
