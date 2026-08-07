---
name: book-assume-tool-finished
description: "Framing rule for the mosura-book: write as if mosura is a finished tool, present tense, no in-progress hedging"
metadata: 
  node_type: memory
  type: feedback
  originSessionId: ba57400a-aa2c-42b8-86ff-0743f7dbd2c1
---

For the [[mosura-book]], the book must be written **as documentation of the
finished tool** — present tense, as though every designed feature already works —
even though mosura is still being built.

**Why:** user directive (2026-06-22): "The book will assume that the tool is
written. It's not the case now but it will eventually be."

**How to apply:**
- No "not yet / in progress / partial / today handles / what doesn't work yet /
  moving target / snapshot" hedging in the book's prose. Describe capabilities as
  present and working.
- Don't enumerate missing features (floats, switches, full type system) as gaps;
  document the tool as designed.
- A `mosura` command-line front end may be referred to as existing (its own
  README calls it "a command-line reimplementation"), but do NOT invent specific
  CLI flags/output that aren't designed — the real, current interface is the Rust
  library API, which is legitimate to document.
- Reconciliation reality (kept in repo meta, NOT in the book): listings for
  already-implemented stages (disassembler, p-code, interpreter) are real source
  + real output; listings for not-yet-built stages track the design and get
  reconciled when the code lands. OUTLINE.md ✅/🟡/✍️ markers track which is which;
  README.md "Relationship to mosura" states the framing.
- This removed the Preface "A note on a moving target" section (now "About the
  code in this book") and the §3.6 validation content was already cut for a
  separate reason ([[mosura-book]] review).

Note tension with the earlier "relax overclaims" steer: that was about not
exaggerating (e.g. "read in an afternoon"); this is about framing the finished
tool. Both hold — be accurate AND present-tense-complete, just don't exaggerate.
