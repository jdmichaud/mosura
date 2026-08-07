---
name: mve-obvious-version-tests-nothing
description: Four for four — the obvious version of an MVE tests something already working; write it, watch it pass, then sharpen to the precise defect.
metadata:
  type: feedback
---

Every MVE this session was green on the first, obvious formulation and only became a real gate
after being sharpened to the exact defect:

1. `datafnptr` rebuilt as an **LE** — passes unfixed; the address-table analyzer handles a pointer
   RUN in LE memory just as in ELF. Sharpened to `lestruct.c`, which closes three mechanisms at
   once (no adjacent pointer words, tags below `MINIMUM_SAFE_ADDRESS`, `g_nodes[i&3].fn(x)` opaque
   to const-prop).
2. Disassembler bound, fall-through landing **on** a data unit's first byte — passes unfixed; the
   old exact-start `code_unit_at` already covered it. The defect is the **offcut/overlap** case.
3. `datafnptr`'s ARM B (a lone data pointer) — already worked, via the constant propagator.
4. The generic recall gate would have "covered" data-pointer targets — but they are outside its
   contract by construction.

**Why:** the obvious formulation tests the mechanism you just read about, not the one that is
broken. **How to apply:** write the obvious MVE, RUN IT, and treat a pass as information — it
tells you the real defect is narrower than you think. Never skip the red run on the grounds that
the shape is obviously untested.
