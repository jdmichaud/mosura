---
name: synthetic-layout-needs-range-guards
description: "Faithfully copying Ghidra's unconditional field write is wrong where OUR layout is the deviation — a 16-bit OMF field cannot hold a linear EXTERNAL slot address"
metadata: 
  node_type: memory
  type: project
  originSessionId: 6a216fa6-e69f-4b20-b0bf-429f1307092c
  modified: 2026-08-09T08:19:06.307Z
---

**⭐ 2026-08-09 (`c676964`, fixing `b678279`).** Porting Ghidra's `OmfLoader.processRelocations` I
copied its unconditional `memory.setShort(loc, (short) finalvalue)` and DROPPED a range guard the
previous code had. Its comment had said why: *"one that cannot reach is left unpatched rather than
silently wrapped onto a wrong target."*

**THE RULE: faithfulness is to Ghidra's SEMANTICS in Ghidra's world.** Ghidra's addresses are real
segmented ones, where a 16-bit offset fits its frame by construction, so its unconditional write is
correct there. **Our synthetic layout is the deviation** — segments laid out linearly, the
`EXTERNAL` block above `0x10000` — so truncating writes an arbitrary value into the INSTRUCTION
STREAM, changes the decode, and destroys the very call the fixup describes. Where our
representation differs from Ghidra's, a guard compensating for OUR choice is not an adaptation to
be retired; deleting it is the bug.

    borland-bc4.5-cs relations   3315 -> 3187 -> 3315
    small-model probe            99 -> 98 -> 99   (lost `_brk`)
    large-model probe            46 -> 45 -> 46   (lost `__write`)

**Isolation method worth reusing:** rebuild ONE database repeatedly, each time disabling exactly
one new behaviour. Far-pointer packing reverted → still 3187. Segment/group targets suppressed →
3187. Displacement suppressed → 3187. Range guard restored → **3315**.

**Traps ruled out first (don't repeat them):** the `_brk` record was byte-identical across both
database sets, the full-hash candidate set was the same ten names, and the result was
deterministic. The loss path is `apply_markup` returning NOTHING — names that no longer collapse
plus a score below `MULTINAME_SCORE_THRESHOLD 30` means the match is *declined entirely*, not
downgraded to an ambiguous plate. So "no FID result at all" ≠ "no candidates".

**Ground truth was the LINKER MAP** (`bcc -M`), which proved 0x123e5 really is `_brk` — a lost true
positive, not a corrected false one. ⚠️ Borland maps DEMANGLE C++ (`operator delete(void near*)`
vs FID's `@$bdele$qnv`), so comparing raw strings invents ~24 fake mismatches.

Related: [[unlinked-zero-field-changes-the-decode]], [[self-referential-gates-prove-nothing]],
[[faithful-type-of-wrong-ir]].
