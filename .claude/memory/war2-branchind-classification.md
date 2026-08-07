---
name: war2-branchind-classification
description: "Verdict on WAR2's 9 unrecovered BRANCHIND (le_war2_analysis): 3 families — 4 narrowed-switch decompiler gaps (reduced+filed), 3 unguarded-byte faithful non-gaps, 2 function-specific computed-goto gaps. Loader ruled out."
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-07-22T06:06:44.970Z
---

First application of [[war2-issues-become-source-tests]]. The 9 BRANCHIND `le_war2_analysis`
leaves unrecovered (8/17 recovered) are NOT "9 register-indirect jmp eax" (only 2 are `ff e0`).
Instrumented via mosura's own analysis of the fixed-up LE image + verified against Ghidra (the
built `oracle/capture` libdecomp oracle — the LE-reduced bytes load as normal ELF32). Committed
`4be984b` (analysis-port).

**Three families:**
- **A — narrowed GUARDED dense switch (4: 0x513a8/0x58afb/0x6af52/0x199b7): REAL decompiler-lane GAP.**
  Tables are correctly fixup-relocated (every entry a valid in-image code addr → **loader NOT
  implicated**). Root: mosura recovers `switch(int)` but not `switch(short)/switch(char)` — the
  `movzx`/`AND` narrowing between the guard and the table index defeats JumpBasic (narrow guard
  var `SUBPIECE(x,0)` not tied to widened index `ZEXT`/`AND`). **Ghidra recovers it** (oracle
  confirmed). Reduced to Watcom ground-truth `oracle/ground-truth/narrowsw.*` (sw_int control vs
  sw_short gap; flat ELF32 — the `CS:` prefix is NOT the cause). Pinned by
  `ground_truth_parity::narrow_switch_recovery_gap`. Filed: `docs/decompiler-bug-narrow-switch.md`
  → see [[decompiler-misport-backlog]].
- **B — UNGUARDED byte-dispatch (3: 0x10b7e/0x7b973/0x7b986): faithful NON-GAP (A6-style).** No CMP
  guard on the byte index → Ghidra ALSO refuses ("Could not recover jumptable ... Too many
  branches"). mosura==Ghidra. No recovery test.
- **C — masked computed-goto `jmp eax` (2: 0x797e4/0x7a9a4, decompressor decode loop):** real but
  function-specific. mosura recovers the ISOLATED `and eax,0xf0; add base; jmp eax` (verified
  minimal, incl. SHRD/ROR-fed + 16-slot); Ghidra recovers it inside the real fn_793e0 (oracle:
  `switch(...&0xf0)`), mosura recovers only the sibling cs-table there. NOT C-reducible
  (hand-written asm); lower priority (functions already discovered).

Fix lane for A + C = DECOMPILER (jumptable.rs/JumpBasic) — analysis lane is faithful (switch
analyzer reads back whatever the decompiler recovers). Nothing to fix analysis-side.
