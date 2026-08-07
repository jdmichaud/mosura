---
name: war2-pragmatism-over-faithfulness
description: USER RULE 2026-08-05 — for WAR2 work, pragmatism wins; improving on Ghidra is sanctioned where Ghidra can't or gets it wrong
metadata:
  type: feedback
---

**USER RULE (2026-08-05, verbatim):** *"In general, we dealing with WAR2, we are in the land of
pragmatism. We want to decompile all the functions byte exact. So if Ghidra is not able to do
something or does not do it right, then we can improve upon it. Faithfulness is on the theoretical
side."*

**Why:** the WAR2 goal is BYTE-EXACT decompilation of every function — an outcome measured against
the ORIGINAL BINARY, not against Ghidra. Ghidra is a means. Where Ghidra is incapable (it cannot
even load a DOS/4GW LE) or simply wrong, beating it is the point. This extends
[[goal-is-the-binary-not-ghidra]] from a target statement into an explicit licence to exceed.

**How to apply:**
- Faithful porting remains the DEFAULT and the general-capability track (CLAUDE.md still governs
  the decompiler core and everything non-WAR2). Beyond-Ghidra work is allowed where Ghidra falls
  short of the WAR2 goal.
- ⚠️ **When you exceed Ghidra you LOSE THE ORACLE.** Beyond-Ghidra code must be validated against a
  SECOND oracle — the expert tracker (`decomp-tracker.csv`), self-compiled ground truth, or the
  byte-exact recompile — never left unvalidated. This is the established precedent from the
  compiler-detection arc (a beyond-Ghidra second oracle, validated against real toolchain output).
- ⚠️ **Additive, never substitutive.** A beyond-Ghidra shortcut must not REPLACE a faithful port,
  and the faithful path's independent contribution must stay separately measurable. Concrete proof
  this matters, from this very session: porting `AddressTableAnalyzer` properly (instead of taking
  the available LE-fixup shortcut) is what surfaced a pre-existing `findLoadAddress` loader
  mis-port that was corrupting EVERY watcom-x86-32 fixture. The shortcut would have hidden it and
  left mosura with no pointer-table analysis for any other binary.
- Mark beyond-Ghidra code clearly as such in-comment, with what oracle validates it.

First sanctioned instance: emitting references/disassembly seeds from the **LE fixup table** in
`load_le`. The linker's fixup table is an exact index of every stored pointer (WAR2: 17,517
relocations, 3,178 into code) — information Ghidra never receives, because the LE→ELF conversion
bakes in the patched values and drops the record. See [[war2-function-set-ground-truth]].
