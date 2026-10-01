---
name: emulator-semantics-beyond-the-sinc
description: Where a SLEIGH spec's p-code is not the hardware (68000 BCD, DIVx.W overflow), the fix goes in the pspec-selected emulator state modifier, validated against an independent CPU model — never in the sinc, never in the decompiler's p-code.
metadata:
  type: project
---

2026-10-01: the 68000 emulator state modifier (`sleigh/emu_m68k.rs`) landed for sor: `abcd`/`sbcd`
executed whole, `nbcd` through a `bcdAdjust` model + post-instruction flags, `divu.w`/`divs.w`
overflow (destination unchanged, V set), register shifts/rotates executed whole (V, counts past the width). Selected like Ghidra selects its Java class: the pspec's
`emulateInstructionStateModifierClass` (`Spec::emulate_modifier`). The decompiler's p-code is untouched.

**Why:** Ghidra's own emulator has no answer there (its m68k modifier registers nothing; the sinc
has no overflow rule), so there is no Ghidra oracle — the oracle is an independent CPU model.
BlastEm (blastdbg `--trace` records work RAM) answered 1.57M BCD cases + 16k divisions + 75k shifts; the
generator is `tests/fixtures/m68k-emulation/generate.py`.

**How to apply:** a further "the emulator disagrees with the hardware" request goes in the same
modifier (or a new one keyed by the same pspec property), with a self-written ROM + independent
oracle. Known traps: the oracle has bugs too — these fixtures found three in BlastEm (nbcd memory store,
memory asl V, rotate-by-0 V; fixed by 05f745d): check every disagreement against the PRM; 68000.sinc `packflags` loses T/S/IPL in `move SR,<ea>` (still open, in
Ghidra too). See [[pragmatism-over-faithfulness (subject-profile note)]].
