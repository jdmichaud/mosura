# An absolute measure of over-decode (spec for §6)

**Status:** spec, 2026-08-06. Written because §6's only evidence — "7,322 extra instruction starts,
255 runs, 104.4% of Ghidra's code coverage" — is **differential against Ghidra's decode**, and this
track has now been burned twice by treating a derived summary as primitive.

## Why the current figures cannot carry the investigation

Per [[absolute-vs-differential-wrongcode]], a differential against an oracle cannot see a defect
present on both sides. §1 showed the mirror failure: a differential *manufactures* a difference
that is a defect on neither side. Both of §6's numbers are of that shape, so before any hypothesis
is worth forming they must be replaced by measures that reference **only the binary and mosura's
own output** — no Ghidra, no expert tracker.

A second requirement, learned the same way: the measure must report **provenance**, not just
magnitude. "7,322 starts" is unactionable; "6,900 of them descend from analyzer X" names a defect.

---

## Part A — absolute wrongness (no oracle, no second run)

Each check below is decidable from the loaded image plus mosura's listing alone. Report **count**,
**total bytes**, and **the contiguous runs** for each, plus a sample of 10 with bytes.

| # | check | why it is absolute |
| --- | --- | --- |
| **A1** | an instruction start inside a memory block whose container marks it **non-executable** | the LE object table (`le.rs:219`, `objN_text` vs `objN_data`) and the ELF section flags are the *producer's own* statement of what is code. Decoding there is wrong with no oracle needed. |
| **A2** | an instruction start that is **offcut** — strictly inside another instruction's extent | a byte cannot be both mid-instruction and an instruction start. Pure self-consistency. Expected 0; if it is not 0 that is the defect, found without any comparison. |
| **A3** | a flow edge (fall-through, branch, call) whose **target is offcut** w.r.t. an existing instruction | same, for flow rather than starts. Also expected 0. |
| **A4** | an instruction whose bytes **overlap a relocation/fixup slot** | an LE fixup names a 32-bit slot as a relocated pointer. Code overlapping one is decoding a pointer. WAR2-specific but principled, and mosura already parses the fixup table (`war2-le-fixups-root-cause`). |
| **A5** | an instruction start with **no inbound flow edge and no seed**, i.e. unreachable from any function entry | not wrong on its own — a legitimate seed produces these — but it is the *entry set* for Part B, and it should be small. |

**A1 and A4 are the magnitude.** They are the honest replacement for "7,322 extra starts": bytes
mosura decoded that the file itself says are not code. If A1+A4 is near zero while the differential
is 7,322, then **§6 is not a defect at all** and the differential was measuring Ghidra's
*under*-decode — which is a live possibility nobody has excluded, and which would close the item.

**A2 and A3 are free assertions** that belong in the corpus regardless of §6: they need no WAR2 and
should hold on every fixture. If they hold everywhere, over-decode is a *seeding* problem, not a
decoding one, which halves the search space before any WAR2 run.

## Part B — provenance by ablation (attribution, not magnitude)

`MOSURA_DISABLE_ANALYZERS` already exists and takes a comma-separated list. For each seeding
analyzer, re-run and diff the **instruction-start set**:

```
Disassembly · Function Start Pre Search · Function Start Search
Function Start Search After Code · Function Start Search After Data
Address Tables · Relocation Seed · GCC Exception Frames
External Jump · Shared Return · Decompiler Switch
```

Report per analyzer: starts removed, bytes removed, runs removed, and how many of the **A1/A4**
addresses disappear. The last column is the one that matters — it names the analyzer responsible
for provably-wrong decode.

**This differential is legitimate where the Ghidra one is not**: the only variable is the analyzer,
and the question is attribution rather than existence. It cannot see decode that survives every
ablation (i.e. caused by the base disassembler), which is exactly why Part A must supply the
magnitude independently.

## What I am NOT asking for

- No comparison against Ghidra, in any part of this. If a Ghidra number is wanted later it is a
  separate question asked after the absolute picture exists.
- No count of "extra" anything. "Extra" presupposes a reference; A1/A4 do not.

## Validation before it is trusted

The measure must be validated where the answer is already known, on the fast fixtures:

- `lestruct.watcom-le` — the LE column, so A1 (object table) and A4 (fixups) both have real inputs;
  its data object is `obj2_data` and nothing in it should decode.
- `noret.gcc-x86-64` — a dynamic ELF with `.plt`, `.got.plt` and `.bss`, so A1 has ELF-side inputs.
- `wprologue_sf.watcom-x86-32` — 17 functions of dense Watcom code with inter-function padding,
  where A2/A3 should be 0 and A1 should be 0.

**A measure that reports 0 on all three has not been shown to work** — it has been shown to be
silent. Give it a positive control: point it at a range deliberately seeded into data (the
relocation-seed analyzer's own targets in `lestruct` will do) and confirm it fires.

## Then, and only then

With A1/A4 magnitude and Part B attribution in hand, §6 either names an analyzer or dissolves.
Either outcome closes it. Do not form a mechanism hypothesis before those two numbers exist —
§6 has already killed three hypotheses that way (`mustTerminate`, the flow-disassembler bounds,
the address-table thread), and §1 died the same death.
