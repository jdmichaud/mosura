---
name: war2-remaining-gap-is-structural
description: "81% of WAR2's mismatching functions differ in >40% of their instructions — the gap to byte-exactness is not a tail of small bugs, and only ~97 functions are one or two regions away"
metadata:
  type: project
---

**⭐ MEASURED 2026-08-12 at 375 byte-clean (`classify_diffs.py`, results.m20).** Both instruction
streams are aligned with difflib over normalized mnemonics; each mismatch is classed by how many
divergent regions it has and what fraction of its instructions differ.

| class | count | share |
|---|---|---|
| STRUCTURAL (>40% of instructions differ) | 2111 | 81.2% |
| PARTIAL (<=40%) | 391 | 15.0% |
| LOCAL (1 region, <=3 instructions) | 78 | 3.0% |
| NEAR (<=2 regions, <=15%) | 19 | 0.7% |

**Only 97 functions are within one or two small regions of matching.** Reaching 600 from 375 needs
+225, so it CANNOT come from the near-miss tail — it requires converting ~46% of the 488
non-structural functions, or breaking into the structural bulk.

## What the closest 97 actually need (censused divergent regions)

    13  orig has trailing `8d 40 ..` (lea-NOP padding)   <- comparator, now fixed, gained 0
    10  orig: and eax,0xff        cand: (none)           <- byte-width parameter typing
     6  orig: mov eax,eax         cand: (none)           <- padding
     6  orig: ret                 cand: ret 0x4          <- caller-pop vs callee-pop convention
     5  orig: (none)              cand: mov ah,0x1
     4  orig: shl eax,0x2         cand: lea eax,[eax*4+0] <- peephole/instruction selection
     2  jbe/jae, jl/jle, jg/jge swaps                     <- condition-code recovery

A large share of these are INSTRUCTION SELECTION (peepholes) and comparator artefacts, not
decompiler defects. `add edx,0x12 ; mov eax,edx` vs `lea eax,[edx+0x12]` (FUN_00023210) is the
worked example: both return in EAX and the C is right; only codegen differs.

## Four hypotheses sized and KILLED with the corrected instrument (do not re-derive)

Measured on the 480 "near" functions (<=40% of instructions differ) — the ONLY population where a
convention change could flip a verdict. All report the survey's own verdict via
`compare.classify(..., objp=...)`:

| hypothesis | byte-clean |
|---|---|
| baseline (per-function flags) | 0 of 480 |
| `modify exact []` (blanket) | 0 |
| `modify exact [<precise list from the original's saves>]` | 0 |
| uniform `-onatx` / `-onatx -d1+` | 0 / 1 |

⚠️ **The instrument was broken for the first three runs of this kind.** A probe that compares
`cand == orig` cannot see compare.py's both-sided relocation masking, so every function containing
a call or a global reference reads MISMATCH and BOTH arms report zero — a negative that looks
clean and means nothing. `compare.classify` now takes an `objp` override; any probe MUST use it.

## Confounds ruled out along the way

- **"Functions preserving many registers are a class."** They are not: leading-push count is a
  proxy for function SIZE (median length 30 / 31 / 56 / 87 / 108 / 163 / 232 bytes for 0..6
  pushes). The low byte-clean rate at 4+ pushes is the low rate for big functions.
- **`modify exact []`** (Watcom's forcing form; plain `modify []` is inert) does produce the
  register saves, but sized on 120 functions it gave EXACT 0 -> 0 and mean |delta| 33.5 -> 34.0.
  Blunt instrument: it also saves registers the original does not, including `push gs`.

## The one thing that IS worth knowing

delta==0 is EMPTY: of 2509 mismatches not one has the original's length, while the neighbouring
buckets hold 70-96 each. Getting a function to the right LENGTH is very nearly equivalent to
getting it byte-clean. Length is the metric to chase.

- **`indirect_call` smell (2019 of 2599 mismatches)** is NOT causal: only 3 functions emit an
  indirect call the original lacks. The smell fires on the IR, not on a defect.
- **`rep movs`/`stos`/`scas` expansion** (we render the loop, the original has the string op) is
  real but small: 109 functions, 4 byte-clean.

## What the aggregate says the difference actually IS

Mnemonic totals over 501 mismatching functions (orig vs cand): `pop` -428, `mov` -382, `push`
-207, `je` -199 against `lea` +267, `and` +266, `jne` +117, `setne` +80, `neg` +73. Total
instructions 26686 -> 25054 (-6%). Register saves are 39% of the deficit and fixing them converts
NOTHING, so the verdict is decided by the other 61%: condition polarity (`je`/`jne`, `jl`/`jge`,
`jbe`), boolean materialization (`setne al ; and eax,0xff` where the original branched), and
instruction selection (`lea` for `add`/`shl`). Those are structurer and codegen-shape questions.

Related: [[byte-exact-class-map-2026-08-11]], [[prologue-order-is-chain-frame]],
[[caller-evidence-prototypes]].
