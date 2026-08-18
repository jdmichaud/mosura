# Byte-exact divergence families — the census

*Generated from sb43 (`a6b4b04`, 586 EXACT / 2210 MISMATCH / 84 SAME_SHAPE). Source data:
`/data/be2/sb43-div.tsv` (88,464 per-instruction divergence rows, `recompile_check
--divergences`) joined with `/data/be2/sb43.tsv`. Regenerate both rather than quote after
any change; every count below is one awk over those files.*

## Method, and what a family is NOT

Families are clustered by **symptom** — the class and text of the diverging instructions —
deliberately without a pre-assigned layer. Whether a family is a port defect, a
representation choice, or an original-source shape Ghidra's reading cannot express is
determined per family, on a specimen, with the oracle open (instrument first). The
byte-reproducing C can be a *different program* from Ghidra's rendering (POPCOUNT, the
int8 divides), so "our C matches Ghidra" never closes a family by itself.

Two divergence classes are excluded from family targeting as non-semantic knock-on:
`layout-shift` (8,290 rows — address drift from earlier length changes) and
`branch-target` (3,135 — same, at the jump site). They disappear when the upstream
divergence does.

## The frontier

- 84 SAME_SHAPE + 166 MISMATCH with ≤5 divergent instructions ≈ **250 functions within a
  handful of instructions of EXACT**.
- The mass has no big-function shortcut: the 30 worst functions carry 11% of the 80k
  unmatched-instruction mass; the rest is spread over ~1400 low-sim functions and moves
  only through systemic fixes.

## Families

### F1 — truth-value / byte-width complex (largest reach)

Symptoms, with corpus-wide function reach (overlapping sets):

| symptom | functions |
| --- | --- |
| extra `AND reg,0xff` (byte-width normalization) | 640 |
| missing `XOR reg,reg` (original zeroes the full register) | 594 |
| extra `SETcc` (materialized truth value) | 199 |
| `MOV Ereg,imm` vs `MOV reg8,imm` (constant store width) | 89 |

The original works at full register width — zeroes with `XOR EAX,EAX`, moves `MOV EAX,1`
— where our C makes Watcom work in byte registers and then normalize (`MOV AL,1`,
`AND EAX,0xff`, `SETNZ AL`).

Specimen `00697`/`FUN_000260c4` (13 near-miss functions share its exact signature): the
original returns constants on separate paths (`MOV EAX,1`; the zero path reuses the
call's own EAX=0), our C returns a merged boolean (`return x != 0`-shape) that Watcom
must materialize with `MOV EDX,EAX` + `TEST` + `SETNZ` + `AND`. At least two sub-shapes:
(a) merged boolean returns vs per-path constant returns; (b) 1-byte-typed values where
the original source used int width. Layer: undetermined — (a) in particular may be a
Ghidra-faithful rendering whose byte-reproducing source is a different program.

### F2 — assign-then-move vs folded LEA (pilot candidate)

`selection MOV>LEA` in 179 functions, 70 of them alongside a missing `ADD`;
`selection SHL>LEA` in 132. 15 near-miss functions carry *exactly* the two-row signature
`missing ADD + MOV>LEA` (a contiguous idx run 00556–00566 — sibling functions from one
source module).

Specimen `00556`/`FUN_00023210`: original ends `ADD EDX,0x12; MOV EAX,EDX` — arithmetic
performed on the variable's own register, then moved to the return register — where our C
lets Watcom fold both into `LEA EAX,[EDX+0x12]`. The source-shape question is "assign
then return" vs "return the expression". Smallest, crispest family: one mechanism, an
immediately answerable triage (is our C Ghidra's C for the specimen?), and 15 quick EXACT
candidates.

### F3 — callee-save divergence (do not target directly)

716 functions missing a prologue `PUSH`; but missing saves outnumber extra saves 1231 to
150, and the missing registers span EBX/ECX/EDX/EDI/ESI evenly. The original uses more
registers than our candidate — predominantly **knock-on** of upstream value/shape
divergences (fewer live values → fewer registers → fewer saves). Re-measure after F1/F2
rather than attacking it head-on.

### SAME_SHAPE clusters (84 functions, every fix +1 EXACT)

| count | signature | reading |
| --- | --- | --- |
| 11 | `operand-form MOV>MOV` ×2, nothing else | one operand-encoding detail, needs a specimen |
| 5 | `immediate CMP` + `selection JL>JLE` | comparison canonicalization: original `<=k`, candidate `<k+1` (or v.v.) |
| 3 | `selection JZ>JNZ` + 2 `immediate MOV` | branch polarity + swapped constant arms |
| 5 | pure regalloc runs | register substitution — the declaration-order lever (byte-exact-status FINDING) |

Top near-miss substitution texts for the record: `MOV EAX,0x1`→`MOV AL,0x1` (68 rows),
`MOV CL,AL`→`MOV CL,[EBP-4]` (23), `MOV EAX,0x1`→`AND EAX,0xff` (21).

## Proposed order

1. **F2 as the pilot** — one mechanism, 15 near-miss functions, fast verdict on the loop
   itself (census → specimen → triage → fix at the named layer → re-measure).
2. **F1** — the mass lever, but a complex; expect it to split into 2–3 mechanisms during
   instrumentation.
3. **SAME_SHAPE clusters** — win density, likely emitter-side levers.
4. Re-run this census (both TSVs + the awks above) after each family lands; F3 should
   shrink on its own.
