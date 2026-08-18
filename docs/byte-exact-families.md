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

**Progress (2026-08-18):** the first resolved sub-shape is the **hardware shift-count
mask** — `1 << (x & 0x1f)` is Ghidra's faithful rendering of the SLEIGH lifter's own
mask (oracle-verified on specimen `01308`/`FUN_00038d88`), and Watcom materializes it as
`AND CL,0x1f`. Resolved via the `shift-mask=hardware` EmitChoices axis: +13 EXACT on
sb44, 0 regressions, extra AND-0x1f rows 94 → 25. Much of the near-miss
`selection MOV>AND` signature was this, not merged booleans.

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

**Triage of the remaining sub-shapes (2026-08-18, both oracle-verified faithful-Ghidra
— fixes are design-level, not axes to bolt on):**

- **The widening idiom** (the family's mass: 591 functions missing `XOR reg,reg`, 305
  with extra `AND reg,0xff`, plus MOVSX-vs-zero-extend signedness flips): the original
  source held narrow memory values in **int-typed locals**, widening once at the load
  (`XOR EBX,EBX; MOV BX,[mem]`); Ghidra's narrowing rules compare/use the narrow value
  directly and the oracle prints exactly our C (specimens `00183`/`FUN_0001562c`,
  `01308`). The byte-reproducing emission needs locals declared at widened width with the
  conversion at the def — the analog of the existing `return-width` axis, for locals.
  Design sketch, not yet implemented.
- **The widening idiom — worked design (probed 2026-08-18, see below).**
- **Merged-boolean returns** (`extra SETcc`, 234 functions, not all this shape): the
  original returns constants on separate paths; Ghidra (oracle-verified on `00697`)
  merges to `return x != 0;`, which Watcom materializes with `TEST/SETNZ/AND`. The
  byte-reproducing form needs the return **split back per path** — a structural
  transform, heavier than any existing axis.

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
lets Watcom fold both into `LEA EAX,[EDX+0x12]`.

**DISPOSITION (pilot, 2026-08-18): not a mosura defect at any layer — a toolchain
fingerprint.** The chain of evidence:

1. Our C is Ghidra's C for the specimen (oracle-verified; body statement identical).
2. No source shape avoids the fold: expression return, assign-then-return, fully
   sequential statements, `return x = ...` — all five variants compile to the LEA.
3. No wcc386 10.0a flag set avoids it while keeping register allocation: every `-o`
   letter the compiler accepts (`-ob/-oh/-ok` are rejected outright), `-onatx`, `-ox`,
   `-or`, `-3r/-4r/-5r`, and the empty set all fold; only `-od` produces the `ADD` — and
   `-od` spills every local to the frame, which the original does not.
4. The original binary is systematic about it: **zero** `LEA reg,[reg+imm]` folds in
   380KB (none in any EXACT function, and the 39 hex hits in MISMATCH originals are not
   this form), while scaled LEAs (`[EDX*4]`) appear freely — but only into a *different*
   register; in-place scaling is `SHL`. Our compiler emits both LEA forms opportunistically
   (`LEA EAX,[EAX*4]` ×41, `LEA EAX,[EDX+0x1a]` ×22 in the extras).

The original's code generator has a recognizably different peephole policy from the
wcc386 10.0a we compile with, under every switch it accepts. The 10.0a identification
came from the warcraft2-re side (runtime library matching); library version and compiler
binary version need not agree. `/data/tools/watcom/` holds installable images for 9.5b,
10.0 (incl. a 3-16-1994 beta), 10.6, and 11.0 — the discriminator is cheap once a tree
exists: compile the specimen, look for the fold. If the true compiler differs, a version
swap moves not just F2's ~300 functions but potentially a large slice of the 2210
MISMATCH population at once, which makes settling the version a prerequisite for every
further family session — otherwise family analyses chase compiler ghosts.

**Cross-cutting consequence:** until the compiler version is settled, every family
disposition below carries an implicit "under wcc386 10.0a" qualifier.

**UPDATE (same day — the version question is now settled as far as it can be):**
[`war2-toolchain-synthesis.md`](war2-toolchain-synthesis.md) assembles both projects'
evidence plus new measurements. Outcome for this family, in two halves:

- The `SHL>LEA` sub-family was **flags, and is FIXED**: `-5r` (Pentium tuning — the CPU
  digit is tuning, not an instruction-set floor; the emitted code is pure 386 ISA)
  suppresses the in-place scaled LEA in 10.0a. Profile base changed `-4r` → `-5r`:
  SHL>LEA rows 157 → 12, EXACT 586 → **591** (+6/−1) on sb43 sources — and → **592**
  once the CPU digit became per-function evidence: WAR2's one `-4r` module (9 functions,
  0x69fb0..0x6e6e0, detected by its in-place scaled LEAs, a form `-5r` cannot emit) is
  downgraded per function by `buildconfig` (`/data/be2/sb43-5r.tsv`).
- The `MOV>LEA` add-fold half **stands as a compiler fingerprint**: every shipped
  revision measured (9.5b, 10.0-LA beta, 10.0a wcc386+wpp386, 10.6, 11.0, OW2) folds
  under every accepted flag except `-od`; WAR2 never does. WAR2's compiler is an
  interim 10.0-line codegen build (a-level front end — the byte-compare promotion is a
  documented a-level fix, verified at 103 disassembled sites — with selection/allocation
  dials set between the shipped snapshots). Not closable by source or flags; do not
  chase per-function.

### F3 — callee-save divergence (compiler policy — do not target)

716 functions missing a prologue `PUSH`; missing saves outnumber extra saves 1231 to
150, spanning EBX/ECX/EDX/EDI/ESI evenly. Originally read here as knock-on of upstream
value/shape divergences; the warcraft2-re investigation had already measured the real
mechanism (`analysis/openwatcom-investigation/cgflag-bxsidi-save-no-modify.md`): **the
target's compiler saves callee-save registers even when not modified**, where 10.0a's
`SaveRegs()` intersects with the used set. A compiler-policy member of the pile-B
residual ([`war2-toolchain-synthesis.md`](war2-toolchain-synthesis.md)) — some knock-on
component remains on top, so re-measure after F1, but the floor is the policy.

### SAME_SHAPE clusters (84 functions, every fix +1 EXACT)

| count | signature | reading |
| --- | --- | --- |
| 11 | `operand-form MOV>MOV` ×2, nothing else | one operand-encoding detail, needs a specimen |
| 5 | `immediate CMP` + `selection JL>JLE` | comparison canonicalization: original `<=k`, candidate `<k+1` (or v.v.) |
| 3 | `selection JZ>JNZ` + 2 `immediate MOV` | branch polarity + swapped constant arms |
| 5 | pure regalloc runs | register substitution — the declaration-order lever (byte-exact-status FINDING) |

#### The `local-width` axis — IMPLEMENTED (tier 1); design below

**Landed (sb45):** axis `local-width={recovered,storage}` in `decompile::emit`, gate in
`printc::storage_widened_local` (register/temp storage, size 1/2, no input members,
value-safe defs only). Deployed per the searched-axis mechanism: two arms + per-function
selection; the materialized union recompiles to **612 EXACT** (+7 over the default arm).
Tier 2's first sub-shape resolved differently than designed: the entry-widening
originals (`SHL then MOVSX`) were a **port defect** — the missing integer-promotion cast
machinery (see byte-exact-status.md, 612 → 616) — not a temp-introduction problem.
Inline narrow reads via `force_explicit` (the `00183` shape) remain open.

The widening idiom's fix, shaped like `return-width` but for locals. Probes (all through
the 1-second single-function loop, sources in the session scratchpad):

- `01043`/`FUN_00031044`: `xunknown1 xVar1` → `uint4 xVar1`, one token — **EXACT** (the
  original's `XOR EAX,EAX; MOV AL,[m]` reappears; the extra `AND EAX,0xff` vanishes).
- `00183`/`FUN_0001562c`: introducing `uint4 t = *(uint2 *)param_2;` for an *inline*
  narrow compare — **EXACT** (`XOR EBX,EBX; MOV BX,[EDX]` reproduced; Watcom emits the
  pair, not MOVZX, under the recovered flags).
- Counterexamples exist: of the 18 currently-EXACT functions declaring narrow locals, a
  blanket widening keeps 12 EXACT and **breaks 6** — the original sometimes chose narrow,
  so the axis is genuinely **searched** (emit.rs rule: the original's choice is not
  derivable from the IR).

**Tier 1 (the axis proper)** — `local-width` = `recovered` | `storage`: an explicit local
HighVariable of size 1/2 with register storage declares at 4 bytes, keeping its recovered
signedness (`uintN`/`xunknownN` → `uint4`, `intN` → `int4` — originals measurably use
both `XOR+MOV` zero-extension and `MOVSX`). Value-safety gate: every def's rvalue must be
narrow-valued (narrow load, narrow global copy, narrow call return) — a def that
truncates a wider expression or wraps narrow arithmetic keeps the narrow declaration
under either axis value, because widening those changes the computed value. Population:
918 sources declare narrow locals; 670 are MISMATCH.

**Tier 2 (temp introduction, follow-up)** — two well-defined sites the axis alone cannot
reach: (a) narrow *params* the original widens at entry (`MOVSX EDX,AX` — 85 functions
carry missing MOVSX; signature must stay narrow, so the widening is a introduced local
copy); (b) *inline* narrow memory reads in wide contexts (the `00183` shape — printc's
`force_explicit` machinery is the natural hook). Both need their own probes before
implementation.

**Deployment decision (open)**: (a) flip the survey default and accept measured
regressions if net-positive, or (b) emit `--arms 'default;local-width=storage'` and let
`recompile_select` take the per-function union — the designed mechanism for a searched
axis (a second *print+compile* round, not a second decompile).

Top near-miss substitution texts for the record: `MOV EAX,0x1`→`MOV AL,0x1` (68 rows),
`MOV CL,AL`→`MOV CL,[EBP-4]` (23), `MOV EAX,0x1`→`AND EAX,0xff` (21).

## Proposed order (revised after the F2 pilot and the toolchain synthesis)

1. ~~F2 as the pilot~~ — **done**: SHL half fixed by `-5r` (+5 net EXACT); add-fold half
   is compiler policy, parked.
2. ~~Settle the compiler version~~ — **done** as far as media exists:
   [`war2-toolchain-synthesis.md`](war2-toolchain-synthesis.md). The pile-B compiler
   families (F2's add-fold, F3, load scheduling, pure-regalloc allocation order) are a
   bounded residual — parked, not worked.
3. **F1** — the mass lever, but a complex; expect it to split into 2–3 mechanisms during
   instrumentation (the merged-boolean-return sub-shape is decompiler-side and live).
4. **SAME_SHAPE clusters** — win density; note the pure-regalloc runs are pile-B.
5. Re-run this census (both TSVs + the awks above) after each family lands, against the
   `-5r` baseline (`/data/be2/sb43-5r.tsv`, `/data/be2/sb43-5r-div.tsv`).
