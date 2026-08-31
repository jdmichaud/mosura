# Where we stand, and a plan to reach WGSS 0.8

*2026-08-22, measured at zc33 (`0f38e00`). Every number below comes from one
`recompile_check` run (`/data/be2/zc33b-rec.tsv` + `/data/be2/zc33-div.tsv`) and is
reproducible with `scripts/war2-mechanism-census.py <rec.tsv> <div.tsv>`. The goal is
recompilation, not resemblance to Ghidra: the only score that counts is the insn-weighted
similarity of the recompiled bytes (WGSS) and the EXACT count.*

## 1. Where we stand

| | |
|---|---|
| functions / weight | 2796 user functions, 121,713 original instructions |
| WGSS | **0.4832** (765 EXACT, 65 SAME_SHAPE, 1 SAME_CODE, 1964 MISMATCH) |
| loss | 62,899 weighted instructions not matched |
| 0.8 requires | loss ≤ 24,343 — i.e. removing **61 %** of today's loss (38,600 rows) |

**The loss is not where EXACT is.** EXACT functions average 15 instructions; the loss lives in
the 20–199-instruction band (83 % of it), where we hold 0.58 → 0.37 similarity:

| size (insns) | n | EXACT | weight | WGSS | share of loss | non-equal rows: semantic / form / layout |
|---|---|---|---|---|---|---|
| < 20 | 849 | 572 | 9,898 | 0.815 | 2.9 % | 506 / 980 / 237 |
| 20–49 | 1150 | 186 | 37,429 | 0.583 | 24.8 % | 4,188 / 8,376 / 2,318 |
| 50–99 | 590 | 7 | 40,262 | 0.436 | 36.1 % | 5,635 / 13,167 / 3,066 |
| 100–199 | 166 | 0 | 22,070 | 0.366 | 22.2 % | 3,831 / 8,208 / 1,585 |
| 200+ | 41 | 0 | 12,054 | 0.275 | 13.9 % | 2,081 / 5,669 / 819 |

So the target population is ~1,900 medium functions, and EXACT flips are the wrong yardstick
for them: a 60-instruction function goes 0.43 → 0.60 → 0.80 one mechanism at a time. (This
is the WGSS-first bar, now with the size data behind it.)

## 2. What the divergent rows are

77,198 attributed rows (both sides), by class:

| class | rows | share | whose |
|---|---|---|---|
| extra — we emit code the original lacks | 16,531 | 21.4 % | ours (source shape) |
| missing — the original computes more | 13,587 | 17.6 % | ours (correctness / interfaces) |
| regalloc — same op, other registers | 13,582 | 17.6 % | allocation (P3) |
| selection — another instruction for the same job | 12,130 | 15.7 % | source form / P3 |
| operand-form — widths, offsets, constants | 8,628 | 11.2 % | ours (types, layout) |
| layout-shift — derived from an upstream size change | 8,025 | 10.4 % | consequence |
| branch-target / immediate / encoding | 4,714 | 6.1 % | ours / flags |

By *mechanism* (instruction shape; rows / functions):

- **extra**: `XOR R,R` 1,389 / 730 · `MOV R,R` 1,352 / 642 · `POP R` 960 / 342 · `ADD R,R`
  841 / 286 · `AND R,imm` 787 / 471 · `TEST R,R` 539 / 291 · `SHL R,imm` 382 / 235 ·
  `CALL` 360 / 227 · spills `MOV [ebp-x],R` 284 / 163.
- **missing**: `POP R` 2,078 / 670 · `PUSH R` 1,315 / 649 · `XOR R,R` 1,100 / 656 ·
  `MOV R,R` 1,017 / 599 · `MOV R,imm` 556 / 353 · `CALL` 311 / 192 · narrow loads
  (`byte/word ptr`) 388 / 256.
- **selection**: branch polarity (`JZ↔JNZ`, `JMP↔Jcc`) ≈ 620 rows; `JMP↔RET` 161 (shared
  returns); `CMP [mem],imm → TEST R,R` 99; `MOV R,word → MOVSX` 69; `XOR R,R → MOV R,R/imm`
  170; `AND R,imm → TEST/SAR` 154.
- **operand-form**: same mnemonic, different immediate/width/offset — 320 `MOV R,imm`,
  292 `CMP R,imm`, 221 loads with another displacement; only 33 rows differ purely by a
  frame offset (frame layout is NOT a class).

Three mechanism families stand out, all reachable from source shape and already half-understood
in [`byte-exact-families.md`](byte-exact-families.md):

1. **Width / truth-value (F1)** — `XOR R,R`/`AND R,0xff`/`TEST`/`SETcc`/`MOVSX`, both directions:
   the original holds narrow memory values in `int` locals, widening once at the load
   (`XOR EBX,EBX; MOV BX,[m]`: 505 missing-XOR rows directly followed by a narrow MOV, in 353
   functions), where our C works in byte registers and normalizes. Worked design exists
   (locals declared at widened width, conversion at the def); `shift-mask`, `return-split`,
   `cond-form=nested` already landed from this family.
2. **Copies and temporaries** — `MOV R,R` extra 1,352 / missing 1,017: our C carries
   temporaries the original didn't (or merges ones it kept). This is the temporary-splitting
   axis of the architecture doc, and it is what drags the **callee-save set** with it:
   missing `POP ECX/EBX/EDX` 1,246 rows and missing `PUSH` 1,315 are Watcom saving registers
   the original's body *used*; we use a different register set because we have different
   values live. Push/pop rows are a consequence class, like layout-shift — they fall when
   the body matches.
3. **Layout and polarity** — branch-polarity selection rows + branch-target 2,654 +
   layout-shift 8,025: the original's block order is *in the bytes*; emitting blocks (and
   if/else orientation, return placement) in the original's address order is a
   semantics-preserving axis with a deterministic answer.

`missing CALL` (311 rows, 192 functions) and `extra CALL` (360 / 227) are spread over many
targets (largest: 0x63be5, 24 functions — the 31c60 family's if-placed call) — not one
class; they are the sweep's prototype/argument frontier.

## 3. The central measurement: form divergence is mostly independent of semantic divergence

99.5 % of the loss sits in functions that still have at least one semantic row
(missing / extra / branch-target), and 13,449 of the 13,582 regalloc rows live in those same
functions; the 66 form-only functions (SAME_SHAPE/SAME_CODE) carry 325 of loss. That could
mean form divergence is a *consequence* of semantic divergence (fix what we compute, the
registers follow) — the hopeful reading. It is mostly not. Binning the mid-size MISMATCH
functions by how many semantic rows they carry:

| semantic rows | n | weight | form rows per insn | mean WGSS |
|---|---|---|---|---|
| 0 | 93 | 3,227 | 0.269 | 0.574 |
| 1–2 | 310 | 11,454 | 0.256 | 0.599 |
| 3–5 | 386 | 15,988 | 0.291 | 0.500 |
| 6–10 | 455 | 24,176 | 0.330 | 0.430 |
| 11–20 | 312 | 24,105 | 0.366 | 0.363 |
| 21+ | 118 | 13,745 | 0.312 | 0.349 |

Functions with nothing semantically wrong still differ in form on **~26 % of their
instructions**, and that density rises only mildly with semantic damage. Inside those 403
low-semantic functions the rows are: extra 2,376, regalloc 1,548, selection 1,152,
layout-shift 1,028, operand-form 974 — the `extra` mass (copies `MOV R,R` 189, `ADD R,R`
178, `XOR R,R` 158, `AND R,imm` 133, `POP` 125, `TEST` 95, `SHL` 76) still leads, and
regalloc is the majority of the residue in only 50 of them.

Consequences:

- **Fixing everything we compute wrong is worth ≈ +0.10–0.12 WGSS**, taking a typical
  mid-size function from ~0.43 to ~0.60. Necessary, not sufficient.
- **0.8 is not reachable without attacking form directly** — the `extra` shape mass
  (temporaries, widths, idioms), selection forms, and finally register allocation.
- The allocator is the *last* of these, not the first: the `extra`/width/idiom rows are
  source-shape choices Watcom answers deterministically, and each one we fix also removes
  the allocation cascade it caused. The 6c6f0 hand-convergence record (structure exact,
  similarity stalls at 0.35) is the 200+ band; the 20–99 band, where 61 % of the loss is,
  has far less allocation freedom and is where the per-mechanism work pays.

## 4. Arithmetic of 0.8

Current loss 62,899. The three routes, with what the evidence supports:

| route | what it removes | evidence | estimate |
|---|---|---|---|
| R1 semantic convergence — sweep-driven faithful ports + interfaces (prototypes, stack/register args, returns, dropped/extra calls) | missing 13.6k + branch-target 2.7k, plus their extra/layout cascades | the coupling table (0.43 → 0.60 on a typical function); today's +181 / +53 / +126 | **+0.10 – 0.12** |
| R2 source-form rules — deterministic emission axes measured against Watcom: widening idiom (F1), truth values, temporary merge/split, `lea`/`shl`/`add` idioms, `rep movs` inlining, comma clauses, block order & polarity, return placement | the `extra` mass 16.5k, selection 12.1k, operand-form 8.6k, and the consequence classes (push/pop 3.4k, layout-shift 8.0k) | F1's probes (`shift-mask` +13 EXACT, `return-split` +14), the families census, the 403-function shape census above | **+0.12 – 0.18** |
| R3 allocation — model-inverse from the OW `regalloc.c` algorithm (savings-sorted conflicts, table-order first-wins) driving declaration order / temporaries, with compile-in-the-loop search as the fallback | the regalloc residue that survives R1+R2 | confirmed levers: commutative-operand order, size-2 aggregation; refuted: tie-order dials, interleave; decl-order hill-climb +12/536 on 6c6f0 | **+0.05 – 0.10** |

Sum: 0.48 + 0.27…0.40 → **0.75 – 0.88**. 0.8 is inside the range only if all three deliver;
R1 and R2 alone plateau around 0.70–0.75. That is the honest shape of it: 0.8 is a three-front
campaign, and the third front (allocation) is the one with the weakest evidence today.

## 5. The plan

Principles (unchanged): faithful Ghidra ports for P1/P2; compiler-specific knowledge only in
the emitter's measured axes (`EmitChoices`) and the codegen model; every change measured by a
corpus round under the WGSS-first bar (WGSS up, zero verdict regressions; a Ghidra-faithful
verdict flip is JD's call, asked, not assumed); the oracle sweep and this mechanism census run
every round, and the census decides priorities.

**Phase A — semantic convergence to the sweep's floor (R1).** Work the sweep's ranked list
and the `missing`/`extra CALL` rows: prototype/argument classes (the 5761c CALLIND class,
FUN_000686bc), the return-side `AncestorRealistic`, the if-condition comma-statement class
(14 functions), then the remaining sub-0.8 sweep functions by lost weight. Checkpoint: the
semantic-row total (missing + branch-target, 16,241 today) halves; WGSS ≈ 0.55–0.58.

**Phase B — the three shape families (R2), in this order, each as an emitter axis with a
Watcom probe behind it:**
1. *Widths* — the F1 widening idiom (locals at widened width, conversion at the def), then the
   remaining truth-value shapes (merged booleans: dominance-gated constant substitution).
   Direct reach 505 missing-XOR rows / 353 functions plus the `AND 0xff`/`TEST`/`SETcc`
   cascades (~4–5k rows).
2. *Temporaries and copies* — a temporary-merging axis: render a value through one variable
   per live range only where the original's register set says so; measured by the extra/missing
   `MOV R,R` rows (2.4k) and the callee-save push/pop rows (3.4k) they control.
3. *Layout* — block emission in the original's address order, branch polarity from the
   original's fallthrough, return placement (the `JMP↔RET` rows): branch-target 2.7k +
   polarity ~0.6k, and the 8.0k derived layout-shift rows vanish with them.
   Checkpoint: WGSS ≈ 0.68–0.72; the push/pop and layout-shift classes below 2k rows each.

**Phase C — allocation (R3), de-risked first.** Before building anything: a pilot on the 403
low-semantic mid-size functions — hill-climb declaration order and the known statement-form
axes with the compile loop (≈1 s per probe, ~200 probes per function, a few hours of
machine time), scoring matched rows. The pilot answers the one question that decides the
design: *how much of the 0.27 form rows per instruction is reachable from source shape at
all?* If most of it moves, build the model-inverse from the OW allocator source (the
deterministic tie-break is known: savings-sorted conflicts, ShellSort, table order
EAX,EDX,EBX,ECX,ESI,EDI) so the search becomes a lookup; if little moves, the residue is
the compiler's and the ceiling is ~0.75. Checkpoint: the pilot's per-function gain
distribution, published before any corpus-wide allocator work.
*Run 2026-08-31: see [`phase-c-pilot-results.md`](phase-c-pilot-results.md) — the twelve free emit
axes reach 60.3 % of the band and improve none of it, so the allocator question is UNJUDGED and
witnessed `extra`-class levers are its prerequisite.*

**Phase D — the last mile to 0.8.** Re-run the census; by then the loss is the allocation
residue plus whatever R1/R2 left per size band. Decide per band: search (compile-in-the-loop
per function) where the freedom is small, model-inverse where it is not.

## 6. What would make this fail, and how we would know

- **R2's axes turn out per-function rather than systemic** (each idiom needs its own gate):
  visible as corpus rounds that move a few dozen rows each. Mitigation: the census ranks by
  functions-reached, not rows; an axis that reaches < 100 functions is not built.
- **The coupling is worse than the table says** (fixing semantics re-rolls allocation into
  new divergence): visible as regalloc rows rising while missing rows fall. Mitigation: report
  regalloc rows per round; the Phase C pilot is scheduled early for this reason.
- **The allocator residue is a compiler property** (6c6f0's tie-break at byte-identical
  context): the ceiling is ~0.75 and 0.8 needs the compiler's own allocator in the loop —
  a different project. The pilot measures this before we commit to it.
- **A ceiling that is not ours** — encoding rows are 141 in 1 function; hand-written or
  foreign-compiler code is not a factor in this corpus.

## 7. Instruments (all in the tree)

`scripts/war2-verdicts.sh` (census + movers, WGSS), `scripts/war2-mechanism-census.py`
(this document's tables), `war2_oracle_sweep` + `scripts/war2-osweep-{rank,cmp}.py` (Ghidra
divergence as a defect finder), `recompile_check --divergences` (the rows), the probe recipe
in `war2-recompile-remeasure.md`, and the oracle recipe in the memory notes.
