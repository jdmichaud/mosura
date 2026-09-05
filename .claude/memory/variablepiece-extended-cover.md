---
name: variablepiece-extended-cover
description: "VariablePiece split ✅ LANDED `be13a04`: mosura's size-blind merge_addrtied approximated Ghidra's EXTENDED COVER (VariablePiece::updateCover), not identity. Fixed 505 the subject value drops (narrow writes rendered full-width). Corpus 0.9542/57, suite 564/0. Residual = upstream IR extracting pieces via uniques."
metadata: 
  node_type: memory
  type: project
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-28T17:32:25.354Z
---

# VariablePiece: identity vs the Cover that spans a group

✅ LANDED `be13a04` (2026-07-28), on top of the copy-marker slot brick `8c9c6bb`.

**The reframe.** Ghidra separates two things mosura conflated:
- **identity** — which C variable a Varnode belongs to. Per `(address, size)`: `mergeRangeMust`
  merges only same-(addr,size) subranges of `overlapLoc` (varnode.cc:1785); different sizes are
  linked by `groupWith` (variable.cc:571) into a VariableGroup of **separate** HighVariables.
- **the Cover used for interference** — spans the overlap group. `VariablePiece::updateCover`
  (variable.cc:160) is eight lines: own internalCover ∪ the internalCovers of byte-overlapping
  pieces. `HighIntersectTest::intersection` (variable.cc:1166) reads exactly that via `getCover()`.

mosura's size-blind union was an approximation **of the extended cover**, not of identity. Ghidra's
caching (`intersectdirty`/`extendcoverdirty`/`combineGroups`/`adjustOffsets`) does **not** port —
mosura recomputes covers from scratch, so both reduce to pure functions. The depth valve
("per-group covers ⇒ VariableGroup ⇒ stop") was priced on an unchecked assumption; the lead lifted
it after verifying the source.

**HEAD was buggy, not merely approximate**: the fusion rendered narrow writes as full-width
assignments — `uRam000000000008196c = (uint4)xVar12;` for a 1-byte store. **505 sites across the subject**,
plus `partialmerge`'s 8-byte store emitted as `iRam0000000000100670 = (int4)param_1`.

## What the unit contains (all five parts, none droppable — every intermediate is wrong code)
1. `merge_addrtied` keyed on (space, address, SIZE) + the overlap groups. Three distinct jobs, kept
   separate in comments: `unifyAddress`/`eliminateIntersect` over the whole overlap range (mosura's
   mergesnip), `mergeRangeMust` over same-(addr,size) subranges, `groupWith` linking them.
   **The extended cover prevents merges; it does not force snips.**
2. `updateIntersections`/`updateCover` as pure functions, consulted **only** at the interference
   tests. ⚠️ Extend over the **group's piece set**, NOT raw byte-overlap of all addrtied varnodes —
   the coarse version grows a snapshot Ghidra never emits (`revisit`).
3. The refusals: `mergeTestRequired` (merge.cc:147-153 — same group never; cross-group only if one
   piece spans its group. Without it the same-address arm re-fuses what mergeRangeMust separated)
   and `mergeTestAdjacent` (merge.cc:210-212).
4. **PIECE/SUBPIECE arms of `markInternalCopies`** (merge.cc:1487/1516) — unportable before, they
   switch on `high->piece`. They land at the copy-marker slot. This **retired a hand-rolled
   adaptation** in `explicit_leading` ("SUBPIECE-of-addrtied is an internal copymarker") — Ghidra's
   `baseExplicit` has no such sub-case; it stood in for this arm.
5. `pushPartialSymbol` (printc.cc:1947) → `unnamedField` (printlanguage.cc:719): a non-spanning
   piece renders off the **spanning piece's** name — cast at group offset 0 (`isSubpieceCast`,
   cast.cc:411, offset 0 only), `._<off>_<size>_` otherwise. An assignment target takes the
   plain-occurrence path with `allowCast=false` (printc.cc:1886) — a cast is not an lvalue.

## Measured
corpus 0.9543→**0.9542**/57 (only the 3 targeted fixtures move; the printc half recovers what the
split costs — the 0.9505/0.9523 diagnostic numbers were intermediates, not the landed state).
`partialmerge` byte-identical to the oracle; `multiret`'s three same-name declarations gone.
the subject 1286/1286, 28 files differ, −171 lines (mostly self-assignment round-trips the fusion created),
**real call count identical at 5123** once prelude macros (`SUB*`/`CONCAT*`/`ZEXT*`/…) are excluded
from the regex — the raw count's −1 was `SUB42(..)` becoming `._2_2_`. Suite 564/0, clippy 0.

## COMPILE_FAIL delta — MEASURED `84fc736`, lead-ruled: the trade is correct, no revert
Both sides same harness, `obj/` cleaned, state-asserted (0 render-files before, 20 after).
**COMPILE_FAIL 71 → 89.** Every transition is MISMATCH → COMPILE_FAIL, 18, nothing the other way,
EXACT holds at 1. All 18 = one new class `E1032` ("Expression for '.' must be a 'structure' or
'union'"). Total E1032 = 20 = exactly the render-files (2 were already failing under E1052, 37→35).
All other classes unchanged. The 18 previously compiled to **0-3% byte match** (17 of 18; last 12%)
— compilable-but-wrong was never a real pass. Results kept at `<subject-survey>/results.copymark-8c9c6bb.tsv`
and `results.varpiece-be13a04.tsv`.

**THE SPLIT THIS NAMES (lead ruling, keep):** `._<off>_<size>_` is Ghidra's own artificial-field
syntax, so the decompiler is FAITHFUL and stays. Ghidra's output was never meant to compile; the
byte-exact goal needs it to. **Faithful and compilable are SEPARATE AXES**, and closing the gap is an
emitter/harness job — NEVER a reason to put a wrong-code render back in the decompiler.

## ✅ RECOVERED in the emitter `cd76111` — COMPILE_FAIL back to 71
`corpus_emit.rs` rewrites `base._<off>_<size>_` → `*(uintN *)((char *)&base + off)` before the
identifier scan (base appears as `&base`, not a pointer use, so it keeps its scalar declaration).
**COMPILE_FAIL 89→71, E1032→0, ZERO transitions vs the pre-VariablePiece baseline** — so the whole
VariablePiece landing is COMPILE_FAIL-neutral while keeping its 505 wrong-code fixes. Decompiler
output (`raw/`) and the corpus both byte-identical across it, as an emitter-only change must be.

**Width checked against wcc386, not assumed** (probe TU, survey flags `-4r -fpi87 -s -onat`):
`(*(uint1 *)((char *)&g + 1)) = v` → `a2 01000000` (`mov [g+1], al`, 1 byte); `uint2 @+2` →
`66 a3 02000000` (2 bytes); the OLD `g = (uint4)v` → `25 ff000000` + `a3` (`and eax,0xff` +
**4-byte** store = the value drop). Only sizes 1/2/4 are rewritten (exact unsigned types); `uint8` is
excluded — the prelude maps it to `double`. Unknown sizes are left to fail loudly, never widened.

**%match cannot adjudicate this**: at 0-12% a one-instruction width change shifts every downstream
offset, so byte-diff percentage is alignment noise (8 better/7 same/5 worse). Use **length fidelity**
instead — 13 of 18 closer to the original, 1 same, 4 further.

**Union form rejected on evidence**: `union { uint4 w; uint1 b[4]; uint2 h[2]; }` accessed `.b[1]`/
`.h[1]` compiles to **byte-identical** code (`a2 01000000`, `66 a3 02000000`, read `a0 01000000`) —
no headroom, and it would force every whole-variable use through `.w`.

**Residual, upstream**: `revisit` renders its low piece but not the oracle's `._2_2_` high piece —
mosura's IR extracts it via `INT_RIGHT` + SUBPIECE **from a unique**, Ghidra uses SUBPIECE at
offset 2 from the addrtied whole. The faithful arm correctly declines on a non-piece operand;
accepting uniques would be an invented heuristic. See [[faithful-type-of-wrong-ir]].

Related: [[adaptations-inventory]], [[merge-family-cluster]], [[gate-byte-identical-only]].

## ✅ LANDED `be13a04` (one unit, all 5 acceptance criteria)

Corpus 0.9543→0.9542 (only the 3 targeted fixtures move); suite 564/0; clippy 0. **HEADLINE: HEAD was dropping values AT SCALE — 505 narrow writes across the subject rendered as FULL-WIDTH assignments** (`uRam..8196c = (uint4)xVar12` for a 1-BYTE store, claiming 4 bytes it never writes → now `uRam..8196c._0_1_ = xVar12`). Same class as partialmerge's `iRam..0670 = (int4)param_1`. **That wrong-code class is CLOSED.** multiret's duplicate-name declarations gone; partialmerge BYTE-IDENTICAL to `oracle/capture --c`; the subject 1286/1286 emitted, 28 files differ, real call count identical (5123), −171 lines, 0 casts reaching an lvalue.

**BEYOND PLAN (correctly): ported the PIECE/SUBPIECE arms of `markInternalCopies` (merge.cc:1487/1516)** — previously unportable (they switch on `high->piece`), enabled by the copy-marker slot from `8c9c6bb`. **This RETIRED A HAND-ROLLED ADAPTATION:** `explicit_leading`'s "SUBPIECE-of-addrtied is an internal copymarker" test had NO counterpart in Ghidra's `baseExplicit` — it was standing in for exactly these arms. ([[port-all-faithful-rules]])

SCAN DISCIPLINE: the raw call count dropping by exactly 1 was the thread pulled → the regex counted a prelude `SUB42` macro as a call; re-ran excluding SUB*/CONCAT*/ZEXT*/SEXT*/CARRY*/SBORROW*/POPCOUNT → 5123 both sides, zero per-file deltas. The −171 lines are dominated by removed self-assignment round-trips that existed ONLY because the fusion made a piece read/write pair look like a self-copy.

**RESIDUAL (named, not papered over):** `revisit` renders its low piece but not the oracle's `iRam..0074._2_2_` high piece — mosura's heritage extracts that half via `INT_RIGHT #0x10` + SUBPIECE FROM A UNIQUE where Ghidra uses `SUBPIECE(addrtied whole, 2)`. The faithful arm correctly DECLINES on a non-piece operand; loosening it to accept uniques would be an invented heuristic ⇒ upstream IR gap, [[faithful-type-of-wrong-ir]].

## ⚖️ LEAD RULING ON THE TRADE (2026-07-27)

`._<off>_<size>_` is Ghidra's own artificial-field syntax and **does NOT compile in C** (~20 of 1286 the subject files), so the compile stage likely trades some passes for fails. **The land STANDS — not reverted, not softened.** Ordering is unambiguous: wrong code is disqualifying; faithful ports land; this is the E1052-class verified-faithful ceiling. **A function that fails to compile is strictly better than one that compiles to WRONG semantics — a wrong-but-compilable function was never a real pass.**

Directed: (1) MEASURE the COMPILE_FAIL delta (clean obj/, same harness both sides, state-asserted) so the record carries the honest number and no future re-measure reads this trade as an unexplained regression. (2) **FILE A NEW ITEM splitting a conflation we'd been carrying: rendering `._0_1_` in COMPILABLE form** (width-correct cast through the base address, or a union) **is an EMITTER-LEVEL, BEYOND-GHIDRA concern — NOT a faithfulness one.** Ghidra's output was never meant to compile; our byte-exact goal requires it to. It belongs with the harness/emitter, is NEVER a reason to keep a wrong-code render in the decompiler, and it is now the thing standing between these 505 sites and compilability.

## 📊 THE TRADE, MEASURED (`84fc736`, docs-only)

**the subject COMPILE_FAIL 71 → 89 (+18).** Both sides same harness, `obj/` cleaned each time, sides state-asserted by the render's presence (0 files before, 20 after). **Side A reproduced the recorded baseline EXACTLY (1 EXACT / 1214 MISMATCH / 71 CF) — the harness attesting itself before side B was trusted.**

| status | `8c9c6bb` | `be13a04` |
|---|---|---|
| EXACT | 1 | 1 |
| MISMATCH | 1214 | 1196 |
| **COMPILE_FAIL** | **71** | **89** |
| DECOMPILE_FAIL | 0 | 0 |

**Every transition is MISMATCH→COMPILE_FAIL, 18 of them, nothing the other way, EXACT held.** All 18 are ONE new class `E1032: Expression for '.' must be a 'structure' or 'union'`; total E1032 = 20 = exactly the 20 render-carrying files; the 2 already-failing move OUT of E1052 (37→35) so the totals reconcile. Every other class unchanged ⇒ **fully attributable, zero collateral.** Prediction check: ~20 predicted, 18 newly-failing of 20 carrying the construct.

**WHAT WAS TRADED, quantified — vindicates the ruling: the 18 that "compiled" matched the original at 0-3% (seventeen of them; the last at 12%). Against 505 narrow writes corrected. They were never passes — wrong bytes that happened to satisfy a compiler.** Recorded as a dated section in `<subject-profile>/notes/function-status.md` so a future re-measure reads the jump as this documented trade. Labelled results: `<subject-survey>/results.copymark-8c9c6bb.tsv`, `results.varpiece-be13a04.tsv`.

## ▶️ TASK #4 (GATED GO) — compilable partial-symbol render, EMITTER-LEVEL

Recovers the 18 directly, serves byte-exact head-on, and being emitter-level **cannot touch decompiler faithfulness — bounded risk by construction.** Scope: `corpus_emit.rs` EMIT stage or its prelude; translate `._<off>_<size>_` into width-preserving compilable C (write through the base address, or a union-typed synthesized global). **DO NOT: change printc's render · loosen the PIECE/SUBPIECE arms · revert any part of `be13a04`.** Nothing in `crates/mosura/src/decompile/`. SUCCESS TEST (agent's design, reaffirmed): **E1032 → 0, no new class, and those 20 files' byte-match NO WORSE than side A's 0-3%** — the second clause is the guard that stops a wider-than-needed write from quietly reintroducing the value drop. Tiebreak between approaches: whichever recompiles closer to the original bytes. Corpus must be UNTOUCHED (harness-only ⇒ any corpus movement is a bug in the change). Open decompiler items after this: audit #8 (names), #9 (CALLOTHER token).

## ✅ TASK #4 LANDED `cd76111` — the whole VariablePiece landing is COMPILE_FAIL-NEUTRAL

**COMPILE_FAIL 89 → 71, E1032 → 0, ZERO transitions vs the pre-VariablePiece baseline (`8c9c6bb`) — while KEEPING the 505 wrong-code fixes.** Faithful decompiler + compilable emitter, no debt traded.

| status | `8c9c6bb` | `be13a04` | `be13a04`+emitter |
|---|---|---|---|
| EXACT | 1 | 1 | 1 |
| MISMATCH | 1214 | 1196 | 1214 |
| **COMPILE_FAIL** | **71** | **89** | **71** |

Mechanism: `corpus_emit.rs` rewrites `base._<off>_<size>_` → `*(uintN *)((char *)&base + off)` BEFORE the identifier scan, so the base keeps its scalar declaration (seen as `&base`, not a pointer use). Emitter-only, verified not assumed: `raw/` byte-identical across the change AND corpus byte-identical to `be13a04`. Only sizes 1/2/4 rewritten — anything else FAILS LOUDLY rather than silently widening; `uint8` excluded (prelude maps it to `double`).

**WIDTH GUARD CHECKED AGAINST wcc386, NOT INFERRED** (probe TU, survey's own flags): `*(uint1*)((char*)&g+0)=v` → `a2 00000000  mov [g+0],al` (1 byte); `+1` → `a2 01000000`; `*(uint2*)(...+2)` → `66 a3 02000000  mov [g+2],ax` (2 bytes); **the OLD form `g = (uint4)v` → `and eax,0xff` + dword store = the value drop, visible in the encoding.**

**UNION FORM REJECTED ON EVIDENCE** — built it rather than argued it: `.b[1]`/`.h[1]` compile BYTE-IDENTICALLY (`a2 01000000`, `66 a3 02000000`). No headroom (the address form already emits the minimal exactly-sized instruction), and the union would force every whole-variable use through `.w`. Dead heat on the byte tiebreak ⇒ decided on invasiveness.

**⚠️ PRECEDENT — post-hoc criterion revision, ACCEPTED but bounded.** The agent's own success clause ("byte-match no worse than 0-3%") returned 8 better / 7 same / **5 worse**. It neither declared failure nor dropped the clause: it argued the metric can't adjudicate this change (at 0-12% match a one-instruction width change shifts every downstream offset ⇒ positional %match is alignment NOISE) and supplied an alignment-independent measure — **length fidelity closer on 13 of 18, same on 1, further on 4**, with a mechanism (narrow stores no longer carry `and eax,0xff` + dword expansion). **LEAD RULE SET: a criterion MAY be revised when direct evidence settles the underlying question INDEPENDENTLY of the metric (here the wcc386 probe answers "does the write have the right width?" at instruction level); it may NOT be revised merely because it returned an unwelcome number.** This cleared that bar.

## ▶️ NEXT (lead-directed, read-only, ahead of #8/#9): characterize the 0-16% match band

The campaign's central open question. We've called the whole-corpus band "codegen/regalloc" for weeks, but **pure register-allocation differences on an otherwise-identical instruction sequence should score FAR higher than 0-12% — a number that low smells STRUCTURAL, not allocational.** Sample the 12% best case + 2-3 typical + 1 newly-compiling function; diff INSTRUCTION BY INSTRUCTION vs the original, classifying each divergence: prologue/epilogue shape · calling-convention/parameter placement · instruction selection · register assignment only · code present in one and absent in the other (is the STRUCTURE even the same?) · artifacts of compiling one function standalone vs in-program (register pressure, no cross-function context). **THE QUESTION: is any material share of that band decompiler-reachable, or is it genuinely the compiler-matching wall we filed? Either answer is valuable — retire the ambition honestly with evidence, or find the largest remaining win we've been walking past.**
