# Byte-exact divergence families — the census

*Generated from sb43 (`a6b4b04`, 586 EXACT / 2210 MISMATCH / 84 SAME_SHAPE). Source data:
`/data/be2/sb43-div.tsv` (88,464 per-instruction divergence rows, `recompile_check
--divergences`) joined with `/data/be2/sb43.tsv`. Regenerate both rather than quote after
any change; every count below is one awk over those files.*

*Re-censused at sb93 (687 EXACT / 0.4355, `/data/be2/sb93-rec{,-div}.tsv`): single-class
marginal values were missing 60 / operand-form 32 / extra 11 / regalloc 9 / selection 7 /
immediate 4; 27 functions one substantive row from EXACT, 154 within three. That pass
surfaced F5 below (landed sb94). F1–F4 counts above remain the sb43 measurement.*

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
- **The comma-clause SETcc mechanism NAMED (2026-08-18 late): most remaining extra SETccs
  are Watcom materializing a statement-carrying short-circuit clause** — our faithful
  collapsed rendering (`if (a && (stmt, b))`) forces the clause's boolean into a value;
  the originals wrote nested ifs and stay branch-only. Hand probe on specimen `01304`:
  the nested form removes every materialization row (2 branch-polarity rows remain). A
  `cond-form=nested` axis was implemented and REVERTED as wrong code: the un-collapse
  must mirror `render_cond_expr`'s exact per-node negation/orientation algebra (each
  condition node carries its own `negated`, XOR-folded by the collapse rules), and a
  simple De Morgan flatten inverted a predicate. The design stands with that trap
  documented; the implementation must drive the split through the real condition
  renderer, not a reimplementation. **DONE (sb58): `cond-form=nested` landed faithfully**
  — `collect_conj_clauses` mirrors only the recursion-where-`&&` decision (per-node
  `cond_flip` and `operand_oriented` XORed into each operand's effective negation) and
  every clause's text comes from `render_cond_expr` itself; the specimen reproduces the
  hand probe exactly (all materializations gone, 2 polarity rows remain). Zero verdict
  wins yet — every comma-clause function carries co-resident divergences — but +37/−14
  sub-verdict sim movers inside the arm; the axis is the foundation the polarity and
  scheduling families will stack on.
- **The general merged-boolean design (next in line, 221 functions still carry extra
  SETcc)**: the remaining shapes materialize a boolean that is BOTH branched on and kept
  as a value (specimens `00211`, `01304`: `SETcc + AND` beside the very `Jcc` that tests
  the same predicate; the originals stay branch-only and resolve each later use
  per-path). The generalization of `return-split`: render uses of `B` that are dominated
  by the then-edge as `1` and by the else-edge as `0` — a dominance-gated constant
  substitution at emission, value-identical by the same argument as the landed axis.
  Needs the dominator query at print time and a per-use gate; design ready, not yet
  implemented.
- **Merged-boolean returns — LANDED as the `return-split` axis (sb57, +14 EXACT)**: the
  tail-pair pattern (`if (B) {body} return B;`) splits back to per-path constant returns
  under a provable value-identity gate. The ternary spelling measurably does NOT work;
  the split must be structural. Remaining shapes in the 234-function `extra SETcc`
  census: booleans stored to variables/globals, returned through φs of non-adjacent
  paths, or tested by a *different* if — each needs its own gate extension.

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

**DISPOSITION RESOLVED (2026-08-19, after the battery below): F2 is RESULT-REGISTER
ASSIGNMENT — compiler identity, and the SAME dial as the regalloc class.** The discriminating
test ran: seven C shapes for the pilot (expression; `t += k`; `t = t + k`; reuse-after-store;
volatile; and both via-call forms) — **all seven fold**. No ordinary C makes 10.0a emit the
original's `ADD EDX,0x12 ; MOV EAX,EDX`, so the difference is not reachable from our side.
Reading the pilot's original explains why, and it is NOT liveness (EDX is dead after — it is
popped): the value sits in EDX because `IDIV` writes the remainder there, and the ORIGINAL's
codegen assigns the add's result to **op1's own register** (in-place `ADD`, then a copy to the
return register), where 10.0a assigns it to the **destination** register and therefore needs
the `LEA`. That is a result-register-assignment preference — the same underlying dial as the
`regalloc` divergence class and warcraft2-re's `ecx-allocator-mystery`, not a fold decision
and not an emission question.

**Consequence — a falsifiable PREDICTION for the allocation-order experiment, recorded before
it runs:** if the interim build's difference is register-assignment preference, then patching
10.0a's allocation dials toward WAR2's observed preference should move F2's rows *together
with* the `regalloc MOV>MOV` class. If the regalloc rows move and F2 does not (or vice versa),
this unification is wrong.

**Prior disposition (superseded twice — kept because the flip-flop is instructive):** The pilot's disposition below rested on two things. Point 4 —
"the original binary is systematic about it: **zero** `LEA reg,[reg+imm]` folds in 380KB" —
is **factually wrong**: it was a hex-pattern scan, and disassembling every original finds 336
such folds in 226 functions (586/312 with address-of-local forms), six in byte-EXACT
functions ([`watcom-nofold-patch.md`](watcom-nofold-patch.md)). So the fold is not something
10.0a "cannot produce". BUT the family is NOT thereby "ordinary recovery work" — that was an
over-swing. The no-fold invariance test settles what the fold ISN'T: disabling folding leaves
all F2 functions byte-invariant (zero → EXACT), so the fold is not the discriminator. What IS
different is the mutation target — original `ADD EDX,0x12 ; MOV EAX,EDX` (in-place) vs our
`y = x + k` (fresh value) — a liveness/coalescing question on our side **whose winnability is
unmeasured**, and point 3 below ("no source shape avoids the fold") is a live hint it may not
be winnable at all, i.e. still compiler identity. Status: fold-explanation dead, real
difference located, disposition OPEN pending the in-place-mutation source-shape test; stays
parked until that runs. Points 1-3 below stand as measurements and now frame that test.

**DISPOSITION (pilot, 2026-08-18) — superseded, kept for the chain:** not a mosura defect at
any layer — a toolchain fingerprint. The chain of evidence:

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

### F1-adjacent finding — caller-side register contracts (FIXED, sb52)

The missing-XOR census led to it: what looked like a widening site in `FUN_0003925c` was
a mis-bound call — the caller compiled its arguments into default-order registers because
the bare `extern` carries no `parm` pragma, while the callee's recovered storage is
nonstandard. Every cross-TU call to the 155 nonstandard callees mis-bound. Fixed by a
survey post-pass (definition-side parm map + arity and directional-width gates; the
worked failure modes are in byte-exact-status.md). The byte-extract idiom at such sites
(`XOR EDX,EDX; MOV DL,AL` vs our `MOV EDX,EAX; AND EDX,0xff`) remains a SAME_SHAPE-class
residue.

### Measured and rejected — caller-side `modify` propagation (sb54)

The natural completion of the caller-side contracts (parm landed at sb52) is propagating
the callee's recovered `modify [..]` list to caller externs. Measured: **net −15 EXACT**
(17 regressions, 2 gains, 4,484 TUs patched). The regression pattern says something real
about the original build: its callers compile under Watcom's DEFAULT assumption — a bare
extern's callee preserves everything but EAX — so Blizzard's headers carried no
per-function modify pragmas, and matching the callers means keeping our externs equally
bare. The definition-side modify list stays (the callee's own body proves it, and it is
worth 39% of the historical instruction deficit); the caller side must not know it.
The FUN_00011954 residual (argument-load hoisted above a call the original loads after)
is therefore a scheduling-policy residue, not a contract one.

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
Inline narrow reads landed as tier 2 proper (sb47, +3 EXACT): `force_explicit` +
unsigned widened temps for narrow loads compared against nonzero positive constants —
both gates measured on `FUN_0001562c` (its second clause, a zero compare, stays inline
because the originals compare zero against memory directly). Widening the use-context
gate (arithmetic, call args, switch indices) is the remaining iteration.

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

**Probed, worked, deferred — the entry-snapshot family** (sibling run 01336-01341 plus
~8 more near-frontier byte-global sites): the original snapshots a byte global into a
byte LOCAL at function entry (`MOV AL,[g]` above the branch) and widens at the use;
the reference rendering (oracle-verified identical) propagates the copy and reads the
global inline at the call. The byte-reproducing shape is probe-validated EXACT
(`uint1 uVar2 = xRam0008032c;` at entry). It cannot be produced at render time: the
entry COPY is rule-propagated out of the final IR (faithfully — Ghidra's is too), so the
materialization needs a survey-side IR edit at the dominating position, and since arms
share one Funcdata, that means cloning `f` per arm or keying the edit to the arm — a
design decision (the arms' "same recovered IR" rule is exactly what it would bend).
Value-safety gate when built: the global must have no write between entry and the use.

**Probed and parked (2026-08-18 late session), with the findings that matter:**

- **Byte-width shift cluster** (9 identical signatures, specimen `00847`/`FUN_0002b054`):
  compound. The byte-shift half is the original REUSING the param's variable
  (`g1 = p; p = 1 << p; g2 = p;` — the reuse creates the dependency that forces the
  original's store order and register flow; probed: it aligns the whole shift group).
  The residual is a constant-store scheduling tangle (which register carries which
  constant to which of five adjacent global stores) — per-site permutation territory.
  A variable-reuse render choice would need coalescing machinery; parked.
- **Index-extract cluster** (13 identical signatures, specimen `01262`): worked further —
  the comma-expression materialization RENDERS correctly (the tier-2 gate extended
  through the ZEXT-between-load-and-scale prints the temp inside the short-circuit
  clause, behind the null guard, at the load op's own position), but the bytes still
  diverge: Watcom keeps `AND EAX,0xff` + register-AND-test where the original widens
  differently and tests the table byte memory-direct (`TEST [mem],8`). The remaining
  unknown is Watcom's TEST-mem selection condition; the gate extension was reverted per
  the probe discipline (no specimen win, no ship). Next lever: small out-of-corpus C
  experiments against wcc386 to map the TEST-mem selection, then revisit.

**WRONG-CODE reframing of the branch-polarity residue (2026-08-18, filed as PRIORITY in
TODO.md):** specimen `01304`'s "2 polarity rows" are a semantic inversion — the original
computes `(X||Y) && P`, the oracle prints it, mosura's structure BUILDS it
(`CondAnd[CondOr,P]`), and the render prints `(X||Y) || P`. The deferred-negation
adaptation (`cond_flip`/`operand_oriented` XORs standing in for Ghidra's materialized
`negateCondition`) is internally inconsistent for this shape. Two consequences: part of
the "branch polarity" class is wrong code, not rendering choice; and the byte-checker
under-reports semantic inversions as cosmetic rows — treat `selection` rows on paired
`Jcc`s as suspect until the fix and the corpus audit land.

### F4 — the MOVSX / narrow-compare family (14 near-frontier functions): WORKED, ceiling is SAME_SHAPE

Signature `selection MOV>MOVSX` (+ `TEST>CMP` or `extra SAR`). The original compares in a
16-BIT register (`MOV AX,[EDX] ; CMP AX,9`); our C's `*param_2 == 9` takes C's integer
promotion and Watcom emits `MOVSX EAX,[EDX] ; CMP EAX,9`. Probed to the end on specimen
`01923`/`FUN_0004cb60`:

| C shape | result |
| --- | --- |
| baseline (`*p == 9 && p[1] == 0`) | MISMATCH, 6 rows |
| narrow local only | MISMATCH — load narrows, compare still promotes (`CWDE`) |
| **narrow constant cast only** (`== (int2)9`) | MISMATCH **9 rows — WORSE**: Watcom switches to `CMP word ptr [EDX],9`, losing the load |
| narrow local + narrow cast | 5 rows — first clause EXACT |
| both locals + casts + comma clause | SETcc materialization (the comma-clause mechanism) |
| **narrow locals + narrow casts + NESTED ifs** | **SAME_SHAPE, 2 rows** |
| …plus single-variable reuse | SAME_SHAPE, same 2 rows |

So the recipe is a three-part combination — narrow local materialization, short-typed
comparison constants, and `cond-form=nested` — and its ceiling on this specimen is
SAME_SHAPE: the last two rows are the allocator choosing `DX` where the original uses `AX`,
which is parked pile-B (`DoubleRegs[]`).

**Measured and rejected: a `compare-width=narrow` axis** (the cast alone, which was the one
cheap piece). Implemented, emitted as a fourth arm, and scored: **590 EXACT against the
default arm's 621, winning ZERO functions uniquely** — the cast without the local is
actively harmful, as the probe table predicted. Reverted rather than shipped. Revival
condition: implement the narrow-local materialization first (tier-2's sibling — it keeps the
value NARROW where `local-width=storage` widens it), then re-test the cast on top of it.

**The zero-store family (7 near-frontier functions, specimen `00878`/`FUN_0002c08c`):
mechanism identified, implementation deferred.** The original stores zero to a byte global
through a REGISTER (`XOR BL,BL ; MOV [..],BL`) where our C's `= 0` compiles to the immediate
store. Probed exhaustively: no flag set (`-osnax` breaks the multiply decomposition), no
plain source shape (`= 0`, `(char)0`, `'\0'`, a fresh zero local, a REUSED widened local)
avoids Watcom folding the constant into the store — **except the self-xor: `b ^= b` compiles
to exactly the original's `XOR reg,reg ; MOV [..],reg`.** The byte-reproducing rendering
therefore needs a compound recovered form: materialize the guard's loaded byte as a variable
(the store target was just compared from it in every specimen), self-xor it, store it. The
probe of that combination reaches all-regalloc residue (Watcom splits our one variable across
AL/ECX where the original keeps EBX throughout, costing a PUSH/POP) — so the family's ceiling
under our allocator is near-SAME_SHAPE, and the remaining gap is the parked allocation
policy. Alternative reading kept open: the interim build may simply not fold `b = 0`
into stores, making this pile-B outright.

**Widen-after flavor: measured and rejected (sb83).** The 7-function
`missing XOR | missing MOV | extra AND` trio shows the widening idiom scheduled AFTER the
load (`MOV AX,[..]` then `XOR EDX,EDX ; MOV DX,AX` — reg-to-reg into a different container).
A classifier extension recognizing it measured net −1 (one EXACT regression, zero wins), and
the blanket `local-width` arm ALSO mismatches the specimen — the declaration width is not
the binding constraint for this shape; the divergence involves cross-register allocation
(the original splits load-register from widened-register where our rendering keeps one
variable). Reverted; the trio stays in the census as allocation-adjacent.

**Stored-boolean battery (sb86 era): the question closes NEGATIVELY.** Seven shapes
compiled against the profile: `g = (a==b)`, the branch-and-store `if (a==b) g=1; else
g=0;`, the ternary, a bool local, and call-arg forms. Result: **Watcom's optimizer converts
branch-and-store BACK into `SETcc`** — no C shape avoids materialization for a stored
boolean under `-onatx`. The only branch-preserving context is DIVERGING call arguments
(`if (a==b) return f(1); return f(0);` stays branch-only, because the continuations
differ). Consequence: the remaining extra-`SETcc` census (184 functions corpus-wide, but
only 7 near-frontier) is NOT reachable by any rendering or recovery for the store-shaped
sites — the originals' branch-only stores are the interim build's selection policy
(pile-B) or flow shapes ours doesn't reproduce for other reasons. The landed recoveries
(return-split, cond-form) already cover the shapes that CAN be reached; call-arg splitting
is expressible but its near-frontier population is within the 7 and duplicates calls —
parked unless a specimen proves the shape.

Top near-miss substitution texts for the record: `MOV EAX,0x1`→`MOV AL,0x1` (68 rows),
`MOV CL,AL`→`MOV CL,[EBP-4]` (23), `MOV EAX,0x1`→`AND EAX,0xff` (21).

### F5 — the permutation family (sb93 census re-run): argument DECLARATION order, RESOLVED

The sb93 re-census (687 EXACT / 0.4355) surfaced a family the sb43 numbers had buried:
**35 functions whose entire substantive divergence is a pure permutation of identical
instruction texts** — right instructions, wrong order. The detector is one awk (per
function, the orig-text multiset equals the cand-text multiset). Dominant sub-shape:
call-argument constant setups rotated (`MOV EAX,0xbe2 ; MOV EBX,0x4d08c ; MOV EDX,0x3`
against ours `EBX, EDX, EAX`) — 5 near-frontier callers of ONE callee (`FUN_00058bec`)
shared it exactly.

**Mechanism (source + probe).** Watcom materializes register arguments in REVERSE declared
order (OW 1.0 `bldcall.c`: `AssgnParms` → `ReverseParmNodeList` → `ParmIns`). So the
original's setup sequence reads out the C parameter order the source DECLARED, which is
invisible exactly when it matches the convention's storage order — and our rendering
assumes storage order always. Probes on `FUN_0004d0f8` (the 1-second loop): ANSI prototype
— no change; `parm [eax ebx edx]` single-bracket — pragma ignored (one bracket group per
parameter is the syntax); `parm [eax] [ebx] [edx]` + args permuted — order follows the
declaration; **`parm [edx] [ebx] [eax]` + `(3, 0x4d08c, 0xbe2)` — EXACT.**

**Landed (sb94, +7 EXACT, zero movement elsewhere, WGSS 0.4361):** per-site evidence
(`buildconfig::call_setup_sites` + `param_orders_from_evidence`), rendered as permuted
argument list + full-arity caller pragma per TU (`RecoveredChoices::call_arg_orders`).
Two measured gates: per SITE not per callee (a per-callee consensus broke two EXACT
callers whose own sites read slot order — one callee's sites genuinely disagree, reason
unresolved), and CONSTANT arguments only (an identifier permutation demoted three
SAME_SHAPE siblings to MISMATCH as a pure regalloc cascade — variable reorder perturbs
the allocator function-wide). Full entry: byte-exact-status.md sb94.

**Residual (28 functions), classified:**

- **Load scheduling — pile-B, now with a direct probe.** `FUN_00073328` forwards two stack
  params; the original loads `[EBP+0xc]` then `[EBP+8]`, 10.0a loads ascending — and NO
  source shape moves it (pragma order, argument order, explicit temps all probed). Also
  `0006b496`/`00068bca` (load pairs) and the `00025a04/25de4/26004` triplet (a widening
  pair displaced).
- **Independent-STATEMENT order (~10, unworked and workable):** stores, INCs, and CALLs
  displaced across one neighboring statement (`000125bc`, `00034590`, `0004c270`,
  `0005d500`/`0005d57c`, `00025260`, `0003e7ec`, `0003ef60`, `0003e858`, `0005bbdc`) —
  the persist-store ordering mechanism generalized beyond stores. Needs its own
  candidate/evidence design; op addresses carry the original schedule.
- **Displaced single constants (~6):** windows with one visible setup carry no order
  information, and their co-arguments are identifiers/loads (`00011954`, `00011b9c`,
  `00030bf4`, `00050a90`, `00021a48`, `000469b4`).
- **Pure allocation pairs (pile-B):** `000294b8`, `000464b4`. **Masking order:**
  `0004d528` (`AND AL,0xc0` vs `AND EAX,0xff` swapped — not a call site). **Encoding:**
  `00074734` (`MOV EBP,ESP`, the other spelling — parked).

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
5. Re-run this census (both TSVs + the awks above) after each family lands — done at sb93
   (surfaced F5, landed sb94); current baseline `/data/be2/sb94-rec{,-div}.tsv`.
6. **F5 residual** — the independent-statement-order subfamily (~10 fns) is the next
   candidate, with the measured caveat that specimen `000125bc`'s C statement order ALREADY
   matches the original (the divergence is a compiler hoist its shape triggers) — probe each
   specimen before designing machinery.
