# Byte-exact — where this stands

*Re-measured from scratch on branch `be2`. Regenerate rather than quote these after any change:
`war2_survey <exe> <out>` then `recompile_check <exe> <out>/manifest.tsv <out>/src recover
<WATCOM> --out <tsv> --divergences <tsv>`. Before ANY corpus round, run the ~3-minute
`scripts/war2-smoke.sh` gate — 15 pinned mechanism sentinels (expected verdicts in
`scripts/war2-smoke.expected.tsv`, baseline 734/8e3ad7b) that fail on drift in either
direction; it exists because two full corpus rounds were burned on state corruption a
probe would have caught in minutes (the sb99 retrospective).*

## The measurement

**539 of 3023 emitted functions are byte-exact** from a single default configuration, and
**557** if the prototype-pass arm is also selected per function (verified by recompiling the
materialized tree, not by joining verdict files).

The default configuration is the one that matters: it is a single decompile pass, so it is
what `war2_survey <exe> <out>` produces with no environment set. The arm requires a second
decompile of every function and a second compile round, and buys 18 functions.

| step (default configuration) | EXACT |
| --- | --- |
| baseline, re-measured | 421 |
| callee stack-cleanup recovery (`recompile::convention`) | 432 |
| recovered callee prototype treated as fact, not candidate | 433 |
| **call arguments the chain rule was discarding** | **514** |
| stack-pointer offset recorded at the CALL op | 536 |
| **range offset canonicalized to its space** | **539** |

| configuration | EXACT |
| --- | --- |
| default, single pass | **585** |
| prototype pass alone (`MOSURA_PROTO_PASS=1`) | 560 |
| both, best-of per function (`recompile_select`) | **593** |

(The default's 539 -> 564 is the function-extent fix -- a measurement correction, recorded in
its own commit. The pass's 501 -> 560 and the union's 557 -> 591 are this thread: the anchored
placeholder (`19d8060`), the locked-with-varargs prototype port (`b6c7d31`), and recovered
per-call extrapop (`d854c22`). 564 -> 566 and union 593 are the stack-convention prototypes and
switch modify lists (`ad4d860`). 566 -> **571** is restoring Ghidra's `ActionDeadCode` to its
real mainloop slot (coreaction.cc:5503) -- a schedule mis-rotation had left the first rule-pool
pass with no dead-code sweep at all, which silently changed RULE OUTCOMES corpus-wide (the
worked chain is in `compilable-c-remediation.md`, CORRECTION 2). 5 wins, 0 losses, 2 fewer
COMPILE_FAILs, and per-function rule-pool churn fell from 2.6x Ghidra to 1.12x.

571 -> **585** is the follow-up audit of the five post-fullloop dead-code sweeps, all of which
were non-Ghidra (Ghidra's universalAction has NO ActionDeadCode after the fullloop). Four were
inert; the one load-bearing sweep existed only because `condnegate_pool` lacked
`RuleEarlyRemoval` -- in Ghidra, RuleCondNegate/RuleBoolNegate live in oppool1 next to
RuleEarlyRemoval, so the pool cleans its own fold-orphans. Restoring that discipline and
deleting all five sweeps: **14 wins, 0 losses**, 7 further MISMATCH -> SAME_SHAPE. The visible
improvement class is structural: guards survive to the structurer instead of a block emptied by
a late sweep being merged away (e.g. `FUN_00038a0c`, whose guarded call was previously hoisted
above its test with the conditions merged). Note the filed guarded-store-hoist specimens in
`FUN_0006c6f0` are NOT fixed by this -- that bug's mechanism is upstream of the late sweeps and
stays open. 585 -> **592** is the implied/explicit classification ported whole — checkImpliedCover's
LOAD-vs-STORE and call-crossing arms, the implied-extended cover, and the descendants-first
decision order — which fixed the post-store re-read wrong-VALUE defect and retired the
conservative multi-use-LOAD stand-in (7 wins, 0 losses, 4 more SAME_SHAPE). 592 -> **590** is wiring
`ActionVarnodeProps` at Ghidra's :5491 slot (the fixture corpus IMPROVES; the -2 is Ghidra's own
RulePiecePathology heuristic meeting mosura's correct 4-byte return recovery on the `xor al,al`
return idiom — the whole chain verified faithful link by link, callers zero, see coverage.md's
ActionVarnodeProps row). `ActionConstantPtr` (:5665, the last
unported mainloop member) landed at **590 — byte-identical emissions**: its composition was
closed against a data-block-equipped app oracle (the term order and the surviving anchored
form are Ghidra's; the missing `spacebaseConstant` type lock was the root cause of an
85-EXACT do/undo cascade), and the byte-exact emitter models Ghidra's STANDALONE global-scope
context (`Program::global_scope_all_loaded`), where the action is silent exactly as the
standalone oracle is — the full story is coverage.md's ActionConstantPtr row. **590 held with
byte-identical WAR2 emissions** (sb34) through the Phase-4 refinement carve-out + stand-in
retirement, the per-fixture cspec threading (`raw_funcdata_flow_image_arch` — datatest-path
only; WAR2 threads its own `__watcall` ids), and `buildReturnOutput`'s multi-piece PIECE
reassembly (never fires on watcall's single-EAX verdicts; mixfloatint 0.857 → 1.000). 590 →
**585** (sb35) is the E1032 partial-symbol resolution (`compilable-c-remediation.md`, Phase 4
addendum): three faithful ports (baseExplicit's lone-descendant escapes, the deadcode
ram-blanket retirement, the `numInstances` gate) took COMPILE_FAIL 22 → 14 and partial
accessors to zero corpus-wide; the −5 net EXACT is the retired blanket's persist-store ordering,
which had been byte-exact-friendlier than Ghidra's real pipeline (oracle prints the same swapped
order — FUN_000165f4 verified; the ordering story is a named emitter-side follow-up). The union
and prototype-pass rows are as of `ad4d860`; re-measure before quoting.)

The prototype pass alone is still 38 behind the default. Against the default it wins 18
functions and loses 56, and those 56 are the work-list below: eliminating them retires the arm
and with it the doubled decompile and compile.

### The global similarity gauge (sb43 baseline: 0.3841)

The EXACT count is the target but it is a step function: a change that takes a
500-instruction function from 60% aligned to 95% aligned moves it not at all.
`recompile_check` therefore also reports a **global similarity** — the micro-average over
instructions,

    Σ equal / Σ max(orig_n, cand_n)   over every measured function

the fraction of the corpus's instructions that recompile identically, instruction-weighted.
The weighting is the point: on sb42/43 the 586 byte-exact functions are 20% of the
population but only **5% of the code bytes**, so the unweighted per-function mean (also
printed) is flattered by small trivial functions and near-blind to the big ones, which is
where the remaining work lives.

Conventions, all load-bearing:

* A function that produced no candidate — EMIT_FAIL (now a real TSV row rather than a lost
  eprintln), COMPILE_FAIL, OBJ_ERROR — scores **zero at its full original-instruction
  weight**, never excluded: excluding it would make "it finally compiles, but mismatches"
  LOWER the score. The survey records a real extent even on DECOMPILE_FAIL manifest rows
  for exactly this reason — a recorded 0 reads as "excluded" downstream.
* The denominator is the EXACT denominator (library excluded, everything else in), so the
  two headline numbers stay comparable.
* The TSV's `equal`/`orig_n`/`cand_n` columns make the number recomputable from the file
  alone: `awk -F'\t' 'NR>1{e+=$8; d+=($9>$10?$9:$10)} END{print e/d}'`.

Baseline (sb43, emit `a6b4b04`, sources byte-identical to sb42): **0.3841** insn-weighted
(53614/139581 over 2893 functions), 0.5430 unweighted; verdicts unchanged (586 EXACT / 84
SAME_SHAPE / 1 SAME_CODE / 2210 MISMATCH / 11 COMPILE_FAIL / 1 EMIT_FAIL). The −0.0011 vs
sb42's re-score is purely the DECOMPILE_FAIL function's 379 instructions entering the
denominator at weight 0.

**586 → 591 (sb43 sources, `-5r`).** The build profile's CPU digit was wrong: WAR2 was
tuned for Pentium, and 10.0a's `-5r` suppresses the in-place scaled-LEA selection
(`SHL EAX,2` where `-4r` emits `LEA EAX,[EAX*4]` — a tuning choice between equally
386-legal encodings, found via the Open Watcom source's CPU_586 gate on V_LEA_GOOD's
OP_LSHIFT arm). +6/−1 EXACT, SHL>LEA divergence rows 157 → 12, global similarity
0.3841 → **0.3858** (`/data/be2/sb43-5r.tsv`). 591 → **592**: WAR2's own build was not
uniform — one contiguous module (9 functions, 0x69fb0..0x6e6e0) carries the in-place
scaled-LEA form `-5r` can never emit, so the CPU digit is now per-function EVIDENCE
(`buildconfig::Evidence::in_place_scaled_lea`: presence proves pre-Pentium tuning,
downgrades that function to `-4r`; absence keeps the profile's `-5r`). The full
toolchain story — including why
the remaining LEA-fold/allocation/callee-save divergences are a bounded compiler
residual, not workable defects — is `war2-toolchain-synthesis.md`.

**592 → 605 (sb44): the hardware shift-mask elision — F1's first resolved sub-shape.**
Ghidra faithfully prints the SLEIGH lifter's shift-count mask (`1 << (x & 0x1f)` — the
oracle prints it too, verified on FUN_00038d88), but the x86 shift instruction performs
that mask itself, so Watcom materializes the printed one as a real `AND CL,0x1f` the
originals never have. New `EmitChoices` axis `shift-mask=hardware` (decompile/emit.rs —
passes all three axis-honesty rules; the elision applies only to an implied single-use
`INT_AND(x, 0x1f)` on a ≤4-byte shift), set by war2_survey on every arm like the
loop-overflow form. +13 EXACT, 0 regressions; extra AND-0x1f rows 94 → 25; global
similarity 0.3858 → **0.3868**.

**605 → 612 (sb45): the `local-width` axis, deployed as arms + per-function selection.**
The widening-idiom fix (`byte-exact-families.md`, the worked design): narrow register
locals whose every def is value-safe declare at register width under
`local-width=storage`. A searched axis, so deployed as the union: the survey emits
`--arms 'default;local-width=storage'`, `recompile_select` picks per function on the
byte verdict, and the MATERIALIZED union tree recompiles to **612 EXACT** (default arm
605, storage arm alone 598 — it wins 7 the default misses and breaks 14 the default
keeps, which is exactly why the union, not a default flip, is the deployment). Global
similarity 0.3868 → **0.3870** on the union. Canonical trees: `/data/be2/sb45{,-lw,
-select,-union}.tsv`, union sources at `/data/be2/sb45/union`.

**612 → 616 (sb46): the integer-promotion cast machinery, ported whole.** Tier 2's first
specimen (`FUN_00048478`: original `SHL ECX,5; MOVSX ECX,CX` — shift narrow, THEN extend)
exposed a PORT DEFECT, not an axis: Ghidra's `CastStrategyC` promotion predicates
(`intPromotionType` / `localExtensionType` / `checkIntPromotionForCompare` /
`checkIntPromotionForExtension`, cast.cc:107-247) force the truncating cast that makes
ANSI C compute the IR's narrow arithmetic — `(int4)(int2)(param_1 << 5)` — and the port's
`input_cast` lacked the whole mechanism, silently dropping the `(int2)` (a VALUE
divergence under promotion, not just bytes). Ported into `cast.rs` with the per-op
consumers (comparisons, SEXT, div/rem, shifts; ZEXT stays with its documented
transparent-render adaptation). Oracle-verified rendering; +4 EXACT, 0 regressions,
global similarity 0.3870 → **0.3889** on the union.

**616 → 619 (sb47): local-width tier 2 — materialized narrow loads.** Under the storage
arm, a narrow LOAD consumed by a comparison against a nonzero positive-at-width constant
materializes as an explicit unsigned widened temp (`uint4 t = (uint2)*p;` — the probed
`XOR EBX,EBX; MOV BX,[EDX]` shape), printed at the load op's own position. Two gates,
both measured on `FUN_0001562c`: positive constants only (extension sign becomes
value-irrelevant) and nonzero only (the originals compare zero against memory directly —
`CMP word ptr [..],0`). +3 EXACT on the union, zero regressions.

**619 → 622 (sb52): caller-side register contracts.** The definition-side `parm [..]`
pragma told Watcom a callee's true argument registers only in the callee's own TU; every
CALLER compiled against a bare extern and bound its arguments POSITIONALLY to the default
order — a silent semantic mis-compile for every cross-TU call to the 155 callees with
nonstandard recovered storage (specimen FUN_0003925c: its table index went to EAX where
the original and the callee both use EDX). The survey now collects each function's own
parm recovery during the emit loop and prepends the pragma to every TU that externs the
callee, in a post-pass, under two measured gates: ARITY (the callee's rendered params are
its USED slots only — a short pragma overflows the caller's extra args to the stack) and
DIRECTIONAL WIDTH (per slot the pragma register must be at least the argument's width —
a byte argument binds `parm [edx]`'s low part, EXACT; a 4-byte argument into `parm [bx]`
goes to the stack). Three wrong derivations were measured and discarded on the way:
`CallSpec::reads` order (8 EXACT broken — reads is evidence, not slot order), ungated
arity (FUN_000345f4), ungated width (FUN_0002c8xx). 124 TUs patched; +3 EXACT, 6
MISMATCH → SAME_SHAPE, zero regressions; global similarity 0.3890 → **0.3894**.

**622 → 630 (sb53): possible-output indirect creations — the dropped-arguments port
defect.** The missing-XOR trail's second find: an argument that is a PREVIOUS call's
still-unrecovered return was judged unrealistic by the ancestor walk and dropped (with
the arguments behind it force-deactivated by the hole rule, and the callee-save
PUSH/POPs lost as knock-on — specimen FUN_00011954, oracle recovers both args). Two
faithful pieces were missing: Ghidra flags an indirect creation's constant as
indirect-zero ONLY when the range is not a possible output of the call
(funcdata_op.cc:726 + heritage.cc:1468-1484 — mosura's composition gate: output not yet
committed + `characterize_as_output` == contains-justified), and
`AncestorRealistic::enterNode`'s INDIRECT arm accepts non-zero creations as POSSIBLE
OUTPUTS (funcdata_varnode.cc:2045-2050) where the port rejected every creation flat.
+8 EXACT, 4 more SAME_SHAPE, global similarity 0.3894 → **0.3962** (+1,054 matched
instructions — recovered arguments across hundreds of MISMATCH functions), one
MISMATCH → COMPILE_FAIL typing regression filed (FUN_00066100, the E1010
CONCAT-into-pointer family).

**630 → 639 (sb55): the `compare-form` axis.** The decompiler canonicalizes comparison
constants (`x >= 4` and `3 < x` are one IR object; the oracle prints the canonical form,
verified on FUN_000207b8) but the original programmer wrote whichever spelling they
wrote, and the bytes differ (`CMP EAX,4`/complementary jump vs `CMP EAX,3`). New axis
`compare-form={recovered,complement}` renders the other spelling of the same predicate
under three value-identity gates (plain integer constant, no required cast on its slot,
±1 representable at the constant's width and signedness). Deployed as a third arm in the
union: +9 EXACT, every one a SAME_SHAPE promotion, zero other movement. The canonical
arms invocation is now `default;local-width=storage;compare-form=complement`.

**639 → 645 (sb56): tier-2 extract materialization.** A multi-use `x & 0xff` byte
extract of a register value term-duplicates at each use in the reference rendering, and
Watcom selects `MOV EDX,EAX; AND EDX,0xff`; the original widens the byte ONCE into its
own register (`XOR EDX,EDX; MOV DL,AL` — specimen FUN_0003925c, whose sibling run
01328-01335 was the residue of the caller-contracts fix). Under the storage arm such
extracts materialize as explicit unsigned temps whose def renders `(uint1)x` — the cast
IS the mask, value-identically, and it is the C shape measured to reproduce the
original's selection. +6 EXACT, every one a SAME_SHAPE promotion, zero other movement.

**645 → 659 (sb57): the `return-split` axis — merged-boolean returns.** The rules
collapse per-path constant returns into one boolean (`return x != 0;`, oracle-verified
faithful), which Watcom materializes with `TEST/SETNZ/AND`; the original returned
constants inside the branch, letting the compiler reuse known register values (the
measured zero path returns the call's own EAX=0). A ternary spelling was probed and does
NOT reproduce the bytes — the return must sit structurally inside the branch, so the
axis is a structured-emission transform: the tail pair [plain `if` testing B] +
[sole-statement `return (zext of) B'`] renders as `return 1;` injected at the body's end
plus `return 0;` on the fall-through, when B and B' provably hold the same value (same
varnode, or same bool opcode over pairwise-identical operands — the rules duplicate the
predicate rather than CSE it, measured in the IR). Bundled into the third arm (no extra
compile round). +14 EXACT, all MISMATCH promotions, zero other movement.

**659 → 661 (sb59): the short-circuit fold opcode corrected to Ghidra's — a WRONG-CODE
fix.** `newBlockCondition` takes `INT_OR` iff `b1->getFalseOut() == b2`, and its only
caller negates `bl` first so that always holds: Ghidra's short-circuit fold never
produces an AND (ANDs come from `BlockCondition::negateCondition` flipping one later,
while distributing the NOT into both children). mosura read the test as pre-fix-up, so
`i==1` folds baked a negation into the KIND *and* recorded it again in `cond_flip` — the
double count printed inverted connectives wherever the enclosing `if` negates the
composite (specimen `FUN_00038bfc`: the original's `(X||Y) && P` emitted as
`(X||Y) || P`, oracle-verified). Installing `CondOr` always: **64 of 3022 TUs' default C
changed** — the wrong-code population — with +2 EXACT and similarity 0.3968 → 0.3973,
zero regressions. Correctness and the diagnostic moved together, which is what a
faithful port is supposed to do.

**Target-independence audit (2026-08-18, after the five axes landed).** The axes are
deliberate departures from Ghidra's rendering, so the question "are these Watcom-specific,
and do they pollute other targets?" was audited rather than assumed. Layering held:
`decompile/` carries no compiler conditional (the only "Watcom" strings in `emit.rs` are the
probe citations its own axis contract requires), the `-5r` profile lives in
`recompile::buildconfig`, the caller pragmas and arm selection in `war2_survey`, and every
axis DEFAULTS to Ghidra's rendering — a different target that selects no arm gets the
faithful port untouched. Three ISA/ABI constants had leaked in anyway and were replaced:
`PROMOTE_SIZE = 4` in the integer-promotion port (the serious one — **default path, every
target**, where Ghidra parameterizes as `TypeFactory::getSizeOfInt`; the vendored
`x86-16.cspec` declares `integer_size 2`), the `shift-mask` axis's `0x1f`/≤4-byte gate (x86-32
shift semantics; now established by PROVENANCE — the mask is the hardware's iff the lifter
emitted it within the shift instruction, which generalizes correctly to every ISA), and
`local-width`'s `Uint(4)` widths (now the target's int size; "1 or 2 bytes" became "narrower
than int"). `Funcdata::size_of_int` ports Ghidra's own inference (`TypeFactory::setupSizes`,
type.cc:3136 — the stack pointer's width capped at 4). Measured: the default arm's emitted C
is **byte-identical corpus-wide** and verdicts are unchanged (661 EXACT, 0.3973) — the fix is
parameterization, not behaviour.

**Register naming was the fourth leak (sb61).** `printc` named `extraout_*` from a
seven-entry x86-64 offset table that ignored the varnode's SIZE, so WAR2's 32-bit `EAX`
printed as `RAX` at 14 sites where the oracle prints `extraout_ECX`/`extraout_CL`. Ghidra
names it through the TRANSLATOR (`glb->translate->getRegisterName(space, offset, size)`,
database.cc:2495) with a literal `var` fallback; mosura now carries the processor's own
SLEIGH register table (`Spec::register_table` → `Funcdata::reg_names`, threaded like
`userops`), so the names are right on any architecture. 17 TUs renamed; verdicts hold at
661 EXACT with one MISMATCH → SAME_SHAPE (renaming shifts Watcom's symbol-order allocation
tie-break — the declaration-order finding in this document, seen from the other side).
The sweep's one remaining gap, endianness, is filed in TODO.md rather than half-fixed.

## From searched axes to RECOVERED choices (the field constraint)

The arms are development-time scaffolding. In the field mosura has **no compiler**, so there
is no verifier and no way to arbitrate arms: it must emit ONE rendering. An axis is therefore
a placeholder for a recovery problem — the choice has to be decided from evidence in the
ORIGINAL BYTES, the way `buildconfig::Evidence` already decides the per-function CPU digit
(`in_place_scaled_lea`), the callee stack cleanup (from the callee's `RET`), and the caller
`parm` pragmas (from the callee's body). None of those touch a compiler.

Architecture, per JD: the AXIS stays target-agnostic in `decompile::emit` (the `emit.rs` rules
already forbid a compiler conditional there); the EVIDENCE RULE that picks its value is
target-specific and belongs with the Watcom profile in `recompile::buildconfig`, exactly as
`Profile::flags_for(&Evidence)` does for flags.

**First calibration — `local-width`, measured on sb63 (both arms' verdicts + per-function
similarity), two candidate rules:**

| rule | coverage | storage better / worse | mean Δ sim |
| --- | --- | --- | --- |
| per-function: "the original contains `XOR r32,r32` + narrow `MOV` anywhere" | 1163 fns | 177 / 245 | **−0.0042** |
| address-anchored: the ORIGINAL instruction at a narrow value's DEF widens it | 28 fns | 9 / 7 | **+0.0134** |

Read: the per-function scan is **anti-correlated** — the widening idiom appears in 40% of
functions for unrelated reasons, so its presence says nothing about the specific local the
axis re-declares. The address-anchored rule points the right way (+0.0134 where it fires, and
−0.0043 where narrow defs exist but are NOT widened, which is the correct negative), but it
covers only 28 functions while the arm changes 945 TUs.

**RESULT (machinery built, rule calibrated):** the printer now records its own candidate set
(`printc::EmitReport::local_width_candidates` — every local the axis would re-declare, with
the address of its defining instruction, recorded on every print regardless of the axis
value), and the Watcom profile scores exactly that set
(`buildconfig::local_width_from_evidence` — target-specific by construction, hence beside the
profile and not in `decompile::emit`). Measured over all 2,892 user functions:

| emission | EXACT | mean per-function sim |
| --- | --- | --- |
| default arm | 621 | 0.5554 |
| **RECOVERED (rule decides per function, no compiler)** | **621** | **0.5550** |
| searched union of the two arms | 637 | 0.5630 | ← ceiling, needs a compiler |

Where the rule chose `storage` (271 functions): **50 better, 41 worse, 180 unchanged.** So
the def-site signature is a real but *weak* signal, and it recovers essentially none of the
16-function benefit the search finds. **`local-width` is not viable as a recovered axis on
def-site evidence alone.** Next lever if it is worth pursuing: score the USE sites too (does
the original re-narrow at each use, or keep the value wide?), since Watcom's choice depends on
the whole live range, not one instruction. Note the ceiling is only 16 functions (2.5%), so
the investment should be weighed against the other axes — whose evidence is far more
determinate: `compare-form` reads the original's own `CMP` constant, `return-split` and
`cond-form` read whether the original materialized a boolean (`SETcc`) or branched. Those are
direct readouts, not correlations, and they are the ones to convert next.

### `compare-form` RECOVERED — the first field-viable win (sb64)

The second axis converted, and this one's evidence is a direct readout rather than a
correlation: at each candidate comparison the ORIGINAL's own `CMP`/`TEST` immediate says which
spelling the source used. Measured over WAR2's candidate sites:

- **452 sites** want the complemented rendering, **749** want it as rendered, 204 match neither
  (the value was transformed), 96 have no compare in the window.
- **101 functions want BOTH at different sites** — so the recovered form is *finer than the
  axis*, which is per function. Recovery can beat search here, not merely match it.

Implemented per site: `printc::EmitReport::compare_sites` records every candidate with the two
spellings; `buildconfig::complement_compares_from_evidence` (target-specific — x86 compare
mnemonics, and the flag-setting compare sits at or just before the IR op's address, since that
address is usually the `Jcc`) returns the sites to complement; `printc::print_c_recovered`
takes the set. `war2_survey --recovered <dir>` emits that single tree.

| emission | compiler needed | EXACT | WGSS |
| --- | --- | --- | --- |
| default, one emission | no | 621 | 0.3963 |
| **RECOVERED, one emission** | **no** | **627** | **0.3973** |
| searched union of three arms | yes | 661 | 0.3972 |

**The field path already matches the searched union's global similarity** — 0.3973 against
0.3972 — from ONE emission with no compiler, while trailing it by 34 on EXACT because the
other three axes are not converted yet. 397 TUs differ from the default; the gain is +6 EXACT
and +0.0010 WGSS over it.

### `return-split` and `cond-form` RECOVERED (sb65) — the field path overtakes the search

Both remaining boolean-shape axes converted in one pass, both determinate readouts: the
candidate is recorded by the printer (`EmitReport::return_split_candidates` — the guarding
branch's address; `EmitReport::cond_nest_candidates` — first-clause key plus the clause span),
and the Watcom rules read whether the ORIGINAL materialized a boolean or stayed branch-only
(`buildconfig::split_returns_from_evidence` — any `SETcc` from the branch to function end
means merged; `nested_conds_from_evidence` — any `SETcc` inside the clause span means the
collapsed comma form). Branch-only is what the split/nested renderings compile to, so the
readout IS the decision. All decisions per site; a `RecoveredChoices` carrier threads them
through `print_c_recovered`, and candidacy is recorded on every print (default rendering
byte-invariant, verified corpus-wide).

| emission | compiler | EXACT | WGSS |
| --- | --- | --- | --- |
| default, one emission | no | 621 | 0.3963 |
| recovered: compare-form only (sb64) | no | 627 | 0.3973 |
| **recovered: + return-split + cond-form (sb65)** | **no** | **643** | **0.3986** |
| searched union of three arms | yes | 661 | 0.3972 |

**The no-compiler emission now BEATS the searched union on weighted global similarity**
(0.3986 vs 0.3972) while trailing by 18 EXACT. Both directions are the same explanation:
per-site recovery applies the right choice inside functions that never reach EXACT — where an
arm's per-function selection helps only if the whole function lands — and the EXACT residue is
local-width's ~16 (the one axis whose evidence measured too weak to recover) plus a couple of
per-function wins. 486 TUs differ from the default.

**sb66 — the recovered tree joins the dev-time selection: 661 → 663 EXACT.** Per-site
recovery wins two mixed-want functions (`01859`, `02294`) that NO per-function arm can reach,
so the field emission is also a strict addition to the development union. The board's two
headline configurations: field (one emission, no compiler) **643 / 0.3986**; dev union (four
inputs, compiler-verified) **663 / 0.3972**.

### `return-width` RECOVERED (sb67) — the fourth conversion, found by the census loop

The 9-function `extra AND EAX,0xff` near-frontier cluster decoded to the `return-width`
axis's OTHER side: our default declares the recovered storage width (4), which forces Watcom
to materialize a widening the original never performs — the original returns with the byte in
`AL` and the high bytes untouched, i.e. a narrow contract. The ORACLE settles the reference:
Ghidra prints `xunknown1` (the value's width), so our wide default was the deviation for this
population — while the 86-function bool-return family measured the opposite way earlier
(originals that DO widen), which is exactly why this is a per-function recovered choice and
not a constant.

Evidence rule (`buildconfig::narrow_return_from_evidence`): the ORIGINAL's last write to the
A-register family before each RET — narrow (`MOV AL`, `SETcc AL`, `MOV AX`) means the source's
return type was narrow; full (`AND EAX,0xff`, `MOVZX`, `XOR EAX,EAX`, a `CALL`) means the
widened declaration is right. Narrow only when every return site agrees. Candidates from
`EmitReport::return_width_candidates` (RETURN sites where the value is narrower than the
recovered storage).

| board | EXACT | WGSS |
| --- | --- | --- |
| field (one emission, no compiler) | 643 → **647** | 0.3986 → **0.3991** |
| dev union (four inputs) | 663 → **668** | 0.3972 → 0.3973 |

Five MISMATCH → EXACT, zero regressions, suite green.

### `local-width` per-site recovery + the arm verdicts (sb69–sb71)

Arm 2 RETIRED (compare-form/return-split/cond-form as a blanket arm): its whole union
contribution was one function, and after the per-site improvements below the three-input
union ties the four-input high anyway — the retirement is free. 792 marginal TU compiles
dropped per cold remeasure.

`local-width` converted to PER-SITE recovery next, calibrated in three measured rounds on
the arm's actual winners (the discriminator hunt runs on winners, not on theory):

1. naive def-site classifier: field 636 / 0.4009 — 16 EXACT regressions. Two false-positive
   classes, both then named:
2. **the consumed zero** — `XOR EAX,EAX ; MOV AL,a ; MOV AL,b`: the zero belongs to the
   FIRST load; the second value's widening is a mask AFTER it. Fix: the back-scan stops when
   an intervening instruction writes the container.
3. **the ABI artifact** — a `CALL` defines full EAX because the convention says so, not
   because the source variable was int; widening byte locals holding call results broke
   EXACT functions. Fix: abstain on call-defined candidates (their readout is at the USES,
   which the def-site rule does not model).

Result: field **651 EXACT / 0.4032 WGSS** (from 647/0.3991), one residual regression.
Candidate precision also fixed: only DECLARED locals report (inline values' widening is
inert and diluted the earlier per-function calibration), and tier-2 candidacy records on
every print (the report print was silently empty before — the axis-gated loop never ran).

**Arm 1 STAYS**: two-input union 656 vs three-input 668 — the blanket arm still wins 12
functions whose widening the def-site evidence cannot justify. That population is the
use-site-evidence question, documented as this axis's remaining gap.

| board | EXACT | WGSS |
| --- | --- | --- |
| field (one emission, no compiler) | **651** | **0.4032** |
| dev union (default + recovered + local-width) | **668** | 0.3973 |

### The "12 lw-only wins" decomposed (sb72–sb73) — no use-site population exists

Worked as JD asked, and the honest outcome is that the use-site-evidence hypothesis
DISSOLVED under instrumentation. The 12 functions the blanket arm still won decomposed into:

- **9 were a plain bug**: the caller-side `parm` pragma post-pass patched arm directories but
  not the recovered tree, so recovered TUs externed nonstandard callees with no contract.
  Fixed (one line — the recovered dir joins the pass): field 651 → 660.
- **~3 were a `return-width` evidence mis-read**: `XOR EAX,EAX ; MOV AL,[m] ; RET` is the
  widening idiom feeding the return — the last write is narrow but the contract is WIDE. The
  rule now runs the same consumed-zero back-scan before calling a return narrow: 660 → 663.
- **4 are codegen butterflies, not evidence**: the difference is EPILOGUE TAIL-MERGING (the
  original duplicates `POP;POP;RET` per return path; our rendering shares one via `JMP`), and
  the widened local merely perturbs Watcom out of merging. No principled rule maps
  "duplicated epilogues" to "widen this local" — these are the arm's earned keep, same class
  as the parked allocation policy.

| board | EXACT | WGSS |
| --- | --- | --- |
| field (one emission, no compiler) | 651 → **663** | 0.4032 → **0.4039** |
| two-input union (default + recovered) | **664** | |
| three-input union (+ local-width) | **668** | |

The union's diagnostic reading now: recovered is within 1 of the two-input union (a single
evidence mis-read left) and 5 of the full board, 4 of which are butterflies. `local-width`
stays for those 4.

### THE UNION RETIRED (sb74) — the recovered tree dominates

JD's objective for this arc: remove the union altogether. Reached by closing its content:

- **The decision-interaction round**: recovered per-site choices interact — a tier-2
  materialization CREATES the statement-carrying clause `cond-form` wants to nest, but
  candidacy had been assessed on the reference print where the clause did not exist
  (`FUN_00025d9c`: the materialized comma re-triggered the SETcc the nested form removes).
  The driver now runs the evidence rules a second time over the first round's own rendering
  and merges (`print_c_recovered_report`); one extra round reaches the fixed point.
- **The no-immediate compare readout**: `TEST r,r` + sign-family branch at a compare site
  means the source spelled the ZERO constant (`FUN_00012ca0`: original `TEST EBX,EBX; JL` =
  `0 <= x`; ours compiled `CMP EBX,-1; JLE` = `-1 < x`). The complement rule now reads it.

Result: **recovered 665 EXACT / 0.4044 WGSS, and ZERO functions where the reference beats
it** — dominance, so default+recovered selection is mathematically inert. The canonical
measurement is now the recovered tree alone (the exact emission a compilerless field run
ships). The `local-width` arm's four tail-merge butterflies remain measurable as an optional
diagnostic margin (+4 when selected in), parked with the allocation policy — chasing them
with a fake evidence rule would be the butterfly-chasing this project refuses.

The arc's full trajectory, one emission with no compiler:
621 (reference) → 627 → 643 → 647 → 651 → 663 → **665 EXACT**, WGSS 0.3963 → **0.4044**.

### The 12 COMPILE_FAILs decomposed (sb82)

Each CF scores zero at full weight in the WGSS denominator, so the population was
characterized function by function:

- **3× EFLAGS/CPU-detection code** (`00387`, `02077`, `02871`): PUSHFD/POPFD flag games and
  `cpuid` — the POPCOUNT prelude tripwire fails them loudly, correctly (the alternative was
  the old silent `(0)`). `00387` carries 8 hand-asm signature instructions; these originals
  are almost certainly hand-written assembly, not compiled C.
- **3× 64-bit values** (`02813`, `02911`, `02950`): `uint8` locals on a compiler with NO
  64-bit type — probed: wcc386 10.0a rejects `__int64` outright. `02950`'s original is a
  raw `MUL [EBP+0xc]` with a `CALL CS:[..]` dispatcher — stack-parameter passing and a
  segment override, again hand-assembly signatures. A 64-bit-consuming original cannot have
  been written in this compiler's C.
- **2× cast-to-nonscalar** (`02714`, `02716`): E1037; `02714` contains `REP MOVSD`
  (possibly Watcom's inlined memcpy — not conclusive either way).
- **2× jumptable index unrecovered** (`03017`, `03018`): `MOSURA_SWITCH_INDEX_UNRECOVERED`
  — genuine recovery work, the known gap.
- **1× `spacebase` symbol leak** (`02474`): the stack-model name printed into C — a real
  rendering bug, findable.
- **1× E1010 partial write** (`02583`): the filed merge-question specimen.

Consequence: roughly half the CF population is likely **hand-written assembly** — those are
un-recompilable from C by construction and belong OUT of the C-recompilation denominator the
way library functions already are (a not-C classification pass over hand-asm signatures:
segment overrides, PUSHFD/POPFD, stack-parm MUL, string ops in nonstandard frames). The
remaining real work: the two switch-index recoveries, the spacebase leak, the E1010 merge.

### The not-C classification (sb84) — the denominator now measures the real target

Per JD's challenge, the class is precisely scoped: it flags functions containing
instructions PLAIN C cannot produce under this toolchain (software interrupts, port I/O,
`PUSHFD`, `CPUID`, the CALL-CS dispatcher) — deliberately NOT a claim of "entirely asm",
since Watcom's `#pragma aux ... = <bytes>` embeds machine code into compiled C and the
detector cannot tell an .asm module from aux-pragma-carrying C. Either way the function is
un-recompilable from the plain C the emitter produces, which is what the exclusion means;
if aux-pragma emission ever lands, the embedded subset comes back in scope (revival note in
`buildconfig::looks_hand_written`).

Calibrated before adoption: zero EXACT/SAME_SHAPE functions trip it (the first draft's bare
`CS:[` signature caught two compiled switches — Watcom's OWN switch tables carry the CS
override — and was narrowed to CALL-only, which appears in exactly two functions
corpus-wide, neither verified-compiled). Trigger census: 32 software interrupts
(`INT 0x21`/`0x31`/`0x10`), 20 port I/O, 7 `PUSHFD`; 5 contiguous runs of 3+ (module-granular),
singletons likely aux-pragma wrappers.

| | before | after |
| --- | --- | --- |
| denominator | 2893 fns / 139,578 insns | **2830 fns / 135,438 insns** |
| EXACT | 683 | **683** (24.1%) |
| WGSS | 0.4085 | **0.4165** |
| COMPILE_FAIL | 12 | **7** |

The remaining 7 CFs are all genuine C-side work: the `spacebase` leak, E1010, two
cast-to-nonscalar, the two switch-index recoveries, and one more to characterize.

**Classification refinements (sb87–sb88):** the `spacebase` CF turned out to be a
hand-asm-signature function (stack-switching support) already leaving via the `asm` class —
but the internal type CAN reach a declaration, so the prelude now typedefs it as an
incomplete struct (declarable pointers, legal casts, loud and greppable, the xunknown-width
pattern). And the signature list gained the mnemonic variants the first census missed
(`PUSHF` 16-bit form, `INT3`), calibrated again at zero EXACT/SAME_SHAPE trips: 71 asm /
2822 C functions. Board: **687 EXACT (24.3%), WGSS 0.4186, 6 COMPILE_FAILs** — the CF set is
now exactly the honest core: E1010 (`02583`), the two cast-to-nonscalar (`02714`/`02716`),
the two switch-index recoveries (`03017`/`03018`), and `02911`.

**The int8-divide CFs fixed by a value-identical narrow rendering (sb89).** Ghidra models
the 32-bit `IDIV`'s 64-bit dividend as 8-byte arithmetic
(`SUBPIECE(INT_SDIV(sext K, sext x), 0)`), and 8-byte integers are undeclarable on this
target — the loud xunknown8 tripwire failed both functions. The 4-byte rendering `K / x`
compiles to the very IDIV the original executes, so it is value-identical to the ORIGINAL
everywhere including the INT_MIN/-1 trap the 64-bit model would avoid. Gated on: low-half
extraction at int width, divide-family def wider than int, each operand a
matching-signedness extension of an int-width value or a constant representable at int
width. COMPILE_FAIL 6 → **4**, WGSS 0.4186 → **0.4194** (the two functions rejoin the
scored population at their real similarity). The remaining four: E1010 (`02583`), the two
switch-index recoveries (`03017`/`03018`), and `02911` — a genuine 64-bit multiply with
both halves consumed, unwritable in plain C but carrying no textual asm signature; it
stays a characterized CF rather than force-classified.

**The switch-index CFs fixed (sb90–sb92) — the COMPILE_FAIL floor is reached.** The two
giant decoders (`FUN_000793e0`, `FUN_0007a5b0`) are multi-entry dispatchers; the unrecovered
switch was a COMPUTED jump (`BRANCHIND(i*0x10 + BASE)` into 16-byte code stanzas, no table
load), which `trace_table_index` now strips exactly as it strips the loaded-table form. Two
follow-on renderings in the same functions: pointer+pointer `+` (an inference artifact) casts
the addend to unsigned at int width on both the `IntAdd` and `Ptradd` paths — value-identical
on the flat target, loud as a cast.

CF ledger: **2** — `02583` (the E1010 partial-write merge question) and `02911` (a 64-bit
multiply original plain C cannot express). Every other zero is gone from the denominator.
WGSS reads 0.4153, DOWN from 0.4194 — deliberately reported without spin: the two decoders
now score `equal/max(orig,cand)` with huge candidates instead of 0/orig_n, and the max()
convention penalizes candidate bloat by design; the number is honest, and the functions are
compiling for the first time.

**The blitters were never C (sb93).** Chasing the two newly-compiling decoders' candidate
bloat led to their originals' first instructions: `PUSH ES` — segment-register saves, stack
parameters, stanza dispatch. Hand-optimized assembly, not compiled C. The segment-op
signatures joined the classifier as EXACT matches — the prefix draft matched `PUSH ESI` and
flagged 47 verified-compiled functions, which the zero-false-positive calibration bar caught
before adoption (the bar's second save). 25 functions reclassified; the denominator is now
**2797 C functions (96 asm / 130 library)**.

| | value |
| --- | --- |
| EXACT | **687** (24.6% of C functions) |
| WGSS | **0.4355** |
| COMPILE_FAIL | **2** (`02583` E1010; `02911` 64-bit original) |

The WGSS jump (0.4153 → 0.4355) is the two giant false-C decoders leaving the denominator —
the same honesty that put them IN as zeros while they were believed compilable C.

**687 → 694 (sb94): argument-order recovery — the C parameter DECLARATION order read per
site.** Found by re-running the census on sb93 (the families doc's standing item 5): 35
functions' entire divergence was a pure PERMUTATION of identical instruction texts, and the
dominant sub-shape was call-argument constant setups rotated (`MOV EAX,0xbe2; MOV EBX,..;
MOV EDX,3` vs ours EBX, EDX, EAX). Mechanism, source-confirmed then probe-confirmed: Watcom
materializes register arguments in REVERSE declared-parameter order (OW 1.0 `bldcall.c`,
`AssgnParms` reverses the parm list before `ParmIns`), so the original's setup sequence is a
direct readout of the parameter order the source declared — invisible in the bytes when it
matches storage order, divergent otherwise, and OUR slot-order rendering is exactly the
storage-order assumption. The recovery: per SITE, `buildconfig::call_setup_sites` reads the
window of last-writes to the argument registers before each original CALL;
`param_orders_from_evidence` reverses it into the declared order; the caller renders the
argument list permuted WITH the matching full-arity `#pragma aux <callee> parm [..]` — the
two are one decision, per TU (`printc::RecoveredChoices::call_arg_orders` +
`EmitReport::call_order_candidates`). Probe P3 on `FUN_0004d0f8`: `parm [edx] [ebx] [eax]`
with arguments `(3, 0x4d08c, 0xbe2)` — EXACT.

Two gates, both MEASURED on their own regressions before landing:

* **Per site, not per callee.** One callee's sites can disagree (`FUN_00058bec`: eight read
  `EAX,EBX,EDX`, two read `EAX,EDX,EBX` — why is unresolved), and the first cut's
  two-thirds per-callee consensus broke two EXACT callers whose own sites read slot order.
  Different TUs may carry different orders for one callee: pragma + permutation are emitted
  together per TU, so each TU's bindings are internally consistent.
* **Constant arguments only.** Permuting register-held variables re-orders their shuffle
  and ripples the allocator through the whole function: three SAME_SHAPE siblings
  (`FUN_00019e38/e98/ef8`) fell to MISMATCH as pure regalloc cascades under an identifier
  permutation. A constant's materialization is one immediate move at the call.

+7 EXACT (all seven predicted by the census: `00012360`, `00021a24`, `0002d318`,
`00040490`, `0004c570`, `0004d0f8`, `00072c37`), zero regressions, WGSS 0.4355 → **0.4361**.
Callees whose own recovered storage is nondefault are excluded (the caller-contract pragma
post-pass owns those TUs' pragmas; 15 callees). The permutation family's residual 28: the
probed load-scheduling class (`FUN_00073328` — no pragma order, argument order, or temp
shape moves Watcom's `[EBP+8]`/`[EBP+0xc]` load pair; pile-B), a ~10-function independent-
STATEMENT-order subfamily (stores/INCs/CALLs displaced across a neighbor — the persist-store
ordering mechanism's generalization, unworked), the pure-allocation pairs (pile-B), and
displaced single-constant sites whose windows carry no order information (one visible
setup) or identifier co-arguments.

**694 → 699 (sb95): VOLATILE recovery — the first recovered source QUALIFIER, decided by a
MODEL of the original compiler's scheduler.** The F5 statement-order residual decomposed
under the probe loop into
something better than statement order: in five specimens the C statement order already
matches the original (oracle-confirmed on `FUN_0005d500` — Ghidra prints the same order),
and the divergence is Watcom's INSTRUCTION SCHEDULER moving the next statement's evaluation
above a global store in our build only. The mechanism is source-grounded in OW 1.0, not
inferred: `Schedule()` (cg/c/inssched.c) is gated on `INS_SCHEDULING`, which the recovered
profile's `-onatx` carries through its `x` — `Set_OX` sets it (cc/c/coptions.c:1236) — so
the scheduler runs on every function we compile at EITHER CPU digit (the earlier probe's
"-4r doesn't change it, so not the scheduler" reasoning was confounded: both digits carried
`-onatx`). `volatile` is a FULL scheduling barrier: `ReDefinedBy` answers TRUE for any
volatile memory operand against every result-writing instruction (cg/c/redefby.c:144), so
nothing crosses it — including register-only constant materializations, exactly as probed.
The scoreboard is the second effect: `scinfo.c`'s `N_VOLATILE` is never reusable/lookupable,
which is why a spurious volatile flips register-reuse stores to immediate forms.
Hand-probes reproduced all five
byte-exactly (`FUN_000125bc` — only `cRam0008032c`, its sibling global must stay plain;
`FUN_00034590`; `FUN_0004c270`; `FUN_0005d500`/`5d57c` — the ISR-flag pattern: a flag
zeroed, a call made, the flag re-tested). The recovered chain:
`printc::EmitReport::volatile_candidates` (per pure-global-store statement, the next
statement's min op pc + its RAM reads + work-free/const-rhs flags) →
`buildconfig::volatile_globals_from_evidence` → `build_tu` renders the qualifier on the
declaration (recovered tree only). The DECISION lives in `recompile::watsched` — a model
of OW 1.0's `inssched.c` (see below), NOT part of the Ghidra port: it models the TARGET
toolchain, beside the profile, placed in `recompile/` by design (it consumes the
original's decoded instructions and answers a recompile-layer question).

**The calibration is the story — measured trajectory −28 → −8 → −5 → +2 → +1-clean:** the
blanket order-readout mass-marked consecutive-store runs whose shared materialization the
original hoisted above them (`FUN_00010d40`'s `MOV AH,0xff` run, 666 EXACT); the
between-instruction gate recovered to 686; read anchors (locating the next statement's
global LOADS in the original — the IR often has no op for a global read, so the op walk is
blind exactly where hoisting is most visible, `FUN_0005f440` both ways) to 689; the
materialization-adjacency veto (a constant store whose register materialization is
separated from it by foreign work is not volatile — `FUN_000121e8`) to 696 with six
regressions; the anchored-read-only cut reached +1 clean. Every gate was an approximation
of one question the calibration could not answer: WOULD the scheduler have moved anything
here?

**The model answers it directly (`recompile::watsched`, per JD's direction to model from
the OW source rather than calibrate).** The original's per-block instruction order is a
fixed point of its own scheduler under the source's constraints, so: re-simulate each
window with no barriers — if the prediction reproduces the original, the order proves
nothing; if it does not, a stored global whose barrier alone restores it was volatile.
Ported: the dependency predicate (`InsOrderDependant`, inssched.c:419 — a later jump
depends on everything, a call cannot rise above a visible store, stack ops never reorder,
data dependence both ways), volatile as depends-on-everything (redefby.c:144), the
`RELAX_ALIAS` model (redefby.c:70 — register-addressed accesses do not alias named
globals under `-oa`), the bottom-up priority walk (`ScheduleIns`, inssched.c:766: min
stall cost, then height, then `InsStallable`, then source order) with the 486/586
operand-stall rows (386funit.c — identical integer rows at both CPU digits). Corrections
the diagnostic loop forced, each measured on real windows: emitted MOVs are `FU_ALUX`,
not no-stall (`Move1[]`'s `G_MOV*` rows — `FU_NO` marks non-emitting reductions); the
scheduler sees IR granularity, so read-modify-writes and store-value materializations
fold into their stores (the encoder splits them AFTER scheduling), and the zero-XOR
idiom's register reads are formal; prologue/epilogue are attached after scheduling and
leave the windows; a call READS its argument registers (`LinkParms` makes the parm union
a call operand). Decision gates, each with its measured counterexample: the CAUSAL gate
(a barrier is depends-on-everything and dampens any motion — it explains the original
only when the predicted motion CROSSES its store; `FUN_00012840`); the SELECTION veto
(a non-zero byte constant stored through a register proves non-volatile — volatile
compiles the immediate form, the zero idiom does not flip; four independent
measurements); the CONFIDENCE gate (priority approximations accumulate — only ≤3
displaced atoms count; `FUN_00019344`'s LEA/ADD chain, whose order even a faithful cost
hand-computation cannot reproduce — plausibly the interim build's own priority, pile-B);
and the BLAST-RADIUS gate (the model validates one window, the declaration reaches every
access — only globals accessed ≤2 times in the function mark; a dozen deep-MISMATCH
functions had lost up to 0.32 alignment to wide marks).

**Result: 694 → 699 EXACT, zero regressions, WGSS 0.4359, 78 TUs marked** — all five
probed specimens convert with exactly their minimal probe sets, validated by a
15-function diagnostic battery (`dumpsched`, the gitignored dump-family) spanning every
measured true positive and every false-positive class from the calibration era. Named
residues: `FUN_00021a48` (true volatile, confidence-gated out — its window displaces four
atoms) and `FUN_00019344` (protected by the same gate).

**Layering note (JD's best-practice flag, recorded rather than glossed):** volatility is
really a PROGRAM fact about a global — in Ghidra's own model it is a symbol/database
property, not a per-TU rendering choice — so its systematic home is the analysis layer's
program model, aggregated corpus-wide (union of per-function positives, vetoes crossing
function boundaries), with the emitter merely projecting the fact onto declarations. The
shipped rule is the minimal-scope version: per-function evidence, per-TU declaration —
correct C, deliberately small blast radius while the evidence rule is young. Promoting the
fact to the program model is the shape to grow toward when the scheduler-model evidence
lands; nothing in the current cut blocks that move. The remaining
F5 statement-displacement members (`INC`/`CALL` displaced across neighbors) were probed to
the end — both CPU digits, five optimization-letter subsets, volatile casts, the
increment-in-condition spelling — nothing moves them: the interim build's instruction-motion
policy, pile-B.

**699 → 700 (sb96): per-call extrapop for EVERY call — the missing-argument door opens.**
The missing-only census (60 functions, the largest single-class population) is dominated by
dropped STACK arguments to caller-cleaned callees (`PUSH <string> ; CALL ; ADD ESP,4` — the
logging/vararg family, ~25-30 functions). The chain, instrumented end to end on specimen
`FUN_000191b8`: per-call extrapop (from the callee's own RET) was populated only inside the
recovered-prototype branch — i.e. only under the off-by-default prototype pass — so the
DEFAULT configuration modelled every watcall call as EXTRAPOP_UNKNOWN; the unknown-case
INDIRECT chain left every stack placeholder unresolvable (`PH abort-UNRESOLVED` at all nine
calls), `spacebase_offset` stayed None, and `guard_calls` never offered a stack range.
HOISTED to run for every direct call (analysis/decompiler.rs — Ghidra carries extrapop on
every analyzed function's prototype and `ActionDefaultParams` copies it onto the call,
coreaction.cc:2327). With it: placeholders resolve at every call, the recorded offsets are
Ghidra-semantics correct (the specimen's argument translates to `+4`, exactly watcall's
stack pentry), the stack trial registers, links to the push's value, and is judged ACTIVE.

Landed effects, zero regressions: `FUN_000420f0` MISMATCH → EXACT (700); COMPILE_FAIL 2 → 1
— the E1010 partial-write specimen `FUN_00066100` (`02583`), half of the "honest core" CF
ledger, now COMPILES; the eternal EMIT_FAIL healed — `FUN_0001aab0`'s decompile panic was a
gutted no-output MULTIEQUAL in `ConditionalExecution`'s block walk (mosura's block lists
keep dead ops where Ghidra's are live-only — the `is_complex` precedent; condexe.rs now
filters, and seven sibling functions the known-extrapop heritage rounds newly panicked are
clean); WGSS **0.4359 → 0.4377**, the largest jump since the argument-recovery era —
correct stack modelling improves alignment broadly across MISMATCH functions.

**The named blocker for the rest of the cluster — measured, not guessed:** with the trial
now ACTIVE, `[fillin:chain]` strips it: four inactive register trials (the watcall model's
register entries, crossed by the caller's own saved registers) build `chainlength > 2` in
`force_inactive_chain`, and the faithful arithmetic (verified against fspec.cc:1111 line by
line) deactivates the later active stack trial. The oracle recovers these arguments only
because the raw-import runs the DEFAULT cspec — stack-only entries, no register trials, no
chain; under the watcall model Ghidra's own arithmetic would drop them too. The fix is the
one Ghidra's architecture already carries (`FuncCallSpecs` IS a `FuncProto` with its own
model): PER-CALL MODEL SELECTION — a caller-cleaned call (`ADD ESP,K` after it, the same
evidence channel as the recovered extrapop) is a cdecl/vararg call and takes a stack-only
input list, no register trials, no chain. Needs: a `__cdecl` prototype beside `__watcall`
in `specs/x86-32-watcom.cspec` (grounded in Watcom's own convention docs), named-prototype
loading, and the CallSpec model override threaded through trial creation.

**700 → 700 EXACT, WGSS 0.4377 → 0.4402 (sb97): PER-CALL MODEL SELECTION — the chain
blocker falls, arguments land corpus-wide.** Implemented exactly as sb96 named it, in
Ghidra's own shape (`FuncCallSpecs` IS-a `FuncProto` owning its model, fspec.hh:1640 —
Ghidra fills it from the database's per-function prototype; mosura recovers it from bytes):

- **Evidence** (`CallSpec::caller_cleans`, analysis/decompiler.rs beside the extrapop
  hoist): the callee's own RET provably pops nothing (`callee_cleanup == Some(0)`) AND the
  call's fallthrough instruction is `ESP = ESP + n` (`recompile::convention::
  caller_stack_cleanup` — rejects POP/memory/flow forms; n > 0, dword-aligned, ≤ 500). The
  fallthrough is RE-DISASSEMBLED FROM BYTES, so the test cannot confuse the original `ADD
  ESP,n` with the extrapop INT_ADD the decompiler itself inserts at the call's pc.
- **Model** (`specs/x86-32-watcom.cspec`): a named `__cdecl` prototype beside the
  `__watcall` default — stack-only input pentry (offset 4, align 4), extrapop 4, EAX
  result — decoded by `analysis::cspec::named_input_paramlist` (the same `decode_param_list`
  over `<prototype name=>` outside `<default_proto>`), threaded as
  `Funcdata::cdecl_input`.
- **Selection** (`Funcdata::input_list_for_call`): consumed at BOTH trial-facing sites —
  heritage `guardCalls`' characterize (register ranges at a caller-cleaned call answer
  `NoContainment`, so `__watcall`'s pentries seed no register trials and no kill-chain) and
  `recover`'s input build + monotone probe. Inert by construction on any target whose cspec
  lacks the named prototype (`cdecl_input = None` ⇒ default model everywhere).

Measured (fresh sb97 emit + full recompile): **320 TUs' rendered sources change — every
one previously MISMATCH; the verdict table is IDENTICAL verdict-for-verdict** (700 EXACT,
73 SAME_SHAPE, 1 SAME_CODE, 1 COMPILE_FAIL); WGSS **0.4377 → 0.4402** (+471 matched
instructions — the recovered pushes now render at ~300 call sites). Specimen
`FUN_000191b8` renders `func_0x0005cf88(0x8c958)` — the dropped-argument chain closed end
to end — sim unchanged at 0.357 because the residue is the EMITTER half: the TU must
declare the callee's contract so Watcom itself emits `push/call/add esp,n` and saves the
registers the callee kills.

**The emitter half, grounded in OW 1.0 source before writing it:** a vararg function takes
`CallClass |= CALLER_POPS | HAS_VARARGS` ON TOP of the default (watcall) aux info
(cfeinfo.c:668) — parameters `DefaultVarParms = {0}` (all on the stack, pdefn386.h),
watcall save set and watcall `name_` objname UNCHANGED — so the plain ellipsis prototype
`extern int f(int, ...);` reproduces the original's whole call sequence, register saves
included, with linkage untouched. (`__cdecl` proper is close but differently named — objname
`_*`, cprag86.c:104 — and its kill set once included EBX: the `HW_CTurnOff( CdeclInfo.save,
HW_EBX )` line is commented out with "AFS Nov-21-94", cprag86.c:155. The observed caller
saves — 191b8 pushes EBX ECX EDX — match the vararg-watcall reading, which is also the
natural source for a logging/printf family.) Declared per TU from the decompiler's own
`caller_cleans` facts (survey `build_tu` `vararg_callees`), zero-argument call sites
excepted (an `(int, ...)` prototype cannot be called with no arguments — E1027).

**700 → 734 EXACT, WGSS 0.4402 → 0.4626 (sb98): the EMITTER half — the callee's
caller-pops contract, WITH its recovered kill set, declared per TU.** The survey's
`build_tu` now emits, for every callee the decompiler recovered as caller-cleaned,
`#pragma aux <name> parm caller [] modify [<regs>];` above the unprototyped
`extern int <name>();` — empty register set = every argument on the stack, `caller` =
caller pops (OW's vararg call class, CALLER_POPS|HAS_VARARGS over the default aux info,
cfeinfo.c:668), and `modify` = THAT CALLEE'S OWN recovered clobber set
(`CallSpec::cdecl_modify`: `callee_writes_cfg` with `calls_clobber=true` — writes minus
saved-and-restored, sub-registers normalized, nested calls counted as the convention's kill
set). Watcom then emits the original's whole shape itself: arguments pushed right-to-left,
`ADD ESP,n` after the call, and the caller's prologue saves of exactly the registers the
callee kills that the caller's own contract must preserve.

Every clause was measured in, not assumed:

- `extern int f(int, ...);` (OW's own vararg trigger) scored +17 EXACT but 42 new
  COMPILE_FAILs — all `E1071` where the first argument is a POINTER
  (`func_0x0005a824(pxRam0008128c, ...)`): a prototype's fixed parameter type-checks what
  the original never type-checked. The PRAGMA form keeps the call unprototyped.
- `parm caller []` alone: +18 EXACT, zero failures — but specimen `FUN_000191b8` stalled at
  sim 0.500, `missing=6`: its prologue/epilogue saves of EBX ECX EDX, which Watcom emits
  only when the callee's declared contract KILLS registers the caller's `modify [eax]` must
  preserve.
- A blanket `modify [eax ebx ecx edx]` (the era's cdecl kill set — CdeclInfo.save cleared
  EAX ECX EDX and, until the change commented "AFS Nov-21-94", EBX; OW 1.0
  cprag86.c:154-157): 729 EXACT including 191b8 — but SIX of the pragma-only winners fell
  back (the 0x31c60 window family), their callees' true contracts being NARROWER than the
  blanket. Two callee populations ⇒ per-callee evidence is the only shape that fits both.
- Per-callee `cdecl_modify`: **734 EXACT (+34)**, both populations reconciled.

The sb97 → sb98 transitions are 34 MISMATCH → EXACT (incl. specimen `FUN_000191b8`,
`FUN_0005cf70`, the 0x318d8/0x31c60 window family, 0x6a7d0–0x6a970, 0x658fc/0x659ec) and
3 MISMATCH → SAME_SHAPE — **zero regressions of any kind against the landed baseline**.
WGSS **0.4402 → 0.4626** (+3126 matched instructions), the largest jump of the campaign:
`missing` as dominant cause fell 830 → ~700 as ~300 caller-cleaned sites gained their
pushes, cleanup adds, and prologue saves.

**Named residue:** `FUN_00031d58` was EXACT under the pragma-only form and is MISMATCH
(regalloc=12) under per-callee modify: its callee CONTAINS a call, so the
`calls_clobber=true` walk inflates that callee's set to the full convention kill set, while
the original's model of it was evidently narrower. The refinement, when the family is next
worked: resolve nested calls with the NESTED callee's own recovered contract instead of the
convention's blanket (a transitive fixed point over the call graph), which is also what the
original compiler knew from its headers.

**734 → 734 (sb99): the GENERAL per-callee contract — explored to its fundamentals,
measured at every step, and PARKED with its design written down.** The near-miss census
after sb98 named argument-position divergences: our recompile hoists an argument setup
across a neighboring call (`FUN_00011b9c`'s `MOV EDX,0x49790` above `CALL 0x1f734`) or
declines a hoist the original made (`FUN_00012360`'s zeroed EBX) — because a bare `extern`
under Watcom's default aux info claims the callee preserves everything
(`HW_CAsgn( DefaultInfo.save, HW_FULL )`, OW 1.0 cmodel.c:381), while the original build
was compiled against richer per-callee declarations. Extending sb98's `modify [..]`
pragmas to EVERY callee was measured through five full corpus rounds:

- blanket (`calls_clobber`) contracts on all callees: **707** (−31/+4) — nested-call
  inflation invents saves;
- TRANSITIVE contracts (`transitive_contract`, a memoized fixed point over the call graph
  in `Program::contract_cache`): **720** — better, and it healed sb98's residue
  `FUN_00031d58`;
- + single-pragma-per-callee MERGE (Watcom treats a second `#pragma aux` for one symbol as
  a REPLACEMENT — split emission silently destroyed the order recovery of every
  modify-annotated callee, the nine-sibling 0x392xx family): **730**;
- + a caller-side "survival veto" read from straight-line byte windows after call sites:
  **722 → 731 → 734-even** across three soundness patches (settled-set, noreturn
  fallthrough, jump-following) and a per-caller restructure.

**The fundamental, per the checkpoint JD called** (the veto iteration was becoming
workarounds-on-workarounds): the ground truth is the ORIGINAL BUILD'S PER-TU DECLARATIONS
— a latent. The callee's body-truth provably differs from it in BOTH directions
(0x58834's callers hold EDX across it though the body clobbers it; 0x52874's callers save
EBX/ECX though the body preserves them) and DIFFERENT callers were built against DIFFERENT
declarations of the same callee (0x5cf88). Reading the callers' testimony from byte
windows is a weak decoder whose soundness holes each demanded a patch. The decompiler's
own dataflow already answers the same questions exactly — "is R live across this call",
"is R saved only around calls to X" — for every caller, with a real CFG.

**The design was then BUILT AND MEASURED in its proper form** — blanket body-truth
narrowed by a per-caller survival veto computed as a first-access walk over the CALLER'S
RAW CFG (`survives_call` on a throwaway `cfg::build_cfg` clone; building the CFG in place
corrupted the whole pipeline, 734 → 139, caught by the corpus gate — and note the harness
trap it exposed: a broken binary's param-order pre-pass cache POISONS every later emit
under the same `-dirty` stamp). Untainted result: **733** — the closest of every round
(−5 EXACT / +4 EXACT / +2 SAME_SHAPE, WGSS 0.4626 → 0.4633) and still not dominating.
The five losses, diagnosed and recorded:

- `FUN_0005d00a`, `FUN_00071caf` — thunks whose OWN inherited contract (transitive) and
  whose callee's DECLARED pragma (blanket-minus-veto) now disagree within one TU, so
  Watcom saves the difference and cannot tail-call. An internal CONSISTENCY defect of the
  experiment, not model incompleteness — the named first fix if reopened: one per-TU
  contract value per callee, used by BOTH the pragma and the own-contract inheritance.
- `FUN_00014754` — a spill-slot appears (`SUB ESP,4`): contract-narrowing changed
  allocation pressure in a direction no read-across testimony describes.
- `FUN_000459a0` — argument-register shuffling (`MOV EDI,EDX` / `MOV EDX,EBX` + save)
  where the original's wider assumed kills made the original allocator's choice.

Stable gains across every sound round: `FUN_00011b9c` (the founding specimen),
`FUN_00031d58` (sb98's residue), `FUN_000362f0`, `FUN_0004f850`. PARKED per the
workarounds-checkpoint stop-rule (one mechanism, at most one soundness fix): net −1 does
not clear the zero-regression bar, and each further rule would reopen the spiral. The
experiment code is reverted, not landed; this entry is its record.

**What LANDED from the frontier (this commit — verdicts identical to sb98,
verdict-for-verdict, WGSS 0.4626 unchanged):**
- the pragma MERGE in the caller-side post-pass (a real latent collision bug — inert
  today only because each callee currently carries at most one pragma source at a time);
- thunk TAIL-CALL contract inheritance: a `Branch` out of the recorded body to another
  function's entry contributes that function's transitive contract to `own_modify`
  (`FUN_00072357` = `JMP unlink_` gets `modify [eax ecx ebx]`, so Watcom needn't save and
  can emit the original's bare `JMP`) — measured verdict-neutral standalone, load-bearing
  under any future contract extension;
- `transitive_contract` + `Program::contract_cache` (the fixed-point machinery, used
  today only by the inheritance) and the `NestedCalls` walk parameterization;
- `CallSpec::cdecl_modify` computation stays at sb98's landed blanket semantics.

**734 → 738 EXACT (sb100): the UNSIGNED-COMPARE spelling recovered from the original's
immediate width — the first frontier run fully under the new experiment discipline.** The
SAME_SHAPE census named a 10-member `immediate` class; its sharpest family (60 functions,
77 rows corpus-wide): equality against an all-ones narrow constant, where Ghidra (verified
on the oracle: `*(char *)(x + 0x1e) != -1`) and mosura both type the operand signed and
print `-1`, while the ORIGINAL compares the zero-extended value against `0xff` — imm32 vs
imm8, a binary-observable spelling. Under Watcom's UNSIGNED-default plain `char` the
signed rendering is not merely a byte difference: `(char)x != -1` zero-extends and can
never be false, so the recovered arm's unsigned form is also the semantically faithful one
for the target.

Recovery, in the standard purity shape: printc records `allones_cmp_candidates`
`(pc, width)` on every equality print (report-only, default render byte-identical to
Ghidra's); `buildconfig::unsigned_cmps_from_evidence` reads the ORIGINAL compare at the
site and selects only the unambiguous form — a WIDER (32-bit) register against the
width-mask immediate (`CMP EDX,0xff`); a compare at the constant's own width
(`CMP DL,0xff`) encodes both spellings and recovers nothing. The chosen site renders
`(uint1)x != 0xff` — re-zero-extending the same value, compiling to the original's exact
sequence.

Pre-registered (memory: experiment-discipline): class = binary-observable fact; ceiling
5–12; budget 2 corpus rounds; park on any regression. Round 1: **+4 EXACT
(`FUN_000260f4`, `FUN_000261e8`, `FUN_0003b088`, `FUN_0003e038`), the ONLY verdict
transitions — zero regressions**, 54 TUs changed, WGSS 0.4626 → 0.4628. Landed in one
round; the family's remaining ~56 MISMATCH members carry other divergences and keep their
77-row spelling improvement.

**738 → 739 EXACT (sb102): `RuleAndCompare` wired at Ghidra's slot — the inert-rule leads
run down on the survey path.** The faithful-convention trace instrument (the watcom cspec
registered into the oracle distribution) named three implemented-but-inert rules; verified
on the SURVEY path with the new per-function trace scope (`MOSURA_TRACE_FUNC`):
`multicollapse` fires fine (fixture artifact of the isolated builder, which lacks the
survey's stack pre-model); `andpiece` is downstream of `andcompare`; and `andcompare` was
the one real gap — implemented, deliberately unwired behind a STALE prerequisite. The doc
said "wire once `addmultcollapse`/`sub2add` run in the main loop (Task #8)"; both have
since been in the main pool at Ghidra's exact actprop positions, so only the wiring
remained. The sequence-aligned trace pair put the first hard rule divergence precisely at
Ghidra's `andcompare @ 0x17e28`.

Wired at Ghidra's own registration slot (AndZext → AndCompare → DoubleSub,
coreaction.cc:5540-5542). The historical over-fire that justified unwiring (forloop_varused
0.984 → 0.970) is GONE — conformance suite green — confirming the pool placement was the
cause exactly as the old doc theorized. Corpus: **+1 EXACT (`FUN_00035b40`, the census's
`TEST AH,0x2` member) — 739**, zero EXACT regressions, WGSS 0.4630 → 0.4633, one
same-sim label shuffle (0x4d37c SS→MM at 0.667 unchanged, 0x58840 MM→SS).

Also landed on the way: the `MOSURA_TRACE_FUNC` per-function trace scope (the survey path
was untraceable before — 3023 decompiles flood the single-function facility), and the
sequence-alignment reading of trace pairs (first-divergence, not just counts).

**739 → 741 EXACT (sb102 re-measured): the "wrong neighboring global" family was a HARNESS
ARTIFACT — OMF fixups are additive, the checker replaced.** Family B's strict sub-census
(58 functions, 92 rows of `MOV` at `symbol ± 1/2/4`) chased through heritage (both
decompilers piece the dword pair identically — `CONCAT22(r0x8f2b0, r0x8f2ae)` in BOTH
traces), then through the emitted C (our reads are the CORRECT shorts), landed on the
specimen that could not lie: `FUN_00045ee0`, SAME_SHAPE 0.939 with exactly two divergent
rows, where the ORIGINAL's own idiom is `MOV EAX,[0x971d2]; SAR EAX,0x10` — load the dword
TWO BYTES BEFORE a short and shift — i.e. the field's operand is `symbol − 2`.

TIS OMF 1.1 fixups are ADDITIVE: the computed target is added to the field's existing
content, and the compiler writes any `symbol ± k` addend INTO the field.
`Candidate::relinked_bytes` REPLACED the field with the bare resolved target, and the
differ's `Relocator::resolve` displayed the same bare target — so every candidate
`symbol ± k` operand compared and printed as `symbol`, manufacturing phantom
neighboring-global accesses. Fixed in both places (absolute arm only; the self-relative
call arithmetic is left as the 739 EXACT functions' call sites prove it).

Re-measured (same emit tree, cached objects re-compared): **+2 EXACT
(`FUN_00045ee0`, `FUN_0004f580` — byte-exact all along), 741**, zero movements in any
other direction — the stricter-correct comparison surfaced no false EXACTs. WGSS 0.4633 →
0.4635. The remaining ~56 family members keep their now-truthful rows; their other
divergence classes stand.

**The "missing MOV before calls" lever, run to ground (post-741; two experiments, both
parked, one mechanism named).** OW source reading (JD's directive): the placement of
argument setups around calls is governed by the SCHEDULER's dependence test
(`inssched.c` — `StackOp` makes calls barriers only against other stack ops;
`ReDefinedBy` blocks register motion via the call's ZAP set) and the zap comes from
`CallZap` (i86reg.c:256):

```
zap = state->modify;                        // declared kills
if (!ROUTINE_MODIFY_EXACT)
    zap |= state->parm.used | return | EAX; // + THIS call's own argument registers
```

So placement encodes BOTH the callee's declared kill set AND — through `parm.used` — the
call's ARITY. Two recompile-side consequences, each measured to a verdict:

- **Prototype pass as default** (arity → zap): corpus round, net −24 (717; 31 real gains
  incl. `FUN_00011b9c` and the 63-memset `FUN_0001fdbc`, 53 losses). The dominant loss is
  NOT the historical phantom-constant defect (the locked parms bind pre-heritage now,
  measured on 11b9c): it is REMATERIALIZATION — a value the original passed through calls
  for free (`XOR EDX,EDX` reborn at `FUN_00012c58`) because our call's `parm.used` kills
  the register the original's declaration preserved. A trailing-valueless-arg trim was
  built and measured INERT: by print time the valueless arguments are genuine `const 0`
  varnodes (the indirect-creation placeholder collapses upstream) — the detection needs an
  analysis-time channel, recorded for the reopened design.
- **Project-wide `modify exact [eax]` default** (the warcraft2-re toolchain.md
  convention): corpus round, net −11 with ZERO gains (730) — refuted as a BLANKET callee
  declaration. The toolchain finding describes the original functions' OWN prologue
  contracts; call sites prove per-callee variation (the sb98 vararg family's caller saves,
  `FUN_00011128`'s EBX/ECX). Both experiment codes reverted.

**The durable yield is the specification**: the sb99 latent (the original build's per-TU
declarations) has exactly the shape `(kill set, exact?)` per callee, and the proto pass's
arity recovery participates through `parm.used`. Every observed placement/remat divergence
is a readout of that pair through `CallZap` + the scheduler. The reopened contract design
(byte-exact-status sb99, parked with its ledger) is where all three threads — kills,
exactness, arity — land as one recovery.

**741 → 743 EXACT, WGSS 0.4635 → 0.4656 (ct1): the CONTRACT DESIGN, Increment 1 —
per-(TU, callee) declarations from three testimonies, landed.** The sb99 park reopened on
JD's greenlight, built as the specification the CallZap investigation defined. One contract
value per (TU, callee), computed in `record_callee_effects` and consumed by every
downstream reader (callee pragma, thunk inheritance — which now agree BY CONSTRUCTION: a
thunk's post-call window is empty, so its veto is empty, so both read plain transitive; the
sb99 consistency defect cannot recur):

- **body-truth**: `transitive_contract` (the call-graph fixed point) — what the callee
  visibly clobbers;
- **survival veto** (`survives_call`, the CFG first-access walk on a `build_cfg` CLONE,
  vetoes UNIONED over all of the TU's sites per callee): a register the caller reads back
  across a call was declared preserved in THIS TU;
- **no-save veto** (the complement, named by round 1's single loss `FUN_00072c37`): a GPR
  the caller's own contract must preserve and never saves-and-restores cannot have been
  declared killed by ANY callee it calls — the original compiler's codegen would have
  forced the very PUSH/POP our recompile added. Computed from the caller's own body walk
  (writes ∪ restored), applied to every non-caller-cleaned contract.

Caller-cleaned callees stay EXEMPT from both vetoes (their full recovered kill set is the
landed sb98 result; the add-direction evidence stands). Round 1: 742 (+2/−1, the loss
diagnosed same day into the third testimony). Round 2: **743 — `FUN_00011b9c` (the
founding argument-position specimen) and `FUN_000362f0` EXACT, `FUN_0004b750` → SAME_SHAPE,
ZERO losses of any kind**. WGSS +435 matched instructions over the sb102 baseline. The
smoke sentinel for 11b9c flips to EXACT with this landing (re-pinned).

Increments 2 (exactness — `ROUTINE_MODIFY_EXACT` recovery, the 12c58 pass-through class)
and 3 (arity via the prototype pass, now that recovered contracts suppress the
rematerialization that sank its solo round) remain pre-registered next steps.

**743 → 743 (zc1): the SCHEDULER-BASED CHECKER built and landed; increment 3 parked at
its fourth coupling.** The verifier the contract design's parks demanded: per TU, the
prototype-informed decompile is adopted only as a GATED UPGRADE over the landed world —
`watsched::order_regressed` (the scheduler model with per-call effects parameterized via
`CallEffects`; comparative, so the model's own imprecision never blocks) plus two
structural gates learned at the smoke gate (~3 min per catch, five hardening iterations,
zero corpus rounds wasted): the LANDED world stays PRIMARY (every definition-side global
map — the caller-side parm network, caller_calls — builds from prototype-less funcdatas,
so upgrades cannot leak into fallen-back TUs through other functions' signatures), own
parameter-signature stability, and refusal for TUs calling any NONDEFAULT-STORAGE callee
(the parm post-pass's arity/width gates key on call arg sizes; memoized landed decompiles
answer per callee).

Round 1: 742 upgrades adopted, 393 TUs changed, **verdict-neutral 743** — +6 EXACT
(`FUN_000294dc` and friends) traded against −6, with the historical scheduler-order losses
GONE (12360/11b9c-class all held; the checker does its dimension). The surviving loss
mechanism, named on `FUN_00034fe0`: REGISTER-ALLOCATION PRESSURE — an upgraded arity
changes which values survive calls, the allocator reaches for ESI/EDI, and a `PUSH EDI`
the original lacks cascades. Structurally outside a scheduler model (order, not
allocation); the honest next unlock is an allocation-aware gate, a new modeling pile.
Parked per pre-registration at +6/−6; the machinery lands env-gated
(`MOSURA_PROTO_PASS=1`), default-off, landed tree untouched (sentinels + default smoke
prove byte-identity).

**743 → 743 landed / 746 measured behind the gate (zc2): the register-allocator model,
phase 1 — the allowed-set condition — built; phase 2's question isolated to a
four-specimen fixture.** `watsched::allocation_regressed`: a register the ORIGINAL
demonstrably carries across a call (written before, read after, straight-line) was in the
allocator's allowed set for that live range, so a candidate declaration killing it would
have re-homed the value — the FUN_00034fe0 `PUSH EDI` shape, now refused (grounded in
regalloc.c's structure: `AssignConflicts` → savings-sorted `GiveBestReg` under an
allowed set).

The full gate stack (scheduler fixed-point + allowed-set + nondefault-storage network +
signature) measured **746 EXACT: +4 (`FUN_000294dc`, `FUN_0003b00c`, `FUN_0005f33b`,
`FUN_0003adec`) − 1 (`FUN_0005ed78`)** — net +3, but the campaign's bar is
zero-regression, so the config stays DEFAULT-OFF and the baseline holds at 743. The one
loss shares its shape with two of the gains — own parameter count GROWS under the
prototype pass (1→3) — and the count is NOT the discriminator (`FUN_0005f33b` grows 0→3
and stays EXACT). The real question, isolated: do the added live-in parameter registers
COLLIDE with the original body's own register usage (5ed78's original saves and uses EBX;
param_3 arrives in EBX)? Answering it per function is the phase-2 cost kernel
(`CalcSavings`/`GiveBestReg`), and the quartet is its ready-made fixture: a correct model
must adopt 294dc/3b00c/5f33b and refuse 5ed78.

A full-signature stability gate was measured on the way and REFUSES EVERY upgrade (all
gains grow their own signatures — the arity recovery working); recorded so it is not
re-derived.

**743 → 746 EXACT (zc2): the COLLISION HYPOTHESIS closes phase 2's cheap half — the
checker-gated prototype pass LANDS, default-on.** The quartet fixture did its job in
minutes: the phase-2 question ("which own-arity growths are allocation-safe?") is answered
for the measured corpus by ONE more gate — an ADDED own-parameter whose register the
original body WRITES with ordinary instructions (calls' convention effects and the
PUSH/POP save pair excluded) is a live-in colliding with the body's own usage; refuse.
Quartet: refuses `FUN_0005ed78` (its body uses EBX; param_3 arrives in EBX), adopts
`FUN_0003b00c`/`FUN_0005f33b`; over-refuses `FUN_000294dc` (body writes EDX somewhere —
not necessarily overlapping the live-in), the known conservatism a full
`CalcSavings`/`GiveBestReg` kernel could recover.

Corpus, one pre-registered round: **746 EXACT — +3 (`FUN_0003b00c`, `FUN_0005f33b`,
`FUN_0003adec`), ZERO losses of any kind, +1 MISMATCH → SAME_SHAPE** — the first
arity-recovery configuration to clear the zero-regression bar. 364 TUs upgraded. The
prototype pass is now DEFAULT-ON in the survey (`MOSURA_PROTO_PASS=0` restores the bare
landed world); per-emit cost roughly doubles (the pass ~97s + per-TU dual decompiles +
gate walks) — the runbook cost model updated.

The full gate stack that makes it safe, in firing order: scheduler fixed-point
(`order_regressed` — placement), allowed-set (`allocation_regressed` — killed-crossing
values), collision (own live-ins vs body usage), nondefault-storage network (the parm
post-pass's arity gates), signature (nondefault-storage stability). Remaining headroom on
this thread: the over-refusals (294dc-class, 26b18-class) recoverable by the full
allocator cost kernel — parked with its fixture until measured worth building.

**Harness note, for the runbook file:** the first sb97 check was run against the wrong
Watcom tree (`/data/watcom16`) — every cache-missing TU "failed" with dosemu's `Bad command
or file name - WCC386` and the 312 fresh entries poisoned the cache as COMPILE_FAIL. Wild
verdict shifts on a small source diff = wrong harness invocation, exactly as the runbook
says; the canonical path is
`/home/jd/projects/warcraft2-re/tmp/watcom-experiments/watcom_10.0a/WATCOM`. Purge the
poisoned entries (they are keyed on content, so they do NOT age out) before re-running.

**The transferable win is the METHOD:** recovered-vs-searched can now be measured for any axis
in one pass, because the candidate enumeration is exposed and the scoring rule is a pure
function of the original's instructions.

**Why the coverage gap, and the fix:** the probe enumerated candidates its own way (ops whose
output is a narrow register varnode with a `MOV` at that address) instead of the candidate set
the axis actually uses (`printc::storage_widened_local`'s gate — HighVariable members, def
value-safety, explicitness). An evidence rule can only be calibrated against the SAME
candidates the rendering keys on. **Next step:** expose the candidate enumeration from the
axis (target-agnostic), have the Watcom profile score those exact candidates against the
original's instruction at each def, and re-measure recovered-vs-searched.

This is NOT the retired similarity-score chase (TODO.md "Direction"): that gauge compared
emitted C **text against Ghidra's rendering** and was chased as a target, which rewarded
approximation over faithfulness. This one compares recompiled **machine code against the
original binary** — the thing byte-exactness is a count of — and it is a trend diagnostic
between verdict transitions, never a target: alignment can rise while semantics diverge,
so the verdicts stay the ground truth.

### One address per location

`wrap_offset` existed but was called in exactly three places in the decompiler, so the
invariant "an offset is canonical for its space" held only where someone remembered it. The
same stack slot reached `guard_calls` as both `0xffffffec` and `0xffffffffffffffe8`; two
spellings are two `Address`es, so a trial created under one never matched the varnode under
the other and the argument was dropped at commit. Canonicalizing before the `Address` is
formed (`c38ce6a`) is worth +3 on the default configuration and, more importantly, removes a
whole class of silent mismatch that is not x86-specific -- any space narrower than 64 bits
has it.

### CLOSED: open thread 3 -- the trailing stack trial (60 -> 38 pass losses, `19d8060`)

The dropped trailing stack argument was not a fillin problem. The chain: the prototype pass's
call_specs entries opt calls in to `ActionExtraPopSetup` (which iterates `call_specs.keys()`
where Ghidra walks ALL calls); watcall's unknown extrapop plants an ESP INDIRECT before the
CALL; the stack placeholder, inserted after it, binds the INDIRECT's post-call OUTPUT; the
recorded stack offset comes out one slot high; the real argument translates below the
parameter area and no trial is ever registered. `FUN_00023514` recorded -20 where the truth
is -24, and `PUSH 9` vanished.

Fixed by anchoring the placeholder BEFORE the call's extrapop INDIRECT -- gated to calls whose
RECOVERED prototype names stack storage (Ghidra's own locked-prototype condition,
coreaction.cc:1498). The gate is load-bearing twice over; both arms were measured before the
gate existed:

* ungated, the default configuration lost 2 functions (`FUN_000121e8`, `FUN_000485a0`);
* anchored at register-only callees, `FUN_0001fdbc`'s 63 memset calls grew phantom stack
  arguments from the caller's own save slots (EXACT -> 0.522).

Standing after: pass 544 (from 522), losses vs default 38 (from 60), union 582, default emit
byte-identical.

### Open thread 4 -- phantom stack trials wherever the offset resolves wrong

REFINED (post `b6c7d31`, `MOSURA_SAVEDSLOT=1` on `FUN_000121e8`): the surviving phantom at the
losses examined is the RETURN-ADDRESS slot, not the save slots. A stale return address is a
constant-valued stack write -- `STORE(ESP, next_pc)` converted to a stack COPY of a constant --
and once a mis-resolved stack offset lets it translate into the parameter window it is
INDISTINGUISHABLE from a `PUSH imm` argument: written (realistic), consumed only by the call
(ancestorOpUse accepts). No value-side guard can reject it; only correct GEOMETRY can, by
keeping it at `trans 0`, below the parameter area. The `is_saved_slot` guard behaved correctly
in the instrumented case (`copy_found=false` for a slot no input register is copied into is
the right answer -- it is not a save slot).

The offsets go wrong at calls still on the OLD placeholder geometry (post-call INDIRECT
binding), which is every call whose recovered prototype does not name stack storage. The
endgame is therefore to make the ANCHORED binding unconditional -- one offset convention for
every call, return-address slots excluded by geometry everywhere, save slots vetoed by
`is_saved_slot`'s copy check, and the remaining trials genuinely arguments. The two default-
config losses the unconditional anchor produced when first tried (`FUN_000121e8`,
`FUN_000485a0`) are the test cases to hold: at correct offsets their RA slots leave the
window, and their save slots must be caught by the copy check or by the restore-side
double-use.

### Superseded framing (kept for the record)

The remaining barrier to resolving stack offsets at EVERY call (as Ghidra does): once the
offset is known, the caller's own saved-register slots (`PUSH EDX ; PUSH EBP` prologue saves)
translate into the callee's parameter window and become trials. They survive realism -- the
slot IS written, and the value DOES trace to a real input -- and `is_saved_slot`'s
`own_saved` veto is inert exactly where it is needed, because `callee_writes_cfg` bails on
any function containing calls, and a function with no calls needs no veto. The emitted
symptom is unmistakable: calls grow arguments that are the caller's own saved registers plus
return-address-shaped constants (`func_0x...(.., param_1, 0x1fe19)`).

A robust `own_saved` (prologue/epilogue save-restore pairing that does not require walking
through calls) would close it, and with it the anchor's gate could widen toward Ghidra's
uniform coverage. 38 pass losses and the 2 known default-config hazards are the measured
stake.

### The single-shot ceiling is Ghidra-parity, measured against the oracle

Asked about `FUN_0001fdbc` with the callee present but unanalyzed (raw import, both functions
created), Ghidra emits `FUN_00050480()` -- ZERO arguments on all 63 calls. The default
single-pass keeps 62 of 63. Argument recovery for calls to known functions is, in Ghidra,
fed by the DATABASE (`ActionDefaultParams` copies the callee's prototype); mosura's
whole-program prototype pass is the port of that database, and under it `FUN_0001fdbc` and
`FUN_00023514` are both EXACT. The pass is the faithful configuration; its remaining 38
losses are the work-list.

### Unrelated pre-existing failure

`disasm_pcode_ratchet` fails (`disasm parity regressed: 244 < 254`). It fails identically
with the working tree stashed, and no commit in this line of work touches disassembler code.
It is inherited, not caused here, and wants its own investigation.

The +81 was two coupled defects — see the commit for `force_inactive_chain`'s missing
`IPTR_SPACEBASE` test and the killedbycall-register save slot. Gained 81, lost 0.

Two instrument defects were fixed before any of this, and numbers predating them are not
comparable: a pushed return address made every call downstream of a size change report a false
`immediate` (5741 rows / 1722 functions), and erasing it turned those into `encoding`, the class
meaning "not reachable from C" — which would have written 122 functions off the work-list.

## Open thread 2 — a trial rejected on an early graph is never reconsidered

The next mechanism in the call-argument family, distinct from the two the +81 fix addressed. It is
NOT "the trial was never registered" and NOT "the chain rule killed it".

Specimen `FUN_00015820`, one divergence from exact: the original is
`MOV EDX,0x8f040 ; MOV EAX,0x8f000 ; CALL 0x12f24` and we emit `func_0x00012f24(0x8f000)` — the
second argument is dropped. `MOSURA_ARG_DEBUG=1` shows the whole story:

```
[why] slot=2 verdict=Inactive uses=[Copy@0x15821 Multiequal Call@0x1584e Call@0x15871 Call@0x15881 …]
[why] slot=2 verdict=Active   uses=[Call@0x1584e]
```

Early on the varnode at that slot is the INCOMING EDX — saved at entry by `PUSH EDX`, used all over
the function — and `ancestor_op_use` correctly rejects it, because it is genuinely not used only by
this call. Later it refines to the `MOV EDX,0x8f040` value whose only consumer IS this call, and the
same machinery correctly judges it **Active**. So the analysis reaches the right answer; the answer
just arrives after the verdict is frozen.

Two things freeze it. `build_input_from_trials` ends with `delete_unused_trials` (fspec.cc:5740),
and a pruned trial cannot return because its range is already heritaged so `guard_calls` never
re-offers it. And `Funcdata::reopen_input` flips `active` alone, which is inert —
`check_input_trial_use` skips any trial already `CHECKED` and the container is still fully-checked,
so the second round re-commits the identical decision.

**Measured and rejected: clearing the verdicts on re-open.** Making `reopen_input` clear
CHECKED/DEFNOUSE/ACTIVE/USED and resetting the pass state, with the pruning deferred until after the
second round, is a REGRESSION — and a bad one. On the specimens it does not add the missing argument;
it removes the arguments that were already right, including `FUN_00033370`'s
`func_0x000332c4(param_1, param_2, 0x8ce58)` which the +81 fix had made exact. Clearing a verdict
discards a good committed decision rather than refining it, because the second evaluation runs
against a graph where the earlier evidence is no longer visible either.

**And the narrow version fails too, which rules out the whole family.** Recording on each trial the
varnode its verdict was formed against, then re-evaluating on re-open ONLY the trials whose slot no
longer holds that varnode, is also a regression — worse than the broad version. `FUN_00033370` drops
from `func_0x000332c4(param_1, param_2, 0x8ce58)` to two arguments, and `FUN_00015820` loses EAX as
well as EDX.

The reason is the opposite of the assumption behind both attempts. The LATE verdict is not the
better one. By the time a re-open happens the graph has been transformed — constants folded, values
merged through MULTIEQUALs — and `ancestor_op_use` fails on values it previously accepted. The early
verdict is usually the sound one; it is simply taken while the slot still holds the wrong varnode.

So the fix is not in the re-open mechanism at any granularity. The question is why the slot holds the
incoming EDX at the moment the trial is first judged, instead of the constant the caller stores
immediately before the call — a heritage/ordering question about when `guard_calls`' manufactured
read is linked, not an argument-recovery one.

## The work-list, by measured marginal value

Not "which class is biggest" — which class, if *eliminated*, leaves functions with **no**
divergence at all. That is the number that converts to EXACT. From the per-divergence fact table
(`recompile::report`):

| cause | functions whose ONLY cause it is | cumulative if also eliminated |
| --- | --- | --- |
| `missing`/`extra` (call arguments) | 45 | 477 |
| `save/args` (missing PUSH/POP) | 9 | 554 |
| `immediate`/`operand-form` | 21 | 629 |
| `selection` | 7 | 828 |
| `regalloc` | 3 | 1510 |

The first two are one cause — **we call functions with too few arguments** — and that is open
thread 1. 996 missing `ADD ESP,K` rows across 354 functions are the caller-side of the same thing.

## Open thread 1 — the propagated-prototype argument, RE-DIAGNOSED

Whole-program prototype recovery is built (`analysis::interface`, `Program::recovered_protos`,
bound at every direct call). It is OFF by default (`MOSURA_PROTO_PASS=1`). Measured on WAR2 with
the corrected instrument: `missing` 1157 → 1081, but `extra` 467 → 603 and COMPILE_FAIL 75 → 96,
so EXACT goes 421 → 394. The prototypes are right; the pass loses on spurious arguments.

**Iterating it to a fixpoint was tried and rejected.** Round one's snapshot is taken before any
prototype exists, so it is systematically narrower than what the same callee recovers later —
`FUN_0004c978` gives `[register+0x0/2]` where the function takes `register+0x0/4, register+0x8/4`,
which deletes its caller's second argument. Iterating measured **413** against 422 for one round,
and never converged within four rounds: each extra round reduces `missing` exactly as predicted
and buys more `extra` than it is worth.

**The previously recorded diagnosis was wrong, and it was wrong in a way that sent the fix to the
wrong subsystem.** It read this instrument line

```
[arg] call@0x13c6b slot=1 size=4 unref=FALSE addr=register+0x0 vn=Some((4, written=false, free=false))
```

as "an argument resolved to a varnode that is linked but UNWRITTEN", concluded the argument had no
reaching definition, and built a call re-open mechanism on that premise. But `written=false,
free=false` is exactly what a **constant** varnode reports — a constant is neither written nor
free. The argument had not failed to resolve; it had already been *replaced by* `#0x0:4`. The
instrument now prints the whole input list, which makes the difference impossible to misread:

```
[arg] call@0x13c6b slot=1 ... inputs=[0:ram+0x5a48c/4- 1*const+0x0/4- 2:register+0x8/4w 3:register+0xc/4w]
```

Slot 1 — the slot the trial names, and the correct one — already holds the constant when
`build_input_from_trials` reads it. The slot bookkeeping is fine.

**What actually happens, from the rule trace** (`MOSURA_OPACTION=1`, `FUN_00013c50`). Heritage
binds the argument correctly:

```
0x13c6b:31: CALL r0x5a48c:4(free) u0x10009:1(...) r0x0:4(free)          r0x8:4(free) r0xc:4(free)
   0x13c6b:31: CALL r0x5a48c:4(free) u0x10009:1(...) r0x0:4(0x13c5e:12) r0x8:4(0x13c56:8) r0xc:4(0x13c54:7)
```

`r0x0:4(0x13c5e:12)` is the output of the call five instructions earlier — exactly the value the
original passes by doing nothing at all. Then one action replaces it:

```
DEBUG 1249404: resolvecalls
0x13c6b:31: CALL ... r0x0:4(0x13c5e:12) r0x8:4(...) r0xc:4(...)
   0x13c6b:31: CALL ... #0x0:4          r0x8:4(...) r0xc:4(...)
```

`ActionResolveCalls` is `resolve_return` + `resolve_call_args`. The constant is already in the slot
by the time this call's `build_input_from_trials` runs, so the substitution happens earlier within
that same action — that is the next thing to isolate, and it is a *dataflow* question, not an
action-ordering one.

**Ground truth, from Ghidra with the callee's parameter forced** (`GHIDRA_POSTSCRIPT=
DecompileWithForcedParams.java GHIDRA_POSTSCRIPT_ARGS='5a48c=EAX' scripts/ghidra-decompile-war2.sh
5a48c 596b0 13c50`):

```c
forced_1 = FUN_000596b0();
if (param_2 != *(int *)(forced_1 + 0x14)) { *(int *)(forced_1 + 0x14) = param_2; FUN_0005a48c(forced_1); }
```

Ghidra passes the previous call's result. mosura emits `func_0x0005a48c(0)`, and Watcom then emits
the `XOR EAX,EAX` that shows up as the `extra` divergence. So this is a port defect with a named
oracle answer, not a design difference.

**Fixed, and what it was worth.** `check_input_trial_use` runs before `derive_input_map`, and its
`markNoUse` verdict does not merely mark — it FREES the dataflow, replacing the input slot with a
constant 0 (fspec.cc:5650-5651). `derive_input_map` then re-marks the trial active, which cannot
restore a varnode that is now a constant. A trial at storage the callee's recovered prototype names
is marked Active inside the check now. Measured: pass ON **394 → 422** EXACT, `missing` 1081 → 1019.

The gate has to sit INSIDE the check. Skipping `check_input_trial_use` wholesale also skips the
marking and the pass counter, so the list commits on pass 0 and arguments vanish — measured, the
specimen came back as `func_0x0005a48c()` with no argument at all.

## Open thread 1b — two coupled defects in the argument chain rule

**This is the call-argument family's root defect in the DEFAULT configuration** (no prototype
pass). Both halves are located and oracle-confirmed; they must be fixed together, because fixing
either alone measures worse.

Sized by marginal value on the 433 baseline: **73 functions** have only call-argument-shaped
divergences — missing `PUSH`/`POP` saves, missing `MOV <argreg>,K` setup, missing `PUSH K` stack
arguments, missing `ADD ESP,K` cleanup. Ten are a single divergence from exact, 26 within three.
(2225 merely *exhibit* one of those; that number means nothing.)

Specimen `FUN_00033370`, three instructions:

```
- 00033373  MOV EBX,0x8ce58 |            [missing]
  00033378  CALL 0x332c4    | CALL 0x332c4
```

The callee takes its argument in **EBX** — watcall slot 3 of EAX/EDX/EBX/ECX — and slots 1 and 2
are unused at this site. We emit `func_0x000332c4()`. Ghidra, asked with the callee's parameter
forced, emits `FUN_000332c4(0x8ce58)`.

`MOSURA_ARG_DEBUG=1` (with the `[check]`/`[verdict]`/`[trials]` instruments) traces it precisely:
the evaluation marks EBX **Active**, and `fillin_map` then clears it. Stage-by-stage, the clearing
is in `force_inactive_chain`, and the kill fires at `i=0` with `chainlength=1` — before any chain
could form.

### Half one — the chain condition is mis-ported (mark it, fix it WITH half two)

Ghidra sets `seenchain` from an unref trial **only for a stack location**:

```c
if (trial.isUnref() && active->isRecoverSubcall()) {
    if (trial.getAddress().getSpace()->getType() == IPTR_SPACEBASE)   // stack only
        seenchain = true;
}
```

The reasoning is specific to the stack: an unreferenced *register* may plausibly be an input the
caller passes straight through, whereas a stack slot cannot, since caller and callee stack offsets
differ. Our port dropped the inner test, under a comment asserting the branch was unreachable
because `is_recover_subcall` is false. **It is reachable and it fires.** One synthesized register
hole then sets `seenchain`, and every later trial in the section is marked inactive regardless of
chain length — which is what kills the real EBX argument.

### Half two — hole-filling promotes synthesized trials into real parameters

Restoring the stack-only test alone measures **373 EXACT against 433** — gained 22, lost 82. The
gains are the intended ones. The losses are all `PUSH`/`POP` of `EDX`/`EBX`: with `seenchain` no
longer poisoning the section, `force_inactive_chain`'s tail loop ("fill in holes of inactive
trials") marks the two synthesized unref holes ACTIVE, `fillin_map` marks every active trial used,
and they become real parameters of the CALLER — `FUN_00033370` goes from `void f(void)` to
`void f(xunknown4, xunknown4)`. Those registers are then live across the function and Watcom saves
and restores them.

So the hole-filling needs to distinguish a hole that stands for a real argument from one
synthesized purely to keep slot numbering contiguous. Until it does, half one stays out — reverted,
not lost.

**And the specimen is not caller-side at all.** With the prototype pass ON, `FUN_00033370` still
emits `func_0x000332c4()`, because the propagated prototype for the callee is
`[(register,0,4), (register,8,4)]` — EAX and EDX, not the EBX the caller demonstrably sets. Ghidra's
own unforced recovery of that callee is `void FUN_000332c4(void)` with a `byte *in_EAX` and **no
mention of EBX anywhere in its body**. So neither decompiler sees the callee read the register its
caller writes: EBX must be consumed further down, and recovering it needs argument propagation
across more than one call level. Ghidra only produced `FUN_000332c4(0x8ce58)` because the parameter
was forced.

That reframes the family. Trial recovery cannot produce a one-argument call at slot 3 even in
principle — Ghidra's hole-filling is deliberate, since C has no gaps, so slots 1 and 2 must become
arguments once slot 3 is one. The answer has to come from a correct callee prototype, and for this
specimen that prototype is only correct if EBX is propagated through the callee to its own callees.

### Half two, located: a spurious STACK trial drags the register holes in

The 82 losses have one shape, and it is not the hole-filling being wrong in general. Comparing the
trial set at the call, instrumented with `MOSURA_ARG_DEBUG=1`:

| case | trials at the call |
| --- | --- |
| `FUN_00033370` — fix GAINS it | `EAX hole · EDX hole · EBX real` |
| `FUN_00013160` — fix LOSES it | `EAX real · EDX real · EBX hole · ECX hole · stack+0x4 real` |
| `FUN_0001193c` — fix LOSES it | identical shape |

Where the fix helps, the real argument sits at the HIGHEST slot and the holes below it are genuine
pass-throughs — filling them is correct, because C has no gaps. Where it hurts, a `stack+0x4` trial
at the far end extends `max`, so the tail hole-filling promotes the two register holes into
parameters of the CALLER, and Watcom then saves and restores those registers.

**That stack trial is spurious.** `FUN_00013160` is `PUSH EDX ; PUSH EBP ; MOV EBP,ESP ; … ; CALL`
and pushes nothing as an argument, so the callee's first stack-argument slot maps onto the caller's
**saved EBP**. The mis-ported `seenchain` was accidentally masking it — which is why half one cannot
land alone and why the masking looked like correct behaviour for so long.

So the chain is three layers, not two:

1. `force_inactive_chain` mis-ports Ghidra's stack-only test and kills real register arguments.
2. Fixing that exposes hole-promotion, which is *correct* in itself.
3. Hole-promotion only misfires because a spurious stack trial extends its range — and that trial
   exists because the caller's saved registers are being mapped to the callee's argument slots,
   i.e. a spacebase-offset question, not an argument-recovery one.

Fix (3) first; (1) then lands on its own and (2) needs no change.

**Eliminated: the heritage marking on the manufactured varnode.** `build_input_from_trials`'s
`isUnref` branch calls `set_active_heritage()` on the varnode it manufactures, which Ghidra does
not (`vn = data.newVarnode(sz, addr)` and nothing else). That looked like the mechanism — the
manufactured read joining the next renaming round, linking to whatever the caller had in that
register, and the caller's own input recovery then seeing a used input. It is not: removing it
alongside half one leaves the specimen byte-for-byte unchanged, caller parameters and all. Whatever
promotes those holes to caller inputs happens elsewhere, and that is the next thing to find.

## Open thread 1a — the 47 functions the pass still breaks

The pass is still net −11 against the default (422 vs 433); the union of on/off is 469. It breaks 47
functions that are EXACT with it off, **17 of them by a single divergence**, and those 17 split into
two opposite defects — which is why a single "the pass over-recovers" story never fit:

**Under-recovery (8).** `missing: MOV EDX,0x4921c` at 0x49298, 0x492bc, 0x492e0 … — consecutive
near-identical wrappers, each stepping 0x24, each loading the SAME constant into EDX. The original
passes a second argument and we drop it: the callee's recovered prototype does not include EDX.

**Over-recovery, by WIDTH (5).** `extra: AND EAX,0xff` at 0x15227, 0x15247, 0x15267, 0x15287,
0x15297 — again consecutive near-identical functions. The caller masks the argument to one byte
before the call because the recovered parameter is one byte wide; the original passes the whole
register. `analysis::decompiler` already widens a recovered parameter to its exclusion entry's slot
width (`width.max(p.size)`) precisely for this — so either that lookup is failing for these, or the
narrowing is re-introduced after it.

**Over-recovery, plain (4).** `extra: XOR EDX,EDX` / `XOR EAX,EAX` / `XOR EBX,EBX` /
`MOV EDX,0xfffffffc` — a parameter materialized for a slot the original does not pass.

Both directions being present at once means the recovered prototype is right in kind and wrong in
extent, so the next step is per-slot evidence (which callee reads which storage, at what width),
not a global loosening or tightening.

## Compilable C

71 of 2,893 non-library functions emit C that does not compile, and several of the causes make
OTHER functions compile into the wrong arithmetic. Survey, design principles and phased plan:
[`compilable-c-remediation.md`](compilable-c-remediation.md).

## P3 — which equivalent C source

The source-form evidence base is [`byte-exact-source-forms.md`](byte-exact-source-forms.md): the
catalog of binary-evidence -> C-shape mappings measured against Watcom 10.0a, the one-second
single-function probe loop, the plateau analysis from hand-converging WAR2's largest honestly-
measured function (27 -> 177 of 536 instructions matching), and the design the evidence implies
for an automated P3 search. Working artifacts are preserved in `oracle/war2-convergence/`.

That session also produced a WRONG-CODE defect, filed separately:
[`decompiler-bug-guarded-store-hoisted.md`](decompiler-bug-guarded-store-hoisted.md) — a store
the subject performs only on the taken side of a test is emitted unconditionally, so the
recompiled program writes where the original does not. Two verified specimens; not yet compared
against Ghidra.

## FINDING — local declaration order steers Watcom's register allocator

Measured during the FUN_0006c6f0 hand-convergence (the single-function compile loop, ~1s per
probe). With the C otherwise byte-identical, permuting ONLY the order of the local variable
declarations changes the emitted registers:

| declaration order | exactly-matched instruction rows (of 536) |
| --- | --- |
| decompiler's natural order | 172 |
| same declarations, reversed | 173 |
| hill-climbed permutation (~200 probes) | 183 |

Watcom's allocator breaks ties using symbol order, so the declaration sequence is a live input
to code generation. printc currently emits locals in the decompiler's internal variable-numbering
order -- an artifact of SSA/merge processing that carries no information about the original
source -- which means every function's register assignment is conditioned on an arbitrary
choice.

This qualifies as an EmitChoices axis on all three rules: it is semantics-preserving, it is not
derivable from the IR (the original's declaration order left no trace except through the
allocation itself), and the compiler distinguishes it. Unlike the existing axes it is
high-dimensional (n! orders), so the arm mechanism cannot enumerate it -- but a cheap
deterministic heuristic (declare in FIRST-USE order, which is how humans write and how the
original sources were likely ordered) may capture most of the value, with per-function search as
the refinement. Sizing it corpus-wide: emit with first-use-ordered declarations and diff the
EXACT count.

## How to size a fix before writing it

Every estimate in this document must come from one query: **how many functions would become
divergence-FREE if this cause were eliminated.** Not "how many functions show this symptom" — that
number is meaningless and it is always large.

The register-parameter widening below is the worked example of getting this wrong. Sized by a grep
over our own emitted signatures it looked like 313 functions. Sized correctly it was **9**, and it
delivered 1:

| question | answer |
| --- | --- |
| functions whose signature has a narrow register parameter, and are non-exact | 313 |
| functions with ANY width-shaped divergence (`AND EAX,K`, `CWDE`, `MOVZX`, `MOV DL,AL`) | 1581 |
| functions whose ONLY divergences are width-shaped | **9** |
| measured outcome | +1, −29 |

The 313 assumed the narrow parameter was WHY those functions were non-exact. It was not — they sit
at a median of 21 divergences. A symptom that appears in half the corpus as one row among twenty
converts nobody.

The calibration that shows the method works: `ret-n` marginal value said 13, the fix delivered 11.

The trap is that the marginal-value query needs a divergence CLASS to filter on, and some causes
have none — parameter width shows up as ordinary `missing`/`extra` rows. That is not a licence to
substitute a grep over our own output: build the instruction-shape filter instead. It is one query,
and it is the difference between a 35x over-estimate and a calibrated one.

## Measured and rejected — widening a register parameter to its slot

**Do not redo this.** Declaring a register parameter at the convention's slot width instead of the
width the body reads is net **−28** (432 → 404, gained 1, lost 29). It is recorded here because the
premise checks out and the conclusion still does not.

The premise: WAR2's `FUN_00015224` takes a value in EAX and hands it straight to another function.
Declared `xunknown1 param_1` it compiles with an `AND EAX,0xff` the original does not have. Asked
with the callee's parameter forced, Ghidra declares `undefined4 in_EAX` and passes it untouched —
four bytes, the whole register. So on that specimen the wide declaration is right, and it agrees
with the reference decompiler.

It does not generalise. The 29 functions it breaks diverge on `missing: AND EAX,K`,
`missing: CWDE`, `missing: MOV DL,AL` — their originals genuinely DO narrow the incoming register,
because their parameter really is a byte. Declaring it wide deletes the narrowing.

So the parameter width is the same value-versus-storage duality as the return width, and neither
rule wins everywhere. It is not worth making an emission axis either: the split is 29 to 1, so the
narrow width is simply the better default and the wide one buys a single function.

Note the asymmetry that misled this: Ghidra declares the RETURN at the value's width (`undefined1`)
and renders an unrecovered INPUT register at the storage width (`undefined4`). The second is not a
parameter declaration at all — it is an unnamed local standing for "whatever the caller left here",
which reads well and does not rebuild. Reading it as a claim about parameter width is the mistake.

## Open thread 2 — make the search generative

`recompile_search` selects among arms a human emitted; it proposes none. Every one of the 26
functions gained by per-function selection comes from the arm that is a net loss of 26 globally —
which is the whole argument for the choice vector, and for keeping a losing arm alive instead of
reverting it.

To become a search it needs:

1. the emitter callable **per function under an explicit choice vector**, rather than through
   process-wide environment variables and a whole-corpus emit;
2. more axes — temporary splitting vs merging, expression inlining vs an explicit temporary,
   declaration order, statement order among independent statements, loop form, cast placement,
   integer width and signedness where the IR does not pin them;
3. a policy table mapping an attributed divergence class to the axis worth perturbing **at that
   site**, so the search is directed rather than exhaustive.

## What not to undo

- **Relocations are resolved, never masked.** Masking passes a candidate that calls the wrong
  function. The permissive count (identical only outside relocation sites) is reported separately
  and is currently 0, which is a check on the symbol resolution rather than an assumption about it.
- **`postlink` is gone and should stay gone.** It rewrote `89 ec` out of the compiler's output so
  the bytes would match, making every verdict on a frame function a claim about the patch. It now
  modifies 0 of 2952 objects.
- **Both compile paths must keep agreeing.** The shell battery and the mosura driver scored
  168/2449/335/71 identically at the time they were cross-checked; a divergence means one of them
  is measuring something else.

## zc19–zc26 (2026-08-22) — the WGSS-first bar, the allocator thread, and the asymptote

**Bar change (JD):** judge by WGSS movement + zero verdict regressions, not EXACT flips —
multi-defect functions advance one defect at a time. `scripts/war2-verdicts.sh` now prints the
insn-weighted net and its WGSS effect beside the flips. Canonical record: `/data/be2/zc*-rec.tsv`.

**Landed (each measured alone, zero verdict regressions):**

| commit | what | round | effect |
| --- | --- | --- | --- |
| `f6a1275` | stack-append kernel enabled (refused the day before on EXACT-count grounds) | zc19 vs zc18 | 36b30 +0.115 sim |
| `d45c4ed` | deterministic per-callee pragma merge | zc23 vs zc19 | 0 flips; 3 movers −0.039 sim |
| `e039e8c` | global-aggregation arm, pure short-run gate | zc24 vs zc23 | FUN_00045aa4 → EXACT |
| `30eff96` | sum-order recovered choice (printc) | zc26 vs zc24 | +5 EXACT, +33.3 insn-sim |

**Baseline: zc26 = 764 EXACT / WGSS 0.4801** (from 758 / 0.4797).

**The determinism bug.** The TU's single `#pragma aux <callee>` was folded over `f.call_specs`
(a HashMap) last-writer-wins; two sites of one callee with different recovered specs made the
pragma a random draw per process (caller 0x3342c / callee 0x63be5: `modify exact [eax]` vs
`[eax ecx]`). This was the standing "N functions moved on byte-identical code" jitter between
rounds — the noise floor under every landing gate to date. Fixed by merging deterministically
(sorted op order; caller_cleans from any site; modify = union). Two probe runs are now
byte-identical; a full double-emit comparison is recorded below.

**The allocator thread — what the model turned out to be.** The Watcom allocator (OW
`regalloc.c`: savings-sorted conflicts, ShellSort with strict `>`, conflict list built by
PREPEND, `GiveBestReg` scoring by `CountRegMoves` with `DoubleRegs` table order and a
`GivenRegisters` reuse tie-break) is deterministic, so every regalloc defect is our C presenting
a different IR structure than the original source. Corpus divergence census (new
`recompile_check --divergences`, zc19: 77,793 rows): extra 16,662 / missing 13,832 /
**regalloc 13,582** / selection 12,251 / operand-form 8,788 / layout-shift 7,980 /
branch-target 2,599 / immediate 1,961 / encoding 138. The "model" materialized as
source-shape levers, each confirmed byte-for-byte with the real compiler (`dumpwc` probes):

- **sum-term order** — Ghidra's canonical term order ≠ the source's; Watcom evaluates terms as
  written. Evidence = each term's earliest inline-op address (IR). Landed (above). Its first cut
  (constants last, bare variables after computed terms) regressed FUN_00031100 (EXACT) and
  FUN_0005fb24 in zc25: only the PC-evidenced swap among computed terms is a recovery; every
  secondary ordering rule is a coin flip.
- **global aggregation** — adjacent shorts declared as one array allocate differently than as
  separate symbols (FUN_00045aa4, `short v[4]`). The full-fire A/B (zc20: any adjacent
  same-type run) was a tie-reshuffler — 403 TUs fired, 5 EXACT lost / 1 gained, winners ≈
  losers in every shape class — because access patterns cannot distinguish array-source from
  adjacent-scalars-source; only the assignment outcome can. Landed gate = the one class that
  measured strictly safe (short runs of ≥3 in pure TUs, 16 TUs). ~235 insn-sim of positive
  movement sits in coin-flip TUs, reachable only by per-TU measured selection.
- **statement interleave** (`172b1aa`, OFF) — census 462 fns / 1,088 inverted independent
  adjacent pairs; the blind lever broke 3 of 5 EXACT probes (a single global-read snapshot
  moved one statement later, to where the original's LOAD sits, turned FUN_00031c60 into
  SAME_SHAPE 0.679). The original's instruction order is the SCHEDULER's output, not the
  source's statement order, and the scheduler does not round-trip its own output.
- **arg-setup order** (parked, no code) — 31 transposed `MOV` pairs before calls. Neither
  `parm` order + permutation, nor nested/hoisted call forms, nor Watcom 10.6 moves the pair;
  the watsched model (faithful to `InsStallable`) predicts our order and 5 of 6 sites in
  FUN_0004b750 — the 6th is the original deviating from its own compiler's policy.
  Pile-B (compiler identity), with FUN_00073328's load pair and the model's 19344 holdout.

**The asymptote.** +0.0004 WGSS for the day, with three independent levers each ending at the
same wall: the residue is the original compiler's tie-breaking (scheduler priority, allocator
tie order), which no C shape reaches with 10.0a. The experiment that can move the number is at
the compiler level — `docs/watcom-dial-patch-experiment.md` (handed off). Open decompiler-side
items, priced: per-TU measured selection (arms revival; the coin-flip mass); the emitter
shared-return arm re-earning the ReturnSplit doctrine trade (3e038/4d0f8/6fd88, ~42
insn-sim); the model-inverse interleave (choose the statement order whose watsched simulation
reproduces the original); 3 const/const call sites refused only by the default-register-set
check. The "declare locals in first-use order" proposal above is already the printer's
behavior for register locals (stack locals follow Ghidra's storage order); what remains of that
finding is the per-function search, i.e. measured selection again.

### Review addendum (2026-08-22, later): a second determinism leak, and what the review found

A full double-emit (`diff -rq detX/recovered detY/recovered` over all 3023 TUs — the test the
probe-level check after `d45c4ed` should have been) found two TUs still varying between runs,
in the RAW print: a callee's call ARITY flipped (`func_0x0005dd14(param_1)` vs
`(param_1, param_2)`). The callee's own prototype was stable; the kernel gate was not — the
survey's `spec_view` folded `f.call_specs` per callee last-writer-wins, so `pragmas_equal`
and with it the network kernel's adopt/refuse (`adopted:passthrough` vs `refused:network`)
was a random draw for multi-site callees. Fixed with the same deterministic merge as the
pragma emission (pop count = max over sites, modify = union, exact = any). Consequence to
note honestly: the network-kernel landing (`405c526`, "+5 zero-loss") was measured under that
random gate; zc27 re-measures the deterministic version.

Other review findings: the status doc had not been updated since `d76c1de` (fixed above);
the smoke set pinned no sentinel for any of the day's landings (now 20 sentinels: 294b8/25f50
sum-order, 45aa4 aggregation, 3342c deterministic pragma merge, 36b30 stack-append kernel);
`war2-verdicts.sh` reported only the unweighted sim net while the bar is weighted (fixed,
`a970c90`); "declaration order inert" was over-generalized from one probe (the 6c6f0 finding
above stands — first-use order is already the printer's behavior, the per-function search is
measured selection); the sum-order lever's pointer-context gate covers 120 chains while 670
chains outside pointer context would reorder under the same evidence (unmeasured A/B
candidate, `MOSURA_SUMORD_CENSUS=1`).

### Dial-patch results (2026-08-22, separate agent) — corrections to the entries above

Full report: `docs/watcom-dial-patch-results.md` (worktree `/data/wt-dialpatch`, branch
`dial-patch`). What it changes in this document's preceding entries:

- **10.0a's 4-byte allocation order is `EAX, EDX, EBX, ECX, ESI, EDI, BP, SP`** — one table,
  which is also the parameter table; the OW 1.0 `DoubleRegs` order (`ECX` before `EBX`) quoted in
  the allocator-thread entry first appears in 11.0. Table-order dial: refuted on binary evidence
  across 8.5a–10.6.
- **Allocation tie-break dial refuted in the tested direction**: one byte (`JG`→`JGE`) turned
  764 → 432 EXACT with zero gains. 332 of our 764 EXACT functions ride on a tie whose direction
  happens to agree — the blast radius of any allocator lever.
- **Declaration order is live**, contradicting the "inert" note above: reordering only the local
  declarations converts 464b4, 5fb24 and 1798c to EXACT under stock 10.0a. Ceiling over every
  permutation: +3 EXACT (3/12 SAME_SHAPE∩regalloc; 0/60 MISMATCH on two samples) plus sim on the
  3320c family (0.50→0.73) and 47c6c (0.49→0.75). Build only as a model-inverse.
- **Scheduler operand weights refuted**; the movable arg-setup pairs flip on the final
  source-order key (`ins->id`, i.e. IR generation order — ours). The "pile-B member #11" added
  above is withdrawn. F2 does not co-move with the regalloc class: the unification is refuted.
- Net for the interim-build hypothesis: four of six legs closed against it on measurement; the
  compiler-level investigation is closed. The residue is on our side — IR generation order and
  declaration order — with small, sized prizes.

### Sum-order outside pointer context — measured at probe scale, parked (2026-08-22)

Census (`MOSURA_SUMORD_CENSUS=1`, zc26): 120 chains in pointer context (the landed gate) vs 670
outside it, in 203 functions (183 MISMATCH, 5 SAME_SHAPE, 4 EXACT). Pre-registered: all 4 EXACT
hold, 1–3 SAME_SHAPE convert, park on any EXACT regression. Probe of all nine EXACT/SAME_SHAPE
members under `MOSURA_SUMORD_CTX=all`: FUN_0004f130 EXACT → SAME_SHAPE 0.915, FUN_00018afc
SAME_SHAPE → MISMATCH, FUN_0004bdb0 0.846 → 0.769, FUN_0005f9b4 0.879 → 0.939, the rest unchanged.
Every diff is two load terms swapped by their original addresses. Reading: outside address
formation the scheduler places independent loads and ALU ops freely, so a term's byte position
is the scheduler's output, not the source's evaluation order — the same finding as the statement
interleave lever, one level down. The pointer-context gate is therefore a mechanism, not a
coincidence: address formation pins Watcom's tree-evaluation order; plain sums do not. Parked
without a corpus round; the switch stays, default pointer-only.

### zc28 (2026-08-22): the shared-return arm lands — 765 EXACT / WGSS 0.4802

Re-earns the ActionReturnSplit doctrine trade. The toggle (`MOSURA_RETSPLIT=0`) flips the six
trade members symmetrically, so the discriminator had to come from the renderings: the three
gains' unsplit forms carry gotos the split repairs; the two clean-unsplit losses are pure
deformation; 4d0f8 is the separate do-while structuring gap. The arm re-decompiles the same
world with the split suppressed and keeps the unsplit rendering iff it is fully structured.
Census: the split fires in 284 functions (8 EXACT, all held at probe scale). Corpus: 3e038 →
EXACT, 6fd88 → SAME_SHAPE, zero verdict regressions, weighted net +7.3 (5 movers up, 5 down —
the downs, 1ed58/280f0/397a8/397f8, are the rule's refinement target).

### zc29 (2026-08-22): the do-while condition port — WGSS 0.4802 → 0.4817

The 4d0f8 "structuring gap" was a printer defect: Ghidra's `emitBlockLs` under `only_branch`
emits only the body list's last sub-block — the `BlockCondition` — and `emitBlockCondition`
prints its second operand with statements (`(a) || (stmt, b)`); mosura read one CBRANCH off the
list's exit basic and dropped the operand, call and all. Found with the oracle recipe
(`capture --c`, `dumpc --raw`, `MOSURA_STRUCT=1`, `trace-diff.sh`) in that order: structure
correct, IR intact, trace identical → printer. One arm ported, fixture + strict regression test
committed. Corpus: 0 flips, 765 EXACT, weighted +181 insn-sim — the largest WGSS move since the
WGSS-first bar (the defect touched every do-while ending in a short-circuit condition).

### zc30 (2026-08-22): the WAR2 oracle sweep, `AncestorRealistic`, and the stack-slot guard — WGSS 0.4817 → 0.4821

**The sweep.** `examples/war2_oracle_sweep.rs` renders every user function's bytes as a standalone
fixture through both decompilers — Ghidra's C (`oracle/capture --c`, cached by `oraclecache`)
and mosura's pure pipeline — and scores them with `ccompare::similarity`: a Watcom-independent
"how far from Ghidra" signal per function, ranked by `scripts/war2-osweep-rank.py` and compared
run-to-run by `scripts/war2-osweep-cmp.py`. First run over 2715 scorable functions: mean 0.9273,
691 exact matches, 208 below 0.8. The do-while port (zc29) had shown the largest WGSS yield of the
campaign came from a Ghidra divergence on a WAR2 fixture; the sweep is that search made
systematic.

**Finding #1 → two faithful ports.** The lowest score (FUN_00066da8, 0.085) was a 61-line body
collapsed to three calls. The trial log named it: the buffer address passed to the call — a
dedicated `mov eax,esp` COPY — was judged no-use, because mosura's flattened `realistic_faithful`
recursed through the COPY into the ESP passthrough INDIRECT and applied the killed-by-call
rejection there. Ghidra's `AncestorRealistic::enterNode` pops `pop_solid` at a non-incidental,
different-address COPY (a minimal walk over the COPY chain that only rules out an
unaffected/non-direct-write input). Replaced with a port of the class itself: the explicit state
stack, `execute`/`enter_node`/`upon_pop`/`check_conditional_exe`, the solid-vs-failkill
MULTIEQUAL arbitration the old walk flattened with `any`, the SUBPIECE/PIECE offset arms, the
trial flags (`indcreate_formed`/`condexe_effect`/`ancestor_realistic`/`ancestor_solid` — the
last two were read by `mark_best_inactive` but never set), the stack-vs-register branch of
`checkInputTrialUse` (`allowFail`), and `finalInputCheck`. Second piece: `guard_calls` spelled a
non-aliased stack slot `unaffected`; Ghidra's `hasEffect` gives `unknown_effect` for every stack
address (passthrough INDIRECT, collapsed later under `nolocalalias`, which is set only at the
aliasyes restructure passes and never cleared). `mark_addrtied` now follows that.

**The faithful walk exposed a mosura-only defect.** The alias probe in `ActionHeritage` (a clone
simplified to find aliased slots) ran `resolve_call_args` without `ActionDirectWrite`;
`AncestorRealistic` fails any input the walk reaches that is not marked a direct write (Ghidra's
DirectWrite always precedes ActiveParam). On the clone a `mov eax,ebx` ← `mov ebx,eax_in`
argument chain was judged no-use, `fillin_map`'s dnu-chain rule dropped the struct-pointer
register behind it, the probe saw no escape, and every by-address stack struct lost its field
stores (59c6c/58694/30550 in the first re-sweep: 23 up, 9 down). The probe now runs the two
DirectWrite instances first. Re-sweep after the fix: **23 up, 0 down, weighted +134**
(66da8 0.085 → 0.936).

**Corpus zc30 vs zc29: 0 flips, 765 EXACT, WGSS 0.4817 → 0.4821 (weighted net +53.1; 15 up,
11 down).** Every down is a MISMATCH→MISMATCH similarity dip whose standalone render is
unchanged against Ghidra (3ffdc, 30e38, 1cfbc: identical sweep scores in both worlds) — i.e. a
recomposition inside the survey's prototype/stack kernel, not a faithfulness regression: 30e38's
dropped stack argument crosses ≥5 of the new passthrough INDIRECTs and exhausts
`ancestorOpUse`'s `trim_recurse_max = 5` exactly as Ghidra's walk does (Ghidra's own render of
that call is `func_0x00063bb0()`); 5886c's extra argument is Ghidra's `CONCAT22(extraout_var,
in_CS)` junk in mosura's spelling; 5ee20/643e0 lose the saved-EBP "argument" (`xStack_c`), which
Ghidra also rejects (`!isDirectWrite` on the EBP input). Smoke 21/21, lib tests 732/0, fixture +
strict test `tests/ancestor_copy_solid.rs`.

**Frontiers opened by the sweep (next):** (1) the stack branch of `checkInputTrialUse` still
lacks Ghidra's `hasLocalAlias` / local-range / `callee_pop` pre-tests — they are what kills the
caller-local-slot trials behind every by-address struct's junk field arguments
(59c6c/58694/30550/5ee20); (2) the return side still uses the flattened `is_realistic`;
(3) `Varnode::incidental_copy` (x86.pspec ST0–ST7) is not carried; (4) the sweep's remaining
classes: FUN_0006c6f0 (weighted 123.6), the if-condition comma-statement class (14 functions /
776 lost weight, e.g. FUN_0003c040), call-argument/prototype divergences (FUN_000686bc).

### zc31 (2026-08-22, NOT landed): the stack branch of `checkInputTrialUse` — and the spurious-restart defect it exposed

Ported Ghidra's three pre-tests for STACK trials (fspec.cc:5605-5622) ahead of the realism walk:
`AliasChecker::hasLocalAlias` (now a faithful `AliasChecker` struct in alias.rs, gathered once per
`ActionActiveParam` pass, unsigned boundary arithmetic), the model's local range, and `callee_pop`
(model extrapop unknown — `__watcall` — and the callee's recovered `RET n` above 4: trials inside
the popped bytes are active, the rest no-use, no realism walk). Standalone fixtures now match
Ghidra's argument lists exactly (59c6c `(param_1, &xStack_18)`, 58694, 30550, 66da8). Oracle
re-sweep vs osweep3: 60 up / 12 down, weighted +35.5 (downs: 5761c's `iVar3+1` was a hole-filled
passenger of the junk stack args and Ghidra kills `EBX` at that CALLIND where mosura's loop
counter survives — a separate call-guard divergence; 72e77 reaches Ghidra's argument count;
27298 is a type reshuffle). Corpus zc31 vs zc30: WGSS 0.4821 → 0.4826 (weighted +60.2; +189
up / −129 down) **but 5 verdict regressions**: 4 EXACT→MISMATCH (31c60/31dc4/31f74/32100, plus
the sibling family 32c48/323c0/32924 at −0.276) and 12e40 SAME_SHAPE→MISMATCH. Not landed at
that point (zero-regression bar); parked on branch `stack-pretests` until the restart defect below
was fixed — then landed as zc33 (see below).

**12e40** is legitimate: its only alias root is the real `lea` escape of `axStack_d4` into the
same call, and the old "`9`" argument was the buffer's first field — the exact junk the pre-test
kills (Ghidra kills it too); the old C compiled closer by accident.

**The 31c60 family is a composition defect outside the port**, traced end to end with the
survey probe (`MOSURA_ARG_DEBUG`, `MOSURA_OPACTION`, `MOSURA_RESTART_DEBUG`):
1. The pushed arguments at `call@0x31c7d` are killed by `hasLocalAlias` because the alias walk
   sees an escape root at the call-time ESP — the **flag ops of the caller's `add esp,8`
   cleanup** (`INT_CARRY/INT_SCARRY/INT_EQUAL@0x31c82`), dead code in Ghidra by pass 1.
2. They are alive because the emitted decompile is a **restarted** one in which the register
   space carries `deadcodedelay=1`, so every register varnode is pre-live at pass 1
   (`[deadcode-prelive] space=register heritage_pass=1 deadcodedelay=1`). Ghidra's standalone
   render of 31c60 has no "Heritage AFTER dead removal" warning — Ghidra does not restart here
   (5 of ~2000 Ghidra standalone renders do; mosura's standalone pipeline bumps 29, and the
   survey world restarted 10 of 10 decompiles in the 31c60 probe).
3. The bump fires on a **free `EDX` hole-filler read by `call@0x31cb0`** that is "new in an
   already-heritaged range" (`prev==2`): the call is committed more than once — after passes 1,
   3 and 4 — because mosura's *re-open repair* for the call-recovery ordering defect (open
   thread 1: `Funcdata` "Re-open a call's input recovery") re-runs `build_input_from_trials`
   once outputs land, and each commit manufactures a fresh `new_varnode` for the unreferenced
   `EDX` slot (EDX never appears in the function's own ops, so it is a hole every time). Ghidra
   commits once (`clearActiveInput`), so its one hole-filler is renamed by the next pass and
   never reads as new.

So the faithful port is right and the regression is the re-open repair's side effect, made
visible because `AliasChecker` now consults the live graph at ActiveParam time. Fixing it means
retiring/reshaping the re-open repair (thread 1) — or, narrower, not re-manufacturing a
hole-filler on re-commit — and is a JD decision. Until then the pre-tests stay unlanded.

### zc32 (2026-08-22): the spurious-restart defect fixed — a re-committed call reuses its hole-filler

JD's call on the zc31 finding: fix the old bug first. The cause was one line of composition:
mosura's re-open repair gives a call a second commit once outputs land, and the first commit's
manufactured hole-filler is itself free, so every call with an unreferenced parameter slot got
that second commit — whose unref branch manufactured a SECOND free varnode after the heritage
pass in between had renamed the first. `delete_unused_trials` already renumbers the used trials'
slots to the new input positions (Ghidra's `deleteUnusedTrials`), so the re-commit now reuses the
varnode sitting at the trial's slot when it carries the trial's address and size. Ghidra commits
exactly once; this makes the mosura-only second commit idempotent on holes. A compact env-gated
trigger print (`MOSURA_RESTART_DEBUG`) now names the read that re-heritages an old range.

Measured: standalone sweep bumps 29 → 0 with byte-identical scores (the standalone pipeline
never re-ran on a bump); the FUN_00031c60 probe's own decompiles no longer restart (the 4
remaining bumps are callee decompiles with a 1-byte `char` hole inside an already-heritaged
`EDX`, which Ghidra bumps on a first commit too); corpus zc32 vs zc30: 0 flips, WGSS 0.4821
unchanged (+2.5 weighted, one mover up); lib tests 732/0. Landed as d7bb5e9; the parked
`stack-pretests` branch merged on top as 0f38e00 and measured as zc33.

### zc33 (2026-08-22): the stack pre-tests land — WGSS 0.4821 → 0.4831

With the re-commit fix underneath, the faithful stack branch of `checkInputTrialUse`
(`hasLocalAlias` / local range / `callee_pop`, 0f38e00) measures zc33 vs zc32: **765 EXACT held,
WGSS 0.4821 → 0.4831 (weighted +125.6, the second-largest move of the campaign after the do-while
port), 41 up / 24 down, one flip: FUN_00012e40 SAME_SHAPE → MISMATCH (weight 11, similarity
unchanged 0.455)**. That flip is the filter doing its job: the corpus render passed
`(axStack_d4, param_2, param_3, param_4, 9)` where the `9` is the by-address buffer's own first
field and the rest are hole-filled passengers; the standalone render is `func_0x00057220(axStack_d4)`
on both sides (sweep score 1.0). JD's call: land it. The 31c60/32c48 families that blocked zc31 no
longer move. Lib tests 732/0 on the merged tree; the merged tree's standalone re-sweep reproduces
the port's 60 up / 12 down exactly, i.e. the restart fix is inert standalone.

Still open from the sweep: the return side still uses the flattened `is_realistic`; the 5761c
CALLIND class (mosura's loop counter survives a call Ghidra kills `EBX` at — `extraout_EBX`);
`Varnode::incidental_copy`; and the sweep's remaining classes (FUN_0006c6f0, the if-condition
comma-statement class, FUN_000686bc).
