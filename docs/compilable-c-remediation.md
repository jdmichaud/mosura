# Compilable C — survey and remediation plan

**Status: planned, not started.** The 64-bit strand is being worked separately (see the last
section); everything else here is recorded for later.

71 of WAR2's 2,893 non-library functions (2.5%) emit C that does not compile. This is the
complete population — mined from the cached compile logs, all 71 matched to their diagnostics,
not a sample.

The goal is not "make the 71 compile". Several of the causes below make *other* functions compile
into the wrong arithmetic, and at least one family cannot be expressed in C at all. Getting the
count to zero by adding definitions would hide more than it fixes.

## Verified findings

| cause | scale | what it actually is |
| --- | --- | --- |
| prelude helper vocabulary is a fixed list | **45 distinct** `CONCAT`/`SUB` variants referenced vs ~20 defined | an open-ended emitter met by an enumerated header |
| Ghidra subfield syntax `x._4_1_` | 33 TUs, 32 fail; **130 of 146 uses are stack locals** | not C; Ghidra's name for an *unnamed field* of an aggregate |
| `typedef double int8/uint8/xunknown8` | ~9 fail, unknown number silently miscompile | integer arithmetic rendered as floating point |
| invented widths | `uint16` ×22, up to **20 bytes** | no 386 register or operation holds these |
| `INT_CARRY(...)` with elided arguments | 7 | the raw *opcode name* leaking; the C form (`CARRY4`) already exists |
| `spacebase *`, `switch (switchD)` | 4 | internal names escaping into C; `switchD` gates the two largest functions |
| `break` outside a breakable statement | 4 | structurer defect |
| pointer + pointer arithmetic, type mismatches | ~5 | type-recovery defects |
| `#define POPCOUNT(x) (0)` | every user | **always wrong, never fails** |

Related and already filed:
[`decompiler-bug-guarded-store-hoisted.md`](decompiler-bug-guarded-store-hoisted.md) — a store the
subject performs only on the taken branch is emitted unconditionally. Wrong code, two verified
specimens.

## Design principles (agreed before the plan)

These came out of working the 64-bit case and they govern the rest.

**Facts versus choices.** Instruction semantics, register widths and endianness are facts — they
*are* the target, and analysis must stay faithful to them. Type assignment, variable merging and
rendering are choices, and may legitimately be target-informed. The 64-bit width of `EDX:EAX` is
a fact; `typedef double int8` is a choice, and a wrong one.

**The target licenses representation, never value.** "Watcom 10.0a has no 64-bit integer type"
answers *what may I write*, not *what does this program compute*. It can never license narrowing:
if a program genuinely computes 64-bit, narrowing on the strength of the target produces a
different program, and it does so exactly where the analysis understood least.

**Narrowing beats lowering.** Where dataflow can prove a wide value unnecessary, the emitted C
compiles to the original's own instructions. Legalizing a genuine wide operation into 32-bit
pieces is correct but reproduces nothing. So prove it away first; legalize only the residue.

**No mode flag through analysis.** A switch that changes analysis behaviour forks the IR away
from Ghidra, and Ghidra is the oracle — the rule-trace diff, the parity gates and the fixtures all
assume one comparable IR. Divergence belongs at a late, identified stage where it stays a bounded
delta.

**Cannot legalize is a first-class outcome.** Better to route a function off-band than to emit
something that compiles into different behaviour.

## Open design questions — settle these before implementing

Recorded because each one is a place where the obvious fix is a workaround.

**1. Generating the prelude is not obviously right.** "Emit whatever helpers a TU references" makes
a 20-byte `CONCAT1010` *compile*, which is worse than failing — it converts a visible defect into
an invisible one. The inverted design is to generate helpers only for widths the target can hold
and treat anything wider as a defect signal, turning the generator into a detector. `CONCAT22`
(a 4-byte result) is legitimate; `CONCAT1010` is not.

**2. The subfields may be a type-recovery problem, not a splitting problem.** `x._4_1_` is Ghidra
saying it could not *name* the field. With 130 of 146 uses on stack locals, the original probably
had a struct on the stack — in which case the right C is a struct with named fields, not N
scalars. This matters for reproduction: a struct local and several scalars allocate differently.
Ask the oracle whether Ghidra splits these before choosing a frame.

**3. Functions that can never be byte-exact are in the denominator.** 87 TUs use `swi`/`in`/
`cpuid`; **zero** are byte-exact, and the prelude itself concedes these declarations make the C
compile but do not make `int 3` reproducible. Same class of measurement error as counting library
functions, which was already corrected once. Decide: track separately, or keep with a documented
unreachable floor.

**4. There is no contract for "compilable C".** The prelude is sediment — its own comments record
that one missing declaration accounted for 74 of 156 failures at the time. Each entry is a patch
for something the renderer emitted that is not C. If the contract existed — *a renderer may only
emit constructs it can define, over types the target can hold* — most of these families would stop
being fixable-in-the-prelude by construction, and the header would shrink to genuine runtime
support. That contract is the actual deliverable; the phases below are its consequences.

## Phases

**Phase 1 — stop being silently wrong. DONE (2026-08-17).** `typedef double int8` (and every
impossible-width integer typedef: `uint8`/`xunknown8`/`xunknown6`/`xunknown7`/`undefined6-8`),
`CONCAT44`, and `POPCOUNT → 0` now alias/`sizeof` an incomplete
`struct mosura_no_such_integer_width_on_this_target` — every declaration, cast, or use is a
compile error naming the problem. Measured exactly as predicted: **EXACT 590 unchanged, zero
transitions; 23 MISMATCH → COMPILE_FAIL (68 → 91)** — twenty-three functions that compiled
into wrong x87 arithmetic now fail honestly. The legitimate float types (`float8`/`float10`)
are untouched; the wrong-WIDTH integer stand-ins (`uint5/6/10` as `unsigned int`) are Phase 2's
contract to retire.

Design intent, to keep straight: the incomplete struct is a TRIPWIRE, not the product. The
invariant (an unrepresentable width must never compile silently) is permanent; the mechanism is
temporary — the end state is the open-question-4 contract, where the EMITTER refuses or
off-bands out-of-contract constructs with its own diagnostic at emit time, nothing ever reaches
the tripwire, and a Watcom error mentioning that struct always means "a defect Phase 2+ has not
fixed yet".

**Phase 2 — prelude generation, in its inverted form** (see open question 1). Generate for
target-representable widths; make anything wider a reported defect rather than a definition.
**Detector half DONE (2026-08-17):** `war2_survey` now classifies every rendered TU against
the representability contract at emit time (`contract_violations`) — `CONCAT<h><l>` is out
when h+l > 4, `SUB`/`ZEXT`/`SEXT` when the SOURCE width exceeds 4 (the result may fit but the
operand cannot exist), the impossible-width typedefs and `POPCOUNT` always — and reports in
its own channel: a `contract` manifest column (`ok` / `wide:<constructs>`) plus an emit-time
summary. Measured: **86 of 3,022 TUs, 50 distinct constructs, widths 5-29 bytes** — top:
`CONCAT24` x38 TUs, `CONCAT44` x31, `xunknown8` x31, `xunknown6` x19. The 10-byte family
(`int10`, `CONCAT210`, `CONCAT810`) is the x87 80-bit spill width; the rest is the mechanism-A
stack-PIECE family. Emissions byte-identical (detector is read-only). The generation half —
the prelude's in-contract vocabulary emitted from use rather than enumerated — is cosmetic
now that Phase 1's tripwire backstops the out-of-contract names with a better error than
"undeclared identifier"; the load-bearing part was mosura reporting its own defects.

**Phase 3 — the 64-bit narrowing. PARTIALLY LANDED, remainder rescoped.** The extension-idiom
divides narrowed as a free consequence of restoring `ActionDeadCode` to its :5503 slot (the
imul flag web died pre-pool, `RuleSubCommute`'s chain fired — `FUN_0002a4f0` now emits the
32-bit divide; the planned bespoke narrowing rule was never needed). Still wide: the
constant-dividend divides (`16000000 / (int8)x`, `FUN_0006c6f0`/`FUN_0006cfd0`) — Ghidra's own
`SubCommute` guard declines them (input 0 must be written by an extension) and emits `longlong`
too, so that residue is representation work under the Phase-2 contract (legalize to 32-bit
pieces or off-band), not a schedule or rule gap. Mechanism A remains Phase 4.

**Phase 4 — the stack aggregates.** Largest population. Gated on open question 2 — establish
whether this is type recovery or variable splitting *before* implementing.

**Phase 5 — internal names escaping into C.** `INT_CARRY`, `spacebase`, `switchD` are one family,
not three gaps: the renderer emitting identifiers it never declared. Fix as one, ideally by making
that impossible rather than by handling each name.

**Phase 6 — the genuine defects.** The guarded-store hoist is **FIXED** (classified MIS-PORT
and repaired — printc's `comma_separate` contract; the post-store re-read fixed with it via the
`ActionMarkImplied` port; see `decompiler-bug-guarded-store-hoisted.md`, both defects closed).
Remaining: `break` outside a breakable statement; pointer + pointer arithmetic. Each wants its
own bug doc and an oracle classification first.

**Cross-cutting — the off-band path.** Needed by Phase 1 and open question 3.

Suggested order: 1 → 3 → 2 → 4 → 5 → 6, correctness before compile count.

## CORRECTION — most of the "64-bit problem" is not 64-bit arithmetic

Traced in the IR (`dumpwar2 --raw`) rather than inferred from rendered C, which had misled the
diagnosis twice. Wide (>= 8 byte) varnodes are created by exactly **two** mechanisms:

**A. `PIECE` + `INT_RIGHT` — an overlapping/misaligned stack access.** Three of four specimens,
always the same shape:

```
s0xfffffff0:8 = PIECE r0x4:4  s0xfffffff0:4      <- built to service a straddling read
u0x10039:8    = INT_RIGHT s0xfffffff0:8 #0x10
s0xfffffff2:4 = SUBPIECE u0x10039:8 #0x0
```

`FUN_00042200` is the worked case. The subject stores 4 bytes at `ebp-4` and then loads 4 bytes
at `ebp-6` — overlapping the store by two bytes — and shifts right 16 to pull out the low word.
Ghidra refines the stack region and emits `uStack_c = (short)param_1; ... (int)uStack_c`. mosura
builds an 8-byte value spanning both accesses and extracts from it.

This is **not** a rule gap. `RuleConcatShift` (`concat(V,W) >> c => zext(V)`) is ported, wired at
pool slot 34 and unit-tested, and it correctly DECLINES here: the shift is 16, less than the low
part's 32 bits, so it straddles and no extension identity applies. The divergence is upstream, in
how heritage refines a memory range under overlapping accesses of different offsets and sizes.

**It is therefore the same root cause as the subfield family** (open question 2), not a separate
problem — which consolidates two of the families in this document into one piece of work.

Also disproved along the way: **no multiply produces a wide varnode.** `FUN_00042200`'s
`INT_MULT` is `r0x4:4 = INT_MULT r0x4:4 r0xc:4`, fully 32-bit. The "25 functions with mul/imul"
correlation was a red herring — those functions contain multiplies AND wide values, unrelated.
The dead-high-half narrowing proposed earlier would have fixed nothing.

## Mechanism A scoped — it is a porting project, not a wiring fix

Measured, so the next session does not repeat it.

**The producer is `normalize_write_size`, not refinement.** Instrumenting every `PIECE` creation
site in `heritage.rs` (`MOSURA_PIECE_SRC=1`) on `FUN_00042200` shows the specimen's wide value
built by the guard/normalize path:

```
[piece] normalize_write_size#1 @0x42209 inputs=[("stack", -12, 4), ("stack", -16, 4)]
```

Normalize widens a narrow write to the full merged range by concatenating it with the
pre-existing bytes. That is correct behaviour *for an unrefined range* — and the range is
unrefined because mosura's refinement is scoped to SIMD.

**Ghidra's ordering is what we lack.** `placeMultiequals` (heritage.cc:2610) refines EVERY
heritaged range whose `size > 4 && max_write < size`, with no space restriction, and it does so
**before** the normalize at :2629. mosura ports the family faithfully in `refine_overlaps` but
restricts it two ways — collection to the register space, and within that to laned/SIMD offsets —
and has a second partial path (`refine_ranges`) that fires only on a space's re-entry passes.

**Widening the scope is NOT sufficient — measured.** Parameterising `refine_overlaps` by space and
running it over the stack with the laned restriction lifted changed **nothing**: same `PIECE` from
`normalize_write_size`, byte-identical C. The range is not intercepted at the point where it is
normalized, so the fix is about *where refinement runs in the sequence*, not which spaces it
covers. Reverted.

This confirms the code's own note (`heritage.rs`, "THE REFINEMENT CARVE-OUT IS NOT WIRED HERE
YET"): the general case is a held piece of work with a measured payoff (`stackreturn` to 1.000,
`deindirect2` restored), and landing it means wiring refinement into the `placeMultiequals`
equivalent ahead of normalize on the shared merged ranges — not extending an existing call.

Cost: substantial, touching heritage sequencing, with corpus-wide blast radius. Value: also
substantial — it is the majority of the wide-value population, the subfield family, and the
general quality of stack-variable recovery, which the `FUN_0006c6f0` convergence showed is
pervasive.

## CORRECTION 2 — the divide non-narrowing traced to its root: late dead-code removal

Established by running Ghidra's own OPACTION_DEBUG trace on the WAR2 function and mosura's
trace beside it — not by reading source. Three claims made from source-reading died on the
traces in one session: "Ghidra emits `longlong` for these too" (it narrows the unsigned case),
"`subvar_subpiece` is what narrows this divide" (it is `subcommute`), and a first-draft "800x
churn" figure (a scope confound — see the measurement note below).

**New capability: `oracle/ghidra_scripts/DumpDecompDebug.java`.** `scripts/trace-diff.sh` can
only trace Ghidra's shipped datatest fixtures, so questions about WAR2 functions used to be
answered by inference from `ruleaction.cc`. The script dumps Ghidra's decompiler debug
savefile for any WAR2 VA, which `oracle/capture_trace <sleighdir> <xml> --trace` replays under
OPACTION_DEBUG so Ghidra names its own mechanisms:

```sh
GHIDRA_POSTSCRIPT=DumpDecompDebug.java GHIDRA_POSTSCRIPT_ARGS=<outdir> \
  WAR2_MANIFEST=<manifest.tsv> GHIDRA_DIST=<dist> scripts/ghidra-decompile-war2.sh 0002a4f0
./oracle/capture_trace <ghidra-src-or-dist-root> <outdir>/0002a4f0.xml --trace
```

(`enableDebug` requires `setOptions` explicitly or the savefile writer NPEs on a null options
block; the non-debug path never encodes options, which is why `DecompileFunctions.java` gets
away without it.)

**Measurement note — scope the trace before comparing.** `MOSURA_TRACE=1` on `dumpwar2`
captures every decompile in `analyze_le_file` (4,718 distinct instruction addresses), not just
the requested function; the target's own decompile is only the final contiguous block of the
trace. A first-draft comparison missed this and reported the whole-analysis count (462,152)
against Ghidra's single function (~585) as "800x churn". Scoped correctly, `FUN_0002a4f0`'s
decompile is **1,525 successful applications vs Ghidra's ~585 — 2.6x** (earlyremoval 723 vs
199, propagatecopy 333 vs 141). Same counting surface both sides (`debug_mod_print` returns
early on an empty modify list, exactly like `debugModPrint`).

**The verified causal chain on `FUN_0002a4f0`** (lifts byte-identical, checked):

1. Ghidra runs its **`deadcode` action immediately after heritage** (trace: `heritage ->
   returnrecovery -> deadcode -> first rule`), which removes the imul's dead flag web (the
   `CF = INT_NOTEQUAL(SEXT48(lo), product)` overflow computation and its consumers) before
   any rule fires. mosura's early `consume` action leaves that web alive; it decays ~800
   blocks later through rule collapse plus `earlyremoval`.
2. With the flag compare alive, the 8-byte product is **not lone-descended**, so mosura's
   `subcommute` — a faithful port; Ghidra's own guard is
   `if (base->loneDescend() != op) return 0;` — **correctly declines** at the imul's
   `SUB84`. In Ghidra it fires (DEBUG 159): `SUB84(SEXT48(x) * #0x9c4, 0) -> x * #0x9c4`,
   and the multiply is 4-byte before the divide is ever considered.
3. Because the multiply stays wide in mosura, its low half stays SUBPIECE-defined, so at the
   divide's `ZEXT` the rule `subzext` matches (in Ghidra the pattern no longer exists) and
   rewrites `ZEXT -> INT_AND`, off the path `shiftpiece`/`piece2sext` need.
4. Meanwhile `doublesub` merges the divide's `SUB84 -> SUB42` chain into a direct **2-byte**
   SUBPIECE of the 8-byte quotient. In Ghidra, `subcommute` dissolved the `SUB84` first
   (DEBUG 168: `SUB84(A / B, 0) -> SUB84(A,0) / SUB84(B,0)`, its INT_SDIV arm requiring
   sign-extended inputs — the soundness precondition), so `doublesub` never fires there.
5. When `subvar_subpiece` finally narrows the product (~860 blocks later) and
   `shiftpiece`/`piece2sext` rebuild `SEXT48(x)`, the divide's only SUBPIECE retains 2 bytes
   — too narrow for `subcommute`'s arm to ever fire soundly. The divide stays 8-byte; the C
   gets `int8`.
6. The do/undo round trips (`subzext` then `subvar_subpiece` undoing it; the doublesub'd
   chain) are a visible slice of the 2.6x churn — same root.

**RESOLVED — the fix landed and the chain held.** `ActionDeadCode` was restored to Ghidra's
`:5503` mainloop slot (one action composing consume + sweep, exactly two pipeline instances at
Ghidra's two slots; the invented `ActionConsume` member and the two misplaced sweep instances
removed; the priming prefix gained `ParamDouble` + `DirectWrite x2`). Measured results:
`FUN_0002a4f0`'s divide narrows to Ghidra's 32-bit form; per-function churn 1,525 -> 654
applications (Ghidra ~585); corpus **EXACT 566 -> 571 with zero losses**, COMPILE_FAIL 71 -> 69.
The constant-dividend divides (`FUN_0006c6f0`/`FUN_0006cfd0`) stay wide on both sides, as
Ghidra's own guard dictates — that residue is real 64-bit rendering work, not a schedule bug.

**The build item was therefore dead-code timing/behavior parity, not a divide rule.** Every
rule involved is already faithfully ported and every guard behaved correctly; what differs is
that Ghidra removes dead ops (flag webs above all) in an ActionDeadCode pass right after
heritage, and mosura does not. Remaining investigation, bounded and specimen-driven: establish
whether mosura's counterpart is mis-positioned in the schedule or mis-behaving on this web
(the op to step is the `INT_NOTEQUAL` CF compare at `0x2a5f5`), against
`coreaction.cc` ActionDeadCode and the consume-bit machinery it relies on.

**Scope note on which divides Ghidra can narrow at all:** `RuleSubCommute`'s DIV/SDIV arms
require input 0 to be *written* by an extension. `FUN_0006c6f0`/`FUN_0006cfd0` divide a wide
**constant** by `SEXT48(x)` (`#0xf42400 / SEXT48(x)`), so the guard declines and Ghidra
itself emits `longlong` there — consistent with the hand-convergence notes. Dead-code parity
recovers the `FUN_0002a4f0` class (extension-fed dividend), not the constant-dividend class.

## The genuinely-64-bit strand

**B. `INT_SEXT` + `INT_SDIV` — the division extension idiom.** The only mechanism that is really
about wide arithmetic:

```
u0x76d00:8 = INT_SEXT r0xa86a8:4
u0x77400:8 = INT_SDIV #0xf42400:8 u0x76d00:8
```

Ten functions, all extension idioms (6 sign-extend, 3 zero-extend, 1 `cwtd` at 16-bit). Ghidra emits `longlong` only for the SIGNED ones (`subflow.cc` has INT_DIV/INT_REM arms and
NO INT_SDIV/INT_SREM arm, so Ghidra structurally cannot narrow a signed divide); it DOES narrow
the unsigned case, which mosura does not — see CORRECTION 2, and it is licensed by a checkable precondition: a dividend that is the extension
of a narrower value, divided by a value of that width, is a division at that width.

This is the tractable, well-scoped part of the original 64-bit plan, and it stands.

## Original 64-bit notes (superseded in part by the correction above)

Settled by measurement on WAR2:

* **No function computes in 64 bits.** Zero high-half reads across all 25 multiplies; all 10
  divides are extension idioms (6 sign-extend, 3 zero-extend, 1 `cwtd` at 16-bit width).
* **Ghidra emits `longlong` for the same code**, so this is not a mis-port — it is a deliberate
  improvement over Ghidra, whose output is meant to be read rather than compiled.
* The two cases need *different* techniques, and conflating them was an error in the first draft
  of this plan: a multiply's high half is genuinely **dead** (liveness), while a divide's high half
  is **consumed by the divide itself** and is instead a recognisable **extension idiom** (pattern).
* `typedef double int8` is ours, not Ghidra's, and is a defect independent of any of this.
