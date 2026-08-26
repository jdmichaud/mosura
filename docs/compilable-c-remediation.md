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
**DONE in full (2026-08-17) — detector + contract-closure. Detector half:** `war2_survey` now classifies every rendered TU against
the representability contract at emit time (`contract_violations`) — `CONCAT<h><l>` is out
when h+l > 4, `SUB`/`ZEXT`/`SEXT` when the SOURCE width exceeds 4 (the result may fit but the
operand cannot exist), the impossible-width typedefs and `POPCOUNT` always — and reports in
its own channel: a `contract` manifest column (`ok` / `wide:<constructs>`) plus an emit-time
summary. Measured: **86 of 3,022 TUs, 50 distinct constructs, widths 5-29 bytes** — top:
`CONCAT24` x38 TUs, `CONCAT44` x31, `xunknown8` x31, `xunknown6` x19. The 10-byte family
(`int10`, `CONCAT210`, `CONCAT810`) is the x87 80-bit spill width; the rest is the mechanism-A
stack-PIECE family. Emissions byte-identical (detector is read-only). **Generation half:** the header is now a
CONTRACT WITH A MACHINE-CHECKED CLOSURE rather than an enumeration — `build_prelude()` asserts
at every emit that the complete in-contract grammar (every `SUB`/`ZEXT`/`SEXT` over sources
<= 4, every `CONCAT` with h+l <= 4, carry/borrow/scarry over 1/2/4) is defined and that no
in-contract name aliases the tripwire. The missing legitimate variants were added mechanically
(`SUB31/32/43`, sub-identities, `ZEXT13/23/33/34`, `SEXT13/23/34`, `CARRY2`, the `SCARRY`
family — 3-byte operands masked or shift-sign-extended in their 4-byte container); the proven
macro text is byte-identical, and the six legitimate CONCATs turned out to already be the
complete in-contract set. Deliberately NOT generated-from-use: that design would define
`CONCAT1010` and convert a visible defect into an invisible one (the inversion this question
was about). The wrong-WIDTH stand-ins (`uint5/6/10`, `int5/6/10`, `xunknown5`, `undefined5` as
`unsigned int` lies) are retired to the tripwire — measured: EXACT 590 unchanged, zero
transitions, **12 more MISMATCH → COMPILE_FAIL (91 → 103)**, the honest total for a corpus
where 103 functions now fail loudly instead of any compiling wrong. The
one-missing-declaration-equals-74-failures class is structurally impossible now.

**Phase 3 — the 64-bit narrowing. PARTIALLY LANDED, remainder rescoped.** The extension-idiom
divides narrowed as a free consequence of restoring `ActionDeadCode` to its :5503 slot (the
imul flag web died pre-pool, `RuleSubCommute`'s chain fired — `FUN_0002a4f0` now emits the
32-bit divide; the planned bespoke narrowing rule was never needed). Still wide: the
constant-dividend divides (`16000000 / (int8)x`, `FUN_0006c6f0`/`FUN_0006cfd0`) — Ghidra's own
`SubCommute` guard declines them (input 0 must be written by an extension) and emits `longlong`
too, so that residue is representation work under the Phase-2 contract (legalize to 32-bit
pieces or off-band), not a schedule or rule gap. Mechanism A remains Phase 4.

**Phase 4 — the stack aggregates. CORE LANDED (2026-08-17).** The heritage refinement is
wired at Ghidra's real slot — the `placeMultiequals` carve-out (heritage.cc:2610-2616),
general over all spaces: `buildRefinement`/`splitByRefinement`/`splitPieces`/`refineRead`/
`refineWrite`/`refineInput` plus `refinement`'s task-list surgery (the range replaced by its
partition pieces in both the local list and `globaldisjoint`, mid-iteration, re-collecting on
the first piece). The hold that kept this out — split inputs needing `fillinMap` re-joining and
the call-output reassembly — was STALE: both consumers had landed since (recover.rs
`fillin_map`; ActionActiveReturn's `findPreexistingWhole` 2-trial fix). Open question 2 is
thereby answered: it was variable splitting (heritage), and the subfield family fell with it.

Measured: **COMPILE_FAIL 93 → 22** (71 functions compile again — the wide-type tripwire AND
the E1032 subfield family, one root as predicted); the contract-flagged work list **86 → 14**,
every survivor named and attributed (2 constant-dividend divides, 2 unrecovered switch
indices, 3 POPCOUNT, 3 spacebase, 5 genuine wide residues incl. two libc functions); EXACT 590
held with zero transitions; `stackreturn` 0.868 → **1.000** (the held port's predicted number);
fixture corpus 0.9569 → 0.9586; `FUN_00042200` (the worked mechanism-A specimen) emits plain C
with no PIECE/INT_RIGHT.

**Phase 4 addendum — the 8 E1032 stragglers. CLOSED (2026-08-17), one mechanism, zero emitter
work.** The 8 unattributed COMPILE_FAILs surviving Phase 4 were all `E1032` on 3-byte
partial-symbol accessors (`x._1_3_`/`x._0_3_`) — the one width `compilable_partial_symbols`
deliberately cannot deref-legalize (no `uint3` in C). Instrumented against the oracle on the
same bytes and cspec (fixtures under scratchpad, plus a new `CAPTURE_FLAGS_AT=<hexaddr>`
varnode-flags dump mode in `oracle/capture`): Ghidra's IR carries the SAME addrtied 3-byte
SUBPIECE piece (`ram:0x8196d:3 addrtied=1`) but marks it `implied` and prints it inline —
`CONCAT31((unkint3)uVar4,1)` — with the superseded byte-stores dead-eliminated. Three faithful
fixes, no `printCompilableC` needed:
1. `ActionMarkExplicit::baseExplicit`'s two lone-descendant ESCAPES for addrtied varnodes
   (coreaction.cc:3029-3047: lone `INT_ZEXT` into a containing whole; lone `PIECE` when not the
   CONCAT-tree root, `PieceNode::findRoot` op.cc:824) were unported — `explicit_leading`
   returned explicit unconditionally, materializing the `._N_M_` statement.
2. The deadcode blanket "every written ram varnode is live" root was a non-Ghidra adaptation —
   Ghidra's global live-out is the persist guard structure (returnCopy + call INDIRECTs), so
   superseded intermediate byte-stores die; the blanket kept them, and their covers forced the
   pieces explicit (the implied-cover conflict).
3. printc's `high_ram_off` explicit arm ignored the `numInstances() > 1` half of the rule it
   cites — a SINGLETON high at a ram offset must fall through to the escapes.

Measured (sb35): **COMPILE_FAIL 22 → 14** (all 8 compile; partial accessors corpus-wide 8 files
→ 0), fixture corpus 0.9620 → **0.9679** (`revisit` 0.767 → 1.000 — its `iRam.._2_2_` defect was
this exact family; `condmulti` 0.845 → 0.968; none down). EXACT 590 → 585: the adaptation's
ordering had been byte-exact-friendlier than Ghidra's real pipeline for 6 functions whose
persist-store INDIRECT input copy-propagates (Ghidra's marker guards permit it; its C prints the
same swapped order — oracle-verified on FUN_000165f4) — the persist-store ordering byte-exact
story is a named emitter-side follow-up. The remaining COMPILE_FAIL (13 as of sb41) = the 11 contract-flagged
non-library functions + the singletons, dispositioned (2026-08-17):
- E1011 (`xStack_4` undeclared, FUN_0007b900) — FIXED: `render_spacebase_ptrsub`'s unmapped-slot
  arm named the slot symbol-style but never declared it; it now declares like the mapped arms
  (also retiring a bogus top-level `int xStack00000000;` global the survey's fallback scan had
  synthesized for FUN_00072bf5's frame slot).
- E1010 (ptr/int compare, FUN_000636f0) — RESOLVED as a knock-on of the E1082 fix below: with
  the call-mechanism stack modeling corrected, the function's pointer typing unified and the
  compare prints `uVar5 < (uint4)(param_1 + 0x1c)`. (The faithful-rendering analysis stands:
  `CastStrategyC::castStandard` with `care_ptr_uint=false` skips casting a pointer under a uint
  requirement, so a genuinely mixed compare would still print uncast, exactly as Ghidra's does.)
- E1082 (label-before-`}`, FUN_0003495c) — FIXED (2026-08-17), three composed defects in the
  call-mechanism stack model:
  1. `ActionExtraPopSetup` ran BEFORE `stackvars::recover_stack`, so the unknown-extrapop
     INDIRECT (an ESP write `symbolic_value` cannot evaluate) knocked ESP out of the sval walk at
     the FIRST call of each path — every later call's return-address store stayed a raw STORE for
     the late rules to place. Reordered: the walk now sees the pristine lift and all calls
     convert at their sval-exact (dead, unaliased) slots.
  2. The unknown-extrapop solver's `+4` guess double-counted the ret-pop on calls whose push
     `recover_stack` had already neutralized to an identity COPY (Ghidra keeps the push, so its
     `+4` restores it; mosura's pre-model had already restored it) — every post-call solution ran
     `+4` high, landing return addresses inside the (CORRECTLY) aliased locals as
     `aiStack_18[0] = 0x34a6d;` and shattering the structure into gotos. New
     `CallSpec::push_neutralized` records the cancelled amount; the solver guess and
     `ActionExtraPopSetup`'s known branch both subtract it.
  3. The "over-recovered stack-address arguments" theory was WRONG: the callees genuinely take
     two pointer args (`FUN_00034918(xunknown2*, xunknown2*)` — oracle-verified under borland
     fastcall, which recovers the same `&xStack_18, &xStack_1c`), and the aliasing they cause is
     correct. Only the composition above was broken.
  Measured (sb42): COMPILE_FAIL 13 → **11** — every remaining failure is contract-attributed —
  EXACT 586 held across 289 changed emissions, +1 MISMATCH → SAME_SHAPE.

Tracked follow-ups: `mixfloatint` −0.025 — CLOSED (2026-08-17): the
fixture declares `x86:LE:64:default:windows` and the datatest paths were pinning the gcc cspec
(fixed by threading each fixture's own arch, `raw_funcdata_flow_image_arch`), and the RETURN kept
only the low XMM0 lane (fixed by porting `buildReturnOutput`'s multi-piece PIECE reassembly,
coreaction.cc:1850-1904) — mixfloatint 0.857 → 1.000, byte-identical to the oracle. Remaining: 3
SAME_SHAPE → MISMATCH shape shifts.

**Phase 5 — internal names escaping into C. DONE (2026-08-17), one family as planned.**
`INT_CARRY(...)` (with elided arguments!) was the printc catch-all fallback — a port GAP, since
Ghidra's token table is total: `TypeOpIntCarry`/`TypeOpIntScarry` are `TypeOpFunc`s rendering
`CARRY<n>(a,b)`/`SCARRY<n>(a,b)` exactly like the SBORROW arm mosura already had. Both arms
ported; with the Phase-2 closed prelude defining the whole carry family, the seven affected
functions went **COMPILE_FAIL → MISMATCH (103 → 96)** — arguments restored, honestly comparing
again. The remaining two names are mosura RECOVERY gaps with no Ghidra counterpart path, made
impossible to hide rather than patched: the fallback now emits `MOSURA_UNRENDERED_<OP>(...)`,
the failed switch index `MOSURA_SWITCH_INDEX_UNRECOVERED`, and the contract detector flags any
`MOSURA_*` identifier and the `spacebase` type name — every renderer escape is a per-function
manifest defect now. `spacebase * pVar` was oracle-classified before touching: Ghidra's own C
for the specimen (`FUN_00060270`, ESP saved to globals) is equally non-compiling
(`register0x00000010`), so there is no compilable-C question — the mosura/Ghidra delta is
upstream type assignment (the locked `Pointer(Spacebase)` reaching a declared local where
Ghidra carries `undefined1 *`), recorded as its own item. Standing rule adopted with JD during
this phase: printc stays the faithful Ghidra renderer — a printc change must be Ghidra's own
rendering (cited) or an explicit `MOSURA_*` failure channel; every compilability mechanism
lives in the emitter layer (war2_survey / EmitChoices arms).

**Phase 6 — the genuine defects. DONE (2026-08-17), all three classified, two were wrong code.**
The guarded-store hoist: **FIXED** (MIS-PORT in printc's `comma_separate` contract; the
post-store re-read fixed with it via the `ActionMarkImplied` port —
`decompiler-bug-guarded-store-hoisted.md`, both closed). The `break`-outside-breakable family
(E1000, 3 TUs): **classified and FIXED** — also wrong code underneath (a jump-table target
bound for the switch EXIT was attributed by address order to a neighboring case, which then
executed the wrong body; `decompiler-bug-switch-exit-case.md`; all three TUs now compile, zero
EXACT movement). The pointer+pointer family: **classified as NOT an independent defect** in the
current tree — every specimen is a knock-on of the mechanism-A wide-value class (`CONCAT44`
etc. feeding pointer arithmetic through the Phase-1 tripwire), already flagged per-function by
the contract column; the family folds into Phase 4.

**Cross-cutting — the off-band path.** Needed by Phase 1 and open question 3.

Suggested order: 1 → 3 → 2 → 4 → 5 → 6, correctness before compile count.

**Phase 7 — narrow unsigned operand vs a negative literal: wrong code, FIXED (2026-08-26).**
`uint1 uVar1; if (uVar1 < -2)` / `!= -1` on a 1- or 2-byte unsigned operand: after C's integer
promotion the compare is folded to a constant (always false / always true), so the recompiled
function silently never takes those cases (0x2d7fc's 0xfe/0xff message types; 60 sites in 20 zc66
TUs, wc2src-reconcile). For 4-byte operands the same spelling is harmless (`-1` converts to
`0xffffffff`). Root cause: `printc::render_const` was type-blind — every narrow constant with its
high bit set printed as a signed negative — where Ghidra's `PrintC::pushConstant` prints signed
**only** for a `TYPE_INT` read-facing type (`push_integer(…, sign=true)`, printc.cc:1288) and
unsigned for `TYPE_UINT`/`TYPE_UNKNOWN`. Ported: `render_const_typed(val, size, sign)` with `sign =
matches!(read-facing type, Int)`, the read-facing type being the reading op's input cast when one
applies, else the constant's own (`Varnode::getHighTypeReadFacing`). Fixture
`x86_uint_cmp_literal.xml` (`cmp al,0xfe ; jb`): `-3 < param_1` → `0xfd < param_1`, character-for-
character what `oracle/capture --c` prints. Test `tests/uint_literal_sign.rs`.
Measured correction (round `uintlit`): the first cut tested `Int` only and printed a non-printable
`char` constant unsigned (`c + -1` → `c + 0xff`), costing 3 EXACT (`-1` is an imm8, `0xff` an
imm32). In Ghidra `char` IS `TYPE_INT` (`TypeChar`: a signed integer with the char-print flag), so
the sign predicate is `Int | Char`; fixture `x86_char_add_neg.xml` pins it against the oracle.
Corrected round (`uintlit2` vs `stringops3`): EXACT 837 → 839, 0 downward verdict flips, WGSS
+0.0003; 13 small MISMATCH dips (max −0.077) are the **faithful-but-costs-bytes** residue: an
unsigned/unknown read-facing constant now prints as Ghidra does (`x & 0x80`, `return 0x8000`)
where the old signed spelling (`& -0x80`) let Watcom use a sign-extended imm8 (`83 /x ib`)
instead of an imm32 — value-identical bit patterns in those ops. Follow-up = an emitter arm
(`const-form=imm8`, witnessed by the original's imm8 encoding, the N1/N3 pattern), not a port change.

**Phase 8 — a byte offset added to a typed stack array (`&local + i*16` on a dword array): wrong
code, FIXED (2026-08-26, wc2src-reconciliation-4 W1).** `*(uint4 *)(&xStack_1dc + iVar8)` with
`iVar8 = i*0x10` on a `xunknown4` local: C scales by `sizeof`, so the recompile strides 64 bytes over
a 16-byte-element array (0x38158, 33 sites; 96 sites across ~30 TUs). Named by the instruments,
not guessed: the rule-trace diff shows both decompilers firing the same rules (RulePtrArith 2×,
RulePtraddUndo 0×); the type-propagation diff shows the SAME `PTRSUB(ESP,-0x20)` edge typing the
output `xunknown4 *` in Ghidra and `Pointer(undefined1)` in mosura. Root cause: the inferencer's
spacebase sub-pointer lookup (`infertypes::spacebase_sub_pointer`, the port of
`TypeSpacebase::downChain`/`getSubType`) took the pointer-width offset constant — `0xffffffe0` held
zero-extended in a `u64` — as +4294967264 instead of −0x20, matched no frame symbol, and fell to the
`Pointer(undefined1)` fallback; RulePtrArith then built a byte-element PTRADD over the dword array
(the recovered scope itself was right on every pass). Ghidra wraps the constant to the stack
space's address width (`resolveConstant` → `wrapOffset`) before the ScopeLocal lookup; with signed
frame offsets, sign-extending from the pointer width is the same lookup. Invisible on the x86-64
datatests (the constant fills the u64). Fixture `x86_local_byte_offset.xml` (dword store at
`[ebp-0x1c]`, then `mov eax,[ebp+eax*16-0x1c]`): `axStack_20 + param_1 * 0x10` →
`(axStack_20)[param_1 * 4]` = the oracle's form. Test `tests/spacebase_ptrsub_offset.rs`.
Collateral caught by the round: typed stack pointers now carry `ActionSetCasts` CASTs between the
phi and the LOAD/STORE, which the string-ops recognizer (COPY-only) could not see through — 0x32c00
lost its `memcpy` (−0.364) and rendered a `memset(p, v, 0)` for the zero-count byte loop; fixed
(CAST-tolerant resolution, no zero-length lone collapse). The `0x2a75c/7a0/7e4` family's dips
(−0.093) are correct-code form drift: `iVar3 * 2` became `auStack_28 + iVar3` on the now-typed
`uint2` array, Ghidra's own spelling. Two more recognizer facts the rounds taught: the loop-entry
resolver may cross only *single-use* COPY/CAST links (crossing a local's own `pTemp = malloc(n)`
COPY inlined the call into the memcpy — a second call, wrong code, 10 sites), and with correctly
typed pointers Ghidra's cleanup `RuleExpandLoad` (ruleaction.cc:10909, a faithful port) widens a
byte copy's LOAD to the pointee width — the recognizers read `SUBPIECE(LOAD:4, 0)` at the pc
as the byte load. Fixtures `x86_memcpy_stackdst.xml`, `x86_32c00.xml` (the specimen, extracted).
The typed-pointer compare variant (`x86_repe_cmpsb_typed.xml`, both operands widened) still
renders `memcmp`. **Measured (round w1e vs uintlit2): WGSS 0.5428 → 0.5430 (+33.5 insn-sim);
EXACT 839 → 840 (0x4db68 SAME_SHAPE → EXACT); 0 EXACT lost; 63 affected TUs, 11 up / 47 flat /
5 down — every down is correct code replacing wrong code (the `uint2` triplet above; 0x38158
−0.010 with its 33 stride sites now `(auStack_1dc)[iVar1 * 4]` in place of the ×64 mis-scale;
0x65fa0 −0.010, a byte offset that had been double-scaled as `aiStack_a8 + iVar3` and now spells
Ghidra's `(uint2 *)((int4)auStack_a8 + iVar3)`); game `memcpy/memset/memcmp` counts unchanged
(78/0/20), zero `mem*(func_0x...` destinations; 0x32c00 and 0x3d85c (+0.075) have their memcpys
back.** The stride fix is form-neutral for the score because Watcom spells the ×16 index the same
way from either C; the win is the corrected code.

**Phase 9 — a switch case that exits after an if-with-return lost its `break` (wrong code, the
C fell through into the next case): FIXED (2026-08-26, wc2src-reconciliation-4 W8).** The case
terminator was a heuristic — "the case's exit basic block ends in a RETURN, so it is terminal" —
which is false for a case whose body is `if (...) { ...; return; }`: the block after the `if` still
has its fall-out edge to the switch tail (WAR2 0x2c00c case 13, original `JE 0x2c085`; also
0x2191c ×3, 0x3ed74 ×2, 0x152e0, 0x3d534). Ghidra's rule (`PrintC::emitBlockSwitch`):
`if (bl->isExit(i) && i != last) print "break;"`, where a case is an exit when its STRUCTURED block
has exactly one out-edge (`BlockSwitch::addCase`: `isexit = bl->sizeOut()==1`) and the last case
gets none. Ported as written on the structured `FlowBlock.out_edges` (the composite's edges, which
`install` propagates from the collapsed sub-blocks) — the RETURN case has zero out-edges, so it
still prints no `break`, and a legitimate fallthrough (0x3d2e8, `case 0: if (...) {...return;}`
running into `case 1: return 0;`) keeps falling through: Ghidra's `newBlockGoto` removes the goto
edge from the wrapper ("treat out edge as if it didn't exist", block.cc), so a fall-through case —
a `BlockGoto` whose goto is not printed because its target is the next case (`gotoPrints`) — has
`sizeOut()==0`; mosura's `rule_block_goto` consumes the `GOTO`-marked edge the same way
(`remove_out_edge`, the block becomes terminal), so the count is zero there too. Fixture `x86_2c00c_switch.xml` = the specimen's bytes plus its 11-entry
jump table relocated by the object base (raw image entries are pre-fixup); test
`tests/switch_case_break.rs`.
**Measured (round w8 vs w1e): WGSS 0.5430 → 0.5433 (+28.3 insn-sim); 840 EXACT held, 0
verdict flips; 17 TUs changed, 4 up / 13 flat / 0 down; 15 `break;` added, 10 removed (last
cases); the five value-wrong TUs gained exactly their breaks (0x2191c ×3, 0x3ed74 ×2, 0x2c00c,
0x152e0, 0x3d534 ×3), the rest are the last-case removals.** One form note: 0x3d2e8's case 0 now
prints `break;` too — its block has one out-edge, to the shared `return 0` block that is also
case 1 — value-identical (the switch tail is `return 0` as well) and byte-identical (flat);
Ghidra would chain that edge as a fallthrough in `ruleCaseFallthru`, which mosura's
`rule_case_fallthru` did not mark here — a structuring item, not the printer's rule.
**Follow-up (fable-b's hold, 0x614fc):** the rule exposed a latent printer gap. A case body whose
own goto edge (cut by `rule_block_goto`, so the block has no out-edge and is not an "exit") targets
a block that is ALSO the landing of a direct head→exit table entry printed nothing: the switch's
exit suppression (`switch_exit_suppress`) was a set of target BLOCKS, meant for the head's own cut
records that the `case N: break;`/`default:` arms represent, but `emit_structured` applied it to
every node's records with that target — case 2's `break` (scopeBreak-typed goto to 0x616a7) was
swallowed and the C ran case 4 after case 2; the old unconditional `break;` had masked it. Ghidra
prints a case's goto after its body (`emitBlockGoto`, unless the target is the next printed case)
— so the suppression is keyed by (node, target) over the head's node chain only.

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
