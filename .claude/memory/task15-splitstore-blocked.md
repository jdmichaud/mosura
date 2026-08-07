---
name: task15-phase1b-tail
description: Task
metadata: 
  node_type: memory
  type: project
  originSessionId: c0fe6b35-0fb2-4ed2-90d8-ec93de63680c
---

Task #15 Phase 1b (owner tail1): port every faithful oppool1/cleanup MISSING rule in Ghidra
registration order. Per-rule commit detail is in git; this file holds the LIVE state.

PAUSED (2026-07-05, weekly limit resets 22:00 Europe/Paris): after tail3 was reaped, the LEAD executed
the remaining pass directly. HEAD `ca61e82`, tree clean, suite 293/0. BOTH queued items are DONE:

1. BooleanMatch cluster LANDED `ca61e82` (lead-executed, byte-IDENTICAL 62/62 exit 0, 8 unit tests):
   expression.rs (NEW module = expression.cc: varnodeSame/sameOpComplement/recursive evaluate w/ De
   Morgan), get_booleanflip (opcode.rs = opcodes.cc:94), op_bool_negate (funcdata.rs =
   funcdata_op.cc:560), RuleBooleanUndistribute #60 + RuleBooleanDedup #61 wired at slots 60/61,
   coverage flipped PORTED. oppool1's clean+helper tail is now FULLY EXHAUSTED — everything left in
   oppool1 is HELD-mover or BLOCKED(#9/#10/subsystem).

2. SubNormal IR instrument DONE — CONTRADICTION RESOLVED, mechanism NAMED: Ghidra fires subnormal 2x
   on packstructaccess (capture_trace) creating SUBPIECE(x,4)/(x,6) mid-pipeline, then fires
   **RuleSubRight 2x in the CLEANUP pool** (`actcleanup->addRule(new RuleSubRight("cleanup"))`,
   coreaction.cc:5700; class ruleaction.hh:1165) which re-expands nonzero-offset SUBPIECE back into
   `(x >> 8c)` + offset-0 SUBPIECE; PrintC then renders the offset-0 SUBPIECE as a truncation cast
   (isSubpieceCast) => `(int2)(x>>0x30)`. Verified in oracle FINAL IR (`--ir -`): shift + SUB82(..,0)
   + casts, NO nonzero-offset SUBPIECE survives. So the SubNormal regression = mosura MISSING
   cleanup-pool RuleSubRight (NOT a printer bug, NOT a missing guard — both earlier hypotheses wrong;
   instrument-first vindicated again).
   *** NEXT CHUNK (gated MOVER): port RuleSubRight (ruleaction.cc, cleanup pool — mosura already has
   a cleanup lane: RuleMultNegOne precedent) THEN wire RuleSubNormal (one line, d8c924f). Expected:
   +ifswitch `(int4)p/5` magic-div win, packstructaccess/impliedfield UNCHANGED (SubRight restores
   Ghidra's exact final shape). Measure both; report delta to user before landing (mover gate). ***

Session totals (tail3 + lead): 10 wired byte-neutral rules + BooleanMatch subsystem + 2 HELD movers
(SubNormal d8c924f, IntLessEqual dd6d48b) + 8 BLOCKED classifications, 40 unit tests. The
adaptation-conflict CLASS finding is in [[printc-structuring-adaptation-conflicts]] (Phase 1c entry;
note: the SubNormal member of that class is now solved by RuleSubRight above — IntLessEqual's
print-time `<=` adaptation remains the open Phase 1c item).

LATEST (2026-07-05, agent tail3):
- RuleIntLessEqual(#10) LANDED HELD defined-but-unwired `dd6d48b` — faithful port of Funcdata::
  replaceLessequal (funcdata_op.cc:1029) as `replace_lessequal` helper + RuleIntLessEqual (V<=c=>V<c+1,
  signed+unsigned+both-operand-positions+overflow guards; copySymbol omitted). 4 unit tests. WIRING is a
  REGRESSING MOVER (63 firings): mosura ALREADY does this rewrite NON-FAITHFULLY at PRINT time
  (printc::incr_in_width `x<=c=>x<c+1`, keeps SLESSEQUAL in IR); the faithful IR rule converts to SLESS
  early and mosura's structuring/condition-negation (tuned for SLESSEQUAL) regresses concat/condconst/
  condmulti/condsplit into `x==c || x<c` disjunctions. FIX = cancel the print-time adaptation + repair
  structuring (instrument-first, P7/P8 #5/#6). *** QUEUED INSTRUMENT alongside SubNormal. ***
  PATTERN FINDING: 2 of the 3 "byte-neutral helper" rules (SubNormal, IntLessEqual) are actually
  adaptation-conflicts — mosura implements these transforms non-faithfully in printc/structuring, so the
  faithful IR ports collide. The lead's "likely byte-neutral" expectation didn't hold for these two.
- RuleSubNormal(#81) LANDED HELD defined-but-unwired `d8c924f` — faithful port of ruleaction.cc:7714
  (sub(V>>n,c) pull-back through RIGHT/SRIGHT; 4 unit tests all branches). MIXED MOVER when wired (8
  firings): +ifswitch (magic `*0x66666667>>0x21 - >>0x1f` => `(int4)p/5`, TOWARD oracle `p/5`!) but
  -impliedfield/-packstructaccess (it makes non-zero-offset SUBPIECEs for high-dword/bitfield
  extracts, which mosura renders as `(int4)V` low bits: p>>0x20=>p, three `(int2)(x>>0x30/0x20)`+
  `(int4)x` terms collapse to `(int4)x`*3). byte-IDENTICAL unwired, suite 281/0. STAYS HELD at d8c924f.
  *** QUEUED NEXT INVESTIGATION (lead, 2026-07-05) — INSTRUMENT before ANY printer/rule fix (CLAUDE.md
  instrument-first). TWO-MODEL CONTRADICTION to resolve: lead traced Ghidra RuleSubNormal on
  SUBPIECE(x>>0x30,0) (n=48,c=0,outsize=2,insize=8): guards 7735/7738 false, 7761 c+=6/n-=48 => n==0
  at 7763 => Ghidra ALSO emits SUBPIECE(x,6) (nonzero offset). Ghidra opSubpiece printer (printc.cc:843)
  renders a non-cast subpiece as `SUB(x,6)` via opFunc — YET the oracle we captured prints
  `(int2)(x>>0x30)`, which is NEITHER `SUB(x,6)` NOR mosura's `(int4)x`. So one mental model is WRONG;
  a printer port now would be built on a false premise. DO: wire SubNormal LOCALLY (uncommitted), dump
  ORACLE IR + MOSURA IR for packstructaccess+impliedfield, diff, answer: (a) does Ghidra FINAL IR hold
  SUBPIECE(x,6) / a shift feeding offset-0 truncation / a field-access node (doesSpecialPrinting
  printc.cc:846)? (b) how does Ghidra's printer render THAT node — `x.field` / `SUB(x,6)` /
  `(int2)(x>>0x30)`? (c) does mosura fire RuleSubNormal on the SAME node Ghidra does (pure printer
  divergence) or where Ghidra keeps the shift (mosura over-fires/missing guard)? Report the NAMED
  divergence BEFORE proposing a fix (printer port of opSubpiece vs missing guard/rule follows from the
  IR). Not urgent (SubNormal inert HELD); do AFTER the two helper clusters land. ***
- RuleBitUndistribute(#59) LANDED WIRED byte-neutral `2b0666c` — faithful port of ruleaction.cc:2614
  (zext(V)&zext(W)=>zext(V&W) for ZEXT/SEXT; (V>>X)|(W>>X)=>(V|W)>>X for LEFT/RIGHT/SRIGHT w/ matching
  amounts; builds inner op via new_op_before_sized). 0 firings, byte-IDENTICAL, 3 tests.
- RuleNegateIdentity(#80) LANDED WIRED byte-neutral `94aeafc` — faithful port of ruleaction.cc:452
  (INT_NEGATE identities: V&~V=>0, V|~V=>-1, V^~V=>-1 via downstream AND/OR/XOR->COPY(const);
  uses slot_of helper + descend.clone() iteration; can't loop). 0 firings, byte-IDENTICAL, 3 tests.
- RuleThreeWayCompare(#50) LANDED WIRED byte-neutral `fa9fa93` — faithful port of ruleaction.cc:10128
  + detectThreeWay(:10017) + testCompareEquivalence(:9942) helpers + lessequal_form helper (opcode
  enum keeps _LESS/_LESSEQUAL adjacency 13/14,15/16,43/44 so lessform+1 == mosura helper). Detects
  three-way `zext(V<W)+zext(V<=W)-1` (3 permutations + partial), folds secondary compare vs small
  const via 24-case form table. 0 firings (spaceship idiom absent from fixtures), byte-IDENTICAL, 3
  unit tests (build real three-way; forms 20 & 14 + no-fire). Suite 271/0.
- Rule2Comp2Mult(#41)+RuleCarryElim(#43)+RuleBxor2NotEqual(#44) LANDED WIRED byte-neutral `00adbed`
  — faithful oppool1 ports (ruleaction.cc:3967/3988/269), wired before RuleLess2Zero. -V=>V*-1
  (cleanup RuleMultNegOne restores -V; separate pools = no ping-pong; verified no other main-pool
  Int2comp producer), carry(V,c)=>(-c)<=V / carry(V,0)=>false, V^^W=>V!=W. Added Funcdata::
  op_insert_input helper (Ghidra opInsertInput). Full-corpus C byte-IDENTICAL. Firings: 2comp2mult 0,
  bxor 0, carryelim 19x-but-byte-identical (absorbed). 5 unit tests. Suite 268/0.
- RuleSLess2Zero(#47) LANDED WIRED byte-neutral `0889114` — faithful port of ruleaction.cc:5693
  + getHiBit helper (:5641). INT_SLESS vs 0/-1, peel a sign-only op: SUBPIECE-top-piece / ~V /
  (V&0x8..) / CONCAT / getHiBit(add|or|xor)=>EQUAL/NOTEQUAL / bool<<(8*sz-1)=>!bool. 0 firings on
  corpus, full-corpus C byte-IDENTICAL (62 x86:LE:64, all exit 0), suite 263/0. 7 unit tests (one
  per mechanism + no-fire; getHiBit test sets vn.nzm directly since nzmask needs propagation).
  Used checked_shr for the AND-mask sign fetch (RuleRightShiftAnd precedent); is_free-on-constant
  divergence per RuleSubCancel applies (only reachable case = genuinely undefined feed vn).
- RuleSubCommute(#66) now WIRED by LEAD at `90b8dd4` (I was the fresh agent; the wire gate the prior
  agent skipped is CLOSED — lead wired + flipped coverage). Corpus avg->0.8870, 54/60. Gate DONE.
- RuleSubCancel(#75)+RuleShiftSub(#76) already PORTED byte-neutral (the "three past the gate" the
  prior agent landed before being stopped; coverage shows PORTED). RuleBoolZext(#62) `4fff9f4`,
  RuleZextSless(#58) `a04ba2e`, RuleAndOrLump(#21)+RuleRightShiftAnd(#23) `717f472` all byte-neutral.
HEAD `70685bf`, suite 277/0. No gates pending. The CLEAN self-contained oppool1 tail is DONE (8 rules
this session, all byte-neutral): SLess2Zero#47, 2Comp2Mult#41, CarryElim#43, Bxor2NotEqual#44,
ThreeWayCompare#50, NegateIdentity#80, BitUndistribute#59 (+ prior tails).
REMAINING MISSING oppool1 — TRIAGED (2026-07-05), none are clean byte-neutral like the above:
- RuleBooleanUndistribute#60 + RuleBooleanDedup#61: BLOCKED — need BooleanMatch helper class
  (testMatchingBooleans/BooleanMatch::evaluate, same/complementary bool classifier); mosura lacks it.
  Marked BLOCKED in coverage `70685bf`. Port BooleanMatch first, then both.
- RuleIntLessEqual: needs Funcdata::replaceLessequal helper (mosura has replace_lessequal only in
  structure.rs=P7, NOT the Funcdata method). Helper port needed first.
- RuleSubNormal#81 (ruleaction.cc:7714): SUBPIECE through RIGHT/SRIGHT, self-contained-ish (is_precis_
  lo/hi EXIST, popcount=count_ones), creates ops + has a popcount-gated extension form. MOVER RISK
  (SUBPIECE/shift territory) — port+measure, gate. NEXT candidate if continuing.
- RuleLeftRight#35, RuleSignShift#14, RuleTestSign: sign/shift, div-race candidates — gate carefully,
  likely movers.
- RuleIndirectCollapse#40 (INDIRECT/effect subsystem), RulePushMulti(nodejoin), RuleTransformCpool
  (cpool): subsystem-coupled, likely BLOCKED.
The mechanical clean tail is exhausted; remainder = helper ports, movers (need lead go), or BLOCKED.

BLOCKED CLASSIFICATION DONE `07b250d` (lead-routed): RuleSignShift#14/RuleTestSign/RuleLeftRight#35 ->
BLOCKED(#9 de-fuse: sign-normalization the fused RuleDivOpt can't re-collapse, RuleSignForm class);
RuleIndirectCollapse#40 -> BLOCKED(INDIRECT/effect subsystem #10); RuleTransformCpool -> BLOCKED(cpool
subsystem absent); RulePushMulti -> BLOCKED(nodejoin). So oppool1's ONLY remaining ports are the two
HELPER-BACKED clusters below.

TURNKEY NEXT CHUNK (lead-approved, fresh-focus pass — sized 2026-07-05, deferred: bigger than it reads):
=== BooleanMatch helper -> RuleBooleanUndistribute#60 + RuleBooleanDedup#61 ===
- Port Ghidra BooleanMatch (expression.cc): enum {same,complementary,uncorrelated};
  varnodeSame (expression.cc:93, ~6 lines: a==b || both-const-equal-offset),
  sameOpComplement (expression.cc:57, ~30 lines),
  get_booleanflip (opcodes.cc:94, ~40-line opcode->flipped-opcode+reorder switch — CHECK if mosura
    already has a booleanflip helper via RuleBooleanNegate before re-porting),
  evaluate (expression.cc:111, ~105 lines RECURSIVE over BOOL_NEGATE/AND/OR/XOR + isBoolOutput +
    depth; De Morgan cases). Unit-test evaluate (same/complementary/uncorrelated) directly.
- Then RuleBooleanUndistribute (ruleaction.cc:2711, ~100 lines, INT_EQUAL/NOTEQUAL over BOOL_AND/OR:
  `A&&B != A&&C => A&&(B!=C)` etc.) + RuleBooleanDedup (ruleaction.cc:2832, ~80 lines, BOOL_AND/OR
  dedup via isMatch->evaluate). Wire both at their slots (60,61), flip coverage BLOCKED->PORTED.
  Likely byte-neutral (no corpus firing site) -> unit-test + self-approve if byte-identical.
=== Funcdata::replaceLessequal -> RuleIntLessEqual ===
- Port Funcdata::replaceLessequal (funcdata_op.cc — NOT the structure.rs replace_lessequal) then
  RuleIntLessEqual (ruleaction.cc:611, delegates to it: `V <= c => V < (c+1)`). Wire at its slot.
tail3 said SPENT at green boundary `07b250d` after 9 ports (8 wired byte-neutral + SubNormal HELD) +
8 BLOCKED classifications this session; BooleanMatch is a fresh-focus chunk, not an end-of-session add.

LANDED prior run (base fec1183; all faithful verbatim, unit-tested if unexercised): RuleFloatCast(#123),
RuleShiftAnd(#71), RuleConcatCommute(#67 mover, switchloop 0.7658->0.7680), RuleConcatZext(#68),
RuleZextCommute(#69), RuleConcatLeftShift(#73), RuleConcatZero(#72 wired mover, nan 0.5385->0.5600),
RuleDoubleShift(#32), RuleDoubleArithShift(#33), RuleDoubleSub(#31 wired mover, switchloop
0.7680->0.7787 — stacks with ConcatCommute on same line), RuleConcatShift(#34), RuleTrivialBool(#12,
fires 83x but C byte-identical), RuleLess2Zero(#45, fires 9x but C identical), RuleOrConsume(#19, fires
124x but C identical), RuleEqual2Constant(#49, byte-neutral). Most byte-neutral (inert on corpus, or
fire-but-absorbed); movers were lead-approved. HEAD 5f2cea5, suite 238/0.

KEY: many bool/compare rules FIRE heavily but render byte-IDENTICAL C (absorbed downstream) — still
byte-identical gate pass, self-approve. Always confirm with the full-corpus before/after C diff.

SIGN-DIV CLUSTER — DEFERRED to RuleDivOpt de-fusion (Task #9/#20): RuleSignForm(#86, 30e9f3f) landed
HELD/unwired — faithful but a NEGATIVE mover (switchloop 0.7787->0.7709: fused RuleDivOpt can't
re-collapse the s>> form it normalizes to; Ghidra reaches `(int4)param_1/10`). modulo fires but stays
byte-identical (no regression). Its siblings SignForm2/SignDiv2/SignNearMult are the same fused-DivOpt-
race class — do NOT port-and-wire them until RuleDivOpt is de-fused; ground+HELD only if preserving.
No gates currently pending. HEAD eca182f.

BLOCKED (subsystem-coupled, cited in coverage.md — NOT mechanical tail): RuleSplitCopy/Load/Store
(SplitDatatype/TypePartialStruct, subflow.cc), RuleSubfloatConvert (SubfloatFlow : TransformManager +
FloatFormat, subflow.cc), RuleLoadVarnode/StoreVarnode (spacebase-placeholder). Lead is tracking
"port ONE TransformManager/TransformVar framework" as a named future subsystem that unlocks
SubfloatFlow + SplitDatatype/SplitFlow + LaneDivide.

PATTERN for movers: land struct+impl+test DEFINED-BUT-UNWIRED (byte-identical) in the neutral batch's
commit, coverage=HELD-gated; report the before/after C delta + ccompare direction; on lead go, wire
(one line) + flip coverage PORTED. Movers self-approve ONLY if byte-IDENTICAL corpus.

GATE-CHECK TOOLING (both load-bearing):
1. `cargo run --example dump_all` HANGS forever on non-x86-64 fixtures (decodes them with the x86-64
   SLA). Pre-existing. Filter to the 62 x86:LE:64 fixtures (`grep -l x86:LE:64` the datatests dir).
2. Counting firings via `MOSURA_TRACE | grep ": <rule>$"` SILENTLY MISSES PANICS (a crashed dump emits
   no stdout -> reads as "0 firings, byte-neutral"). ALWAYS check dump's per-fixture EXIT CODE
   (0/101-panic/124-hang) AND prefer a real before/after C diff. A green FULL SUITE also rules out
   panics (pipeline tests decompile real fixtures). Both caught real bugs this run.
3. ccompare per-fixture: throwaway `examples/simcmp.rs` (decompile + oraclecache::capture("--c") +
   ccompare::similarity), rm after. Oracle capture: `oracle/capture <ghidra_src> <fixture.xml> --c`.

NEXT queue (registration order), GROUNDED sizing (DONE: OrConsume#19, Equal2Constant#49, TrivialBool#12,
Less2Zero#45):
- Safe Bool/Sub/Zext tail (div-independent): RuleBoolZext(#62, :2995 — larger, needs isBooleanValue/
  isTypeRecoveryOn + builds ops for the &&/|| cases), RuleSubCommute(#66, :4514 — larger, isPrecisLo/Hi +
  shortenExtension + DIV/REM cases so partly div-touching, gate carefully), RuleSLess2Zero(#47, :5693 —
  BIG ~150 lines: getHiBit helper + SUB/NEGATE/AND/PIECE/hi+lo forms, needs fresh focus not a quick port),
  RuleZextSless,
  RuleAndOrLump, RuleRightShiftAnd, RuleSubCancel, RuleShiftSub, Rule2Comp2Mult, RuleBxor2NotEqual,
  RuleCarryElim, RuleThreeWayCompare(bigger), RuleIndirectCollapse. Ground each; most small self-contained.
  Many fire-but-absorbed (byte-identical -> self-approve).
- RuleLeftRight (#35, ruleaction.cc:2010): `(V<<c) s>>c => sext(sub(V,#0))`, shift multiple of 8.
  Self-contained (creates SUBPIECE + SEXT/ZEXT). BUT touches sext/sign forms — gate for div interaction
  like SignForm; may be a mover.
- sign-div cluster: now BLOCKED(de-fusion Task #9) in coverage (b7cf99c) — SignForm2/SignDiv2/
  SignNearMult/SignMod2Opt. Port them INSIDE the Task #9 de-fusion effort, not before. RuleSignShift(#14)
  left MISSING/separable (general sign-bit norm, test later — may also race).
Discipline per rule unchanged; check self-contained vs subsystem-coupled before porting.
See [[task2-tailrules-progress]].
