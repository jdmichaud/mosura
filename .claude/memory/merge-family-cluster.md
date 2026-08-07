---
name: merge-family-cluster
description: "✅ Bricks 1-3 LANDED `8ec771d`+`f49aa34`. ★★ unaff1 2026-07-18 BUILT+GATED (held for lead GO): `ActionDirectWrite` (coreaction.cc:1350) + deadcode's addrforce-clear-for-!directwrite (coreaction.cc:3944) — the REAL noforloop_alias lever (deadcode keep-alive is addrforce, NOT addrtied; RBP-save chain isn't directWrite → addrforce stripped → deadcoded). avg 0.9462→0.9480/57, suite 507/0, noforloop_alias 0.920→1.000 + loopcomment 0.903→0.929, both convergent, ZERO regressions. Turnkey = directwrite-brick.patch. Retires BOTH prior mis-frames (ActionLikelyTrash corpus-inert; unaffected-save-slot/markUnaliased wrong). mergeIndirect re-probe on this base = UNPARK GATE GREEN (piecestruct+offsetarray HOLD 1.000); its only residual = stackreturn CONCAT44 half-drop (mergeIndirect's own)."
metadata:
  node_type: memory
  type: project
  originSessionId: 9beadf25-4682-4e85-94fa-f326d85ed777
  modified: 2026-07-19T07:33:26.062Z
---

# Merge-family cluster (board #11) — mrg1, 2026-07-17

## ✅ LANDED (lead GO): `8ec771d` (Bricks 1+2) + `f49aa34` (Brick 3 wire)
Post-commit verify @f49aa34: **avg 0.9432, 57/60 (self-dated), suite 437/0, jumptable 6/6, all
must-holds hold, tree clean**, clippy 79==79, corpus runtime flat.

## What landed (mechanism chains in the commit messages)
- **Brick 1 — full `Merge::mergeOp` (merge.cc:719)** in merge.rs: three phases (required trims
  incl. pairwise j<i; BLIND-SEQUENTIAL cover loop w/ cumulative mergeTest testlist — trace DEBUG
  560 = 11 trims on switchloop's 13-input phi = the per-case `iVar3 = 2; param_1 = …` order;
  trimOpOutput; forced union), live union state across markers, `class_intersect` w/ copyShadow+
  partialCopyShadow exemptions. **Plus the composition piece**: ActionMarkImplied-before-
  ActionMergeCopy (coreaction.cc:5720-5722) + mergeTestBasic implied exclusion (merge.cc:255) as
  `mark_explicit` at the required-only slot inside read-only `merge()` — without it the trims emit
  WRONG code (single-use trim inputs re-fused, case bodies vanish). Classification core
  `explicit_leading`/`explicit_trailing` SHARED with printc::is_explicit (print layers
  force_explicit/slot_write/high_ram_off on top; merge-explicit ⊆ print-explicit = safety).
- **Brick 2 — ActionDominantCopy + ActionCopyMarker**: `Funcdata::copy_trims` (allocateCopyTrim
  record, both trim sites); processCopyTrims/findAllIntoCopies/buildDominantCopy
  (merge.cc:1415/1290/1151) + common_dominator; cover.rs `cover_replacing`/`merge_from`/
  `def_point_cover`; `copy_marker_nonprinting` (markInternalCopies: shadow skip + checkCopyPair
  redundant marking) → printc `nonprinting`. Dedups: switchloop case 4, loopcomment init set,
  switchhide case 8.
- **Brick 3 — ActionRedundBranch (coreaction.cc:3492)** in determinedbranch.rs (`splice_block_
  basic` = funcdata_block.cc:908 + block.cc:1597), wired after the stackstall group (Ghidra
  :5658). Fires on switchloop (2 splices); corpus byte-identical.
- ir_parity invariant = Ghidra's own verifyHighCovers (copy shadows exempt; probe: the elseif
  pair was two COPYs of one varnode).

## Wrong-code classes closed (3)
loopcomment's uninitialized spill-slot reads (Ghidra-real init set now materializes once);
switchhide's 3 dropped stores (cases 8/14/15); longdouble's double store to fRam101010.

## Movers (vs 0.9408 @78de54a; other 51 fixtures byte-identical)
UP: switchloop 0.877→**0.943**, loopcomment 0.790→**0.838**, ptrtoarray→**1.000**,
forloop_thruspecial→**1.000**, nan→0.596, modulo→0.966, elseif→0.923.
DOWN (classified faithful-exposes, upstream NAMED):
- noforloop_alias 1.000→0.920 — trim materializes the saved-RBP slot phi only mosura keeps alive.
  **★★ RESOLVED 2026-07-18 (unaff1) — BUILT + GATED (held for lead GO): `ActionDirectWrite`.**
  Two prior framings FALSIFIED instrument-first (ActionLikelyTrash-precedent, ×2): (1) trash1's
  "ActionLikelyTrash" — CORPUS-INERT (empty `<likelytrash>` on gcc/win, 0 firings); (2) trash1's
  own follow-on "unaffected-save-slot classification via ScopeLocal isUnaffectedStorage /
  markUnaliased / ActionRestrictLocal / localrange" — ALSO not the lever (-0x8 IS in localRange
  [-1M,-1]; markUnaliased keeps it aliased: contiguous with the array, no rangeTree gap, dist 0x17
  ≪ 0xffff; mosura's coarse `alias_boundary`=-0x18 likewise keeps -0x8 addrtied). **THE REAL
  MECHANISM (deadcode addrforce/directwrite, NOT addrtied):** Ghidra's deadcode keep-alive seed is
  `Varnode::isAutoLive() = (addrforce | autolive_hold)` (varnode.hh:252) — **addrtied does NOT
  protect a write from deadcode**. `ActionDeadCode::apply` line **coreaction.cc:3944** clears
  `addrforce` on every varnode that is `!isDirectWrite()` at the top of each pass. The RBP-save
  chain `s-0x8 = COPY RBP(input)` → MULTIEQUAL → guardCalls INDIRECTs: `RBP` is NOT a param
  (`possibleInputParam` false), NOT persist/spacebase → `ActionDirectWrite` (coreaction.cc:1350)
  never marks the chain directWrite → line 3944 strips the INDIRECTs' addrforce → not auto-live,
  never read → plain deadcode (trace DEBUG 196) removes it. Probe-confirmed: mosura's -0x8 INDIRECTs
  had `addrforce=true,autolive=true` (guardCalls) and mosura had NO directWrite pass + never cleared
  addrforce → chain survived → `xStack_8 = xVar1`. The array slots -0x18..-0xc survive via real
  reads (consumption), not addrforce, so the same clear is harmless to them.
- longdouble 0.952→0.909 — output now MORE correct; residual = **processMultiplier/
  max_term_duplication** (ActionMarkExplicit multlist, coreaction.cc:3091/3166, unported; same
  class = switchloop case 7 + the case-4 uVar2 frozen-vs-rederived explicitness shape).

## ✅✅ unaff1 BRICK — ActionDirectWrite (2026-07-18, BUILT + GATED, held for lead GO)
Files (tree, uncommitted; turnkey backup = `directwrite-brick.patch` this memory dir, 6-file
self-contained, re-applies clean to baseline): NEW `directwrite.rs` (faithful `ActionDirectWrite`
coreaction.cc:1350 — clear+seed directwrite from persist/spacebase inputs, `possibleInputParam`
inputs via `sysv_input`.possible_param, real (non-COPY/PIECE/SUBPIECE) writes, non-indirect-zero
constants; forward taint through assignment outputs; 2 instances propagate=true/false, second wins;
+4 unit tests) + deadcode.rs (the coreaction.cc:3944 addrforce-clear-for-`!directwrite`, gated on
new Funcdata `directwrite_pending_clear` — set by directwrite, consumed by the next deadcode, so
ONLY the two Ghidra-paired deadcodes clear, not mosura's extra rotated/cleanup sweeps) + varnode.rs
(is/set/clear_direct_write) + funcdata.rs (the flag) + pipeline.rs (wired at BOTH Ghidra slots:
mainloop after Heritage before the tail deadcode = :5497-5503; fullloop-tail before its deadcode =
:5680-5682). **MEASURE @6542ea8: avg 0.9462→0.9480, 57/60, suite 503→507/0, jumptable 6/6, clippy
0==0. TWO movers BOTH UP + Ghidra-CONVERGENT (identical RBP-save removal, dump-verified):
noforloop_alias 0.920→1.000 (target CLOSED, oracle-exact) + loopcomment 0.903→0.929 (bonus, SAME
`xVar1`/`xStack_8=xVar1` removal). ZERO regressions, ZERO drops, all must-holds hold** (piecestruct/
offsetarray/elseif 1.000, switchloop 0.943, varcross 0.936, stackstring 0.933, concatsplit 0.978,
revisit 0.894, floatcast 0.880). Gate rationale: fixture MOVER ⇒ lead GO (gate-byte-identical-only).
Blast radius is ZERO through `isIllegalInput` (mosura uses it nowhere) and through the other
directwrite readers (ancestorOpUse, mosura doesn't do full input-param trials) — the ONLY consumer
is deadcode's addrforce-clear.
Not-yet-modeled (faithful-partial, documented in directwrite.rs, inert exactly as the flags are
unset): `Varnode::isStackStore` (setStackStore omitted in RuleStoreVarnode → the COPY-of-INDIRECT-
source directWrite branch coreaction.cc:1381-1393 cannot fire) + `PcodeOp::isIndirectStore`. A
call-modified write-only aliased spill could in theory regress (its addrforce would clear) — NONE
manifested in the 62-fixture corpus; port setStackStore if one ever does.

## Brick 4 — mergeIndirect: PARKED TURNKEY, patch = `brick4-mergeindirect.patch` (this memory dir)
Faithful + complete (mergeIndirect merge.cc:846, snipOutputInterference :815, collectInputs :780;
addr-force protocol; indirect-creation skip). **★ RE-PROBED 2026-07-18 (unaff1) ON THE directwrite
BASE = UNPARK GATE NOW GREEN.** Applied brick4 on top of the unaff1 tree, full corpus: avg
0.9480→**0.9487**, **piecestruct 1.000 HOLDS** + **offsetarray 1.000 HOLDS** (the two hard must-hold
breaks that made it RED are HEALED) + **switchhide 0.996 HOLDS** (was 0.970) + partialsplit 0.941 /
wayoffarray 0.894 hold; switchmulti 0.586→**0.667** (+0.081 win). **CONFIRMS trash1's hypothesis:
the addrforce/directwrite deadcode classification (= the unaff1 brick) WAS mergeIndirect's real
unpark prerequisite** (NOT LikelyTrash — corpus-inert; NOT markUnaliased). **★ mergeIndirect RE-
GROUNDED on the LANDED directwrite base @65ffa1f (unaff1, post-land): full suite GREEN 507/0 WITH
brick4 (no hard-test break), avg 0.9480→0.9487, sole dip = stackreturn 0.926→0.889.** But the
"stackreturn = the CONCAT44 half-drop" premise is FALSIFIED: the CONCAT44 drop (`xRam0140 =
xStack_10` vs oracle `CONCAT44(xStack_c,xStack_10)` + a duplicate-named `xunknown8 xStack_10;` /
`xunknown4 xStack_10;`) is **PRE-EXISTING on the directwrite base at 0.926, independent of
mergeIndirect** — a stack-slot WIDTH-recovery gap (mosura makes one 8-byte -0x10 slot instead of
two 4-byte slots -0x10/-0xc that CONCAT44). **mergeIndirect's OWN residual is a statement REORDER**:
it moves the store `xRam0140 = xStack_10` from BEFORE `func_0x00100121` (oracle order) to AFTER it.
The oracle IR models these globals as INDIRECTs AT the call boundary (`r0x100140 = u0x1000003b []
i…:15` tied to the call), so the reorder is entangled with INDIRECT-modeled global stores at call
boundaries + mergeIndirect's cover/def-point placement (merge.cc:846) — a DEEP mergeIndirect-brick
investigation, NOT the bounded CONCAT44 fix. **VERDICT: mergeIndirect is UNPARK-GREEN but its
stackreturn placement residual is a fresh-run task** (two separable pieces: (a) pre-existing
stackreturn 4-byte-slot/CONCAT44 width recovery — own gap; (b) mergeIndirect store-vs-call ordering
at the INDIRECT boundary — verify wrong-code vs benign-reorder before landing). Patch reverted, tree
clean @65ffa1f. Starting point stays `brick4-mergeindirect.patch`. (Prior "task#8 Brick D" gate refs
moot.)

## ★★ processMultiplier / ActionMarkExplicit multlist — pmul1 2026-07-18: BUILT FAITHFUL, PARKED (wrong-code exposure). Turnkey = `processmultiplier-brick.patch`
**Premise CONFIRMED (brief was RIGHT this time, unlike the last 3 targets).** longdouble's residual =
mosura's `explicit_trailing` (merge.rs) had a blanket `if vn.descend.len() != 1 { return true; }` —
ANY multi-use varnode → explicit, short-circuiting Ghidra's entire ActionMarkExplicit `multlist` /
`processMultiplier` / `multipleInteraction` machinery (coreaction.cc:3091/3166/3237). mosura had NO
port of it (the EXPLICIT/IMPLIED/MARK varnode flags exist but NOTHING sets them; classification is the
pure-fn Vec<bool>). Ghidra: `max_implied_ref=max_term_duplication=2` (architecture.cc:1420-1) → a
value with EXACTLY 2 descendants is a multlist member; `processMultiplier` counts explicit terms and
if `> maxdup(2)` names it, else keeps it IMPLIED and duplicates the expression at each use. longdouble's
`in_stack + (float10)fRam1b8` = 2 terms ≤ 2 → Ghidra inlines it into BOTH stores (mosura materialized
`fVar1`). Confirmed on HEAD by direct IR inspection (op graph IDENTICAL to oracle; divergence is PURELY
explicit-marking — ActionMarkExplicit is a print-prep marking action, invisible to the pool trace, so
trace-diff shows no rewrite-rule gap — consistent).

**BUILT (faithful, all in merge.rs, ~215 lines):** replaced the blanket with baseExplicit's descend-count
arms (`0`/`>maxref` → explicit) + a `dn==2` multlist arm calling ported `is_purged_top`
(multipleInteraction), `process_multiplier` (OpStackElement term walk), `is_mark_candidate`/
`is_core_explicit` (the multlist-membership + processMultiplier-time isExplicit snapshot), and the
extracted `implied_cover_ok` (checkImpliedCover's input-cover arm, reused for both dn==1 and dn==2).
Implemented as PURE per-varnode predicates (mark/purge computed on-the-fly) → NO batch restructuring;
existing per-varnode `explicit_trailing` API works for BOTH merge + printc consumers unchanged. Multi-use
LOADs kept explicit (checkImpliedCover's LOAD-vs-STORE/CALL arms :3384-3406 not ported — documented
under-approximation, never wrong). Single-use path byte-unchanged.

**MEASURED @a2211f3-dirty (re-confirmed on the post-restart HEAD; 65ffa1f→a2211f3 is oracle-only, merge.rs
byte-identical, corpus identical, patch re-applies clean): avg 0.9480→0.9516, suite 507/0 (one unit test
faithfully updated — see below), jumptable 6/6, clippy 0.** THREE movers, ZERO drops, other 59 byte-identical:
- **longdouble 0.909→~1.000** (target CLOSED — mosura == oracle structure, only name `fStack_8` vs
  `in_stack_00000008` differs, ccompare-erased).
- **floatcast 0.880→0.990** (bonus — `fVar1 - fVar2` now duplicated into both CONCAT44 args = Ghidra-exact,
  RESOLVES task21's filed "fVar3 temp" residual; remaining = pre-existing #13-class weak-type `xunknown4`/
  missing `(uint8)` cast).
- **switchloop 0.943→0.963** — MIXED: case 7 now `8 - ((param_1 ^ 0x87) & 1)` == oracle EXACTLY (the
  filed case-7 processMultiplier target, FIXED). BUT **case 2 = WRONG-CODE**: renders `param_1 = param_1
  * 2; if (10 < (int4)(param_1 * 2))` → the inlined `param_1 * 2` re-reads the REASSIGNED param_1 =
  `10 < 4*old` (oracle/baseline: `10 < (int4)param_1` = `10 < 2*old`). Semantically incorrect.

**Why case-2 is wrong (ROOT = pre-existing UPSTREAM IR, not the port):** oracle IR — T=`param_1*2`
(u0x1000006a) is SINGLE-use (feeds only the phi, explicit via baseExplicit marker-descendant :3076); the
comparison reads a SEPARATE varnode u0x100000b9 (= phi-merged param_1). mosura's IR — copy-prop
OVER-PROPAGATED T into the comparison AND routed T→COPY(u0x10283)→phi (extra trim COPY breaking the
marker-descendant link), giving T 2 non-marker uses. My faithful processMultiplier correctly makes the
now-2-use T implied → but the inlined expr reuses the reassigned name. checkImpliedCover CANNOT catch it
even faithfully: T's cover and the phi-COPY's cover only BOUNDARY-TOUCH (read at op-i vs write at op-i =
the mergeable x=x+1 case), which Ghidra's `inflateTest` `intersect()==2` (real overlap) also would not
flag (merge.cc:1616). So it is the classic **faithful-type-of-wrong-IR**: the faithful downstream
renders the ugly truth of wrong upstream IR (was MASKED while T was explicit-rendered-as-param_1).
**BLOCKING FAITHFUL PIECE (fix FIRST, then unpark):** ⚠️ **THIS "copy-prop over-propagation / comparison-
reads-T" framing was FALSIFIED by cprop1 (instrument-first) — see the cprop1 section below.** The real
root is NOT copy-prop: mosura's phi-slot ORDER puts the sole conflicting input (case-4) LAST, so the
mergeOp blind-sequential trim (merge.cc:719) snips case-2's phi edge as COLLATERAL reaching case-4 → T
feeds a trim COPY not the phi marker → not explicit. Ghidra's slot order has case-2 LAST (survives
untrimmed → feeds the phi directly → explicit). DEEP = phi-slot-order/CFG alignment. Defer to cprop1.

**Unit-test update in the patch (faithful, NOT a workaround):** `merge_copy_merges_noninterfering_but_
not_interfering` (merge.rs) asserted `a=c+c` (2 uses) is explicit + merges — that was mosura's OLD
non-faithful blanket. Under faithful processMultiplier `a=c+c` = 2 terms → IMPLIED (Ghidra does the same)
→ not a merge seed. Rewrote a/e to 3-term `(c+c)+c` so they stay explicit and the mergeCopy
interfering-vs-non-interfering logic is still exercised. This is the ONE hard-test the change touched;
green after the update.

**VERDICT:** faithful + suite-green + strong wins, but PARKED because it ships wrong-code on switchloop
case-2 (hard blocker per mission). Turnkey `processmultiplier-brick.patch` (this dir, re-applies clean to
`a2211f3` = HEAD, one file: merge.rs). Unpark AFTER the upstream over-propagation fix (or lead GO if the lead
judges the case-2 exposure acceptable-and-file). longdouble + floatcast wins are pure-clean and would
land immediately if switchloop weren't entangled — but it is one uniform mechanism, not selectively
disableable without a non-Ghidra heuristic.

## ★★ cprop1 2026-07-18 — case-2 PREMISE FALSIFIED + root is DEEP (mergeOp phi-slot over-trim). STAYS PARKED
Ground READ-ONLY @65ffa1f (oracle `--ir -` + mosura `--raw` + merge_op instrumentation + trace-diff).
**pmul1's "copy-prop over-propagation / comparison-reads-T" framing is FALSIFIED** — it is NOT copy-prop,
and the comparison-reads-T is a red herring: mosura has no CAST op (never fires `setcasts`; trace-diff
shows setcasts as Ghidra-only) so its comparison reads T=`param_1*2` directly where oracle reads
`(cast)T`, but **`ActionSetCasts` runs AFTER merge (coreaction.cc:5735 > ActionMergeCopy :5722)**, so at
merge time BOTH read T directly — the cast changes nothing about the trim.

**TRUE MECHANISM (instrument-proven):** mosura's `mergeOp` blind-sequential trim (merge.rs:676, faithful
port of merge.cc:719) **over-trims case-2's phi edge**. Instrumented the r0x80 (param_1) 13-input phi:
the SOLE real cover conflict is **case-4** (INT_SDIV `param_1/10`, v598) vs the phi output —
`blk9: v598[2,8] ∩ output[0,3]` (case-4's divide is defined, THEN param_1 is read by the `<0x96` cmp at a
later op → real overlap). **Case-2's T (INT_MULT, v1026) does NOT conflict** (`conflictWithOutput=false`:
param_1's last read is the SAME op that defs T, half-point covers touch but don't overlap — the x=x+1
case). BUT mosura's phi slot order puts the conflicting case-4 at the LAST slots (11,12) and case-2 at
slots 9,10; the in-order blind loop (trim slot 0,1,2,… until `merge_test_all` clean) snips slots 0..12 to
reach case-4, taking case-2 as **collateral**. **Ghidra's final IR has case-2's edges LAST (slots 11,12,
`u0x1000006a` direct, untrimmed) and case-4 at 9,10** → Ghidra's blind loop trims 0..10 and stops, case-2
survives → T feeds the phi MARKER directly → `baseExplicit`'s marker-descendant bail (coreaction.cc:3076)
marks T explicit, FROZEN (ActionMarkExplicit :5719 runs BEFORE the merge trim :5722, sees the pre-trim
graph). mosura re-derives explicitness at PRINT (post-trim); on the clean base the blanket
`descend.len()!=1→explicit` saves the trimmed 2-use T; processMultiplier faithfully makes it implied →
inlined into the reassigned-param_1 cmp → `10 < (int4)(param_1*2)` = wrong. **This is faithful-type-of-
wrong-IR: the wrong-code is the faithful downstream render of over-trimmed upstream IR.**

**NO BOUNDED MARKING-LAYER FIX (falsified by test):** built `copy_feeds_marker` (marker bail follows the
trim COPY: value→COPY→phi ⇒ explicit) — case-2 → CORRECT (`10 < (int4)param_1`, oracle-exact) BUT
**case-7 REGRESSED** (its XOR `param_1^0x87`, ALSO value→trim-COPY→phi + an INT_AND use, is now forced
explicit → loses the `8 - ((param_1^0x87)&1)` inline). In mosura's post-trim IR case-2's T and case-7's
XOR are **structurally identical** (value → arithmetic-use + trim-COPY→phi). In Ghidra they differ ONLY
upstream: case-2's T is a UNIQUE fed to the phi DIRECTLY (→ explicit `param_1=param_1*2`); case-7's XOR is
register-EAX fed via a trim COPY (→ implied/duplicated). `numInstances>1` would fail the same way (both
merge into param_1). **The case-2/case-7 distinction is UNREACHABLE at the per-varnode marking layer** —
it lives in the merge trim decision.

**ROOT = DEEP (fresh task, both stay parked):** the decisive lever is the **phi input slot order**
(cfg.rs:284 pushes in_edges in ascending predecessor block-index order; Ghidra's block ordering puts
case-2's two edges last). Verified: if case-2 were LAST (after the sole conflict case-4), the blind loop
would trim 0..case-4-slot and case-2 survives — regardless of mosura's distinct-unique modeling (2ndary:
Ghidra's case values are shared EAX where mosura's are distinct uniques, which changes WHICH inputs
conflict but not case-2's survival). Aligning the loop-header in_edges/phi-slot order with Ghidra is a
CFG/block-indexing change, broad blast radius. Architecturally-correct alternative = port the FROZEN-
explicit-flags model (follow-on #4): ActionMarkExplicit/MarkImplied as a PRE-merge pass (:5719-5720 before
:5722) that SETS+freezes varnode flags used at print — freezes T explicit while it still feeds the phi
marker pre-trim; robust to the trims. But that restructures mosura's re-derive-at-print explicitness
(itself a corpus-mover) — also not bounded. **Neither is the bounded cover/interference-gate fix the
mission hypothesized; processMultiplier stays PARKED.** (mergeOp blind-trim algorithm itself is a verified-
faithful port of merge.cc:719 — not the bug.)

## Follow-ons filed
1. ~~**ActionLikelyTrash / unaffected-save-slot classification**~~ — **RESOLVED: the real lever was
   `ActionDirectWrite` + deadcode's addrforce-clear (see the unaff1 brick above), BUILT + GATED.**
   Both prior namings were mis-frames (instrument-first, ActionLikelyTrash-precedent ×2):
   ActionLikelyTrash is corpus-inert (empty `<likelytrash>` on gcc/win); the "unaffected-save-slot /
   ScopeLocal isUnaffectedStorage / markUnaliased / ActionRestrictLocal / localrange" framing is
   also wrong (-0x8 IS in localRange and markUnaliased keeps it aliased). ActionLikelyTrash remains
   a low-priority 32-bit-x86-only pipeline-completeness item, NOT a paydown lever.
2. ~~processMultiplier/max_term_duplication~~ — **BUILT FAITHFUL + PARKED (pmul1).** longdouble→~1.000 +
   floatcast→0.990 + switchloop case-7 Ghidra-exact, BUT switchloop case-2 wrong-code. **cprop1 2026-07-18:
   the case-2 blocker premise (copy-prop over-propagation) is FALSIFIED; root is DEEP = mergeOp phi-slot
   over-trim (case-2's phi edge is snipped as collateral because mosura's slot order puts the sole
   conflicting input, case-4, LAST). NO bounded marking-layer fix (case-2 ≡ case-7 in post-trim IR). Unpark
   needs EITHER the phi-slot-order/CFG fix OR the frozen-explicit-flags model (#4) — both fresh DEEP tasks.
   See the cprop1 section above.** Turnkey stays `processmultiplier-brick.patch`.
3. testUntiedCallIntersection (HighIntersectTest tail — needs stackAffectingOps/hasNoLocalAlias).
4. Frozen-explicit-flags model (Ghidra sets flags once at MarkExplicit/MarkImplied; mosura
   re-derives at print — case-4's inlined div is the only visible instance). **RE-FRAMED + PARK-ELIGIBLE
   by explicit1, see the CAMPAIGN MAP section below.**
5. loopcomment 0.838→~0.9: mosura loses the written spill-slot defs Ghidra keeps (params flow as
   registers into addrtied phis → per-join required-trims; Ghidra's IR has real stores).

## ★★★ FROZEN-EXPLICIT-FLAGS CAMPAIGN — explicit1 2026-07-18: GROUNDED + Brick-1 IMPL-VERIFIED (READ-ONLY, tree clean @65ffa1f)
The user-approved "frozen-explicit-flags" campaign was grounded premise-first. **The brief's premise
that freezing the flags fixes switchloop case-2 is FALSE — case-2's real root is an UPSTREAM
phi-slot-order over-trim, unaffected by any marking model. The corrected map + Brick-1 verdict:**

**CORRECTED CAMPAIGN MAP (land order):**
- **Brick 1 = the REAL unlock = phi-input slot-order alignment (mergeMarker over-trim).** mosura orders
  a block's phi in-edges by ASCENDING predecessor block-index/address (`cfg.rs:281-285`: `for bi in
  0..nb { for o in out_edges { in_edges[o].push(bi) }}`). Ghidra orders in-edges by edge
  DISCOVERY/collection order (`FlowInfo::connectBasic`, flow.cc:1021, iterating `block_edge1`). For
  switchloop's param_1 loop-header phi this puts mosura's sole cover conflict (case-4 INT_SDIV) at the
  LAST slots (11,12) with case-2 INT_MULT at 9,10 → the blind-sequential trim (`merge_op`, merge.rs:649,
  faithful merge.cc:719) trims 0..12 (all) to reach case-4, taking case-2's MULT as collateral → MULT
  feeds a trim COPY not the phi marker. Ghidra has case-4 at 9,10, case-2 LAST → trims 0..10, case-2's
  MULT survives → feeds the phi MARKER directly → `baseExplicit` marker-descendant bail (coreaction.cc:3076)
  → frozen explicit. **Class: gated mover, blast PROVEN switchloop-only (see below).**
- **Brick 2 = pmul1's `processmultiplier-brick.patch`** (applies clean @65ffa1f). Once Brick 1 makes
  case-2's MULT marker-adjacent, pmul1's print-time processMultiplier renders it correct (the patch
  ALREADY has the marker-descendant bail `descend.iter().any(is_marker)→explicit`). **This is the whole
  corpus payoff — needs NO varnode-flag plumbing, NO subsystem rewrite.**
- **Brick 3 = the literal frozen-flags subsystem (set+freeze varnode explicit/implied as real passes,
  flip printc/merge to consume) = PARK-ELIGIBLE, LOW-ROI.** It is a REFACTOR (retire the re-derive
  adaptation) whose only behavioral delta vs Brick 2 is full-merge-graph vs pre-speculative-graph, whose
  sole known effect is case-4's inlined div. **Does NOT fix case-2** (freezing runs AFTER mosura's
  over-trim → sees the trim COPY → same wrong-code; VERIFIED at HEAD: applying pmul1 alone gives
  `if (10 < (int4)(param_1 * 2))`). Retires follow-on #4; schedule last or skip.

**Brick-1 IMPLEMENTATION-VERIFIED (transient probes, all reverted, tree clean):**
- Debug probe in `merge_marker_trim`: at trim entry the r0x80 phi reads RAW values — slots 9,10 =
  INT_MULT (case-2, u0x10248), slots 11,12 = INT_SDIV (case-4, LAST). Confirms cprop1's slot order.
- REORDER probe (move INT_MULT phi inputs to the END, permuting in_edges + all phis in the block
  consistently) + pmul1: **case-2 → `if (10 < (int4)param_1)` (CORRECT, Ghidra-exact)**; without reorder
  pmul1 gives `if (10 < (int4)(param_1 * 2))` (WRONG). IR-confirmed: reordered, u0x10248 sits at phi
  slots 11,12 DIRECT (untrimmed), descendants = {MULTIEQUAL marker, INT_SLESS}. **cprop1's slot-order
  root is CONFIRMED — phi-slot order IS the operative lever.**
- (The naive per-phi reorder introduced a `bVar2 = iVar1!=10; while(bVar2)` artifact — a PROBE BUG
  from desyncing the two block-1 phis' shared in_edges; the block-consistent reorder gives switchloop a
  CLEAN single delta = only the case-2 fix.)

**BLAST RADIUS = BOUNDED, PROVEN switchloop-only (the decision-maker):**
- pmul1 + block-consistent reorder, full corpus: **avg 0.9480→0.9517, 57/60**; per-fixture diff vs
  pmul1-only = **switchloop 0.963→0.969 and NOTHING else** (longdouble 1.000, floatcast 0.990 from pmul1).
- **Upper-bound test: reversing EVERY block's in_edges corpus-wide on the CLEAN base** (max disruption,
  no pmul1) moves **ONLY switchloop (0.943→0.855); all other 61 fixtures BYTE-IDENTICAL** (avg
  0.9480→0.9465). **Phi-slot order is not load-bearing anywhere but switchloop** — the blind-trim
  collateral-trim of a should-be-explicit multi-use value is order-sensitive ONLY there. So ANY
  phi-order change (targeted or a corpus-wide cfg.rs in_edge-ordering rule change) CANNOT destructively
  move another fixture. This DE-RISKS Brick 1 entirely.

**BOUNDED-vs-DEEP VERDICT: BLAST is BOUNDED (contained to switchloop, proven). The faithful CODE shape
is a localized in_edge-ordering change in `cfg.rs` (align with Ghidra's connectBasic discovery order),
NOT a corpus-wide block re-index — and even if it touches CFG edge-ordering broadly it is output-safe
everywhere but switchloop.** TWO residual grounding items before building (neither is "deep CFG
campaign"): (a) the oracle `capture` binary currently throws DecoderError on ALL fixtures (env/stale
binary — corpus test works off cached C in build/oracle-cache; needs `scripts/setup-oracle.sh` rebuild)
→ so Ghidra's exact phi-slot order could NOT be live-re-confirmed this session; relying on cprop1's
same-SHA oracle grounding (case-2 last). (b) Must confirm the FAITHFUL connectBasic order actually
yields case-2-last for switchloop (vs cprop1's noted secondary factor: Ghidra's shared-EAX case values
vs mosura's distinct uniques) — if connectBasic-order does NOT put case-2 last, the lever is the
distinct-unique modeling (deeper). Step 1 of Brick 1 = rebuild oracle, dump Ghidra's switchloop phi,
confirm case-2-last + which in_edge rule reproduces it. Turnkey pmul1 patch unchanged
(`processmultiplier-brick.patch`).

## ★★★ Brick-1 FAITHFULNESS GATE — explicit1 2026-07-18 (part 2): BLOCKED on oracle + evidence leans DEEPER than the scoped connectBasic port. STOPPED, did NOT build.
Coordinator GO'd Brick 1 behind a gate: rebuild oracle capture, live-confirm Ghidra's switchloop
phi has case-2 LAST, and verify porting `FlowInfo::connectBasic` discovery-order (flow.cc:906/1021)
to mosura's `cfg.rs` in_edge ordering REPRODUCES case-2-last. **Gate could NOT pass; STOPPED per the
coordinator's deeper-branch instruction (do NOT force a hack).** Evidence (all probes reverted, tree
clean @65ffa1f):

**(1) Oracle IR is UNAVAILABLE — a real tooling blocker, not a stale binary.** Rebuilt via
`setup-oracle.sh --skip-specs` (sleigh_opt/decomp_dbg/decomp_test_dbg + capture + capture_trace all
rebuilt; datatests 599/599). `oracle/capture … --ir -` AND `--c` STILL throw
`terminate: ghidra::DecoderError` on EVERY fixture. Root: `DecoderError` (xml.hh:297) is NOT a
`LowlevelError` subclass, so it escapes capture.cc's `catch(LowlevelError&)` → uncaught. It's a
capture.cc-vs-Ghidra-12.0.3 XML/marshal-decoder incompatibility in the manual arch-setup path
(`store.registerTag`/`conf->init`), NOT the specs (decomp_test_dbg decodes the SAME fixtures fine via
the datatest harness). `capture_trace` fails identically. `decomp_dbg` needs a Ghidra-install root
(absent). `decomp_test_dbg` works but buffers console output into `midBuffer`/`bulkout` for stringmatch
(testfunction.cc:315-330) — `print raw` is not surfaced (adding it + an error-trigger did not dump it).
No cached `--ir` output exists (oracle-cache holds only `--c`). **→ Ghidra's actual phi-slot order could
NOT be observed. The whole gate hinges on it. `oracle/capture --ir` is BROKEN and must be fixed
(update capture.cc to Ghidra 12.0.3's decoder, or make DecoderError catchable) before this or any
IR-parity grounding can proceed.**

**(2) Analytical evidence LEANS DEEPER than the scoped fix (cprop1's own wording agrees).** Dumped the
loop-header (block1) in_edges at trim entry: predecessor block order = **0,4,5,8,11,12,13,14,15,6,7,9,10**
— NOT simple ascending block-index/address. The CBRANCH cases (case-2 = blocks 6,7 @0x100058; case-4 =
blocks 9,10 @0x100074) land at slots 9-12 while the simple `+N` cases (blocks 4,5,8,11-15) occupy slots
1-8 despite mixed addresses. So mosura's phi-slot order is a **non-trivial CFG-structure artifact**
(shaped by the switch/CBRANCH sub-block structure ± structuring), NOT the flat "ascending predecessor
index" the Brick-1 scope assumed maps cleanly to Ghidra's connectBasic push-order. cprop1 itself
attributes Ghidra's arrangement to **"Ghidra's BLOCK ordering puts case-2's edges last"** = block-
indexing/structuring, which is DEEPER than the `connectBasic` in_edge-construction rule. So "port
connectBasic in_edge ordering to cfg.rs" is UNCONFIRMED as the faithful mechanism — the divergence
plausibly lives in block indexing/structuring OR the distinct-unique (shared-EAX) case-value modeling.

**(3) What REMAINS confirmed (part-1, still valid):** the LEVER is real (block-consistent phi reorder
→ case-2 correct `10 < (int4)param_1`, IR-verified MULT feeds the phi marker directly); the BLAST is
bounded switchloop-only (max in_edge reversal moves nothing else). So whatever the faithful fix, it is
corpus-safe.

**VERDICT: STOP. Do NOT build Brick 1 on an unverifiable premise (CLAUDE.md: never implement on a
guess).** Prerequisites before Brick 1 can proceed faithfully: **(A) FIX `oracle/capture` (the
DecoderError) — a tooling task, gates all IR-parity grounding; (B) with the oracle live, ground the
ACTUAL faithful mechanism** — connectBasic in_edge order vs block-indexing/structuring vs distinct-
unique EAX modeling. A lower-risk alternative if the oracle stays broken: implement a faithful
connectBasic port and validate mosura+pmul1's C output against the AVAILABLE oracle **C** ground truth
(case-2 = `param_1 = param_1*2; if (10 < (int4)param_1)`) — faithful either way, byte-safe (blast
bounded). Brick 2 (pmul1 patch) and Brick 3 (frozen-flags) unchanged/park-eligible. Coordinator taking
the deeper branch to the user.

## ★★★ explicit1 part-3 — 2026-07-19 @a2211f3 (READ-ONLY grounding, tree clean): frozen-flags premise DEFINITIVELY FALSIFIED from Ghidra source; oracle BLOCKER GONE → phi-slot-order now LIVE-groundable. STAGE-1 REPORT ONLY, did NOT build.
Re-grounded the assigned frozen-flags campaign at HEAD. Baseline re-measured 0.9480/57 (switchloop
0.943, longdouble 0.909, floatcast 0.880, all must-holds present). **Two decisive findings:**

**(1) The frozen-flags premise is FALSE — falsified from Ghidra's own action ORDER, not a probe.** The
brief's premise: "port ActionMarkExplicit as a PRE-merge pass (:5719, BEFORE ActionMergeCopy :5722) so
T is frozen explicit while it still feeds the phi marker pre-trim." **But the phi-input trim is NOT at
ActionMergeCopy (:5722).** It is `Merge::mergeMarker`→`mergeOp`→`trimOpInput` (merge.cc:889/719/692),
invoked by **ActionMergeRequired at coreaction.cc:5718** — one slot BEFORE ActionMarkExplicit (:5719).
So in GHIDRA the marker trim already ran when MarkExplicit fires; T survives as marker-adjacent ONLY
because Ghidra's slot order leaves case-2 untrimmed, NOT because of any freeze-before-trim. cprop1/pmul1
conflated ActionMergeCopy(:5722, the COPY-opcode trim) with the marker trim(:5718). Mosura mirrors this
exactly: `ActionMergeMarkerTrim` (merge.rs:614, the graph-mutating mergeMarker) runs in the pipeline
BEFORE printc re-derives explicitness (pipeline.rs:753). **A faithful MarkExplicit/freeze at the :5719
slot sees the already-trimmed graph → CANNOT rescue case-2. Frozen-flags does NOT fix case-2 and does
NOT unlock processMultiplier.** (Confirms prior part-2/Brick-3 conclusion, now with the precise
:5718-vs-:5719 mechanism.) The mission SUCCESS TEST ("frozen-flags lands → pmul1 renders case-2 correct")
is therefore UNACHIEVABLE by frozen-flags. Frozen-flags remains a legitimate faithful refactor (retire
the re-derive-at-print adaptation; varnode EXPLICIT/IMPLIED/MARK flags exist varnode.rs:18/24/25 but
nothing sets them) — but its only behavioral delta is case-4's inlined div (win/regression UNASSESSED),
orthogonal to the goal. LOW-ROI; do not build without lead sign-off.

**(2) THE ORACLE BLOCKER THAT STOPPED PART-2 IS GONE — `oracle/capture --ir -` WORKS at HEAD** (oraclefix1's
DecoderError catch landed the capability; part-2's "IR unavailable, STOP" premise is STALE). Live-dumped
Ghidra's switchloop SSA IR + mosura's post-pipeline raw IR at HEAD and traced both param_1 phis. **The
slot order is SWAPPED, definitively confirmed (not inferred):**
- MULT `param_1*2` (case-2, addr 0x100058) / SDIV `param_1/10` (case-4, addr 0x100074) — SAME addrs both.
- **Ghidra:** case-4(SDIV) @ phi slots 9,10 ; **case-2(MULT) @ slots 11,12 LAST → survives blind-trim →
  marker-adjacent → explicit → oracle-C `param_1=param_1*2; if(10<(int4)param_1)` (CORRECT).**
- **Mosura:** case-2(MULT) @ slots 9,10 ; case-4(SDIV) @ slots 11,12 LAST → blind-trim snips 0..12 to
  reach case-4, case-2 trimmed as collateral → its MULT feeds a trim COPY (u0x10283=COPY u0x10248), not
  the marker → not explicit → (with pmul1) inlined into reassigned param_1 → wrong `if(10<param_1*2)`.
- ROOT mechanism NAMED: mosura numbers blocks by **ADDRESS** (cfg.rs:255-258 "Address order otherwise")
  and builds in_edges in ascending predecessor-block-index=ascending-address order (cfg.rs:282-285), so
  case-2's edges (0x100058) precede case-4's (0x100074). Ghidra numbers blocks **structurally** (switch-
  successor/flow-discovery order — Ghidra's Block 9,10=case-4 precede Block 12,13=case-2 despite case-4's
  HIGHER address; Ghidra's case-body block indices run ~descending-address). The MULTIEQUAL input order
  follows the block in-edge list. Aligning mosura's in_edge/block order with Ghidra's is the faithful fix
  (mosura's address-order block numbering is itself the non-Ghidra adaptation). Blast PROVEN bounded to
  switchloop (part-1 probes). DEEP-code (block indexing feeds dominators/heritage) but output-safe.

**VERDICT / RECOMMENDATION TO LEAD: pivot off frozen-flags (wrong tool, premise dead) → the real unlock
is phi-slot-order, and part-2's STOP-blocker (no oracle IR) is REMOVED. Next faithful step = fully
characterize Ghidra's block-edge/structuring order vs mosura's cfg.rs address-order (now doable with the
live oracle), then align. Did NOT start it — it is a deep CFG change and prior sessions deliberately
stopped here; awaiting lead direction on (A) pursue phi-slot-order, (B) build frozen-flags as standalone
adaptation-retirement anyway, or (C) park. Turnkey `processmultiplier-brick.patch` still applies clean
@a2211f3 and lands longdouble→1.000 + floatcast→0.990 the moment case-2 is unblocked.**

## ★★★ explicit1 part-4 — 2026-07-19 @a2211f3 (coordinator GO'd (A)): Ghidra block-order MECHANISM named; contained in_edge-RPO fix BUILT+MEASURED+FALSIFIED; effective fix is a BROAD RPO renumber → STOP per stop-condition. All probes reverted, tree clean.
Coordinator GO'd (A) with premise-first mandate: name the ACTUAL Ghidra block-order mechanism, verify blast, report before editing. Done, read-only + one transient measured probe (reverted):

**GHIDRA MECHANISM (fully named, source-verified):**
- Phi input SLOT = predecessor's position in the successor block's `intothis` in-edge list:
  `Heritage::renameRecurse` (heritage.cc:2527) `slot = bl->getOutRevIndex(i)`, filling MULTIEQUAL
  inputs by out-edge→in-edge reverse-index. So phi order ≡ the loop-header's in-edge order.
- In-edges built by `FlowInfo::collectEdges`+`connectBasic` (flow.cc:906/1021) in **source-op ADDRESS
  order** (CBRANCH: fallthru-then-target; BRANCHIND: jumptable-INDEX order via `jt->getAddressByIndex(i)`).
- Block INDEX = **reverse-post-order (RPO)** via `BlockGraph::findSpanningTree` (block.cc:1009-1123,
  `curbl->index = rpostcount`, DFS visiting out-edges in edge order), recomputed by `structureReset`→
  `calcForwardDominator` (funcdata_block.cc:704/711) AFTER switch recovery and on each re-heritage.
- Net: Ghidra's FINAL phi order reflects the POST-switch-recovery **structured/RPO** CFG. Live oracle
  IR @HEAD confirms case-4(SDIV,B9/B10) precede case-2(MULT,B12/B13) — RPO, NOT address (case-4 is the
  HIGHER address). mosura's `merge_op` blind-trim is a faithful port; the divergence is purely this order.

**MOSURA DIVERGENCE (named):** `cfg.rs::build_cfg` numbers blocks by ADDRESS (cfg.rs:255-266 "Address
order otherwise") and builds in_edges by ascending block-index (`for bi in 0..nb`, cfg.rs:282-285) — a
non-Ghidra adaptation. mosura DOES compute RPO but only for dominators (dominator.rs:35 `postorder`/:64
`rpo_num`), never as the block index.

**CONTAINED FIX (order in_edges by RPO at cfg.rs build time) — BUILT, MEASURED, FALSIFIED:** transient
probe (DFS-RPO over build-time `blocks`, push in_edges in RPO order). Corpus BYTE-IDENTICAL on the clean
base (avg 0.9480, switchloop 0.943, ZERO fixtures move → contained/safe). BUT + pmul1 → **case-2 STILL
WRONG** (`if(10 < (int4)(param_1*2))`, switchloop 0.963 = pmul1-ONLY, longdouble 1.000/floatcast 0.990).
**ROOT of the miss:** build-time RPO is computed over the PRE-switch-recovery CFG; its RPO still puts
case-2(b5,b6 slots 9,10) before case-4(b8,b9 slots 11,12) — the SAME as address order for these two. The
order that fixes case-2 is the POST-switch-recovery RPO (dumpprobe over the final CFG DID put case-4
before case-2). So the fix requires RPO on the STRUCTURED CFG at heritage time = Ghidra's `structureReset`
→`findSpanningTree` RPO block RENUMBER, run after switch recovery. **That is a BROAD change** (block index
feeds dominators/heritage phi-placement/statement-emission order globally; renumbering ≠ the in_edge-only
tweak the earlier blast probe modeled). Per the coordinator's explicit "STOP if broader than switchloop-
bounded," I STOPPED and did not attempt the broad renumber. (Part-1's "block-consistent phi reorder" that
worked was a POST-heritage direct phi permutation — effective but NOT a Ghidra mechanism = heuristic,
forbidden by CLAUDE.md.)

**VERDICT: the faithful fix = port Ghidra's RPO block numbering (`findSpanningTree` block.cc:1009 +
`structureReset` recompute after switch recovery / re-heritage), retiring cfg.rs's address-order block
numbering. This is a DEDICATED task-#8-class structural-CFG campaign (broad blast, its own staged gates),
NOT a bounded brick. ROI = switchloop case-2 correct + pmul1 unlock (avg→~0.9516, longdouble→1.000,
floatcast→0.990). Recommend coordinator choose: greenlight the RPO-block-numbering campaign, or PARK the
processMultiplier unlock. Contained in_edge-only tweaks are byte-identical but ineffective (proven).**

## ★★★ explicit1 part-5 — 2026-07-19: RPO campaign GREENLIT → Stage-1 correctness gate FAILED (mosura RPO ≠ Ghidra RPO) → PARKED. Tree clean @a2211f3.
Coordinator greenlit the staged RPO-block-numbering campaign with a HARD Stage-1 gate: on 5-6 diverse
fixtures, mosura's new RPO block order MUST MATCH Ghidra's oracle block order before trusting the renumber
("if mosura's RPO ≠ Ghidra's, the port is wrong — fix before measuring corpus"). Ran the READ-ONLY
verification (mosura findSpanningTree-style RPO over the post-pipeline CFG vs Ghidra `--ir` block order):
- **switchloop ✓ (the target):** mosura RPO CASE order = Ghidra EXACTLY (`default, case9…case1`) → the
  renumber WOULD fix case-2. Only diff = exit-block position (CBRANCH out-edge order), doesn't touch the phi.
- **noforloop_iterused ✓:** order matches (only block-boundary start-addr diffs).
- **loopcomment ✗:** REAL order divergence — the ~0x725 block is LAST in Ghidra, pos-8 in mosura; AND the
  block BOUNDARIES differ (Ghidra 0x6e4/0x700/0x725/0x757/0x75f/0x76a/0x7f3/0x7fb vs mosura
  0x6fe/0x704/0x72c/0x75d/0x766/0x771/0x7f9/0x80c).
- **ifswitch ✗:** 2 order divergences (pos1 0x100010 vs 0x100025; pos5 0x100040 vs 0x10004d).
- revisit: capture dumped only 1 block (unusable).

**ROOT of the mismatch (source-verified) — the RPO port is ENTANGLED with ≥3 other structural subsystems:**
1. **Out-edge order + branch normalization.** mosura freezes out_edges at build-time `[fallthru,target]`
   (cfg.rs:117-122); `boolean_flip`/normalization (condconst.rs, funcdata op_flip_in_place) and structuring
   NEVER reorder them. Ghidra computes RPO (`findSpanningTree` block.cc:1009, via `structureReset`/
   `calcForwardDominator` funcdata_block.cc:704/711) AFTER branch normalization + structuring flip edges
   (`forceFalseEdge` block.cc:1204, `preferComplement`). So mosura RPO ≠ Ghidra RPO wherever a loop/if edge
   is flipped (switchloop header: Ghidra out=[exit,switch] post-flip vs mosura [switch,exit] raw).
2. **Block boundaries differ** (mosura skips leading COPYs, splits basic blocks at different addresses —
   loopcomment).
3. RPO depends on out-edge DFS visitation order, so (1)+(2) propagate into the block numbering.

**VERDICT: Stage-1 gate NOT passed. The faithful RPO renumber is NOT a bounded change — reproducing
Ghidra's RPO requires ALSO aligning mosura's out-edge order + branch-normalization timing + block-boundary
splitting to Ghidra's, a multi-subsystem structural effort with broad, uncertain blast. Per the
coordinator's "clean park beats a rushed global CFG renumber," PARKED. switchloop's case order happening to
match is real (the fix is viable IN PRINCIPLE) but can't be reached without the entangled structural
alignment. RECOMMEND: park the processMultiplier unlock (turnkey `processmultiplier-brick.patch` stands),
OR pivot to the coordinator's mentioned audit A1. All probes reverted, tree clean @a2211f3.**

---

# cspec1 — A1 (cspec ProtoModel) + A2 (call-arg recovery) coupled campaign — 2026-07-19, @a2211f3, HELD/staged

**Topic note: this is the prototype-recovery/fspec subsystem, parked here at the coordinator's
request (not merge-cluster). Patches live in the mosura repo root.**

## State: SUITE-GREEN intermediate held for lead GO (NOT landed). Corpus 0.9445/57 (baseline 0.9480, A1-only 0.9419), jumptable 6/6, clippy 0, suite 462+integration all green.
Patches (apply to clean `a2211f3`, stacked): `cspec1-a1-protomodel.patch` (A1 only, 0.9419) → superseded by `cspec1-a1a2-argrecovery.patch` (A1 + the two arg-recovery bricks below, 0.9445).

## What A1 is (faithful, LANDS once wrong-code cleared)
Retires adaptation A1: decompiler now consumes a cspec-decoded `fspec::ProtoModel` (input/output ParamLists + EffectRecord list) instead of hardcoded `fspec::sysv_input/sysv_output/sysv_effect_list`. Decoder = `analysis/cspec.rs::default_proto_model` (faithful `ProtoModel::decode`, fspec.cc:2545). Carried on `Funcdata::proto_model`, populated in `build.rs` (laned precedent). Consumers: directwrite.rs, heritage.rs `guard_calls` (`has_effect`), recover.rs `resolve_call_output`, fspec.rs `recover_input_params`.
**Premise diff (verified):** input list IDENTICAL; output minsize 4→1 (cspec authoritative); **effect list DIFFERS** — cspec kills only RAX/RDX/XMM0 (+unaff RBX/RSP/RBP/R12-15 + retaddr), NOT the param regs RCX/RSI/RDI/R8/R9/XMM1-7 (x86-64-gcc `<input>` has no `killedbycall="true"` → autoKilledByCall=false). So caller-saved arg regs become `unknown_effect` PASSTHROUGH, not killedbycall creations. The old hardcoded kill-all-param-regs was the adaptation compensating for the missing passthrough-realism handling below.

## The two BRICKS built on A1 (both faithful, cited)
- **Brick R1 — setup-all-first in `resolve_call_args` (recover.rs):** set up EVERY call's `active_inputs` before checking any, so `check_call_double_use`/`checkCallDoubleUse` (funcdata_varnode.cc:1756) sees the OTHER call's active trials (Ghidra creates all `FuncCallSpecs::ParamActive` at heritage `guardCalls`, all `isInputActive` during ActionActiveParam). Fixes a legit cross-call double-use (piecestruct `&xStack_18`) being rejected → real arg dropped. **HEALED elseif, piecestruct, switchind, switchhide, loopcomment to baseline.**
- **Brick R2 — AncestorRealistic CPUI_INDIRECT reject (recover.rs `realistic_faithful`):** port funcdata_varnode.cc:2052-2054 — a killed-by-call (register) trial whose value flows THROUGH a *call* passthrough INDIRECT is `pop_fail` (invalid); guarded by `!isIndirectStore` (:2052) via the INDIRECT's `guarded_op` (STORE vs CALL). Drops the leaked `extraout_RSI` on a following call. Inert pre-A1 (regs were killedbycall creations). Test `arg_through_passthrough_indirect_is_realistic` → renamed `register_arg_through_call_passthrough_is_dropped` (old assertion codified pre-A1 behavior).

## REMAINING wrong-code (the deep piece — coordinator's S1-S3): multi-indirect-call arg ATTRIBUTION
- **deindirect (0.812) + indproto (0.967): SAME class.** Args recovered correctly BUT attached to the WRONG indirect call. deindirect: `(param_2+3,param_3+5)` lands on callind@0x100755 (block 2) not @0x100769 (block 1, where Ghidra puts them). indproto: `param_1` on the 1st indirect call not the 2nd. Root = append-all (`recover_call_args` appends all 6 arg regs to EVERY call) + the double-use resolution attributing to the earlier-processed call. Ghidra registers args per-heritaged-range at `guardCalls` via `characterizeAsInputParam` (heritage.cc:1495-1509, `opInsertInput`), so only the call whose block genuinely reads the value gets it.
- **FIX (S1-S3):** retire `recover_call_args` unconditional append; register input trials + `op_append_input` in `guard_calls` per heritaged range where `proto_model.input.characterize_as_param()==ContainsJustified` (whichTrial dedup; per-call `active_inputs` created at heritage — mosura's rename already links appended reads at ranges in `new_addrs`/cover, verified). Then `build_input_from_trials` must order by ParamList group not op_slot (guardCalls appends in address order). S5 = output side (`characterizeAsOutput`+isAutoKilledByCall+tryOutputOverlapGuard, heritage.cc:1469-1493).
- **partialsplit (0.910):** pre-existing A1 mover (cspec output-minsize/effect), NOT from R1/R2 — classify separately. **deindirect2 +0.044** (faithful model wins).

## Gate: HELD (wrong-code on deindirect/indproto). Land order once S1-S3 clears them: A1 + R1 + R2 + S1-S3 as one arc; then delete `fspec::sysv_*` literals + convert their machinery-tests. A fresh agent continues from `cspec1-a1a2-argrecovery.patch`.

## ★★★ arg1 — 2026-07-19 @a2211f3: S1-S3 PREMISE FALSIFIED (re-frame). The fix is `Funcdata::sortCallSpecs`, BUILT + suite-green + GATED (movers → lead GO). Turnkey = `cspec1-a1a2-sortcallspecs.patch`.
**PREMISE VERDICT: S1-S3 (per-heritaged-range `guardCalls` trial registration, retire append-all,
group-order build) is a RE-FRAME — it is NOT the fix.** Instrumented deindirect/indproto premise-first
(oracle `--ir`/`--c`, `capture_trace --trace`, mosura `--raw`, a reverted call-order/RPO probe):
- Ghidra's `guardCalls` DOES append the arg regs per-heritaged-range (`opInsertInput`, in ADDRESS
  order RDX/RSI/RDI — S3 confirmed), but it appends the SAME inputs to the SAME (both) calls that
  append-all does. Trace-proven: at the committing `activeparam` (DEBUG 223) BOTH calls read the
  identical reaching defs `RDI(...:a2),RSI(...:99)`. So per-range registration does NOT change which
  call keeps the arg — S1-S3 would not move deindirect.
- **TRUE MECHANISM (source + trace + probe proven): `Funcdata::sortCallSpecs` (funcdata.cc:516) +
  `compareCallspecs` (:504).** Ghidra sorts the call sites by BLOCK INDEX (structured RPO from
  `structureReset`/`findSpanningTree`) then within-block order, ONCE in `startProcessing` (:165, "Must
  come after structure reset"; comment: "Calls are put in dominance order so that earlier calls get
  evaluated first. Order affects parameter analysis."). `ActionActiveParam` iterates that order, and a
  cross-block double-use is attributed to whichever call is evaluated FIRST (the later call's
  `checkCallDoubleUse` sees the first's now-`isActive` trial and yields, funcdata_varnode.cc:1787).
  For deindirect/indproto the ELSE-branch call sits in the block Ghidra's RPO indexes FIRST even though
  its ADDRESS is HIGHER (deindirect: else 0x100765 = Ghidra block-idx 1 / mosura rpo=1; if 0x100751 =
  idx 2 / rpo=2). mosura evaluated calls in `op_ids()` = ADDRESS order → the fall-through (if) call won
  → args on the WRONG call. `recover_call_args` append-all is NOT the root (append-all is fine; Ghidra
  appends-all-then-trims too).
**BUILT (faithful, recover.rs `call_specs_in_dominance_order`, ~35 lines + doc):** sort the call list
`resolve_call_args` processes by (block reverse-postorder position from `dominator::postorder` — the
faithful stand-in for Ghidra's `getParent()->getIndex()`, since mosura numbers `BlockId` by ADDRESS,
cfg.rs:256), then `block_pos`. mosura ALREADY computes this RPO (dominator.rs) and it matches Ghidra's
structural block index for these fixtures (probe-verified: rpo puts else-call first). BOUNDED — NOT the
parked deep RPO-block-renumber (explicit1 part-5): only the call-processing SEQUENCE is reordered, no
block/heritage/phi renumber. + regression test `deindirect_args_land_on_correct_call`.
**MEASURED @a2211f3-dirty (combined A1+A2+sortCallSpecs): avg 0.9445→0.9482/57 (ABOVE clean baseline
0.9480), suite 509/0, jumptable 6/6, ir_parity 9/9, clippy 0.** sortCallSpecs ALONE (vs A1+A2 base)
moves EXACTLY TWO fixtures, ZERO collateral: **deindirect 0.812→1.000 (Ghidra-EXACT arg list on the
right call), indproto 0.967→1.000 (Ghidra-EXACT).** R1-healed set HOLDS (elseif/piecestruct/switchind
1.000, switchhide 0.996, loopcomment 0.929). NO wrong-code anywhere. vs the CLEAN 0.9480 baseline the
whole arc's only net movers: deindirect2 0.936→0.980 (+0.044, A2 faithful win) + partialsplit
0.941→0.910 (-0.031, PRE-EXISTING A1 cspec output-minsize/effect — NOT from sortCallSpecs, confirmed
unchanged by it; faithful-exposes = incomplete arg recovery on a direct call `func_0x00101000`, not
semantically-wrong code).
**GATE (movers ⇒ lead GO; gate-byte-identical-only): HELD. On GO land the WHOLE arc — A1 + R1 + R2 +
sortCallSpecs — as one coherent commit set, then delete `fspec::sysv_input`/`sysv_output`/
`sysv_effect_list` literals + convert their machinery-tests to the `proto_model` helper, and flip A1+A2
to RETIRED in adaptations-inventory + MEMORY.** Turnkey `cspec1-a1a2-sortcallspecs.patch` (repo root,
re-applies clean to a2211f3; supersedes `cspec1-a1a2-argrecovery.patch`). S5 (output-side
`characterizeAsOutput` single-trial) remains a separate backlog item, unrelated to this attribution
class. The literal S1-S3 (guardCalls per-range registration) is faithful-but-inert for this class and
should NOT be built as a fix for deindirect/indproto — retire it from the plan.
