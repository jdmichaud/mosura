---
name: task9-stage3-blocker
description: "Task #9 Stage 3 (wire SubVariableFlow driving rules) attempted and REVERTED — wiring the 5 subvar rules + SubZext/Piece2Zext regresses corpus (piecestruct 0.889->0.791, wrong direction) and crashes on an incomplete shadow op. Root-cause diagnosis + exact next step for a fresh agent. Base f59dc35."
metadata: 
  node_type: memory
  type: project
  originSessionId: c0fe6b35-0fb2-4ed2-90d8-ec93de63680c
---

# Task #9 Stage 3 — attempted, REVERTED to f59dc35 (do NOT re-wire until the trace bug is fixed)

Stage 2 (`f59dc35`, traceForward/traceBackward core opcodes) is solid and byte-neutral. Stage 3
(wire the driving rules — the corpus-changing payoff) was attempted and **reverted**: it regresses
the corpus and exposes a real correctness bug in the SubvariableFlow trace that the Stage-2 unit
tests did not catch. See [[task9-subvariableflow-plan]].

## What was done (saved as patches, reverted from the tree)
- Ported all 5 driving rules VERBATIM into `rules.rs` (faithful, cite subflow.cc): RuleSubvarAnd
  (1553), RuleSubvarSubpiece (1590), RuleSubvarCompZero (1628), RuleSubvarShift (1686),
  RuleSubvarZext (1710). `aggressive` is always false (mosura has no `Varnode::isPtrFlow`).
- Faithful oppool1 slots (calibrated to mosura's anchors RuleHighOrderAnd=25 / RuleHumptyOr=79 /
  RuleOrCompare=109): **RuleAndDistribute=26, RuleSubZext=74, RulePiece2Zext=103, RuleSubvarAnd=110,
  RuleSubvarSubpiece=111, RuleSubvarCompZero=114, RuleSubvarShift=115, RuleSubvarZext=116.** So the
  HELD rules go at their own slots (NOT appended): AndDistribute between RuleHighOrderAnd(25)/
  RuleAndPiece(28); SubZext between RuleZextShiftZext(70)/RuleHumptyDumpty(77); Piece2Zext between
  RuleLessEqual(99)/RulePopcountBoolXor(105). The 5 subvar rules append after RuleOrCompare(109).
- Patches in scratchpad (session c0fe6b35): `stage3_rules_and_wiring.patch` (292 lines = the 5 rules
  + pipeline wiring), `stage3_skipfix.patch` (30 lines = the do_replacement band-aid below). Re-apply
  to resume; the rule ports are correct, the problem is upstream in the trace.

## Result — REGRESSION, not convergence (so it was reverted)
Wired 5 subvar + SubZext + Piece2Zext (did NOT reach AndDistribute): corpus **0.8649/54 -> 0.8534/52**.
The EXPECTED gains DID appear — floatcast +0.044 (Piece2Zext converging), deindirect +0.039,
switchhide +0.019, elseif/forloop_withskip up — but they are swamped by regressions, and crucially
**the TARGET fixture piecestruct went 0.889 -> 0.791 (WRONG direction)**, plus namespace -0.163,
inline -0.111, orcompare -0.090, floatconv -0.066. A target-fixture regression = the transform emits
wrong output, not a convergence. trace-diff piecestruct: mosura 812 firings vs Ghidra 599,
propagatecopy 486-vs-161, dumptyhump +42 — downstream churn from a divergent graph.

## Root cause found (a real trace bug) — the "incomplete shadow op"
`SubvariableFlow::traceForward` INT_AND arm (subflow.cc:426) does
`rop=createOpDown(INT_AND,2,op,rvn,slot); createLink(rop,mask,-1,outvn)`. When `outvn` is "already
the logical value" (`size==flowsize && mask==calc_mask(flowsize)`), `set_replacement` sets
`inworklist=false, replacement=outvn`, so **outvn is never traced backward → the shadow AND's OTHER
operand slot is never filled** → a shadow INT_AND with only 1 input. `do_replacement` then
materializes a malformed 1-input INT_AND (and `op_set_output` orphans the original 2-input AND). A
LATER subvar rule tracing backward through that 1-input AND panics in `does_and_clear`
(`input(1).unwrap()` on None). Reproduced on **loopcomment**: RuleSubvarSubpiece seeds root = a
4-byte AND output with mask 0xff; forward-tracing an operand into a SIBLING AND@0x1007a2 (out 1 byte,
out_is_self) creates the incomplete shadow. Only triggers once SubZext/Piece2Zext are also wired
(they expose the sibling AND).

## Band-aid tried (in stage3_skipfix.patch) — insufficient
In `do_replacement`, skip materializing a shadow op whose input vector is incomplete
(`(0..numparams).any(slot missing)`) — such an op's output is `out_is_self` (used as-is), so the
original op already produces it. This STOPS the crash (60/60 run) but the corpus STILL regresses
(piecestruct 0.791) → the divergence is deeper than the crash; the trace itself diverges from Ghidra.

## The wall (unresolved) — the exact thing a fresh agent must settle
Ghidra fires subvar 28x on loopcomment WITHOUT crashing (oracle: subvar_zext/subpiece/compzero all
fire). By my reading BOTH Ghidra and mosura propagate mask 0xff into the sibling AND, making outvn
`out_is_self`, so Ghidra SHOULD hit the same incomplete shadow — yet doesn't crash and produces good
output. So EITHER (a) Ghidra's upstream graph/mask differs (mosura propagates 0xff where Ghidra
propagates a narrower mask → outvn NOT out_is_self → outvn worklisted → shadow completed), OR (b)
Ghidra materializes the incomplete op differently (its `newOp(numparams)` leaves a null slot that is
somehow harmless). Could not resolve analytically from subflow.cc alone.

## NEXT STEP (definitive): instrument Ghidra
Add debug to the real `subflow.cc` (traceForward INT_AND createOpDown, and set_replacement's
inworklist decision), rebuild `oracle/capture_trace`, and run loopcomment to observe: does Ghidra
reach the createOpDown-with-out_is_self case? If NOT, the divergence is an upstream mask/graph
difference (compare the mask mosura vs Ghidra propagate to the sibling AND). If YES, see exactly how
Ghidra's doReplacement materializes the incomplete shadow. THEN fix the mosura transfer to match —
do not keep the skip band-aid. Only after piecestruct CONVERGES (toward 0.889 / CONCAT form) with
zero target regressions should the rules be committed. AndDistribute (slot 26) still un-wired; wire
it LAST and watch for a RuleHumptyOr ping-pong hang.
CAVEAT on this step: `oracle/capture_trace` links the SHARED `libdecomp_dbg.a` (186MB, no .o's
present → a from-scratch decompiler rebuild). Instrumenting = recompile subflow.cc and `ar r` it into
a COPY of the archive, link a throwaway trace binary against the copy — do NOT mutate the real oracle
(capture/capture_trace must stay pristine per AGENT.md). This is invasive; get the lead's OK first.

## Session-2 re-confirmation (2026-07-02, same session id) + sharper conclusion
Re-attempted from `f59dc35`; independently reproduced the SAME blocker; **reverted, tree clean, 198
green.** New data points that sharpen the root cause:
- **The 5 driving rules ALONE are GREEN + no hang** (corpus 0.8649→0.8627, piecestruct stays 0.889).
  So the crash is NOT the driving rules — it's the driving+held interaction.
- **SubZext ALONE (without Piece2Zext or AndDistribute) already triggers the crash** on loopcomment,
  and separately regresses x86_64_sem output (printc `emits_c_for_a_straight_line_function`:
  `param_1*3 + -5 + (param_2>>2)` no longer emitted). So it is not AndDistribute-specific and not a
  ping-pong; it is SubZext reshaping the graph so a driving rule (RuleSubvarCompZero, seeded from an
  INT_NOTEQUAL) traces forward through `AND(nonconst,nonconst)` → the createOpDown gap.
- **Decisive**: the prior band-aid already showed fixing only the crash leaves piecestruct at 0.791
  (still divergent). Combined with Ghidra shipping CLEAN loopcomment C (no malformed op) and the plan +
  RuleAndDistribute doc both flagging mosura's STALE mid-pool nzmask, the weight of evidence is
  hypothesis (a): **upstream mask divergence → this is blocked on Task #10 (nzmask/consume refreshed
  mid-pool), not a subvarflow port bug.** subvarflow forward-AND matches subflow.cc byte-for-byte.
- RECOMMENDATION to lead: don't re-wire Stage 3 until Task #10 (mid-pool mask freshness) lands, OR
  authorize the (invasive) Ghidra instrumentation above to convert hypothesis (a) from strong-evidence
  to proof. A crash-only guard is not enough (corpus still regresses). See [[task9-subvariableflow-plan]] Stage-3.

## Session-3 (2026-07-02): Task #5 mask-freshness GROUNDED + DISPROVEN. The blocker is NOT freshness.
Lead approved grounding+planning Task #5 (mid-pool nzmask/consume freshness) as the presumed Stage-3
prerequisite. Grounded it against Ghidra and **empirically disproved that freshness is the cause** —
so Task #5 as framed will NOT unblock Stage 3. Tree reverted, 198 green.

GHIDRA CADENCE (coreaction.cc:5462 universalAction): `actmainloop` is a `rule_repeatapply` ActionGroup
= [ActionUnreachable, ActionHeritage, …, **ActionDeadCode(5503, computes consume)**, …, **ActionNonzeroMask(5507)**, ActionInferTypes, **oppool1(5511, rule_repeatapply)**, …]. So deadcode+nonzeromask run ONCE per
mainloop iteration, BEFORE oppool1; oppool1 fixpoints internally with NO mask refresh inside it; the
mainloop repeats the whole thing to fixpoint. `Varnode::getNZMask()` (varnode.hh:231) is a plain
cached field `return nzm` — NOT lazily recomputed. A fresh Varnode is constructed with `nzm=~0`
(varnode.cc:601) = widest.

MOSURA ALREADY MATCHES THIS: universal_action (pipeline.rs:241) hand-unrolls the mainloop 3× — each
pass is [ActionNonzeroMask, ActionConsume, default_rule_pool()(rule_repeatapply), ActionDeadCode].
Fresh varnodes get `nzm = calc_mask(size)` (funcdata.rs:196) = widest, same as Ghidra. So mosura's
mask-refresh cadence AND fresh-varnode init already equal Ghidra's. There is no literal "mid-pool
freshness gap" — neither refreshes inside an oppool fixpoint.

PROTOTYPE (disproof): wired 5 driving + SubZext, added a refresh of calc_nzmask+calc_consume at the
start of EVERY ActionPool round (strictly fresher than Ghidra). **Crash PERSISTS** (subvarflow.rs:482).
→ freshness does not affect the malformed-AND. Then replaced the forward-AND/OR `create_op_down`
branches with `return false` (abort the unrepresentable down-op): **crash stops, but corpus REGRESSES —
piecestruct 0.889→0.779, avg 0.8649→0.8484, 51/60**, and the `piecestruct_folds_shifts_to_concat`
assertion fails. trace-diff piecestruct with that guard: **subvar_zext ghidra=12 vs mosura=1**,
subvar_subpiece 8 vs 14 (over-fires), shiftpiece 4 vs 1, andzext 4 vs 1, dumptyhump mosura=50 (Ghidra
far fewer). The abort-guard SUPPRESSES 11 of 12 legitimate subvar_zext flows (they route through a
forward-AND/OR-down) → so the forward-AND/OR-down IS reached by legitimate flows; it is not an
"unreachable" case.

SHARPENED ROOT CAUSE (supersedes the "Task #10 mask" hypothesis above): the divergence is STRUCTURAL,
not mask-freshness. mosura's subvar flows route through a forward-AND/OR of two NON-constant operands
(subflow.cc:401/407/426 createOpDown, whose non-traced operand is never linked) where Ghidra's do not;
Ghidra fires subvar_zext 12× / subvar_subpiece 8× on piecestruct and ships clean C. The real question
is WHY mosura's pre-subvar graph presents that form — an upstream graph-shape difference (NOT masks;
proven). Answering it needs an IR-level comparison of mosura vs Ghidra at the subvar seed points on
piecestruct/loopcomment (the Ghidra subflow.cc instrumentation, or a mosura-side IR dump correlated to
Ghidra `--c`/`--ir`). NEXT AGENT: do NOT pursue Task #5 (freshness) — it is disproven. Investigate the
structural graph divergence directly. subvarflow forward-AND/OR-down handling also warrants a hard look
(it builds an incomplete op for any non-constant other operand — Ghidra has the same shape but never
reaches it, so mosura reaching it is the symptom, not the disease).

## Session-4 (2026-07-02): VERDICT = (ii) UPSTREAM DIVERGENCE. The exact divergent op is NAMED. subvarflow.rs is NOT the fix site.
Diagnostic-first task (no re-wire, no oracle rebuild). Line-by-line re-read of subflow.cc vs subvarflow.rs
+ sanctioned oracle dumps (`oracle/capture … --c/--ir`) + mosura IR dump (`cargo run --example dump --
loopcomment --ir` / `--prestack`). Tree clean, 198 green, base 6f62b45. Findings:
- **The port is FAITHFUL.** The forward down-AND's 2nd operand is filled ONLY by traceBackward-of-the-
  OUTPUT (createOp returns the existing def set by the forward createLink slot=-1, then links BOTH slots:
  subflow.cc:684-694 / subvarflow.rs:873-890). That runs ONLY if the output is worklisted, i.e. NOT
  out_is_self. For a 1-byte AND output with a full-byte mask, out_is_self ALWAYS holds (size==flowsize==1,
  mask==calc_mask(1)==0xff, consume⊆0xff trivially) → output never worklisted → down-AND stays 1-input in
  BOTH Ghidra and mosura. do_replacement then materializes a malformed op in BOTH (mosura: 1-input AND
  → later does_and_clear input(1) panics; Ghidra: newOp(2) with a null in1 → would null-deref). setReplacement
  out_is_self (66/259), createOpDown (184/295), createLink slot-1 (1030/312), traceForward-AND (411/607),
  do_replacement input loop (1473/1128) all match. So mosura is NOT failing to link where Ghidra links.
- **Ghidra ships CLEAN C on loopcomment** (verified) and its IR has NO INT_AND at all post-pool (analysis/
  cleanup snapshots empty of `&`), and NO size-mismatched/1-byte-nonconst AND at any stage. So Ghidra
  NEVER reaches the incomplete-down-AND → the graph mosura feeds subvar differs. = (ii).
- **THE DIVERGENT OP (directly observed, mosura loopcomment IR, subvar OFF):**
  `0x1007a2:228  u0xdff00:1 = INT_AND u0x10098:4 u0x100b1:1` — a SIZE-INCONSISTENT INT_AND: in0 = the
  4-byte `EAX&EDX` result (u0x10098:4, from `0x1007a0:218 u0x10098:4 = INT_AND u0x10090:4 u0x10094:4`),
  in1 = its own 1-byte SUBPIECE (u0x100b1:1 = SUBPIECE u0x10098:4 #0). BOTH operands non-constant → this
  is the exact op subvar forward-traces into (out_is_self 1-byte) → incomplete down-AND → crash. Renders in
  printc as `xVar1 & (uint1)xVar1` (final C line: `while ((xVar1 & (uint1)xVar1) != 0)`).
- **It is the `test al,al` at 0x1007a2.** Ghidra lifts+keeps it as `AL:1 & AL:1` (equal-size), recovers to
  boolean `bool1 && bool2` (Ghidra final IR: `u…:1 = bool && bool`; clean C `10 < iStack_28 && aiStack_1c[0]
  < 100`). **mosura's RAW LIFT is CORRECT too**: `0x1007a2:228 u0xdff00:1 = INT_AND r0x0:1 r0x0:1` (AL&AL,
  both 1-byte). The malformation is introduced by a mosura PIPELINE step (heritage/rule), NOT the SLEIGH lift
  and NOT subvarflow: the two identical AL reads (r0x0:1, low byte of the 4-byte r0x0 def at 0x1007a0:218)
  resolve DIFFERENTLY — one truncated to SUBPIECE(u0x10098,0)=u0x100b1:1, the other bound to the wide
  u0x10098:4 — yielding a 4-byte∧1-byte AND. This is a sub-register (AL-over-EAX) read-resolution/heritage
  defect upstream of subvarflow.
- **Fix site = the upstream heritage/read-resolution, NOT subvarflow.rs.** A crash-only guard in do_replacement
  is insufficient (prior band-aid → piecestruct 0.791) because the corrupt AND still misleads subvar's
  narrowing across fixtures. NEXT (GATED by lead): hunt which mosura pass turns `INT_AND r0x0:1 r0x0:1` into
  `INT_AND u0x10098:4 u0x100b1:1` (candidate: heritage refinement / SUBPIECE-insertion when a byte read
  overlaps a wider def; or a simplify rule on `x & subpiece(x)`). Do NOT re-wire Stage 3 until that op lifts
  clean. Reproduce: `cargo run -q --example dump -- loopcomment --ir` (op 130) vs `--prestack` (raw op 231,
  clean) vs `oracle/capture <ghidra> …/datatests/loopcomment.xml --c/--ir -`.

## Session-5 (2026-07-02): CULPRIT GROUNDED + FIX PROTOTYPED (uncommitted, reverted, lead gates). It's RuleSelectCse, not heritage.
Lead asked to ground the exact pass + report a fix plan with blast (do NOT land — "core heritage, high-blast"). Result:
the pass is **RuleSelectCse (CSE), NOT heritage**, and the fix is a faithful one-liner with tiny, positive blast.
- **Heritage is CORRECT.** Staged dump (throwaway `examples/stagedump.rs`, since removed) shows after heritage the two
  AL reads are both `SUBPIECE r0x0:8 #0`:1 and the AND is size-consistent `INT_AND u0x100b0:1 u0x100b1:1` (1,1,1). The
  `rule pool sweep 1` malforms it.
- **CULPRIT: `RuleSelectCse::apply_op` (rules.rs ~643-679).** Its equality test checks opcode+parent+num_inputs+input
  VALUES (`same_value`) but **omits an OUTPUT-SIZE check**. So two `SUBPIECE r0x0:8 #0` ops that share inputs but
  truncate to different widths — the x86 **AL:1 vs EAX:4 sub-register reads** — are judged equal and MERGED: the 1-byte
  AL SUBPIECE (u0x100b0) is destroyed and the AND's operand repointed to a 4-byte EAX SUBPIECE → the size-mismatched
  `INT_AND u0x10098:4 u0x100b1:1`. Confirmed in MOSURA_TRACE (selectcse firings ~DEBUG 161/165 on loopcomment; `100b0`
  vanishes from the trace = merged away).
- **Ghidra guards exactly this** (`PcodeOp::isCseMatch`, op.cc): `if (output->getSize() != op->output->getSize()) return
  false;` and folds `output->getSize()` into `getCseHash`. mosura's OTHER CSE path (`cse_find_in_block` via
  `functional_equality_level0`) already checks size (`if a.size != b.size return -1`) — so the gap is ONLY RuleSelectCse.
- **THE FIX (faithful, ~4 lines):** in RuleSelectCse, right after `let Some(other_out)=…output`, add
  `if data.vn(out).size != data.vn(other_out).size { continue; }` (ports isCseMatch's output-size guard).
- **MEASURED blast (prototyped, then reverted — tree clean at 6f62b45, 198 green):** corpus **0.8649→0.8659, 54/60
  unchanged**; ONLY TWO fixtures move, both UP: loopcomment 0.740→0.762 (+0.022), switchloop 0.724→0.762 (+0.038); every
  other fixture byte-identical; existing `selectcse_merges_duplicate_subpieces` test still green (it merges SAME-size :4
  subpieces). The malformed AND now lifts clean: `AL & AL` → `COPY AL` (x&x=x). LOW blast, strictly toward Ghidra.
- STATUS: fix NOT landed (lead gates). Once landed, re-test Stage 3 wiring (the malformed AND was the crash seed; expect
  the subvar forward-AND-of-nonconst to no longer be reached on loopcomment).

## Session-6 (2026-07-02): CSE guard LANDED (8dd6d80). Stage 3 re-attempted → crash gone but STILL net-regresses; NOT committed.
Lead approved+committed the CSE guard as **8dd6d80** (on 6f62b45; corpus 0.8649→0.8659, 198 green). Then re-attempted
Stage 3 (re-ported the 5 driving rules RuleSubvarAnd/Subpiece/CompZero/Shift/Zext into rules.rs from subflow.cc:1553-1721;
RuleSubvarSext deferred — sext tracer still stubbed; wired them + SubZext(74)/Piece2Zext(103)/AndDistribute(26) at the
Ghidra coreaction.cc:5536-5628 slots). RESULT — **reverted, tree clean at 8dd6d80, NOT committed** (lead gates zero-regression):
- **Crash GONE.** loopcomment decompiles clean, no crash/hang, emits Ghidra's `while (10 < xStack_28 && xStack_1c <= 99)`
  (the malformed `xVar1 & (uint1)xVar1` is gone). So the CSE fix DID resolve the loopcomment crash seed.
- **RuleAndDistribute HANGS (ping-pong) on orcompare + piecestruct** — confirmed by bisect (removing it clears both). Matches
  the long-standing AndDistribute/HumptyOr ping-pong warning. Left UNWIRED; it's a separate canonicalization-fight blocker.
- **The 7 that run (5 driving + SubZext + Piece2Zext) NET-REGRESS: corpus 0.8659→0.8543 (11 up / 16 down / 33 same).**
  SAME regression pattern as the pre-CSE attempt: piecestruct 0.889→0.791 (WRONG way), namespace 1.000→0.837, inline
  1.000→0.889, orcompare 0.929→0.839, floatconv 0.578→0.512; gains floatcast +0.044, deindirect +0.039, switchhide +0.019.
- **trace-diff piecestruct (mosura 812 vs Ghidra 599 firings):** subvar_zext 12 vs **7** (under), subvar_subpiece 8 vs **15**
  (OVER), piece2zext 19 vs **4** (under), andzext 4 vs 1, shiftpiece 4 vs 1. mosura fires subvar_subpiece at 0x100756/0x100762
  where GHIDRA fires subvar_zext → the SEED SELECTION differs → the pre-subvar graph STILL diverges at MULTIPLE sites (the
  CSE bug was ONE of several). Also addmultcollapse 33 vs 1 (Task #3: RuleAddMultCollapse not in main pool) may feed subvar a
  divergent graph.
- CONCLUSION: CSE guard is a real standalone win (kept, 8dd6d80). Stage 3 is NOT ready — the remaining subvar_subpiece-over /
  piece2zext-under structural divergence needs the SAME method as the CSE find (IR compare mosura vs Ghidra at the piecestruct
  seeds 0x100748/0x100756/0x100762 cluster) to locate the next divergent op(s). AndDistribute ping-pong is its own blocker.
  Re-port of the 5 driving rules is verbatim/correct (loopcomment converges) — keep it for when the graph diverges are fixed.

## Session-7 (2026-07-02): (b) DISPROVEN + STRATEGIC PIVOT — Stage-3 wiring is REDUNDANT/net-negative for mosura's current rules.
Investigated the lead's (a)-vs-(b) fork. Both experiments prototyped uncommitted, reverted, tree clean at 8dd6d80.
- **(b) Task #3 first is DISPROVEN as a subvar unblock AND harmful standalone.** Prototyped RuleSub2Add(42)+
  RuleAddMultCollapse(52) into the main pool: **breaks 4 jumptable/switch tests (build.rs) + corpus 0.8659→0.7904, 47/60.**
  Confirms pipeline.rs's note that RuleSub2Add is deliberately kept in ptrarith_pool. RuleAddMultCollapse ALONE: **198 green,
  corpus EXACTLY 0.8659 (neutral)** — so its 33-vs-1 firing gap on piecestruct is a DOWNSTREAM SYMPTOM of subvar re-shaping
  the graph, NOT a cause. → Task #3 will not reduce the subvar divergence; it's independently risky. Don't do (b) for subvar.
- **DECISIVE PIVOT (piecestruct): mosura ALREADY produces Ghidra's byte-packing WITHOUT subvar.** At 8dd6d80 (subvar off)
  mosura's piecestruct C has `xStack_18 = CONCAT22(param_2,param_1); xStack_14 = CONCAT31(CONCAT21(CONCAT11(param_6,param_5),
  param_4),param_3);` — **line-for-line identical to Ghidra's**. The org rules (ShiftPiece/HumptyDumpty/DumptyHump/AndPiece)
  already dissolve the packing. The remaining 0.889-vs-Ghidra gap is (1) param TYPES (mosura xunknown8 vs Ghidra xunknown2/1)
  and (2) stack-canary/FS_OFFSET recovery (mosura `xVar1` unrecovered FS base, `x ^ y != 0` vs `x != y`, spurious `return
  xVar2`) — BOTH unrelated to subvar. So wiring subvar RE-transforms the already-correct SUBPIECEs (subvar_subpiece over-fires
  at the 0x100748/0x100756 CONCAT sources) → regresses 0.889→0.791. The piecestruct "divergence" is NOT a bounded malformed-op
  bug — it's subvar being REDUNDANT+divergent where mosura's existing rules already match Ghidra.
- **NET PICTURE of Stage-3 wiring on mosura's CURRENT ruleset:** helps where org rules fall short (floatcast +0.044, deindirect
  +0.039, switchhide +0.019) but regresses where they already succeed (piecestruct -0.098, namespace -0.163, inline -0.111,
  orcompare -0.090, floatconv -0.066) → net -0.0116. Not one bug; structural double-transform. The Task #9 plan premise
  ("mosura's graph doesn't canonicalize byte-packing like Ghidra") is now OUTDATED — mosura's rules evolved (Task #7 per-op
  priority etc.) to produce the CONCAT forms WITHOUT subvar.
- **RECOMMENDATION to lead: SHELVE Stage-3 wiring.** The CSE guard (8dd6d80) was the real win from this line of work. Keep the
  subvar SUBSYSTEM (Stages 0-2, byte-neutral infra) but do NOT wire the driving rules — they net-regress. The open-ended
  per-site reconciliation of (a) is not worth it when the target fixture (piecestruct) doesn't even need subvar. Revisit only
  if a fixture that ONLY subvar can fix becomes a priority (floatcast/deindirect) — and even then wire selectively + gated.

## Session-8 (2026-07-02): lead said CONTINUE to DONE. Found the CONCRETE piecestruct regression MECHANISM. CHECKPOINT (context loading up).
Lead overrode the shelve rec — drive Stage 3 to done, hunt each divergence. Re-wired Stage 3 (5 driving + SubZext@74 +
Piece2Zext@103, AndDistribute held) and captured the EXACT piecestruct regression:
- **subvar-OFF (8dd6d80): `xStack_14 = CONCAT31(CONCAT21(CONCAT11(param_6,param_5),param_4),param_3);`** (clean, = Ghidra).
- **subvar-ON: `xStack_14 = ((param_6 << 8 | param_5 & 0xff) << 8 | param_4) << 8 | param_3;`** (shift-or, ugly, 0.791).
  BUT subvar-ON also FIXED param types (now `xunknown2 param_1..xunknown1 param_6` = Ghidra). So subvar helps types, hurts CONCAT.
- **MECHANISM:** subvar turns the clean PIECE packing into a `zext(a)<<8 | <lowpiece>` shift-or chain. The reassembly rule
  RuleShiftPiece (rules.rs:1356) would turn `zext(a)<<8 | zext(b)` back into PIECE — BUT mosura's low piece is
  `INT_AND r0x80:4 #0xff` (an AND-mask), not `zext(b)`. Subvar-wired IR at the packing (0x1007ac):
  `u0x1010f:4 = INT_AND r0x80:4 #0xff:4` then `INT_OR (zext<<8) (that AND)`. RuleShiftPiece requires the low piece to be
  INT_ZEXT (only other case = CDQ sign-ext INT_SRIGHT) → the `&0xff` low piece is rejected → shift-or survives → renders ugly.
- **RuleShiftPiece is FAITHFUL** — verified Ghidra `RuleShiftPiece::applyOp` (ruleaction.cc) ALSO requires the low piece to be
  CPUI_INT_ZEXT (same CDQ exception). So the gap is UPSTREAM: mosura presents `X & 0xff` low pieces where Ghidra presents
  `zext(subpiece(X)):1`. Ghidra never feeds ShiftPiece an AND-mask low piece.
- **PRIME SUSPECT (unverified): RuleSubZext converts `zext(subpiece(X,0))` → `X & mask`** (rules.rs RuleSubZext body:
  `op_set_opcode(op, IntAnd); op_append_input(op, constvn)`). If SubZext fires on subvar's zext low-pieces and rewrites them to
  `&0xff` BEFORE ShiftPiece reassembles, that's the block. CAVEAT: trace-diff shows subzext mosura=23 vs ghidra=26 (mosura fires
  FEWER, not more) — so it may be a WHERE/ordering issue, or the `&0xff` comes from RuleAndZext/RulePiece2Zext/subvar's own
  extension patch, not SubZext. NOT yet confirmed which rule emits `u0x1010f = INT_AND r0x80 #0xff`.
- **NEXT EXPERIMENTS (cheap, from a fresh re-wire):** (1) wire Stage 3 MINUS SubZext → does piecestruct CONCAT survive / beat
  0.791? (2) if not, MOSURA_TRACE the piecestruct packing region and find which rule firing creates `INT_AND r0x80 #0xff` at
  0x1007ac. (3) compare mosura RuleSubZext / RuleAndZext / RulePiece2Zext guards vs Ghidra ruleaction.cc for a missing
  loneDescend/context guard. The fix is likely a rule-interaction/ordering bounded fix OR a missing guard — this is the concrete
  lead to chase, NOT the whole "structural" wall.
- **RE-WIRE NOTE: the saved scratchpad `stage3_wiring.patch` is EMPTY/broken** (git diff hit an external difftool). To re-wire,
  redo the manual edits: `use super::subvarflow::SubvariableFlow;` in rules.rs; the 5 driving rule structs (verbatim from
  subflow.cc:1553-1721, code in Session-6 notes + this session's edits); pipeline.rs import + pool slots SubZext(74)/
  Piece2Zext(103)/RuleSubvar{And,Subpiece,CompZero,Shift,Zext}(110-116). AndDistribute stays OUT (RuleHumptyOr ping-pong hang).
- BANKED: CSE guard 8dd6d80 (corpus 0.8659, 198 green). Tree clean at 8dd6d80.

## Session-11 (2026-07-04, base 640bdab — tryReturnPull committed 936afcc): re-wired 5 driving rules WITH tryReturnPull ACTIVE. NOW +0.0021 and DELIVERS int4 returns.
CRUCIAL: with tryReturnPull in-tree, RuleSubvarZext ACTUALLY narrows returns (never happened in 8 prior sessions — RETURN arm was a stub). Differs materially from Session-10's +0.0008:
- baseline 640bdab **0.8804** → +5 driving rules (slots 110-116) **0.8825 (+0.0021)**, 54/60, NO crash. Return-width WORKS: twodim `uint8`→`uint4 func()`, wayoffarray `xunknown4` (signedness uint4-vs-int4 = separate type-infer nuance).
- DOWN only loopcomment -0.042; UP union_datatype +0.036, forloop_withskip +0.034, elseif +0.031, noforloop_globcall +0.019, switchhide +0.017, forloop_varused +0.016, pointerrel +0.006, varcross +0.004. 9 up/1 down.
- 179 lib green (+3: subvarflow subvar_zext_narrows_a_zext_fed_return + try_return_pull_refuses_when_upper_bytes_consumed; rules subvar_zext_rule_narrows_a_zext_fed_return). SubZext/Piece2Zext STILL HELD.
- CORRECTION: the +0.0021 5-rule config has a REAL BUG in RuleSubvarZext — narrowed returns get UNIQUE storage not the register EAX. proto_recovery twodim/modulo FAIL (output=u0x23d00 not RAX r0x0); ir_parity x86_64_sem merge shifts (Zext fires on internal ZEXTs too). ROOT: `use_same_address` (subvarflow.rs:363) returns false for addrtied RAX → `get_replace_varnode` (:434) mints a unique; Ghidra lands the narrowed return at EAX (register) → recover.rs records register; mosura records the unique's addr. Non-Ghidra bug (addrtied/use_same_address and/or recover.rs recording varnode-addr not candidate-register).
- THE 4 OTHER driving rules (And/Subpiece/CompZero/Shift, slots 110-115; NO Zext) are CLEAN: **corpus 0.8812 (+0.0008)**, ALL tests green (proto_recovery 3/3, ir_parity, 184 lib, 6 corpus, 62/62). LANDABLE.
- STATUS: tree = clean 4-rule state (RuleSubvarZext HELD in pool w/ bug note; struct+unit test stay defined, unwired). Reported to lead: land 4 clean rules (+0.0008); hold+fix RuleSubvarZext (delivers #12 once addrtied fixed). Tests added: subvarflow return-pull path (narrow/consume-refusal/slot-0) + per-rule (Zext fire, Subpiece fire, And/CompZero/Shift guard). NEXT: RuleSubvarZext addrtied fix → loopcomment -0.042 → RuleShiftPiece low-piece.
- x86_64_sem ORACLE-VERIFIED (lead asked (a)-more-faithful vs (b)-regression): Ghidra `--c` = `int4 func(int4 param_1,int4 param_2){return param_1*3 + -5 + (param_2>>2);}`. mosura 4-rule(Zext off) = `uint8 func(int8 param_1,int4 param_2)` (return 8-byte). mosura 5-rule(Zext ON) = `xunknown4 func(int8 param_1,int4 param_2)` — return NARROWED 8→4 toward Ghidra's int4. Body byte-identical all 3. ⇒ (a): RuleSubvarZext moves x86_64_sem return TOWARD Ghidra; the ir_parity merge shift (covers 12→10, no collapse) is benign (SubvariableFlow dissolves redundant SSA versions). So when RuleSubvarZext lands, ADAPT the merge test for x86_64_sem (cited, strengthen per pointerrel precedent) — it's stale, not a regression. The ONLY real blocker for Zext = the return-STORAGE-as-unique bug. CAUTION: `git checkout -- <file>` on the shared tree WIPES uncommitted wiring (bit me once — pipeline.rs; use --no-ext-diff for diffs, and re-apply from context).

## Session-12 (2026-07-04, base 153149a = 4 rules LANDED): RuleSubvarZext storage-bug premise FALSIFIED by instrumentation. Real cause = copy-prop eats the subvar return-COPY.
- **PREMISE FALSIFIED (instrumented):** `use_same_address` (subvarflow.rs:357) is byte-identical to Ghidra useSameAddress (subflow.cc:1274). Instrumented RuleSubvarZext on twodim: seed (ZEXT out r0x0:8) is **addrtied=FALSE** → use_same_address returns true → subvar CORRECTLY creates `EAX:4=COPY(u); return EAX` (INT_ZEXT backward, subvarflow.rs:961-975), matching Ghidra. use_same_address/getReplacementAddress is NOT the bug.
- **REAL CAUSE:** twodim final IR (Zext ON) = `RETURN r0x288:8 u0x23d00:4` — EAX GONE; RulePropagateCopy propagated `u` INTO the RETURN, eating the subvar `EAX=COPY(u)`. Ghidra KEEPS EAX (return reads register). So resolve_return records u's addr (unique) not RAX. = SAME copy-prop-into-return divergence as #12/#13 (propagatecopy 110-vs-56).
- **FIX SITE (grounding needed, NOT use_same_address):** why Ghidra's `EAX=COPY(u)` survives copy-prop at a RETURN. Ghidra order: ActionReturnRecovery(coreaction.cc:5500) BEFORE oppool1(5511) — return committed at register first, then subvar narrows; committed return value resists copy-prop (isReturnCopy gate / addrforce). Ground Ghidra RulePropagateCopy return gates + committed-return addrforce before code.
- STATUS: reported FALSIFICATION to lead (stop+report on falsify, per instruction). RuleSubvarZext STAYS HELD. 4 rules landed 153149a, tree clean. Awaiting steer: ground copy-prop-return gate vs park Zext for loopcomment/ShiftPiece.
- LOOPCOMMENT -0.042 DIAGNOSED (instrument-first C-diff 640bdab vs 153149a + trace-diff): MIXED, not a pure regression. The 4 rules IMPROVE param types (`xunknown8 param_1, uint8 param_2` → `uint4 param_1, int4 param_2` — param_2 now == Ghidra int4) BUT eliminate the param→stack-spill copies Ghidra retains (Ghidra keeps `aiStack_1c[0]=param_1; iStack_20=param_2;`; mosura drops them + the iStack_20 local, uses params directly) → structural divergence nets -0.042 despite the type gain. Likely culprit RuleSubvarSubpiece. The `while ((CONCAT71(uStack_28,10<uStack_28) & uStack_24)!=0)` mangling is PRE-EXISTING (present at 640bdab) — separate held-Zext/SubZext/Piece2Zext issue (Ghidra fires subvar_zext 15×/subzext 15×/piece2zext 16× to dissolve it to `&&`); the RuleShiftPiece low-piece fix (next) unblocks those and cleans it. Verdict: 4 rules STAY (net +0.0008, more type-faithful); loopcomment stack-spill divergence = tracked, tied to the addrtied theme. Reported to lead; proceeding to RuleShiftPiece low-piece next.

## Session-13 (2026-07-04, base 153149a): r0x80/RuleShiftPiece PREMISE FALSIFIED. SubZext+Piece2Zext's WHOLE drag = the return-width (RAX:8-vs-EAX:4) divergence, which RuleSubvarZext fixes. Un-hold order is INVERTED.
Turnkey step was "fix r0x80 read-resolution (piecestruct low piece → RuleShiftPiece reassembly) → un-hold SubZext+Piece2Zext". Reproduced by TEMP-wiring SubZext@74+Piece2Zext@103 (never committed; reverted, tree clean 153149a, 219 green). Instrument-first (dump --ir / --prestack + oracle capture --c/--ir + full corpus per-fixture diff):
- **PREMISE FALSIFIED — piecestruct is CLEAN.** With SubZext+Piece2Zext wired, piecestruct = 0.889 UNCHANGED, final IR `PIECE r0x88:1 r0x80:1` (clean CONCAT, byte-matches Ghidra). NO `INT_AND r0x80:4 #0xff`, NO shift-or mangle. The Session-8/12 r0x80 low-piece observation no longer reproduces at HEAD (the 4 landed subvar rules + a working RuleShiftPiece already dissolve/reassemble it). So r0x80 read-resolution is NOT the blocker; there is NO ShiftPiece low-piece fix to make for piecestruct.
- **REAL DRAG = return width.** SubZext+Piece2Zext net -0.0040 (baseline 0.8812 → 0.8772, 54/60). ALL 6 regressors are functions where Ghidra returns 4-byte but mosura returns RAX:8: namespace -0.163 (Ghidra `int4`, was perfect 1.000), orcompare -0.090 (Ghidra `char`), floatconv -0.066, ifswitch -0.039 (`int4`), modulo -0.037 (`int4`), impliedfield -0.027; + breaks unit test printc `emits_c_for_a_straight_line_function` (x86_64_sem). Two signatures, same root: `CONCAT44(upper-RAX-garbage, realvalue)` (namespace/orcompare/modulo) and `... & 0xffffffff` truncation (ifswitch/modulo/x86_64_sem returns). SubZext/Piece2Zext (FAITHFUL) reconstruct the upper-half byte-packing that the too-wide 8-byte RETURN consumes; Ghidra's 4-byte return never consumes the upper half. GAINS (10 up) are real: floatcast +0.064, deindirect +0.047, union_datatype +0.036, nan +0.022, noforloop_iterused/globcall, elseif, partialsplit.
- **PROOF the fix is return-narrowing (RuleSubvarZext):** TEMP-wiring ONLY RuleSubvarZext (no SubZext/Piece2Zext) narrows namespace to **`int4 func(int4 param_1){ ... return param_1 + iRam...; }` — byte-perfect vs Ghidra** (return IR `RETURN r0x288:8 u0x10108:4`, a 4-byte value). Ghidra late IR (oracle `--ir cleanup`) confirms `return(#0x0) EAX` (4-byte); mosura baseline `RETURN r0x288:8 r0x0:8` (RAX:8). So RuleSubvarZext IS the mechanism that resolves these regressors.
- **CAVEAT (ordering interaction):** wiring all 3 (SubZext@74+Piece2Zext@103+RuleSubvarZext@116) does NOT narrow namespace (still CONCAT44) — SubZext/Piece2Zext run EARLIER in the pool and reshape the return's clean `RAX=ZEXT(EAX)` into a `PIECE(leftover, val)` before RuleSubvarZext@116 can seed on the ZEXT. Ghidra avoids this because its return is committed to EAX:4 by return-recovery (mainloop) before the packing survives. So landing RuleSubvarZext is necessary but the pool-ordering/mainloop-commit interaction must also hold — verify namespace stays int4 with all 3 wired once RuleSubvarZext's storage bug is fixed.
- **BLOCKER unchanged = Session-12's copy-prop-into-return** (RuleSubvarZext narrows correctly but `RETURN ... u...:4` records the return as a UNIQUE not EAX → proto_recovery twodim/modulo fail). NOT use_same_address. Needs the Ghidra-grounded fix for why `EAX=COPY(u)` survives copy-prop at a RETURN (isReturnCopy / committed-return addrforce; ActionReturnRecovery 5500 BEFORE oppool1 5511).
- **CORRECTED SEQUENCE (supersedes turnkey):** the RuleShiftPiece low-piece / r0x80 step is DROPPED (premise dead). Un-hold order is: (1) fix RuleSubvarZext copy-prop-into-return storage → land RuleSubvarZext (delivers int4 returns: namespace→perfect, +#12), (2) THEN un-hold SubZext+Piece2Zext (their upper-RAX-garbage regressors vanish once returns are 4-byte) + verify the all-3 ordering holds + adapt the x86_64_sem ir_parity/printc test (Session-11: stale not regression). Reported to lead, STOP+REPORT on premise falsification per instruction.

## Session-14 (2026-07-04, base 153149a): copy-prop-into-return BLOCKER CRACKED by static reading (NO instrumentation). Commit A landed 5a8ac03. Commit B (RuleSubvarZext) gated.
The Session-12 blocker ("why does Ghidra's `EAX=COPY(u)` survive copy-prop at a RETURN") is answered — the pre-authorized Ghidra instrumentation was NOT needed.
- **MECHANISM:** Ghidra `RulePropagateCopy::applyOp` (ruleaction.cc:3933) opens `if (op->isReturnCopy()) return 0;`. The `return_copy` flag (op.hh:94) is set NOT ONLY by the globals-only `markReturnCopy` (heritage.cc:1686, gated on `Varnode::persist` — what the prior session found + correctly ruled out) BUT ALSO as a **default opflag of `TypeOpReturn` (typeop.cc:878: `opflags = special|returns|nocollapse|return_copy`)**. `PcodeOp::setOpcode` (op.cc:283) ORs `t_op->getFlags()` into every op → **every CPUI_RETURN op has isReturnCopy()==true** → RulePropagateCopy NEVER propagates a copy into a RETURN's inputs → Ghidra keeps EAX in the return. The "isReturnCopy globals-only, FALSIFIED" note was the miss — it checked only the markReturnCopy source, not the TypeOpReturn default opflag.
- **COMMIT A LANDED `5a8ac03`** (on 153149a; byte-neutral faithful, self-approved per gate): mosura `RulePropagateCopy::apply_op` (rules.rs ~429) now `if data.op(op).code()==OpCode::Return { return 0; }`. Corpus byte-neutral (0.8812, 54/60 — no return reads a propagatable COPY without subvar), 219 green. Also chips at propagatecopy over-fire (Task #13, 110-vs-56). mosura has no markReturnCopy globals-COPY yet (Task #3 guardReturns) so isReturnCopy ≡ RETURN op here (noted in the code comment).
- **COMMIT B (proposed, gated, awaiting lead go):** un-hold RuleSubvarZext (wire slot 116; TEMP-verified). Storage bug GONE — twodim `RETURN r0x288:8 r0x0:4` (EAX register, not unique) → `uint4 func`; namespace `int4 func(int4){return param_1+iRam...}` byte-perfect vs Ghidra; **proto_recovery 3/3 PASS**. Corpus **0.8825 (+0.0013), ZERO regressions** (union_datatype +0.036, noforloop_globcall +0.019, elseif +0.014, pointerrel +0.006). printc `emits_c_for_a_straight_line_function` (x86_64_sem) now PASSES. ONE stale test to adapt: `merged_variables_have_no_internal_interference` (ir_parity.rs:372) — x86_64_sem `by_hv=covers=11` (zero merges: subvar minimizes its straight-line SSA, no redundant versions); the correctness/interference check (line 364) PASSES, only the "merge collapsed something" sanity assert fails. Adapt = gate that assert on the fn having mergeable versions (mirror sibling phi test's `if had_phi`, ir_parity.rs ~324). Session-11 pre-flagged benign.
- **COMMIT B LANDED `381e745`** (lead GO): wired RuleSubvarZext slot 116 + adapted merge test. 219 green, corpus 0.8825 (+0.0013), ZERO reg (union_datatype +0.036, noforloop_globcall +0.019, elseif +0.014, pointerrel +0.006). Delivers #12 int4 returns; fixes x86_64_sem printc test. Merge-test adaptation: gate the collapse assert on `had_phi` (mirrors sibling phi test) — x86_64_sem now minimal SSA (by_hv==covers==11), interference invariant stays unconditional.
- **SubZext+Piece2Zext RE-MEASURE (post-B, TEMP, reverted): ordering STILL bites — both STAY HELD.** All-3 = 0.8778 (-0.0047 vs B), SAME wide-return regressors (namespace 1.000→0.837 etc.). Commit A+B do NOT resolve it. **DISAMBIGUATED: SubZext is the SOLE culprit; Piece2Zext INNOCENT for returns.** Piece2Zext+B (no SubZext): namespace→perfect int4, ifswitch→int4, corpus 0.8828 (+0.0003; floatcast +0.064, nan +0.022, floatconv -0.066 — marginal, green). SubZext+B (no Piece2Zext): namespace `xunknown8 return CONCAT44(0,...)`, ifswitch `int8 ... & 0xffffffff` — SubZext rewrites the return `RAX=ZEXT48(EAX)` to AND-mask/PIECE BEFORE RuleSubvarZext@116 seeds → preempts the narrowing.
- **SubZext ROOT (hypothesis, next investigation):** SubZext@74 < RuleSubvarZext@116 (same as Ghidra pool order) yet Ghidra doesn't regress → Ghidra's return is EAX:4 pre-pool (ActionReturnRecovery/output-prototype commits reaching-def width in mainloop) so SubZext never sees an 8-byte ZEXT return; mosura's return stays RAX:8 until RuleSubvarZext narrows in-pool. ALT: mosura RuleSubZext missing a Ghidra guard, over-fires on the return ZEXT (cheap faithful-diff vs ruleaction.cc). Reported to lead; offered (a) RuleSubZext guard-diff, (b) ground ActionReturnRecovery early-commit, (c) pause #8. Awaiting steer.

## Session-10 (2026-07-04, base ee3579a): lead UN-HELD #8. Re-wired + MEASURED on today's baseline. DECISIVE: 5 driving rules NET-POSITIVE; SubZext/Piece2Zext are the whole drag.
Re-ported 5 driving rules VERBATIM into rules.rs (RuleSubvarAnd subflow.cc:1553 / Subpiece 1590 / CompZero 1628 / Shift 1686 / Zext 1710; Sext deferred) + wired 7 at faithful slots (SubZext@74, Piece2Zext@103, subvar@110-116; AndDistribute OUT). **NO CRASH (62/62)** — CSE guard fixed the old loopcomment crash. MEASURED (decompile_track_corpus_report avg / 54-of-60):
- baseline **0.8804** → +5 driving only **0.8812 (+0.0008 NET POSITIVE)**, lib GREEN. UP: forloop_withskip +0.034, switchhide +0.017, elseif +0.017, forloop_varused +0.016, varcross +0.004; DOWN: only loopcomment -0.042. **piecestruct does NOT move** (was flagship -0.098 in stale data → graph evolved).
- +SubZext+Piece2Zext **0.8744 (-0.0060; the two cost -0.0068)** — breaks printc unit test `emits_c_for_a_straight_line_function` (`param_1*3 & 0xffffffff`, the RuleShiftPiece low-piece `&mask` divergence); regresses namespace 1.0→0.837, inline 1.0→0.889, orcompare 0.929→0.839, floatconv 0.578→0.512.
- **VERDICT: land 5 driving rules (net +0.0008, faithful, green); KEEP SubZext+Piece2Zext HELD.** The clean split prior sessions never isolated (they always wired all 7).
- **#12 return-width NOT delivered** — twodim still `uint8`; RuleSubvarZext aborts on RETURN (tryReturnPull Stage-4 stub, subvarflow.rs:837-839). Needs a SEPARATE commit: port tryReturnPull (subflow.cc:238) → the wired RuleSubvarZext then narrows returns→int4 (safe for 8-byte via consume gate).
- TREE (awaiting lead gate): 5 driving rules wired; SubZext/Piece2Zext defined-but-held (out of pool+import). 176 lib+6 corpus green. Rule-level unit tests NOT yet added (engine has 14 trace tests) — add on landing. loopcomment -0.042 = the one divergence to diagnose (fix, don't unwire).

## Session-9 (2026-07-04, base ee3579a): RETURN-WIDTH (int4) angle — a NEW, un-tried scoped slice of Stage 3+4
Task #12 (return int8-vs-int4, e.g. twodim `int8 func(){return uVar1}` vs Ghidra `int4`) root-caused to THIS subsystem. trace-diff twodim: the exact Ghidra op that narrows the return = **`subvar_zext` = RuleSubvarZext** (subflow.cc:1710) firing on `RAX:8=ZEXT48(u:4)`, rewriting `return RAX:8`⇒`return EAX:4` (then propagatecopy+earlyremoval finish). NOT copy-prop (identical both sides), NOT guardReturns (single RAX:8 trial), NOT ActionReturnRecovery/OutputPrototype/InferTypes (walked the cluster read-only — buildReturnOutput/ActionOutputPrototype/updateOutputTypes only READ the already-narrowed return), NOT a recover.rs heuristic (would be non-faithful).
- **KEY: the return-narrow path was NEVER exercised in the 8 prior Stage-3 sessions.** RuleSubvarZext's doTrace forward-traces the ZEXT value into the RETURN → `tryReturnPull` (subflow.cc:238). mosura's `trace_forward` RETURN arm is a **Stage-4 abort stub** (subvarflow.rs:837-839 `_ => return false`). So in every prior wiring, subvar aborted on any return → the prior net-regression numbers (piecestruct etc.) reflect RuleSubvarSubpiece/held-rule churn, NOT return-narrowing. Return-narrowing is untested territory.
- **PREMISE VERIFIED (mechanism, read-only):** twodim `RAX:8=ZEXT(u:4)`'s ONLY descendant is the RETURN → doTrace would succeed → tryReturnPull narrows → int4. SAFE for genuine-8-byte returns by Ghidra's own gate: tryReturnPull (subflow.cc:242-245) refuses when output-locked OR when `getConsume()&~mask != 0` (upper bytes used). mosura HAS bit-level consume (Stage 0 `9111b49`). So structurally safe.
- **SCOPED GATED PLAN proposed to lead (awaiting approval):** Commit A = port tryReturnPull (subflow.cc:238, ~46 lines) into subvarflow.rs RETURN arm + confirm parameter_patch handled in do_replacement (Stage-1 ported it); INERT while no rule wired → corpus byte-neutral (self-approve). Commit B (GATED corpus-mover) = re-port + wire ONLY `RuleSubvarZext` (subflow.cc:1710) at its Ghidra slot; EXCLUDE RuleSubvarSubpiece (the piecestruct regressor) + held SubZext/Piece2Zext; run full corpus + twodim/wayoffarray/packstructaccess, report delta+cause BEFORE landing. CAVEAT: RuleSubvarZext seeds on ALL zexts, so it may reshape graph beyond returns — corpus outcome is UNKNOWN read-only, hence gated. If it net-regresses like prior Stage-3, STOP + report (don't force).

## Session-14 LEAD CHECKPOINT (2026-07-04 ~17:00): SubZext preemption — corrected framing for resume
State: A+B landed (5a8ac03 isReturnCopy guard, 381e745 RuleSubvarZext un-hold; corpus 0.8825, 219/0). SubZext+Piece2Zext HELD; SubZext is sole culprit (Piece2Zext innocent for returns; only +0.0003 standalone w/ floatconv dip — rides with SubZext).
(a) FALSIFIED: RuleSubZext is a faithful port (rules.rs:2496 == ruleaction.cc, both arms, all guards).
"Early return commit pre-pool" framing LIKELY FALSE: Ghidra's own twodim trace shows subvar_zext narrowing the return IN-POOL (DEBUG 187) — the 8-byte return ZEXT still existed at pool time in Ghidra.
REAL question (redirected (b), NOT yet verified): the ZEXT-INPUT SHAPE. Ghidra: ZEXT48(EAX)/ZEXT48(u:4) — clean 4-byte value, never SUBPIECE → SubZext (needs zext(SUBPIECE)) can't match → subvar_zext@116 narrows. mosura: ZEXT48(SUBPIECE(base:8,0)) → SubZext@74 matches first and rewrites to AND-mask/PIECE, preempting the narrowing. So: WHY does mosura present the pre-return value as SUBPIECE(wide:8,0) where Ghidra has a clean 4-byte varnode? Prime suspect: heritage normalize_read_size (narrow read of wide write -> SUBPIECE(whole,0) — the documented adaptation) vs Ghidra heritage linking a proper narrow varnode. Same SUBPIECE-of-wide class as the RuleSelectCse fix (8dd6d80) + the r0x80 case — possibly ONE upstream divergence, several symptoms.
RESUME (read-only first): (1) confirm Ghidra's ZEXT input never SUBPIECE at that site (existing traces/IR); (2) pin where mosura introduces SUBPIECE(base:8,0) (raw lift? normalize_read_size? which pass); (3) what Ghidra heritage does instead (cite heritage.cc); (4) premise: matching Ghidra's shape makes SubZext stop matching the return ZEXT -> BOTH rules un-holdable. If it pins to normalize_read_size: heritage-layer fix, HIGH blast, scope deliberately with lead. Report before code.

## Session-14 ZEXT-SHAPE INVESTIGATION DONE (2026-07-04, read-only, namespace; tree clean 381e745): root = heritage PIECE(nonzero-upper) round-trip, NOT normalize_read_size directly. Reported, awaiting lead decision (leaned (c) bank A+B, defer heritage root).
- (1) CONFIRMED Ghidra clean: raw lift == mosura (`EAX=v; RAX=ZEXT48(EAX)`); Ghidra `--ir cleanup` has NO ZEXT/SUBPIECE/PIECE surviving (fully dissolved); return ZEXT input = clean unique (DEBUG 187).
- (2) mosura shape is MORE specific than framing: NOT `ZEXT(SUBPIECE(RAX:8,0))` — it's **`ZEXT( SUBPIECE( PIECE(nonzero_upper:4, param_1:4), 0 ) )`**. MOSURA_TRACE namespace: SubZext fires 8× `r0x0:8=ZEXT(u:4)` => `r0x0:8 = INT_AND r0x0:8 #0xffffffff`; the ZEXT input u:4 = SUBPIECE(r0x0:8,0) where r0x0:8 = `PIECE(u0x10004:4, param_1:4)` (heritage-built; UPPER piece is a non-zero unresolved unique).
- (3) WHY collapse rules don't win: **RuleSubExtComm fires 0× on namespace** (only cancels SUBPIECE(ZEXT/SEXT), base here is PIECE). **RuleDumptyHump** (SUBPIECE(PIECE(hi,lo),0)→lo) is slot **78** but **SubZext is slot 74** → SubZext converts the ZEXT to AND before DumptyHump collapses the SUBPIECE; once it's AND (not INT_ZEXT), RuleSubvarZext@116 can't seed → preempted. **RulePiece2Zext** needs const-0 upper (`PIECE(0,lo)→ZEXT(lo)`), but mosura's upper is a non-zero unique.
- (4) ROOT = heritage sub-register WRITE resolution: mosura widens the 32-bit EAX write to `PIECE(incoming_upper_bytes, EAX)` (normalizeWriteSize-style) WITHOUT zeroing the upper for the x86-64 zext idiom. Ghidra's upper is effectively 0 → collapses to clean ZEXT(lo), no round-trip. Same class as RuleSelectCse (8dd6d80) + r0x80; documented heritage normalize_*/refine adaptation (Task #3/#10); HIGH BLAST. NOTE: disabling normalize_read_size's ZEXT-idiom branch (heritage.rs:254-270) did NOT fix it (changed upper 0→leftover, still 8-byte) — the SUBPIECE-of-PIECE source is the write-side PIECE, not that read-side branch.
- (5) PREMISE (verified in principle, NOT landed): if the upper resolved to 0 the round-trip collapses to `ZEXT(param_1)` → SubZext can't match → RuleSubvarZext narrows → SubZext+Piece2Zext un-holdable. Heritage change (high blast) NOT made.
- RECOMMENDATION to lead: (c) bank A+B (clean wins: #12 int4 returns, +0.0013, isReturnCopy guard); defer SubZext/Piece2Zext + this heritage root to the heritage-restructure track (#3/#10) — shared root with #12/#13 return-width, so higher-value than just the SubZext unblock. OR (b1) scope the heritage fix (zero the ZEXT-idiom upper / match Ghidra normalizeWriteSize) now. Leaned (c). Awaiting steer.

## Session-16 (2026-07-04, base 381e745): the const-0 upper fold PINNED + LANDED `68a059e` (byte-neutral). SubZext/Piece2Zext un-hold STILL net-neg → STAY HELD (premise partially falsified).
Lead's turnkey = pin+port the fold that zeroes the widened-write upper so the round-trip collapses to clean ZEXT BEFORE the pool (so SubZext@74 can't preempt RuleSubvarZext). Instrument-first (trace-diff namespace) PINNED it decisively:
- **THE FOLD = Ghidra `ActionDeadCode::neverConsumed` (coreaction.cc:3809), invoked from the apply final sweep (4032-4052) when a written, heritaged (`doesDeadcode`), backward-reached (`isConsumeVacuous`) Varnode has `getConsume()==0`.** Trace-confirmed: namespace `DEBUG 5: deadcode` rewrites `RAX = CONCAT44(%upper, EAX)` → `CONCAT44(#0x0:4, EAX)` (upper `%=SUB84(RAX_in,4)` never consumed → replaced by `#0x0`, def destroyed). NOT a pool rule — an ACTION, runs before oppool1. mosura HAD consume analysis (`consume::calc_consume`) but the `neverConsumed` sweep was explicitly NOT wired (old consume.rs:17 note).
- **PORTED** into `calc_consume` (runs in ActionConsume, before the pool = Ghidra's deadcode-before-oppool1 slot): after the fixpoint, sweep written+heritaged+`vacuous`+`consume==0`+non-call Varnodes → `never_consumed` replaces all reads with fresh const 0 and `op_destroy`s the def. mosura keeps the OTHER sweep arm (destroy never-reached ops) in its after-pool whole-varnode `deadcode::dead_code` (split is a mosura structure; the fold itself is faithful). Verified: namespace uppers → `#0x0`, C byte-perfect (int4 returns intact).
- **3 OMITTED FAITHFUL PIECES the fold needed to compose (each pinned by the regressing fixture, all now ported in `68a059e`):** (a) consume SEEDING: seed written `ram` (persist-global) Varnodes fully-consumed — mosura flags globals persist only after type recovery, so use the ram-space proxy = the consume-dual of `dead_code`'s persist live-out roots — else the fold zeroed a global store's value (`iRam=0`). (b) **SUBPIECE consume transfer extended-precision case** (coreaction.cc CPUI_SUBPIECE: `if a==0 && outc!=0 && in(0).size>8 { a = 1<<63 }`) — mosura had OMITTED it (consume.rs:99-100 note); without it the 64×64→128 div-by-mult idiom's `SUBPIECE(mult:16, hi)` pushes consume 0 to the 128-bit multiply → fold zeroes it → **divopt -0.253** (division recovery collapses to `x + 0 >> 1 >> 6`). (c) **PIECE consume transfer extended case** (`vn.size>8`: high piece gets `~0` when low piece ≥8) — omitted too; without it a 16-byte `CONCAT88` store value's high piece folds to 0 → **concatsplit -0.086**. WITH both extended-precision branches ported, divopt/concatsplit fully recover.
- **2 latent robustness bugs in EXISTING rules, exposed by the const-0 graphs the fold makes before the pool (both guarded faithfully, byte-neutral):** RuleAndCommute `fullmask >> sa` panicked on a degenerate `#0x0 >> #0xffffffff` (Rust shift-overflow) — Ghidra's C++ `>>` on x86-64 masks count mod 64, so use `wrapping_shr/shl` (== `>>`/`<<` for sa<64). RuleMultiCollapse `defcopyr->getDef().unwrap()` panicked when a const-0 (from the fold) became the first-loop base branch — set `nofunc` (mirrors the None-branch; Ghidra reaches it only because its dead const-input MULTIEQUAL marker is swept in the same combined deadcode pass).
- **RESULT: LANDED `68a059e` (self-approved, byte-neutral faithful): corpus 0.8825 == baseline (only loopcomment +0.003), 220 green (+1 unit test).** So the fold is a clean IR-fidelity win independent of SubZext.
- **STEP-3 RE-MEASURED (fold IN-TREE, temp-wire SubZext@74+Piece2Zext@103, reverted): STILL net-neg -0.0050 (0.8775). SubZext/Piece2Zext STAY HELD.** Lead's premise "the 6 wide-return regressors clear" PARTIALLY confirmed: **namespace + orcompare NOW clear (stay perfect — the CONCAT44-upper-garbage subset the fold fixes)**, BUT floatconv -0.066 / ifswitch -0.039 / impliedfield -0.027 / modulo -0.091 PERSIST (a DIFFERENT mechanism — the `& 0xffffffff` truncation-return, not the CONCAT44 upper) + NEW inline -0.111 / piecestruct -0.098 / twodim -0.022. Gains floatcast +0.064, deindirect +0.064, nan +0.022. So the fold removes ONE of the two SubZext regressor families; the truncation-return family + inline/piecestruct structural churn remain. NOT un-holdable yet.
- NEXT (for lead): the fold banked #8's mechanism cleanly. The remaining SubZext blocker = the `& 0xffffffff` truncation-return family (floatconv/ifswitch/impliedfield/modulo) + inline/piecestruct — a separate divergence from the now-fixed CONCAT44 upper. Also: the SUBPIECE/PIECE extended-precision consume branches are now correct — a general consume-fidelity improvement beyond this task.
- **TRUNCATION-RETURN FAMILY GROUNDED (ifswitch, read-only, tree clean 68a059e): it's the SUB-REGISTER WIDTH divergence (Task #12), NOT reachable by the const-0 fold.** ifswitch at HEAD (SubZext held): `int4 func(int8 param_1) { ... return param_1*8; }` — return already int4 (RuleSubvarZext narrowed: final IR `r0x0:4=COPY u; RETURN r0x288:8 r0x0:4`). SubZext ON: `int8 func(uint8) { ... return param_1*8 & 0xffffffff; }` — return widens back to int8+mask. MECHANISM: mosura computes the value at 8-byte width and truncates via `RAX=ZEXT48(SUBPIECE(wide:8,0))`; SubZext@74 matches `ZEXT(SUBPIECE(x,0))` and rewrites to `wide & 0xffffffff` BEFORE RuleSubvarZext@116 can narrow. Ghidra computes at 4-byte width → return is `ZEXT48(cleanEAX:4)` (NO SUBPIECE) → SubZext can't match → subvar narrows to int4. So the SUBPIECE source here is a GENUINE wide computation (`param_1*8` at 8 bytes), NOT a `PIECE(nonzero,val)` round-trip — the const-0 fold has nothing to zero. This is Task #12's root (unique-vs-EAX / RAX:8 widening), a HERITAGE/lift-width issue. CONCLUSION: the fold cleanly cleared the PIECE-round-trip subset (namespace/orcompare); the truncation-return subset is the width divergence (heritage track #12/#3), same long-standing wall, now 2 fixtures narrower. SubZext/Piece2Zext STAY HELD; un-hold blocked on the width fix (high-blast heritage), not on anything the fold or a pool rule can reach. Recommend treating the fold as #8's deliverable this session.

## Session-17 (2026-07-11, subvar1, base 191d3fa READ-ONLY re-measure): PREMISE DRAMATICALLY SHIFTED. The 6-fixture wide-return wall is GONE. Only RuleSubZext remains held; it now nets −0.0016, ONE root cause (loop-induction 8-byte phi).
STATE CHANGE since Session-16: RulePiece2Zext is now WIRED (task #17, slot 103) + the 5 driving rules already landed + iterating mainloop (25cb50b) + pullsub cluster (191d3fa) + SplitFlow. So "wire the held Stage-3/4" reduces to **RuleSubZext** (RuleAndDistribute still OUT = HumptyOr ping-pong; RuleSubvarSext Stage-4 tracer still stubbed).
- **TEMP-WIRED RuleSubZext @74, measured, REVERTED (tree clean 191d3fa, git status verified empty).** avg **0.9213 → 0.9197 (−0.0016)**, 56/60 unchanged. The ENTIRE old wide-return wall (namespace/orcompare/floatconv/ifswitch/impliedfield/inline/piecestruct) is now **byte-identical with SubZext ON** — the mainloop + const-0 fold (68a059e) + subvar-zext return-narrowing (381e745) + Piece2Zext-now-wired cleared it. The Session-3/4 "forward-AND-of-nonconstants" framing (which the lead's task #18 still cites) is DEAD/stale.
- **Per-fixture movers (SubZext on vs off @191d3fa):** forloop_varused **1.0000→0.9140 (−0.086, DOMINATES)**, noforloop_iterused 0.7540→0.7320 (−0.022), modulo 0.9500→0.9470 (−0.003); GAIN switchloop 0.8080→0.8200 (+0.012). Everything else byte-identical.
- **ONE ROOT CAUSE (IR-confirmed both loop fixtures): SubZext leaves the loop INDUCTION VARIABLE as an 8-byte phi where Ghidra narrows it to a clean 4-byte phi.** forloop_varused OFF(=Ghidra) IR: `r0x18:4 = MULTIEQUAL r0x18:4 u0x10054:4` (clean 4-byte induction, increment `INT_ADD r0x18:4 #1` 4-byte). ON IR: `r0x18:8 = MULTIEQUAL r0x18:8 r0x18:8` + `u0x1006c:4 = SUBPIECE r0x18:8 #0` + back-edge `r0x18:8 = INT_ZEXT(INT_ADD(SUBPIECE,1))`. Renders as the split `uVar1 = (uint4)uVar2; for(uVar2=0; (int4)uVar1<n; uVar2=uVar1+1)`. noforloop_iterused: IDENTICAL pattern (`iVar1=(int4)uVar2; for(uVar2=10;...; uVar2=uVar3)`). = the SAME "SubZext@74 preempts subvar narrowing (slots 110-116)" class as the Session-13/14 return-width case, now on LOOP INDUCTION instead of returns.
- **TRACE EVIDENCE (trace-diff forloop_varused, Ghidra vs mosura-baseline):** Ghidra fires **subzext 5×** here and STILL ships clean C — because it also fires **subvar_subpiece @0x400585 (the loop-header/phi block)** to narrow the 8-byte induction phi, plus **andmask 5× (mosura baseline 2×), ghidra-only @0x400557/0x400571/0x400582** (the loop-critical sites). mosura's baseline reaches the 4-byte phi via a DIFFERENT route (subvar_zext over-firing 7× vs Ghidra 2×) that does NOT survive adding SubZext. NEXT GROUNDING STEP (bounded, one fixture): instrument WHY, with SubZext on, mosura's subvar does not narrow the 8-byte induction phi at 0x400585 the way Ghidra's subvar_subpiece does (candidate: SubZext@74 rewrites a zext-of-subpiece on the induction into `X&0xffffffff` before subvar can seed; Ghidra's andmask removes it at 0x400582/0x400571 so subvar still narrows — mosura's andmask/nzmask leaves it).
- **GATE STATUS:** RuleSubZext IS a faithful port (rules.rs:4268, unit-tested, == ruleaction.cc:5039). Per [[faithful-ports-land-not-held]] it is LANDABLE-as-diagnostic (the forloop regression names the next fix). BUT it is a corpus-MOVER (−0.0016) → per gate it is REPORT + WAIT (not self-approve). Reported to lead; decision pending: (A) land SubZext now, regression = diagnostic; or (B) fix the loop-induction-phi preemption (the andmask/subvar-narrowing grounding step) first, then land clean. Did NOT force the wire.
- **LEAD CHOSE (A) → RuleSubZext LANDED `4fa456c` (on 191d3fa).** Wired @74 (Ghidra coreaction.cc:5585, body ruleaction.cc:5039). Suite 403/0, switch 6/6, corpus 0.9213→0.9197 (56/60). The 16-session hold is OVER. Task #18 DONE. The forloop_varused/noforloop_iterused dip is now **task #24** (induction-phi narrowing payback, owner subvar1, in_progress) — the RuleIntLessEqual→RuleRangeMeld faithful-exposes-gap pattern. coverage.md updated (SubZext HELD→WIRED; only SubvarSext/RulePtrFlow remain BLOCKED).
