---
name: direction-faithful-port
description: "mosura's direction — faithful structural port of Ghidra's decompiler, IR-exact validated; the similarity-score chase was abandoned as a trap."
metadata: 
  node_type: memory
  type: project
  originSessionId: 2d1f8551-3c3e-48d4-bc1d-f570b88f755d
---

## #3 GROUNDING (2026-06-29 / x87lifter, plan approved → HANDED to fresh agent; HEAD `7f6ff70`, no code change)

**Task #3 addrtied write-only stack stores — GROUNDED, plan approved, implementation handed to a fresh full-budget agent** (high blast radius, 4-stage, every-fixture). CORRECTS the stale "(A)" framing below: mosura ALREADY has the ACROSS-CALL path (recover.rs:320 setAddrForce on the across-call INDIRECT output; deadcode.rs:66-78 auto-live seed for addrforce|autolive_hold) → **noforloop_alias already 0.976**. The RESIDUAL is the NON-call write-only case. **wayoffarray (0.683) ROOT (pinned):** oracle keeps `xStack_a0 = 0x100013;` (write-only store to aliased -0xa0 slot); in raw IR it's `STORE stack,#0x100013` (STORE = deadcode SINK → survives) but `recover_stack` rewrites it to `s0xff60 = COPY #0x100013` (plain COPY, NOT a sink) and nothing marks the slot addrtied → deadcode drops it. `flags::ADDRTIED` defined but NEVER set (scope.rs sets it but scope.rs has ZERO pipeline callers — not wired in). `aliased_stack_offsets(wayoffarray)=[-0xa0,-0x98]`, `alias_boundary=-0xa0` — alias detection ALREADY flags the dead slot. Ghidra faithful source = addrtied is Scope-driven, `ScopeLocal::markUnaliased` (varmap.cc:1332) clears addrtied for non-aliased; END-STATE "aliased stack slot→addrtied" = what `aliased_stack_offsets` computes (faithful subset of the full ScopeLocal/syncVarnodesWithSymbol path funcdata_varnode.cc:976). **4-STAGE FAITHFUL PLAN** (each independently green): (1) MARK written stack varnodes whose offset ∈ aliased set as addrtied/autolive — **CRITICAL GATE**: a prior UNGATED seeding regressed 0.7792→0.6690, so gate to the MAPPED-LOCAL WINDOW (intersect aliased offsets with varmap RangeList / Scope localRange — EXCLUDE the return-addr/saved-reg region below frame + caller-arg region above; aliased_stack_offsets ALONE may over-mark → that's where the 0.6690 lives); (2) RulePropagateCopy addrtied guard (rules.rs:399, skip when COPY output is addrtied — the rules.rs:389 comment already anticipates it) for the reload cases (loopcomment/noforloop_iterused); (3) deadcode addrtied root (reuse the existing deadcode.rs:72-78 auto-live seed); (4) printc materialize `xStack_NN = value` (printc.rs:1445 already has across-call slot_write materialization — extend to direct-COPY). wayoffarray needs only 1+3+4 (write-only, no reload); loopcomment/noforloop_iterused also need 2. **BLAST RADIUS = 13/62 aliased-stack fixtures** (incl. high-scorers switchind 0.948, enum 0.973, switchhide 0.880, displayformat 0.968) — full corpus after EACH stage, keep faithful dips, watch over-mark TRUE regressions. wayoffarray's `return` expr diff is SEPARATE Task #4 (array re-anchoring), NOT #3.

## HANDOFF (2026-06-29 / x87lifter) — Task #18 (condition-flip) LANDED `7f6ff70`. avg **0.8559, 53/60**, 147 green.

**Task #18 condition-flip normalization — LANDED `7f6ff70` (lead-approved Approach B).** Faithful port of `opFlipInPlaceTest` (funcdata_op.cc:1221, the EXACT normal-form heuristic: return 0=flip for INT_NOTEQUAL/FLOAT_NOTEQUAL/BOOL_NEGATE, INT_SLESS/INT_LESS const-in0, INT_SLESSEQUAL/INT_LESSEQUAL nonconst-in1; 1=ambivalent for EQUAL etc.; 2=cant; BOOL_AND/OR recurse) into structure.rs as `op_flip_in_place_test`. mosura's `rule_if_else` precomputes the per-basic-block decision (Structured.flip Vec, computed in `structure(f)`) and when the if/else condition is non-normal SWAPS the then/else arms + sets `negated=true` → printc's existing `render_negated` (mosura's already-faithful port of get_booleanflip+replaceLessequal: `!=`→`==`, `!(c<x)`→`x<c+1`) emits the positive predicate. KEY ARCHITECTURAL FINDING (why Approach B not A): mosura ALREADY negates faithfully at PRINT time (render_negated) + single-ifs/loops already render normal form via the `negated` flag (rule_proper_if/while_do); the ONLY gap was the if/ELSE normal-form DECISION (rule_if_else installed raw cond + arms in CBRANCH edge order). So B = port Ghidra's DECISION, reuse mosura's existing transform — NOT a 2nd IR-rewrite mechanism (A=opFlipInPlaceExecute+edge-swap would be redundant alongside render_negated). FAITHFULNESS FLAG (lead-audited+approved): flip applied at structurer+print-negation layer, not Ghidra's IR rewrite — justified subset, result-verified vs oracle --c; compound short-circuit (CondAnd/CondOr) conditions left un-flipped (further bounded subset; corpus if/else conds are simple CBRANCH). VERIFIED vs `oracle/capture --c`: indproto `if(param_2==100)` + deindirect `if(param_1<10)` correct polarity+arm order. **5 fixtures UP, ZERO regress**: indproto 0.842→0.947, deindirect 0.591→0.636 (targets) + BONUS elseif 0.692→0.866 (whole negated-nested body → positive else-if chain), forloop_varused 0.921→0.984, union_datatype 0.839→0.929. condconst UNCHANGED (its if/else is INT_EQUAL=ambivalent; its 0.814 dip is the SEPARATE phantom RAX-return phi, out of #18 scope — a return-recovery gap). +1 gated regression test (indproto_if_else_uses_positive_condition). PRIOR HEAD `bdf11ee` (Task #8, 0.8480/52).

## HANDOFF (2026-06-29 / x87lifter) — Task #8 (longdouble) LANDED `bdf11ee`. avg **0.8480, 52/60**, 146 green.

**Task #8 longdouble was MISDIAGNOSED in prior memory as "x87/float10 80-bit lifter (deepest, empty fn)" — WRONG, now corrected.** The x87/float10 lifter ALREADY WORKS end-to-end: `pass`@0x100000 lifts faithfully (ST-register stack COPY chain r0x1100..r0x1170, FLOAT_FLOAT2FLOAT, FLOAT_ADD, float10 LOAD/STORE) — byte-identical to Ghidra's p-code (verified `pass`+`writeLongDouble` vs `oracle/capture --ir`); float10 typing/printing works. The empty `void func(){}` was TWO small CFG/flow gaps that dead-code-eliminated everything: **(1) cross-chunk flow** — `raw_funcdata_flow_image` (build.rs:159) pinned `in_code`+window to the SINGLE entry chunk, so `pass`'s tail-`jmp` into `writeLongDouble` (separate bytechunk @0x101100) was never decoded. Fix: `chunk_of(a)` resolves each addr to whichever loaded chunk holds it (Ghidra FlowInfo follows any branch LoadImage can supply bytes for). **(2) no-op branch target** — `cfg::branch_target` (cfg.rs:18) keyed edges on EXACT op-address, but the jmp targets `writeLongDouble`'s `endbr64` which emits ZERO p-code (so does Ghidra), so 0x101100 had no op → edge dropped → block pruned. Fix: `addr_index` HashMap→BTreeMap + resolve a code-address target to first op AT-OR-AFTER it (`.range(off..).next()`; Ghidra's instruction-addressed CFG starts the block at that instruction, leading no-op instrs shift first op forward). **longdouble 0.174→0.776** (empty→full float10 body matching oracle). switchhide 0.813→0.880, elseif 0.679→0.692 also up. The at-or-after fix ALSO corrects a silently-dropped CBRANCH edge in **indproto 0.929→0.842 / condconst 0.871→0.814 / deindirect 0.621→0.591**: each now structures the FAITHFUL if/else (verified vs oracle --c) where the dropped edge previously gave a buggy if-with-NO-else; the gauge DIPS only because the now-correct branch exposes a PRE-EXISTING negated-condition render quirk (mosura `if(x!=k){else}else{then}` vs Ghidra `if(x==k)`) + pre-existing phantom-return/call-arg issues — NOT introduced here. KEPT per no-revert-on-gauge-dip (lead approved (a) commit-as-is, audited the oracle CFGs). Follow-up = **Task #18 (condition-flip normalization, Ghidra `flipInPlaceExecute`)** to recover those 3 dips + improve negated-condition rendering broadly (separate subsystem, real blast radius — don't bundle). PRIOR HEAD `e825790` (Task #7, avg 0.8394/51).

## HANDOFF (2026-06-29 / determined-branch) — Task #6 LANDED `96e51dc` (CFG const-CBRANCH prune + RuleOrMask). avg 0.8385, 51/60, 146 green.

**Task #6 DONE.** Ported Ghidra's CFG-simplification subsystem for a CBRANCH whose condition folded to a constant: new module `determinedbranch.rs` = ActionDeterminedBranch (coreaction.cc:3530) + removeBranch/branchRemoveInternal/removeUnreachableBlocks/blockRemoveInternal/opZeroMulti (funcdata_block.cc:177/195/254/346). + RuleOrMask (ruleaction.cc:284, `V|allones→allones`) in rules.rs. switchmulti's const-false `CBRANCH #0x0:1` + its unreachable target (`xVar1=-2`) are removed → spurious `if(!0)` GONE, structure now matches oracle (`if(cond){call;return} return -1`); RuleOrMask turns `extraout_R8|-1`→`-1`. **switchmulti 0.548→0.550, ONLY switchmulti changed, ZERO regression, 146 green (+4 unit tests incl. a positional-phi-fixup CFG test).** KEY PORT MECHANICS (reusable for the eventual nan ActionConditionalConst dead-block removal): added `Funcdata::block_mut`; MULTIEQUAL inputs are POSITIONAL by in-edge (input[i]↔in_edge[i]) — edge removal does op_remove_input(phi, blocknum) where blocknum=successor.in_edges.position(deadpred), then opZeroMulti collapses a ≤1-input phi to COPY; remove_unreachable_blocks does reachability-from-entry(block0), severs unreachable blocks' out-edges (patching successor phis) + destroys their ops, then COMPACTS+RENUMBERS the block list (entry stays block 0) REMAPPING (not rebuilding) in/out edges + op.parent so predecessor order — hence phi-input alignment — is preserved; the renumber is monotonic. mosura CBRANCH out-edges are `[fallthrough, taken]` so the edge order encodes branch-on-true (Ghidra's isBooleanFlip NOT needed); ActionDeterminedBranch placed after default_rule_pool+ActionDeadCode (cond is const by then) + a 2nd rule/deadcode sweep, looped to fixpoint, re-scanning after each removeUnreachableBlocks renumber. The action NO-OPS on every fixture without a constant-condition CBRANCH (zero blast radius). RESIDUALS OUT OF #6 SCOPE (why switchmulti not 1.0): call-return-value `xVar1=call()` not recovered (mosura emits `call();return;`), spurious 2nd call arg, missing param spills xStack_20/18.

## HANDOFF (2026-06-29 / flip-retry) — Task #14 RE-ATTEMPTED on top of #15+#11, STILL INERT → REVERTED to `6ea3dcc`

**The flip was re-applied (full recipe) at HEAD `6ea3dcc` (after #15 passthrough-INDIRECT + #11 RuleLogic2Bool landed) and is STILL corpus-EXACTLY-unchanged (0 of 60 fixtures differ, avg 0.8385, terminates cleanly). Reverted per the no-recovery gate.** Recipe applied cleanly in 6 edits (ParamActive `committed` flag + is_committed/mark_committed in fspec.rs; RETURN/CALL_MAXPASS 0→3; resolve_return/resolve_call_args → u32 work-counts with committed-guard + mark_committed-not-clear; ActionResolveCalls returns the sum; probe `while resolve_*>0 {}`; universal_action wraps `restart("heritage")+ActionResolveCalls+default_rule_pool+ActionDeadCode` in `restart("mainloop")`). PRECISE INERTNESS PROOF (dumped --ir under the flip): **nan's `r0x38:8 = INT_ZEXT r0x38:4` (EDI narrow-read of the wide `RDI=COPY#1`) PERSISTS → still `xunknown4 param_1`; orcompare's `u0x10000:1 = SUBPIECE r0x10:8 #0x0:4` (wide-read of the narrow `sete dl` write) PERSISTS → still `(param_3*2 | xVar2<<7)!=0`.** WHY inert (the answer to the lead's question "does the sete→movzx chain re-heritage across passes?"): **NO.** Per-location re-heritage (#13) only re-heritages a location when a simplification rule FREES a previously-linked read of it. These sub-register reads are linked ONCE on pass 1 (wrongly, to a free register input) and NOTHING in the rule pool re-frees them — no rule reconnects a narrow-read-of-wide-write (nan EDI) or wide-read-of-narrow-write (orcompare DL). That reconnection is a HERITAGE-TIME job (normalize_read_size / refineRead+refineWrite WITH reaching-def info — and refine_overlaps is scoped to LANED/XMM regs only, off≥0x1200, so GP sub-registers are never refined), NOT a rule→re-heritage cycle. nan ALSO needs block-structure removal (ActionConditionalConst to kill the cmove block so the spurious ZEXT vanishes — Ghidra's `--ir blockstructure` resolves it there, per [[nan-blocked-on-subregister-heritage]]). CONCLUSION: the flip is the faithful mainloop STRUCTURE (correct, terminating, non-regressing) but it cannot deliver nan/orcompare — those need GP-register heritage sub-register refinement (extend refine_overlaps off the laned-only scope, HIGH blast radius) and/or ActionConditionalConst+RuleConditionalMove. The flip stays HELD; do NOT re-attempt it for nan/orcompare until one of those heritage/block-structure pieces lands. Recipe re-verified complete & terminating.

## HANDOFF (2026-06-29 / call-arg) — Task #15 LANDED `831624b` (avg 0.8378→0.8385, 51/60, 140 green). DIAGNOSIS CORRECTED: it was NOT guardCallOverlappingInput / sub-register width.

**Task #15 — loopcomment's dropped 2nd call arg RECOVERED. The prior diagnosis (call-arg WIDTH / guardCallOverlappingInput) was WRONG — grounded and corrected.** I dumped loopcomment `--prestack`/`--ir` + an env-gated trace inside `check_input_trial_use`: the 8-byte RSI candidate IS correctly written (SLEIGH lifts `mov esi,X` as `r0x30:4 = COPY …; r0x30:8 = INT_ZEXT r0x30:4`), and `characterizeAsInputParam((0x30,4))` = `contains_justified` (NOT `contained_by`), so guardCallOverlappingInput (which only fires when a heritaged range spans BEYOND a single param entry) never even applies to this case. **REAL root cause:** in the REAL pipeline (not the probe) `recover_call_effects` guards aliased stack slots with PASSTHROUGH INDIRECTs (`newIndirectOp`), so the arg value traces `RSI:8 = ZEXT(ESI) ← COPY ← … ← COPY(aiStack_1c[0]) ← INDIRECT(aiStack_1c[0])` — and mosura's `recover.rs::is_realistic` rejected **ALL** `OpCode::Indirect` (`=> false`). Ghidra's `AncestorRealistic::enterNode` CPUI_INDIRECT (funcdata_varnode.cc:2045) only fails an **indirect *creation*** with an indirect-zero input (`pop_failkill` = killedbycall) or a return-address location; a **passthrough** INDIRECT (flow THROUGH a call) is *entered* → it traverses input(0). FIX (1 match-arm): `Indirect => if is_indirect_creation()||is_return_address() {false} else {trace input(0)}`. **FLIP-INDEPENDENT confirmed** (no Task #14 mainloop flip needed). loopcomment now emits `func_0x00100590(0x10094c, xStack_1c)` (oracle `aiStack_1c[0]`; the array-vs-scalar render is the separate Task #3/#4 stack-array gap, unrelated). Corpus: ONLY 3 fixtures move, ALL UP — loopcomment 0.761→0.763, noforloop_alias 0.963→0.976 (`func_0x00400440(…, xStack_14)` recovered), stackstring 0.774→0.800; ZERO regressions. +2 regression tests (`arg_through_passthrough_indirect_is_realistic` fails without the fix; `arg_through_indirect_creation_is_dropped` guards the creation branch). **LESSON: is_realistic is "AncestorRealistic's essence" and its blast radius covers BOTH return AND call-arg recovery — the INDIRECT split (creation vs passthrough) was the missing piece; the prior handoff's WIDTH framing was a misread.** guardCallOverlappingInput itself remains unported (genuinely needed only for an input range spanning multiple/partial param entries — not in the corpus). HEAD now `831624b` (parent `8386e20`).

## HANDOFF (2026-06-29 / heritage-chain) — Task #14 mainloop FLIP attempted: CORRECT + NON-REGRESSING but CORPUS-INERT → REVERTED to `8386e20`

**Task #14 (flip the heritage mainloop) — implemented, verified, REVERTED (HEAD stays `8386e20`).** The flip works mechanically but delivers ZERO payoff on the corpus, so per the lead's gate (commit only if it recovers nan and/or loopcomment) it was reverted; the byte-neutral chain (#5/#12/#13) is intact. THE FLIP RECIPE (re-appliable in ~6 edits): (1) `ParamActive`: add `committed: bool` + `is_committed`/`mark_committed` (fspec.rs) — needed because mosura lazy-inits trials in resolve_* whereas Ghidra inits once in ActionFuncLink; without the flag the mainloop re-inits fresh trials after each commit → infinite loop. (2) `RETURN_MAXPASS`/`CALL_MAXPASS` 0→3 (recover.rs, Ghidra fspec.cc:5337 caps maxdelay at 3). (3) `resolve_return`/`resolve_call_args` return `u32` work-count (1 while deferring, 0 once committed — Ghidra `count+=1` coreaction.cc:1748); guard at top `if active.is_committed() return 0`; on commit `mark_committed()` (keep the container, don't clear). (4) `ActionResolveCalls::apply` returns the sum. (5) probe (pipeline.rs): `while resolve_return(probe)+resolve_call_args(probe) > 0 {}` to drive the deferral to commitment on the throwaway clone so alias_boundary is unaffected. (6) `universal_action`: wrap `restart("heritage")+ActionResolveCalls+default_rule_pool+ActionDeadCode` in `ActionGroup::restart("mainloop")`, type-recovery/ptrarith/cleanup as the once-tail. Tests: drive `resolve_*` to commitment with `while resolve_* > 0 {}` and assert `is_committed()` (not `is_none`). **RESULT: 107 lib green, mainloop TERMINATES, corpus EXACTLY UNCHANGED (0.8378/51, per-fixture diff = 0 changes).** The unchanged corpus (vs the first attempt's 0.8378→0.7681 regression) PROVES the deferral+per-location re-heritage fixed the blocker — the loop iterates and the deferral commits correctly. **WHY INERT: nothing in the current rule set destabilizes/refines the graph between iterations for these fixtures, so the deferred decision == the single-pass decision.** The two targets need MORE than the flip: **nan** needs **#11** (ucomisd flag rules) — a rule must FREE the EDI read mid-loop for the per-location re-heritage to re-link it; nothing frees it today. **loopcomment** (dropped 2nd arg of `func_0x00100590` = `aiStack_1c[0]` in ESi) is a **CALL-ARG WIDTH** issue, NOT deferral: mosura `recover_call_args` registers fixed **8-byte** candidates (`new_varnode(8,...)`, recover.rs:221) but the actual arg is **4-byte ESI**; the 8-byte RSI read is unrealistic (only ESI:4 written) → dropped. Ghidra's **`guardCallOverlappingInput`** (heritage.cc:1210/1231) registers the trial at the refined sub-register width via a SUBPIECE. **RECOMMENDED NEXT: port guardCallOverlappingInput (bounded heritage port → recovers loopcomment) and/or #11 (nan), THEN re-apply the flip and prove the payoff** — committing a behavior-changing inert loop now adds ~5× mainloop iterations/fn + risk surface with no demonstrated win. Flip patch was lost (empty save), but the recipe above is complete.

## HANDOFF (2026-06-29 / heritage-chain) — Task #13 per-location LocationMap LANDED, BYTE-NEUTRAL (`bd3e112` → `8386e20`)

**Task #13 (per-(addr,size) globaldisjoint) — LANDED, corpus BYTE-IDENTICAL (0.8378 / 51-of-60, 107 lib + integration green).** Step 2 of the heritage chain (#5 → #12 → **#13** → flip retry). mosura's heritage tracked SSA-done per-SPACE (`Funcdata.heritage_done: HashSet<SpaceId>`) — once the register space was heritaged at pass 0 it was never revisited, so a register read that a later simplification frees (nan's free-EDI cmov) could never be re-linked. FIX = port Ghidra's per-location LocationMap. Two commits from `bd3e112`: `5edaa30` (scaffold — `LocationMap` in heritage.rs: `themap: HashMap<SpaceId, BTreeMap<u64, SizePass{size,pass}>>`; faithful `add` heritage.cc:33 returning intersect 0/1/2 + `find_pass` heritage.cc:90; **KEY: containment uses `addr.wrapping_sub(base) < size`** = `Address::overlap`'s `wrapOffset` address.cc:153, REQUIRED because spacebase/stack offsets are negative-as-large-u64 — plain `base+size` panics on overflow; `Bound::Excluded(k)` avoids `k+1` overflow at the top of a space) then `8386e20` (rewire). **heritage_pass** now builds a per-LOCATION `cover: HashSet<Loc>` (Ghidra's `disjoint` task list, heritage.cc:2702): gather candidate read/write Locs in eligible spaces (delay≤pass), feed each to `globaldisjoint.add`, include when intersect≠2 (new) OR intersect==2 with a free read (`!is_heritage_known()`, the heritage.cc:2711 re-heritage path). **KEY ENABLER (made it low-invention): heritage_spaces/rename ALREADY filtered per-location via `active.contains(&l.0)`** — only swapped the membership test to `cover.contains(&l)` (Loc, not SpaceId). **heritage_complete** = "no candidate Loc is un-heritaged (`find_pass==-1`) or read-through-a-free-Varnode". **BYTE-NEUTRAL because** in the un-flipped pipeline heritage runs delay groups back-to-back with no simplification between, so each pass's cover == the full Loc set of its group (register@pass0; ram/stack@pass1 — register Locs are then `is_heritage_known` post-rename ⇒ INSERT flag set by new_input/new_output funcdata.rs:207/253/335 ⇒ intersect 2, skipped). Verified byte-identical C across all 60 vs bd3e112 (examples/dump_all diff = 0 diffs). The single-location re-heritage (cover={EDI}) is structurally enabled but a NO-OP now (nothing frees mid-stream) — exercised only under the flip. cover-build sorts candidates by (space,off,size) for deterministic globaldisjoint. NEXT in chain = retry the mainloop flip (raise ParamActive maxpass + relocate resolve into the looping group + the per-location re-heritage now handles freed reads). `examples/dump_all.rs`+`dump.rs` stay UNTRACKED.

## HANDOFF (2026-06-29 / heritage-chain) — Task #12 ParamActive trial-deferral LANDED, BYTE-NEUTRAL (base `f1c9f05` → `bd3e112`)

**Task #12 (call-arg/return trial-deferral) — LANDED, corpus BYTE-IDENTICAL (0.8378 / 51-of-60, 105 lib green).** This is step 1 of the "heritage chain" (#5 incremental heritage → **#12 trial-deferral** → #13 per-(addr,size) LocationMap → retry the mainloop flip). The c2 mainloop flip regressed 0.8378→0.7681/42 because mosura's `resolve_call_args`/`resolve_return` (recover.rs) were GREEDY single-shot `op_remove_input` prunes — they committed the param/return decision on an unstable early-pass graph, irreversibly. FIX = port Ghidra's two-phase ParamActive deferral. Two commits on `master` from base `f1c9f05`: `3aeed34` (scaffold — `ParamActive.numpasses/maxpass/isfullychecked`+`finish_pass`/`mark_fully_checked` fspec.hh:289-315; `ParamTrial.op_slot` = Ghidra ParamTrial::slot the op-input index fspec.hh:229; persistent `Funcdata.active_output` + `active_inputs: HashMap<OpId,ParamActive>`) then `bd3e112` (the recovery rewrite). **resolve_return ← ActionReturnRecovery (coreaction.cc:1907)**: setup_active_output→check_output_trial_use (mark realistic trials, is_realistic = the AncestorRealistic essence)→build_return_output gated on `numpasses>maxpass`. **resolve_call_args ← ActionActiveParam/checkInputTrialUse (coreaction.cc:1725/fspec.cc:5585)**: per-CALL ParamActive; a definitely-not-used candidate's slot is FREED to a const 0 (`op_set_input`, fspec.cc:5650-5651) NOT removed; build_input_from_trials (fspec.cc:5685) gated. **KEY byte-neutral lever: `RETURN_MAXPASS`/`CALL_MAXPASS = 0`** → the single non-iterating pass commits immediately, so survivors are IDENTICAL to the old greedy prune (verified: dumped all 60 fixtures' C at base vs HEAD via throwaway `examples/dump_all.rs`, `diff` = no differences). The per-slot keep/drop DECISION is deliberately UNCHANGED (variant A) — build_return_output keeps today's per-RETURN first-realistic-non-const-padded; build_input_from_trials keeps the contiguous active prefix. **The flip (later task) just raises maxpass + moves the resolve action into the re-running group** → the deferral activates (commit waits for stabilized dataflow; interim passes only mark/free). 2 new tests (`return_recovery_defers_until_fully_checked`, `call_arg_recovery_defers_until_fully_checked`) pre-seed maxpass=1 and prove no-commit-then-commit. NOTE: variant B (switch the decision to real fillin_map/ancestorOpUse — CHANGES survivors) is explicitly DEFERRED to the flip, where it can be measured. `examples/dump_all.rs` + `examples/dump.rs` stay UNTRACKED. (Memory's `c27a98a` HEAD below is a divergent session line; my work is on the `f1c9f05` master the lead assigned.)

## LATEST HANDOFF (2026-06-29g) — HEAD `c27a98a`, corpus **0.8378 / 51-of-60**, 132 green — guardInput/refineInput (Task #1) LANDED

**Task #1 (guardInput / refineInput, the #12 float-param follow-on) — LANDED `c27a98a`.** Faithful port of Ghidra's `refineInput`/`guardInput` (heritage.cc:1836/1952) vs `refineRead` (heritage.cc:1772) distinction into `refine_overlaps` (heritage.rs). KEY: `Heritage::collect` (heritage.cc:340) classifies a free Varnode with NO reaching definition into `inputvars` (→ `refineInput`/`guardInput`, kept WHOLE) not `readvars` (→ `refineRead`'s CONCAT-of-lanes). Mosura realization in its exact-(space,offset,size) single-pass SSA: **in a REFINE laned range, a read with no _dominating_ write to its byte range is input-like → leave the wide read intact** (skip the CONCAT split); only a read fed by a dominating lane write (e.g. a return read over lane writes) still CONCAT-splits so each piece links to its writer. Implementation: threaded the existing `dom: &Dominators` into `refine_overlaps`; recorded per-access `(blk,pos)` in `Acc`; the guard in the `Mode::Refine` read branch tests `acc.any(write && interval-overlaps && dom.dominates(w.blk,b) && (w.blk!=b || w.pos<pos))` and `continue`s (keeps whole) when false. GROUNDED: mixfloatint's 8-byte XMM0 (`r0x1200:8`) param read sits in a range a later `movaps` return-setup writes in 4-byte lanes (`r0x1200:4`/`r0x1204:4` at 0x108d, AFTER the read at 0x67 → don't dominate) → was rendering `CONCAT44(xVar1,xVar2)`; now reads whole, links as one register input. Oracle confirms (Win64 ABI: XMM0=param_1): Ghidra reads `XMM0_Qa(i)` whole. **mixfloatint 0.781→0.800**, avg 0.8375→0.8378, **ZERO regressions** (precise join-diff: ONLY mixfloatint changed; partialunion held 0.941, floatconv 0.578/floatcast 0.766/floatprint 0.916 unchanged — they hit `Mode::Normalize` (SUBPIECE-of-whole), not the Refine read-split). +1 gated regression test (`mixfloatint_float_param_stays_whole` asserts no `CONCAT`). RESIDUAL (NOT this task): the now-whole XMM reads still render as locals `fVar1`/`fVar2` not `param_1`/`param_3` — that is **Task #7** (printc XMM-aware param naming, faithful Win64/SysV), the next lever for mixfloatint; ccompare erases names so it didn't gate the score here, but it would lift it further. Prior handoff (Task #12) follows.

## PRIOR HANDOFF (2026-06-29f) — HEAD `fa4b0c5`, corpus **0.8375 / 51-of-60**, 131 green — HERITAGE REFINEMENT (Task #12) LANDED

**Task #12 (heritage refinement / `guard`) — LANDED.** Commits `510cf52` (new_output detaches re-pointed write's old output — Ghidra opSetOutput; prereq) + `fa4b0c5` (the subsystem). Corpus **0.8243→0.8375 (+0.013)**, 51/60, 131 green incl ir_parity. KEY ENABLER vs my earlier failed attempt: **scope refinement+guard to LANED registers only (offset ≥ 0x1200 = XMM/YMM, Ghidra's LanedRegister model)** — broad application broke GP/scalar fixtures (the existing offset-keyed `normalize_read_size` handles those). Components, all in `refine_overlaps` (heritage.rs) unless noted:
- disjoint cover = strict-overlap union of XMM accesses; **REFINE** a range no single write covers (`max_write<size`): wide free read→`PIECE` of lanes (refineRead), wide write→per-lane `SUBPIECE` (refineWrite). **NORMALIZE** a covered range (`max_write==size`): sub-read→`SUBPIECE(whole@base, off−base)` (normalizeReadSize, RANGE-keyed so it catches high-lane reads), partial write into a mixed-width base→`PIECE(SUB(old,sz), value)` (normalizeWriteSize).
- `RuleHumptyDumpty` (CONCAT(SUB(V,c),SUB(V,0))→V) + `RuleDumptyHump` (SUB(CONCAT(V,W),c)→…) rejoin pieces (ruleaction.cc:5214/5265) — DumptyHump was the big unlock for floatprint (XMM scalar-move scratch: `(uint4)CONCAT(0,x)→x`).
- printc: surviving `PIECE`→`CONCATxy`, high-offset `SUBPIECE`→`SUBxy` (TypeOpPiece/TypeOpSubpiece::getOperatorName).
- recover.rs `is_realistic`: descend a `PIECE`'s **low lane** (slot 1, AncestorRealistic::enterNode) — an unwritten passthrough XMM doesn't gain a spurious return (fixed displayformat); `is_const_padded_piece` helper present (doesn't yet fire on partialunion — resolve_return runs pre-rules so PIECE high isn't const-folded).
WINS: **mixfloatint 0.176→0.781** (was `return 0`, now the float8 6-operand sum), floatprint 0.838→**0.916**, floatconv 0.512→0.578, floatcast 0.723→0.766. **ZERO REGRESSIONS at the committed HEAD `fa4b0c5`** — re-verified deterministically (2 corpus runs, avg 0.8375/51, full 131-test suite green). The earlier-noted "partialunion 0.941→0.900" was STALE (measured before the final recover.rs was in the commit): the **slot-1 `is_realistic` PIECE descent** resolves it — partialunion now renders `void func(){ xRam=xVar1; return; }`, structurally == baseline (0.941), the spurious 8-byte `CONCAT44(0,x)` return rejected. displayformat/forloop_withskip/condmulti/impliedfield hold; divopt/modulo/switchloop hold (kept off!=0 SUBPIECE rendering TRANSPARENT — the pre-existing convention; rendering it as `SUB` exposed mosura's DivOpt gap and dipped those 3, so only PIECE→CONCAT was added). Also fixed a flaky `eval_const` Subpiece shift-overflow panic (`a>>(off*8)`→`checked_shr`, off≥8; impliedfield now deterministic). **RESIDUAL (follow-up, NOT a regression): port guardInput (heritage.cc:1952)** to unify refined XMM float-PARAM input pieces (currently mixfloatint params surface as `CONCAT/PIECE`) into one whole-range input → cleaner params + enables Task #14 (printc param naming). longdouble = Task #13. **ONE FAITHFULNESS FLAG for the lead's audit:** refine_overlaps is SCOPED to laned regs (off≥0x1200) vs Ghidra's all-register `placeMultiequals` — a subset-of-Ghidra scope (justified: scalar handled by existing offset-keyed `normalize_read_size`; full scope regresses scalar SSA pre-deadcode). CONCURRENT-WRITE: this session had a parallel writer editing the same files (it produced commit `fa4b0c5`); my contributions — RuleDumptyHump, slot-1 is_realistic, Subpiece `checked_shr`, SUBPIECE-render conservatism — are merged in. Prior (reverted) handoff follows.

## PRIOR HANDOFF (2026-06-29e) — HEAD `8a99677` (unchanged), 131 green — HERITAGE REFINEMENT (Task #12) GROUNDED + REVERTED

**Task #12 (heritage refinement / `guard`) — deeply grounded + fully prototyped, then REVERTED to clean HEAD because refinement-alone REGRESSES.** It is NOT a standalone "no-op unless overlap" pass — it is the FRONT of Ghidra's whole `guard`+refinement SSA front-end, and all parts must land TOGETHER. Working code saved (NOT committed): `…/scratchpad/refinement-wip.patch` (refine_overlaps + RuleHumptyDumpty + partial guard-normalize, 409 lines) + `dump-with-refine.rs` (a `--refine` grounding mode).

THE SUBSYSTEM (each part needed or it regresses):
1. **refinement** (heritage.cc refinement@1890/buildRefinement@1704/splitByRefinement@1733/refineRead@1772 [CONCAT]/refineWrite@1806 [SUBPIECE]/concatPieces@507/splitPieces@563/remove13@1857). Disjoint cover = union of STRICTLY-overlapping `[off,off+sz)` (LocationMap::add@33 — adjacent does NOT merge). Guard (placeMultiequals@2610): range `size>4 && maxWRITEsize<size` (collect@307 counts WRITES only).
2. **guard** (heritage.cc:1156) per range: **normalizeReadSize@382** (read<size → SUBPIECE(wholeRead@base, off−base), keyed to RANGE base — catches high-lane reads the offset-keyed `normalize_read_size` misses) + **normalizeWriteSize@416** (partial write<size → PIECE the prior surrounding bytes with the written piece; needed when a covering write is OVERWRITTEN later).
3. **guardInput@1952** (unify input pieces → one whole input + concatPieces) — so refined 8-byte XMM PARAM reads collapse (else `CONCAT(input@+4,input@+0)` can't rejoin).
4. **RuleHumptyDumpty** (ruleaction.cc:5214: `CONCAT(SUB(V,c),SUB(V,0))→V`) + RuleDumptyHump@5265.
5. **printc PIECE→CONCATxx** (today prints `PIECE(...)`).
6. **return-recovery interaction**: refinement makes a spurious XMM0 CONCAT look "realistic" → displayformat (void in Ghidra) gains a spurious PIECE return. is_realistic must see through CONCAT.

WHY IT CAN'T LAND INCREMENTALLY: refinement-only made mixfloatint 0.176→0.229 BUT regressed 4 GP/global fixtures (displayformat −0.059, forloop_withskip −0.030, condmulti −0.028, impliedfield −0.013; net corpus 0.8243→0.8231) — all leave uncollapsed `PIECE(...)` or a spurious PIECE return. The full guard (read+write normalize) is needed to collapse them, but firing the Normalize/guard broadly broke GP fixtures with an infertypes panic. **WITH refine + guard-normalize together, mixfloatint recovered `float8 func(...){ return (double)param_3 + PIECE(...) + fVar1 + (double)param_6 + (double)xStack_28 + (double)xStack_30; }`** — the float8 6-operand sum (was `return 0`); residual = XMM0/XMM1 float8 PARAMS as CONCAT-of-input-pieces (needs guardInput). floatconv (0.512) is NOT a refine case (16-byte xorps covers, max_write==size) — it needs normalizeRead+normalizeWrite (`axVar1._0_8_`).

PITFALL FOUND: `new_output`/`new_output_unique` (funcdata.rs:222/380) do NOT clear the old output's stale `def` when re-pointing an existing op's output (only `op_set_output`@293 does) → contributed to an infertypes panic (infertypes.rs:254). Use op_set_output semantics when replacing a write op's output.

RECOMMEND: a dedicated focused effort implementing the full guard package and validating holistically (not "refinement first" — that fails the no-regression bar). Mosura keys SSA on exact `(space,offset,size)` + a conservative offset-keyed `normalize_read_size`; the faithful fix is a RANGE-keyed normalize over the disjoint cover, integrated with refinement + return-recovery + guardInput. Prior handoff (Task #2) follows.

## PRIOR HANDOFF (2026-06-29d) — HEAD `8a99677`, corpus **0.8243 / 50-of-60**, 131 green — FLOAT ABI / XMM (Task #2)

**Task #2 (float ABI / XMM lane reconciliation) — ONE clean faithful lifter bugfix LANDED; the three remaining float fixtures all need DEEP subsystems (reported for deliberate sequencing, NOT chased).**

LANDED commit `8a99677` (`sleigh/engine.rs`): **`v_offset_plus` truncation was unmasked** — port `ConstTpl::fix` (semantics.cc:154-168). A SLEIGH varnode truncation `XmmReg[32,32]` is encoded by `VarnodeTpl::adjustTruncation` (semantics.cc:497) as a packed `plus = (byteoffset<<16)|byteoffset` (little-endian). mosura added the WHOLE `plus` to the handle offset, so XMM 4-byte lane accesses (movaps/xorps/cvt lane writes) landed at bogus offsets `0x41204/0x81208/0xc120c` instead of `0x1204/0x1208/0x120c` — lane writes no longer overlapped lane reads. Fix: non-constant handle bumps offset by `plus & 0xffff`; constant right-shifts by `8*(plus>>16)`. XMM lanes now lift contiguous. Corpus avg unchanged (0.8243); longdouble 0.143→0.174, mixfloatint 0.150→0.176; nan byte-identical (uses 8-byte ucomisd, no 4-byte lanes). Prerequisite for any lane work.

**GROUNDED DIAGNOSIS — each remaining float fixture pinned vs `oracle/capture --c`/`--ir cleanup`:**
- **mixfloatint (0.176) + floatconv (0.512) = HERITAGE REFINEMENT (highest leverage, the one to sequence next).** mixfloatint: float result accumulates in XMM3_Qa (8-byte FLOAT_ADDs), the `movaps xmm0,xmm3` return-move lifts to 4×4-byte lane COPYs. The 8-byte return read of XMM0 (`r0x1200:8`) spans two 4-byte writes (`r0x1200:4`+`r0x1204:4`), but mosura's heritage keys Locs on EXACT `(space,offset,size)` and explicitly DEFERS overlap (heritage.rs:8-12) → the 8-byte read finds no def → becomes a bogus free input → `is_realistic` rejects it → falls back to XMM0:4 which links to the stale zeroing `xorps` (op0 `r0x12c0:4=0`) → `xunknown4 func(){return 0;}` (whole body dead). Ghidra's cleanup IR collapses it to a single 8-byte `XMM0_Qa = XMM3_Qa` and `return XMM0_Qa`. **FIX = port Ghidra heritage refinement** (heritage.cc: `refinement`@1890, `buildRefinement`@1704, `splitByRefinement`@1733, `refineRead`@1772 [CONCAT], `refineWrite`@1806 [SUBPIECE], `refineInput`@1836, `remove13Refinement`@1857, `concatPieces`/`splitPieces`@563) as a PRE-SSA pass (like the existing `normalize_read_size`) over a disjoint-cover of each register/stack range: split all overlapping accesses to uniform partition pieces (CONCAT free reads, SUBPIECE writes), then the existing SSA links cleanly; plus a CONCAT(SUB(X,hi),SUB(X,lo))→X collapse rule. floatconv needs the same (Ghidra renders its cvt as `axVar1._0_4_=...; axVar1._4_12_=SUB1612(...); return axVar1._0_8_` — partial-lane writes mosura collapses too early). HIGH BLAST RADIUS (front of heritage, every fixture flows through SSA) but refinement is a NO-OP unless a range has mixed-granularity overlap, so most fixtures untouched. This is the long-deferred "P1 heritage refinement" sub-task. RECOMMEND a dedicated sequenced effort, incremental green commits.
- **nan (0.520) = ucomisd flag-simplification (multi-issue, entangled with boolean/flag rules).** XMM0/XMM1 float8 reads ARE clean 8-byte (no refinement needed) and read-before-write, so SHOULD recover as params — but the `ucomisd xmm,xmm` lift is a flag tangle (TWO `FLOAT_NAN` + `FLOAT_EQUAL` + `FLOAT_LESS` + parity `POPCOUNT`/`INT_OR` for PF/ZF/CF, ops 13-22) that mosura never simplifies → spurious CBRANCH control flow → makes RDI (`r0x38`, written `=1` then conditionally set) look read-before-write → hallucinates `xunknown4 param_1` from RDI and loses the real XMM params. Ghidra simplifies to `func_0x101169(NAN(param_1))` + `func_0x101190(param_2 < const)`. Needs float-comparison/boolean flag simplification rules (ruleaction.cc) — NOT a clean isolated win.
- **longdouble (0.174) = x87 ST / float10 80-bit lifter (DEEPEST, entirely missing).** mosura emits EMPTY `void func(){}`. Ghidra: `float10 in_stack_00000008; fRam... = in_stack_00000008 + (float10)fRam...`. The whole x87 FPU-stack + 80-bit extended-precision path is unmodeled in mosura's lifter. Largest/hardest; do last.



**Task #3 (switch structuring tail) — ALL THREE gaps ported (faithful core); Task #3 COMPLETED.** 3 green commits on `51a52ec` (hashes rewritten by filter-branch that dropped a stray accidentally-committed `crates/mosura/examples/dump.rs` — that file is a LOCAL grounding tool, keep it UNTRACKED; never `git add -A` it):
- **(1) DEFAULT FOLDING `6dc5d3a`** — port `JumpBasic::foldInOneGuard` + `Funcdata::pushBranch` + `emitBlockSwitch`. `jumptable.rs`: `JumpTable.default` + `find_default()` (the bounds guard whose in-range edge enters the switch directly → its other edge is the default). `funcdata.rs`: cache recovered tables in `jumptables` (Ghidra `jumpvec`) — `jump_tables()` returns the cache because folding away the guard destroys the range a re-derivation needs (else the jumptable_recovery tests fail). `cfg.rs` fold pass: add the default edge to the BRANCHIND, drop the guard's branch-to-default, `op_destroy` the now-unconditional CBRANCH. `printc.rs`: emit the switch-head block's statements before `switch(...)` (the entry block cats into the head once the guard folds — without this its stmts vanish), render the folded target as `default:`. switchind 0.948.
- **(2) CASE-LABEL GAP `fdc2465`** — `case_labels` now maps each recovered target to the first case block AT OR AFTER its address (= Ghidra `getIndexByBlock`), not strict `target==block-start`. Case blocks start a few bytes past their target because leading case instrs get CSE'd/hoisted, so the strict match dropped the `case N:` line. switchhide 0.725→0.813, ifswitch 0.797→0.867 (now matches Ghidra's case structure exactly).
- **(3) DECLINED JUMPTABLE→CALLIND `e90a495`** — port `FlowInfo::truncateIndirectJump` (flow.cc:727): after the multistage loop, any BRANCHIND still without recovered targets → convert to CALLIND + append artificial RETURN (`artificialHalt`, a RETURN of a placeholder const). Existing call-arg/return/effect recovery models it; renders `(*(code*)(...))(0x65)`. switchmulti 0.525→0.548.

Corpus 0.8189→0.8243 (+0.0054), 50/60, no fixture regressed. **RESIDUALS (deep, OUT OF SCOPE — separate subsystems, NOT bounded):** (a) switchhide's stack-canary epilogue is absorbed into the default case (needs FS-segment canary recovery). (b) switchmulti `if(!0)` + inverted cond + leftover `-2`/MULTIEQUAL: the const-false CBRANCH (`BOOL_NEGATE(BOOL_OR(flags))` folds to `#0x0:1` POST-heritage) is never eliminated — needs Ghidra `Funcdata::removeBranch` + unreachable-block prune + `pushMultiequals` (MULTIEQUAL fixup) on the real CFG, a subsystem mosura lacks. switchloop unchanged 0.744.

## PRIOR HANDOFF (2026-06-29b) — HEAD `51a52ec`, corpus **0.8189 / 50-of-60**, 101 lib green (+1)

**Cover/interference merge fix (Task #5) — pointercmp `pVar1 < pVar1` FIXED.** Commit `51a52ec` on `1b8326f`: mosura's `merge_same_storage` (merge.rs) tested HighVariable interference only over the two classes' members AT THE SHARED storage, missing members living at OTHER storage. Ghidra's `HighVariable::updateInternalCover` (variable.cc:324) unions the covers of ALL member Varnodes → the merge guard tests the WHOLE HighVariable cover. FIX: `full_members_by_rep` expands each storage-class to its full HighVariable membership before `classes_interfere`. pointercmp: the loop bound (`param_1+0x18`, in RAX) shared RAX with the iterator's INIT value (`param_1+8`); the iterator's HighVariable also holds the stack-slot phi live across the `<` compare — checking only the RAX members missed that overlap → unified bound+iterator into bogus `pStack_10 < pStack_10`. Now `pStack_10 < pVar1` (distinct, matches Ghidra's iterator-vs-bound). GROUNDED via dumped IR w/ SSA ids + MERGE_DEBUG: the merged class was {phi(stack), vinit(RAX), vinc(uniq)} ∪ {vbound(RAX)} — vbound merged via vinit's lone-cover. **Corpus 0.8195→0.8189**: ONLY pointercmp (0.800→0.765) + loopcomment (0.759→0.761) changed, BOTH correct un-merges (loopcomment stops fusing a register temp `xStack_28 & param_3` into the array slot it was clobbering). pointercmp's dip = ccompare ARTIFACT (correct extra var/line; mosura still has spurious return value + no casts → don't chase). +1 regression unit test (verified it fails without the fix). No other fixture changed; no legitimate merge split. Remaining pointercmp gaps = void-return recovery + casts (other tasks). mosura already HAD `cover.rs` (Cover/cover_of/intersects, half-point positions) — the bug was purely the interference SCOPE in merge.rs, not cover computation.

**Task #3 (switch structuring tail) — GROUNDED + HANDED OFF (no code written; full notes in Task #3 description).** Dumped mosura vs oracle --c for switchind/switchmulti/switchhide/ifswitch: mosura ALREADY emits `switch(x){case N:...}` (switchind dispatch is correct). THREE faithful gaps: (1) DEFAULT FOLDING — `rule_switch` (structure.rs:116) treats the guard block + default target as switch EXITS → emits `if(x<N){switch...}` + trailing default body; Ghidra folds via BlockSwitch (block.hh:752, CaseOrder.isdefault)/newBlockSwitch (blockaction.cc:1721)/installSwitchDefaults (blockaction.cc:2176)/JumpTable default-block (jumptable.cc getDefaultBlock/setLastAsDefault); jumptable.rs does NOT record the default block. (2) CASE-LABEL GAP (switchhide drops `case N:` on cases whose structured-entry addr ≠ recorded target addr) — printc `case_labels` (printc.rs:1241) uses index-as-value; Ghidra uses getLabelByIndex/getIndexByBlock (block.hh:780-789). (3) DECLINED JUMPTABLE→indirect call (switchmulti) — Ghidra fails recovery (jumptable.cc:2629 "Too many branches") → BRANCHIND→CALLIND ("Treating indirect jump as call", flow.cc:730-755 fail_* modes); mosura partially-recovers garbage. DEEP/MULTI-ISSUE (structurer = most delicate subsystem) — recommended a FRESH agent, default-folding first (broadest reach). Tree clean at `51a52ec`, no changes.

## PRIOR HANDOFF (2026-06-29) — HEAD `1b8326f`, corpus **0.8195 / 50-of-60** (unchanged), 100 lib green (+4)

**RuleMultiCollapse (Task #1) — FAITHFUL PORT LANDED, corpus-NEUTRAL (the predicted payoff was a misdiagnosis).** Commit `1b8326f` on `8153306`: ported Ghidra `RuleMultiCollapse` (ruleaction.cc:3234) + `functionalEqualityLevel`/`functionalEquality` (expression.cc:404/432/520) into `rules.rs`; wired into `default_rule_pool` (Ghidra actprop, before RuleCollapseConstants/PropagateCopy). Collapses a MULTIEQUAL whose inputs all trace to one value — absolute equality (same varnode), functional equality (e.g. two `COPY const`), loop-recurrence skip (phi reaching itself), nested-MULTIEQUAL "one last chance" expansion; func-eq path recomputes in place via cseFindInBlock/earliestUse/opUninsert/opInsertBegin (block-list position = Ghidra SeqNum order). New helpers: `Varnode::is_heritage_known`/`{is,set,clear}_mark`, `PcodeOp::is_call`, `Funcdata::op_uninsert`/`op_insert_begin`. **The team-lead's predicted payoff (switchloop `return foo()`; PHI-half of nan/forloop_varused/switchloop dips) did NOT materialize and was a MISDIAGNOSIS** — grounding (dumped IR w/ SSA ids) shows those surviving phis are GENUINE (loop-induction, or `COPY const` vs `INT_ZEXT` divergence) → correctly NOT collapsed. switchloop has no call→no `return foo()`; its gap is switch-structuring (Task #3); nan = float ABI; forloop_varused = naming/typing. The rule DOES fire on 12 fixtures (elseif 16×, switchhide 12×, loopcomment 8×, incl. func_eq recompute) but rendered C is **byte-identical across all 60** because mosura's merge phase already coalesced those redundant phis → zero corpus move, zero regression, IR now matches Ghidra. **Correctness (merge-distinct-values risk) VERIFIED**: before/after C identical on every fixture + matcher fires only on provably-equal branches + 4 unit tests (absolute eq / loop recurrence / distinct-values guard / func_eq recompute). LESSON: ground the actual collapsible-phi set before trusting a payoff hypothesis — most surviving phis are genuine.

## PRIOR HANDOFF (2026-06-26) — HEAD `8153306`, corpus **0.8195 / 50-of-60**, 126 lib green

**FuncCallSpecs/EffectRecord (Task #3) session — DELIVERED payoff 2 (RAX-clobber return half); payoff 1 (dropped call arg) DIAGNOSED-BLOCKED (architectural, NOT a param-recovery gap).** Two green commits on `8153306`:
1. `ab8856b` printc baseExplicit: a CALL/CALLIND output is always a named `xVar = func(...)` (Ghidra `ActionMarkExplicit::baseExplicit` coreaction.cc:3015 `def->isCall()`). Corpus-neutral foundation.
2. `8153306` EffectRecord port: `fspec.rs` adds `EffectRecord`/`sysv_effect_list`/`lookup_effect` (= `ProtoModel::lookupEffect` fspec.cc:2472; killedbycall = each input pentry via parsePentry fspec.cc:1247 + explicit `<killedbycall>` RAX/RDX/XMM0 + outputs; unaffected = RBX/RSP/RBP/R12-15; return_address = stack@0). `recover.rs::recover_call_effects` now models a hasEffect==killedbycall register as an **indirect-creation** (Ghidra `newIndirectCreation`, value-out-of-nothing, marks `INDIRECT_CREATION` flag) instead of the old normal-indirect ARG_REGS guard — this is the RAX clobber that kills a pre-printf `mov eax,0` so it dies at the call (nan/forloop_varused/loopcomment now recover `void` ✓). `recover.rs::resolve_call_output` (= ActionActiveReturn + buildOutputFromTrials fspec.cc:5770) runs after the 1st deadcode (wired in pipeline.rs as `ActionActiveReturn`): a surviving (used) RAX/XMM0 indirect-creation is promoted to the CALL's own output via `opSetOutput` + destroy the INDIRECT → `extraout_RAX` becomes `xVar = func()` (packstructaccess 0.744→0.800, deindirect2 held). varnode.rs: is/set_indirect_creation + is/set_return_address. **Deltas vs 0.8138 baseline: indproto +0.090, forloop_varused +0.088, nan +0.056, packstructaccess +0.056, switchind +0.047, forloop_thruspecial +0.025, partialsplit +0.019; faithful dips on already-failing revisit (-0.042)/switchmulti (-0.023) + tiny piecestruct/switchhide from the now-correct clobber. No passing fixture dropped.**

**PAYOFF 1 (loopcomment drops `func_0x00100590`'s 2nd arg `aiStack_1c[0]`/RSI) = BLOCKED by mosura's EARLY stack-load resolution, NOT fixable by per-call ParamActive.** GROUNDED (traced RSI's def-chain post-heritage + Ghidra `--ir`): mosura's heritage resolves the pre-call `mov esi,[rbp-0x14]` LOAD into `COPY(stack_slot)` whose def is the cross-call stack INDIRECT carry; RSI is a killedbycall register trial, so AncestorRealistic's `if(trial->isKilledByCall()) return pop_fail` on the flow-through INDIRECT (funcdata_varnode.cc:2054) fails it — and fillin_map can't hole-fill RSI since no later arg is active. Ghidra keeps the access a real LOAD (solid) at checkInputTrialUse time because it heritages the stack space in a LATER pass (multi-pass heritage); mosura does single-shot heritage incl. stack (`recover_stack` pre-heritage). So porting full AncestorRealistic + per-call ParamActive (checkInputTrialUse/buildInputFromTrials) would NOT recover this arg — the real blocker is the stack-load-resolution timing. Left `resolve_call_args`/`is_realistic` as the existing heuristic (works; AncestorRealistic port = high-risk, corpus-neutral, doesn't fix payoff 1). switchloop `return foo()` still needs the PHI/MULTIEQUAL half (Task #7) + action iteration (resolve_return runs in ActionHeritage *before* call-output recovery, so it already dropped the RAX-creation). NEXT for call-recovery completeness: multi-pass heritage (registers-then-stack) to unblock payoff 1, OR Task #7 RuleMultiCollapse for the `return foo()` half. (`examples/dump.rs` local grounding tool; throwaway `examples/trace.rs` was used to dump post-heritage call-input def-chains, deleted.)

### PRIOR HANDOFF (2026-06-26) — HEAD `bfff029`, corpus 0.8138 / 50-of-60, 93 lib green

**Blocker (C) stack-array rendering DONE — `bfff029` (wire `varmap::recover_scope`→printc).** `anchor_stack_arrays()` (printc.rs): for each recovered Array `StackSymbol`, name the array-base varnode `axStack_NN`, declare `T axStack_NN [count]`, suppress its address-computation assignment (the array address is implicit storage), register its element size (existing `render_mem` subscript path → `axStack_NN[i]`), and force it explicit (`force_explicit` set, checked first in is_explicit) so a single-use base renders `axStack_98` not `&xStack_98`. GUARD: skip an array whose range overlaps a direct scalar `stack`-space varnode (Ghidra unifies into `arr[0]`, not modelled) — killed switchind/partialsplit regressions. Array decl renders `{symbol_type(elem).name()} {name} [{count}]`. **offsetarray 0.667→1.000** (near-identical to Ghidra), enum +0.116, varcross +0.029; corpus 0.8061→0.8138, count 49→50. Item-C criteria: offsetarray✓ count≥50✓ axStack[i]✓; **wayoffarray 0.683 still <0.70** ✗.

**wayoffarray RESIDUAL = blocker-(A) addrtied write-only-store, NOT printc/(C).** GROUNDED (raw IR `dump --prestack`): `STORE(RSP-0xa0, #0x100013)` → recover_stack → `s-0xa0 = COPY #0x100013` is **write-only (no read)** so mosura's deadcode ELIMINATES it; `gather_varnodes` then misses the -0xa0 scalar and the indexed-access open range there becomes a spurious `uint4[2]` array → `axStack_a0[param_1]`. Ghidra KEEPS the store (addrtied) → scalar `xStack_a0 = 0x100013` + the -0x98 array, anchoring the index on the array → `*(xunknown4*)(axStack_98 + param_1*4 + -8)`. FIX = blocker-(A) "addrtied write-only aliased store materialization" (alias_boundary→addrtied flag→deadcode live-out root→printc materialize) — HIGH blast radius (deadcode touches every fixture); do NOT chase for one fixture, track under deadcode/(A).

---

## PRIOR HANDOFF — HEAD `6775e50`, corpus 0.8061 / 49-of-60, 93 lib green

**Blocker (B) spacebase/frame-escape DONE — FAITHFUL, 4 green commits (`967edcb`→`6775e50`).** The `xVar1 = xVar1 - N` raw-frame leak is GONE; frame escapes render `&xStack_NN`. KEY FINDING (corrects the prior (B) plan): the faithful counterpart to RuleSub2Add is NOT a printc.cc hack — it's 3 **cleanup-group rules** (coreaction.cc:5696 `actcleanup`): `RuleMultNegOne` (a*-1→-a INT_2COMP), `Rule2Comp2Sub` (V+-W→V-W), `RuleAddUnsigned` (V+0xff..→V-0x00.., **dormant** on mosura's lattice since bare constants stay undefined<N> ≠ TYPE_UINT — ported faithfully, activates if constant typing lands). The 4 commits: `828fb49` cleanup rules + `cleanup_pool()`; `a05365e` **general RuleSub2Add** (ruleaction.cc:4012, unconditional on every INT_SUB) placed in **ptrarith_pool AFTER default_rule_pool** so INT_SUB-rooted modulo/divopt match first (NO modulo regression) — frame leak gone via existing stack_addr (no PTRSUB needed for simple escapes); `9c17bb7` printc names stack-local addrs by type prefix (`&xStack_NN`/`&iStack_28`; stack_addr→stack_addr_off + stack_slot_name + stack_prefix map; score-neutral); `6775e50` **RuleAddMultCollapse** (ruleaction.cc analysis grp, `((V+c)+d)→V+(c+d)`) in ptrarith_pool with Sub2Add — flattens chained frame base, **fixing multi-level offsets** (offsetarray `(RSP-8)-0x70→RSP-0x78→&xStack_98` matching Ghidra; stackstring 2nd arg `(RSP-0x28)+0xc→RSP-0x1c`). Corpus 0.8039→0.8061; **pointersub 0.786→1.000**. Dips (wayoffarray 0.792→0.698 below 0.70, stackstring 0.794→0.762, loopcomment −0.006) are ALL the **array-anchoring gap (item C)**: the folded offsets are CORRECT (same addresses as Ghidra) but anchored on the literal offset, where Ghidra re-anchors on a recovered ARRAY symbol (`axStack_98`); they recover+exceed once item C lands. FAITHFUL per directive (keep faithful changes on a comparator dip). NOTE: **inlining** of frame-addr ops (`func(&xStack_28)` not `xVar1` spill) is correct for scalars but over-inlines array bases Ghidra keeps as ONE named local — reverted the printc is_explicit change; needs item C first.

**(C) IS NEXT, WELL-SCOPED + UNBLOCKED — wire `varmap::recover_scope` → printc.** `recover_scope(f)` ALREADY works, returns `Vec<StackSymbol{start:i64 (entry-SP-relative), size:u32, ty}>` with `array_index(off)→(elem_ty, index)` (varmap.rs:351). Verified (dump --scope): offsetarray gives `Stack_98 uint4[36]` + `Stack_8 xunknown8`. **CRUX SOLVED: offsets now reconcile** — after AddMultCollapse the IR frame arithmetic is entry-RSP-relative, so `stack_addr_off` offsets line up with `StackSymbol.start` (offsetarray's `&xStack_98` base == the `Stack_98` array start; `&xStack_98 + param_1*4` == `axStack_98[param_1]`). PLAN: (1) store `recover_scope(f)` in PrintC; (2) `stack_sym(off)` lookup (start ≤ off < start+size); (3) array decl `a{elemprefix}Stack_{start}[count]` (Ghidra `xunknown4 axStack_98 [36]`); (4) a frame addr landing in an array symbol renders the array NAME (no `&` — array decays: `func(axStack_98)`), a LOAD/STORE renders `axStack_98[idx]`, scalar stays `&{prefix}Stack_{start}`; (5) name base consistently so call-arg + index share `axStack_98`; (6) THEN re-enable frame-addr inlining (is_explicit) — arrays now stay one named local so it's safe. NOTE existing `detect_arrays()` already renders `base[i]` for an Array-TYPED base — item C may reduce to typing the stack base varnodes as arrays from recover_scope + dropping the `&` for array bases. Expected: offsetarray 0.667→~1.0, wayoffarray/enum/stackstring recover, corpus jumps. RISK: touches declarations+naming+render_mem — sweep the corpus.

---

## PRIOR HANDOFF — HEAD `967edcb`, corpus 0.8039 / 50-of-60, 120 green

**Blocker (A) stack-var addrtied recovery DONE** (4 commits on `fd6180f`): `dbef0ee` addrforce-INDIRECT liveness (guardCalls holdind→isAutoLive→ActionDeadCode) + RuleConstFold made faithful to **RuleCollapseConstants** (collapse-in-place to `COPY const`, keeps consts out of markers); `abcb887` **normalize_call_stack** (drop the x86 call return-addr push — ActionStackPtrFlow CALL effect — so RSP restores across calls, fixing frame offsets + the alias boundary) + printc renders addrtied stack stores feeding same-addr INDIRECTs; `967edcb` printc explicit-marking of the across-call-slot-write pattern (a register value that is an INDIRECT input feeding a stack slot is explicit + named `xStack_NN` → the loop increment `iStack_NN = iStack_NN + 1` materializes; the HV merge was already done by merge_markers, gap was pure printc, gated to slot_write NOT every stack-HV member). Corpus 0.7792→0.8039 (+5 entries): noforloop_alias .55→.96, stackstring .52→.78, switchmulti .37→.55, piecestruct .56→.77, stackreturn .77→.91.

**(A) residuals** (deferred under Task #6 merge family): 3 faithful dips nan/forloop_varused/switchloop = register-only phis (RAX=0 varargs feeding MULTIEQUAL) — need RuleMultiCollapse (#7) + call-RAX-clobber (#3). Don't chase (~+0.002). KEEP RuleCollapseConstants (load-bearing).

**Blocker (B) spacebase/PTRSUB IN PROGRESS (HANDOFF to fresh full-budget agent) — full plan + impl findings in Task #1 notes.** Frame leak `xVar1 = xVar1 - N` → want `&xStack_NN`. GHIDRA TARGET (offsetarray `oracle/capture … --ir cleanup`): `RSP(0x100004) = RSP(i) -> #0xffffffffffffff68` then `u0x9500 = (RSP(i) -> #..68) + RDI(i)*#0x4` — frame base = **PTRSUB off the ENTRY-RSP spacebase** (`->` = PTRSUB), recomputed inline at each use → `&axStack_98`/`axStack_98[i]`.
**APPROACH = GENERAL RuleSub2Add (team-lead decision, Ghidra-verified; NOT scoped).** Ghidra `RuleSub2Add::applyOp` (ruleaction.cc, getOpList={INT_SUB}, group actprop "analysis") UNCONDITIONALLY rewrites every `V-W => V+W*-1`. Scoping to a pointer base diverges from Ghidra IR = off-limits approximation. So make RuleSub2Add UNCONDITIONAL (drop the is_pointer guard from my WIP). PAIRED FAITHFUL PORT (not a hack — Ghidra needs it too since INT_SUB is gone): printer reconstructs subtraction from `a + (b*-1)` / `a + (-c)` → `a - b`; port from printc.cc (binary_minus/unary_minus tokens at printc.cc:40/31; the INT_ADD-with-negative-operand rendering — my WIP showed un-reconstructed `xVar1 + -40`).
WIP IMPL (all reverted, tree clean at 967edcb), 4 parts: (1) type entry RSP spacebase+Pointer(8,unk1) in ActionInferTypes; (2) RuleSub2Add in ptrarith.rs — make UNCONDITIONAL; (3) ptrarith_pool MUST be Sub2Add→ConstFold→**PropagateCopy**→PtrArith (ConstFold leaves COPY-const so propagate is required to feed the constant into the INT_ADD); (4) printc ALREADY renders `&Stack_<off>` via stack_addr() (printc:437) for INT_ADD(RSP,c) — RuleSub2Add alone flips the frame into that path (RulePtrArith made no PTRSUB for stackstring; PTRSUB likely needed only for multi-level/array). WIP got stackstring `xVar1=&Stack_28`, corpus FLAT 0.8040/green. REMAINING: (i) frame base spills `xVar1=&Stack_28;f(xVar1)` not `f(&Stack_28)` — 2nd call's `&Stack_c` DOES inline, so it's the frame-base value being explicit [is_explicit]; (ii) `Stack_`→`xStack_` prefix in stack_addr; (iii) multi-level `RSP-8-0x90` needs pointer/spacebase flag to propagate to inner INT_ADD/PTRSUB output; (iv) full corpus + p-q ptrdiff regression check; (v) ground rule-pool fixpoint (RuleCollectTerms/RuleTermOrder converge on the `*-1` form as Ghidra oppool1 does). Land as ONE green commit; never half-green.

---

As of 2026-06-22 the mosura direction was reset by the user. The objective is to
**translate Ghidra's C++ decompiler to Rust** (a bounded ~100k-LOC codebase under
`../ghidra/Ghidra/Features/Decompiler/src/decompile/cpp`), validated against Ghidra's
**intermediate IR exactly, stage by stage** — NOT to maximize the token-skeleton
structural-similarity score on the ~50 datatests.

**Why:** the similarity score diverges from the objective — it rewards approximations
that coincidentally match Ghidra's tokens and punishes faithful algorithms (every
"more-correct-but-net-negative, reverted" result was this), and approximations don't
compose. The plan is now a faithful port of Ghidra's data model (the **Varnode-graph
SSA**) + the **`Action`/`Rule` pipeline framework** (the missing keystone), then
`Heritage` → rules → dead code → types → merge → prototypes → structuring → PrintC,
each gated on IR-parity vs Ghidra.

**Keep:** the SLEIGH engine (254/254 parity). **Rebuild:** the decompiler core in a new
`src/decompile/` (mirroring Ghidra file/class names); the old `src/decomp/` prototype is
a coarse gauge, retired stage-by-stage. The `datatest_score` ratchet is **demoted** — no
longer a gate.

**Written plan:** `mosura/docs/port-plan.md` (master), `mosura/TODO.md` (phases P0–P8),
`mosura/AGENT.md` (updated validation principle). Approximation-era docs
(floats/switches/type-system/decompiler-plan) are bannered superseded. Detailed
per-feature grounding (Ghidra source refs, why each approximation was net-negative) is in
the repo's `.claude/memory/mosura-project.md`.

**P0 DONE** (commits `598ec93`..`b328503`): faithful Varnode-graph data model in
`src/decompile/` (opcode/space/varnode/op/block/funcdata, arena+index); `build.rs::
raw_funcdata` (lifter→Funcdata, Ghidra-shaped raw p-code); `action.rs` Action/Rule
framework (ActionGroup restart-to-fixpoint, ActionPool); `oracle/capture --ir [action]`
dumps Ghidra per-phase IR via `printRaw` at an action breakpoint; `tests/ir_parity.rs`
gate (mosura covers Ghidra's pre-heritage instruction addresses). 254/254 disasm parity
intact.

**P1 — Heritage: CORE DONE, advanced features remain.** Commits through `671a7e7`.
DONE + validated: `cfg.rs::build_cfg` (blocks + reachability prune; calls don't split
blocks; ranges match Ghidra for flow-aligned funcs), `dominator.rs` (Cooper idom +
frontiers), `heritage.rs` (semi-pruned Cytron SSA — reads linked, single-assignment, phi
arity=#preds; def-use matches Ghidra on x86_64_sem), `build.rs::raw_funcdata_flow`
(faithful followFlow). The condconst/boolless/ifswitch block-range divergences are a
lifter jump-target bug + P7 jump tables, NOT flow drift.
Also DONE (`ca3533b`): **read-side refinement** (`heritage.rs::normalize_read_size`,
Ghidra's `normalizeReadSize`) — a sub-register read of a single-width-written location
becomes `SUBPIECE(W,0)` of a full-width read; closes the clean overlap gap (twodim/
threedim fully, elseif reduced), invariants hold, regression-guarded. Added
`Funcdata::new_output_unique`/`set_block_ops`.
**REMAINING P1 (edge-case / cross-phase — do as-needed, faithfully):** (1) **write-side
refinement** (`normalizeWriteSize`/PIECE for partial writes — 8/16-bit AL/AX; rare in
x86-64 since 32-bit writes zero-extend) + cross-offset CONCAT. (2) **INDIRECT guards**
for calls (post-call reads of clobbered regs must depend on the call) — naturally done
WITH **P6** (needs the call-effect/clobber model) + entry `DF=0`. (3) multi-pass
iteration. Heritage now produces correct SSA for the common case; these close the tail.
**P1 heritage core is complete and validated.** Reasonable to proceed to P2 (rule pool)
and revisit (1)-(3) when a concrete function needs them.

**P2 — Rule pool: CORE done.** Commits through `~a0609f2`+pipeline. `funcdata.rs`
op-rewrite primitives (`op_set_opcode`/`op_remove_input`/`op_swap_input`/`total_replace`/
`mark_dead`). `rules.rs` (ports of `ruleaction.cc`): `RuleConstFold` (+`eval_const`
mirroring emu's parity-validated p-code semantics), `RuleTrivialArith` (x OP x),
`RuleTermOrder` (const→slot1), `RuleIdentityEl` (x+0/x*1/x*0), `RuleTrivialShift`. All
unit-tested + integration (folds to fixpoint, no live ops added). `pipeline.rs` assembles
the universal action: `ActionHeritage` (CFG+dom+SSA) → `default_rule_pool()`;
`pipeline::decompile(f)` runs it end-to-end. Also `RuleCollectTerms` (binary form: a*c1+a*c2→a*(c1+c2), a+a→a*2; `op_set_all_input`;
unit-tested a+a*2→a*3; deeper trees collapse pairwise at fixpoint — full N-ary gather
remains). REMAINING P2 tail: copy-propagation, SUBPIECE/MULTIEQUAL pull-through,
`RuleSub2Add`, ~90 others (drop-ins; no single one closes the gap).

**P3 — Dead code: DONE** (`deadcode.rs::ActionDeadCode`, `eee3408`). Whole-varnode
liveness seeded from sinks (return/branch/store/call consume inputs), propagated backward;
removes the pool's collapsed ops + dead computations. `Funcdata::op_destroy`. Wired into
the pipeline. INTERIM (important wart): seeds SysV return regs RAX(0x0)/XMM0(0x1200) as
live-out roots because the return value isn't wired to RETURN yet (that's P6
ActionReturnRecovery) — without it deadcode nuked the whole computation (x86_64_sem→1 op).
x86-specific + over-keeps; P6/addrtied replaces it.

**P5 — Merge: STARTED** (`merge.rs`, `3d24838`). `HighVariables` union-find over Varnodes
(each class = one C variable) + `Merge::mergeMarker` (a MULTIEQUAL/INDIRECT output is one
variable with its non-const inputs — threads SSA versions across control flow: loop
counters, merged conditionals). Unit + integration tested (phi versions merge, variable
count drops). `merge::merge(f) -> HighVariables`; standalone (no pipeline consumer until
P8 PrintC). Also added `Funcdata::op_set_all_input`, `RulePropagateCopy` (P2, copy-prop).
**P5 increment 2 DONE** (`5ec40bd`): `cover.rs` — per-varnode liveness (Ghidra `Cover`),
half-position model (op i reads 2i+1 / writes 2i+2 so a def doesn't interfere with the use
it consumes — `x=x+1` mergeable), ground-truth unit-tested. `merge_same_storage` greedily
unions non-interfering HighVariables at the same storage → reused regs/scratch become one
variable. Validated: no two versions of one variable simultaneously live; realistic counts
(x86_64_sem 10 SSA→6 vars, twodim 36→13, threedim 57→21, elseif 196→25). **P5 variable
grouping COMPLETE.** Remaining P5: variable **naming** — deferred to its consumer P8 PrintC
(or a NameVars action).

**P7 — Structuring: CORE DONE** (`structure.rs`, `81ef902`). Structured `FlowBlock` graph
+ ported `CollapseStructure` reducible rules: `ruleBlockCat`(list), `ruleBlockProperIf`,
`ruleBlockIfElse`, `ruleBlockWhileDo`, `ruleBlockDoWhile`. Iterates to fixpoint; out-edges
source-of-truth, in-edges recomputed per pass; CBRANCH order [false,true]. Unit-tested per
shape; fully structures reducible CFGs (x86_64_sem/twodim/threedim/boolless → 1 block).
REMAINING P7: `ruleBlockOr` (short-circuit &&/||), `ruleBlockGoto` (irreducible), switch,
condition negation — elseif(8)/condconst(3) stall pending these.

**P8 — PrintC: STARTED, EMITS REAL C** (`printc.rs`, `a627ad6`). Expression rendering
(precedence-aware parens, signed constants), variable naming (params by SysV reg,
HighVariable names), explicit/implicit (single-use inlining), function signature,
return-value inlining, linear block emission. **On straight-line functions the body
matches Ghidra EXACTLY** — x86_64_sem → `return param_1 * 3 + -5 + (param_2 >> 2);` (only
type names differ; P4 supplies them, comparator erases them). Return value via a heuristic
(last write to RAX/XMM0) until P6. **Structured control-flow emission DONE** (`f41beb2`):
walks the `structure.rs` tree → if/else/while/do-while, condition from the exit CBRANCH
(negated per the branch via `FlowBlock::negated`). threedim emits a `while`. The
control-flow + expressions are recovered; the distance to Ghidra's quality is NOT
structuring but: **(1) stack-variable recovery — THE biggest gap** (raw RSP/RBP frame ops
`uVar1=uVar1-8; *uVar1=...` aren't abstracted to locals; Ghidra elides the frame; the old
prototype did this via recover_stack — needs faithful stack-space heritage + local mapping),
(2) flag-condition simplification (`a==0||SBORROW(..)!=a<0` → `a<29`: RuleSborrow + the rule
tail), (3) casts, P4 types, P6 return/params, gotos for irreducible CFGs. Meaningful
whole-corpus measurement vs Ghidra's `--c` awaits stack recovery (it dominates the noise).

**STACK RECOVERY DONE** (`stackvars.rs`, `179f076`): forward symbolic stack-pointer flow
(Ghidra `ActionStackPtrFlow`/spacebase) — `*(RSP/RBP+c)`→`stack[c]`, heritaged like regs;
spilled params link, frame collapses (twodim 47→31 ops, params flow directly). RSP/RBP
unified via entry-RSP; runs pre-heritage (tracks by location since reads aren't linked yet).

═══════════════════════════════════════════════════════════════════════════════════
**HANDOFF — read this first (fresh agent picks up here). HEAD = `5308808`.**
═══════════════════════════════════════════════════════════════════════════════════

**STATE:** committed `5308808` ("type-width SUBPIECE casts"), tree clean, ALL GREEN —
`cargo test -p mosura` = 75 lib + ir_parity + 254/254 disasm. Corpus **avg 0.7021, 38/62 ≥ 0.70**
(C-similarity, image flow). The analysis-track WIP (loader/snapshot) lives in a SEPARATE workspace
now — ignore it; this track is the decompiler only (`crates/mosura/src/decompile/`).

**METHOD (the rule that matters — see AGENT.md "decision rule"):** faithful translation of Ghidra's
C++ decompiler, validated against Ghidra's **IR/`--c` output**, NOT the C-similarity gauge. Keep a
parity-clean faithful change even if the gauge dips; port Ghidra's ACTUAL code, never invent a
heuristic. **HARD LESSON FROM THE LAST SESSION (I burned hours on it): GROUND THE IR/Ghidra OUTPUT
*BEFORE* WRITING CODE.** Dump the actual mosura IR + run `oracle/capture <ghidra> <fixture> --c` and
read them; do NOT trust memory or guess the mechanism. I guessed the cast mechanism ~5 times and
reverted ~5 times — every premise (cast renderer, copy-prop guard, normalizeWriteSize, addrtied) was
wrong, disproved only by finally reading the IR. Don't repeat that.

**IR-FAITHFULNESS METRIC (the port driver):** `oracle/capture <ghidra> <datatests/X.xml> --ir cleanup`
dumps Ghidra's simplified IR (printRaw). Compare to mosura's live op count (`raw_funcdata_flow`
single-chunk + `pipeline::decompile`, sum of block ops). Currently **mosura 1281 vs Ghidra 1350 = 0.949x**,
total |gap| 503. The OVER-side (mosura > Ghidra = under-simplified) is the clean signal and is largely
worked out; the UNDER-side is murkier (breakpoint mismatch — mosura's pipeline is shorter than Ghidra's).
Datatests: `ghidra/Ghidra/Features/Decompiler/src/decompile/datatests/*.xml`. `--ir` is single-chunk
only (multi-chunk funcs → 0 ops, skip). ROADMAP = Ghidra's `universalAction` order (coreaction.cc:5474):
ActionPrototypeTypes, ActionParamDouble (←concatsplit CONCAT44), ActionInferTypes (←casts),
ActionLaneDivide (←mixfloatint XMM lanes), ActionMultiCse, ActionConditionalExe, + ~120 rules.

**WINS THIS EFFORT (committed):** `676c109` sub-register reconciliation + CSE; `0b200ed` signed
mod-2^k; `8f16763` De Morgan condition negation; `252d752` `c<x`→`x<c+1`; `c12c4fe` **RuleSubExtComm**
(push SUBPIECE through ZEXT/SEXT — moved the metric 1.34x→0.949x); `5308808` **type-width SUBPIECE casts**
(`PrintC::effective_width` = highest byte any use reads; a truncating offset-0 SUBPIECE renders `(int4)x`
iff `effective_width(input) > out_size`; x86_64_sem's Ghidra-exact test guards against over-casting).

**TYPES + CASTS SUBSYSTEM PORTED (2026-06-24, COMMITTED `a1867e7`, `79f5406`, `9351f25` on `3383e45`).
All green: 82 lib + ir_parity + 254/254 disasm.** Three increments:
(1) `a1867e7` `propagateOneType` (below). (2) `79f5406` **cast subsystem** — new `cast.rs` ports
`CastStrategyC::castStandard` (`cast.cc`); `printc` gains `get_input_cast` (`TypeOp::getInputCast`
for the comparisons) + `cast_operand`, routed through the binary-op renderer: a signed `INT_SLESS`/
`SLESSEQUAL` on a non-signed operand prints `(int4)x` (constants are NOT wrapped — the literal adopts
the type, like Ghidra `castInput`). (3) `9351f25` — `render_negated` (the if/while false-edge path)
also routes operands through `cast_operand`, so flipped signed bound checks keep the cast. RESULT on
loopcomment: `(int4)uVar2 < 0xa`, `(int4)uVar2 < 0x14`, `(int4)uVar2 < 0x7d0`, `(int4)param_3 <= 0x1d`
— matching Ghidra's `(int4)param_1 < 10` etc. **Verified via IR: RuleSborrow DOES recover the signed
compares (the ops are `INT_SLESS`); the missing casts were purely a printc-wiring gap, now closed.**
CAST TAIL + P6 PARAM TYPES PORTED (2026-06-24, COMMITTED `33d8ed7`, `123149c`, `ce7dc9f`): (a) **P6
param symbol types** — `print_c` forces each parameter's whole HighVariable to `undefined<N>` (mirrors
Ghidra type-locking the param symbol to the prototype), so params declare `undefined4` (=Ghidra
`xunknown4`) and become cast sources. (b) **SEXT input casts** — `get_input_cast` handles `IntSext`
(care_uint_int=true) + the SEXT renderer routes through `cast_operand` → `(int8)(int4)param`. (c)
**pointer-deref casts** — `render_mem` emits `*(vty *)(addr)` when the address isn't genuinely a
matching pointer; an arithmetic-computed address is treated as int-natured (else the LOAD's
back-propagated pointer temp-type would wrongly suppress the cast). (d) **markExplicitUnsigned** —
`5U`/`4U` on sign-inheriting ops' unsigned/undefined constants, with a sign guard (mosura doesn't type
constants, so skip small-negatives so `+ -5` stays). **RESULT: twodim now nearly matches Ghidra** —
`(((int8)(int4)param_1 * 5U ...) * 4U + 0x601060)`, `*(... *)(...)`, all cast structure identical.
VALUE-TYPING + RENDERING PORTED (2026-06-24, COMMITTED `6285c1f`): closed diffs (1),(3),(4),(5) below.
**twodim is now NEARLY IDENTICAL to Ghidra** (only param/return WIDTH 8-vs-4 differs). Done: (a) **symbol
types** — `printc::type_of` downgrades an `int`/`uint` to `undefined<N>` for *explicit* (named) varnodes
(params/locals/globals) + `symbol_type` for the return type and deref-cast access type; Ghidra recovers
no type for these stripped binaries so int-ness shows only as casts at uses. Replaced the narrower P6
param override with this one rule; inlined intermediates (a SEXT result) keep their produced type so
`5U` still fires. Globals now render `(int8)(int4)xRam`. (b) **`xunknown<N>` naming** (`Datatype::name`,
Ghidra core type `sleigh_arch.cc`) + locals named by type prefix (`xVar`/`iVar`/…, not fixed `uVar`).
(c) **decimal consts** — ported `mostNaturalBase` (small/round → decimal `10`/`100`/`1000`, masks → hex).
(d) **local var declarations** emitted at the top of the body.
**STRUCTURAL WORK (2026-06-24): power-of-2 modulo DONE (`c68bfb6`) — ported `RuleSignMod2nOpt2` (the
division-form `x-((x+(x>>w-1))&~1)` ⇒ `x%2`, the mod-2 case the prior session reverted) + div/rem input
casts; **modulo2 0.483→0.941, corpus 0.7587→0.7626**. Then DIVISION-CHAIN (`8356508`) — ported Ghidra's
`RuleDivOpt::findForm` + `checkFormOverlap` faithfully (the simple `mulhi(ext(x),magic)>>e` form, no
add-correction, that mosura's ad-hoc try_unsigned/try_signed missed); once the division becomes
INT_SDIV/INT_DIV, the existing RuleModOpt collapses `x-(x/d)*d`→`x%d`. modulo's %3/%5/%6/%10 recover;
**corpus 0.7626→0.7665, 43/60**. NOTE: Ghidra's width ext/trunc branch (x not output-width) is restricted
OUT — mosura's printer renders the inserted ZEXT/SEXT where Ghidra absorbs them, moving output AWAY from
`--c` (modulo 0.61→0.51 if included). NOTE 2: mosura's `RuleModOpt` roots on INT_SUB (mosura keeps INT_SUB)
where Ghidra roots on the division + INT_ADD-of-neg (needs `RuleSub2Add` canonicalization mosura omits) —
a shape-adaptation, not yet a 1:1 port.
**USER DIRECTIVE (CRITICAL, 2026-06-24): "port Ghidra, don't be creative; when you find a creative
invention in mosura, nix it and port Ghidra."** I violated it once (an invented escape-detector for
switchmulti's addrtied issue) and REVERTED it — the faithful fix is `Heritage::guardCalls`+`addrtied`
(needs the Scope/Symbol layer mosura skipped). REMAINING gains all need DEEP interconnected subsystems
mosura never ported: **Scope/Symbol/database** (gives `addrtied`/`mapped`/symbol-types — keystone for
prototypes, the guards, and faithful (un-approximated) symbol typing), **FuncCallSpecs/EffectRecord**
(param recovery, real `recover_call_effects`), **ActionSetCasts** (insert real CAST ops — retires the
render-time cast scaffolding `effective_width`/`symbol_type`/`arithmetic_addr`), the **division chain
tail** (`RuleDivTermAdd`/`RuleSub2Add`). The render-time printc approximations are scaffolding for these
unported subsystems — nixing them faithfully REQUIRES porting the subsystem, not a rip-out. SWITCHES + STRUCT GROUNDED AS DEEP MULTI-ISSUE (NOT
bounded, deferred — don't rush a partial): switchmulti(0.37) ROOT CAUSE = an address-taken stack local
`&xStack_28` passed to a call is constant-folded across the call (mosura doesn't model the call writing
through the pointer), so the guard `xStack_28!=0` folds to `if(0)` and everything collapses. **FAITHFUL
FIX = port Ghidra's `Heritage::guardCalls`/`guardStores`/`guardLoads` (`heritage.cc:1443+`, gated on the
`Varnode::addrtied` flag mosura already defines but never sets) + mark address-taken stack slots addrtied.
This is the P1 "INDIRECT guards" remainder. DO NOT invent an escape detector — I tried a creative
arg-register scanner (2026-06-24) and reverted it; the user's rule: port Ghidra, don't be creative.**
piecestruct(0.54) = no sub-byte param recovery + CONCAT22/31 splitting (P6 `ActionParamDouble`), no
FS-segment/stack-canary recognition (`in_FS_OFFSET`), CONCAT rendering. Each is a focused subsystem.
Lowest scorers longdouble/mixfloatint (0.14) are the float ABI / XMM-lane LIFTER layer, not decompiler.

**NEW-TRACK CORPUS MEASUREMENT (2026-06-24, `cdda2d5` `tests/decompile_corpus.rs`): avg 0.7586, 42/60
≥0.70 — the faithful `decompile` track has now PASSED the old `decomp` prototype (0.7021/38).** twodim
0.989, nestedoffset/inline/namespace 1.000. Worst (the real next levers, all STRUCTURAL): longdouble
0.14/mixfloatint 0.15 (float ABI/XMM lanes — lifter), switchmulti 0.37/switchloop 0.39 (switch P7),
floatconv/nan (float), modulo2 0.48/modulo 0.54 (pow-2 modulo rule), piecestruct 0.54 (struct/CONCAT P6),
stackstring 0.57, deindirect 0.61, divopt 0.61, orcompare/revisit 0.67 (branchless bool flags).
**KEY COMPARATOR FACT (read `decomp/ccompare.rs::normalize`): it erases ALL identifiers→`ID`, ALL type
names→`T`, ALL numbers→`N`, and grouping `(){};,`. So variable NAMES (xVar vs xStack), TYPE-name spelling
(undefined vs xunknown), and CONSTANT formatting (10 vs 0xa) have ZERO score impact — this session's
naming/const/type-name polish was pure fidelity/readability, not score. What MOVES the score: structure,
operators, KEYWORDS, and the count/sequence of `T` (each cast = one T), `ID`, `N`. So the score levers are
STRUCTURAL (the low-scorers above), and casts (T-count) — NOT naming.** Stack-local naming committed
(`88f296e`, `xStack_<off>` + decls) for fidelity; corpus flat 0.7587 as predicted.

**STILL OPEN — param/return WIDTH (deep P6, fully diagnosed, ~1 token so low score value, NOT a render
fix):** ROOT CAUSE pinned to `heritage.rs::normalize_read_size`: it canonicalizes `(reg,0x30)` to width 8
because there's a single write (`RSI = SEXT48(EDX)`) and a narrower read (the `ESI:4` param), so it widens
the param read to `SUBPIECE(RSI:8)` and the param input becomes `RSI:8`. But the ESI:4 param read happens
*before* that write — independent values sharing storage; Ghidra keeps the param at the convention's
4-byte width. Pre-heritage the widening can't tell the param read isn't reached by the wide write, and the
general widening HELPS other cases (forloop_varused, switchloop) so it can't just be removed. Fix needs the
convention/`ParamActive` model OR pre-heritage reachability. Earlier framing kept for context:
mosura declares
`xunknown8 param_2` where Ghidra has `xunknown4`. ROOT CAUSE (grounded via `--ir` + input dump): the
raw IR (shared lifter) reads the param as `ESI:4` (`tmp:4 = ESI`), but mosura's heritage
`normalize_read_size` **widens the param-register input to the full `RSI:8`** (canonicalizes the
sub-register read to storage width). Ghidra keeps the param at the calling-convention's 4-byte width
(`getBase(4,TYPE_UNKNOWN)`) and treats the wider read as a `SEXT` of the 4-byte param. Fix = the
prototype/`ParamActive` model giving heritage convention-aware param sizing so it does NOT widen an input
register past the convention width. Heritage-level subsystem; do it deliberately, not a printc tweak.
Also still open: stack-local *naming* (mosura `xVar1` vs Ghidra `xStack_28` by frame offset).

**`propagateOneType` PORTED (`a1867e7`).**
`infertypes.rs` is now a faithful port of `ActionInferTypes` (`coreaction.cc`): `buildLocaltypes`
(`getLocalType` via per-op `inputTypeLocal`/`outputTypeLocal` metatypes) → `propagateOneType` DFS
(`PropagationState`/`step`/`valid` + `propagateTypeEdge`) → `writeBack`, with the per-op
`TypeOp::propagateType` rules (COPY/MULTIEQUAL/INDIRECT relay; signed-compare relays signedness;
EQUAL/LESS relay via `propagateAcrossCompare`; LOAD/STORE pointer↔pointee). `types.rs` gained the
faithful `type_order` (Ghidra `Datatype::compare`: `submeta` then bigger-size-first) + `submeta()` —
this is the storage-decoupling: a type is installed on a varnode when it orders strictly *more
specific*, regardless of either width, not pinned to `vn.size`. Observable: types now propagate
transitively (loopcomment `param_2` undefined8→**uint8**, `param_3` int4→**uint4**, faithful to the
unsigned compares). All green (79 lib + ir_parity + 254/254 disasm). Deferred faithfully (need the
aggregate lattice / are no-ops for primitives): `propagateAcrossReturns`, `propagateSpacebaseRef`,
SUBPIECE/PIECE-into-composite, INT_ADD/PTRADD pointer arithmetic (`propagateAddIn2Out`/`downChain`).

**DIAGNOSIS CORRECTION — the prior handoff's "int8 / storage-decoupled width cast" premise was a
MISREAD. Re-grounded `oracle/capture <g> loopcomment.xml --c` + `--ir`:** the 9 casts are
`(int4)param_1`/`(int4)xStack_NN` where the var is declared **`xunknown4` (undefined4, 4 bytes)** — they
are **SIGNEDNESS casts (undefined4 → signed int4 at signed compares), NOT width casts (int8→int4).**
The IR confirms the param is `EDI:4` (4-byte, `u0x0000d400:4 = EDI`), and the signed `<` comes from
`SBORROW4`. There is NO int8 anywhere; types are storage-*coupled* here. So a "type-width exceeds
storage" model is NOT what produces these casts. **The actual producer is the CAST subsystem**
(`CastStrategy::castStandard` + `TypeOp::getInputCast`, Ghidra's `ActionSetCasts`/"casts" group):
`INT_SLESS` requires `TYPE_INT` inputs, so `castStandard(int4, undefined4)` inserts `(int4)`.
`propagateOneType` (now done) is the *prerequisite* that gives each varnode a faithful type; it does
not by itself emit casts. **NEXT: port `ActionSetCasts`/`getInputCast`/`castStandard`** — that's what
turns the now-faithful types into `(int4)param_1`. (Aside: mosura's params are often the *full* 8-byte
register, e.g. `uint8 param_2`, where Ghidra recovers a 4-byte `undefined4` param — a param-recovery/P6
width difference, separate from casts.) The committed `effective_width` (printc) is an unrelated
width-cast heuristic for the genuinely-wide cases (modulo2 register multi-width); leave it.

**ALSO STILL OPEN (subsystems):** float ABI (mixfloatint/longdouble — XMM lane offsets like reg_0x41244
with a +0x40000 stride are a SLEIGH *lifter*-layer concern, not decompiler); P6 prototype/param model
(concatsplit/piecestruct CONCAT44/CONCAT22 splitting, ActionParamDouble); the rest of the TypeOp/Cast
suite; switch polish. modulo's residual IR +147 is a single-chunk artifact (magic constants in an absent
data chunk; image flow recovers them) — NOT a rule gap, don't chase it.

**TOOLING GOTCHAS:** (1) corpus/measurement examples — a `println!` arg-count typo build-FAILS silently
under `2>/dev/null` and a STALE `target/debug/examples/_X` binary then runs with OLD output. Always run
`cargo build -q -p mosura --example _X 2>&1 | grep error` first, or don't pipe stderr to null. (2) ALWAYS
verify Ghidra's `--c` for the target function before coding a feature — my "memory" that divopt casts
`(uint8)*p` was FALSE (Ghidra types the param `uint8 *`, so `*param_1` is uint8, no cast).

───────────────────────────────────────────────────────────────────────────────────
Historical session log below (most recent first); superseded details may differ from the handoff above.

Earlier (C-score era):
**(`252d752`): avg ~0.6985, 38 ≥ 0.70 (IMAGE flow, source-built Ghidra 12.0.3).**
`252d752`: negated `c < x` (constant on left) renders the strict `x < c+1` not `x <= c`
(Ghidra's print-time negation; `incr_in_width` guards overflow) — loopcomment guard →
`uVar2 < 10` matching Ghidra; exact identity, parity-clean, corpus net-flat (localized).
**SEAM-EXHAUSTED NOTE:** after this session's bounded-rule wins (sub-register+CSE 676c109,
modulo 0b200ed, De Morgan 8f16763, c+1 252d752), every remaining low-scorer probed bottoms
out in a SUBSYSTEM, not a one-rule fix: (a) **casts/P4** — Ghidra's `(int4)param_1`,
`(uint8)*p` type-driven cast insertion (`CastStrategy`/`PrintC::opCast`); mosura renders
SUBPIECE transparently. Broad (loopcomment/divopt/modulo2/many). (b) **P6 prototype model** —
param→`CONCAT44/CONCAT22` splitting + stack params (concatsplit/piecestruct), param typing.
(c) **stack-frame elision** — loopcomment's `uVar1=uVar1-8` is the push-rbp/sub-rsp prologue
(INT_SUB→STORE) not fully elided; also a suspicious 0x58300 offset from `and rsp,-0x10`
(possible lifter quirk). (d) **SLEIGH XMM map** (float cluster — lifter layer, reg_0x41244
+0x40000 stride). (e) **write-side heritage** `normalizeWriteSize` (CONCAT range model).
NEXT SESSION: pick ONE subsystem (casts/P4 is broadest + mosura has the type foundation;
P6 prototypes is the keystone the memory keeps flagging) and port it end-to-end. Earlier:
**(`8f16763`): avg ~0.6985, 38 ≥ 0.70 (IMAGE flow, source-built Ghidra 12.0.3).**
Latest (`8f16763`): **DE MORGAN condition negation** in printc — a short-circuit condition on
the body's false edge was rendered `!(a||b)`; now `render_cond_expr` threads a `negated` flag
that pushes the negation inward (`!(a||b)`→`!a&&!b`, recursing + flipping leaf comparisons), so
no leading `!` survives on a compound condition. loopcomment guard → `(uVar2<=9)&&(0x64<param_2)`
(was `!((9<uVar2)||...)`), 0.634→0.661; broad (every negated compound cond). NOTE remaining
loopcomment/others gap: `x<=c` vs Ghidra's `x<c+1` (Ghidra negates `c<x` to the strict form) —
murky whether IR-rule or render-level; didn't chase. Also NOTE: the float cluster's weird XMM
offsets (reg_0x41244 = 0x1244+0x40000 stride) are a SLEIGH/lifter-layer concern, not decompiler;
concatsplit/piecestruct need the P6 prototype model (param→CONCAT splitting), a real subsystem.
Earlier this session:
**(`0b200ed`): avg ~0.6966, 38 ≥ 0.70 (IMAGE flow, source-built Ghidra 12.0.3).**
This turn the user called out a recurring mistake: I kept REVERTING parity-clean faithful
changes when the C-similarity gauge dipped, and inventing heuristics instead of porting Ghidra.
Fix landed in **AGENT.md → "The decision rule"**: ccompare is a coarse gauge, NEVER the gate;
keep a change that passes ir_parity+disasm and matches Ghidra's IR even if the gauge dips; a dip
after a faithful change means a DOWNSTREAM consumer isn't ported yet — port it, don't revert the
upstream; only revert genuinely WRONG output; never invent a heuristic where Ghidra has code.
PROVEN by re-landing the work I'd wrongly reverted: **SUB-REGISTER RECONCILIATION + CSE**
(`676c109`) — heritage `normalize_read_size` now canonicalizes an x86-64 self-zero-extension
register (`O:8=ZEXT(O:4)`) to its full width, narrow reads → `SUBPIECE(O:8)` (Ghidra's
full-register heritage range); alone it dipped the gauge (broke nothing — parity green) because
the duplicate SUBPIECEs blocked the signed-compare/`x&x`/`x^x` idioms, so I ported the CONSUMER:
`RuleSelectCse` (Ghidra `ruleaction.cc`/`cseElimination`, on SUBPIECE+INT_SRIGHT) + `RuleIdempotent`.
As a whole subsystem: forloop_varused fully recovers, switchloop's loop var unifies (spurious
`param_4^param_4` gone), floatconv 0.419→0.476, avg 0.6938→0.6959, good 37→38. Then **SIGNED
MODULO BY POWER OF TWO** (`0b200ed`): ported Ghidra `RuleSignMod2nOpt` (`((x+corr)&(2^k-1))-corr`
⇒ `x%2^k`) matched against mosura's folded INT_SUB shape; modulo's `%2`/`%4` recover, 0.532→0.579.
NOTE attempted modulo2's division-form (`RuleSignMod2nOpt2`, `base-((base+corr)&~(2^k-1))`) — its
mosura IR is `INT_ADD(base, INT_MULT(and,-1))` (same as Ghidra), but my port misfired (broke the
pipeline test) and the exact shape stayed elusive; REVERTED as genuinely-broken (correct per the
rule — a test break is WRONG output, not a gauge dip). modulo2 needs proper IR investigation.
Prior baseline: **(`cb95592`): avg 0.6938, 37 ≥ 0.70 (IMAGE flow, source-built Ghidra 12.0.3).**
NOTE: the `ghidra/` symlink now points to a SOURCE CLONE (tag Ghidra_12.0.3_build), not a binary
distro — run `scripts/setup-oracle.sh` to build sleigh_opt/decomp_dbg/decomp_test_dbg + compile
the `.sla` specs + `oracle/capture` (C++ toolchain only, no Gradle). SWITCH-IN-LOOP DONE
(switchloop 0.126→0.432): `rule_switch` defers until each case collapses to ≤1 exit (cat its
single-entry "break" tail first), printc emits `break;` per non-terminal case, and cfg's decline
heuristic is refined to single-vs-multi loop-exit (single=recover like switchloop, multi=decline
like switchmulti which Ghidra calls "too many branches"). Also in-code jump tables (validation-
based detection, ifswitch 0.404→0.683, switchind→0.800). switchloop's remaining gaps: loop-var
phi rendering, bound-check→`default:`. Prior reframe-driven wins (heritage indirect targets,
(code*) cast, XMM0:4 return, call-clobber/extraout, loop-header guard):

**(`9b00c8e`): avg 0.6832, 37 ≥ 0.70 (IMAGE flow).** The user's reframe — "don't
mistake the thermometer for the temperature; a faithful port of Ghidra keeps parity by
construction, so internals aren't 'risky'" — unlocked a string of wins I'd wrongly avoided:
(1) HERITAGE INDIRECT TARGETS: `read_loc` skipped slot 0 for ALL branch/call ops, but
BRANCHIND/CALLIND targets are dataflow → heritage them (deindirect resolves `(*(code*)0x1006ca)`).
(2) `(code *)` cast on indirect calls. (3) XMM0:4 return candidate (float cluster was NOT a
sleigh bug — floatconv 0.171→0.419, just a return-recovery gap). (4) CALL CLOBBER
(`recover_call_effects`, Ghidra's ActionFuncLink): INDIRECT-mark RDI/RSI/RDX/RCX/R8/R9 after
each call so a later call's leftover "arg" is dropped (deindirect's 2nd call 3→1 args); printc
names a read-after-clobber `extraout_<reg>`. (5) LOOP-HEADER GUARD: `rule_if_no_exit` was
dissolving loop headers (collapsing `if(cond)return` before the multi-block body could collapse
for `rule_while_do`), dropping the back-edge → guard with `reaches(other,b)` so loops form
(forloop_varused 0.576→0.857, forloop_withskip→0.912). REMAINING intricate: float-compare
idioms (nan), SysV float-param numbering (mixfloatint), CONCAT write-side heritage (concatsplit/
piecestruct), power-of-2 modulo, longdouble(x87), switch-in-loop structuring (switchloop). Prior:

**(`1c5c0a4`): avg 0.6625, 32 ≥ 0.70 (IMAGE flow).** CONDITION COLLAPSE added:
`RuleBoolNegate` (negated comparison→complement: `!(a==b)`→`a!=b`, `!(a<b)`→`b<=a`, exact for
0/1 cmps, reaches negations nested in BOOL_AND/OR), `RuleRangeAnd` (`(x!=c)&&(x<=c)`→`x<c`,
swapped/signed forms — disequality strips the equality off `<=`), and render_negated now flips
`!(a<b)`→`b<=a` at emit. Broad: varcross 0.582→0.649, loopcomment +0.03, deindirect 0.460→0.494,
ifswitch +0.03. REMAINING ALL INTRICATE per-function: (1) INDIRECT-TARGET RESOLUTION is a
heritage gap — CALLIND/BRANCHIND targets come out as unwritten unique/RAX (deindirect's
`(*uVar5)` not folded to `0x1006ca`; switch index needs the bound-check fallback). Likely the
indirect-target input isn't registered as a use → its def dead-code-removed; a fix here is
BROAD (calls + switches). (2) struct/aggregate types (piecestruct, packstructaccess packed-reg
returns, concatsplit reg-params-spilled-to-stack + CONCAT44). (3) value-merge/CSE (uVar2=uVar1
dup from call-arg re-establishment). (4) stack-string recognition. (5) float-XMM (SLEIGH bug).
(6) power-of-2 signed modulo. (7) switch `default:` inside (now the bound-check else). Earlier:

**(`2aab9b1`): avg 0.6572, 31 ≥ 0.70 (measured via the IMAGE flow).** SWITCHES
DONE for the recoverable cases. `build::raw_funcdata_flow_image(spec,name,chunks:&[(u64,&[u8])],
entry,ctx)` flows over a multi-chunk memory image and recovers jump tables at a BRANCHIND:
table base = latest const addressing a data chunk (the `lea`), 4-byte relative entries
(target=base+(i32)entry, in-code), follows the case targets → `f.switch_targets:HashMap<pc,
Vec<target>>`. cfg.rs wires case edges + DECLINES switches whose cases cycle back through the
dispatch (switch-in-loop = Ghidra's "too many branches" → indirect) by dropping edges +
op_destroy-ing pruned blocks' ops (else heritage's cover panics on orphan defs). structure.rs
`rule_switch`/`FlowKind::Switch` collapses a ≥3-way head + single-in cases. printc emits
`switch(idx){case N:…}`, grouped labels from switch_targets, idx via the bound-check
`index<=count-1` fallback (lifter doesn't link RAX→lookup). switchind 0.369→0.752, switchhide
0.447→0.591, switchmulti correctly declined. NOTE: the corpus harness must use the image flow
(all chunks) to see switches; ir_parity/disasm still use raw_funcdata_flow (chunk 0). Remaining
switch polish: `default:` inside, switchloop/ifswitch (in-loop / if-chain, not jump tables).

**(`5012f9d`): avg 0.6491, 30 ≥ 0.70.** DIVISION/MODULO RECOVERY DONE for the
clean cases (`divopt.rs` RuleDivOpt unsigned add-correction + signed sign-subtraction;
RuleModOpt `x-(x/d)*d→x%d`; RuleMultMult `(x*c1)*c2→x*(c1*c2)`; CollectTerms also on INT_SUB).
divopt 0.520→0.605, modulo 0.437→0.532; all unit-tested (calc_divisor verified, end-to-end
pattern tests). Remaining modulo: power-of-2 signed `%2/4/8` (uses `&(d-1)`+sign), shift-based
composite `*60`. **FLOAT CLUSTER IS A SLEIGH/LIFTER BUG, NOT DECOMPILER**: the 8-byte float
result is moved to XMM0 in 4-byte lanes at NON-CONTIGUOUS register offsets (0x1200, then
0x41204 not 0x1204 — a +0x40000 stride), and the FLOAT ops write XMM contiguously while movaps
reads it as those mismatched lanes → heritage can't reconcile → result dies → empty func
(mixfloatint/floatconv/longdouble). Fix is in the sleigh XMM register map, not the decompiler.
SWITCHES need jump-table recovery (read table data + re-flow + BlockSwitch) — big, decompiler-
level if the table bytes are in the datatest. STRUCT types + CSE also remain (big). Earlier:

**(`462fdae`): avg 0.6447, 30 ≥ 0.70** (from
0.5089/11). LENS CORRECTION (user, twice): faithful porting CONVERGES — a regression means the
change is an APPROXIMATION, not a port; fix it to be faithful, revert only WRONG output (output
Ghidra would never emit), not small gauge dips (the comparator erases names + is noisy). This
run: global naming, SEXT cast, float-op rendering, array subscript (uniform-access pointee
inference — structs stay `*(p+k)`, never wrong `s[1]`), print-time `!(!x)`/`==`↔`!=`,
`&Stack_<off>`, **ruleBlockIfNoExit** (terminal `if(cond)return;`) + irreducible gotos — the
structuring rules were the jump: elseif .135→.623, condconst →.727, loopcomment →.587. LOWEST
now: floats needing XMM param/return recovery (longdouble/floatconv/mixfloatint ~.15), switches/
jump-tables (~.31), division magic-numbers. Prior line:

**DIVISION RECOVERY — crux done (`divopt.rs`, `56a4991`), rest is a 5-rule chain.**
`calc_divisor` (RuleDivOpt's 128-bit magic→divisor, ported with Rust `u128`) is DONE + unit-
tested (recovers /3 /5 /9 32-bit, /3 /5 64-bit). But real compilers emit the ADD-CORRECTION
form (divopt: `(mulhi + ((x-mulhi)>>1)) >> e`, mulhi = SUBPIECE(MULT(zext x, magic),8) rendered
transparently as `x*magic`) and the SIGN-SUBTRACTION signed form (modulo: `mulhi_s - (x>>63)`),
NOT the textbook `(x*magic)>>shift`. Ghidra recovers these with a CHAIN: RuleDivTermAdd +
RuleDivTermAdd2 + RuleDivOpt(findForm+rewrite) + RuleDivChain, then RuleModOpt for `x-(x/d)*d→
x%d`. findForm's non-extended branch also needs `getNZMask` (a non-zero-bit dataflow mosura
lacks). So: a focused multi-rule effort (each rule unit-tested like calc_divisor), not a quick
win. calc_divisor is the verified foundation that de-risks it. XMM-float and switches are
similarly multi-piece. NEXT TIME pick ONE chain and port it end-to-end carefully.

Prior line:

**(prior, `f761a33`): avg 0.5973, 30 ≥ 0.70** Latest: `jle`/`jbe`→`<=` (RuleSborrow value-compare +
RuleEqual2Zero + RuleLessEqual); short-circuit `&&`/`||` structuring (COND_AND/COND_OR — correct
but corpus-neutral, the &&/|| funcs are dominated by branchless-flags/float/irreducible gaps);
print-time boolean negation (`!(!x)→x`, `==`/`!=` flip — condmulti `if(param_1==0)`). NEXT
dominant gaps: branchless boolean flags (orcompare `(a)*2|(b)<<7 != 0`→`a||b`), global-var
naming (`xRam...`), float-compare/NAN simplification, irreducible-CFG gotos (elseif), casts. Recent: loop-increment emission, call-arg recovery, for-loop
recognition (`findLoopVariable`/`findInitializer`) + phis always named, **for-loop INIT** (a
targeted heritage fix links a sub-register phi input EBX:4 → its wider RBX:8 covering reaching
def via SUBPIECE — only when the exact width is absent, so def chains untouched, no regressions).
**forloop1 0.555→0.950**, forloop_varused →.886, threedim →.788. NEXT: short-circuit conditions
(threedim/elseif still show raw `== 0 || SBORROW...`), casts (`(int8)(int4)`), global-var naming
(`xRam...`), switches, param-passthrough call args. Earlier line (still accurate for the rest): All gained by PORTING, not tuning: faithful
return recovery (AncestorRealistic) + global persistence (11→16), shift-add strength reduction
`getMultCoeff` (→17), RuleSborrow (signed-compare flag idiom → clean `<`), void-call emission
(→18), **call-ARGUMENT recovery** (symmetric to return: wire RDI..R9, keep the contiguous
`is_realistic` prefix; + `func_0x<addr>(...)` naming; + count only USED param-register inputs)
(→21). twodim 0.555→0.829, nestedoffset →0.950, threedim →0.738, floatprint faithful .789,
forloop1 `func_0x00400430(0x400820)`. Each unit-tested; 52 lib tests, ir_parity, 254/254 disasm
always green. NEXT GAPS (TODO): loop-increment-into-phi emission (for/while bodies drop the
`i=i+1`), param-passthrough call args (unwritten forwards — needs directWrite), float/XMM args,
casts (`(int8)(int4)`), global-var naming, switches, short-circuit conditions (elseif/condmulti).
avg dragged by empty-reference datatests (multiret/sbyte: Ghidra `--c` blank) — good-count truer.

**FIRST WHOLE-CORPUS MEASUREMENT vs Ghidra `--c`** (faithful `print_c`, 62 x86-64 datatests):
**avg 0.5085, 11 ≥ 0.70** (prototype was 0.756/34). HONEST READ: the faithful pipeline is
architecturally COMPLETE and produces CORRECT C, but is below the prototype because it lacks
the prototype's accumulated feature BREADTH — types (P4), switches (P7 tail), short-circuit
conditions (elseif/condconst stall), strength reduction ((x<<2)+x→x*5), global-var recovery,
and ~125 of Ghidra's 135 rules. Best: inline 1.000, heapstring .864, floatprint .857,
partialunion .842; worst ~.55 (loops/globals). The prototype HIT A WALL at .756 (couldn't go
higher without the faithful architecture). The faithful pipeline has NO such ceiling — adding
these features faithfully will compose (the whole thesis), unlike the prototype's hacks.
Highest-leverage next: P4 types, the rule tail (strength-reduction/flag-conditions), P7
short-circuit+switch, global-var recovery.

**P4 — Types: FOUNDATION DONE** (`types.rs`+`infertypes.rs`, `66d457e`). `Datatype` lattice
(void/undefined/int/uint/bool/float/pointer) + metatype-ordered `meet` (Ghidra TypeFactory);
`infertypes::infer` gives each varnode a local type from its def/uses and meets per
HighVariable. Wired into PrintC signature+return types. Comparator-NEUTRAL (0.5089/11) since
the comparator erases type names. **KEY DIAGNOSTIC FINDING: variable DECLARATIONS are the
binding constraint, not types.** Tried emitting Ghidra-style local decls — DIPPED to 0.4987/5
because the variable count is inflated (twodim 12 decls vs Ghidra 1): the global `0x60109c` is
read+copied into many uVars where Ghidra recognizes ONE global. So **the highest-leverage next
lever is the VARIABLE-COUNT GAP — value-numbering/CSE across storage + global-variable
recovery** (recognize `*(const)` as a named global). That unlocks declarations (faithful →
beneficial), shrinks the uVar copy-chains, and moves the comparator. Then casts (ZEXT/SEXT/
SUBPIECE→`(T)x`), pointer pointees, struct/array, param-size (P6).

**RETURN RECOVERY — DONE FAITHFULLY** (`recover.rs`, `0dff383`). RESOLVED the failures below.
The fix was the user's point made concrete: the heuristics failed BECAUSE they weren't ports.
Ported `ActionReturnRecovery` + the core of `AncestorRealistic`: wire RAX/XMM0 candidates to
each RETURN pre-heritage; post-heritage keep only the candidate whose value traces to a REAL
write (`is_realistic`: traverse COPY/SUBPIECE/ext/MULTIEQUAL; solid producer or const =
realistic; unwritten passthrough = not). Correctly handles int(RAX via mov-eax zext)/float
(XMM0)/void/multiret — the exact cases the heuristics broke. UNIT-TESTED in isolation before
wiring in (the discipline that made the difference). Removing the seed-all exposed a separate
real gap it had crutched — **global (ram) writes are persistent side effects**; added that as a
deadcode live-out root (Ghidra `persist`/addrtied), restoring floatprint faithfully. **Corpus
funcs ≥0.70 jumped 11→16**; twodim .555→.717, threedim →.694, floatprint .789. avg flat
(0.5111) only because empty-reference datatests (multiret/sbyte: Ghidra's own `--c` is blank)
drag it — good-count is the honest signal. LESSON CONFIRMED: port the algorithm, unit-test it,
it composes; approximating regresses. The (now-resolved) failure log, kept for the lesson:

**RETURN-RECOVERY HEURISTIC ATTEMPTS — regressed, reverted, THEN fixed by porting (above).**
Diagnosed the variable-count bloat's biggest cause: the P3 interim deadcode seed keeps EVERY
RAX/XMM0 write live-out, so all intermediate scratch `RAX = ...` (0 uses) survive as bloat
uVars (twodim 31 ops, most are dead RAX copies). Two fixes both regressed vs seed-all
(0.5089): (1) seed only the *last* RAX write → 0.4733 (breaks multi-path — a loop's scratch
RAX seeded instead of the real return); (2) proper return recovery (`recover_return` wiring
the reaching RAX/XMM0 def into each RETURN, dropping the seed) → 0.4670 and BROKE floatprint
0.857→0.103, multiret/sbyte→0.000 (float vs RAX register selection, multi-return, and
return-size detection are subtly wrong; removing over-kept ops also exposed other gaps).
Reverted to seed-all. **LESSON: seed-all over-keeping scores HIGHER than a naive "correct"
return handler; the real fix needs a CORRECT return recovery (unit-test float/XMM0, multiple
returns, return size) AND likely CSE — a careful effort, not a quick change.** twodim DID
clean up to 22 ops with both attempts (the principle is right; the impl wasn't). Seed-all is
the safe baseline; working tree clean at the P4 commit.

**OVERALL: the COMPLETE faithful pipeline exists end to end** — bytes → CFG → SSA →
simplify → deadcode → variables(P5) → structure(P7) → **C(P8)** — producing real decompiled
C that matches Ghidra on straight-line functions. Built from an empty `src/decompile/` this
session (~32 commits, all green, 254/254 disasm parity intact, every stage validated
against Ghidra/ground-truth, nothing rushed). Remaining: P8 structured emission (then
corpus measurement), P4 Types, P6 Prototypes (retires P3/print return heuristics + P1
INDIRECT guards), the P2/P7 rule tails. `pipeline::decompile` + `printc::print_c` are the
entry points.


## ARCHIVED index-overflow log (moved verbatim from MEMORY.md index, 2026-07-04)

mosura decompiler port: faithful Ghidra translation, IR-validated (not the similarity gauge). **LATEST HEAD `9111b49`. Corpus 0.8649, 54/60, 178 green.** **TASK #7 (ActionPool per-op rule PRIORITY) DONE** (`5859055` reorder→oppool1 + `2c50e8a` perop[opcode] dispatch+restart-on-opcode-change + `c88ff35` SeqNum op order, all byte-neutral; `5a13962`/`0c00d71` held-rule doc-correction). KEY DISPROOF: priority was NOT the blocker for the 5 held rules — perop measured each with trace-diff, all still over-fire/hang from UPSTREAM graph-coverage gaps, NOT ordering. Real blockers: SubZext/Piece2Zext→#9 (SubVariableFlow), AndDistribute→#9 primary +#10 secondary (nzmask mid-pool freshness; guards verified byte-for-byte, faithful), AndCompare→#8 (sub2add/addmultcollapse in main loop), NotDistribute→#4 (nan flags). **TASK #9 (port SubVariableFlow subflow.cc — dissolves byte-packing→narrow PIECE/CONCAT/zext, unblocks 3 held rules) IN PROGRESS**: plan `[[task9-subvariableflow-plan]]` (5 stages, HARD prereq = bit-level consume); **Stage 0 (bit-level `consume` = backward dual of nzmask, ActionConsume after ActionNonzeroMask) LANDED byte-neutral `9111b49`** (+4 tests); Stage 1 (SubvariableFlow core structs) next. `[[task7-perop-priority-plan]]` `[[task7-perop-priority-outcome]]`. **PRIOR HEAD `6a9c4fc`. NZMASK BIT-RULE PORT (Task #3) — 8 WIRED, 5 HELD** (`24d54a0`/`f055947`/`6bf66a5`/`7735dac`/`62368a8`/`6a9c4fc`): WIRED zero-regression RuleOrCollapse 384, RuleXorCollapse 4050 (partialsplit 0.870→0.884), RuleHighOrderAnd 1196, RuleZextShiftZext 4865, RuleLessEqual2Zero 5601, RuleShiftBitops 490 (live-opcode guard — panicked on stale INT_MULT→COPY input(1)), RuleHumptyOr 5332, RuleAndPiece 1640; +Funcdata::new_op_before_sized. **HELD (ported+unit-tested, NOT pool-wired, ALL blocked on Task #7 perop priority)**: RuleNotDistribute 1147 (nan 7×vs3×, wiring is part of Task #4 nan completion), RuleAndCompare 1745 (forloop_varused 3×vs0×), RuleSubZext 5039 (piecestruct 36×vs26× breaks CONCAT), RulePiece2Zext 219 (floatconv 2×vs1×, but CONVERGES floatcast 4=4 +0.044), **RuleAndDistribute 1254 (HANGS — ping-pongs with the now-wired RuleHumptyOr; the two are mutual inverses, mosura's flat pool never reaches a fixpoint; do NOT wire together pre-Task#7)**. **REMAINING to port**: RuleAndCommute 1532 (complex, op-creating + infinite-loop guards), RulePositiveDiv 7799/RuleDivTermAdd2 7951 (divopt subsystem). **KEY STRUCTURAL FINDING**: "collapse-to-const/compare" rules land clean but "rewrite-structure" rules over-fire because `default_rule_pool` is a FLAT insertion-order fixpoint lacking Ghidra's **per-op rule PRIORITY** (`perop[opcode]` lists, action.cc processOp restarts at index 0 on fire) — mosura's SubZext wins where Ghidra's RuleShiftPiece fires first. Porting perop priority into ActionPool (action.rs) is the real unlock for the held + remaining rewrite rules (AndCommute/AndDistribute/AndPiece); asked lead A(port priority)/B(continue collapse rules). Deep-defer: RuleOrConsume 353 (per-bit getConsume), subvar_* (subflow.cc), RuleSubCommute 4514 (precisLo/Hi), RuleIndirectCollapse 3157; RulePiece2Zext 219 ground floatconv first. **PRIOR HEAD `e54fe68` (712066d Task #2 rule-trace diff + e54fe68 gitignore dump*.rs). TASK #2 = the mosura↔Ghidra rule-firing trace diff (the "killer feature")**, off by default both sides → corpus BYTE-IDENTICAL. GROUNDING CORRECTION (durable): prior "OPACTION_DEBUG compiled OUT of libdecomp_dbg.a, needs a separate -DOPACTION_DEBUG build" was WRONG — `types.h:88` does `#ifdef CPUI_DEBUG→#define OPACTION_DEBUG`, so trace machinery is ALREADY in the existing lib+`oracle/capture` (nm-verified). So NO separate library (Opt-1 dropped): `oracle/capture_trace` (new binary, links the SAME existing libdecomp_dbg.a, SAME switches, capture 100% untouched) `--trace` = fd->debugEnable()+debugSetRange(Address(),Address())+setDebugStream(&cout)+perform. mosura side: env-gated MOSURA_TRACE=1 hook in ActionPool::apply (action.rs) + Funcdata::op_str + suppress around the alias-probe pool (pipeline.rs); examples/trace.rs runner (TRACKED, unlike dump*.rs). Differ `scripts/trace-diff.{py,sh}` keys each firing on (rulename, instr-addr) — Ghidra printRaw uses operator glyphs (&,<,SBORROW8) not CPUI names so opcode-string can't be the key; note printRaw also renders POPCOUNT/ZEXT48/CONCAT22 vs mosura INT_*/PIECE. shiftpiece 4=4 no-divergence validated the Task#1 port. Surfaced candidate ports: piece2zext/subzext/subvar_zext/subvar_subpiece/zextshiftzext/xorcollapse/subcommute/notdistribute/andcompare. **PRIOR `138ad80` (Task #1): 3-RULE getNZMask BATCH — RuleAndMask 302 (fires 167×, byte-neutral, omits getConsume() arm), RuleSlessToLess 2530 (+signbit_negative port of address.cc:641), RulePopcountBoolXor 10273 + getBooleanResult 10399; all re-check live opcode at entry; +4 synthetic unit tests** [[task3-getnzmask-rules-batch]] [[port-all-faithful-rules]]. **PRIOR `e5fc487`: RuleShiftPiece 3753 + RuleAndZext 1696 → CONCAT; piecestruct 0.754→0.889, switchloop 0.720→0.724.** **PRIOR HEAD `32cbac8`. Corpus 0.8623, 54/60, 151 green. TASK #4 orcompare `||` LANDED** (`32cbac8` — RuleOrCompare/ShiftCompare/ZextEliminate/BooleanNegate chain + opFlipInPlaceTest-GATED De Morgan in render_negated + a 3rd simplify cycle; orcompare 0.806→0.929 matching oracle, ZERO regressions; lead ruled both faithfulness flags acceptable) [[task4-orcompare-boolchain]]. **PRIOR HEAD `68658d5`. Corpus 0.8603, 54/60, 149 green. TASK #8 getNZMask FOUNDATION LANDED** (`68658d5`, byte-neutral — non-zero-mask analysis, 42 rule sites, gates #4+#3) [[nzmask-foundation]]. **PRIOR TASK #1 (guard() write+read normalization) LANDED** [[task1-guard-write-normalization]] (`a85ee89` byte-neutral normalizeWriteSize helper + `302676d` the faithful UNIFORM guard() over GP+laned — normalizeReadSize+normalizeWriteSize per single-write-cover range; removed the unfaithful self-extension skip [THE bug] + read-deferral, retired normalize_read_size implicitly, Mode::Refine stays laned-only, CALL newIndirectCreation branch DEFERRED=Task #7). orcompare 0.741→0.806 (real `param_1==10`/`param_2==0x14` compares recovered; residual `|`→`||`=#4), concatsplit/varcross bonuses, modulo HELD; faithful downstream dips nan/revisit/deindirect2/switchloop/loopcomment (kept). UNBLOCKED #4 (orcompare `||`), #5 (nan flip). RulePiece2Zext/Sext DECLINED (regress floatconv). **PRIOR HEAD `b598b04`. Corpus 0.8592, 54/60, 147 green. #19 CFG-aware recover_stack** (`ca29bdf`, corpus-EXACTLY-NEUTRAL; **FLAGGED ADAPTATION ruled acceptable by lead, USER MAY RE-RULE** — pre-heritage RPO forward-CFG-dataflow predecessor-meet = the pre-SSA analog of Ghidra's POST-heritage SSA ActionStackPtrFlow/StackSolver phi-joins; a literal port = huge restructure; fixes recover_stack's flat-linear RSP drift across switch epilogues). **#3 LANDED (`b598b04`) on top of #19**: kept the CALL return-address store at its real slot -0xa0 → wayoffarray 0.683→0.880, ONLY wayoffarray changed, zero regressions; reused the existing across-call INDIRECT/setAddrForce/deadcode (no addrtied stages needed). **NEXT BIG UNBLOCK = #17** guard() normalizeWriteSize + PIECE/SUBPIECE collapse (frees orcompare + nan; #16 BLOCKED on it [[task16-normalize-readonly-blocker]]; #14 flip HELD, inert without it). NEW NOTE [[task3-wayoffarray-retaddr-drift]]. LESSON: messaging a TERMINATED agent RESUMES it — never message a dead agent. PRIOR `7f6ff70` (Task #18 condition-flip: port opFlipInPlaceTest DECISION into structure.rs rule_if_else — non-normal if/else cond → swap arms + negated, reuse printc render_negated; Approach B = flip at structurer+print not Ghidra IR-rewrite, justified subset verified vs oracle --c; indproto 0.842→0.947, deindirect 0.591→0.636 + bonus elseif/forloop_varused/union_datatype, ZERO regress; avg 0.8559, 53/60, 147 green). PRIOR `bdf11ee` (Task #8 longdouble: NOT the x87 lifter — it works; cross-chunk flow + at-or-after no-op `endbr64` branch-target CFG fixes; longdouble 0.174→0.776, avg 0.8480, 52/60). PRIOR `e825790`. Corpus avg 0.8394, 51/60, 146 green.** HERITAGE MULTI-PASS THREAD (this run, serialized single-owner agents on master): **#5 multi-pass heritage FOUNDATION** byte-neutral (`cdf8678` per-space delay/HeritageInfo + `57c12dc` heritage iterates by delay group reg→stack + `f1c9f05` re-invocable persistent state); **#12 ParamActive/ParamTrial trial-deferral** byte-neutral (`3aeed34`+`bd3e112` — resolve_call_args/resolve_return refactored to ActionReturnRecovery/ActionActiveParam, keep/drop decision UNCHANGED, maxpass=0 commits-in-one-pass, defers when maxpass raised); **#13 per-(addr,size) LocationMap globaldisjoint** byte-neutral (`5edaa30`+`8386e20`, per-location cover; caught a wrapping_sub overflow on negative stack offsets); **#15 trace call-arg realism through PASSTHROUGH INDIRECTs** (`831624b` — faithful AncestorRealistic::enterNode CPUI_INDIRECT split: reject indirect-creation/return-addr, else trace input(0); recovered loopcomment 2nd arg + noforloop_alias/stackstring; the assigned guardCallOverlappingInput diagnosis was WRONG—corrected by grounding, stays unported as no fixture exercises it); **#11 RuleLogic2Bool** (`6ea3dcc` — INT_AND/OR/XOR-of-bools→BOOL_*; corpus-neutral; declined RuleFloatRange/RuleBoolNegate-FLOAT = NO firing site); **#6 ActionDeterminedBranch+RuleOrMask** (`96e51dc` — const-CBRANCH prune removeBranch/branchRemoveInternal/removeUnreachableBlocks/opZeroMulti+renumber, switchmulti structure matches oracle, ZERO blast radius; RuleOrMask V|allones→allones; dead-block infra = groundwork for nan's ActionConditionalConst); **#7 XMM param naming** (`e825790` — see [[printc-param-recovery]], [[corpus-windows-x64-fixtures]]). **FLIP #14 = HELD**: recipe complete+terminating+NON-regressing but PROVABLY INERT for nan/orcompare (retried TWICE on top of #15+#11, corpus exactly unchanged 0/60) — the sete→movzx GP sub-register reconnection is a HERITAGE-TIME job not rule-pool; per-location re-heritage only re-fires when a rule FREES a linked read, nothing does. **KEY UNBLOCK = Task #16 (IN PROGRESS)**: extend refine_overlaps off LANED/XMM-only (off≥0x1200) to GP sub-registers (nan ZEXT48(EDI) narrow-read-of-wide-write, orcompare SUBPIECE-of-sete-DL wide-read-of-narrow-write) — HIGH blast radius (broad GP application broke GP/scalar before), grounding-plan-first; nan ALSO needs ActionConditionalConst+RuleConditionalMove. **ORCHESTRATION LESSON (reinforced, TWO collisions this run)**: SERIALIZE handoffs — terminate + CONFIRM-DEAD the outgoing agent BEFORE spawning/activating the next; never shutdown+spawn the same turn (both collisions were zero-damage only because the fresh agent halted on foreign-edit). PRIOR HEAD `c27a98a` (0.8378/51/132): guardInput/refineInput (Task #1) — LANDED `c27a98a`: faithful refineInput vs refineRead split (heritage.cc:1836/1772 — Heritage::collect@340 sends a free Varnode with NO reaching def to inputvars→kept WHOLE, not readvars→CONCAT). In refine_overlaps a REFINE-laned read with no DOMINATING write to its byte range is input-like → left intact (skip CONCAT); threaded existing `dom` in, recorded per-access (blk,pos) on Acc, guard = `acc.any(write && overlap && dom.dominates && before)`. mixfloatint's 8-byte XMM0 param read (lane-written later by movaps return-setup, doesn't dominate) was CONCAT44(xVar1,xVar2), now a clean register input. mixfloatint 0.781→0.800, ZERO regressions (only mixfloatint moved; partialunion held 0.941; floatconv/floatcast/floatprint hit Mode::Normalize not the read-split). +1 gated regression test. Residual = Task #7 (XMM reads still render fVar1/fVar2 not param_1/param_3 — printc XMM-aware param naming). PRIOR HEAD `fa4b0c5` (0.8375/51/131): HERITAGE REFINEMENT (Task #12) — LANDED (`510cf52` new_output-detach prereq + `fa4b0c5` subsystem). KEY: scope refinement+guard to LANED regs only (offset ≥ 0x1200 = XMM, Ghidra LanedRegister) — broad application broke GP/scalar fixtures. refine_overlaps (heritage.rs): disjoint cover, REFINE (refineRead→PIECE/refineWrite→SUBPIECE) a range no write covers + NORMALIZE (normalizeReadSize/normalizeWriteSize) a covered one; RuleHumptyDumpty + RuleDumptyHump rejoin (the DumptyHump `(uint4)CONCAT(0,x)→x` unlocked floatprint); printc PIECE→CONCATxy/high-SUBPIECE→SUBxy; recover.rs is_realistic descends PIECE LOW lane (no spurious return). mixfloatint 0.176→0.781, floatprint 0.838→0.916, floatconv 0.512→0.578, floatcast 0.723→0.766. **ZERO regressions** (re-verified deterministically at HEAD fa4b0c5, full 131-test suite green; the earlier "partialunion 0.941→0.900 dip" was STALE — the final slot-1 is_realistic PIECE descent keeps partialunion at 0.941, `void func(){…return;}`). Also fixed a flaky `eval_const` Subpiece shift-overflow panic (checked_shr). FAITHFULNESS FLAG for lead audit: refine_overlaps scoped to laned regs (off≥0x1200) vs Ghidra's all-register placeMultiequals (justified subset). Follow-up (Task #15, NOT a regression) = port guardInput (heritage.cc:1952) to unify XMM float-param input pieces (mixfloatint params still surface as PIECE/CONCAT). PRIOR — FLOAT ABI/XMM (Task #2): landed `v_offset_plus` truncation mask (`8a99677`, ConstTpl::fix semantics.cc — XMM 4-byte lanes were lifting at bogus `0x41204`-style offsets, now contiguous; longdouble 0.143→0.174, mixfloatint 0.150→0.176). Remaining float fixtures all DEEP (diagnosed in handoff): mixfloatint/floatconv = HERITAGE REFINEMENT (8-byte XMM return read over two 4-byte lane writes → no def → dead body; port heritage.cc refinement/buildRefinement/refineRead+Write as a pre-SSA disjoint-cover split + CONCAT(SUB,SUB) collapse; highest leverage, high blast radius), nan = ucomisd flag-simplification (multi-issue), longdouble = x87/float10 80-bit lifter (deepest, empty fn). PRIOR — SWITCH TAIL (Task #3 DONE, 3 commits): default-folding `6dc5d3a` (foldInOneGuard/pushBranch/emitBlockSwitch + `jumptables` cache so jump_tables() survives the fold; switchind 0.948), case-label getIndexByBlock `fdc2465` (map target→first case block at/after addr, not strict ==; switchhide 0.725→0.813, ifswitch 0.797→0.867), declined-jumptable→CALLIND `e90a495` (truncateIndirectJump: BRANCHIND→CALLIND+artificial RETURN; switchmulti 0.525→0.548). Residuals deep/out-of-scope: switchhide canary-in-default (FS-canary recovery), switchmulti `if(!0)` (needs removeBranch+unreachable-prune+pushMultiequals). `examples/dump.rs` MUST stay UNTRACKED — never `git add -A` (a stray commit of it had to be filter-branch'd out). PRIOR HEAD `51a52ec` (0.8189/50, 101 lib). Cover/interference merge fix (Task #5, `51a52ec`): mosura's `merge_same_storage` (merge.rs) tested HighVariable interference only over members AT THE SHARED storage — Ghidra's `HighVariable::updateInternalCover` (variable.cc) unions ALL member covers, so the guard must test the WHOLE HighVariable. FIX = `full_members_by_rep` expands each storage-class to its full membership before `classes_interfere`. pointercmp's bogus `pStack_10 < pStack_10` → correct `pStack_10 < pVar1` (the RAX bound was merging into the iterator via the iterator's stack-phi). Corpus 0.8195→0.8189: ONLY pointercmp (0.800→0.765, ccompare ARTIFACT — correct extra var/line) + loopcomment (0.759→0.761) changed, BOTH correct un-merges; +1 regression test (fails without fix). No legitimate merge split. cover.rs already existed; bug was interference SCOPE, not cover computation. PRIOR HEAD `1b8326f` follows. RuleMultiCollapse (Task #1, `1b8326f`): faithful port of `RuleMultiCollapse` (ruleaction.cc) + `functionalEquality` (expression.cc) into rules.rs, wired into default_rule_pool — collapses redundant MULTIEQUALs (absolute/functional eq + loop-recurrence skip + nested-phi expansion + func_eq in-place recompute via cseFindInBlock/opUninsert/opInsertBegin). CORPUS-NEUTRAL: fires on 12 fixtures but rendered C **byte-identical across all 60** (mosura's merge phase already coalesced these phis) → faithful IR-alignment, zero regression. The predicted payoff (switchloop `return foo()`; nan/forloop_varused/switchloop dip phi-halves) was a **MISDIAGNOSIS** — those surviving phis are genuine (loop-induction / `COPY const`-vs-`INT_ZEXT` divergence), correctly NOT collapsed; their gaps are switch-structuring (#3)/float-ABI/naming. Correctness (merge-distinct-values risk) verified: before/after C identical + 4 unit tests. PRIOR HEAD `8153306` (126 lib) follows. FuncCallSpecs/EffectRecord (Task #3): ported `EffectRecord`/`lookup_effect` (fspec.rs) + per-call killedbycall **indirect-creation** clobber (RAX dies at the call → nan/forloop_varused/loopcomment recover `void`) + `resolve_call_output` (buildOutputFromTrials: used RAX/XMM0 creation→CALL output, `extraout_RAX`→`xVar=func()`, packstructaccess+0.056) + printc baseExplicit (`ab8856b`). Payoff-1 dropped-arg (loopcomment RSI) BLOCKED by mosura's early stack-load resolution (single-shot heritage vs Ghidra multi-pass) — NOT a param-recovery gap; details in HANDOFF. PRIOR HEAD `bfff029` (avg 0.8138/50): STACK-VARS Task #1 blockers **(B) frame-escape + (C) stack-array rendering DONE** (5 faithful commits `828fb49`/`a05365e`/`9c17bb7`/`6775e50`/`bfff029`): general RuleSub2Add + cleanup subtraction-reconstruction (RuleMultNegOne/Rule2Comp2Sub/RuleAddUnsigned, the faithful counterpart — NOT a printc hack) + RuleAddMultCollapse (flattens chained frame base, fixes multi-level offsets) + `&xStack_NN` naming + (C) wire `varmap::recover_scope`→printc (`axStack_NN[i]` arrays via anchor_stack_arrays). `xVar1=xVar1-N` leak GONE; **pointersub→1.000, offsetarray 0.667→1.000**. Only residual = **wayoffarray 0.683** = blocker-(A) addrtied write-only-store deadcode'd (deep deadcode fix, high blast radius — don't chase). Full grounding in HANDOFF + Task #1 notes. PRIOR STACK-VARS (Task #3) session: landed the **faithful `varmap.rs` foundation** (`fd6180f`: ScopeLocal/MapState/RangeHint + restructure ← varmap.cc — RangeHint reconcile/contain/preferred/attemptJoin/absorb/merge, MapState gatherVarnodes/gatherOpen/reconcileDatatypes/initialize, createEntry; recovers the disjoint stack-symbol cover incl. arrays via open-range+highind→TypeArray; + AliasChecker gatherAdditiveBase/gatherOffset in alias.rs). 90 lib green, corpus unchanged (module **not yet wired into printc**). GROUNDED (dumped mosura IR + `oracle/capture --c` for loopcomment/noforloop_alias/stackstring): `recover_scope` is correct where the IR is complete (loopcomment `aiStack_1c[4]` ✓) but its payoff is GATED by TWO upstream blockers that must land before wiring helps: **(A) addrtied-store materialization** — mosura's deadcode (`deadcode.rs`) treats stack slots as NON-addrtied and eliminates write-only aliased spill stores Ghidra keeps (loopcomment's `-0x20`/param_2 slot never materializes as a value varnode → varmap then makes a spurious `Stack_24[2]` over the gap); ALSO the loop-increment/HighVariable-merge gap (noforloop_alias drops `iStack_14=0`/`+1` because the increment writes RAX and the slot updates via INDIRECT — Ghidra merges them into one HighVariable). SHARPENED (A) ROOT CAUSE + PLAN (resume here): the spill store IS created by recover_stack and IS read back, but `RulePropagateCopy` propagates THROUGH the stack slot (guard awaits the flag) so spill→reload collapses to the register and the store dies; mosura defines `flags::ADDRTIED` but NEVER sets it. PLAN, incremental green commits: mark aliased stack varnodes addrtied via the existing `alias_boundary` (match Ghidra's default-addrtied + markUnaliased END-state — don't under-mark) → addrtied guard in RulePropagateCopy → addrtied live-out root in deadcode → printc materialize `xStack_NN = …`; HIGH blast-radius (copy-prop + deadcode touch every fixture), keep faithful dips (no revert). **(B) spacebase/PTRSUB leak** (`xVar1 = xVar1 - N`) — the frame `INT_SUB(RSP,N)` stays live because escaping address-of `INT_ADD(RSP,c)` reads it; Ghidra renders these as `PTRSUB(RSP_input, off)` off the ENTRY spacebase (verified via `--ir`: `RSP = RSP(i) -> #-0x28`). FAITHFUL FIX = RuleSub2Add (mosura lacks it; RISKY — general, needs printer `a+b*-1`→`a-b`) + type RSP input as **TypeSpacebase** (type.cc:2947 getSubType queries ScopeLocal=my varmap symbols) + RulePtrArith spacebase path (infra ALREADY present in ptrarith.rs:129-145, awaiting pointer-typed RSP) + printc PTRSUB-spacebase→`&iStack_NN`. No shortcut: confirmed mosura's RuleCollectTerms does NOT flatten nested `(I+k1)+k2`, so RuleSub2Add alone won't collapse it. NEXT increment = (A) addrtied stores (broadest, unblocks varmap wiring), THEN (B), THEN wire varmap→printc for arrays+names. (`crates/mosura/examples/dump.rs` is a local grounding tool — dumps mosura C/IR/scope per fixture, NOT committed.) PRIOR: HEAD `d5ae08d`, TRUSTWORTHY baseline — the corpus oracle `oracle/capture` is now fixed to match canonical Ghidra. ORACLE FIX (`d5ae08d`, owner-approved): capture was compiled WITHOUT `-DCPUI_DEBUG -D__TERMINAL__`, the exact flags `libdecomp_dbg.a` is built with; CPUI_DEBUG adds INSTANCE members to core classes (Funcdata/PcodeOp/Action/Architecture), so capture's struct layouts were SMALLER than the lib's → silent ABI/field-offset corruption → wrong decompilation (no crash). Fixed in `scripts/setup-oracle.sh` + comment in `oracle/capture.cc` (gitignored binary rebuilt; NO mosura Rust touched, still all green). CONSEQUENCE: **the `divopt 0.927→0.614` called a "regression" below was an ORACLE ARTIFACT, NOT a mosura regression** — mosura matched canonical Ghidra all along (proto-typer proved it via decomp_dbg: raw, symbols-stripped, script-decls-removed all give `uint8 *param_1`+`param_1[i]`); divopt now scores **0.940** and RulePtrArith (Task #1) is a CLEAN NET WIN. Task #10 (ActionPrototypeTypes / "param over-typing") was the SAME artifact → resolved "no faithful change applicable." With a canonical answer key, remaining low-scorers are REAL mosura gaps, ranked: float ABI (longdouble 0.143, mixfloatint 0.150 — #4, lowest/hardest), **stack-vars (#3 = broadest reach = NEXT: ScopeLocal/varmap.cc + ActionRestructureVarnode + AliasChecker)**, switches (#6), deindirect, orcompare/revisit (#7). Tasks done: #1 #2 #10 #12. PRIOR framing follows (divopt-as-regression now superseded): THIS SESSION (Task #1 RulePtrArith + Task #2 param typing): landed the **in-pipeline type-recovery writeback** (`5f3c910`: `Funcdata::new_op_before`/`op_insert_before`/`op_set_output`, `has_type_recovery_started`, `infertypes::infer_types` ← ActionInferTypes writeBack commits types onto varnodes, + TypeOpPtradd/Ptrsub::propagateType); ported **`RulePtrArith` + `AddTreeState`** faithfully (`86bd58f`, new `ptrarith.rs` ← ruleaction.cc — INT_ADD tree on a pointer base → PTRADD/PTRSUB; wired after ActionInferTypes; printc renders `base[i]`/`base->field`, PTRADD/PTRSUB outputs implied; declined the TypePointerRel/distributeIntMultAdd/nearestArrayedComponent/union paths as faithful subsets); **force_pointer size-guard** (`677bef8`: access-width≠elemsize keeps `*(T*)(base+i)` not `base[i]` ← Ghidra checkArrayDeref/force_pointer; fixed heapstring's 1-byte store); and the KEY **size-aware HighVariable merge** (`5d5ea02`: merge_same_storage keys on (space,offset,**size**) — a Ghidra HighVariable is single-size; the 8-byte RDI param was merging with 4-byte int scratch parked in RDI and the meet dragged it to int4). **modulo 0.527→0.748** (param_1 now `int8 *`, renders `param_1[i]`, signature identical to Ghidra); condconst 0.727→0.871. COUPLING/regression: RulePtrArith fires on mosura's OVER-typed params where Ghidra keeps `xunknown8` → **divopt 0.927→0.614** (the old cast-guard was HIDING the over-typing); root = missing Ghidra prototype/symbol type recovery (ActionPrototypeTypes) — deep, NOT width. Net corpus ~neutral; the architecture is now much more faithful (type recovery→ptrarith, size-correct HVs). REMAINING bounded-ish: pointercmp bound/iterator merge is a cover/interference bug (both 8-byte, simultaneously live across loop → `pVar1 < pVar1`); see Task #2 notes. PRIOR session (HEAD `3d893f3`, avg 0.7677/44): salvaged + landed the **types-on-Varnode foundation** (`debc5aa`: `Varnode::ty`/`get_type`/`update_type` ← Ghidra writeBack target) and ported **`TypeOpIntAdd` pointer propagation** (`3d893f3`: propagateAddIn2Out/propagateAddPointer/downChain ← typeop.cc/type.cc — pointer relays through `ptr + i*elemsize`; removes the documented infertypes deferral; corpus-neutral, can't fire until param bases get pointer-typed). **GROUNDED DIAGNOSIS (dumped mosura vs `oracle/capture --c` for orcompare/modulo/loopcomment/pointercmp): NO bounded corpus wins remain — all low/mid-scorers are deep-multi-issue.** Three entangled blocking subsystems, ranked by leverage: (1) **pointer/aggregate PARAM typing** — modulo keeps `*(xunknown8*)param_1` not `param_1[i]` because param_1 never becomes `int8*` (param typelocked/untyped → blocks propagateAddIn2Out; the `int4 * *` malformed store-dest type is the same root); needs Scope/prototype + RulePtrArith/PTRADD. (2) **Scope/Symbol stack-vars** — loopcomment loses stack arrays/`xStack_NN` slots, emits uninit `xVar1 = xVar1 - 8`; broadest reach. (3) **float ABI/lifter** — longdouble 0.143, mixfloatint 0.150 (lowest single-entry gaps, hardest). NOTE: ActionSetCasts is architectural-fidelity-only (print-time `get_input_cast` already emits the casts → no score gain, high risk) — DEFER. WORKTREE-SUBAGENT ORCHESTRATION FAILED (isolation gave wrong base commit `89838da` to 5/6 agents) — work solo on master with green commits. **HANDOFF block at top**: HEAD `8356508`. Corpus (new track, `decompile_corpus.rs`) was **avg 0.7665, 43/60** (passed prototype 0.7021/38). Structural this session: RuleSignMod2nOpt2 (mod-2), then RuleDivOpt::findForm port (`8356508`, simple multiply-reciprocal division → RuleModOpt collapses %d). USER DIRECTIVE: port Ghidra, NEVER invent — I reverted an invented escape-detector; remaining gains need DEEP unported subsystems (Scope/Symbol for addrtied+prototypes, ActionSetCasts, FuncCallSpecs). printc render-time approximations are scaffolding for those. Prior HEAD `c68bfb6`. Corpus diagnostic (`cdda2d5`) measures the new track: now **avg 0.7626, 42/60** (passed prototype 0.7021/38). Structural: power-of-2 modulo DONE (`c68bfb6` RuleSignMod2nOpt2 division-form + div/rem casts, modulo2 0.48→0.94). SWITCHES (switchmulti/loop 0.37-0.39) + STRUCT (piecestruct 0.54) grounded as DEEP MULTI-ISSUE (stack/condition recovery, P6 CONCAT param splitting, FS-segment canary) — deferred, not bounded. Float low-scorers = lifter/XMM layer. KEY: ccompare erases names/types/numbers → only structure/casts/op-counts score. Earlier HEAD `88f296e`. NEW-TRACK CORPUS now measured (`cdda2d5` decompile_corpus.rs): **avg 0.7586, 42/60 — PASSED the old prototype (0.7021/38)**. KEY: ccompare erases names/types/numbers → naming/const/type-name polish is ZERO score; score levers are STRUCTURAL low-scorers (float ABI, switches, modulo, struct/CONCAT) + cast T-count. Stack-local naming `xStack_<off>` (`88f296e`). param-WIDTH pinned to heritage normalize_read_size over-widening (deep, ~1 token). Earlier HEAD `6285c1f`. Ported this session (all green, 82 lib + ir_parity + 254/254, 127 total): `propagateOneType`/`type_order` (`a1867e7`); cast subsystem `castStandard`+comparison casts (`79f5406`); negated-condition casts (`9351f25`); P6 param undefined types + SEXT casts (`33d8ed7`); pointer-deref `*(T *)addr` (`123149c`); markExplicitUnsigned `5U` (`ce7dc9f`); **value-typing undefined symbols + `xunknown` naming + decimal consts (mostNaturalBase) + local var decls (`6285c1f`)**. **twodim now NEARLY IDENTICAL to Ghidra** (only param/return WIDTH 8-vs-4 differs). DIAGNOSIS FIX (verified by IR): casts are SIGNEDNESS casts via CastStrategy, NOT width casts; RuleSborrow recovers the signed compares. ONLY DEEP THING LEFT = **param WIDTH recovery** (P6/heritage): mosura `normalize_read_size` widens the param reg to RSI:8; raw IR reads ESI:4, Ghidra keeps the 4-byte convention width — needs a convention-aware ParamActive model in heritage (not a printc tweak). Plus minor: stack-local naming (xVar vs xStack_NN). KEY LESSON: ground the IR / Ghidra `--c` before coding. Plan in docs/port-plan.md.
