# Coverage matrix — Ghidra decompiler mechanisms vs mosura

Phase 0 of [`roadmap-100.md`](roadmap-100.md). The authoritative inventory of every Ghidra
decompiler mechanism (from the pinned `ghidra/` checkout) against mosura's port, so the
remainder is a burn-down list and every not-yet-stumbled-on gap is visible at once.

**Status legend**
- `PORTED` — a faithful port exists and is active. Cited by mosura symbol/file (landmark commit
  where known; per-rule commit is recoverable via `git blame`, not spelled out for all ~130).
- `HELD(reason)` — ported (struct/code exists) but deliberately **not wired** into the pipeline.
- `BLOCKED(dep)` — not yet portable; needs a subsystem/decision mosura lacks.
- `MISSING` — no port yet, and not blocked (mechanical tail work).
- `PARTIAL` — a subset/related functionality exists, but the Ghidra mechanism is not fully ported.
- `N/A` — marker/no-op action, or arch feature irrelevant to x86-64-first (segmented spaces, etc.).

**Precision note.** The rule-pool sections (oppool1/oppool2/cleanup) are *exact*: status is verified
against the `pub struct Rule*` set and the `.with(...)` wiring in `pipeline.rs`. The action and
subsystem sections (heritage/fspec/jumptable/printc/merge) are *function-mapped* — mosura rarely
names an Action after Ghidra, so these map by behaviour and several are annotated `PARTIAL`
pending a deeper per-mechanism audit.

Source of truth: Ghidra `coreaction.cc:5462` (`universalAction`), `ruleaction.cc`, `heritage.cc`,
`fspec.cc`, `jumptable.cc`, `printc.cc`. mosura HEAD at authorship: `68a059e`.

---

## 1. universalAction — actions (coreaction.cc:5462-5739)

Ghidra's action pipeline in order. mosura's `pipeline::universal_action` hand-unrolls the mainloop
3× as `[ActionNonzeroMask, ActionConsume, default_rule_pool, ActionDeadCode]` and folds/omits most
of the fine-grained actions.

**Iterating mainloop re-heritage (S8-2, landed):** the first real repeated group is
`ActionGroup::restart("reheritage") { ptrarith_pool → ActionHeritage → deadcode }` (before
cleanup_pool), the faithful analogue of Ghidra running `ActionHeritage` every `actmainloop`
iteration (coreaction.cc:5492): a LOAD/STORE that `RuleLoadVarnode`/`RuleStoreVarnode` converts to a
free COPY in `ptrarith_pool` re-enters heritage, which WIDENS the range (`globaldisjoint.add`) and
re-versions it. The widening re-free (`removeRevisitedMarkers` + `normalize_ranges`, §5) then
reconstructs Ghidra's whole-range SSA, and the printc baseExplicit SUBPIECE-of-addrtied copymarker
(MarkExplicit row) renders the re-freed narrow pieces inline. Converges to a fixpoint
(`rule_repeatapply`): ptrarith bottoms out, heritage returns 0 once complete, deadcode is idempotent
— measured ≤2 passes, perf-flat. Corpus-NEUTRAL (avg unchanged): **longdouble +0.043** (a global
read/modify/written across a call now widens + re-versions in-place, `iRam=iRam+10`, matching
Ghidra), **revisit** recovers its `SUB42`/`CONCAT22` re-versioning (the two spurious
`iRam74=(int2)iRam74;` markers collapse via the printc enabler; residual is pre-existing P6
void-return + P4 type). **switchmulti −0.042 = a GAUGE ARTIFACT, not a regression and NOT a mis-port:**
the restart correctly inlines the switch-selector global read (`(int8)iRam1000c0`), which MATCHES
Ghidra's oracle (`xVar1 = (*(code*)((int8)iRam1000c0 + 0x1000c0))(0x65)`) — the IR got MORE faithful;
the token-LCS similarity (ccompare.rs) only drops because baseline's spurious `iVar1 = iRam1000c0;`
(skeleton `IDENT = IDENT ;`) coincidentally matched Ghidra's mosura-MISSING param-spill
`xStack_20 = param_1;`. switchmulti's real gaps (missing param-spills + void-return = P6, jumptable
"Too many branches") are pre-existing and unchanged. Still SCOPED (only ptrarith re-enters heritage,
not the full mainloop body = S8-3); iterative condconst and the full actmainloop are the follow-ons.

### Setup (top-level, pre-loop)
| Ghidra action | mosura | notes |
|---|---|---|
| ActionStart | PORTED (build.rs) | raw funcdata construction |
| ActionConstbase | PORTED (build.rs) | constant space base |
| ActionNormalizeSetup | MISSING | normalize/jumptable setup |
| ActionDefaultParams | PARTIAL (fspec.rs) | default proto model (sysv) |
| ActionExtraPopSetup | MISSING | extrapop/stack-adjust modelling |
| ActionPrototypeTypes | PARTIAL (fspec.rs) | proto param/return types |
| ActionFuncLink / …OutOnly | PARTIAL (recover.rs) | call linking (recover_call_args) |

### mainloop (repeated group)
| Ghidra action | mosura | notes |
|---|---|---|
| ActionUnreachable | PARTIAL (cfg.rs) | CFG build prunes; no standalone unreachable action |
| ActionVarnodeProps | PORTED (varnodeprops.rs `ActionMarkAddrTied`, wired; scope.rs `query_properties`) | Sets `mapped/addrtied/persist` on memory varnodes before the first pool (Ghidra's `setVarnodeProperties`/`queryProperties` + the `ActionRestructureVarnode`/`syncVarnodesWithSymbols` `nolocalalias` clear): ram→addrtied\|persist, stack→addrtied iff aliased (`AliasChecker::hasLocalAlias`, `offset >= alias_boundary`). Byte-neutral on the corpus (the addrtied/persist guards in RuleSubRight/ActionConditionalConst/SubVariableFlow are inert/absorbed on these fixtures); the real flag is the Task #1 MergeRequired snip gate prereq. Run a **second** time just before ActionMergeRequired so pool-created ram/stack varnodes (e.g. a SubVariableFlow-narrowed global read) are marked — a once-pass approximation of Ghidra's addrtied-at-**creation** (`setVarnodeProperties` per varnode). **BACKLOG (faithful follow-up):** set addrtied at varnode creation, retiring the double-mark. |
| ActionHeritage | PORTED (heritage.rs) | see §5 |
| ActionParamDouble | MISSING | double-precision parameter join |
| ActionSegmentize | N/A | segmented arch only |
| ActionInternalStorage | MISSING | internal-storage annotation |
| ActionForceGoto | MISSING | forced goto (blockrecovery) |
| ActionDirectWrite ×2 | PARTIAL (heritage.rs) | mosura has limited addrforce; no directwrite pass |
| ActionActiveParam | PORTED (recover.rs `resolve_call_args`/`check_input_trial_use`) | Ghidra `FuncCallSpecs::checkInputTrialUse` register branch (fspec.cc:5638-5651), Task #4 Stage B: each call-argument trial gets Ghidra's 3-way disposition — realistic (`AncestorRealistic::execute`: a top-level input trial is rejected via the funcdata_varnode.cc:2211 early-return, but an input reached *through* a copy/subpiece/piece/zext chain is accepted — `realistic_faithful`, the traversal-aware sibling of `is_realistic`) AND `ancestor_op_use` (the same input-side USE gate as return recovery) ⇒ markActive; realistic-but-not-only-used or a not-realistic *passed-through input* ⇒ markInactive (dataflow PRESERVED, fspec.cc:5645); otherwise ⇒ markNoUse (dataflow FREED to const 0). This recovers a function-input register passed straight through to a call (indproto's else-call `param_1`, deindirect's/noforloop_globcall's args), reproducing Ghidra's if/else asymmetry (the arg is kept only where `ancestor_op_use` passes). Corpus 0.9077→0.9140 (+.0063, 55→56): indproto→1.000, deindirect .636→.857, deindirect2 .889→.936, noforloop_globcall .889→.947, switchhide .955→.960, switchmulti .559→.564; elseif .912→.904 wash. **BACKLOG (elseif −.008, the faithful-port-exposes-downstream-gap class, same as Stage A's elseif −.003):** the gate CORRECTLY recovers elseif's missing call args (matches Ghidra), but two residuals remain — (1) `build_input_from_trials` keeps a leading-active-run rather than Ghidra's `deriveInputMap`→`fillinMap`/`forceInactiveChain` hole-filling, so one call gains a spurious trailing `param_1`; (2) the newly-recovered params shift type inference uint4-vs-int4. Both are downstream of the (correct) arg recovery. Not full multi-pass ParamActive (maxpass 0). |
| ActionReturnRecovery | PORTED (recover.rs) | recover_return / resolve_return. Each return trial passes BOTH of Ghidra's gates (coreaction.cc:1930-1931): realism (`is_realistic` ≈ `AncestorRealistic::execute`) AND USE (`ancestor_op_use` = `Funcdata::ancestorOpUse` + `only_op_use`/`check_call_double_use`/`is_alternate_path_valid`/`TraverseNode` flags): the value must be used *only* to feed the RETURN, not consumed by a STORE/LOAD/BRANCH/CALL/persist elsewhere. The USE gate voids leftover-in-RAX arithmetic (condconst's `&array[i]` STORE address, the merge-bank held global / stack-canary) that realism alone accepts → condconst/piecestruct/pointercmp/etc. become void. mosura's `recover_return` appends fixed candidates (RAX:8/XMM0:8) where Ghidra registers one output trial per heritaged range (`guardReturns`, heritage.cc:1652). The former OVERLAPPING XMM0:4 sibling candidate and its `is_const_padded_piece` arbitration (a narrowing check Ghidra does not have) are RETIRED (task #5 Brick 1): both were corpus-inert, and the XMM0:4 trial's dead `SUBPIECE XMM0:16→:4` was what mis-sized ActionLaneDivide's lane choice. A `float` return now commits at XMM0:8 as Ghidra's `buildReturnOutput` commits the registered trial; 8→4 narrowing is downstream IR work (SubvariableFlow/SubfloatFlow family). `is_return_value_use` (any-return-value-slot use = the return use) remains as the accommodation to the residual multi-candidate list; whether it can revert to Ghidra's exact own-slot test (funcdata_varnode.cc:1823-1825) is an instrument-first open question shared with the CALL-input path (task #5 Brick 3). **BACKLOG (faithful follow-up): the remaining fixed-candidate list → the per-heritaged-range single-trial `characterizeAsOutput` model.** Approximations: no typelock/incidental-COPY model; `check_call_double_use` uses block position for `getSeqNum().getOrder()`; single-pass (maxpass 0) so a value that is *computed then both returned and passed to a call* is voided at this stage (the deferred-maxpass/mainloop-repeat class — see the 3 residuals) — not hit by the corpus. |
| ActionRestrictLocal | MISSING | restrict local before deadcode |
| ActionDeadCode | PORTED (deadcode.rs + consume.rs) | whole-varnode removal + neverConsumed const-0 fold `68a059e` |
| ActionDynamicMapping | MISSING | dynamic (hash-based) symbol mapping |
| ActionRestructureVarnode | PORTED (varmap.rs) | recover_scope |
| ActionSpacebase | PORTED (pipeline.rs `ActionSpacebase` + `Funcdata::spacebase`, funcdata.cc:230 — task #3 S2a) | Marks every non-free SSA version of the stack pointer RSP `is_spacebase()` + a locked pointer type on the input; wired before the first nonzero-mask/infertypes/pool (coreaction.cc:5506). The `stack` space registers RSP `(register:0x20,8)` as its spacebase register + `space_by_spacebase`/`getSpaceBySpacebase` (architecture.cc:264). Activates the faithful `is_spacebase()` consumers (ptrarith push-guards, nzmask alignment, infertypes pointer propagation). **TypeSpacebase stack-naming LANDED (task #22-A-1):** the RSP input is now typed `Pointer(8, Datatype::Spacebase)` (TYPE_SPACEBASE, type.hh:721) not the `Unknown(1)` stand-in, so `RulePtrArith`'s TYPE_SPACEBASE arm folds `RSP+off` to `PTRSUB(RSP, off)` and `printc::render_spacebase_ptrsub` (Ghidra `opPtrsub`, printc.cc:1057) names it off the recovered `ScopeLocal` symbol table (`recover_scope`) — array ⇒ `axStack_N`/`[i]`, scalar ⇒ `&xStack_N`. This **retires the print-time stack-naming adaptation** (`anchor_stack_arrays`/`stack_addr`, INT_ADD-keyed). The 2nd `ActionSpacebase` pass now runs *inside* the reheritage restart group (before `ptrarith_pool`) so splitUses' single-use frame base folds to PTRSUB, matching Ghidra's per-iteration ActionSpacebase+RulePtrArith. Corpus 0.9228→0.9206/55: varcross +.031, wayoffarray +.043, switchind +.041, loopcomment +.037, stackstring +.024; **offsetarray −.314** = faithful exposure of the then-missing ActionInferTypes-in-reheritage two-pass PTRADD (see RulePtrArith row). **task #22-A-2b LANDED** (paying back the −.314): ActionInferTypes wired into the reheritage restart + the spacebase `getSubType` type-propagation (§6) → offsetarray 0.686→**1.000**, wayoffarray 0.963→**1.000** (this also root-fixes the former #22-A-2 loop-ptr `Unknown(1)`-element poison — the poison *was* the `getSubType` `Unknown(1)` stub), partialsplit +.029, corpus 0.9206→0.9269/56. |
| Funcdata::splitUses | PORTED + WIRED (funcdata.rs `split_uses`, funcdata_varnode.cc:1540; `spacebase()` re-mark arm funcdata.cc:253-259; 2nd `ActionSpacebase` pass pipeline.rs after the reheritage restart — task #27 S1/S2/S3) | Clones a varnode's defining op at each read so every read becomes its own single-use SSA version. The `spacebase()` re-mark arm calls it on an already-spacebase register with an `INT_ADD` def (the frame base `RSP = RSP-0x68`) to turn mosura's ONE broad RSP version — shared by a loop-phi init AND a call arg, hence live across the loop → cover conflict → the #26 `trimOpInput` over-fires the spurious `pVar2 = pVar1;` — into Ghidra's narrow single-use RSP:93/RSP:94. S1 ported UNWIRED (byte-identical, 2 unit tests); S2 added the re-mark arm (inert/byte-identical on the single early call); S3 wired a 2nd `ActionSpacebase` pass after the reheritage restart (mirrors Ghidra's every-mainloop ActionSpacebase — the frame base's descendants now exist so the split fires). Corpus 0.9227→0.9228 (56/60): **varcross 0.851→0.884 (+.033)** recovers the #26 diagnostic (final IR now has the two split `r0x20 = INT_ADD r0x20 #-0x68` versions, matching Ghidra RSP:93/94; spurious `pVar2=pVar1` + trim-COPY gone). **CITATION (partialsplit −.024):** faithful-exposes-gap — Ghidra ALSO splits the frame base there (oracle IR RSP:14f/151, both `RSP(i)+-0x58`), so the split is correct; the dip is the split removing mosura's coincidental `iVar1=&xStack_58` artifact that luck-matched Ghidra's `puVar3=auStack_58`, while mosura still MISSES the late struct-return-to-stack stores (`*(...)puVar3+8=0; *puVar3=0xffff..`) that keep Ghidra's `puVar3` live → task #28 (struct-return-to-stack materialization, #22-adjacent). |
| ActionNonzeroMask | PORTED (nzmask.rs; `ActionNonzeroMask` pipeline.rs) | calc_nzmask. `apply` returns **0** (Ghidra coreaction.hh:301 `calcNZMask(); return 0;`): mask recomputation is analysis, never a data-flow change, so it must not drive the mainloop's `rule_repeatapply` fixpoint. (Was 1 — a mis-port that made the reheritage restart never converge once nzmask was placed inside it, task #22-A-2b.) |
| ActionInferTypes | PORTED (infertypes.rs) | see §6. `apply` returns 0 + self-caps at `localcount>=7` (coreaction.cc:5390/5415) → convergence-safe inside the iterating reheritage restart, where it now runs (before `ptrarith_pool`, Ghidra actmainloop order coreaction.cc:5508/5666) so a pass-1 spacebase `PTRSUB` output is re-typed and pass-2 `RulePtrArith` forms the array subscript (task #22-A-2b). |
| ActionLaneDivide | PORTED-INERT (transform.rs TransformManager S1 `c65b2cd`; lanedivide.rs LaneDivide S2 `7d3fb71`; ActionLaneDivide + pipeline wire S3a `73bd676`; Spec.laned/loader plumbing S3b) | SIMD lane splitting. Full faithful subsystem, wired post-heritage/pre-pool, but the loader does NOT populate `Spec.laned` (see the HELD-INERT note in `speccache::get`): live it net-regresses the corpus (avg 0.8936→0.8935) — mosura over-splits XMM into 4-byte lanes where Ghidra uses 8-byte. REACTIVATE (re-add the populate line in `speccache::get` + `lang::load`) when EITHER: (i) [primary] P6 stops the spurious 4-byte XMM output/param trials (`characterizeAsOutput` over-widen — a dead `SUBPIECE r0x1200:16→:4` of XMM0 that Ghidra lacks, so `collectLaneSizes` smallest-first picks 4); (ii) spacebase/StackPtrFlow moves stack resolution post-pool → Ghidra's stackstall slot usable (measured: post-pool the laned reg copy-props away, no split). `floatcast` already +0.038 → the split is right once fed correct-width reads. |
| ActionMultiCse | MISSING | MULTIEQUAL-input cross-block CSE (multicse.cc). Distinct from RuleSelectCse, which DOES do cross-block cseElimination as of Task #1; and from in-block cse_find_in_block. |
| ActionShadowVar | MISSING | shadow-varnode detection |
| ActionDeindirect | PARTIAL (recover.rs) | resolve_call_output; deindirect fixture works. Call-output recovery is now the faithful `ActionActiveReturn::apply` chain (see that row). |
| ActionStackPtrFlow | PARTIAL (stackvars.rs) | |
| ActionRedundBranch | MISSING | redundant-branch removal |
| ActionBlockStructure | PORTED (structure.rs) | |
| ActionConstantPtr | PARTIAL (infertypes.rs) | constant-pointer typing |
| ActionDeterminedBranch | PORTED (determinedbranch.rs) | |
| ActionNodeJoin | MISSING | MULTIEQUAL node-join (RulePushMulti pair) |
| ActionConditionalExe | MISSING | conditional-execution recovery |
| ActionConditionalConst | PORTED (condconst.rs) — WIRED after ActionDeterminedBranch (Task #5) | conditional constant propagation (full faithful port incl. pushConstant + phi machinery). condconst 0.814→0.862, elseif 0.899→0.915, no regressions. Runs ONCE (mosura's hand-unrolled pipeline) vs Ghidra's mainloop-repeat, which can re-fire condconst on its own output — the once-pass approximation used throughout; iterative condconst would be the mainloop-repeat item (backlog #8). |

### fullloop tail
| Ghidra action | mosura | notes |
|---|---|---|
| ActionLikelyTrash | MISSING | likely-trash register elimination |
| ActionDoNothing | N/A | |
| ActionSwitchNorm | PORTED (jumpbasic.rs `switch_norm`, wired pipeline.rs after the reheritage mainloop, before cleanup — Ghidra actfullloop coreaction.cc:4548/5684) | see §7 |
| ActionReturnSplit | MISSING | return-block split |
| ActionUnjustifiedParams | MISSING | |
| ActionStartTypes | PORTED (infertypes.rs) | type-recovery gate |
| ActionActiveReturn | PORTED (recover.rs) | wired in pipeline. CALL-output side = `resolve_call_output`, a faithful port of `ActionActiveReturn::apply` (coreaction.cc:1773): `checkOutputTrialUse` (fspec.cc:5661, output trials from the surviving killedbycall INDIRECT creations, active iff live) → `deriveOutputMap` (`ParamListStandardOut::fillinMap` firstOnly, fspec.cc:1721/1762 — the first-in-class register of the covered output class, so a lone RDX/XMM1 high-half is never a return) → `buildOutputFromTrials` (fspec.cc:5770) incl. the **2-trial `findPreexistingWhole` reassembly** (fspec.cc:5750). RETIRES the earlier first-present-of-[RAX,XMM0] single-pick adaptation (no-adaptation-grandfathered). Byte-identical on the corpus (single-trial reduces to the old pick; firstOnly re-voids loopcomment's spurious lone-RDX return the faithful multi-register scan would otherwise take). The 2-trial reassembly is the **call-output-in-RAX** fix (task #6, deindirect2): a return register split by a later sub-register write reassembles into a unique whole instead of merging with the sub-register return — NOT exercised by the single-pass corpus (activates once the mainloop's un-scoped normalize produces the split), so synthetically unit-tested (`split_call_output_reassembles_via_preexisting_whole`, `lone_rdx_clobber_is_not_a_return`). It is the **batch-retirement prereq** (see the normalizeReadSize row). Deferred: `join_dual_class` 16-byte RAX:RDX pair (no 128-bit-int-return corpus fixture); the 2-trial no-preexisting-whole join-space construction (fspec.cc:5823). |

### merge / output / finalize tail
| Ghidra action | mosura | notes |
|---|---|---|
| ActionMappedLocalSync | MISSING | |
| ActionPreferComplement | PORTED (`ActionPreferComplement`, structure.rs — Task #1 mechanism A) | The `if`/`else` normal-form flip, materialized in the IR. Runs after `ActionOrientBranches`+condnegate_pool: `structure().if_else_splits()` finds each `if`/`else` split CBRANCH (Ghidra `BlockIf::preferComplement`, block.cc:3093, `getSize()==3`); for each whose `Funcdata::op_flip_in_place_test` returns 0 (normalizes), `op_flip_in_place_execute` rewrites the comparison in place (`get_booleanflip` + `replace_lessequal` — e.g. `9 s< param_1` ⇒ `param_1 s<= 9` ⇒ `param_1 s< 10`) and `flip_in_place_execute` toggles `fallthru_true` (Ghidra `swapBlocks(1,2)` analogue, flag not edge-reversal). `rule_if_else` reads the flag (`is_oriented`) to swap arms and prints `negated=false`, retiring the print-time `if_else_flip`/`render_negated` normal-form flip for `if`/`else`. **BYTE-IDENTICAL corpus (0.9195/56)** — the IR now holds the normal form the print path used to synthesize. 4 unit tests. |
| ActionStructureTransform | PARTIAL (structure.rs) | |
| ActionNormalizeBranches | PARTIAL (`ActionOrientBranches`, structure.rs — Task #1 S1) | Branch-orientation stage after types (mirrors Ghidra's final-act placement). Covers mechanism **B** (RuleCondNegate/boolean_flip): sets `boolean_flip`+`fallthru_true` on body-on-false simple-comparison guards, then condnegate_pool materializes+normalizes. **KNOWN DIVERGENCE (tied to backlog Task #8 "port Ghidra's mutating mainloop-with-repeats structurer"):** Ghidra's `BlockBasic::negateCondition` reverses the CFG out-edge order to keep its persistent mutated block tree consistent with `boolean_flip`; mosura RE-DERIVES the block tree at print (structure() is read-only), so there is nothing to keep consistent and reversing edges instead hangs the re-collapse on loop/short-circuit-entangled guards. mosura therefore records the orientation in the persistent `fallthru_true` flag (which Ghidra's printc.cc:542 also reads) and XORs it into structure()'s `negated` — the behavior-preserving translation of the edge-reversal into the re-deriving structurer. When Task #8 lands the mutating structurer, replace the XOR with the real `negateCondition` edge-reversal. Mechanism **A** (`opFlipInPlaceExecute` normal-form flip) is now LANDED for `if`/`else` via `ActionPreferComplement` (see that row) — the faithful Ghidra path is `BlockIf::preferComplement` (if/else-scoped), NOT the global per-basic-block `ActionNormalizeBranches`, which stays MISSING/deferred (near-inert on the corpus: e.g. it would flip ifswitch's `99<param_1` guard, which Ghidra renders unflipped, so a naive global port would regress). render_negated's `<=`/`<` flip + incr_in_width are now RETIRED (deleted): with mechanism A + compound landed, every oriented order comparison is materialized in the IR, so no `<`/`<=` condition reaches print still negated (verified: zero corpus fixtures hit those arms or incr_in_width). Only the faithful `==`↔`!=` token flip (Ghidra `negatetoken`, printc.cc:133-134) + the compound De Morgan + the `!(...)` fallback remain in render_negated. |
| ActionAssignHigh / MergeRequired / MarkExplicit / MarkImplied / MergeMultiEntry / MergeCopy / DominantCopy / MarkIndirectOnly / MergeAdjacent / MergeType / HideShadow / CopyMarker | PARTIAL (merge.rs, mergesnip.rs) | merge.rs is minimal (high/same/count/merge, read-only naming). **MergeRequired**: the addrtied cover-intersection snip (`Merge::mergeAddrTied`/`unifyAddress`/`eliminateIntersect`/`snipReads` + `characterizeOverlap`/`partialCopyShadow`/`containVarnodeDef`) is PORTED **WIRED** in `mergesnip.rs` (`ActionMergeRequired`), gated on the real ADDRTIED flag (`ActionMarkAddrTied`) so it fires on ram globals / aliased stack slots, not non-aliased stack temps. INDIRECT cover positions come from the `guarded_op`/`op_index` iop link (Ghidra `getUIndex`). partialmerge is BANKED (0.786→0.970) by the B-iii module. **mergeAddrTied** (`merge_addrtied`, merge.cc:609): force-union every non-free addrtied version at one storage address, ANY size — the VariablePiece approximation (no `groupWith`/PIECE-arm; P4/P8 debt). Gated on `!isFree` not on Cover (Ghidra's `unifyAddress`) so an addrForce hold-to-end COPY output joins the global's high. Runs BEFORE `mergeMarker` (`ActionMergeRequired` = `mergeAddrTied(); groupPartials(); mergeMarker();`, coreaction.hh:370) so the marker gate sees address-tied highs already aggregated. **mergeMarker** (`merge_markers`, merge.cc:889): union each MULTIEQUAL/INDIRECT output with its inputs (INDIRECT = data input slot 0 only), each union GATED by `merge_test_required` exactly as `Merge::mergeOp`/`mergeIndirect`/`mergeOpcode` gate theirs — Ghidra force-resolves a forbidden merge by trimming the input (an inserted COPY), which in mosura's union-find is a non-union (the input keeps its own high). This is what keeps an address-forced INDIRECT that copy-prop threads a stack slot through (`r140 = INDIRECT s_f0`, stackreturn) from fusing the ram global with the stack slot — without the gate the global's store COPY looks same-high and vanishes. Verified faithful against oracle IR (elseif: Ghidra merges `u = COPY(EDI)`, not `EDI`, into the `s_f4` stack slot). `mergeIndirect`'s cover-interference snip on an address-forced INDIRECT is not modeled (the gate + non-union suffice for the union-find). **mergeOp/trimOpInput** (`merge_marker_trim`/`ActionMergeMarkerTrim`, merge.cc:719/692): the graph-mutating half of the required marker merge, WIRED right after `ActionMergeRequired`/`mergeAddrTied` (Ghidra runs `mergeMarker` inside `ActionMergeRequired`). For each MULTIEQUAL, `mergeOp` trims (via `trimOpInput`) the first input whose HighVariable Cover conflicts with the output's — inserting a COPY of the input at the predecessor block's end (`op_insert_end`, Ghidra `opInsertEnd`, at the block's stop address) and rewiring the phi to read the COPY, so the read-only `merge_markers` no longer fuses the phi output into the conflicting value. This is what mosura's read-only `merge` structurally cannot do (a non-union leaves no COPY; the trim materializes the init assignment). **floatcast 0.791→0.871 (+0.080):** the incoming address-tied global `fRam80` reaches the phi with a broad Cover that conflicts with the phi output; the trim severs the fusion → `fVar1 = fRam80;` init + the phi output a distinct local (residual to ~0.95 = the CONCAT44/#21 return decomposition, gated on #23, + a minor extra `fVar3` temp). **Faithful trim-any-conflict** (Ghidra trims on *any* cover conflict, no addrtied restriction): **varcross 0.905→0.851 (−0.054)** is the DIAGNOSTIC — a conflicting *register* input Ghidra would SSA-split into narrow single-use versions (that never conflict) is trimmed here because mosura keeps one broad register version (coarse register SSA = **Task #27**, the upstream fix), not a reason to restrict this faithful pass. Only floatcast + varcross move; all other fixtures byte-identical. **MergeCopy** (`merge_copy`, mergeOpcode COPY, merge.cc:326): block-order COPY in/out merge gated by `merge_test_basic`/`merge_test_required` (the addrtied-diff-addr / input+persist subset; a `stack` member counts as tied-to-address since mosura flags only escaped slots) + Cover interference — a snapshot COPY whose input stays live across a later store is LEFT distinct. **MarkExplicit + CopyMarker** are folded into printc's `is_explicit`/emission: addrtied → explicit (baseExplicit "pointers may reference it"), EXCEPT the addrtied **SUBPIECE-of-addrtied** sub-case (baseExplicit coreaction.cc:3023-3029: `vn->overlapJoin(vin) == SUBPIECE offset`, both addrtied → an internal copymarker "not printed") which inlines as a piece read `(int2)glob` instead of a spurious `glob = (int2)glob;`; a same-high COPY **or SUBPIECE** is hidden (`markInternalCopies` `opMarkNonPrinting`, merge.cc:1461/1508 — mosura's `high_of` identity stands in for Ghidra's VariablePiece group+offset key, as for the COPY arm); a cross-high COPY of a **persistent** input renders `iVar = <snapshot>`; a value merged into a global's high is named/materialized by that address (`high_ram_off`, the ram analogue of `high_stack_off`). This scalar SUBPIECE case keeps the mainloop re-heritage's write-masked narrow piece markers (`removeRevisitedMarkers`/`normalizeReadSize`, revisit `r74:2 = SUB42(r74:4,#0)`) from printing as `iRam74 = (int2)iRam74;` — **now ACTIVE under the landed S8-2 re-heritage restart** (revisit; was dormant/byte-identical before the restart). **The PIECE arm + the VariablePiece-needing SUBPIECE cases (a piece of a genuinely WIDER, differently-typed whole) stay deferred (P4/P8 VariablePiece debt)** — union_datatype-class residuals; also partialmerge's sole remaining `iVar1 = (int4)xRam..` cast (the 4-byte piece of the 8-byte global, which Ghidra keeps distinct via VariablePiece and casts). **multiret/sbyte B-ii tripwire RESOLVED:** the pre-B-iii `xStack_14 = xStack_14` partial-overlap self-assigns now render as named temps (`xStack_14 = 0x61`/`0x3e9`, `iVar1 = *(int1 *)..`) once markInternalCopies hides the same-high COPYs — the standing multiret citation clears, no dedicated multi-width task needed. **Not yet ported:** MergeMultiEntry / DominantCopy / MergeAdjacent / MergeType speculative merges, `processHighRedundantCopy` (Task #4 P5). |
| ActionDynamicSymbols | MISSING | |
| ActionOutputPrototype | PORTED (recover.rs) | recover_output |
| ActionInputPrototype | PORTED (recover.rs) | recover_input_params |
| ActionMapGlobals | PARTIAL (scope.rs) | |
| ActionNameVars | MISSING | variable naming (Task #4 P5) |
| ActionSetCasts | PORTED (cast.rs) | |
| ActionFinalStructure | PORTED (structure.rs) | |
| ActionPrototypeWarnings / ActionStop | N/A | |

---

## 2. oppool1 rules (coreaction.cc:5512-5646) — ~130 rules

Order = Ghidra registration = per-opcode priority. Status verified against `rules.rs` structs +
`default_rule_pool` wiring.

| # | Ghidra rule | mosura |
|---|---|---|
| RuleEarlyRemoval | PORTED (rules.rs; byte-neutral, 78× on namespace) — + ram-persist guard (Ghidra's commented isPersist, load-bearing under mosura's ram-root global liveness) |
| RuleTermOrder | PORTED |
| RuleSelectCse | PORTED — full `cseEliminateList`/`cseElimination` (funcdata_op.cc:1418/1356): getCseHash (op.cc:130) list collect + isCseMatch (op.cc:153) + **CROSS-BLOCK** elimination (Task #1: keep the dominating op, else build at the common dominator via `find_common_block`; the prior same-block-only limitation is removed — it fragmented impliedfield's shared union field). (+ earlier: isCseMatch output-size guard `8dd6d80`; Task #20 `cd0fd9e` constant inputs match by VALUE not size, so `x s>> (w-1)` merges with the compiler's own #0x3f:4/#0x3f:8) |
| RuleCollectTerms | PORTED (N-ary, `cd0fd9e` Task #20 — Ghidra's TermOrder::collect + Varnode::termOrder + distributeIntMultAdd; the whole additive tree is linearized so `(SDIV + s) - s` cancels, replacing the binary as_term collector) |
| RulePullsubMulti | PORTED (rules.rs, WIRED coreaction.cc:5516 after RuleCollectTerms; + shared helpers min_max_use/acceptable_size/find_subpiece/build_subpiece/replace_descendants + block_has_loop_in for the `hasLoopIn` guard via dominators). Pulls `SUBPIECE(MULTIEQUAL, off)` up into a narrow phi — the clean phi-narrowing mosura lacked. **The only corpus mover:** switchloop +0.019 (accumulator narrows to a clean 4-byte `uVar2 = uVar2 + 2`; the selector dups survive — loop-header phi skipped by `hasLoopIn`, complete fix → task #23). floatcast −0.054 = **faithful-exposes-gap** (fires 1x = Ghidra 1x; the pull removes a global-snapshot → exposes the pre-existing global-vs-local divergence, the #21/#22 class), lands as the diagnostic per faithful-ports-land-not-held. |
| RulePullsubIndirect | PORTED (rules.rs, WIRED coreaction.cc:5517). The INDIRECT analogue; faithfully translated to mosura's 1-input INDIRECT model — Ghidra's `getIn(1)`-IOP = mosura's `guarded_op`, `isIndirectCreation` = `Varnode::INDIRECT_CREATION` on the output (see `Funcdata::new_indirect_op`/heritage's `newIndirectCreation`). Inert on the corpus (does not fire on any fixture); unit-tested. |
| RulePushMulti | PORTED (rules.rs, WIRED coreaction.cc:5518 group "nodejoin", registered into oppool1). Push a 2-input phi down through a shared functional op / collapse a phi of two shadowing COPYs; uses a pair-returning `functional_equality_level` (added additively — existing `==0` callers untouched) + `find_substitute` (cse_find_in_block). No separate node-join subsystem is needed — Ghidra registers it directly in oppool1. Corpus score-neutral (fires switchloop 13x / loopcomment 1x, final C unchanged; over-fire vs Ghidra 2x = the #23 8-byte-r0x8 upstream); unit-tested; no SSA breakage. |
| RuleSborrow | PORTED (+ AddExpression `b5e3df8` Task #20 — subtract_matches now uses Ghidra's functional additive comparison, so `a - b` in the post-Sub2Add `a + b*-1` form still matches) |
| RuleScarry | PORTED (rules.rs; ADD sibling of RuleSborrow via add_matches, now Ghidra's AddExpression `b5e3df8` Task #20) |
| RuleIntLessEqual | DONE — WIRED in the main oppool1 @10 (Task #9) AND the post-orientation `condnegate_pool` (Task #1 S1), faithful to Ghidra's two registrations (coreaction.cc:5521 + the analysis re-run). `V <= c => V < (c+1)` via `replace_lessequal` (port of Funcdata::replaceLessequal), 4 unit tests. Wiring @10 was HELD pre-keystone (it made the print-time negation emit `100 <= x` vs Ghidra `99 < x`); task #8 materialized the negation in the IR → unblocked. Instrumented on wire (Ghidra `capture_trace` on condmulti): the @10 firing is **byte-faithful** — Ghidra fires `intlessequal` on the identical op (`6 <= x => 5 < x`). It exposed ONE downstream gap, now CLOSED by **RuleRangeMeld** (Task #11, see its row): the @10 SLESSEQUAL→SLESS conversion put the flag-reconstruction fold out of RuleLessNotEqual's reach (SLESSEQUAL-form only, ruleaction.cc:2290), and RuleRangeMeld recovers it in the SLESS form, matching Ghidra's `sborrow→intlessequal→rangemeld` chain. Landing @10 alone dipped condmulti/deindirect/elseif/loopcomment (corpus 0.9196/56→0.9168/55 at `0c6e0ea`) — the diagnostic naming the gap, not a mis-port (suite green, switch green); RuleRangeMeld then restored all four byte-identically (→0.9196/56). Landed per faithful-ports-land-not-held. printc::incr_in_width already DELETED (mechanism A `ActionPreferComplement` + compound `BlockCondition::negateCondition` materialize the print-time `<=` shortcut in the IR). |
| RuleTrivialArith | PORTED |
| RuleTrivialBool | PORTED (rules.rs; unit-tested — fold BOOL_AND/OR/XOR with a constant operand; fires 83× on corpus but rendered C is byte-IDENTICAL, effect absorbed downstream) |
| RuleTrivialShift | PORTED |
| RuleSignShift | PORTED (rules.rs, WIRED slot 14 — Task #20 keystone, RuleSub2Add now in the main pool) |
| RuleTestSign | PORTED (rules.rs, WIRED slot 15 — Task #20 keystone) |
| RuleIdentityEl | PORTED |
| RuleOrMask | PORTED |
| RuleAndMask | PORTED |
| RuleOrConsume | PORTED (rules.rs; unit-tested — drop OR/XOR input whose nz bits are unconsumed downstream; fires 124× on corpus but rendered C byte-IDENTICAL, absorbed by consume/deadcode) |
| RuleOrCollapse | PORTED |
| RuleAndOrLump | PORTED (rules.rs; byte-neutral, unit-tested — `(V op c) op d => V op (c⊙d)` for AND/OR/XOR; fires 1x on corpus but rendered C byte-IDENTICAL, absorbed downstream) |
| RuleShiftBitops | PORTED |
| RuleRightShiftAnd | PORTED (rules.rs; byte-neutral, unit-tested — `(V & M) >> sa => V >> sa` when the mask covers the whole surviving field, INT_RIGHT/INT_SRIGHT; inert on corpus) |
| RuleNotDistribute | HELD(defined, unwired — no verified firing site / kept out) |
| RuleHighOrderAnd | PORTED |
| RuleAndDistribute | HELD(RuleHumptyOr ping-pong hang) |
| RuleAndCommute | PORTED (+ wrapping_shr x86 shift guard `68a059e`) |
| RuleAndPiece | PORTED |
| RuleAndZext | PORTED |
| RuleAndCompare | HELD(defined, unwired) |
| RuleDoubleSub | PORTED (rules.rs; unit-tested — sub(sub(V,c),d)=>sub(V,c+d); MOVER, lead-approved: sole corpus mover is switchloop 0.7680->0.7787 toward Ghidra, floatcast/floatprint byte-identical) |
| RuleDoubleShift | PORTED (rules.rs; byte-neutral, unit-tested — combine/cancel chained shifts; inert on corpus) |
| RuleDoubleArithShift | PORTED (rules.rs; byte-neutral, unit-tested — (x s>> c) s>> d => x s>> saturate(c+d); inert on corpus) |
| RuleConcatShift | PORTED (rules.rs; byte-neutral, unit-tested — concat(V,W)>>c => ext(V) when the shift discards W; inert on corpus) |
| RuleLeftRight | DEFERRED (`(V << c) s>> c => sext(sub(V,#0))`; needs op_unset_input/output + register-piece varnode creation (new_varnode_out+renormalize) mosura lacks — same register-piece territory as Task #7; not blocked on the (now-done) RuleDivOpt de-fusion) |
| RuleShiftCompare | PORTED |
| RuleShift2Mult | PORTED |
| RuleShiftPiece | PORTED |
| RuleMultiCollapse | PORTED (+ nofunc const-base guard `68a059e`) |
| RuleIndirectCollapse | BLOCKED (INDIRECT/effect subsystem, Task #10 — "remove a CPUI_INDIRECT if its blocking PcodeOp is dead"; depends on mosura's INDIRECT/effect-guard machinery, which is the iop/2-input-INDIRECT debt) |
| Rule2Comp2Mult | PORTED (rules.rs; byte-neutral, unit-tested — `-V => V * -1` canonicalization in the main pool so mult/term rules act on it uniformly; cleanup-pool `RuleMultNegOne` restores `-V` (separate pools, no ping-pong); 0 firings on corpus — no surviving INT_2COMP reaches actprop — byte-IDENTICAL. Added `op_insert_input` helper) |
| RuleSub2Add | PORTED (relocated to the main pool slot 42, Ghidra's actprop position — Task #20 keystone; the switch/jumptable cascade it triggered was resolved by the RuleEqual2Zero mask fix `3225f2b` + the faithful comparison/sign cluster, not by keeping it out of main) |
| RuleCarryElim | PORTED (rules.rs; byte-neutral, unit-tested — `carry(V, c) => (-c) <= V`, special case `carry(V, 0) => false`; fires 19x on corpus but rendered C byte-IDENTICAL, absorbed downstream) |
| RuleBxor2NotEqual | PORTED (rules.rs; byte-neutral, unit-tested — `V ^^ W => V != W` (BOOL_XOR is boolean inequality); inert on corpus) |
| RuleLess2Zero | PORTED (rules.rs; unit-tested — INT_LESS vs extremal 0/max constants; fires 9× on corpus but rendered C byte-IDENTICAL, absorbed downstream) |
| RuleLessEqual2Zero | PORTED |
| RuleSLess2Zero | PORTED (rules.rs; byte-neutral, 7 unit tests — INT_SLESS vs 0/-1, peel a sign-only op: SUBPIECE-of-top-piece / `~V` / `V & 0x8..` / `CONCAT(V,W)` / `getHiBit(add\|or\|xor)`=>EQUAL/NOTEQUAL / `bool << (8*sz-1)`=>`!bool`; 0 firings on corpus, byte-IDENTICAL — the sign-only-op-against-0/-1 idiom doesn't survive to actprop in the fixtures) |
| RuleEqual2Zero | PORTED (+ the INT_ADD(x, y*-1) variable-negation arm `2b22f65`, Task #20 — `(x + y*-1) == 0 => x == y` for the post-Sub2Add subtraction form). **DEBT:** Ghidra's all-descendants-bool-output guard (`for (iter : addvn->beginDescend()) if (!boolop->isBoolOutput()) return 0`, ruleaction.cc) is deliberately OMITTED — adding it suppresses an equal2zero firing switchloop's jumptable recovery depends on (mosura's switch-path IR gives the guard sum a non-bool use Ghidra's doesn't, a separate switch-path divergence). Per no-adaptation-grandfathered this omission is CANCELED the moment that divergence is fixed: restore the guard + re-verify switchloop then. Code comment at the arm in rules.rs. |
| RuleEqual2Constant | PORTED (rules.rs; byte-neutral, unit-tested — fold const through arith operand of INT_EQUAL/NOTEQUAL when V only used in similar compares; inert on corpus) |
| RuleThreeWayCompare | PORTED (rules.rs; byte-neutral, 3 unit tests — detect a three-way `zext(V<W)+zext(V<=W)-1` (3 add/const permutations + partial form, via detectThreeWay/testCompareEquivalence helpers) and fold a secondary compare of it vs a small constant back to a direct `V`/`W` compare (24-case form table); 0 firings on corpus — the C++ spaceship idiom doesn't occur in the fixtures) |
| RuleXorCollapse | PORTED |
| RuleAddMultCollapse | PORTED (relocated to the main pool slot 52 — Task #20 keystone) |
| RuleCollapseConstants | PORTED (= RuleConstFold; + the previously-omitted `PcodeOp::isCollapsible` size guard restored (op.cc:115 `getOut()->getSize() > sizeof(uintb)` → no fold) — mosura constants carry a u64, so folding a >8-byte output silently zero-extended, e.g. turning the sign-extended 64-bit division magic into the unrecoverable magic65; restoring the guard collapsed modulo's 64-bit signed `%0x3c`/`%100` byte-exact (0.893→0.950) and fixed floatconv's same-class truncating fold (0.578→0.596)) |
| RuleTransformCpool | BLOCKED (constant-pool subsystem absent — transforms CPUI_CPOOLREF by looking the reference up in the constant pool; mosura has the CPOOLREF opcode but no constant-pool resolution subsystem) |
| RulePropagateCopy | PORTED (+ isReturnCopy RETURN guard `5a8ac03`) |
| RuleZextEliminate | PORTED |
| RuleSlessToLess | PORTED |
| RuleZextSless | PORTED (rules.rs; byte-neutral, unit-tested — `zext(V) s< c => V < c` (+ SLESSEQUAL / reversed-operand), when c's narrow sign bit is clear so the zext is unnecessary; inert on corpus: no surviving signed-compare-of-zext-vs-const idiom in the fixtures) |
| RuleBitUndistribute | PORTED (rules.rs; byte-neutral, 3 unit tests — pull a common ext/shift out of both operands of a bitwise op: `zext(V)&zext(W)=>zext(V&W)` (ZEXT/SEXT), `(V>>X)|(W>>X)=>(V|W)>>X` (LEFT/RIGHT/SRIGHT, shift amounts must match); builds an inner bitwise op on the un-ext/un-shifted values via new_op_before_sized; 0 firings on corpus — the idiom doesn't occur in the fixtures) |
| RuleBooleanUndistribute | PORTED (rules.rs; byte-neutral, 2 unit tests — undo distributed BOOL_AND through INT_EQUAL/NOTEQUAL: `A&&B != A&&C => A&&(B!=C)`, `A&&B == A&&C => !A\|\|(B==C)`; backed by the `BooleanMatch` classifier now ported as expression.rs (expression.cc:57-216: varnodeSame/sameOpComplement/recursive evaluate with De Morgan) + `get_booleanflip` (opcodes.cc:94, opcode.rs) + `Funcdata::op_bool_negate` (funcdata_op.cc:560); 0 firings on corpus) |
| RuleBooleanDedup | PORTED (rules.rs; byte-neutral, 3 unit tests — remove duplicate clauses in boolean expressions: `(A&&B)\|\|(A&&C) => A&&(B\|\|C)`, contradiction `(A&&B)&&(!A&&C) => false`, tautology `=> true`, `(A\|\|B)\|\|(!A&&C) => A\|\|(B\|\|C)`; same BooleanMatch dependency as RuleBooleanUndistribute, both wired at oppool1 slots 60/61; 0 firings on corpus) |
| RuleBoolZext | PORTED (rules.rs; byte-neutral, unit-tested — simplify `zext(V)*-1` extended booleans: `+1`=>`zext(!V)`, `==-1`=>`V==true`, `&`/`|`/`^`=>`zext(V&&W)*-1`; inert on corpus: the all-ones-smeared boolean idiom doesn't survive to actprop in the fixtures) |
| RuleBooleanNegate | PORTED |
| RuleLogic2Bool | PORTED |
| RuleSubExtComm | PORTED |
| RuleSubCommute | PORTED (ruleaction.cc:4514 incl. shortenExtension/cancelExtensions; wired lead-side, corpus avg->0.8870 [modulo 0.908, ifswitch 0.922 toward Ghidra]; sole dip impliedfield 0.889 = token artifact of correctly dropping redundant casts over an upstream float-typing divergence, debt-tracked) |
| RuleConcatCommute | PORTED (rules.rs; unit-tested — commute PIECE with AND/OR/XOR-const; MOVER: fires 11×/5 fixtures, 4 byte-identical, switchloop 0.7658→0.7680 toward Ghidra; surfaces an `xunknown1` cast on the rule-created PIECE input — separate type-inference gap, debt-tracked) |
| RuleConcatZext | PORTED (rules.rs; byte-neutral, unit-tested — pull zext out of concat: concat(zext(V),W)=>zext(concat(V,W)); inert on corpus) |
| RuleZextCommute | PORTED (rules.rs; byte-neutral, unit-tested — commute zext/right-shift: zext(V)>>W=>zext(V>>W); inert on corpus) |
| RuleZextShiftZext | PORTED |
| RuleShiftAnd | PORTED (rules.rs; byte-neutral, unit-tested — shift/mult over redundant AND-mask drop, nzmask-gated; inert on corpus: mosura collapses the masked AND upstream before it reaches actprop) |
| RuleConcatZero | PORTED (rules.rs; unit-tested — concat(V,0)=>zext(V)<<c; MOVER, lead-approved: sole corpus mover is nan CONCAT44(0,0)=>0, ccompare 0.5385->0.5600 toward Ghidra) |
| RuleConcatLeftShift | PORTED (rules.rs; byte-neutral, unit-tested — concat(V,zext(W)<<c)=>concat(concat(V,W),0); inert on corpus) |
| RuleSubZext | PORTED (rules.rs; WIRED at coreaction.cc:5585, slot 74, between RuleConcatLeftShift and RuleSubCancel). Held 16 sessions for corpus-protection (a faithful-ports-land-not-held drift); landed once the old wide-return regressors were cleared by the iterating mainloop + const-0 fold + RuleSubvarZext return-narrowing + RulePiece2Zext (piecestruct/namespace/orcompare/floatconv family now byte-identical with it on). Residual forloop_varused/noforloop_iterused −0.086/−0.022 = the missing induction-phi narrowing diagnostic (Ghidra narrows the 8-byte loop phi via subvar_subpiece+andmask at the loop header; mosura doesn't) → Task #24; switchloop +0.012. |
| RuleSubCancel | PORTED (rules.rs; byte-neutral, unit-tested — SUBPIECE cancels a ZEXT/SEXT/AND: `sub(zext(V),0)`=>V/sub(V)/narrower zext, `sub(V&fullmask,0)`=>sub(V), `sub(zext(V),c>=farin)`=>0; fires 5x but rendered C byte-IDENTICAL, absorbed downstream. mosura's is_free treats constants as non-free, so the big-constant offset-0 sub-case is structurally preserved but unreachable) |
| RuleShiftSub | PORTED (rules.rs; byte-neutral, unit-tested — `sub(V << 8k, c) => sub(V, c-k)` for a byte-granular left shift when the window stays within V; inert on corpus) |
| RuleHumptyDumpty | PORTED |
| RuleDumptyHump | PORTED |
| RuleHumptyOr | PORTED |
| RuleNegateIdentity | PORTED (rules.rs; byte-neutral, 3 unit tests — INT_NEGATE identities against a logical op reading both `~V` and `V`: `V & ~V => 0`, `V | ~V => -1`, `V ^ ~V => -1` (collapse the AND/OR/XOR to a COPY of the constant); 0 firings on corpus — the idiom doesn't survive to actprop in the fixtures) |
| RuleSubNormal | PORTED (rules.rs, WIRED at slot 81 — faithful port of ruleaction.cc:7714, `sub(V>>n,c) => sub(V,c+n/8) >> (n mod 8)` / `=> ext(sub(V,c'))`, 4 unit tests. Its non-zero-offset SUBPIECEs are re-expanded for printing by the cleanup-pool RuleSubRight, exactly as Ghidra does (instrumented: Ghidra fires subnormal 2x then subright 2x on packstructaccess; oracle final IR keeps shift + offset-0 SUBPIECE). Lead-approved mover: ifswitch 0.922→0.985 (`(int4)p/5`), packstructaccess 0.826→0.913; impliedfield dip traces to the pre-existing missing float4-conversion/explicit-var path, divopt dip to the fused RuleDivOpt #9) |
| RulePositiveDiv | PORTED |
| RuleDivTermAdd | PORTED (WIRED slot 83 — Task #20 keystone; the fused RuleDivOpt that raced it is retired) |
| RuleDivTermAdd2 | PORTED |
| RuleDivOpt | PORTED (FAITHFUL, de-fused `cd0fd9e` Task #20 — findForm signed INT_SEXT path + nzmask xsize + applyOp width ext/trunc + moveSignBitExtraction (emits `(x s/d)+(x s>>63)`); the fused try_unsigned/match_mulhi/try_signed/add_correction recognizers RETIRED) |
| RuleSignForm | PORTED (WIRED slot 86 — Task #20 keystone; the fused RuleDivOpt that failed to re-collapse its s>> form is retired) |
| RuleSignForm2 | PORTED (WIRED slot 87 — Task #20; ruleaction.cc:8476, replicates Ghidra's return-0-after-mutate quirk) |
| RuleSignDiv2 | PORTED (divopt.rs, WIRED slot 88 — Task #20; ruleaction.cc:8339 `(V + -1*(V s>> 8n-1)) s>> 1 => V s/2`) |
| RuleDivChain | PORTED (divopt.rs, WIRED slot 89 — Task #20; ruleaction.cc:8392 `(x/c1)/c2 => x/(c1*c2)` + unsigned INT_RIGHT case + overflow/reuse guards) |
| RuleSignNearMult | PORTED (divopt.rs, WIRED slot 90 — Task #20; ruleaction.cc:8533 `(V + (V s>>0x1f)>>(32-n)) & (-1<<n) => (V s/2^n)*2^n`) |
| RuleModOpt | PORTED (FAITHFUL, `cd0fd9e` Task #20 — Ghidra's INT_DIV/INT_SDIV-rooted forward walk over the post-Sub2Add `x + (x/d)*(-d)` ADD form, replacing the non-faithful INT_SUB-rooted adaptation) |
| RuleSignMod2nOpt | PORTED (FAITHFUL, `4f19ab6` Task #20 — INT_RIGHT-rooted, walking forward to the `* -1`/AND/`V + correction`, replacing the INT_SUB-rooted adaptation that fired where Ghidra didn't) |
| RuleSignMod2nOpt2 | PORTED (FAITHFUL, `4f19ab6` Task #20 — INT_MULT-rooted with checkSignExtForm; the general 2^n MULTIEQUAL conditional form is deferred) |
| RuleSignMod2Opt | PORTED (divopt.rs, WIRED slot 94 — Task #20; ruleaction.cc:8776 `(V - sign)&1 + sign => V s%2` + check_sign_extraction / trunc-re-extend path) |
| RuleSwitchSingle | MISSING |
| RuleCondNegate | PORTED (WIRED in condnegate_pool — Task #1 S1; ruleaction.cc:5474: on a CBRANCH the late `ActionOrientBranches` (§1 ActionNormalizeBranches row) marked `boolean_flip`, insert `BOOL_NEGATE(cond)`, repoint the CBRANCH, `opFlipCondition`; RuleBoolNegate folds it to the complementary comparison. Orientation via the `fallthru_true` flag + structure() XOR, NOT edge-reversal — see the ActionNormalizeBranches row for that KNOWN DIVERGENCE (→ backlog Task #8). Corpus 0.8865→0.8882, all-positive delta, switch canary green; ifswitch `99 < (int4)param_1`, pointerrel `fRam < fStack_18` now materialized in IR. **KNOWN LIMITS (each a documented deferral, not a silent easy-case skip — `branch_negations`/`near_switch`):** (1) compound `&&`/`||` guards NOW PORTED (Task #1 compound): `collect_negations`/`compound_leaves` recurse a negated compound condition and orient EVERY short-circuit leaf CBRANCH (Ghidra `BlockCondition::negateCondition`, block.cc:3023, distributes the NOT to each side) — all-or-nothing (only when every leaf is a cleanly-foldable comparison + non-switch, matching Ghidra's recursion over both sides), the connective re-derived by De Morgan, per-leaf orientation read at print (printc `operand_oriented`), `is_oriented` returns false for compound blocks so the top-level `negated` (De Morgan direction) is not perturbed. loopcomment leaf `0x65 <= param_2` → `100 < param_2` (materialized IR `INT_SLESS #0x64 param_2` = Ghidra `#0x64 < ESI`), 0.736→0.745; elseif byte-identical (already matched); nan skipped (nested `BOOL_OR`/NAN leaf not foldable → stays print-time De Morgan). No hang (flag approach, no edge reversal). **The all-or-nothing gate is a STAGING BOUNDARY, not a grandfathered adaptation** — the oriented leaves match Ghidra and the deferred (skipped) compound is left byte-identical on the correct print-time De Morgan; FOLLOW-UP: port `BlockCondition::negateCondition` for the nested-`BOOL_OR`/`NAN` leaf case (Ghidra recurses into a nested `BlockCondition`/negates a `BOOL_NEGATE`/`FLOAT_NAN` leaf that mosura's `condition_folds_cleanly` currently rejects) → then the all-or-nothing gate AND the print-time De Morgan fallback both retire (same all-or-nothing discipline S1 established). (2) non-comparison conditions (BOOL_AND/OR/etc.) as the WHOLE condition skipped → need mechanism-A `opFlipInPlaceExecute` normal-form flip, DEFERRED (Task #4/S3). (3) switch range-guards skipped (`near_switch`, via cached `f.jumptables` op_addr) → VERIFIED FAITHFUL: Ghidra `JumpBasic::foldInOneGuard` (jumptable.cc:1373, `guard.clear()`) folds the guard INTO the switch rather than rendering it as an oriented `if`, so we are not dropping a case Ghidra keeps (ifswitch oracle: outer `if (99<param_1)` oriented + switch guard folded — matches). (4) orientation skipped during build's jump-table recovery probe (`table_recovery_probe` flag, build.rs:224) → materializing a guard there perturbs the range analysis and under-recovers in-code tables; follow-up is the build-probe/recovery interaction. |
| RuleBoolNegate | PORTED |
| RuleLessEqual | PORTED |
| RuleLessNotEqual | PORTED (rules.rs, WIRED slot 100 — `2b22f65` Task #20; BOOL_AND `(V <= W) && (V != W) => V < W`, collapses the for-loop guard to `<` without the print-time `<=` adaptation) |
| RuleLessOne | MISSING |
| RuleRangeMeld | PORTED (rules.rs, WIRED slot 101 — Task #11; BOOL_AND/BOOL_OR of two `V s< c`/`c s< V`/`V == c`/`V != c` range conditions, pulled back to a common Varnode as a `CircleRange` and intersected/unioned, then `CircleRange::translate2_op` re-expresses the result as one comparison. Collapses the x86 signed-compare flag reconstructions — `jg` form `(x != c) && (c-1 s< x) => c s< x`, `jle` form `(x == c) || (x s< c) => x s< c+1`. This is the paydown for RuleIntLessEqual @10 (Task #9): the @10 SLESSEQUAL→SLESS conversion put the fold out of RuleLessNotEqual's reach (SLESSEQUAL-form only); RuleRangeMeld recovers it in the SLESS form, matching Ghidra's `sborrow→intlessequal→rangemeld` chain. Recovers condmulti/deindirect/elseif/loopcomment byte-identically (corpus 0.9168/55→0.9196/56). 3 unit tests. `CircleRange::pullBack`/`intersect`/`circleUnion` already present; only `translate2Op` was added.) |
| RuleFloatRange | PORTED |
| RulePiece2Zext | PORTED (rules.rs; WIRED at coreaction.cc:5614, after RuleFloatRange). Was HELD ("rides with SubZext un-hold") for a floatconv over-fire; that hold is RESOLVED — the over-fire was the wide-return divergence, cleared once RuleSubvarZext narrows returns (floatconv unchanged 0.653 at wiring). Feeds RuleSplitFlow (movsd zero-high `CONCAT88(#0,Qa)`->`ZEXT816(Qa)`). |
| RulePiece2Sext | MISSING |
| RulePopcountBoolXor | PORTED |
| RuleXorSwap | MISSING |
| RuleLzcountShiftBool | MISSING |
| RuleFloatSign | MISSING |
| RuleOrCompare | PORTED |
| RuleSubvarAnd | PORTED |
| RuleSubvarSubpiece | PORTED. Its trace now handles the CALL-pull: `SubvariableFlow::try_call_pull` (subflow.cc:208) + `PcodeOp::getRepeatSlot` (op.cc:93) + the traceForward CALL/CALLIND arm (subflow.cc:616-623) are ported (was a Stage-4 `_ => return false` stub) — the loop induction phi passed to a call now narrows 8→4 bytes. WIRED (engine, all subvar rules). Net-positive: forloop_varused 0.914→1.000 (byte-identical to Ghidra), noforloop_iterused +0.035, noforloop_alias/elseif/loopcomment bonus, 0 down (+0.0025). Prereq: `active_inputs` cleared on param-recovery commit (isInputActive→false in a later mainloop pass). |
| RuleSplitFlow | PORTED (`splitflow.rs` SplitFlow + RuleSplitFlow on the transform.rs TransformManager; subflow.cc:1754-2088; S1 `d171301`). WIRED at coreaction.cc:5623 (after RuleSubvarSubpiece) = the floatcast XMM 16→8 narrowing: splits a movsd-zero-joined XMM0 MULTIEQUAL into 8-byte Qa/Qb lanes (Qb=0 dies). floatcast 0.776→0.845, the only mover, zero regressions. RESIDUAL (task #21): the straight-line `PIECE #0:8 -> SUBPIECE #0` return chain stays 16-byte — faithfully NOT split (Ghidra `vn->getDef()!=multiOp` guard); Piece2Zext re-widens the 8-byte diff, so the return decomposition renders CONCAT124 not CONCAT44. |
| RulePtrFlow | MISSING (needs Varnode::isPtrFlow — aggressive subvar) |
| RuleSubvarCompZero | PORTED |
| RuleSubvarShift | PORTED |
| RuleSubvarZext | PORTED (`381e745`; delivers int4 returns) |
| RuleSubvarSext | BLOCKED(sext tracer `trace_forward_sext`/`trace_backward_sext` stubbed in subvarflow.rs; the last Stage-4 remainder alongside RulePtrFlow=isPtrFlow) |
| RuleNegateNegate | MISSING |
| RuleConditionalMove | MISSING |
| RuleOrPredicate | MISSING |
| RuleFuncPtrEncoding | MISSING |
| RuleSubfloatConvert | BLOCKED(SubfloatFlow subsystem — subflow.cc) |
| RuleFloatCast | PORTED (rules.rs; byte-neutral, unit-tested — inert on corpus: the stacked FLOAT2FLOAT/INT2FLOAT pattern it targets doesn't survive to actprop; floatcast fixture's imperfection is upstream float sizing, not this rule) |
| RuleIgnoreNan | PORTED |
| RuleUnsigned2Float | MISSING |
| RuleInt2FloatCollapse | MISSING |
| RulePtraddUndo | MISSING |
| RulePtrsubUndo | MISSING |
| RuleSegment | N/A (segmented arch) |
| RulePiecePathology | MISSING |
| RuleDoubleLoad | MISSING |
| RuleDoubleStore | MISSING |
| RuleDoubleIn | MISSING |
| RuleDoubleOut | MISSING |

**mosura-only pool rules (no Ghidra oppool1 counterpart, slotted next to siblings):** RuleMultMult,
RuleIdempotent, RuleRangeAnd — faithful IR-alignment extras (see pipeline.rs comments).

**Sign-div cluster DE-FUSED + WIRED (Task #20, done 2026-07-07).** The RuleDivOpt de-fusion landed:
the fused non-faithful recognizer (try_unsigned/match_mulhi/try_signed/add_correction) is RETIRED and
replaced by Ghidra's separate composition — RuleDivTermAdd(83)/DivTermAdd2(84) reassembly →
RuleDivOpt(85, faithful findForm/applyOp signed+unsigned) → RuleModOpt(91, INT_DIV-rooted) — and the
whole normalizer/recognizer cluster around it is now WIRED at Ghidra's actprop slots: RuleSignShift(14),
RuleTestSign(15), RuleSignForm(86), RuleSignForm2(87), RuleSignDiv2(88), RuleDivChain(89),
RuleSignNearMult(90), RuleSignMod2nOpt(92), RuleSignMod2nOpt2(93), RuleSignMod2Opt(94). RuleSub2Add(42)
and RuleAddMultCollapse(52) were relocated from ptrarith into the main pool so the additive forms these
rules key on actually appear. The sign correction `(x s/d)+(x s>>k) - (x s>>k)` cancels via the
isCseMatch-value fix + N-ary RuleCollectTerms; the comparison flag idioms compose via AddExpression +
RuleLessNotEqual + the RuleEqual2Zero variable arm. Corpus net-positive (0.8865 vs 0.8864); divopt +0.021.
Residual: the 64-bit signed 65-bit-magic case (modulo -0.012) = Task #9.

**RuleSubfloatConvert** is BLOCKED, not a mechanical tail rule: it is a thin dispatcher (`subflow.cc:3489`)
into `SubfloatFlow : public TransformManager` (subflow.cc). That needs (a) the generic `TransformManager`/
`TransformVar` transform framework — NOW PORTED (transform.rs, task #6 S1: TransformManager/TransformVar/
TransformOp/LaneDescription/LanedRegister, the reusable base SubfloatFlow/SplitFlow/SplitDatatype extend;
mosura's `SubvariableFlow` in subvarflow.rs remains a bespoke integer-subvalue port) — and (b) `FloatFormat`-driven
precision tracing (maxPrecision/exceedsPrecision/traceForward/traceBackward/doTrace/apply). This is the
float-precision-narrowing subsystem (Task #11 float / a TransformManager port), not the rule tail. It is
`FLOAT_FLOAT2FLOAT`'s real handler; RuleFloatCast (also on FLOAT_FLOAT2FLOAT) is the small in-place
sibling and IS ported.

---

## 3. oppool2 rules (coreaction.cc:5664-5669)

| Ghidra rule | mosura |
|---|---|
| RulePushPtr | PORTED (ptrarith.rs `RulePushPtr`, ptrarith_pool — task #22 A) — ruleaction.cc:6834: push a pointer-typed Varnode to the bottom of its additive expression (`INT_ADD(INT_ADD(ptr,a),b)` → `INT_ADD(ptr, INT_ADD(a,b))`) so `RulePtrArith` can root at the pointer. Fires when `evaluatePointerExpression == 1` (a push is needed) — the case mosura's `apply_op` previously treated as no-op. Wired **before** RulePtrArith (Ghidra actprop2 order, coreaction.cc:5664/5666). This is what lets a shared frame base `RSP - k` feeding a variable-indexed stack-array LOAD `framebase + i*elem` reroot at `RSP_input` so the tree folds to `PTRSUB(RSP, array) + i` (wayoffarray 0.920→0.963). Ghidra's `collectDuplicateNeeds`/`duplicateNeed` CSE (multi-descendant shared push) omitted — `splitUses` gives each frame base a single descendant, so the duplicate path is unreached. |
| RuleStructOffset0 | PARTIAL (ptrarith.rs / infertypes struct-offset-0) |
| RulePtrArith | PORTED (ptrarith.rs, ptrarith_pool) — incl. the **TYPE_SPACEBASE arm** of `calcSubtype` (ruleaction.cc:6286, task #22 A): a spacebase pointee always has a matching sub-type (`getSubType` never null), so any `RSP + const` folds to `PTRSUB(RSP, off)`. `hasMatchingSubType` (ruleaction.cc:6064) ports the array-hint path — `TypeSpacebase::nearestArrayedComponent{Backward,Forward}` (type.cc:2971/3020) over the recovered `ScopeLocal` table (`recover_scope`): resolves a variable-indexed stack array to its base + folds the residual into the additive tail. **offsetarray two-pass PTRADD (task #22-A-2b LANDED):** the clean `axStack_98[param_1]` subscript needs the *two-pass* PTRADD — pass-1 ptrarith forms `PTRSUB(RSP, array_start)`, then `ActionInferTypes` (now run *inside* the reheritage restart) types that PTRSUB output as a pointer to the ScopeLocal array element (via the TYPE_SPACEBASE `getSubType` propagation, §6), so pass-2 ptrarith's Array arm folds the index into `PTRADD(array, i, elem)`. `default_rule_pool` in the restart folds the pass-1 `+array_start … −array_start` compensation to a bare `i*elem` first. offsetarray 0.686→1.000, wayoffarray 0.963→1.000. (The earlier "-0x98 vs -0x68 offset gap" premise was a mis-read cross-contaminated from varcross — offsetarray's final IR uses −0x98 throughout, no gap; the compensation was the un-folded residual, now folded.) |
| RuleLoadVarnode | PARTIAL (rules.rs, ptrarith_pool — task #7 S1) — the **ram-global const-offset branch** ported (ruleaction.cc:4277, the `checkSpacebase` `offvn->isConstant()` case): `LOAD #space #constaddr` → `COPY <space:addr>`, so a constant-address global access names as `iRam/fRam/xRam` instead of `*addr`. Wired in ptrarith_pool after RulePtrArith (Ghidra actprop2 order, coreaction.cc:5666-5669). Corpus 0.9140→0.9168 (+.0028): longdouble .783→.909, switchmulti .564→.628; revisit .654→.633 CITED below. NOT ported: the **spacebase-register branch** (`vnSpacebase`/`correctSpacebase`, stackpointer+const — the stack case, entangled with pre-pool stackvars + heritage guardLoads versioning) = task #7 S2; the `isSpacebasePlaceholder`→`resolveSpacebaseRelative` SP-across-call trigger = S3. **CITATION (revisit −.021):** the pool-converted ram varnode is not re-heritaged (Ghidra runs this rule in the re-heritaging mainloop; mosura runs heritage-to-completion before the pools), so a read/modify/write of a global reads the pre-store version and the faithful merge-snip snapshots it (`iVar1=iRam; iRam=iVar1+10` vs Ghidra `iRam=iRam+10`). The value-versioning fix (re-heritage after conversion) folds into S2, same class as the multiret partial-overlap citation. |
| RuleStoreVarnode | PARTIAL (rules.rs, ptrarith_pool — task #7 S1) — the ram-global const-offset counterpart of RuleLoadVarnode (ruleaction.cc:4319): `STORE #space #constaddr val` → `<space:addr> = COPY val`. `setStackStore` (a later-stack-analysis marker) + `markNotMapped` (needs a local scope the raw-decompile path lacks) omitted — neither affects ram-global naming. Same S2/S3 remainder + versioning citation as RuleLoadVarnode. |

---

## 4. cleanup rules (coreaction.cc:5696-5710)

| Ghidra rule | mosura |
|---|---|
| RuleMultNegOne | PORTED (cleanup_pool) |
| RuleAddUnsigned | PORTED (cleanup_pool) |
| Rule2Comp2Sub | PORTED (cleanup_pool) |
| RuleDumptyHumpLate | MISSING |
| RuleSubRight | PORTED (rules.rs, wired in cleanup_pool at Ghidra's actcleanup slot (coreaction.cc:5700) — `sub(V,c) => sub(V>>c*8, 0)` truncation-to-cast cleanup, with lone INT_RIGHT/SRIGHT descendant lumping + sign-extraction clamp; 4 unit tests. Ghidra's special-print/isPieceStructured guard is vacuously absent (no TypePartialStruct yet, P4/P8 debt); the uint/int typing of the new shift output is likewise not carried (no datatypes at rule time)) |
| RuleFloatSignCleanup | MISSING |
| RuleExpandLoad | MISSING |
| RulePtrsubCharConstant | MISSING |
| RuleExtensionPush | MISSING |
| RulePieceStructure | MISSING |
| RuleSplitCopy | BLOCKED(SplitDatatype subsystem — subflow.cc) |
| RuleSplitLoad | BLOCKED(SplitDatatype subsystem — subflow.cc) |
| RuleSplitStore | BLOCKED(SplitDatatype subsystem — subflow.cc; concatsplit fixture: mosura emits one 16-byte store where Ghidra splits) |
| RuleStringCopy | MISSING (constsequence) |
| RuleStringStore | MISSING (constsequence) |

**RuleSplitCopy/RuleSplitLoad/RuleSplitStore** are not standalone cleanup rules: each is a thin
dispatcher (`subflow.cc`, not `ruleaction.cc`) into the `SplitDatatype` class. The gate
`SplitDatatype::getValueDatatype` (subflow.cc:2910) needs `getTypeReadFacing`, `TypePointerRel`/
`isPointerRel`, `TypeFactory::getExactPiece` (which produces `TypePartialStruct`/`TYPE_PARTIALSTRUCT`)
and `getTypeArray`; the split itself uses the full 23-method `SplitDatatype`
(getComponent/categorizeDatatype/testDatatypeCompatibility/buildInSubpieces/buildOutConcats/
RootPointer::find…). mosura has none of `SplitDatatype`/`TypePartialStruct`/`getExactPiece`, so this
is composite-type (Task #1) machinery, not the mechanical rule tail — BLOCKED like the oppool2
LOAD/STORE spacebase set.

---

## 5. heritage.cc mechanisms

mosura `heritage.rs`. Core SSA construction (buildInfoList/collect/rename/placeMultiequals) is PORTED.
Guards/normalize/refine are the restructure remainder (Task #3).

| Ghidra mechanism | mosura |
|---|---|
| heritage / heritage_pass / rename / renameRecurse | PORTED (heritage.rs heritage/heritage_pass/rename) |
| buildInfoList / collect / calcMultiequals / placeMultiequals | PORTED (build_info_list, gather_candidates, reaching_phi_input). `collect`'s write-mask skip (heritage.cc:326) + prior-heritage marker detection (heritage.cc:327-338) PORTED — `gather_candidates`/`widening_ranges` skip `is_write_mask` varnodes; the narrower-marker detection feeds `remove_revisited_markers` (see below). |
| removeRevisitedMarkers | PORTED (`remove_revisited_markers`, Ghidra heritage.cc:244-297; `Varnode::writemask` flag `8f18c22`, `clear_addr_force`). On a WIDENING re-entry (shared `widening_ranges` gate, non-refine), a prior-pass MULTIEQUAL/INDIRECT marker or return-COPY narrower than the widened merged range is rewritten in place as `narrow = SUBPIECE(big,#off)` (`big` = fresh FREE whole-range read), narrow output write-masked (INDIRECT also clears addrForce; return-COPY → unlinked). The fresh whole reads flow through `gather_candidates`/cover/`rename` into the widened SSA → revisit's `r74:2 = SUB42(r74:4,#0)`. mosura-shape: bridges the narrow per-location SSA to the widened range's base. Runs BEFORE `normalize_ranges` each pass (Ghidra order: removeRevisitedMarkers precedes guard()). **Now ACTIVE under the landed S8-2 re-heritage restart** (fires on widening — revisit/longdouble; was dormant/byte-identical before the restart) — 3 synthetic unit tests (MULTIEQUAL/INDIRECT/return-COPY). `deadremoved` warning + `bumpDeadcodeDelay` (heritage.cc:248) omitted (unreachable: no dead removal in the brick). |
| guardCalls (+ call-effect INDIRECTs) | PORTED (guard_calls, guard_calls_models_call_effects; `7e06aa2`; ram-globals extension below). **Ram-global passthrough** (heritage.cc:1443/1467): Ghidra's `ProtoModel::lookupEffect` (fspec.cc:2472-2485) returns `unknown_effect` for any address not in the (register-only) EffectRecord list, so a ram global under the default proto takes the passthrough-INDIRECT branch. `guard_calls` now routes a ram range to `UNKNOWN_EFFECT` (beside the aliased-stack branch), and `holdind` generalized from `spc==stack` to the faithful `fl & addrtied` (`ram || aliased_stack`, per `mark_addrtied`) so the ram passthrough output is addrForced. Corpus 0.9168→**0.9156** (56/60): **noforloop_globcall 0.947→1.000 (+0.053)**, **revisit 0.633→0.691 (+0.058)** — the +100 threads across the call as `SUB42(post-call whole)` instead of the stale pre-call value, recovered WITHOUT the S8-2 restart. **Exposes stackreturn 0.926→0.739 (−0.187):** faithful INDIRECT (mosura `r140=INDIRECT s_f0` == Ghidra `r140(:5a)=u...b [] i(call)`); copy-prop folds the stored value into the INDIRECT before-value, orphaning the bare store COPY; Ghidra renders the addr-forced INDIRECT itself as `xRam..140 = ..`. **RESOLVED by Task #7 (the `mergeMarker` gate, merge row):** it was a `merge_markers` mis-port — the unconditional INDIRECT union fused the ram global with the stack slot `s_f0` (via `r140 = INDIRECT s_f0` after copy-prop), so the store COPY `r140 = COPY s_f0` looked same-high and was hidden. Gating the marker union on `merge_test_required` (as `mergeOp`/`mergeIndirect` do) un-hides the store COPY → stackreturn 0.739→0.926. |
| guardStores | PORTED (guard_stores; `aa5edef`) |
| guardReturns / guardReturnsOverlapping | PARTIAL — persist branch PORTED (`guard_returns`, heritage.cc:1676-1691: a `markReturnCopy` COPY before each RETURN for a persistent range, wired in `heritage_spaces` after guardCalls); persist by space (ram→persist, no scope). Active-output/return-value branch (heritage.cc:1658-1675: `characterizeAsOutput` return-width, `guardReturnsOverlapping`) → P6 prototypes, Task #4. **TRIPWIRE for Task #4 P6:** the faithful persist COPY holds a global to end-of-function even on a VOID fn — mosura's return-recovery then renders that held global as a return value where Ghidra's active-output trials detect void. This cost switchhide (0.940→0.918: stack-canary epilogue returned as `iVar2`) and noforloop_globcall (0.857→0.810: `return iVar1 = iRam601030`; its global-STORE handling is itself correct/banked). Same persist COPY BANKS partialmerge (+0.184) — inseparable. **RESOLVED by the Task #4 P6 `ancestorOpUse` USE gate (recover.rs `return_trial_kept`):** the held global / stack-canary leftover is realistic but used only elsewhere (not solely by the RETURN), so the USE gate voids it — switchhide 0.918→0.955, noforloop_globcall 0.810→0.889, both tripwires closed. |
| guardInput | PARTIAL — unification pending (Task #3) |
| guardLoads / generateLoadGuard / analyzeNewLoadGuards | BLOCKED(needs discoverIndexedStackPointers; Task #10) |
| discoverIndexedStackPointers | BLOCKED (Task #10) |
| guardOutputOverlap / guardOutputOverlapStack / tryOutputOverlapGuard | MISSING |
| normalizeReadSize | PORTED — two paths. (1) FAITHFUL per-range `normalize_ranges` (heritage.rs, Ghidra `guard()`:1172-1182 driven per merged range by `placeMultiequals`:2608-2629, keyed on the cumulative `globaldisjoint` merge via new `LocationMap::merged_range`); wired at top of `heritage_pass` every pass but **scoped WIDENING-re-entry-only** for S8-1 (a range grown vs a prior pass) → **now driven by the landed S8-2 re-heritage restart** (revisit's `SUB42`/`CONCAT22` re-versioning; was a dormant/byte-identical no-op before the restart). 4 synthetic unit tests. (2) `normalize_read_size` — the INTERIM pass-0 batch adaptation (single-write-width-keyed, read-only) that still does first-pass normalization. **Batch RETIREMENT (path 1 drives first-pass normalize too) is coupled to call-output-in-RAX (task #6)**: retiring it now regresses deindirect2 −0.116 by exposing that adaptation (mosura's CALLIND output lands in RAX, so a whole-range `guard()` normalize PIECEs a RAX+AX merge Ghidra never makes). The call-output MODELING half is now landed (faithful `buildOutputFromTrials` 2-trial `findPreexistingWhole` reassembly — ActionActiveReturn row): once the un-scoped normalize produces clean split pieces (AX:2 + upper6), the call output reassembles into a unique instead of merging. The remaining half (the un-scoped normalize producing *clean* pieces rather than mosura's current overlapping RAX:8+AX:2) lands with mainloop S8-2/batch-retirement. |
| normalizeWriteSize | PORTED (normalize_write_size) — the widened-write PIECE source; used by both `normalize_read_size`'s refine and the faithful `normalize_ranges` (Task #8/#12) |
| refineRead / refineWrite / refinement / buildRefinement / splitByRefinement | PARTIAL (refine_overlaps, split_by_refinement) — partition-broadening → Task #3/#15 |
| splitJoinRead / splitJoinWrite / processJoins / concatPieces / splitPieces | PARTIAL (heritage.rs join handling) |
| protectFreeStores / reprocessFreeStores | MISSING |
| handleNewLoadCopies / findAddressForces (LoadGuard addrforce) | MISSING |
| deadRemovalAllowed / getDeadCodeDelay / bumpDeadcodeDelay | PARTIAL (space.rs deadcodedelay; mosura runs heritage to completion) |

---

## 6. fspec / prototype + infertypes machinery

mosura `fspec.rs`, `recover.rs`, `infertypes.rs`, `types.rs`.

| Ghidra mechanism | mosura |
|---|---|
| ProtoModel (sysv x86-64) input/output placement | PORTED (fspec.rs sysv_input/sysv_output/sysv_effect_list) |
| EffectRecord (killedbycall/unaffected) | PORTED (fspec.rs lookup_effect) |
| ParamActive / ParamTrial multi-pass (solid/kill thresholds) | PARTIAL (recover.rs register_trial/mark_active/num_trials) — full state machine is Task #2 P6 |
| AncestorRealistic::execute / ancestorOpUse | PORTED (recover.rs `is_realistic` + `ancestor_op_use`/`only_op_use`) — the two return-trial gates. **checkConditionalExe** (the extra realism sub-gate, funcdata_varnode.cc:1997) still MISSING, but it is NOT the void-recovery lever (AncestorRealistic accepts condconst's RAX; the USE gate `ancestorOpUse` is what voids it). Input-side symmetric use (`checkInputTrialUse`) PORTED Task #4 Stage B (recover.rs `check_input_trial_use` + `realistic_faithful`): the same `ancestor_op_use` USE gate, paired with a traversal-aware realism that (unlike the return-register `is_realistic`) accepts an unwritten input reached *through* a copy chain — `AncestorRealistic::execute` rejects only the top-level-input trial (funcdata_varnode.cc:2211), while `enterNode` returns `pop_success` for a traversed-to input (2033). |
| ActionOutputPrototype / InputPrototype | PORTED (recover.rs recover_output/recover_input_params) |
| passthrough params + XMM/float args | MISSING (Task #2 P6) |
| TypeInference / propagation (ActionInferTypes) | PORTED (infertypes.rs). `get_local_type` honors the varnode's OWN type-lock (Ghidra `Varnode::getLocalType`: `if (isTypeLock()) return type;`) so the ActionSpacebase-locked RSP input seeds propagation as `Pointer(TypeSpacebase)` (the in-pipeline `infer_types` passes an empty external-lock map). The TYPE_SPACEBASE `getSubType` descent (Ghidra `TypePointer::downChain`→`TypeSpacebase::getSubType`+`getTypePointerStripArray`) is resolved in the `propagate_add_in2out` down_chain loop from `varmap::recover_scope` (the `Datatype::get_subtype` spacebase arm returns the `undefined1` stub — no `glb` back-pointer), so a `PTRSUB(RSP, off)` output types as a pointer to the mapped ScopeLocal symbol's element. This drives the two-pass array PTRADD (task #22-A-2b) and root-fixes the #22-A-2 loop-ptr `Unknown(1)` pointee poison. `propagateSpacebaseRef`/`propagateRef` (the memory-alias direction) still deferred. |
| composite types (struct/array/pointer inference) | PORTED (Task #1, infertypes/types.rs) |
| constant typing in infertypes | PARTIAL (Task #10) |

---

## 7. jumptable models (jumptable.cc / jumptable.hh)

mosura `jumptable.rs` (`JumpTable`, `recover`, `recover_staged`).

| Ghidra model | mosura |
|---|---|
| JumpBasic (the common LOAD-table model) | PORTED (jumpbasic.rs `recover_jumpbasic` — the driver `jumptable::recover` calls; Stage 4 swap landed, old `recover_one` retired) |
| CircleRange pull-back (rangeutil.cc) | PORTED (circlerange.rs — faithful port of the pull-back half: ctors/intersect/circleUnion/minimalContainer/setNZMask/setStride/pullBackUnary+Binary and the `pullBack` op-driver, validated against Ghidra's own `testcirclerange.cc` element-set oracle (intersect/union/pullback vectors) + the `(index-1)<8`→[1,9) key case; plus `translate2Op` (rangeutil.cc:1093 — the reverse direction, a range back to one comparison op; added for RuleRangeMeld, Task #11, 2 unit tests). pushForward/ValueSet half deliberately not ported. Wired via `recover_jumpbasic` (Task #8) + RuleRangeMeld (Task #11)) |
| PathMeld + findDeterminingVarnodes (jumptable.cc) | PORTED (jumpbasic.rs — faithful port of `PathMeld` (internalIntersect/meldOps/meld/markPaths/truncatePaths/append/getEarliestOp), `findDeterminingVarnodes`, and the `isprune`/`ispoint`/`getStride`/`getMaxValue` statics. meldOps' `getSeqNum().getOrder()` maps to within-block op index (`op_order`); the op MARK flag was added to op.rs. Unit-tested incl. a split-rejoin diamond exercising meld. Wired via `recover_jumpbasic`, Task #8) |
| GuardRecord + analyzeGuards (jumptable.cc) | PORTED (jumpbasic.rs — faithful port of `GuardRecord` (+valueMatch/oneOffMatch/quasiCopy statics) and `analyzeGuards`: the maxpullback CircleRange::pull_back chain that turns `INT_LESS(INT_ADD(index,-1),8)` into a `[1,9)` bound on `index`, one GuardRecord per pull-back step. Block-walk adapted to mosura's canonical CFG (getInRevIndex via out_edges.position; no isBooleanFlip/getFlipPath ⇒ toswitchval=(indpath==1), indpathstore=indpath); checkUnrolledGuard (sizeIn>1 unrolled) deferred+cited. Unit-tested (ADD-form guard). Wired via `recover_jumpbasic`, Task #8) |
| recoverModel/calcRange/findSmallestNormal/buildAddresses (jumptable.cc) | PORTED (jumpbasic.rs `recover_jumpbasic` — the JumpBasic driver `jumptable::recover` calls (Stage 4 swap landed; `recover_one` retired). calcRange (initial nzmask/maxvalue/stride/bool range + guard-range intersect + positive-only), findSmallestNormal (smallest-range common varnode = normalized switch var), buildAddresses (CircleRange value iteration → reuses `jumptable::emulate`/`in_image`/`find_default`/`backtrace_set`). Corpus byte-identical to `recover_one` across 62 x86:LE:64 fixtures. Task #8) |
| FlowInfo::recoverJumpTables → newAddress edge-feedback (flow.cc:806) | PORTED (build.rs multistage: each recovery partial's `switch_targets` is seeded from prior passes' recovered tables so discovered case blocks become reachable and the loop-header switch phi widens pass-over-pass — required for switch-variable-is-loop-variable forms, e.g. switchloop. Targets only; the guard fold (foldInOneGuard) stays post-recovery, Task #8) |
| Table lifecycle: freeze + multistage retry (`Funcdata::recoverJumpTable` funcdata_block.cc:639-673; `matchModel`/`checkForMultistage`/`recoverMultistage` jumptable.cc:2699/2847/2653; `analyzeGuards` `usenzmask = !isPartial()` jumptable.cc:1052) | PORTED (jumptable.rs `recover_staged`, driven per pass by build.rs's multistage loop over the persistent `jumpvec` (the Ghidra `jumpvec` analogue surviving each flow pass; Ghidra's Override-survives-restart channel, funcdata.cc:106, collapses into it since the loop replaces the whole-decompile restart): a complete (>1-entry) table is FROZEN — never re-recovered, so later-pass simplification changes cannot shrink it; a 1-entry table is matchModel-rechecked on the richer graph (nzmask on, matchsize=1) and on mismatch re-recovered with the nzmask OFF, so the *guard comparison* — not the realized value set of the partially-wired flow — bounds the switch (switchloop's 1→9 stage); a failed retry keeps the old table (recoverMultistage restore-on-failure). `usenzmask`/`matchsize` threaded through `recover_jumpbasic`→`analyze_guards`/`find_smallest_normal` (jumptable.cc:1052/1178). Retires the last-pass-wins cache; makes recovery robust to index-reshaping rules — unblocks the #21(a) RuleSubExtComm straddle split (switchloop stays 9 under it). Corpus + all switch-fixture C byte-identical, suite 414/0. Task #31) |
| JumpBasicOverride | MISSING |
| JumpModelTrivial | MISSING |
| JumpAssisted / JumpAssistOp | MISSING |
| JumpValuesRange / JumpValuesRangeDefault | PARTIAL |
| findUnnormalized / buildLabels / backup2Switch / flowsOnlyToModel / markModel (jumptable.cc:1462/1506/472/1274/1254) | PORTED (jumpbasic.rs — `find_unnormalized` peels the normalized variable back through maxaddsub=1 INT_ADD/INT_SUB-by-const + maxext=1 ZEXT/SEXT (defaults jumptable.cc:2390-2392) to the *unnormalized* switch variable, each step guarded by `flows_only_to_model` over `mark_model`-marked model ops; `backup2switch` reverse-emulates each normalized-range value to it (OpBehavior::recoverInput*, opbehavior.cc:257/273/297/311) giving the real case labels (switchloop 0..8 → 1..9). Runs at recovery time where the bounded range is known; the labels + switchvn storage are saved on the JumpTable — mosura's stand-in for Ghidra's saved `origmodel` (the final graph loses the range, which only the recovery partial's edge-feedback phi widening bounds). Ghidra's readonly-memory binary companion in backup2Switch (jumptable.cc:488) is unreachable after the const-peel and declined; an incomplete label set drops labels whole (Ghidra pushes NO_LABEL + warns) and normalization declines. Unit-tested: identity labels + the `index-1` peel/shift/fold case) |
| ActionSwitchNorm: matchModel + recoverLabels + foldInNormalization (coreaction.cc:4548, jumptable.cc:2683/2714/1546) | PORTED (jumpbasic.rs `switch_norm` + pipeline.rs `ActionSwitchNorm`, wired after the reheritage mainloop before cleanup (Ghidra actfullloop :5684, before ActionStartCleanUp :5692), final graph only — never inside the multistage recovery partial (`table_recovery_probe`), where folding the BRANCHIND would destroy the address path table discovery re-emulates. matchModel re-finds the switch variable on the final graph as the `find_determining_varnodes` common varnode at the saved storage; recoverLabels' labels come from the saved recovery-time model (above); foldInNormalization = `op_set_input(indop, switchvn, 0)` + a deadcode sweep (Ghidra: the repeating fullloop's ActionDeadCode member). RETIRES the print-time switch heuristics for normalized tables — printc `switch_index` reads the folded BRANCHIND input (Ghidra `BlockSwitch` `getSwitchVarnode()`) and `case_labels` the recovered labels, keeping the trace/position fallback only for unnormalized tables. ifswitch 0.985→1.000 (real case values 19/20 not positions), switchloop 0.820→0.828 (`switch(iVar1)` cases 1..9 = Ghidra's exact shape), zero regressions) |
| RuleSwitchSingle | MISSING |
| getSwitchVarConsume (deadcode integration) | MISSING (mosura fully-consumes switch var — consume.rs note) |

---

## 8. printc emitters (printc.cc — 26 `PrintC::opXxx`)

mosura `printc.rs`. The common emitters are covered; the gaps are P8 (Task #6).

| Ghidra emitter | mosura |
|---|---|
| opCopy / opLoad / opStore / opBranch / opCbranch / opReturn | PORTED (printc.rs) |
| opCall / opCallind / opCallother | PORTED |
| opFunc / opTypeCast / opHiddenFunc | PORTED (opTypeCast = cast.rs) |
| opIntZext / opIntSext / opBoolNegate / opSubpiece | PORTED (opSubpiece is faithful to Ghidra printc.cc:843 — `is_subpiece_cast` port of `CastStrategyC::isSubpieceCast` (cast.cc: offset0 + scalar in/out metatypes → C truncation cast) + the `opFunc` non-cast branch `SUB<insize><outsize>(x,off)`. Replaced the non-faithful `effective_width`/nzmask gate (Task #12), which suppressed the cast whenever the value's used width already fit the slice — packstructaccess now `(int4)(int2)(uVar1>>0x30)`, impliedfield `(float4)(param_1>>0x20)`, matching Ghidra. Corpus 0.9196→0.9209 (+0.0013): packstructaccess +.045, impliedfield +.017, floatconv +.057. Dips are the faithful cast EXPOSING upstream type gaps the adaptation was masking (faithful-exposes-gap): (xunknownN) on wide/multi-precision CONCAT truncations where mosura infers Unknown vs Ghidra float8 = **Task #13** (floatcast −.028, revisit −.012, switchloop); extra/narrower SUBPIECE type-width divergence = **Task #14** (loopcomment −.003, switchloop −.001). The struct-field `doesSpecialPrinting` path (`tVar1.b`) stays deferred — the oracle gauge doesn't apply composite types.) |
| opFloatInt / float+NAN emission | PORTED (Task #11; float.rs) |
| emitBlockIf `else if` merge (pending_brace) | PORTED WIRED (`emit_if`, printc.rs — Task #19) | Faithful port of `PrintC::emitBlockIf`'s pending-brace handling (printc.cc:2882-2943): an `if`/`else` whose else-arm is itself an `if` (`FlowBlock::t_if`) glues onto the `else` on one line (`else if (…)`) unless the nested condition block emits a leading statement (then the brace fires → `else { … }`, e.g. elseif's `else { if (param_1==0x25){…} func(0x100a42); }` where the else-arm is a List). Produces Ghidra's EXACT `else if` C instead of mosura's nested `else { if … }`. **GAUGE-INERT / BYTE-IDENTICAL corpus (0.9222/56):** ccompare (ccompare.rs:53) drops `(){};,` as noise so both render to the same token skeleton (1.0000 either way) — this is a faithfulness/readability win owed by port-all-faithful-rules, not a corpus mover. The for/while/do-while loop-recovery emitters + short-circuit split (the actual loopcomment/elseif residual) are the deferred CollapseStructure/TraceDAG/LoopBody subsystem (Task #25). |
| opBranchind (switch) | PARTIAL |
| opPtradd / opPtrsub | PORTED (ptrarith) |
| opConstructor / opNewOp / opInsertOp / opExtractOp | MISSING (C++/high-level constructs) |
| opSegmentOp / opCpoolRefOp | MISSING |
| branchless boolean flags / global naming / gotos | MISSING (Task #6 P8) |

---

## Summary (rule pools — the exact core)

- **oppool1**: ~84 PORTED (incl. the now-de-fused div/sign cluster — RuleDivOpt (faithful), RuleDivTermAdd,
  RuleSignShift, RuleTestSign, RuleSignForm, RuleSignForm2, RuleSignDiv2, RuleDivChain, RuleSignNearMult,
  RuleModOpt, RuleSignMod2nOpt, RuleSignMod2nOpt2, RuleSignMod2Opt, RuleLessNotEqual — Task #20; plus
  RuleFloatCast, RuleShiftAnd, RuleConcat*, RuleDouble*, RuleTrivialBool, RuleLess2Zero, RuleOrConsume,
  RuleEqual2Constant, RuleBoolZext), 3 HELD (NotDistribute, AndDistribute, AndCompare), 1 BLOCKED
  (SubvarSext / RulePtrFlow=isPtrFlow; SubZext + Piece2Zext now WIRED), 1 DEFERRED (RuleLeftRight — register-piece dep, Task #7),
  ~61 MISSING, 0 non-faithful (the fused DivOpt is retired), + 3 mosura-only extras.
  The MISSING set is the mechanical rule tail (Phase 1b, in progress).
- **oppool2**: 1 PORTED (PtrArith), 3 PARTIAL (LoadVarnode/StoreVarnode ram-global branch ported task #7 S1;
  stack/spacebase-reg branch = S2), 1 MISSING (PushPtr).
- **cleanup**: 3 PORTED (the Sub2Add reconstruction subset), 3 BLOCKED (RuleSplitCopy/Load/Store —
  SplitDatatype/TypePartialStruct dep), 9 MISSING (DumptyHumpLate etc.).

**Highest-value MISSING (already surfaced by trace-diff / fixtures):** RuleConcatZext/RuleConcatZero
family. (RuleEarlyRemoval — 78× —, RuleScarry, RuleFloatCast, and RuleShiftAnd now PORTED byte-neutral;
RuleLoadVarnode/StoreVarnode ram-global branch PORTED (task #7 S1, +.0028); their stack branch + the
RuleSplit* family remain on the spacebase-S2 / SplitDatatype subsystems respectively.)

**Sub-case gaps within PORTED functions** (the class this matrix is meant to catch — e.g. the
extended-precision consume branches found in Task #8): audit each PORTED rule/action for omitted
`size > sizeof(uintb)`, `isPersist`, `isPtrFlow`, and aggressive-mode branches. Consume transfers
(`consume.rs`) are now complete for SUBPIECE/PIECE extended precision (`68a059e`); other transfers
and nzmask/refinement should get the same pass.
