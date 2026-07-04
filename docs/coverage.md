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
| ActionVarnodeProps | PORTED (scope.rs) | query_properties (mapped/addrtied/persist) |
| ActionHeritage | PORTED (heritage.rs) | see §5 |
| ActionParamDouble | MISSING | double-precision parameter join |
| ActionSegmentize | N/A | segmented arch only |
| ActionInternalStorage | MISSING | internal-storage annotation |
| ActionForceGoto | MISSING | forced goto (blockrecovery) |
| ActionDirectWrite ×2 | PARTIAL (heritage.rs) | mosura has limited addrforce; no directwrite pass |
| ActionActiveParam | PARTIAL (recover.rs) | register_trial/mark_active; not full ParamActive multi-pass (Task #2/P6) |
| ActionReturnRecovery | PORTED (recover.rs) | recover_return / resolve_return |
| ActionRestrictLocal | MISSING | restrict local before deadcode |
| ActionDeadCode | PORTED (deadcode.rs + consume.rs) | whole-varnode removal + neverConsumed const-0 fold `68a059e` |
| ActionDynamicMapping | MISSING | dynamic (hash-based) symbol mapping |
| ActionRestructureVarnode | PORTED (varmap.rs) | recover_scope |
| ActionSpacebase | PARTIAL (stackvars.rs) | stack-pointer flow |
| ActionNonzeroMask | PORTED (nzmask.rs) | calc_nzmask |
| ActionInferTypes | PORTED (infertypes.rs) | see §6 |
| ActionLaneDivide | MISSING | SIMD lane splitting |
| ActionMultiCse | MISSING | cross-block CSE (mosura has in-block cse_find_in_block only) |
| ActionShadowVar | MISSING | shadow-varnode detection |
| ActionDeindirect | PARTIAL (recover.rs) | resolve_call_output; deindirect fixture works |
| ActionStackPtrFlow | PARTIAL (stackvars.rs) | |
| ActionRedundBranch | MISSING | redundant-branch removal |
| ActionBlockStructure | PORTED (structure.rs) | |
| ActionConstantPtr | PARTIAL (infertypes.rs) | constant-pointer typing |
| ActionDeterminedBranch | PORTED (determinedbranch.rs) | |
| ActionNodeJoin | MISSING | MULTIEQUAL node-join (RulePushMulti pair) |
| ActionConditionalExe | MISSING | conditional-execution recovery |
| ActionConditionalConst | MISSING | conditional constant propagation |

### fullloop tail
| Ghidra action | mosura | notes |
|---|---|---|
| ActionLikelyTrash | MISSING | likely-trash register elimination |
| ActionDoNothing | N/A | |
| ActionSwitchNorm | PARTIAL (jumptable.rs) | see §7 |
| ActionReturnSplit | MISSING | return-block split |
| ActionUnjustifiedParams | MISSING | |
| ActionStartTypes | PORTED (infertypes.rs) | type-recovery gate |
| ActionActiveReturn | PORTED (recover.rs) | wired in pipeline |

### merge / output / finalize tail
| Ghidra action | mosura | notes |
|---|---|---|
| ActionMappedLocalSync | MISSING | |
| ActionPreferComplement | MISSING | branch-complement (P7) |
| ActionStructureTransform | PARTIAL (structure.rs) | |
| ActionNormalizeBranches | MISSING | (P7) |
| ActionAssignHigh / MergeRequired / MarkExplicit / MarkImplied / MergeMultiEntry / MergeCopy / DominantCopy / MarkIndirectOnly / MergeAdjacent / MergeType / HideShadow / CopyMarker | PARTIAL (merge.rs) | merge.rs is minimal (high/same/count/merge); most Merge* actions not individually ported (Task #4 P5) |
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
| RuleSelectCse | PORTED (+ isCseMatch output-size guard `8dd6d80`) |
| RuleCollectTerms | PORTED |
| RulePullsubMulti | MISSING |
| RulePullsubIndirect | MISSING |
| RulePushMulti | MISSING (nodejoin) |
| RuleSborrow | PORTED |
| RuleScarry | MISSING |
| RuleIntLessEqual | MISSING |
| RuleTrivialArith | PORTED |
| RuleTrivialBool | MISSING |
| RuleTrivialShift | PORTED |
| RuleSignShift | MISSING |
| RuleTestSign | MISSING |
| RuleIdentityEl | PORTED |
| RuleOrMask | PORTED |
| RuleAndMask | PORTED |
| RuleOrConsume | MISSING |
| RuleOrCollapse | PORTED |
| RuleAndOrLump | MISSING |
| RuleShiftBitops | PORTED |
| RuleRightShiftAnd | MISSING |
| RuleNotDistribute | HELD(defined, unwired — no verified firing site / kept out) |
| RuleHighOrderAnd | PORTED |
| RuleAndDistribute | HELD(RuleHumptyOr ping-pong hang) |
| RuleAndCommute | PORTED (+ wrapping_shr x86 shift guard `68a059e`) |
| RuleAndPiece | PORTED |
| RuleAndZext | PORTED |
| RuleAndCompare | HELD(defined, unwired) |
| RuleDoubleSub | MISSING |
| RuleDoubleShift | MISSING |
| RuleDoubleArithShift | MISSING |
| RuleConcatShift | MISSING |
| RuleLeftRight | MISSING |
| RuleShiftCompare | PORTED |
| RuleShift2Mult | PORTED |
| RuleShiftPiece | PORTED |
| RuleMultiCollapse | PORTED (+ nofunc const-base guard `68a059e`) |
| RuleIndirectCollapse | MISSING |
| Rule2Comp2Mult | MISSING |
| RuleSub2Add | PORTED (ptrarith_pool, not main — deliberate: switch/jumptable cascade, Task #9) |
| RuleCarryElim | MISSING |
| RuleBxor2NotEqual | MISSING |
| RuleLess2Zero | MISSING |
| RuleLessEqual2Zero | PORTED |
| RuleSLess2Zero | MISSING |
| RuleEqual2Zero | PORTED |
| RuleEqual2Constant | MISSING |
| RuleThreeWayCompare | MISSING |
| RuleXorCollapse | PORTED |
| RuleAddMultCollapse | PORTED (ptrarith_pool) |
| RuleCollapseConstants | PORTED (= RuleConstFold) |
| RuleTransformCpool | MISSING (constant pool) |
| RulePropagateCopy | PORTED (+ isReturnCopy RETURN guard `5a8ac03`) |
| RuleZextEliminate | PORTED |
| RuleSlessToLess | PORTED |
| RuleZextSless | MISSING |
| RuleBitUndistribute | MISSING |
| RuleBooleanUndistribute | MISSING |
| RuleBooleanDedup | MISSING |
| RuleBoolZext | MISSING |
| RuleBooleanNegate | PORTED |
| RuleLogic2Bool | PORTED |
| RuleSubExtComm | PORTED |
| RuleSubCommute | MISSING |
| RuleConcatCommute | MISSING |
| RuleConcatZext | MISSING |
| RuleZextCommute | MISSING |
| RuleZextShiftZext | PORTED |
| RuleShiftAnd | MISSING |
| RuleConcatZero | MISSING |
| RuleConcatLeftShift | MISSING |
| RuleSubZext | HELD(preempts RuleSubvarZext return-narrowing on the truncation-return family; Task #8) |
| RuleSubCancel | MISSING |
| RuleShiftSub | MISSING |
| RuleHumptyDumpty | PORTED |
| RuleDumptyHump | PORTED |
| RuleHumptyOr | PORTED |
| RuleNegateIdentity | MISSING |
| RuleSubNormal | MISSING |
| RulePositiveDiv | PORTED |
| RuleDivTermAdd | HELD(regresses modulo — fused RuleDivOpt races it; Task #9) |
| RuleDivTermAdd2 | PORTED |
| RuleDivOpt | PORTED (NON-FAITHFUL: fused recognizer; de-fusion is Task #9/#20) |
| RuleSignForm | MISSING |
| RuleSignForm2 | MISSING |
| RuleSignDiv2 | MISSING |
| RuleDivChain | MISSING |
| RuleSignNearMult | MISSING |
| RuleModOpt | PORTED |
| RuleSignMod2nOpt | PORTED |
| RuleSignMod2nOpt2 | PORTED |
| RuleSignMod2Opt | MISSING |
| RuleSwitchSingle | MISSING |
| RuleCondNegate | MISSING |
| RuleBoolNegate | PORTED |
| RuleLessEqual | PORTED |
| RuleLessNotEqual | MISSING |
| RuleLessOne | MISSING |
| RuleRangeMeld | MISSING |
| RuleFloatRange | PORTED |
| RulePiece2Zext | HELD(rides with SubZext un-hold; Task #8) |
| RulePiece2Sext | MISSING |
| RulePopcountBoolXor | PORTED |
| RuleXorSwap | MISSING |
| RuleLzcountShiftBool | MISSING |
| RuleFloatSign | MISSING |
| RuleOrCompare | PORTED |
| RuleSubvarAnd | PORTED |
| RuleSubvarSubpiece | PORTED |
| RuleSplitFlow | MISSING (subvar SplitFlow) |
| RulePtrFlow | MISSING (needs Varnode::isPtrFlow — aggressive subvar) |
| RuleSubvarCompZero | PORTED |
| RuleSubvarShift | PORTED |
| RuleSubvarZext | PORTED (`381e745`; delivers int4 returns) |
| RuleSubvarSext | BLOCKED(sext tracer stubbed in subvarflow.rs; Stage 4) |
| RuleNegateNegate | MISSING |
| RuleConditionalMove | MISSING |
| RuleOrPredicate | MISSING |
| RuleFuncPtrEncoding | MISSING |
| RuleSubfloatConvert | MISSING |
| RuleFloatCast | MISSING (floatcast fixture imperfect) |
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

---

## 3. oppool2 rules (coreaction.cc:5664-5669)

| Ghidra rule | mosura |
|---|---|
| RulePushPtr | MISSING |
| RuleStructOffset0 | PARTIAL (ptrarith.rs / infertypes struct-offset-0) |
| RulePtrArith | PORTED (ptrarith.rs, ptrarith_pool) |
| RuleLoadVarnode | MISSING (stack LOAD→varnode; trace shows 3× on namespace) |
| RuleStoreVarnode | MISSING (stack STORE→varnode; 2× on namespace) |

---

## 4. cleanup rules (coreaction.cc:5696-5710)

| Ghidra rule | mosura |
|---|---|
| RuleMultNegOne | PORTED (cleanup_pool) |
| RuleAddUnsigned | PORTED (cleanup_pool) |
| Rule2Comp2Sub | PORTED (cleanup_pool) |
| RuleDumptyHumpLate | MISSING |
| RuleSubRight | MISSING |
| RuleFloatSignCleanup | MISSING |
| RuleExpandLoad | MISSING |
| RulePtrsubCharConstant | MISSING |
| RuleExtensionPush | MISSING |
| RulePieceStructure | MISSING |
| RuleSplitCopy | MISSING |
| RuleSplitLoad | MISSING |
| RuleSplitStore | MISSING (concatsplit fixture: mosura emits one 16-byte store where Ghidra splits) |
| RuleStringCopy | MISSING (constsequence) |
| RuleStringStore | MISSING (constsequence) |

---

## 5. heritage.cc mechanisms

mosura `heritage.rs`. Core SSA construction (buildInfoList/collect/rename/placeMultiequals) is PORTED.
Guards/normalize/refine are the restructure remainder (Task #3).

| Ghidra mechanism | mosura |
|---|---|
| heritage / heritage_pass / rename / renameRecurse | PORTED (heritage.rs heritage/heritage_pass/rename) |
| buildInfoList / collect / calcMultiequals / placeMultiequals | PORTED (build_info_list, gather_candidates, reaching_phi_input) |
| guardCalls (+ call-effect INDIRECTs) | PORTED (guard_calls, guard_calls_models_call_effects; `7e06aa2`) |
| guardStores | PORTED (guard_stores; `aa5edef`) |
| guardReturns / guardReturnsOverlapping | BLOCKED(→P6 prototypes, Task #3) |
| guardInput | PARTIAL — unification pending (Task #3) |
| guardLoads / generateLoadGuard / analyzeNewLoadGuards | BLOCKED(needs discoverIndexedStackPointers; Task #10) |
| discoverIndexedStackPointers | BLOCKED (Task #10) |
| guardOutputOverlap / guardOutputOverlapStack / tryOutputOverlapGuard | MISSING |
| normalizeReadSize | PORTED (normalize_read_size) — documented x86-64 adaptation |
| normalizeWriteSize | PORTED (normalize_write_size) — the widened-write PIECE source (Task #8/#12) |
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
| AncestorRealistic (checkConditionalExe) | MISSING (Task #2 P6) |
| ActionOutputPrototype / InputPrototype | PORTED (recover.rs recover_output/recover_input_params) |
| passthrough params + XMM/float args | MISSING (Task #2 P6) |
| TypeInference / propagation (ActionInferTypes) | PORTED (infertypes.rs) |
| composite types (struct/array/pointer inference) | PORTED (Task #1, infertypes/types.rs) |
| constant typing in infertypes | PARTIAL (Task #10) |

---

## 7. jumptable models (jumptable.cc / jumptable.hh)

mosura `jumptable.rs` (`JumpTable`, `recover`).

| Ghidra model | mosura |
|---|---|
| JumpBasic (the common LOAD-table model) | PARTIAL (jumptable.rs recover) |
| JumpBasicOverride | MISSING |
| JumpModelTrivial | MISSING |
| JumpAssisted / JumpAssistOp | MISSING |
| JumpValuesRange / JumpValuesRangeDefault | PARTIAL |
| ActionSwitchNorm / RuleSwitchSingle normalization | MISSING (Task #9 cascade) |
| getSwitchVarConsume (deadcode integration) | MISSING (mosura fully-consumes switch var — consume.rs note) |

---

## 8. printc emitters (printc.cc — 26 `PrintC::opXxx`)

mosura `printc.rs`. The common emitters are covered; the gaps are P8 (Task #6).

| Ghidra emitter | mosura |
|---|---|
| opCopy / opLoad / opStore / opBranch / opCbranch / opReturn | PORTED (printc.rs) |
| opCall / opCallind / opCallother | PORTED |
| opFunc / opTypeCast / opHiddenFunc | PORTED (opTypeCast = cast.rs) |
| opIntZext / opIntSext / opBoolNegate / opSubpiece | PORTED |
| opFloatInt / float+NAN emission | PORTED (Task #11; float.rs) |
| opBranchind (switch) | PARTIAL |
| opPtradd / opPtrsub | PORTED (ptrarith) |
| opConstructor / opNewOp / opInsertOp / opExtractOp | MISSING (C++/high-level constructs) |
| opSegmentOp / opCpoolRefOp | MISSING |
| branchless boolean flags / global naming / gotos | MISSING (Task #6 P8) |

---

## Summary (rule pools — the exact core)

- **oppool1**: ~54 PORTED (incl. RuleEarlyRemoval), 6 HELD (NotDistribute, AndDistribute, AndCompare,
  SubZext, Piece2Zext, DivTermAdd), 2 BLOCKED (SubvarSext, and RulePtrFlow needs isPtrFlow), ~67
  MISSING, 1 non-faithful (DivOpt fused), + 3 mosura-only extras. The MISSING set is the mechanical
  rule tail (Phase 1b, in progress).
- **oppool2**: 1 PORTED (PtrArith), 1 PARTIAL, 3 MISSING (PushPtr, LoadVarnode, StoreVarnode).
- **cleanup**: 3 PORTED (the Sub2Add reconstruction subset), 12 MISSING (SplitStore etc.).

**Highest-value MISSING (already surfaced by trace-diff / fixtures):** RuleLoadVarnode/RuleStoreVarnode,
RuleSplitStore (concatsplit), RuleFloatCast (floatcast), RuleScarry, RuleConcatZext/RuleShiftAnd
family. (RuleEarlyRemoval — 78× on namespace — now PORTED, byte-neutral.)

**Sub-case gaps within PORTED functions** (the class this matrix is meant to catch — e.g. the
extended-precision consume branches found in Task #8): audit each PORTED rule/action for omitted
`size > sizeof(uintb)`, `isPersist`, `isPtrFlow`, and aggressive-mode branches. Consume transfers
(`consume.rs`) are now complete for SUBPIECE/PIECE extended precision (`68a059e`); other transfers
and nzmask/refinement should get the same pass.
