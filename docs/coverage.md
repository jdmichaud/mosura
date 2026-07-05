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
| RuleScarry | PORTED (rules.rs; byte-neutral, unit-tested — ADD sibling of RuleSborrow via add_matches) |
| RuleIntLessEqual | MISSING |
| RuleTrivialArith | PORTED |
| RuleTrivialBool | PORTED (rules.rs; unit-tested — fold BOOL_AND/OR/XOR with a constant operand; fires 83× on corpus but rendered C is byte-IDENTICAL, effect absorbed downstream) |
| RuleTrivialShift | PORTED |
| RuleSignShift | MISSING |
| RuleTestSign | MISSING |
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
| RuleLeftRight | MISSING |
| RuleShiftCompare | PORTED |
| RuleShift2Mult | PORTED |
| RuleShiftPiece | PORTED |
| RuleMultiCollapse | PORTED (+ nofunc const-base guard `68a059e`) |
| RuleIndirectCollapse | MISSING |
| Rule2Comp2Mult | PORTED (rules.rs; byte-neutral, unit-tested — `-V => V * -1` canonicalization in the main pool so mult/term rules act on it uniformly; cleanup-pool `RuleMultNegOne` restores `-V` (separate pools, no ping-pong); 0 firings on corpus — no surviving INT_2COMP reaches actprop — byte-IDENTICAL. Added `op_insert_input` helper) |
| RuleSub2Add | PORTED (ptrarith_pool, not main — deliberate: switch/jumptable cascade, Task #9) |
| RuleCarryElim | PORTED (rules.rs; byte-neutral, unit-tested — `carry(V, c) => (-c) <= V`, special case `carry(V, 0) => false`; fires 19x on corpus but rendered C byte-IDENTICAL, absorbed downstream) |
| RuleBxor2NotEqual | PORTED (rules.rs; byte-neutral, unit-tested — `V ^^ W => V != W` (BOOL_XOR is boolean inequality); inert on corpus) |
| RuleLess2Zero | PORTED (rules.rs; unit-tested — INT_LESS vs extremal 0/max constants; fires 9× on corpus but rendered C byte-IDENTICAL, absorbed downstream) |
| RuleLessEqual2Zero | PORTED |
| RuleSLess2Zero | PORTED (rules.rs; byte-neutral, 7 unit tests — INT_SLESS vs 0/-1, peel a sign-only op: SUBPIECE-of-top-piece / `~V` / `V & 0x8..` / `CONCAT(V,W)` / `getHiBit(add\|or\|xor)`=>EQUAL/NOTEQUAL / `bool << (8*sz-1)`=>`!bool`; 0 firings on corpus, byte-IDENTICAL — the sign-only-op-against-0/-1 idiom doesn't survive to actprop in the fixtures) |
| RuleEqual2Zero | PORTED |
| RuleEqual2Constant | PORTED (rules.rs; byte-neutral, unit-tested — fold const through arith operand of INT_EQUAL/NOTEQUAL when V only used in similar compares; inert on corpus) |
| RuleThreeWayCompare | PORTED (rules.rs; byte-neutral, 3 unit tests — detect a three-way `zext(V<W)+zext(V<=W)-1` (3 add/const permutations + partial form, via detectThreeWay/testCompareEquivalence helpers) and fold a secondary compare of it vs a small constant back to a direct `V`/`W` compare (24-case form table); 0 firings on corpus — the C++ spaceship idiom doesn't occur in the fixtures) |
| RuleXorCollapse | PORTED |
| RuleAddMultCollapse | PORTED (ptrarith_pool) |
| RuleCollapseConstants | PORTED (= RuleConstFold) |
| RuleTransformCpool | MISSING (constant pool) |
| RulePropagateCopy | PORTED (+ isReturnCopy RETURN guard `5a8ac03`) |
| RuleZextEliminate | PORTED |
| RuleSlessToLess | PORTED |
| RuleZextSless | PORTED (rules.rs; byte-neutral, unit-tested — `zext(V) s< c => V < c` (+ SLESSEQUAL / reversed-operand), when c's narrow sign bit is clear so the zext is unnecessary; inert on corpus: no surviving signed-compare-of-zext-vs-const idiom in the fixtures) |
| RuleBitUndistribute | MISSING |
| RuleBooleanUndistribute | MISSING |
| RuleBooleanDedup | MISSING |
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
| RuleSubZext | HELD(preempts RuleSubvarZext return-narrowing on the truncation-return family; Task #8) |
| RuleSubCancel | PORTED (rules.rs; byte-neutral, unit-tested — SUBPIECE cancels a ZEXT/SEXT/AND: `sub(zext(V),0)`=>V/sub(V)/narrower zext, `sub(V&fullmask,0)`=>sub(V), `sub(zext(V),c>=farin)`=>0; fires 5x but rendered C byte-IDENTICAL, absorbed downstream. mosura's is_free treats constants as non-free, so the big-constant offset-0 sub-case is structurally preserved but unreachable) |
| RuleShiftSub | PORTED (rules.rs; byte-neutral, unit-tested — `sub(V << 8k, c) => sub(V, c-k)` for a byte-granular left shift when the window stays within V; inert on corpus) |
| RuleHumptyDumpty | PORTED |
| RuleDumptyHump | PORTED |
| RuleHumptyOr | PORTED |
| RuleNegateIdentity | PORTED (rules.rs; byte-neutral, 3 unit tests — INT_NEGATE identities against a logical op reading both `~V` and `V`: `V & ~V => 0`, `V | ~V => -1`, `V ^ ~V => -1` (collapse the AND/OR/XOR to a COPY of the constant); 0 firings on corpus — the idiom doesn't survive to actprop in the fixtures) |
| RuleSubNormal | MISSING |
| RulePositiveDiv | PORTED |
| RuleDivTermAdd | HELD(regresses modulo — fused RuleDivOpt races it; Task #9) |
| RuleDivTermAdd2 | PORTED |
| RuleDivOpt | PORTED (NON-FAITHFUL: fused recognizer; de-fusion is Task #9/#20) |
| RuleSignForm | HELD(defined+unit-tested in rules.rs, UNWIRED — faithful, but mosura's FUSED RuleDivOpt fails to re-collapse the s>> form it normalizes to, regressing switchloop 0.7787->0.7709 `(int8)iVar5`->`iVar5>>0x1f` vs Ghidra's `(int4)param_1/10`; same class as RuleDivTermAdd; wire after RuleDivOpt de-fusion Task #9/#20. NB: modulo fires 4x but byte-identical — no modulo regression) |
| RuleSignForm2 | BLOCKED(fused RuleDivOpt de-fusion — Task #9) |
| RuleSignDiv2 | BLOCKED(fused RuleDivOpt de-fusion — Task #9) |
| RuleDivChain | MISSING |
| RuleSignNearMult | BLOCKED(fused RuleDivOpt de-fusion — Task #9) |
| RuleModOpt | PORTED |
| RuleSignMod2nOpt | PORTED |
| RuleSignMod2nOpt2 | PORTED |
| RuleSignMod2Opt | BLOCKED(fused RuleDivOpt de-fusion — Task #9) |
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

**Sign-div cluster BLOCKED on RuleDivOpt de-fusion (Task #9).** The signed-division normalizers/
recognizers registered around RuleDivOpt — RuleSignForm2, RuleSignDiv2, RuleSignNearMult, RuleSignMod2Opt
(and RuleSignForm, ported+HELD as the proof case) — all race mosura's FUSED non-faithful RuleDivOpt (#85),
which recognizes the whole signed-div idiom in one step rather than composing from these faithful pieces.
RuleSignForm demonstrated it: wiring it regressed switchloop (0.7787->0.7709) because the fused recognizer
can't re-collapse the `s>>` form the normalization exposes (Ghidra reaches `(int4)param_1 / 10`). Porting
these held-now is dead code that can't be validated until de-fusion; they belong to the de-fusion effort
itself (Task #9/#20), where they'd compose and be verified. Kept visible here as BLOCKED, not declined.
RuleDivTermAdd is the same class (HELD). (RuleSignShift #14 is a general sign-bit normalization, not in
this cluster — left MISSING, separable.)

**RuleSubfloatConvert** is BLOCKED, not a mechanical tail rule: it is a thin dispatcher (`subflow.cc:3489`)
into `SubfloatFlow : public TransformManager` (subflow.cc). That needs (a) the generic `TransformManager`/
`TransformVar` transform framework — which mosura lacks; its `SubvariableFlow` (subvarflow.rs) is a
bespoke integer-subvalue port, not the reusable base SubfloatFlow extends — and (b) `FloatFormat`-driven
precision tracing (maxPrecision/exceedsPrecision/traceForward/traceBackward/doTrace/apply). This is the
float-precision-narrowing subsystem (Task #11 float / a TransformManager port), not the rule tail. It is
`FLOAT_FLOAT2FLOAT`'s real handler; RuleFloatCast (also on FLOAT_FLOAT2FLOAT) is the small in-place
sibling and IS ported.

---

## 3. oppool2 rules (coreaction.cc:5664-5669)

| Ghidra rule | mosura |
|---|---|
| RulePushPtr | MISSING |
| RuleStructOffset0 | PARTIAL (ptrarith.rs / infertypes struct-offset-0) |
| RulePtrArith | PORTED (ptrarith.rs, ptrarith_pool) |
| RuleLoadVarnode | BLOCKED(mosura resolves LOAD addresses pre-pool via stackvars; a faithful pool-rule port needs the spacebase-placeholder model — checkSpacebase/resolveSpacebaseRelative/isSpacebasePlaceholder) |
| RuleStoreVarnode | BLOCKED(same spacebase-placeholder dep as RuleLoadVarnode) |

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

- **oppool1**: ~71 PORTED (incl. RuleFloatCast, RuleShiftAnd, RuleConcatCommute, RuleConcatZext, RuleZextCommute, RuleConcatLeftShift, RuleConcatZero, RuleDoubleSub, RuleDoubleShift, RuleDoubleArithShift, RuleConcatShift, RuleTrivialBool, RuleLess2Zero, RuleOrConsume, RuleEqual2Constant, RuleBoolZext), 7 HELD (NotDistribute, AndDistribute,
  AndCompare, SubZext, Piece2Zext, DivTermAdd, SignForm=fused-DivOpt-race), 6 BLOCKED (SubvarSext,
  RulePtrFlow=isPtrFlow, and the sign-div cluster SignForm2/SignDiv2/SignNearMult/SignMod2Opt on
  RuleDivOpt de-fusion Task #9), ~61 MISSING, 1 non-faithful (DivOpt fused), + 3 mosura-only extras.
  The MISSING set is the mechanical rule tail (Phase 1b, in progress).
- **oppool2**: 1 PORTED (PtrArith), 1 PARTIAL, 1 MISSING (PushPtr), 2 BLOCKED (LoadVarnode, StoreVarnode
  — spacebase-placeholder dep).
- **cleanup**: 3 PORTED (the Sub2Add reconstruction subset), 3 BLOCKED (RuleSplitCopy/Load/Store —
  SplitDatatype/TypePartialStruct dep), 9 MISSING (DumptyHumpLate etc.).

**Highest-value MISSING (already surfaced by trace-diff / fixtures):** RuleConcatZext/RuleConcatZero
family. (RuleEarlyRemoval — 78× —, RuleScarry, RuleFloatCast, and RuleShiftAnd now PORTED byte-neutral;
RuleLoadVarnode/StoreVarnode and the RuleSplit* family reclassified BLOCKED on the spacebase /
SplitDatatype subsystems respectively.)

**Sub-case gaps within PORTED functions** (the class this matrix is meant to catch — e.g. the
extended-precision consume branches found in Task #8): audit each PORTED rule/action for omitted
`size > sizeof(uintb)`, `isPersist`, `isPtrFlow`, and aggressive-mode branches. Consume transfers
(`consume.rs`) are now complete for SUBPIECE/PIECE extended precision (`68a059e`); other transfers
and nzmask/refinement should get the same pass.
