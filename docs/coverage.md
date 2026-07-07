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
| RuleSelectCse | PORTED (+ isCseMatch output-size guard `8dd6d80`; + Task #20 `cd0fd9e` isCseMatch INPUT rule — constant inputs match by VALUE not size, so the division sign correction `x s>> (w-1)` merges with the compiler's own #0x3f:4/#0x3f:8) |
| RuleCollectTerms | PORTED (N-ary, `cd0fd9e` Task #20 — Ghidra's TermOrder::collect + Varnode::termOrder + distributeIntMultAdd; the whole additive tree is linearized so `(SDIV + s) - s` cancels, replacing the binary as_term collector) |
| RulePullsubMulti | MISSING |
| RulePullsubIndirect | MISSING |
| RulePushMulti | BLOCKED (nodejoin subsystem — pushes an op back through a MULTIEQUAL across the node-join machinery mosura lacks) |
| RuleSborrow | PORTED (+ AddExpression `b5e3df8` Task #20 — subtract_matches now uses Ghidra's functional additive comparison, so `a - b` in the post-Sub2Add `a + b*-1` form still matches) |
| RuleScarry | PORTED (rules.rs; ADD sibling of RuleSborrow via add_matches, now Ghidra's AddExpression `b5e3df8` Task #20) |
| RuleIntLessEqual | HELD (defined + 4 unit tests in rules.rs via `replace_lessequal` port of Funcdata::replaceLessequal, UNWIRED — faithful `V <= c => V < c+1` / signed / both operand positions / overflow guards). CONFLICTS with a mosura print-time adaptation: printc::incr_in_width already does `x <= c => x < c+1` at render, keeping SLESSEQUAL in the IR. Wiring the faithful IR rule (63 firings) converts to SLESS early and the structuring/condition-negation (tuned for SLESSEQUAL) regresses concat/condconst/condmulti/condsplit into `x == c || x < c` disjunctions. Wire after cancelling the print-time adaptation + fixing the structuring dependency (instrument-first; P7/P8 #5/#6) |
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
| RuleEqual2Zero | PORTED (+ the INT_ADD(x, y*-1) variable-negation arm `2b22f65`, Task #20 — `(x + y*-1) == 0 => x == y` for the post-Sub2Add subtraction form. NB: Ghidra's all-descendants-bool-output guard is NOT ported — adding it suppresses an equal2zero firing switchloop's jumptable recovery needs, a separate switch-path IR divergence) |
| RuleEqual2Constant | PORTED (rules.rs; byte-neutral, unit-tested — fold const through arith operand of INT_EQUAL/NOTEQUAL when V only used in similar compares; inert on corpus) |
| RuleThreeWayCompare | PORTED (rules.rs; byte-neutral, 3 unit tests — detect a three-way `zext(V<W)+zext(V<=W)-1` (3 add/const permutations + partial form, via detectThreeWay/testCompareEquivalence helpers) and fold a secondary compare of it vs a small constant back to a direct `V`/`W` compare (24-case form table); 0 firings on corpus — the C++ spaceship idiom doesn't occur in the fixtures) |
| RuleXorCollapse | PORTED |
| RuleAddMultCollapse | PORTED (relocated to the main pool slot 52 — Task #20 keystone) |
| RuleCollapseConstants | PORTED (= RuleConstFold) |
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
| RuleSubZext | HELD(preempts RuleSubvarZext return-narrowing on the truncation-return family; Task #8) |
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
| RuleCondNegate | MISSING |
| RuleBoolNegate | PORTED |
| RuleLessEqual | PORTED |
| RuleLessNotEqual | PORTED (rules.rs, WIRED slot 100 — `2b22f65` Task #20; BOOL_AND `(V <= W) && (V != W) => V < W`, collapses the for-loop guard to `<` without the print-time `<=` adaptation) |
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
| JumpBasic (the common LOAD-table model) | PORTED (jumpbasic.rs `recover_jumpbasic` — the driver `jumptable::recover` calls; Stage 4 swap landed, old `recover_one` retired) |
| CircleRange pull-back (rangeutil.cc) | PORTED (circlerange.rs — faithful port of the pull-back half: ctors/intersect/circleUnion/minimalContainer/setNZMask/setStride/pullBackUnary+Binary and the `pullBack` op-driver, validated against Ghidra's own `testcirclerange.cc` element-set oracle (intersect/union/pullback vectors) + the `(index-1)<8`→[1,9) key case; pushForward/ValueSet half deliberately not ported. Wired via `recover_jumpbasic`, Task #8) |
| PathMeld + findDeterminingVarnodes (jumptable.cc) | PORTED (jumpbasic.rs — faithful port of `PathMeld` (internalIntersect/meldOps/meld/markPaths/truncatePaths/append/getEarliestOp), `findDeterminingVarnodes`, and the `isprune`/`ispoint`/`getStride`/`getMaxValue` statics. meldOps' `getSeqNum().getOrder()` maps to within-block op index (`op_order`); the op MARK flag was added to op.rs. Unit-tested incl. a split-rejoin diamond exercising meld. Wired via `recover_jumpbasic`, Task #8) |
| GuardRecord + analyzeGuards (jumptable.cc) | PORTED (jumpbasic.rs — faithful port of `GuardRecord` (+valueMatch/oneOffMatch/quasiCopy statics) and `analyzeGuards`: the maxpullback CircleRange::pull_back chain that turns `INT_LESS(INT_ADD(index,-1),8)` into a `[1,9)` bound on `index`, one GuardRecord per pull-back step. Block-walk adapted to mosura's canonical CFG (getInRevIndex via out_edges.position; no isBooleanFlip/getFlipPath ⇒ toswitchval=(indpath==1), indpathstore=indpath); checkUnrolledGuard (sizeIn>1 unrolled) deferred+cited. Unit-tested (ADD-form guard). Wired via `recover_jumpbasic`, Task #8) |
| recoverModel/calcRange/findSmallestNormal/buildAddresses (jumptable.cc) | PORTED (jumpbasic.rs `recover_jumpbasic` — the JumpBasic driver `jumptable::recover` calls (Stage 4 swap landed; `recover_one` retired). calcRange (initial nzmask/maxvalue/stride/bool range + guard-range intersect + positive-only), findSmallestNormal (smallest-range common varnode = normalized switch var), buildAddresses (CircleRange value iteration → reuses `jumptable::emulate`/`in_image`/`find_default`/`backtrace_set`). Corpus byte-identical to `recover_one` across 62 x86:LE:64 fixtures. Task #8) |
| FlowInfo::recoverJumpTables → newAddress edge-feedback (flow.cc:806) | PORTED (build.rs multistage: each recovery partial's `switch_targets` is seeded from prior passes' recovered tables so discovered case blocks become reachable and the loop-header switch phi widens pass-over-pass — required for switch-variable-is-loop-variable forms, e.g. switchloop. Targets only; the guard fold (foldInOneGuard) stays post-recovery, Task #8) |
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

- **oppool1**: ~84 PORTED (incl. the now-de-fused div/sign cluster — RuleDivOpt (faithful), RuleDivTermAdd,
  RuleSignShift, RuleTestSign, RuleSignForm, RuleSignForm2, RuleSignDiv2, RuleDivChain, RuleSignNearMult,
  RuleModOpt, RuleSignMod2nOpt, RuleSignMod2nOpt2, RuleSignMod2Opt, RuleLessNotEqual — Task #20; plus
  RuleFloatCast, RuleShiftAnd, RuleConcat*, RuleDouble*, RuleTrivialBool, RuleLess2Zero, RuleOrConsume,
  RuleEqual2Constant, RuleBoolZext), 3 HELD (NotDistribute, AndDistribute, AndCompare), 3 BLOCKED (SubZext,
  Piece2Zext, SubvarSext / RulePtrFlow=isPtrFlow), 1 DEFERRED (RuleLeftRight — register-piece dep, Task #7),
  ~61 MISSING, 0 non-faithful (the fused DivOpt is retired), + 3 mosura-only extras.
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
