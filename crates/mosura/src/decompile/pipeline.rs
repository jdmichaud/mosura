//! The decompiler pipeline — the assembly of phases into one composable action, the
//! analogue of Ghidra's `ActionDatabase::universalAction` (`coreaction.cc`). Grows as each
//! phase lands; currently heritage (P1) + the simplification rule pool (P2).

use super::action::{Action, ActionGroup, ActionPool, OncePerFunc};
use super::funcdata::Funcdata;
use super::rules::{
    Rule2Comp2Sub, RuleAddUnsigned, RuleCollectTerms, RuleEarlyRemoval, RuleConstFold, RuleEqual2Zero,
    RuleIdentityEl, RuleLessEqual, RuleLessNotEqual, RuleRangeMeld, RuleBoolNegate, RuleBooleanNegate, RuleIdempotent,
    RuleMultiCollapse, RuleMultNegOne, RuleSubExtComm, RuleMultMult, RuleHumptyDumpty,
    RuleAndZext, RuleDumptyHump, RuleOrCompare, RulePropagateCopy, RuleRangeAnd,
    RuleLogic2Bool, RuleOrMask, RuleShiftAnd, RuleShiftCompare, RuleShiftPiece, RuleZextEliminate,
    RuleSborrow, RuleScarry, RuleSelectCse, RuleShift2Mult, RuleTermOrder, RuleTrivialArith, RuleTrivialShift,
    RuleAndMask, RulePopcountBoolXor, RuleSlessToLess, RuleZextSless, RuleBoolZext,
    RuleOrCollapse, RuleAndOrLump, RuleRightShiftAnd, RuleXorCollapse, RuleHighOrderAnd, RuleZextShiftZext, RuleConcatCommute, RuleConcatZext,
    RuleZextCommute, RuleConcatZero, RuleConcatLeftShift, RuleSubCancel, RuleShiftSub, RuleSubCommute,
    RuleDoubleSub, RuleDoubleShift, RuleDoubleArithShift, RuleConcatShift, RuleTrivialBool, RuleLess2Zero,
    RuleSLess2Zero, Rule2Comp2Mult, RuleCarryElim, RuleBxor2NotEqual, RuleThreeWayCompare,
    RuleNegateIdentity, RuleBitUndistribute, RuleBooleanUndistribute, RuleBooleanDedup,
    RuleSubNormal, RuleSubRight, RuleOrConsume, RuleEqual2Constant,
    RuleLessEqual2Zero, RuleShiftBitops, RuleHumptyOr, RuleAndPiece, RulePositiveDiv,
    RuleAndCommute, RuleFloatRange, RuleFloatCast, RuleIgnoreNan,
    RuleSubvarAnd, RuleSubvarSubpiece, RuleSubvarCompZero, RuleSubvarShift, RuleSubvarZext,
};

/// Build the CFG and SSA form, iterating heritage one delay-group pass per call (Ghidra's
/// `ActionHeritage`, plus the CFG construction Ghidra does in `followFlow`). The first call
/// (blocks not yet built) does the one-time setup — stack recovery, CFG construction, the alias
/// probe, call-effect modelling — then heritages the register group (delay 0). Each later call
/// heritages the next delay group (`ram`/`stack`, delay 1) until every space is in SSA form.
///
/// Wrapped in a restart group (see [`universal_action`]) so it re-runs to completion. Driving it
/// one pass per call is the foundation for the iterating mainloop, which will run param recovery
/// and simplification between the register and stack passes.
pub struct ActionHeritage;

impl Action for ActionHeritage {
    fn name(&self) -> &str {
        "heritage"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        if data.num_blocks() == 0 {
            // First call: one-time setup, then heritage the register group (pass 0).
            // Build the CFG before stack recovery so recover_stack can propagate the stack pointer
            // over the control-flow graph (per-block entry = predecessor exit), not the flat op list.
            super::cfg::build_cfg(data);
            super::stackvars::recover_stack(data);
            // wire return/argument candidates before heritage links them to reaching defs
            super::recover::recover_return(data);
            super::recover::recover_call_args(data);
            // Probe pass: fully simplify a copy (heritage + rules + dead-code, no call-guards),
            // then run Ghidra's AliasChecker on the resulting graph to find which stack slots are
            // aliased — their address escapes to a call. This decides which slots heritage's
            // `guard_calls` guards, so a non-aliased local (a spilled loop variable) is never
            // guarded and its loop SSA is left intact — without a calling-convention scan.
            let boundary = {
                let mut probe = data.clone();
                let pdom = super::dominator::compute(&probe);
                super::heritage::heritage(&mut probe, &pdom);
                super::recover::resolve_return(&mut probe);
                super::recover::resolve_call_args(&mut probe);
                // Suppress the MOSURA_TRACE trace here: this rule pool runs on a throwaway clone
                // for alias analysis, so its firings would double the real pipeline's trace.
                super::action::with_suppressed_trace(|| default_rule_pool().apply(&mut probe));
                super::deadcode::ActionDeadCode.apply(&mut probe);
                super::alias::alias_boundary(&probe)
            };
            // Enable heritage's per-range call-effect guarding (Ghidra `Heritage::guardCalls`),
            // threading the alias boundary. The probe clone above heritaged with guarding OFF (the
            // default), so its boundary was computed on a graph free of the call INDIRECTs — as
            // Ghidra runs guardCalls only in the true heritage, not the AliasChecker probe.
            data.alias_boundary = boundary;
            data.call_guards_active = true;
            let dom = super::dominator::compute(data);
            super::heritage::heritage_pass(data, &dom);
            return 1;
        }
        // Later calls: heritage the next delay group, until all spaces are in SSA form.
        if super::heritage::heritage_complete(data) {
            return 0;
        }
        let dom = super::dominator::compute(data);
        super::heritage::heritage_pass(data, &dom);
        1
    }
}

/// Keep only the realistic return value / call arguments (Ghidra's `ActionActiveParam` /
/// `ActionReturnRecovery`). Runs after heritage has linked the call/return varnodes to their
/// reaching defs; split out of `ActionHeritage` so it runs once heritage is complete.
pub struct ActionResolveCalls;

impl Action for ActionResolveCalls {
    fn name(&self) -> &str {
        "resolvecalls"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        // Ghidra's count conventions, per side: ActionReturnRecovery +1 per unchecked trial + 1 on
        // commit (coreaction.cc:1933/1951); ActionActiveParam +1 per call still being evaluated + 1
        // on commit (coreaction.cc:1748/1756). Bottoms out at 0 once both trial containers are
        // committed and cleared. (Was an unconditional `1` — the return-1 mis-port class that makes
        // a rule_repeatapply group never converge; cf. ActionNonzeroMask/ActionInferTypes.)
        super::recover::resolve_return(data) + super::recover::resolve_call_args(data)
    }
}

/// Ghidra `ActionSwitchNorm` (`coreaction.cc:4548`): normalize each recovered jump table late on the
/// final graph — recover the case labels and fold the `BRANCHIND` onto the switch variable. See
/// [`super::jumpbasic::switch_norm`].
pub struct ActionSwitchNorm;

impl Action for ActionSwitchNorm {
    fn name(&self) -> &str {
        "switchnorm"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        // Ghidra `ActionSwitchNorm::apply` counts +1 per table folded, gated `!jt->isLabelled()` so
        // each table is counted at most once across the repeating actfullloop (coreaction.cc:4551-
        // 4557); `switch_norm` returns that count. (Was an unconditional `1` — the return-1
        // mis-port class; ActionSwitchNorm sits in Ghidra's actfullloop, which iterates on it.)
        super::jumpbasic::switch_norm(data)
    }
}

/// The simplification rule pool (Ghidra's `oppool1`, `coreaction.cc:5512`). The rules are ordered to
/// match Ghidra's `addRule` registration sequence — which *is* the per-opcode priority
/// (`ActionPool::addRule` appends each rule to `perop[opcode]`, so registration order = the order
/// [`ActionPool::apply`] tries rules for a given opcode). The parenthesised number after each rule is
/// its index in the canonical oppool1 list. The three mosura-only rules with no Ghidra counterpart
/// (RuleMultMult, RuleIdempotent, RuleRangeAnd) are slotted next to their closest Ghidra sibling.
pub fn default_rule_pool() -> ActionPool {
    ActionPool::new("oppool")
        .with(RuleEarlyRemoval) // (1)
        .with(RuleTermOrder) // (2)
        .with(RuleSelectCse) // (3)
        .with(RuleCollectTerms) // (4)
        .with(RuleMultMult) // mosura extra — term collection over MULT, next to CollectTerms
        // RulePullsubMulti (coreaction.cc:5516): pull a SUBPIECE truncation up through a MULTIEQUAL —
        // the faithful clean phi-narrowing mosura lacked. On a dual-width selector heritaged wide
        // (switchloop's r0x8), it narrows the switch-merge phis in one step where SubVariableFlow
        // otherwise over-fires and duplicates. Loop-header phis are skipped (hasLoopIn guard).
        .with(super::rules::RulePullsubMulti) // (5)
        .with(super::rules::RulePullsubIndirect) // (6) coreaction.cc:5517 — the INDIRECT analogue
        .with(super::rules::RulePushMulti) // (7) coreaction.cc:5518 ("nodejoin") — dual: push a phi
        // down through a shared functional op / collapse a phi of two shadowing COPYs.
        .with(RuleSborrow) // (8)
        .with(RuleScarry) // (9)
        // RuleIntLessEqual (10): `V <= c => V < (c+1)`. Faithful Ghidra rule; wiring it here mirrors
        // Ghidra's own trace (coreaction.cc:5521, "analysis" pool) — e.g. condmulti's SF==OF term
        // reconstructs to `6 <= x`, which Ghidra AND mosura convert to `5 < x` at this slot. Formerly
        // HELD-unwired: pre-keystone it made the PRINT-time branch negation emit `100 <= x` vs Ghidra's
        // `99 < x`; task #8 (isBooleanFlip/RuleCondNegate) materialized the negation in the IR, so that
        // blocker is gone. It exposes one downstream gap — mosura lacks RuleRangeMeld (coreaction.cc:
        // 5612), which collapses the SLESS-form flag reconstruction `(x==c)||(x<c)` / `(x!=c)&&(c-1<x)`
        // that this rule's early SLESSEQUAL->SLESS conversion hands off; mosura had leaned on
        // RuleLessNotEqual (SLESSEQUAL-form only). Until RuleRangeMeld lands (task #11), condmulti/
        // deindirect/elseif/loopcomment render the un-collapsed disjunction. The regression is the
        // diagnostic naming that gap, not this faithful wiring (per faithful-ports-land-not-held).
        .with(super::rules::RuleIntLessEqual) // (10)
        .with(RuleTrivialArith) // (11)
        .with(RuleTrivialBool) // (12)
        .with(RuleTrivialShift) // (13)
        .with(super::rules::RuleSignShift) // (14)
        .with(super::rules::RuleTestSign) // (15)
        .with(RuleIdentityEl) // (16)
        .with(RuleIdempotent) // mosura extra — trivial idempotent AND/OR/XOR/SUB folds
        .with(RuleOrMask) // (17)
        .with(RuleAndMask) // (18)
        .with(RuleRangeAnd) // mosura extra — AND with a range mask, next to AndMask
        .with(RuleOrConsume) // (19)
        .with(RuleOrCollapse) // (20)
        .with(RuleAndOrLump) // (21)
        .with(RuleShiftBitops) // (22)
        .with(RuleRightShiftAnd) // (23)
        .with(RuleHighOrderAnd) // (25)
        .with(RuleAndCommute) // (27)
        .with(RuleAndPiece) // (28)
        .with(RuleAndZext) // (29)
        .with(RuleDoubleSub) // (31)
        .with(RuleDoubleShift) // (32)
        .with(RuleDoubleArithShift) // (33)
        .with(RuleConcatShift) // (34)
        .with(RuleShiftCompare) // (36)
        .with(RuleShift2Mult) // (37)
        .with(RuleShiftPiece) // (38)
        .with(RuleMultiCollapse) // (39)
        .with(Rule2Comp2Mult) // (41)
        .with(super::rules::RuleSub2Add) // (42)
        .with(RuleCarryElim) // (43)
        .with(RuleBxor2NotEqual) // (44)
        .with(RuleLess2Zero) // (45)
        .with(RuleLessEqual2Zero) // (46)
        .with(RuleSLess2Zero) // (47)
        .with(RuleEqual2Zero) // (48)
        .with(RuleEqual2Constant) // (49)
        .with(RuleThreeWayCompare) // (50)
        .with(RuleXorCollapse) // (51)
        .with(super::rules::RuleAddMultCollapse) // (52)
        .with(RuleConstFold) // (53) RuleCollapseConstants
        .with(RulePropagateCopy) // (55)
        .with(RuleZextEliminate) // (56)
        .with(RuleSlessToLess) // (57)
        .with(RuleZextSless) // (58)
        .with(RuleBitUndistribute) // (59)
        .with(RuleBooleanUndistribute) // (60)
        .with(RuleBooleanDedup) // (61)
        .with(RuleBoolZext) // (62)
        .with(RuleBooleanNegate) // (63)
        .with(RuleLogic2Bool) // (64)
        .with(RuleSubExtComm) // (65)
        .with(RuleSubCommute) // (66)
        .with(RuleConcatCommute) // (67)
        .with(RuleConcatZext) // (68)
        .with(RuleZextCommute) // (69)
        .with(RuleZextShiftZext) // (70)
        .with(RuleShiftAnd) // (71)
        .with(RuleConcatZero) // (72)
        .with(RuleConcatLeftShift) // (73)
        // RuleSubZext (coreaction.cc:5585, between RuleConcatLeftShift and RuleSubCancel; body
        // ruleaction.cc:5039): `zext(sub(V,0)) => V & mask` etc. Now WIRED — the SubVariableFlow
        // driving rules (slots 110-116) landed, so this composes as Ghidra intends. The old
        // wide-return regressors it caused are gone (the iterating mainloop + const-0 fold + subvar
        // return-narrowing + RulePiece2Zext cleared them; those fixtures are byte-identical). The
        // residual forloop_varused/noforloop_iterused dip is the diagnostic for the missing
        // induction-phi narrowing (Ghidra narrows the 8-byte loop phi via subvar_subpiece+andmask at
        // the loop header; mosura doesn't yet) — Task #24, the faithful-exposes-gap payback.
        .with(super::rules::RuleSubZext) // (74)
        .with(RuleSubCancel) // (75)
        .with(RuleShiftSub) // (76)
        .with(RuleHumptyDumpty) // (77)
        .with(RuleDumptyHump) // (78)
        .with(RuleHumptyOr) // (79)
        .with(RuleNegateIdentity) // (80)
        .with(RuleSubNormal) // (81) — its non-zero-offset SUBPIECEs are re-expanded for printing
        // by the cleanup-pool RuleSubRight (Ghidra actcleanup, coreaction.cc:5700), as in Ghidra.
        .with(RulePositiveDiv) // (82)
        .with(super::divopt::RuleDivTermAdd) // (83)
        .with(super::divopt::RuleDivTermAdd2) // (84)
        .with(super::divopt::RuleDivOpt) // (85)
        .with(super::rules::RuleSignForm) // (86)
        .with(super::rules::RuleSignForm2) // (87)
        .with(super::divopt::RuleSignDiv2) // (88)
        .with(super::divopt::RuleDivChain) // (89)
        .with(super::divopt::RuleSignNearMult) // (90)
        .with(super::divopt::RuleModOpt) // (91)
        .with(super::divopt::RuleSignMod2nOpt) // (92)
        .with(super::divopt::RuleSignMod2nOpt2) // (93)
        .with(super::divopt::RuleSignMod2Opt) // (94)
        // RuleCondNegate (coreaction.cc:5607, immediately before RuleBoolNegate) is defined +
        // unit-tested in rules.rs but HELD UNWIRED: it only fires on a CBRANCH the structurer has
        // marked `boolean_flip`, and mosura does not yet set that flag — it still negates branch
        // sense at PRINT time (printc::render_negated + the structurer's `Structured.negated`).
        // Wiring it is inert until the structurer sets `boolean_flip` instead (task #1 S1/S2); at
        // that point this materializes the negation in the IR so RuleBoolNegate/RuleIntLessEqual
        // normalize it there and printc reads the positive condition directly.
        .with(RuleBoolNegate) // (98)
        .with(RuleLessEqual) // (99)
        .with(RuleLessNotEqual) // (100)
        .with(RuleRangeMeld) // (101)
        .with(RuleFloatRange) // (102)
        // RulePiece2Zext (coreaction.cc:5614): `CONCAT(#0, W) => ZEXT(W)`. Wired now that RuleSubvarZext
        // narrows returns — the earlier floatconv over-fire that held it was the wide-return divergence,
        // which the int4-return narrowing cleared (floatconv unchanged 0.653 at wiring). It feeds
        // RuleSplitFlow: a movsd's zero-high half `CONCAT88(#0, Qa)` becomes `ZEXT816(Qa)`, the form
        // SplitFlow's traceBackward splits into low/high lanes.
        .with(super::rules::RulePiece2Zext) // (103)
        // RulePiece2Sext (coreaction.cc:5615, immediately after RulePiece2Zext):
        // `CONCAT(V s>> (8*|V|-1), V) => SEXT(V)` — the cdq;idiv dividend; feeds RuleSubCommute's
        // SDIV/SREM arm so the 8-byte signed-division idiom narrows to the 4-byte `/`.
        .with(super::rules::RulePiece2Sext) // (104)
        .with(RulePopcountBoolXor) // (105)
        .with(RuleOrCompare) // (109)
        // SubVariableFlow driving rules (coreaction.cc:5621-5627). RuleSubvarSext (5628) deferred —
        // sign-extension tracer still stubbed. RuleAndDistribute (5537) stays OUT (RuleHumptyOr
        // ping-pong hang). RuleSubZext is now wired at slot 74 above (its wide-return regressors were
        // cleared by the mainloop + subvar return-narrowing + Piece2Zext).
        .with(RuleSubvarAnd) // (110)
        .with(RuleSubvarSubpiece) // (111)
        // RuleSplitFlow (coreaction.cc:5623): split an artificially-joined wide value — a high SUBPIECE
        // of a PIECE reached through INDIRECT(s)/MULTIEQUAL — into its two logical halves ([`super::
        // splitflow`]). The floatcast XMM 16->8 narrowing: the movsd-zero-joined XMM0 MULTIEQUAL splits
        // into 8-byte Qa/Qb lanes and the `Qb = #0` lane dies. The straight-line `PIECE #0:8 -> SUBPIECE
        // #0` return chain is faithfully NOT split (Ghidra's `vn->getDef() != multiOp` guard rejects a
        // direct PIECE->SUBPIECE); that return-decomposition residual is task #21.
        .with(super::splitflow::RuleSplitFlow) // (112)
        .with(RuleSubvarCompZero) // (114)
        .with(RuleSubvarShift) // (115)
        // RuleSubvarZext (116): narrows a zext-fed value to its logical width; its RETURN pull
        // (try_return_pull, subflow.cc:238) narrows int8 returns to int4 (twodim uint8->uint4,
        // namespace int4 == Ghidra). The old return-storage-as-unique bug is closed: RulePropagateCopy
        // no longer eats the subvar `EAX = COPY(u)` at the RETURN (5a8ac03 ports isReturnCopy), so the
        // narrowed return lands at the register EAX and recover.rs records it faithfully.
        .with(RuleSubvarZext) // (116)
        .with(RuleFloatCast) // (123) floatprecision group
        .with(RuleIgnoreNan) // (124) floatprecision group
        // The double-precision LOAD/STORE recombiners sit at Ghidra's oppool1 tail (coreaction.cc:
        // 5643-5644, after RulePiecePathology :5642 — not ported). RuleDoubleStore is dormant until
        // a PRECISLO/PRECISHI marker port lands (ActionParamDouble / SplitVarnode markings); the
        // remaining family members RuleDoubleIn/RuleDoubleOut (:5645-5646) need combineInputVarnodes
        // and join with their own port.
        .with(super::double::RuleDoubleLoad) // (125) doubleload group
        .with(super::double::RuleDoubleStore) // (126) doubleprecis group
}

/// Sync address-tied varnode properties with the alias classification (the
/// `ActionRestructureVarnode`/`Funcdata::syncVarnodesWithSymbols` + `ScopeLocal::markUnaliased`
/// update, coreaction.cc:2274 / funcdata_varnode.cc:939 / varmap.cc:1332). The *set* side is at
/// varnode creation (`Funcdata::alloc_varnode`, Ghidra's `newVarnode` → `queryProperties`); this
/// pass reconciles — clearing `addrtied`/`addrforce` on the non-aliased stack locals
/// (`nolocalalias`) — so the downstream rules that guard on `addrtied`/`persist` see the net
/// classification. See [`super::varnodeprops::mark_addrtied`].
pub struct ActionMarkAddrTied;

impl Action for ActionMarkAddrTied {
    fn name(&self) -> &str {
        "markaddrtied"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        super::varnodeprops::mark_addrtied(data);
        // Analysis convention: recomputing varnode property flags is never a data-flow change, so it
        // must not drive a rule_repeatapply fixpoint — same convention as ActionNonzeroMask
        // (coreaction.hh:300) and ActionSpacebase (coreaction.hh:277). (Ghidra's
        // ActionRestructureVarnode likewise returns 0, coreaction.cc:2296.)
        0
    }
}

/// Ghidra `ActionRestructureVarnode` (coreaction.hh:848, apply coreaction.cc:2274; mainloop slot
/// :5505, immediately before ActionSpacebase): re-analyze the stack scope every mainloop
/// iteration — `l1->restructureVarnode(aliasyes)` re-runs the `AliasChecker` and marks the
/// unaliased symbols `nolocalalias`, then `syncVarnodesWithSymbols` reconciles the varnode
/// `addrtied`/`addrforce` flags with that classification. `aliasyes = (numpass != 0)`: "Alias
/// calculations are not reliable on the first pass" (coreaction.cc:2279) — pass 0 syncs against
/// the creation-time flags without re-classifying.
///
/// mosura: the alias re-analysis is [`super::alias::alias_boundary`] on the real graph (Ghidra's
/// checker shape — by pass 1 the previous iteration's actprop2 has resolved the direct
/// `RSP [+ const]` LOAD/STOREs, so only genuine escapes root the walk), and the sync is
/// [`super::varnodeprops::mark_addrtied`]. At pass 0 the boundary is the `ActionHeritage`
/// first-call probe's (the up-front clone probe — mosura's stand-in for the `guardCalls`
/// param-trials, P6-adjacent; its retirement is a follow-up). The switch-path INDIRECT
/// protection (`protectSwitchPaths`, jumptable-recovery-time only) is not modelled.
#[derive(Default)]
pub struct ActionRestructureVarnode {
    /// Ghidra `ActionRestructureVarnode::numpass` (coreaction.hh:849), reset per function (:856).
    numpass: u32,
}

impl Action for ActionRestructureVarnode {
    fn name(&self) -> &str {
        "restructure_varnode"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        let aliasyes = self.numpass != 0; // coreaction.cc:2279
        if aliasyes {
            data.alias_boundary = super::alias::alias_boundary(data);
        }
        super::varnodeprops::mark_addrtied(data);
        self.numpass += 1;
        // Ghidra returns 0 (coreaction.cc:2296): scope/property maintenance is analysis, never a
        // data-flow change driving the repeatapply fixpoint (syncVarnodesWithSymbols' update count
        // feeds Ghidra's statistics `count`, not a graph change).
        0
    }
    fn reset(&mut self, _data: &mut Funcdata) {
        // Ghidra `ActionRestructureVarnode::reset` (coreaction.hh:856): numpass = 0 per function.
        self.numpass = 0;
    }
}

/// Ghidra `ActionSpacebase` (coreaction.cc:5506, "Must come before infertypes and nonzeromask"):
/// mark the input stack pointer (and every SSA version of it) `is_spacebase()` and give the input a
/// locked pointer type — see [`Funcdata::spacebase`]. Activates the faithful pointer-arithmetic /
/// nonzero-mask / type-inference rules that key on `is_spacebase()`. The spacebase-register
/// (`RuleLoadVarnode` stack) branch that this enables is not yet wired (S2b).
pub struct ActionSpacebase;

impl Action for ActionSpacebase {
    fn name(&self) -> &str {
        "spacebase"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        data.spacebase();
        0
    }
}

/// Ghidra `ActionActiveReturn`: recover each call's return value from its surviving `killedbycall`
/// output-register clobber (see [`super::recover::resolve_call_output`]). Runs after the first
/// dead-code pass, so only the *used* output creations remain to be promoted to call outputs.
pub struct ActionActiveReturn;

impl Action for ActionActiveReturn {
    fn name(&self) -> &str {
        "activereturn"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        // Ghidra `ActionActiveReturn::apply` counts +1 per call output committed (coreaction.cc:
        // 1788, the isOutputActive body); `resolve_call_output` returns that count and skips calls
        // that already have an output, so the count bottoms out at 0. (Was an unconditional `1` —
        // the return-1 mis-port class; ActionActiveReturn sits in Ghidra's actfullloop.)
        super::recover::resolve_call_output(data)
    }
}

/// The universal decompile action: heritage, simplification, then dead-code removal.
/// Ghidra `ActionInferTypes`: recover and commit a data-type onto every varnode, so the
/// pointer-arithmetic rules can read pointer types during the pipeline.
#[derive(Default)]
pub struct ActionInferTypes {
    /// Ghidra `ActionInferTypes::localcount` (coreaction.hh:964): passes performed for this
    /// function, reset per function ([`Action::reset`]). Capped at 7 (coreaction.cc:5390).
    localcount: u32,
}

impl Action for ActionInferTypes {
    fn name(&self) -> &str {
        "infertypes"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        // Ghidra `ActionInferTypes::apply` (coreaction.cc:5378): inert until `ActionStartTypes`
        // has flipped type recovery on — "Make sure spacebase is accurate or bases could get
        // typed and then ptrarithed". The fullloop's first round runs the whole mainloop
        // typeless; only after StartTypes fires does inference (and the ptrarith rules it feeds)
        // participate.
        if !data.has_type_recovery_started() {
            return 0;
        }
        // Ghidra `ActionInferTypes::apply` (coreaction.cc:5390-5397): at most 7 propagation passes
        // per function ("This constant arrived at empirically"). On the 7th, flag type-recovery
        // exceeded (so `AddTreeState::buildTree` assigns propagated types directly instead) and
        // stop; thereafter this action is a no-op. This is the mainloop's convergence safety net —
        // a type lattice that never settles caps out rather than re-propagating forever.
        if self.localcount >= 7 {
            if self.localcount == 7 {
                data.set_type_recovery_exceeded();
                self.localcount += 1;
            }
            return 0;
        }
        // No recovered type-locks yet (see printc), so inference types every varnode. Count a pass
        // only when writeBack actually changed a committed type (coreaction.cc:5411-5414).
        if super::infertypes::infer_types(data, &std::collections::HashMap::new()) {
            self.localcount += 1;
        }
        // Ghidra returns 0 (coreaction.cc:5415, "Do not consider this a data-flow change"): type
        // inference must never drive the mainloop's `rule_repeatapply` fixpoint (only
        // heritage/ptrarith/deadcode do). Returning nonzero would prevent the reheritage restart
        // group from ever converging.
        0
    }
    fn reset(&mut self, _data: &mut Funcdata) {
        // Ghidra `ActionInferTypes::reset` (coreaction.hh:975): localcount = 0 per function.
        self.localcount = 0;
    }
}

/// Ghidra `ActionStartTypes` (coreaction.hh:74-86): mark that data-type analysis has started.
/// Its slot is the tail of `actfullloop` (coreaction.cc:5687): the repeating fullloop first runs
/// the whole mainloop to quiescence TYPELESS — every `hasTypeRecoveryStarted`-gated site
/// ([`ActionInferTypes`], `RulePushPtr`, `RulePtrArith`) inert — then this action flips the flag
/// and counts one change, which forces the fullloop into another round that re-runs everything
/// TYPED. `Funcdata::startTypeRecovery` returns true exactly once (funcdata.cc:182-188), so
/// exactly one extra round is forced. (Ghidra's `reset` also sets the `typerecovery_on` "type
/// recovery will be performed" flag, coreaction.hh:77 — trivially true in mosura, not modeled.)
pub struct ActionStartTypes;

impl Action for ActionStartTypes {
    fn name(&self) -> &str {
        "starttypes"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        // coreaction.hh:82-85: `if (data.startTypeRecovery()) count += 1; return 0;` — mosura's
        // `Action::apply` returns the change count directly, so the counted start is the return.
        u32::from(data.start_type_recovery())
    }
}

/// The pointer-arithmetic rule pool (Ghidra runs `RulePtrArith` in the main rule group, gated on
/// type recovery). Run after `ActionInferTypes` so the base pointers are typed.
///
/// `RuleSub2Add` runs here (rather than in `default_rule_pool`) so the INT_SUB-rooted modulo/divopt
/// rules match the original subtraction form first; it canonicalises `V - W` to `V + W*-1` so
/// `RulePtrArith` sees a single additive shape. `RuleConstFold` then collapses a constant `W*-1` to
/// `-c` (leaving a COPY, per RuleCollapseConstants) and `RulePropagateCopy` threads it onward, so
/// the negated constant actually reaches the INT_ADD before pointer arithmetic / cleanup runs.
pub fn ptrarith_pool() -> ActionPool {
    ActionPool::new("ptrarith")
        .with(RuleConstFold)
        .with(RulePropagateCopy)
        // Ghidra actprop2 order (coreaction.cc:5664/5666): RulePushPtr normalizes a pointer to the
        // bottom of its additive expression, then RulePtrArith converts.
        .with(super::ptrarith::RulePushPtr)
        .with(super::ptrarith::RulePtrArith)
        // Ghidra actprop2 order (coreaction.cc:5666-5669): RulePtrArith, then RuleLoadVarnode,
        // RuleStoreVarnode. The ram-global (const-offset) branch of the spacebase model (task #7 S1).
        .with(super::rules::RuleLoadVarnode)
        .with(super::rules::RuleStoreVarnode)
}

/// Ghidra's cleanup rule pool (`actcleanup`, `coreaction.cc`) — the tail group that runs after all
/// analysis/type recovery. We port the subtraction-reconstruction subset, which is the printable
/// counterpart of `RuleSub2Add`: it turns the canonical `V + W*-1` / `V + 0xff..` additive forms
/// back into `V - W` / `V - c` so the printer renders subtractions, not negative addends.
pub fn cleanup_pool() -> ActionPool {
    ActionPool::new("cleanup")
        .with(RuleMultNegOne)
        .with(RuleAddUnsigned)
        .with(Rule2Comp2Sub)
        .with(RuleSubRight)
}

/// Ghidra `ActionNonzeroMask` (`coreaction.cc:5507`, group "analysis"): recompute every Varnode's
/// non-zero mask ([`super::nzmask::calc_nzmask`]). Ghidra runs it in the main rule loop so the
/// masks stay fresh as the graph is rewritten; here it runs before each rule pool. Nothing consumes
/// the masks yet (the dependent rules — RuleShiftCompare etc. — land next), so it is output-neutral.
pub struct ActionNonzeroMask;

impl Action for ActionNonzeroMask {
    fn name(&self) -> &str {
        "nonzeromask"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        let dom = super::dominator::compute(data);
        super::nzmask::calc_nzmask(data, &dom);
        // Ghidra `ActionNonzeroMask::apply` returns 0 (coreaction.hh:301): recomputing nonzero masks
        // is analysis, never a data-flow change, so it must not drive the mainloop's rule_repeatapply
        // fixpoint. (Was 1 — a mis-port that made the reheritage restart group never converge.)
        0
    }
}

/// The consume-analysis half of Ghidra `ActionDeadCode` (`coreaction.cc:3925`), split out as its
/// own action ([`super::consume::calc_consume`]) so `Varnode::consume` is fresh when the rule pool
/// runs — mirroring how [`ActionNonzeroMask`] is factored out of the rule that reads `nzm`. It
/// reads `nzm` (comparison/int2float/call-parameter transfers), so it runs *after* the mask pass.
/// Nothing consumes the field yet (the SubVariableFlow rules land next), so it is output-neutral.
pub struct ActionConsume;

impl Action for ActionConsume {
    fn name(&self) -> &str {
        "consume"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        super::consume::calc_consume(data);
        // The consume sweep is the analysis prelude of Ghidra's ActionDeadCode (coreaction.cc:
        // 3925+), whose count reports only actual dead-code changes — mosura's deletion half
        // (deadcode.rs) counts those. Recomputing consume is analysis, never a data-flow change,
        // so it must not drive a rule_repeatapply fixpoint. (Was an unconditional `1` — the
        // return-1 mis-port class, cf. ActionNonzeroMask; inside the mainloop restart it would
        // never converge. This edit overlaps the parked consume-default brick, which owns the
        // remaining `Varnode::consume` default fix — see consume-model-misport.)
        0
    }
}

/// The universal decompile action: heritage, simplification, dead-code removal, then type recovery
/// and the pointer-arithmetic rewrite (PTRADD/PTRSUB), a cleanup pass, and a final dead-code sweep.
pub fn universal_action() -> ActionGroup {
    ActionGroup::once("decompile")
        // Iterating heritage: re-run ActionHeritage to completion (register pass, then stack
        // pass). Ghidra's mainloop is a single restart group; here heritage is its own restart
        // group, the foundation for folding the rest of the pipeline into the loop next.
        .then(ActionGroup::restart("heritage").then(ActionHeritage))
        .then(ActionResolveCalls)
        // ★ The two-phase fullloop (task #8 Brick C1): Ghidra `actfullloop` (rule_repeatapply,
        // coreaction.cc:5487) wrapping `actmainloop` (rule_repeatapply, :5489) with
        // `ActionStartTypes` at its tail (:5687). It replaces the three hand-unrolled
        // nzmask→consume→pool→deadcode sweeps and the once-instances of determinedbranch/
        // condconst/infertypes that approximated it. The mainloop body — grown from the
        // "reheritage" restart, Ghidra's actmainloop member cycle rotated to mosura's spacebase
        // entry — first runs to quiescence TYPELESS: ActionInferTypes (coreaction.cc:5378),
        // RulePushPtr (ruleaction.cc:6851) and RulePtrArith (ruleaction.cc:6642) are inert behind
        // the `hasTypeRecoveryStarted` gate, while the UNGATED RuleLoadVarnode/RuleStoreVarnode
        // resolve stack/ram accesses in phase 1 exactly as Ghidra's actprop2 does. Then
        // ActionStartTypes flips the flag, counting one change — which forces the repeatapply
        // fullloop into round 2: the whole mainloop re-runs TYPED to quiescence.
        //
        // Mainloop member notes (Ghidra actmainloop order, coreaction.cc:5490-5676):
        // - ActionSpacebase first ("must come before infertypes and nonzeromask", :5506): marks
        //   the input stack pointer `is_spacebase()`; on re-entry its re-mark arm's splitUses
        //   clones `RSP = RSP-k` per read (funcdata.cc:253-259) into narrow single-use versions,
        //   ending each version's cover at its lone use so ActionMergeRequired's trimOpInput no
        //   longer over-fires the spurious frame-base COPY (task #27 S3); the single-use base then
        //   folds to `PTRSUB(RSP, -k)` in the same pass's ptrarith, so every stack address is a
        //   PTRSUB the ScopeLocal naming resolves.
        // - ActionNonzeroMask → ActionConsume → ActionInferTypes (:5507-5508): the analysis
        //   recomputes, refreshed every iteration as Ghidra does (consume is the analysis half of
        //   Ghidra's ActionDeadCode, coreaction.cc:3925+ — the slot the parked consume-default
        //   brick re-uses). InferTypes-in-the-loop is what forms the clean array subscript (task
        //   #22-A-2b): pass N's ptrarith creates `PTRSUB(RSP, array_start)`, pass N+1's
        //   ActionInferTypes types it as a pointer to the ScopeLocal symbol (TYPE_SPACEBASE
        //   getSubType), so the next ptrarith Array arm folds the index into `PTRADD(array, i,
        //   elem)` — `axStack_N[i]` — instead of a raw `+ i*elem`.
        // - default_rule_pool = oppool1/actstackstall (:5509-5652), ActionDeadCode (:5503,
        //   rotated), ptrarith_pool = actprop2 (:5666-5669): a LOAD/STORE that RuleLoadVarnode/
        //   RuleStoreVarnode converts to a free COPY re-enters ActionHeritage below, which widens
        //   the range (globaldisjoint.add) and re-versions it — the widening re-free
        //   (removeRevisitedMarkers + normalize_ranges, S8-1/2) reconstructs Ghidra's whole-range
        //   SSA (revisit `iRam74 = iRam74 + 10` in-place instead of the snapshot).
        // - The Brick-B tail: ActionDeterminedBranch (:5672) → ActionUnreachable (:5673, inlined
        //   in mosura's determinedbranch) → ActionConditionalConst (:5676) — then the cycle wraps
        //   to ActionHeritage (:5492) + ActionDeadCode, the next iteration's head, so within every
        //   pass the stack/global LOAD/STOREs just resolved are seen by determinedbranch/condconst
        //   in the same iteration (the #22-B ordering evidence). ActionNodeJoin (:5674) /
        //   ActionConditionalExe (:5675) join here when ported.
        // - Convergence: heritage returns 0 once complete, deadcode counts removals, the pools are
        //   fixpoint, nzmask/consume return 0 (analysis), determinedbranch/condconst are monotone
        //   (branch removal strictly shrinks the CFG; a propagated constant no longer matches),
        //   and ActionInferTypes returns 0 and self-caps at 7 passes (localcount, coreaction.cc:
        //   5390) — only heritage/pools/deadcode/branch-folds drive the repeat, and StartTypes
        //   forces exactly one extra fullloop round (startTypeRecovery returns true once).
        .then(
            ActionGroup::restart("fullloop")
                .then(
                    ActionGroup::restart("mainloop")
                        // ActionRestructureVarnode (:5505, before spacebase): per-iteration stack
                        // re-analysis — recompute the alias boundary on the real graph (aliasyes =
                        // pass != 0) and reconcile addrtied/addrforce with it, so RuleSubRight /
                        // ActionConditionalConst's phi guards / SubVariableFlow see the net
                        // classification (pass 0 syncs against the ActionHeritage probe boundary).
                        .then(ActionRestructureVarnode::default())
                        .then(ActionSpacebase)
                        .then(ActionNonzeroMask)
                        .then(ActionConsume)
                        .then(ActionInferTypes::default())
                        // Ghidra `actstackstall` (coreaction.cc:5509, rule_repeatapply; mainloop
                        // slot :5651-5656): an INNER fixpoint group {oppool1, ActionLaneDivide}.
                        // The repeat is load-bearing: when LaneDivide splits a laned store,
                        // `buildStore` mints new pointer arithmetic (base + lane offset); the
                        // group re-runs oppool1 so RuleCollectTerms/AddMultCollapse fold it to
                        // spacebase-relative form BEFORE the group quiesces — then actprop2
                        // (ptrarith below) converts ALL the lane STOREs in one sweep and the
                        // next ActionHeritage sees the complete access set (its refinement
                        // partition links every lane; a flat member ordering left the high lane's
                        // STORE unconverted across the heritage pass — the concatsplit
                        // read-never-written wrong code). LaneDivide is `rule_onceperfunc`
                        // (OncePerFunc): it fires once per function AT this slot — after the
                        // first oppool1 quiescence, where the SubVariableFlow-family rules have
                        // already narrowed the spurious sub-lane reads (call-arg float4 SUBPIECEs
                        // etc.), so `collectLaneSizes`' smallest-first pick sees only the real
                        // lane widths. (The former post-heritage/pre-pool placement — forced
                        // while recover_stack resolved stack stores pre-pool — saw the raw 4-byte
                        // SUBPIECEs and over-split; task #8 Brick D retired that ordering.) Inert
                        // unless the Funcdata carries laned-register records (parsed from the
                        // pspec by the build caller). Absent members join at their slots when
                        // ported: ActionMultiCse (:5653), ActionShadowVar (:5654),
                        // ActionDeindirect (:5655), ActionStackPtrFlow (:5656).
                        .then(
                            ActionGroup::restart("stackstall")
                                .then(default_rule_pool())
                                .then(OncePerFunc::new(super::lanedivide::ActionLaneDivide)),
                        )
                        .then(super::deadcode::ActionDeadCode)
                        .then(ptrarith_pool())
                        .then(super::determinedbranch::ActionDeterminedBranch)
                        .then(super::condconst::ActionConditionalConst)
                        .then(ActionHeritage)
                        .then(super::deadcode::ActionDeadCode),
                )
                // The actfullloop tail (Ghidra coreaction.cc:5678-5689), the mosura-present members
                // at Ghidra's order — each re-evaluates at the end of every fullloop round, and a
                // change any of them makes forces another full round (mainloop re-quiesces on the
                // updated graph):
                // - ActionDeadCode (:5682): the between-rounds sweep — e.g. the address computation
                //   a SwitchNorm fold orphaned in the PREVIOUS round dies here.
                // - ActionDoNothing (:5683, "deadcontrolflow"): remove marker-only blocks
                //   (removeDoNothingBlock -> blockRemoveInternal -> pushMultiequals) — collapsing a
                //   switch's common join pushes the per-case values directly into the loop-header
                //   MULTIEQUAL, the flattened phi the merge phase's cover trims key off
                //   (switchloop's accumulator).
                // - ActionSwitchNorm (:5684): for each recovered jump table, re-find the
                //   unnormalized switch variable on the final graph (matchModel over the saved
                //   recovery-time model — findUnnormalized ran at recovery, jumptable.cc:1462) and
                //   fold the BRANCHIND onto it (foldInNormalization, jumptable.cc:1546); the
                //   recovered labels (buildLabels/backup2Switch, jumptable.cc:1506/472) become the
                //   printed case values. Retires the print-time switch heuristics for normalized
                //   tables — the printer reads `switch(switchvn)` + labels directly. Convergent:
                //   +1 once per table (`jt.normalized`, = Ghidra `!jt->isLabelled()`,
                //   coreaction.cc:4551); a fold counts a change, so the fullloop repeats and the
                //   next round's dead-code members clean up the folded-away address code.
                // - ActionStartTypes (:5687): flips type recovery on after the first (typeless)
                //   round, counting one change — forces the typed round 2 (see above).
                // - ActionActiveReturn (:5688): commit call outputs from the surviving
                //   killedbycall clobbers. Convergent: +1 per committed output, committed calls
                //   are skipped (`output.is_some()`, cleared isOutputActive).
                // Tail members mosura has not ported are absent here: ActionLikelyTrash (:5679),
                // ActionDirectWrite ×2 (:5680-5681), ActionReturnSplit (:5685),
                // ActionUnjustifiedParams (:5686) — each joins at its slot with its port.
                .then(super::deadcode::ActionDeadCode)
                .then(super::determinedbranch::ActionDoNothing)
                .then(ActionSwitchNorm)
                .then(ActionStartTypes)
                .then(ActionActiveReturn),
        )
        .then(cleanup_pool())
        .then(super::deadcode::ActionDeadCode)
        // Late branch-orientation stage (task #1): materialize the structurer's body-on-false
        // branch negations in the IR, mirroring Ghidra's final ActionNormalizeBranches placement
        // (after type recovery, where the guards are in final simplified form). ActionOrientBranches
        // sets boolean_flip on each body-on-false CBRANCH (Ghidra BlockBasic::negateCondition);
        // condnegate_pool then materializes and normalizes the negation so printc reads the positive
        // condition directly instead of negating at print time.
        .then(super::structure::ActionOrientBranches)
        .then(condnegate_pool())
        .then(super::deadcode::ActionDeadCode)
        // Materialize the if/else normal-form flip in the IR (Ghidra ActionPreferComplement /
        // BlockIf::preferComplement, block.cc:3093 — scoped to if/else). Runs after the condnegate
        // pool so it sees the mechanism-B-materialized conditions; opFlipInPlaceExecute rewrites the
        // comparison into normal form (via replace_lessequal), retiring the print-time if_else_flip.
        .then(super::structure::ActionPreferComplement)
        .then(super::deadcode::ActionDeadCode)
        // Re-sync addrtied before the merge phase (Ghidra's ActionMappedLocalSync slot,
        // coreaction.cc:2298: the late syncVarnodesWithSymbols before merge). Creation marks every
        // pool-created ram/stack varnode addrtied (e.g. partialmerge's SubVariableFlow-narrowed
        // input read r0x100670:4); this reconciles the now-linked ones against the alias boundary
        // so the snip sees the net classification.
        .then(ActionMarkAddrTied)
        // Address-tied cover-intersection snip (Ghidra ActionMergeRequired, coreaction.cc:5718):
        // snapshot each addrtied read whose live range crosses a same-address write into a COPY, so
        // the printer doesn't re-read post-write memory at the use site. Gated on the real ADDRTIED
        // flag, so it fires on ram globals / aliased stack slots but not on non-aliased stack temps.
        // The snapshot only survives as a named temp once ActionMarkExplicit keeps printc from
        // inlining the single-use COPY (Task #1 B-iii); until then printc inlines it, so partialmerge
        // stays flat while the wire is live. A deadcode sweep follows.
        .then(super::mergesnip::ActionMergeRequired)
        .then(super::deadcode::ActionDeadCode)
        // The graph-mutating half of Ghidra's ActionMergeRequired: mergeMarker -> mergeOp ->
        // trimOpInput (merge.cc:889/719/692), run after mergeAddrTied above. For each MULTIEQUAL,
        // trim (snip into a predecessor-end COPY) the first input whose HighVariable Cover conflicts
        // with the output's — so the read-only merge in printc no longer fuses the phi output into a
        // conflicting address-tied global (floatcast's `fVar1 = fRam80;` init). A deadcode sweep
        // follows the inserted COPYs.
        .then(super::merge::ActionMergeMarkerTrim)
        .then(super::deadcode::ActionDeadCode)
        // Ghidra ActionDominantCopy (coreaction.cc:5723, after ActionMergeCopy): collapse the
        // same-source COPY groups the merge trimming inserted into one dominant COPY
        // (Merge::processCopyTrims/buildDominantCopy, merge.cc:1415/1151).
        .then(super::merge::ActionDominantCopy)
}

/// The post-orientation rule pool (task #1): once [`ActionOrientBranches`](super::structure::
/// ActionOrientBranches) has set `boolean_flip` on the body-on-false CBRANCHes, [`RuleCondNegate`]
/// materializes `BOOL_NEGATE(cond)` (Ghidra ruleaction.cc:5474, registered coreaction.cc:5607 just
/// before RuleBoolNegate), [`RuleBoolNegate`] folds it into the complementary comparison, and
/// [`RuleIntLessEqual`] normalizes `<=` to the strict form — yielding e.g. ifswitch's `99 < param_1`
/// in the IR. Scoped to the branch-negation cluster; the normal-form flip (opFlipInPlaceExecute) is
/// deferred.
///
/// [`RuleCondNegate`]: super::rules::RuleCondNegate
/// [`RuleIntLessEqual`]: super::rules::RuleIntLessEqual
fn condnegate_pool() -> ActionPool {
    ActionPool::new("condnegate")
        .with(super::rules::RuleCondNegate)
        .with(RuleBoolNegate)
        .with(super::rules::RuleIntLessEqual)
}

/// Run the pipeline on a raw (post-load) Funcdata in place.
pub fn decompile(data: &mut Funcdata) {
    universal_action().apply(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::build::raw_funcdata_flow;
    use crate::decompile::{OpCode, OpId};
    use crate::sleigh::engine::Spec;
    use crate::{datatest, paths};

    #[test]
    fn pipeline_runs_end_to_end() {
        let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
        if !sla.exists() {
            return;
        }
        let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
        let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
        let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_sem.xml")).unwrap();
        let mut f = raw_funcdata_flow(&spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

        decompile(&mut f);
        assert!(f.num_blocks() > 0);

        // every op still in a block is live: a sink, or its output is consumed. (No
        // collapsed/dead ops survive, no unconsumed computations remain.)
        for b in 0..f.num_blocks() as u32 {
            for &op in &f.block(crate::decompile::BlockId(b)).ops {
                assert!(!f.op(op).is_dead(), "a dead op survived in a block");
                let is_sink = matches!(
                    f.op(op).code(),
                    OpCode::Return | OpCode::Branch | OpCode::Cbranch | OpCode::Branchind
                        | OpCode::Store | OpCode::Call | OpCode::Callind | OpCode::Callother
                );
                if !is_sink {
                    let out = f.op(op).output.expect("non-sink op has an output");
                    let vn = f.vn(out);
                    // consumed by another op, or live-out in a return register (RAX/XMM0)
                    let reg = f.spaces.by_name("register");
                    let live_out = Some(vn.loc.space) == reg && matches!(vn.loc.offset, 0x0 | 0x1200);
                    assert!(
                        !vn.descend.is_empty() || live_out,
                        "live op's output must be consumed or live-out"
                    );
                }
            }
        }

        // and constant folding still ran to fixpoint (no foldable all-const op left)
        for i in 0..f.num_ops() as u32 {
            let op = OpId(i);
            if f.op(op).is_dead() || f.op(op).num_inputs() == 0 || f.op(op).output.is_none() {
                continue;
            }
            let all_const = f.op(op).inrefs.iter().all(|&v| f.vn(v).is_constant());
            let foldable = !matches!(
                f.op(op).code(),
                OpCode::Load | OpCode::Store | OpCode::Call | OpCode::Callind | OpCode::Multiequal
            );
            assert!(!(all_const && foldable), "unfolded constant op survived");
        }
    }
}
