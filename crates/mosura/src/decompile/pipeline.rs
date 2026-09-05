//! The decompiler pipeline — the assembly of phases into one composable action, the
//! analogue of Ghidra's `ActionDatabase::universalAction` (`coreaction.cc`). Grows as each
//! phase lands; currently heritage (P1) + the simplification rule pool (P2).

use super::action::{Action, ActionGroup, ActionPool, OncePerFunc};
use super::funcdata::Funcdata;
use super::rules::{
    Rule2Comp2Sub, RuleAddUnsigned, RuleCollectTerms, RuleEarlyRemoval, RuleConstFold, RuleEqual2Zero,
    RuleIdentityEl, RuleLessEqual, RuleLessNotEqual, RuleRangeMeld, RuleBoolNegate, RuleBooleanNegate,
    RuleMultiCollapse, RuleMultNegOne, RuleSubExtComm, RuleHumptyDumpty,
    RuleAndZext, RuleDumptyHump, RuleOrCompare, RulePropagateCopy,
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
    RuleAndCommute, RuleAndCompare, RuleFloatRange, RuleFloatCast, RuleIgnoreNan,
    RuleSubvarAnd, RuleSubvarSubpiece, RuleSubvarCompZero, RuleSubvarSext, RuleSubvarShift,
    RuleSubvarZext, RuleLessOne, RuleXorSwap, RuleLzcountShiftBool, RuleFloatSign, RuleNegateNegate,
    RuleFuncPtrEncoding, RuleUnsigned2Float, RuleInt2FloatCollapse, RuleDumptyHumpLate,
    RuleFloatSignCleanup, RuleExtensionPush, RuleConditionalMove, RuleSwitchSingle, RuleExpandLoad,
    RulePiecePathology, RulePtrsubCharConstant, RulePieceStructure,
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
            // ActionConstbase (coreaction.cc:678, universalAction slot 5478 — right after
            // ActionStart, before heritage): seed each pspec-tracked register with its default
            // value as a `reg = COPY val` at the entry block, so constant propagation folds it.
            // On x86 this is `DF = 0`, which collapses a `rep`-string stride `zext(DF)*-2+1` to
            // `+1` (matching the Ghidra oracle; see docs/tracked-set-port.md). Ghidra's slot is
            // before ExtraPopSetup; DF is independent of the stack, so the order does not interact.
            apply_tracked_context(data);
            // ActionExtraPopSetup (coreaction.cc:1436, group `base`, universalAction slot 5477):
            // model each call's effect on the stack pointer. Ghidra's slot is right after
            // `ActionStart`, whose `startProcessing`/`followFlow` builds the p-code AND the basic
            // blocks — so when it runs the CFG exists and heritage has not happened. In mosura the
            // block construction lives here, inside this one-time setup, so this is that same point
            // in the graph's life. (It cannot go at the head of `universal_action`: there
            // `num_blocks() == 0`, so `op_insert_before` finds no parent block, leaves the new op
            // orphaned, and the later CFG build strands the INDIRECT in a block away from the CALL
            // it guards — which then reads as a marker-only "do nothing" block and trips
            // `blockRemoveInternal`'s "deleting op with descendants".)
            // `recover_stack` FIRST: its sval walk models each call's return-address push from
            // the pristine lift ops. Run the other way, ExtraPopSetup's unknown-case INDIRECT
            // (an ESP write `symbolic_value` cannot evaluate) knocked ESP out of the tracked
            // state at the first call of each path, so every LATER call's retaddr store stayed
            // an unconverted raw STORE for the late rules to place with solver-derived offsets —
            // one +4 composition slip away from landing return addresses inside aliased locals
            // (WAR2 FUN_0003495c, the E1082 family). With the walk first, every call converts at
            // its sval-exact slot and ExtraPopSetup models only the residual delta (see
            // `CallSpec::push_neutralized`).
            super::stackvars::recover_stack(data);
            ActionExtraPopSetup.apply(data);
            // Open return-value and argument recovery before heritage (Ghidra
            // `ActionPrototypeTypes`, coreaction.cc:4651, and `ActionFuncLink::funcLinkInput`,
            // coreaction.cc:1483). Both containers start EMPTY: the candidates are registered per
            // heritaged range during heritage, by `guard_returns`' `characterizeAsOutput` and
            // `guard_calls`' `characterizeAsInputParam` queries over the compiler spec.
            super::recover::init_active_output(data);
            super::recover::init_active_input(data);
            // Probe pass: fully simplify a copy (heritage + rules + dead-code, no call-guards),
            // then run Ghidra's AliasChecker on the resulting graph to find which stack slots are
            // aliased — their address escapes to a call. This decides which slots heritage's
            // `guard_calls` guards, so a non-aliased local (a spilled loop variable) is never
            // guarded and its loop SSA is left intact — without a calling-convention scan.
            let boundary = {
                let mut probe = data.clone();
                probe.call_guards_active = true; // PROBE-DIAGNOSTIC
                let pdom = super::dominator::compute(&probe);
                if !super::heritage::heritage(&mut probe, &pdom) {
                    // The probe could not reach SSA, so its graph says nothing about aliasing and
                    // `alias_boundary` would report whatever the half-built form happened to show
                    // — most likely `None`, i.e. "no stack slot is aliased", which is the LEAST
                    // conservative answer available and exactly the wrong way to fail. Guard the
                    // whole stack instead: over-guarding costs SSA quality, under-guarding is how
                    // wrong code gets out.
                    //
                    // Reached by Open Watcom's `signl.c`, whose overlapping unaligned stack
                    // locations never enter SSA (task #8).
                    Some(i64::MIN)
                } else {
                    // The probe's ActiveParam/ReturnRecovery must see the same varnode marks the
                    // real mainloop pass sees: Ghidra's `AncestorRealistic` fails any input
                    // reached by the walk that `ActionDirectWrite` has not marked a direct write
                    // (funcdata_varnode.cc:2038/:2089), and in Ghidra the two DirectWrite
                    // instances (coreaction.cc:5497-5498) always precede ActionActiveParam.
                    // Without them here, a `mov eax,ebx` ← `mov ebx,eax_in` argument chain was
                    // judged no-use on the clone, `fillin_map`'s dnu-chain rule then dropped the
                    // struct-pointer register behind it, the pointer never reached the call, and
                    // the probe reported NO aliased slot — the field stores of every by-address
                    // stack struct died (WAR2 59c6c/58694/30550, oracle re-sweep).
                    super::directwrite::ActionDirectWrite::new(true).apply(&mut probe);
                    super::directwrite::ActionDirectWrite::new(false).apply(&mut probe);
                    super::recover::resolve_return(&mut probe);
                    super::recover::resolve_call_args(&mut probe);
                    // Suppress the op-action trace here: this rule pool runs on a throwaway
                    // clone for alias analysis, so its firings would double the real trace.
                    super::action::with_suppressed_trace(|| default_rule_pool().apply(&mut probe));
                    super::deadcode::ActionDeadCode.apply(&mut probe);
                    super::alias::alias_boundary(&probe)
                }
            };
            // Enable heritage's per-range call-effect guarding (Ghidra `Heritage::guardCalls`),
            // threading the alias boundary. The probe clone above heritaged with guarding OFF (the
            // default), so its boundary was computed on a graph free of the call INDIRECTs — as
            // Ghidra runs guardCalls only in the true heritage, not the AliasChecker probe.
            debug!(crate::debug::Topic::Pipeline, "== alias_boundary = {:?}", boundary);
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
/// its index in the canonical oppool1 list. Every rule here now corresponds to a Ghidra class —
/// `scripts/trace-names.py` reports an empty ADAPTATION list, and that is the invariant to keep:
/// a new rule with no Ghidra class named is the thing this pool must not grow again.
pub fn default_rule_pool() -> ActionPool {
    ActionPool::new("oppool")
        .with(RuleEarlyRemoval) // (1)
        .with(RuleTermOrder) // (2)
        .with(RuleSelectCse) // (3)
        .with(RuleCollectTerms) // (4)
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
        .with(RuleOrMask) // (17)
        .with(RuleAndMask) // (18)
        .with(RuleOrConsume) // (19)
        .with(RuleOrCollapse) // (20)
        .with(RuleAndOrLump) // (21)
        .with(RuleShiftBitops) // (22)
        .with(RuleRightShiftAnd) // (23)
        .with(RuleHighOrderAnd) // (25)
        .with(RuleAndCommute) // (27)
        .with(RuleAndPiece) // (28)
        .with(RuleAndZext) // (29)
        .with(RuleAndCompare) // (30)
        .with(RuleDoubleSub) // (31)
        .with(RuleDoubleShift) // (32)
        .with(RuleDoubleArithShift) // (33)
        .with(RuleConcatShift) // (34)
        .with(RuleShiftCompare) // (36)
        .with(RuleShift2Mult) // (37)
        .with(RuleShiftPiece) // (38)
        .with(RuleMultiCollapse) // (39)
        .with(super::rules::RuleIndirectCollapse) // (40) coreaction.cc:5551
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
        // RuleSwitchSingle (coreaction.cc:5606): a recovered switch whose block has a single
        // out-edge is not a switch — the BRANCHIND becomes a BRANCH and the table is forgotten.
        .with(RuleSwitchSingle) // (95)
        // RuleCondNegate (coreaction.cc:5607, immediately before RuleBoolNegate) is NOT wired
        // here: it fires only on a CBRANCH the structurer has marked `boolean_flip`, which is set
        // after block orientation, so it runs in the post-orientation `condnegate_pool` instead
        // (task #1 S1) — see that pool for the ordering argument.
        .with(RuleBoolNegate) // (97)
        .with(RuleLessEqual) // (98)
        .with(RuleLessNotEqual) // (99)
        // RuleLessOne (coreaction.cc:5611): `V < 1` / `V <= 0` => `V == 0` — the only non-trivial
        // answer a comparison against the unsigned range boundary has.
        .with(RuleLessOne) // (100)
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
        // RuleXorSwap (coreaction.cc:5617): `V ^ (V ^ W)` => `W`, undoing the XOR swap idiom.
        .with(RuleXorSwap) // (106)
        // RuleLzcountShiftBool (coreaction.cc:5618): `LZCOUNT(V) >> k` used as a boolean is
        // `V == 0`, when `8*|V|` is a power of two and `(8*|V|) >> k == 1`.
        .with(RuleLzcountShiftBool) // (107)
        // RuleFloatSign (coreaction.cc:5619): an integer sign-bit manipulation neighbouring a
        // float op is really FLOAT_ABS/FLOAT_NEG (TypeOp::floatSignManipulation, typeop.cc:153).
        .with(RuleFloatSign) // (108)
        .with(RuleOrCompare) // (109)
        // SubVariableFlow driving rules (coreaction.cc:5621-5628). RuleAndDistribute (5537) stays OUT
        // (RuleHumptyOr ping-pong hang). RuleSubZext is now wired at slot 74 above (its wide-return
        // regressors were cleared by the mainloop + subvar return-narrowing + Piece2Zext).
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
        // RuleSubvarSext (117, coreaction.cc:5628): the sign-extension twin, driving the
        // `sextrestrictions` tracers. Its `aggressive` argument comes from the compiler spec's
        // `<aggressivetrim signext=>`, not a constant.
        .with(RuleSubvarSext) // (117)
        // RuleNegateNegate (coreaction.cc:5629): `~~V` => `V`.
        .with(RuleNegateNegate) // (118)
        // RuleConditionalMove (coreaction.cc:5630): a 2-input MULTIEQUAL whose arms both carry
        // booleans is a conditional move — replace the control flow with `zext(c)`, `c || d`,
        // `c && d`, or a plain COPY, per which arms are literals.
        .with(RuleConditionalMove) // (119)
        // RuleOrPredicate (coreaction.cc:5631): recover a short-circuit `||` from the
        // conditionally-zeroed form — two values each zeroed on the opposite path of one
        // condition, OR'd together, collapse to a single MULTIEQUAL merging them.
        .with(super::condexe::RuleOrPredicate) // (120)
        // RuleFuncPtrEncoding (coreaction.cc:5632): drop the low-bit mask before an indirect call
        // on a target with aligned function pointers. Inert on x86 — no cspec sets `<funcptr>`,
        // so `funcptr_align` is 0 and the rule declines at its first test, as Ghidra's does.
        .with(RuleFuncPtrEncoding) // (121)
        .with(RuleFloatCast) // (123) floatprecision group
        .with(RuleIgnoreNan) // (124) floatprecision group
        // The unsigned-int-to-float pair (coreaction.cc:5636-5637), for hardware that only
        // converts signed integers: RuleUnsigned2Float collapses the arithmetic form
        // (halve-convert-double), RuleInt2FloatCollapse the branching one (a MULTIEQUAL joining a
        // signed and an unsigned conversion under a sign test). Both rewrite to the single
        // `FLOAT_INT2FLOAT(ZEXT(V))` the printer renders as an unsigned cast.
        .with(RuleUnsigned2Float) // (125)
        .with(RuleInt2FloatCollapse) // (126)
        // Ghidra's actprop slot for RulePtraddUndo (coreaction.cc:5638), immediately after the
        // float group — NOT actprop2, where RulePushPtr/RulePtrArith live (:5664/5666). The
        // separation is load-bearing: this rule undoes a mis-typed PTRADD here, and RulePtrArith
        // may legitimately rebuild one later in the pass with the element size read from the
        // current type.
        .with(super::ptrarith::RulePtraddUndo) // (127)
        // RulePtrsubUndo (coreaction.cc:5639), the PTRSUB counterpart: a PTRSUB asserts its base
        // type has a component at the offset, so when type recovery says otherwise the op goes
        // back to an INT_ADD — along with everything stacked below it that was built on the same
        // wrong type (`removeLocalAdds`). The offset checked includes what is added BELOW the
        // PTRSUB (`getExtraOffset`), so a component exceeded only after further additions is
        // caught too.
        .with(super::ptrarith::RulePtrsubUndo)
        // RulePiecePathology (coreaction.cc:5642): a CONCAT whose upper half is the untouched high
        // bytes of a partially-written register is a pathology, not a value. It rewrites nothing —
        // it records how many bytes are real at each CALL argument and RETURN, which the dead-code
        // consume sweep then reads (see `consume.rs`).
        .with(RulePiecePathology) // (130)
        // The double-precision LOAD/STORE recombiners sit at Ghidra's oppool1 tail (coreaction.cc:
        // 5643-5644, after RulePiecePathology :5642 — not ported). RuleDoubleStore is dormant until
        // a PRECISLO/PRECISHI marker port lands (ActionParamDouble / SplitVarnode markings); the
        // remaining family members RuleDoubleIn/RuleDoubleOut (:5645-5646) need combineInputVarnodes
        // and join with their own port.
        .with(super::double::RuleDoubleLoad) // (125) doubleload group
        .with(super::double::RuleDoubleStore) // (126) doubleprecis group
        // RuleDoubleOut (coreaction.cc:5646): a PIECE of two contiguous persistent INPUTs is a
        // double-precision parameter that arrived as halves — fuse them into one wider input. Its
        // `attemptMarking` arm is also what SETS the PRECISLO/PRECISHI markers, which is what
        // RuleDoubleStore above has been waiting for (it was PORTED-DORMANT until now).
        // RuleDoubleIn (coreaction.cc:5645): the SUBPIECE side — a marked low half feeds the
        // SplitVarnode engine, which finds arithmetic done on the pair and rewrites it as one
        // whole-width operation. Wired BEFORE RuleDoubleOut, as Ghidra registers it.
        .with(super::double::RuleDoubleIn) // (134)
        .with(super::double::RuleDoubleOut) // (135)
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
        // No alias analysis has run at this slot (mosura-only pass, before the first
        // restructure): reconcile addrtied/addrforce, but do not pre-mark `nolocalalias` —
        // Ghidra sets that only under `unmappedAliasCheck` (the aliasyes restructure passes).
        super::varnodeprops::mark_addrtied(data, false);
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
            // One gather feeds both consumers: the boundary approximation (heritage's
            // `guard_calls` holdind) and the full sorted alias-offset list that
            // `mark_addrtied`'s `markUnaliased` walk needs (varmap.cc:1332).
            let offsets = super::alias::aliased_stack_offsets(data);
            data.alias_boundary = offsets.iter().min().copied();
            let canonical: Option<Vec<u64>> = data.spaces.by_name("stack").map(|stack| {
                let mut v: Vec<u64> =
                    offsets.iter().map(|&o| data.spaces.get(stack).wrap_offset(o as u64)).collect();
                v.sort_unstable();
                v
            });
            data.alias_offsets = canonical;
        }
        super::varnodeprops::mark_addrtied(data, aliasyes);
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
/// (`RuleLoadVarnode`/`RuleStoreVarnode` stack) branch this enables is LIVE (task #22-B Brick 1
/// `41ab722` ported it dormant; Brick 2 `47d082f` activated it by retiring recover_stack's general
/// LOAD/STORE arms, so stack accesses now reach the pool instead of being pre-resolved).
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

/// Ghidra `ActionExtraPopSetup` (coreaction.cc, group `base`, slot :5477): model the stack
/// pointer's change across each call, so later stack analysis sees a value it can reason about.
///
/// Two shapes, and the difference matters. A KNOWN extrapop becomes `sp = sp + n` inserted AFTER
/// the call, because the change is exact. An UNKNOWN one becomes an `INDIRECT` on the stack pointer
/// inserted BEFORE the call — the value afterwards is indeterminate, and saying "unchanged" would
/// be a lie the stack recovery would then build on. WAR2's `__watcall` is the unknown case;
/// x86-64-gcc's `__stdcall` is the known one (8).
/// Ghidra `ActionConstbase::apply` (coreaction.cc:678), tracked-set half: for each register the
/// pspec's `<tracked_set>` declares a default value for (x86 = `DF=0`), insert `reg = COPY val` at
/// the START of the entry block. Heritage SSA-ifies it and constant propagation flows the value
/// forward — collapsing e.g. a `rep`-string stride `size*(zext(DF)*-2+1)` to `size*(+1)`. The op
/// idiom (`new_const` + `new_op(Copy)` + `new_output` + `op_insert_begin`) mirrors
/// [`ActionExtraPopSetup`] below. Inert when the pspec tracks nothing (empty `tracked_context`).
fn apply_tracked_context(data: &mut Funcdata) {
    if data.tracked_context.is_empty() || data.num_blocks() == 0 {
        return;
    }
    let Some(reg) = data.spaces.by_name("register") else { return };
    let entry = super::block::BlockId(0);
    let pc = data.addr; // the entry address (Ghidra `bb->getStart()`)
    for (offset, size, val) in data.tracked_context.clone() {
        let uniq = data.num_ops() as u32;
        let cst = data.new_const(size, val);
        let op = data.new_op(super::opcode::OpCode::Copy, super::op::SeqNum { pc, uniq }, vec![cst]);
        data.new_output(op, size, super::space::Address::new(reg, offset));
        data.op_insert_begin(op, entry);
    }
}

pub struct ActionExtraPopSetup;

impl Action for ActionExtraPopSetup {
    fn name(&self) -> &str {
        "extrapopsetup"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        use super::fspec::EXTRAPOP_UNKNOWN;
        // The containing model's extrapop is only the FALLBACK: Ghidra gates per call on
        // `fc->getExtraPop() == 0` (coreaction.cc:1447), never on the evaluation model, so a
        // call with recovered extrapop is modelled even under a zero-extrapop model.
        let extrapop = data.proto_model.extrapop;
        // Ghidra reads the stack space's spacebase register (`stackspace->getSpacebase(0)`).
        let Some(stack) = data.spaces.by_name("stack") else { return 0 };
        let Some(&(sb_addr, sb_size)) = data.spaces.get(stack).spacebase.first() else {
            return 0; // no stack to speak of
        };
        // Ghidra walks `data.numCalls()`/`getCallSpecs(i)` — an ORDERED vector, in call order.
        // mosura keys call specs by OpId in a HashMap, whose iteration order is randomized per
        // process, so the keys must be sorted or the pass is nondeterministic. (It is: leaving
        // this unsorted made 11 of 3023 WAR2 functions emit differently between two runs of an
        // otherwise identical build.) OpId is creation order, which for calls is program order.
        let mut calls: Vec<super::op::OpId> = data.call_specs.keys().copied().collect();
        calls.sort();
        let mut count = 0;
        for call in calls {
            if data.op(call).is_dead() {
                continue;
            }
            // Ghidra reads `fc->getExtraPop()` -- the CALL's own extrapop, which
            // `ActionDefaultParams` seeds from the callee's prototype when one is known
            // (coreaction.cc:2327 copies the whole proto, extrapop included). mosura's per-call
            // value is recovered from the callee's own RET by the whole-program pass; a call
            // without one falls back to the containing model's, exactly as before.
            let extrapop = data.call_specs.get(&call).and_then(|c| c.extrapop).unwrap_or(extrapop);
            // `recover_stack`'s call-mechanism model may have already cancelled this call's
            // return-address push; the delta left to model is what the callee pops BEYOND the
            // return address (see `CallSpec::push_neutralized`). Without the subtraction the
            // known case inserts `esp + 4` on top of the cancelled push — the same ret-pop
            // double-count the solver's guess had.
            let neutralized =
                data.call_specs.get(&call).and_then(|c| c.push_neutralized).unwrap_or(0) as i32;
            let extrapop =
                if extrapop != EXTRAPOP_UNKNOWN { extrapop - neutralized } else { extrapop };
            if extrapop == 0 {
                continue;
            }
            let pc = data.op(call).seqnum.pc;
            let uniq = data.num_ops() as u32;
            let sp_in = data.new_varnode(sb_size, sb_addr);
            if extrapop != EXTRAPOP_UNKNOWN {
                // We know exactly how the stack pointer changes.
                let k = data.new_const(sb_size, extrapop as u64);
                let op = data.new_op(super::opcode::OpCode::IntAdd, super::op::SeqNum { pc, uniq }, vec![sp_in, k]);
                data.new_output(op, sb_size, sb_addr);
                data.op_insert_after(op, call);
                if let Some(cs) = data.call_specs.get_mut(&call) {
                    cs.effective_extrapop = Some(extrapop);
                }
            } else {
                // We do not know exactly, so the value afterwards is indeterminate.
                let op = data.new_op(super::opcode::OpCode::Indirect, super::op::SeqNum { pc, uniq }, vec![sp_in]);
                data.op_mut(op).guarded_op = Some(call); // Ghidra's `newVarnodeIop(fc->getOp())`
                data.new_output(op, sb_size, sb_addr);
                data.op_insert_before(op, call);
            }
            count += 1;
        }
        debug_assert!(count <= data.call_specs.len());
        0 // Ghidra `ActionExtraPopSetup::apply` returns 0 unconditionally (coreaction.cc:1465)
    }
}

/// Ghidra `ActionLikelyTrash::traceTrash` (coreaction.cc:2047): follow every path out of `vn` and
/// report whether all of them end in a "trash sink" — an INDIRECT that is not an indirect-store, or
/// an INT_AND that keeps only the topmost significant bytes. The sinks found are collected in
/// `indlist`; a single non-sink use anywhere makes the whole trace fail.
fn trace_trash(data: &mut Funcdata, vn: super::varnode::VarnodeId, indlist: &mut Vec<super::op::OpId>) -> bool {
    use super::opcode::OpCode;
    let mut allroutes: Vec<super::op::OpId> = Vec::new(); // merging ops (more than one input)
    let mut markedlist: Vec<super::varnode::VarnodeId> = vec![vn];
    data.vn_mut(vn).set_mark();
    let mut traced = 0;
    let mut istrash = true;

    'outer: while traced < markedlist.len() {
        let curvn = markedlist[traced];
        traced += 1;
        for op in data.vn(curvn).descend.clone() {
            let Some(outvn) = data.op(op).output else {
                istrash = false;
                break 'outer;
            };
            match data.op(op).code() {
                OpCode::Indirect => {
                    if data.vn(outvn).is_persist() {
                        istrash = false;
                    } else if data.op(op).is_indirect_store() {
                        if !data.vn(outvn).is_mark() {
                            data.vn_mut(outvn).set_mark();
                            markedlist.push(outvn);
                        }
                    } else {
                        indlist.push(op);
                    }
                }
                OpCode::Subpiece => {
                    if data.vn(outvn).is_persist() {
                        istrash = false;
                    } else if !data.vn(outvn).is_mark() {
                        data.vn_mut(outvn).set_mark();
                        markedlist.push(outvn);
                    }
                }
                OpCode::Multiequal | OpCode::Piece => {
                    if data.vn(outvn).is_persist() {
                        istrash = false;
                    } else {
                        if !data.op(op).is_mark() {
                            data.op_mut(op).set_mark();
                            allroutes.push(op);
                        }
                        // Only follow a merge once EVERY input has been reached.
                        let nummark = (0..data.op(op).num_inputs())
                            .filter(|&i| {
                                data.op(op).input(i).is_some_and(|v| data.vn(v).is_mark())
                            })
                            .count();
                        if nummark == data.op(op).num_inputs() && !data.vn(outvn).is_mark() {
                            data.vn_mut(outvn).set_mark();
                            markedlist.push(outvn);
                        }
                    }
                }
                OpCode::IntAnd => {
                    // An AND that keeps ONLY the topmost significant bytes is a trash sink.
                    let mut sink = false;
                    if let Some(k) = data.op(op).input(1) {
                        if data.vn(k).is_constant() {
                            let sz = data.vn(k).size;
                            let mask = if sz >= 8 { u64::MAX } else { (1u64 << (8 * sz)) - 1 };
                            let val = data.vn(k).constant_value();
                            sink = val == ((mask << 8) & mask)
                                || val == ((mask << 16) & mask)
                                || val == ((mask << 32) & mask);
                        }
                    }
                    if sink {
                        indlist.push(op);
                    } else {
                        istrash = false;
                    }
                }
                _ => istrash = false,
            }
            if !istrash {
                break 'outer;
            }
        }
    }

    for &op in &allroutes {
        // A merge whose output was never reached means not all its inputs were seen.
        if data.op(op).output.is_some_and(|o| !data.vn(o).is_mark()) {
            istrash = false;
        }
        data.op_mut(op).clear_mark();
    }
    for &v in &markedlist {
        data.vn_mut(v).clear_mark();
    }
    istrash
}

/// Ghidra `ActionVarnodeProps` (coreaction.cc:1282, group `base`, slot :5491): a varnode whose
/// non-zero bits are entirely unconsumed downstream carries no information, so every read of it
/// becomes a read of the constant 0.
///
/// This is NOT `Funcdata::setVarnodeProperties` (funcdata_varnode.cc:25) — the mapped/addrtied/
/// persist lookup mosura ported as `varnodeprops.rs`'s `ActionMarkAddrTied`. Ghidra's action has
/// three arms and only the third is portable today; the other two are cited rather than faked:
///
/// * **auto-live-hold** (coreaction.cc:1296): clear `auto_live_hold` once a heritage pass has run,
///   unless the varnode is a LOAD through a constant or read-only pointer. mosura models no
///   `auto_live_hold` flag. BLOCKED(auto_live_hold).
/// * **action properties** (coreaction.cc:1318): `fillinReadOnly` substitutes the value straight
///   out of the load image, and `replaceVolatile` rewrites a volatile access as a CALLOTHER.
///   mosura has `Funcdata::is_read_only` but no fill-in, and models no volatile varnodes.
///   BLOCKED(readonly fill-in / volatile model).
///
/// The third arm needs only `nzmask` and `consume`, which mosura computes
/// ([`super::consume::calc_consume`]), so it stands alone.
pub struct ActionVarnodeProps;

impl Action for ActionVarnodeProps {
    fn name(&self) -> &str {
        "varnodeprops"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        let mut count = 0;
        for vn in (0..data.num_varnodes() as u32).map(super::varnode::VarnodeId) {
            let v = data.vn(vn);
            if v.is_annotation() || v.size as usize > std::mem::size_of::<u64>() {
                continue;
            }
            if v.get_nzmask() & v.consume != 0 {
                continue;
            }
            if v.is_constant() {
                continue; // don't replace a constant
            }
            if let Some(def) = v.def {
                if data.op(def).code() == super::opcode::OpCode::Copy {
                    // Don't replace a COPY of 0 with a zero — let constant propagation do it, or
                    // the two rewrite each other forever (Ghidra's infinite-recursion note).
                    if let Some(in0) = data.op(def).input(0) {
                        if data.vn(in0).is_constant() && data.vn(in0).constant_value() == 0 {
                            continue;
                        }
                    }
                }
            }
            if data.vn(vn).descend.is_empty() {
                continue; // `hasNoDescend`: nothing reads it, so there is nothing to replace
            }
            data.total_replace_constant(vn, 0);
            count += 1;
        }
        count
    }
}

/// Ghidra `ActionBlockStructure` (blockaction.cc:2169, group `blockrecovery`, mainloop slot
/// :5659): build the structured block hierarchy if the CFG changed since it was last built.
/// `graph.getSize() != 0` maps to the cache being `Some`; `installSwitchDefaults`
/// (funcdata_block.cc:687, the jump tables' default-edge marks) is derived inside mosura's
/// `structure()` build from the jumptable records, so the slot's ordering obligation is met by
/// construction. The returned collapse count drives the mainloop repeat exactly as Ghidra's
/// `count += collapse.getChangeCount()` does — a CFG change late in an iteration buys one more
/// quiescing round over the settled graph.
pub struct ActionBlockStructure;

impl Action for ActionBlockStructure {
    fn name(&self) -> &str {
        "blockstructure"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        if data.structure.is_some() {
            return 0; // already structured, CFG unchanged (Ghidra blockaction.cc:2175)
        }
        if data.num_blocks() == 0 {
            return 0;
        }
        let s = super::structure::structure(data);
        // Freeze the first collapse's per-block complexity verdicts (Ghidra collapses once per
        // CFG and never revisits them; see `Funcdata::structure_complex`). Later re-deriving
        // builds (orientation stages, FinalStructure, printc's fallback) reuse this vector.
        if data.structure_complex.is_none() {
            data.structure_complex = Some(s.complex.clone());
        }
        let count = s.collapse_count;
        data.structure = Some(s);
        count
    }
}

/// Ghidra `ActionFinalStructure` (blockaction.cc:2186, slot after `ActionSetCasts`): the final
/// structuring pass whose result the printer emits. Ghidra's runs `orderBlocks`/
/// `finalizePrinting`/`scopeBreak`/`markUnstructured`/`markLabelBumpUp` over the persistent
/// graph; mosura's `structure()` build performs all of those internally, so this slot builds
/// (or keeps) the cache that `printc` then consumes instead of re-deriving.
pub struct ActionFinalStructure;

impl Action for ActionFinalStructure {
    fn name(&self) -> &str {
        "finalstructure"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        if data.structure.is_none() && data.num_blocks() != 0 {
            data.structure = Some(super::structure::structure(data));
        }
        0
    }
}

/// Ghidra `ActionStartCleanUp` (coreaction.hh:58, group `cleanup`, slot :5692): mark the start of
/// the clean-up phase by stamping the varnode creation index.
///
/// The whole body is `data.startCleanUp()`. Worth noting rather than hiding: in Ghidra 12.0.3 the
/// companion `Funcdata::getCleanUpIndex()` has **no callers anywhere** in the decompiler, so the
/// watermark is written and never read. It is ported anyway — it is a real member of
/// `universalAction` and the state is cheap and correct, so a future consumer of the index finds
/// it already there instead of the action being a silent roster gap.
pub struct ActionStartCleanUp;

impl Action for ActionStartCleanUp {
    fn name(&self) -> &str {
        "startcleanup"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        data.start_clean_up();
        0 // Ghidra's apply returns 0 (coreaction.hh:66)
    }
}

/// Ghidra `ActionLikelyTrash` (coreaction.cc:2140, group `protorecovery`, slot :5679): a register
/// the calling convention marks as likely holding caller garbage, and every one of whose uses is a
/// trash sink, has its data flow cut — the INDIRECT becomes an indirect *creation* and the
/// masking AND's constant becomes zero.
///
/// Driven by the cspec's `<likelytrash>` element (`ProtoModel::likelytrash`). x86-32-watcom (WAR2)
/// and x86-64-gcc (the corpus) declare none, so this is inert on both of mosura's targets;
/// x86win, x86gcc, x86borland, x86delphi and x86-32-golang declare it.
pub struct ActionLikelyTrash;

impl Action for ActionLikelyTrash {
    fn name(&self) -> &str {
        "likelytrash"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        let trash = data.proto_model.likelytrash.clone();
        let mut count = 0;
        for (addr, size) in trash {
            let Some(vn) = data.find_covered_input(size, addr) else { continue };
            if data.vn(vn).is_typelock() || data.vn(vn).is_namelock() {
                continue;
            }
            let mut indlist: Vec<super::op::OpId> = Vec::new();
            if !trace_trash(data, vn, &mut indlist) {
                continue;
            }
            for op in indlist {
                match data.op(op).code() {
                    super::opcode::OpCode::Indirect => {
                        // Truncate data flow through the INDIRECT, turning it into an indirect
                        // creation.
                        let sz = data.op(op).output.map(|o| data.vn(o).size).unwrap_or(0);
                        let k = data.new_const(sz, 0);
                        data.op_set_input(op, 0, k);
                        data.mark_indirect_creation(op, false);
                    }
                    super::opcode::OpCode::IntAnd => {
                        let sz = data.op(op).input(1).map(|v| data.vn(v).size).unwrap_or(0);
                        let k = data.new_const(sz, 0);
                        data.op_set_input(op, 1, k);
                    }
                    _ => {}
                }
                count += 1;
            }
        }
        count
    }
}

/// Ghidra `ActionParamDouble` (coreaction.cc:1597, group `protorecovery`): a call argument built
/// by a `PIECE` whose two halves are each a parameter in their own right is split back into two
/// arguments.
///
/// Ghidra's `apply` has three blocks. Only the first — the SPLIT of an active input trial — is
/// ported; the other two are gated on subsystems mosura does not have, and are cited rather than
/// approximated:
///
/// * **join** (`!isInputLocked() && isDoublePrecisOn()`, coreaction.cc:1636): fuses two adjacent
///   argument slots that are the halves of one double-precision value. It needs
///   `FuncCallSpecs::doInputJoin` → `Architecture::constructJoinAddress` and
///   `ParamActive::joinTrial`, i.e. the **JOIN address space**, which mosura has no counterpart
///   for (`ParamEntry` models no join records either). BLOCKED(join space).
/// * **locked-parameter split** (coreaction.cc:1667): searches a *locked* prototype's parameters
///   for hi/lo components. mosura has no locked prototype parameters in a batch decompile, so the
///   block has nothing to iterate. BLOCKED(locked prototypes).
///
/// The split block is independent of both: it reads only the active trial container and the
/// model's input `ParamList`, so porting it alone lands a whole mechanism, not half of one.
pub struct ActionParamDouble;

impl Action for ActionParamDouble {
    fn name(&self) -> &str {
        "paramdouble"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        let Some(input) = data.proto_model.input.clone() else { return 0 };
        // Ghidra's `spc->getType() != IPTR_SPACEBASE` test: only a stack-space trial splits here.
        let Some(stack) = data.spaces.by_name("stack") else { return 0 };
        // Ghidra walks `data.numCalls()`/`getCallSpecs(i)` — an ORDERED vector, in call order.
        // mosura keys call specs by OpId in a HashMap, whose iteration order is randomized per
        // process, so the keys must be sorted or the pass is nondeterministic. (It is: leaving
        // this unsorted made 11 of 3023 WAR2 functions emit differently between two runs of an
        // otherwise identical build.) OpId is creation order, which for calls is program order.
        let mut calls: Vec<super::op::OpId> = data.call_specs.keys().copied().collect();
        calls.sort();
        let mut count = 0;
        for call in calls {
            if data.op(call).is_dead() || !data.is_input_active(call) {
                continue;
            }
            let mut j = 0;
            loop {
                let Some(active) = data.active_inputs.get(&call) else { break };
                if j >= active.trial.len() {
                    break;
                }
                let t = &active.trial[j];
                // Ghidra skips trials already investigated or with no reference.
                if t.is_checked() || t.is_unref() || t.addr.space != stack {
                    j += 1;
                    continue;
                }
                let (taddr, tsize, slot) = (t.addr, t.size, t.slot as usize);
                let Some(vn) = data.op(call).input(slot) else {
                    j += 1;
                    continue;
                };
                if !data.vn(vn).is_written() {
                    j += 1;
                    continue;
                }
                let concatop = data.vn(vn).def.expect("written");
                if data.op(concatop).code() != super::opcode::OpCode::Piece {
                    j += 1;
                    continue;
                }
                // Ghidra's `!fc->hasModel()` bail-out: mosura always carries a prototype model, so
                // the check is structurally satisfied here.
                let mostvn = data.op(concatop).input(0).expect("PIECE input 0");
                let leastvn = data.op(concatop).input(1).expect("PIECE input 1");
                // Little-endian: the split size is the LEAST significant piece's size.
                let splitsize = data.vn(leastvn).size;
                if !input.check_split(taddr, tsize, splitsize) {
                    j += 1;
                    continue;
                }
                debug!(crate::debug::Topic::Args, "split trial {j} at {:x} size {tsize} -> {splitsize}", taddr.offset);
                data.active_inputs.get_mut(&call).expect("checked").split_trial(j, splitsize);
                data.op_insert_input(call, slot, leastvn);
                data.op_set_input(call, slot + 1, mostvn);
                count += 1;
                // Ghidra decrements j so a nested CONCAT is checked at the same index.
            }
        }
        count
    }
}

/// Ghidra `ActionUnjustifiedParams` (coreaction.cc:4784, group `protorecovery`): widen any
/// function input that the calling convention says is *improperly justified* within its parameter
/// container.
///
/// An input varnode may land partway into a parameter's storage — a sub-range that does not start
/// where a parameter of that size starts under the convention. Leaving it that way gives the
/// function an input that is not a parameter. Instead the containing storage becomes the input,
/// and the original is carved back out as a `SUBPIECE` (`Funcdata::adjust_input_varnodes`).
///
/// The inner loop is Ghidra's container-growing fixpoint: after choosing a container, any *other*
/// input that overlaps it and extends past its start grows the container leftwards, and the grown
/// container is re-tested for justification — repeating until it stops growing.
pub struct ActionUnjustifiedParams;

impl Action for ActionUnjustifiedParams {
    fn name(&self) -> &str {
        "unjustifiedparams"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        // Ghidra reads `data.getFuncProto().unjustifiedInputParam`, which consults locked
        // parameters first and otherwise delegates to the model's input ParamList
        // (fspec.cc:4426-4452). mosura has no locked prototype parameters in a batch decompile, so
        // only the model delegation exists; the locked pre-check joins when user prototypes do.
        let Some(input) = data.proto_model.input.clone() else { return 0 };
        let mut count = 0;
        let mut done: Vec<(super::space::Address, u32)> = Vec::new();
        loop {
            // Ghidra walks `beginDef(Varnode::input)` and restarts the iterator after each
            // adjustment (the additions and deletions invalidate it); mosura re-collects instead.
            let inputs: Vec<super::varnode::VarnodeId> = (0..data.num_varnodes() as u32)
                .map(super::varnode::VarnodeId)
                .filter(|&v| data.vn(v).is_input())
                .collect();
            let mut adjusted = false;
            for v in inputs {
                let (loc, size) = (data.vn(v).loc, data.vn(v).size);
                let Some((mut caddr, mut csize)) = input.unjustified_container(loc, size) else {
                    continue;
                };
                if done.contains(&(caddr, csize)) {
                    continue; // already widened to this container
                }
                loop {
                    // Grow the container over any other input that overlaps it and starts earlier.
                    let mut overlaps = false;
                    for w in (0..data.num_varnodes() as u32).map(super::varnode::VarnodeId) {
                        let wn = data.vn(w);
                        if !wn.is_input() || wn.loc.space != caddr.space {
                            continue;
                        }
                        let last = wn.loc.offset + (wn.size as u64 - 1);
                        if last >= caddr.offset && wn.loc.offset < caddr.offset {
                            overlaps = true;
                            let endpoint = caddr.offset + csize as u64;
                            caddr = super::space::Address::new(caddr.space, wn.loc.offset);
                            csize = (endpoint - caddr.offset) as u32;
                        }
                    }
                    if !overlaps {
                        break; // no additional overlaps, go with the current container
                    }
                    // Having grown, the container may no longer be justified itself.
                    match input.unjustified_container(caddr, csize) {
                        Some((a, s)) => {
                            caddr = a;
                            csize = s;
                        }
                        None => break,
                    }
                }
                debug!(crate::debug::Topic::Args, "widen {:?}+{:x} size {} (from {:?}+{:x}/{})",
                        caddr.space, caddr.offset, csize, loc.space, loc.offset, size);
                data.adjust_input_varnodes(caddr, csize);
                done.push((caddr, csize));
                count += 1;
                adjusted = true;
                break; // the varnode set changed; re-collect
            }
            if !adjusted {
                break;
            }
        }
        count
    }
}

/// Ghidra `ActionInputPrototype` (coreaction.cc:4707, group `fixateproto`, placed at :5731): the
/// model-resolution half — see [`super::fspec::resolve_model`]. Counts 1 when the model changed.
pub struct ActionInputPrototype;

impl Action for ActionInputPrototype {
    fn name(&self) -> &str {
        "inputprototype"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        // Ghidra's returns 0 (coreaction.cc:4707-4760): no graph change, nothing to count.
        super::fspec::resolve_model(data);
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
    // Label distinct from RulePtrArith's own `ptrarith`: the OPACTION_DEBUG trace prints actions and
    // rules in one format, so a pool sharing a rule's name makes a firing unattributable (and
    // `--debug opaction=<name>` ambiguous). scripts/trace-names.py audits for that collision.
    ActionPool::new("ptrarithpool")
        .with(RuleConstFold)
        .with(RulePropagateCopy)
        // Ghidra actprop2 order (coreaction.cc:5664/5666): RulePushPtr normalizes a pointer to the
        // bottom of its additive expression, then RulePtrArith converts.
        .with(super::ptrarith::RulePushPtr)
        .with(super::ptrarith::RulePtrArith)
        // Ghidra actprop2 order (coreaction.cc:5666-5669): RulePtrArith, then RuleLoadVarnode,
        // RuleStoreVarnode. BOTH branches of the spacebase model are live through one shared
        // `check_spacebase`: the ram-global const-offset branch (task #7 S1) and the
        // spacebase-register `RSP_input [+ const]` branch (task #22-B Bricks 1-2). The strict
        // `correctSpacebase !isInput` boundary declines a COPY-of-RSP, a MULTIEQUAL-of-RSP and any
        // indexed pointer, leaving them indirect as Ghidra does.
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
        // RuleDumptyHumpLate (coreaction.cc:5698): `SUB(PIECE(a,b),k)` reads the component
        // directly — the concatenation taken apart again.
        .with(RuleDumptyHumpLate)
        .with(RuleSubRight)
        // RuleFloatSignCleanup (coreaction.cc:5700): the post-type-inference twin of
        // RuleFloatSign — a sign manipulation whose result is TYPED float needs no neighbouring
        // float op to be recognized.
        .with(RuleFloatSignCleanup)
        // RuleExpandLoad (coreaction.cc:5701): a LOAD reading only part of what its pointer points
        // at is widened to the whole value, the narrow value recovered by a SUBPIECE — or, in the
        // mask-and-compare shape, by shifting the masks instead.
        .with(RuleExpandLoad)
        // RulePtrsubCharConstant (coreaction.cc:5702): a PTRSUB off a spacebase resolving to a
        // read-only address that holds a string is really a pointer constant. Inert until global
        // symbol management exists (mosura registers only the stack spacebase, never read-only),
        // but ported and wired so it is correct when the producer lands — see docs/coverage.md.
        .with(RulePtrsubCharConstant)
        // RuleExtensionPush (coreaction.cc:5703): an extension feeding several PTRADD readers is
        // duplicated into each, so it prints inline instead of forcing a temporary.
        .with(RuleExtensionPush)
        // RulePieceStructure (coreaction.cc:5704): a CONCAT tree that is really building a
        // STRUCTURE is split along the structure's own field boundaries. Inert until type recovery
        // ever gives a value a struct/array type (measured: 0 such varnodes on the corpus), but
        // ported and wired so it is correct when that lands — see docs/coverage.md.
        .with(RulePieceStructure)
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

/// The universal decompile action: heritage, simplification, dead-code removal, then type recovery
/// and the pointer-arithmetic rewrite (PTRADD/PTRSUB), a cleanup pass, and a final dead-code sweep.
pub fn universal_action() -> ActionGroup {
    ActionGroup::once("decompile")
        // ONE priming heritage pass — Ghidra has no pre-mainloop ActionHeritage at all, and this
        // single invocation is what makes mosura's rotation of `actmainloop` an EXACT rotation.
        // Ghidra runs ActionHeritage at the HEAD of the mainloop (coreaction.cc:5492), so its
        // sequence is `H [rest] H [rest] …`; mosura moved ActionHeritage to the tail, so priming with
        // exactly one invocation reproduces the same sequence. Wrapping the prime in a restart group
        // instead ran heritage TO COMPLETION first — `H H [rest] H [rest] …` — which is a different
        // pipeline, and specifically one with NO rule pool between the register pass and the stack
        // pass.
        //
        // That gap is not cosmetic: it is the entire window the stack-pointer placeholder lives in.
        // ActionFuncLink hangs a placeholder LOAD off every call, heritage's REGISTER pass links its
        // free spacebase reference to the value reaching the call, the pools fold that to
        // `<sp_input> + delta` and RuleLoadVarnode reads `delta` out — and then the STACK pass
        // consumes it (`clear_stack_placeholders`, then guardCalls registering stack trials against
        // the now-known offset). With both passes back-to-back the placeholder was cleared before any
        // rule could ever resolve it, so no call site could learn its stack offset and mosura
        // registered zero STACK input trials anywhere.
        .then(ActionHeritage)
        // The rest of the priming prefix — Ghidra's mainloop members between ActionHeritage
        // (:5492) and ActionRestrictLocal (:5502), so that entering the mainloop at RestrictLocal
        // is an EXACT rotation from the first iteration on: ActionParamDouble (:5493), the two
        // ActionDirectWrite (:5497-5498) whose marks the first ActionDeadCode's addrforce-clear
        // reads, then ActionResolveCalls (= ActionActiveParam + ActionReturnRecovery,
        // :5499-5500). Without these the first mainloop iteration ran RestrictLocal/DeadCode with
        // no directwrite marks at all. (Segmentize/InternalStorage/ForceGoto are unported;
        // ActionUnreachable (:5490) cannot precede the priming heritage because mosura builds the
        // CFG inside ActionHeritage's first call — its mainloop instance covers later cycles.)
        .then(ActionParamDouble)
        .then(super::directwrite::ActionDirectWrite::new(true))
        .then(super::directwrite::ActionDirectWrite::new(false))
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
        // - ActionNonzeroMask → ActionInferTypes (:5507-5508): the analysis recomputes,
        //   refreshed every iteration as Ghidra does; the consume masks NonzeroMask reads are
        //   recomputed by the :5503 ActionDeadCode earlier in the same iteration (consume is the
        //   analysis half of Ghidra's ActionDeadCode, coreaction.cc:3925+, and runs inside
        //   mosura's ActionDeadCode too — the slot the parked consume-default brick re-uses). InferTypes-in-the-loop is what forms the clean array subscript (task
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
        //   in the same iteration (the #22-B ordering evidence). ActionNodeJoin (:5674) and
        //   ActionConditionalExe (:5675) are both wired here.
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
                        // Ghidra `ActionRestrictLocal` (:5502) runs BEFORE the deadcode (:5503)
                        // that collects the callee-save chain, so what it observes is the graph
                        // left by the PREVIOUS iteration's pool.
                        .then(super::restrictlocal::ActionRestrictLocal)
                        // ActionDeadCode at Ghidra's :5503 — INSIDE the mainloop, after
                        // RestrictLocal and BEFORE restructure/spacebase/nzmask/infertypes and the
                        // pools, so every pool pass runs on a dead-code-swept graph. The slot is
                        // load-bearing for RULE OUTCOMES, not just hygiene — verified on WAR2
                        // FUN_0002a4f0 with parallel OPACTION_DEBUG traces: this sweep kills the
                        // imul's dead flag web (CF = INT_NOTEQUAL(SEXT48(lo), product)), which
                        // makes the wide product lone-descended, which lets RuleSubCommute narrow
                        // the multiply and then the divide. With the slot empty the flag web
                        // survived into the pool, subcommute's loneDescend guard declined, and
                        // subzext/doublesub took the IR down a path where the divide stays 8-byte
                        // (docs/compilable-c-remediation.md, CORRECTION 2). The action recomputes
                        // the consume masks itself (as Ghidra's does), so ActionNonzeroMask below
                        // reads fresh masks — Ghidra's :5503 -> :5507 order.
                        .then(super::deadcode::ActionDeadCode)
                        .then(ActionRestructureVarnode::default())
                        .then(ActionSpacebase)
                        .then(ActionNonzeroMask)
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
                        // ported: ActionDeindirect (:5655).
                        // ActionMultiCse (:5653) and ActionShadowVar (:5654) are in place, in
                        // Ghidra's order directly after LaneDivide.
                        .then(
                            ActionGroup::restart("stackstall")
                                .then(default_rule_pool())
                                .then(OncePerFunc::new(super::lanedivide::ActionLaneDivide))
                                .then(super::multicse::ActionMultiCse)
                                // ActionShadowVar (:5654, group `analysis`): a MULTIEQUAL that
                                // merely shadows an earlier one in the same block — same inputs in
                                // the same branch order — becomes a COPY of it.
                                .then(super::multicse::ActionShadowVar)
                                // ActionStackPtrFlow (:5656, group `stackptrflow`): repair stack-
                                // pointer clogs, then run the linear analysis that resolves the
                                // stack-pointer change across calls whose extrapop is unknown. It
                                // is the consuming half of `ActionExtraPopSetup` — it rewrites the
                                // INDIRECTs that action plants into solved `sp_input + const` adds.
                                .then(super::stackvars::ActionStackPtrFlow::default()),
                        )
                        // Ghidra ActionRedundBranch (:5658, "deadcontrolflow"), directly after
                        // actstackstall: splice single-in/single-out block pairs and drop branches
                        // whose exits all reach the same block.
                        // Ghidra :5658-:5666: RedundBranch, BlockStructure, ConstantPtr,
                        // actprop2 — no dead-code member between them (a deadcode here was a
                        // rotation-era addition, removed when the real :5503 slot was restored).
                        .then(super::determinedbranch::ActionRedundBranch)
                        .then(ActionBlockStructure)
                        // ActionConstantPtr (:5665, group `typerecovery`): infer constants that
                        // are really data-space pointers, rewriting them to
                        // `PTRSUB(<ram spacebase>, #addr)` so actprop2's RulePtrArith below folds
                        // global address arithmetic the same pass, exactly Ghidra's ordering.
                        .then(super::constantptr::ActionConstantPtr::new())
                        .then(ptrarith_pool())
                        .then(super::determinedbranch::ActionDeterminedBranch)
                        // ActionUnreachable (:5673, group `unreachable`), Ghidra's slot directly
                        // after ActionDeterminedBranch — which in Ghidra leaves its orphaned
                        // blocks for exactly this action to collect.
                        .then(super::determinedbranch::ActionUnreachable)
                        // ActionNodeJoin (:5674, group `nodejoin`), Ghidra's slot directly after
                        // ActionUnreachable: merge two blocks that duplicate the same conditional
                        // test into the same pair of exits.
                        .then(super::blockjoin::ActionNodeJoin)
                        // ActionConditionalExe (:5675, group `conditionalexe`), Ghidra's slot
                        // directly after ActionNodeJoin and before ActionConditionalConst.
                        .then(super::condexe::ActionConditionalExe)
                        .then(super::condconst::ActionConditionalConst)
                        // ActionUnreachable (:5490, group `base`) opens Ghidra's mainloop, ahead
                        // of ActionVarnodeProps/ActionHeritage.
                        .then(super::determinedbranch::ActionUnreachable)
                        // ActionVarnodeProps (:5491, group `base`) at Ghidra's slot, between
                        // ActionUnreachable and ActionHeritage. (Held out before the schedule
                        // fixes; re-wired and re-measured after ActionDeadCode returned to :5503,
                        // which changed when `consume` — the input to this action's zero-consume
                        // arm — is computed.)
                        .then(ActionVarnodeProps)
                        .then(ActionHeritage)
                        // ActionParamDouble (:5493, group `protorecovery`), Ghidra's slot directly
                        // after the mainloop ActionHeritage: a call argument built by a PIECE whose
                        // halves are each a parameter is split back into two arguments.
                        .then(ActionParamDouble)
                        // ActionDirectWrite ×2 (Ghidra :5497-5498, "protorecovery_a"/"_b"): mapped
                        // to mosura's rotated cycle between ActionHeritage (:5492) and the deadcode
                        // it feeds (:5503) — the tail DeadCode below. The pass recomputes the
                        // `directwrite` attribute from legal inputs/constants so that DeadCode can
                        // clear `addrforce` off any value NOT reachable from a real input (a
                        // callee-saved-register save slot), removing the write-only chain a bare
                        // alias classification would otherwise force-keep. The second (propagate=
                        // false) pass re-clears and wins, so directwrite does not flow through call
                        // INDIRECTs.
                        .then(super::directwrite::ActionDirectWrite::new(true))
                        .then(super::directwrite::ActionDirectWrite::new(false))
                        // ActionActiveParam + ActionReturnRecovery (Ghidra :5499-5500), at their
                        // real slot: directly after the two ActionDirectWrite and before the
                        // DeadCode below. They are members of `actmainloop` (rule_repeatapply), and
                        // that is not decoration — `initActiveInput` sets `maxPass` to 3 whenever
                        // the convention has a delayed resource (fspec.cc:5335), so a call needs
                        // FOUR evaluations before `isFullyChecked` lets its argument list commit.
                        // Run once, as the standalone instance below the heritage group used to be,
                        // every call stays at `passes=1/3` forever and `buildInputFromTrials` is
                        // never reached. That was invisible while mosura pinned `maxPass` to 0.
                        // (No dead-code here: Ghidra's cycle order is ... ActiveParam/
                        // ReturnRecovery -> RestrictLocal -> DeadCode, so in the rotated frame the
                        // one mainloop DeadCode sits after RestrictLocal at the TOP of the next
                        // iteration. The former tail instance here was that slot displaced by one
                        // member — before RestrictLocal instead of after — which also left the
                        // FIRST pool pass with no dead-code sweep at all.)
                        .then(ActionResolveCalls),
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
                // Tail members mosura has not ported are absent here:
                // (all fullloop-tail members are now at their slots.)
                // - ActionLikelyTrash (:5679, "protorecovery"): cut the data flow out of a
                //   convention-declared trash register whose every use is a trash sink. Inert on
                //   both of mosura's targets (neither cspec declares `<likelytrash>`).
                // - ActionDirectWrite ×2 (:5680-5681): the fullloop-tail directwrite recompute,
                //   feeding the tail DeadCode's addrforce-clear exactly as in the mainloop.
                .then(ActionLikelyTrash)
                .then(super::directwrite::ActionDirectWrite::new(true))
                .then(super::directwrite::ActionDirectWrite::new(false))
                .then(super::deadcode::ActionDeadCode)
                .then(super::determinedbranch::ActionDoNothing)
                .then(ActionSwitchNorm)
                // ActionReturnSplit (:5685, group `returnsplit`), Ghidra's slot directly after
                // ActionSwitchNorm and before ActionUnjustifiedParams.
                .then(super::blockjoin::ActionReturnSplit)
                // ActionUnjustifiedParams (:5686, group `protorecovery`), directly after
                // ActionSwitchNorm/ActionReturnSplit and before ActionStartTypes.
                .then(ActionUnjustifiedParams)
                .then(ActionStartTypes)
                .then(ActionActiveReturn),
        )
        // ActionStartCleanUp (:5692, group `cleanup`), Ghidra's slot directly before the cleanup
        // rule pool and after ActionMappedLocalSync.
        .then(ActionStartCleanUp)
        // (No dead-code after the cleanup pool: Ghidra's universalAction has NO ActionDeadCode
        // anywhere after the fullloop — the cleanup rules are self-contained. The sweep that sat
        // here was audited over the whole-image trace and removed zero live ops.)
        .then(cleanup_pool())
        // ActionInputPrototype (:5731, group `fixateproto`): in `ActionDatabase::universalAction`
        // it comes after the cleanup pool and ActionOutputPrototype (:5730), before ActionNameVars
        // (:5734) and ActionSetCasts (:5735) — on the final input varnodes,
        // after merging. mosura derives the parameter list at print time from the same trials
        // (`recover_func_proto`), so the one thing that must happen in the pipeline, ahead of that,
        // is the MODEL resolution a `<resolveprototype>` placeholder needs
        // (`FuncProto::resolveModel`, coreaction.cc:4731) — the printer then reads the chosen
        // model's list and prints its name.
        .then(ActionInputPrototype)
        // Late branch-orientation stage (task #1): materialize the structurer's body-on-false
        // branch negations in the IR, mirroring Ghidra's final ActionNormalizeBranches placement
        // (after type recovery, where the guards are in final simplified form). ActionOrientBranches
        // sets boolean_flip on each body-on-false CBRANCH (Ghidra BlockBasic::negateCondition);
        // condnegate_pool then materializes and normalizes the negation so printc reads the positive
        // condition directly instead of negating at print time.
        .then(super::structure::ActionOrientBranches)
        // condnegate_pool cleans its own fold-orphans via RuleEarlyRemoval, exactly as Ghidra's
        // oppool1 does for the same two rules — no standalone sweep after it.
        .then(condnegate_pool())
        // Materialize the if/else normal-form flip in the IR (Ghidra ActionPreferComplement /
        // BlockIf::preferComplement, block.cc:3093 — scoped to if/else). Runs after the condnegate
        // pool so it sees the mechanism-B-materialized conditions; opFlipInPlaceExecute rewrites the
        // comparison into normal form (via replace_lessequal), retiring the print-time if_else_flip.
        .then(super::structure::ActionPreferComplement)
        // BEYOND GHIDRA (recompilation): restore the stack-slot address RulePushMulti's
        // spacebase substitute destroyed, so variadic recovery can see `va_start`'s value
        // (`varargs.rs`). Before the type/merge freezes so the new PTRSUB is typed and merged
        // like any other.
        .then(super::varargs::ActionVarargsRecovery)
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
        // stays flat while the wire is live. (The snip inserts COPYs and orphans nothing — Ghidra
        // runs no dead-code after its merge actions, and neither does mosura.)
        .then(super::mergesnip::ActionMergeRequired)
        // The graph-mutating half of Ghidra's ActionMergeRequired: mergeMarker -> mergeOp ->
        // trimOpInput (merge.cc:889/719/692), run after mergeAddrTied above. For each MULTIEQUAL,
        // trim (snip into a predecessor-end COPY) the first input whose HighVariable Cover conflicts
        // with the output's — so the read-only merge in printc no longer fuses the phi output into a
        // conflicting address-tied global (floatcast's `fVar1 = fRam80;` init). (Trim inserts
        // COPYs and orphans nothing; no dead-code follows, matching Ghidra.)
        .then(super::merge::ActionMergeMarkerTrim)
        // Ghidra ActionDominantCopy (coreaction.cc:5723, after ActionMergeCopy): collapse the
        // same-source COPY groups the merge trimming inserted into one dominant COPY
        // (Merge::processCopyTrims/buildDominantCopy, merge.cc:1415/1151).
        .then(super::merge::ActionDominantCopy)
        // Stage 0c (ir-cast-model): a final type-inference commit on the fully-settled graph. The
        // mainloop's `ActionInferTypes` (:626) runs BEFORE the tail cleanup/merge actions above
        // (which insert COPYs and reshape the graph), so the committed `Varnode::ty` was slightly
        // stale relative to the final form printc renders. mosura's retired render-time re-inference
        // was exactly this final pass done at print time; committing it in-pipeline makes the
        // committed types authoritative for the printer (and, later, for `ActionSetCasts`).
        .then(ActionInferTypes::default())
        // Ghidra `ActionMarkExplicit`/`ActionMarkImplied` (coreaction.cc:5719-5720): freeze the
        // explicit/implied classification (set the flag on every varnode) on the FINAL pre-cast graph,
        // so the CAST ops the next action inserts can't perturb the use-count/cover classification
        // printc reads. Ghidra runs this BEFORE ActionSetCasts (5735); mosura previously recomputed it
        // at print time (after the casts), which flipped switchloop/stackstring values implied.
        .then(super::merge::ActionMarkImplied)
        // Ghidra's merge slot (`ActionMergeType`, coreaction.cc:5727, the last of 5718-5727): freeze
        // the HighVariables on the FINAL pre-cast graph. Every Ghidra merge action runs before
        // `ActionSetCasts` (:5735) and each CAST varnode it inserts gets a fresh HighVariable, so a
        // merge recomputed after the casts partitions a different varnode set. printc consumes this
        // rather than re-deriving it — the merge analogue of the ActionMarkImplied freeze above.
        .then(super::merge::ActionMergeType)
        // Ghidra `ActionCopyMarker` (coreaction.cc:5729, right after ActionMergeType at :5727 and
        // ActionHideShadow at :5728): freeze the non-printing marks (`Merge::markInternalCopies`,
        // merge.cc:1444) on the FINAL pre-cast graph. `ActionSetCasts` below rewires the outputs of
        // the very opcodes this switches on (COPY/PIECE/SUBPIECE), so marks decided after it would
        // be decided from a different output Varnode, HighVariable and Cover than Ghidra sees.
        .then(super::merge::ActionCopyMarker)
        // Ghidra `ActionSetCasts` (coreaction.cc:5735, DEAD-LAST — after ActionMarkImplied at 5720
        // and with no ActionInferTypes after it): insert real CPUI_CAST ops where a value's committed
        // type and an operation's natural token/required type diverge, so printc renders `(type)expr`
        // from IR rather than deciding casts at render time. Runs after the final ActionInferTypes so
        // the committed types are settled. Currently the def-side `castOutput` only.
        .then(super::setcasts::ActionSetCasts)
        // Ghidra's tail order is ...NameVars, SetCasts, FinalStructure, PrototypeWarnings, Stop
        // (coreaction.cc:5735+): the final structure is built AFTER the casts land, and nothing
        // that follows mutates the graph — printc consumes exactly this build.
        .then(ActionFinalStructure)
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
    // Label distinct from RuleCondNegate's own `condnegate` — see `ptrarith_pool`.
    ActionPool::new("condnegatepool")
        // RuleEarlyRemoval first, as in Ghidra's oppool1 (coreaction.cc:5510) — Ghidra registers
        // RuleCondNegate/RuleBoolNegate in THAT pool (:5607-5608), so the comparisons orphaned by a
        // RuleBoolNegate fold are cleaned by the pool itself. Extracting the rules into this late
        // pool without earlyremoval left 8-31 dead comparison ops per function for a standalone
        // deadcode sweep that Ghidra's schedule does not have (audit: no post-fullloop
        // ActionDeadCode exists in universalAction).
        .with(RuleEarlyRemoval)
        .with(super::rules::RuleCondNegate)
        .with(RuleBoolNegate)
        .with(super::rules::RuleIntLessEqual)
}

/// Run the pipeline on a raw (post-load) Funcdata in place.
pub fn decompile(data: &mut Funcdata) {
    universal_action().apply(data);
}

/// Ghidra's `ActionRestartGroup` maximum (coreaction.cc:5474: `ActionRestartGroup(…,"universal",1)`)
/// — exactly one restart is allowed per function.
pub const MAX_RESTARTS: u32 = 1;

/// Ghidra `ActionRestartGroup::apply` (action.cc:553): run the universal action, and if analysis
/// asked for a restart, clear everything and run it again.
///
/// A restart is requested by [`super::heritage::bump_deadcode_delay`] when a range is re-heritaged
/// in a space that has already had dead code removed: the earlier SSA was built on incomplete
/// information, so that space's dead-code removal is delayed one pass and the whole decompile is
/// redone. The delay is carried in `Funcdata::deadcode_delay_override`, which is exactly the state
/// Ghidra's `Funcdata::clear` refuses to reset ("Do not clear overrides", funcdata.cc:106) — carry
/// it and the restart converges; drop it and it would rediscover the same problem forever.
///
/// Ghidra's `clearAnalysis` resets the Funcdata in place and lets `ActionStart`'s `followFlow`
/// regenerate the p-code, so its restart lives inside the action tree. mosura generates p-code in
/// `build.rs` before the pipeline is entered, so the rebuild has to be done by whoever holds the
/// builder inputs; `rebuild` is that callback, and it must apply
/// [`Funcdata::take_deadcode_delay_override`] to the fresh Funcdata.
///
/// Ghidra also refuses to restart inside jumptable recovery; mosura's equivalent partial is marked
/// `table_recovery_probe`, and `bump_deadcode_delay` is not reached for it.
pub fn decompile_with_restart(data: &mut Funcdata, mut rebuild: impl FnMut(&mut Funcdata)) -> u32 {
    decompile(data);
    let mut restarts = 0;
    while data.restart_pending && restarts < MAX_RESTARTS {
        restarts += 1;
        let carried = std::mem::take(&mut data.deadcode_delay_override);
        rebuild(data);
        data.deadcode_delay_override = carried;
        data.apply_deadcode_delay_override();
        decompile(data);
    }
    restarts
}

#[cfg(test)]
mod tests {

    /// `ActionVarnodeProps`' zero-consume arm: a varnode whose possibly-non-zero bits are entirely
    /// unconsumed downstream carries no information, so every read becomes a read of constant 0
    /// (Ghidra coreaction.cc:1327). Held out of the pipeline (see the wiring comment), so tested
    /// directly.
    #[test]
    fn varnode_props_replaces_unconsumed_value_with_zero() {
        use crate::decompile::space::{Address, SpaceManager};
        use crate::decompile::op::SeqNum;
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);

        let a = f.new_input(4, Address::new(reg, 0x10));
        let k = f.new_const(4, 3);
        let op = f.new_op(OpCode::IntAdd, SeqNum { pc: Address::new(ram, 0), uniq: 0 }, vec![a, k]);
        let out = f.new_output(op, 4, Address::new(reg, 0x20));
        let use_op = f.new_op(OpCode::IntAdd, SeqNum { pc: Address::new(ram, 4), uniq: 1 }, vec![out, k]);
        f.new_output(use_op, 4, Address::new(reg, 0x28));
        // Nothing downstream consumes any bit of `out`.
        f.vn_mut(out).consume = 0;

        assert!(ActionVarnodeProps.apply(&mut f) >= 1);
        let now = f.op(use_op).input(0).expect("the read");
        assert!(f.vn(now).is_constant() && f.vn(now).constant_value() == 0,
            "the read is rewritten to constant 0");
    }

    /// A COPY of the constant 0 is left alone — replacing it would rewrite itself forever
    /// (Ghidra's explicit infinite-recursion guard, coreaction.cc:1332-1338).
    #[test]
    fn varnode_props_leaves_a_copy_of_zero_alone() {
        use crate::decompile::space::{Address, SpaceManager};
        use crate::decompile::op::SeqNum;
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);

        let zero = f.new_const(4, 0);
        let cop = f.new_op(OpCode::Copy, SeqNum { pc: Address::new(ram, 0), uniq: 0 }, vec![zero]);
        let out = f.new_output(cop, 4, Address::new(reg, 0x20));
        let k = f.new_const(4, 3);
        let use_op = f.new_op(OpCode::IntAdd, SeqNum { pc: Address::new(ram, 4), uniq: 1 }, vec![out, k]);
        f.new_output(use_op, 4, Address::new(reg, 0x28));
        f.vn_mut(out).consume = 0;

        ActionVarnodeProps.apply(&mut f);
        assert_eq!(f.op(use_op).input(0), Some(out), "a COPY of 0 is left for constant propagation");
    }

    /// `ActionStartCleanUp` stamps the varnode creation index at the moment it runs, so the
    /// watermark separates varnodes made before the clean-up phase from those made during it.
    #[test]
    fn start_clean_up_stamps_the_creation_index() {
        use crate::decompile::space::{Address, SpaceManager};
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        assert_eq!(f.clean_up_index(), 0);

        let before = f.new_input(4, Address::new(reg, 0));
        ActionStartCleanUp.apply(&mut f);
        let mark = f.clean_up_index();
        let after = f.new_const(4, 7);

        assert!(f.vn(before).create_index < mark, "varnodes made before the phase are under it");
        assert!(f.vn(after).create_index >= mark, "varnodes made during it are at or above");
    }

    /// `ActionLikelyTrash` cuts the data flow out of a convention-declared trash register when
    /// every path from it is a trash sink: the INDIRECT's before-value becomes a zero constant
    /// (indirect *creation*) — Ghidra coreaction.cc:2158-2162.
    #[test]
    fn likely_trash_truncates_indirect_into_creation() {
        use crate::decompile::space::{Address, SpaceManager};
        use crate::decompile::op::SeqNum;
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let ecx = Address::new(reg, 0x4);
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        f.proto_model.likelytrash = vec![(ecx, 4)];

        let vn = f.new_input(4, ecx);
        let target = f.new_const(4, 0x1000);
        let call = f.new_op(OpCode::Call, SeqNum { pc: Address::new(ram, 0), uniq: 0 }, vec![target]);
        // A call-caused INDIRECT on ECX: the only use, and a trash sink.
        let ind = f.new_op(OpCode::Indirect, SeqNum { pc: Address::new(ram, 0), uniq: 1 }, vec![vn]);
        f.op_mut(ind).guarded_op = Some(call);
        f.new_output(ind, 4, ecx);

        assert_eq!(ActionLikelyTrash.apply(&mut f), 1, "the one sink is cut");
        let before = f.op(ind).input(0).expect("INDIRECT before-value");
        assert!(f.vn(before).is_constant() && f.vn(before).constant_value() == 0,
            "data flow through the INDIRECT is truncated to a zero constant");
    }

    /// A non-sink use anywhere makes the whole trace fail, and nothing is cut (Ghidra's
    /// `istrash = false` default arm, coreaction.cc:2119).
    #[test]
    fn likely_trash_declines_when_a_use_is_not_a_sink() {
        use crate::decompile::space::{Address, SpaceManager};
        use crate::decompile::op::SeqNum;
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let ecx = Address::new(reg, 0x4);
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        f.proto_model.likelytrash = vec![(ecx, 4)];

        let vn = f.new_input(4, ecx);
        // A real arithmetic use — the register is not trash.
        let k = f.new_const(4, 1);
        let add = f.new_op(OpCode::IntAdd, SeqNum { pc: Address::new(ram, 0), uniq: 0 }, vec![vn, k]);
        f.new_output(add, 4, Address::new(reg, 0x8));

        assert_eq!(ActionLikelyTrash.apply(&mut f), 0, "a genuine use blocks the cut");
        assert_eq!(f.op(add).input(0), Some(vn), "the graph is untouched");
    }

    /// The `<likelytrash>` cspec element decodes. x86win declares ECX; x86-64-gcc declares none,
    /// which is why the action is inert on mosura's corpus target.
    #[test]
    fn likelytrash_decodes_from_the_cspec() {
        let sla = paths::language_dir("x86").join("x86.sla");
        if !sla.exists() {
            return;
        }
        let Ok(bytes) = std::fs::read(&sla) else { return };
        let Some(spec) = Spec::from_sla(&bytes).ok() else { return };
        let spaces = crate::decompile::space::SpaceManager::standard();
        let win = crate::analysis::cspec::default_proto_model(&spec, "x86:LE:32:default", "windows", &spaces);
        if let Some(m) = win {
            assert!(!m.likelytrash.is_empty(), "x86win declares <likelytrash> (ECX)");
        }
    }
    use super::*;
    use crate::decompile::build::raw_funcdata_flow;
    use crate::decompile::{OpCode, OpId};
    use crate::sleigh::engine::Spec;
    use crate::{datatest, paths};

    #[test]
    fn pipeline_runs_end_to_end() {
        let sla = paths::language_dir("x86").join("x86-64.sla");
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
