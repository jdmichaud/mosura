//! The decompiler pipeline — the assembly of phases into one composable action, the
//! analogue of Ghidra's `ActionDatabase::universalAction` (`coreaction.cc`). Grows as each
//! phase lands; currently heritage (P1) + the simplification rule pool (P2).

use super::action::{Action, ActionGroup, ActionPool};
use super::funcdata::Funcdata;
use super::rules::{
    Rule2Comp2Sub, RuleAddUnsigned, RuleCollectTerms, RuleEarlyRemoval, RuleConstFold, RuleEqual2Zero,
    RuleIdentityEl, RuleLessEqual, RuleBoolNegate, RuleBooleanNegate, RuleIdempotent,
    RuleMultiCollapse, RuleMultNegOne, RuleSubExtComm, RuleMultMult, RuleHumptyDumpty,
    RuleAndZext, RuleDumptyHump, RuleOrCompare, RulePropagateCopy, RuleRangeAnd,
    RuleLogic2Bool, RuleOrMask, RuleShiftAnd, RuleShiftCompare, RuleShiftPiece, RuleZextEliminate,
    RuleSborrow, RuleScarry, RuleSelectCse, RuleShift2Mult, RuleTermOrder, RuleTrivialArith, RuleTrivialShift,
    RuleAndMask, RulePopcountBoolXor, RuleSlessToLess,
    RuleOrCollapse, RuleXorCollapse, RuleHighOrderAnd, RuleZextShiftZext, RuleConcatCommute, RuleConcatZext,
    RuleZextCommute, RuleConcatZero, RuleConcatLeftShift,
    RuleDoubleSub, RuleDoubleShift, RuleDoubleArithShift, RuleConcatShift,
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
        super::recover::resolve_return(data);
        super::recover::resolve_call_args(data);
        1
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
        .with(RuleSborrow) // (8)
        .with(RuleScarry) // (9)
        .with(RuleTrivialArith) // (11)
        .with(RuleTrivialShift) // (13)
        .with(RuleIdentityEl) // (16)
        .with(RuleIdempotent) // mosura extra — trivial idempotent AND/OR/XOR/SUB folds
        .with(RuleOrMask) // (17)
        .with(RuleAndMask) // (18)
        .with(RuleRangeAnd) // mosura extra — AND with a range mask, next to AndMask
        .with(RuleOrCollapse) // (20)
        .with(RuleShiftBitops) // (22)
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
        .with(RuleLessEqual2Zero) // (46)
        .with(RuleEqual2Zero) // (48)
        .with(RuleXorCollapse) // (51)
        .with(RuleConstFold) // (53) RuleCollapseConstants
        .with(RulePropagateCopy) // (55)
        .with(RuleZextEliminate) // (56)
        .with(RuleSlessToLess) // (57)
        .with(RuleBooleanNegate) // (63)
        .with(RuleLogic2Bool) // (64)
        .with(RuleSubExtComm) // (65)
        .with(RuleConcatCommute) // (67)
        .with(RuleConcatZext) // (68)
        .with(RuleZextCommute) // (69)
        .with(RuleZextShiftZext) // (70)
        .with(RuleShiftAnd) // (71)
        .with(RuleConcatZero) // (72)
        .with(RuleConcatLeftShift) // (73)
        .with(RuleHumptyDumpty) // (77)
        .with(RuleDumptyHump) // (78)
        .with(RuleHumptyOr) // (79)
        .with(RulePositiveDiv) // (82)
        .with(super::divopt::RuleDivTermAdd2) // (84)
        .with(super::divopt::RuleDivOpt) // (85)
        .with(super::divopt::RuleModOpt) // (91)
        .with(super::divopt::RuleSignMod2nOpt) // (92)
        .with(super::divopt::RuleSignMod2nOpt2) // (93)
        .with(RuleBoolNegate) // (98)
        .with(RuleLessEqual) // (99)
        .with(RuleFloatRange) // (102)
        .with(RulePopcountBoolXor) // (105)
        .with(RuleOrCompare) // (109)
        // SubVariableFlow driving rules (coreaction.cc:5621-5627). RuleSubvarSext (5628) deferred —
        // sign-extension tracer still stubbed. RuleAndDistribute (5537) stays OUT (RuleHumptyOr
        // ping-pong hang). SubZext/Piece2Zext stay HELD until re-measured after RuleSubvarZext narrows
        // returns: their earlier regressors were all the wide-return divergence (they reconstruct the
        // upper-RAX packing an 8-byte RETURN consumes), which int4 returns should clear.
        .with(RuleSubvarAnd) // (110)
        .with(RuleSubvarSubpiece) // (111)
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
        super::recover::resolve_call_output(data);
        1
    }
}

/// The universal decompile action: heritage, simplification, then dead-code removal.
/// Ghidra `ActionInferTypes`: recover and commit a data-type onto every varnode, so the
/// pointer-arithmetic rules can read pointer types during the pipeline.
pub struct ActionInferTypes;

impl Action for ActionInferTypes {
    fn name(&self) -> &str {
        "infertypes"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        // No recovered type-locks yet (see printc), so inference types every varnode.
        super::infertypes::infer_types(data, &std::collections::HashMap::new());
        1
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
        .with(super::rules::RuleSub2Add)
        .with(RuleConstFold)
        .with(RulePropagateCopy)
        .with(super::rules::RuleAddMultCollapse)
        .with(super::ptrarith::RulePtrArith)
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
        1
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
        1
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
        .then(ActionNonzeroMask)
        .then(ActionConsume)
        .then(default_rule_pool())
        .then(super::deadcode::ActionDeadCode)
        // Fold any CBRANCH whose condition simplified to a constant, then prune the unreachable
        // target (Ghidra ActionDeterminedBranch). A second simplify+dead-code sweep cleans up the
        // collapsed MULTIEQUAL (now a COPY) and the dead ops the prune leaves behind.
        .then(super::determinedbranch::ActionDeterminedBranch)
        .then(ActionNonzeroMask)
        .then(ActionConsume)
        .then(default_rule_pool())
        .then(super::deadcode::ActionDeadCode)
        // A third simplify+dead-code sweep, continuing the hand-unrolled approximation of Ghidra's
        // `rule_repeatapply` mainloop (which repeats pool+deadcode to fixpoint). It is a no-op for
        // functions already converged; it matters when a rule needs a *prior* dead op cleared
        // before it can fire — e.g. the orcompare boolean chain, where RuleOrCompare/RuleShiftCompare
        // settle in the second sweep and only then does dead-code drop the multiply, exposing the
        // `loneDescend` that lets RuleZextEliminate/RuleBooleanNegate recover the `||`.
        .then(ActionNonzeroMask)
        .then(ActionConsume)
        .then(default_rule_pool())
        .then(super::deadcode::ActionDeadCode)
        .then(ActionActiveReturn)
        .then(ActionInferTypes)
        .then(ptrarith_pool())
        .then(cleanup_pool())
        .then(super::deadcode::ActionDeadCode)
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
