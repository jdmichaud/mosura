//! The decompiler pipeline — the assembly of phases into one composable action, the
//! analogue of Ghidra's `ActionDatabase::universalAction` (`coreaction.cc`). Grows as each
//! phase lands; currently heritage (P1) + the simplification rule pool (P2).

use super::action::{Action, ActionGroup, ActionPool};
use super::funcdata::Funcdata;
use super::rules::{
    RuleCollectTerms, RuleConstFold, RuleEqual2Zero, RuleIdentityEl, RuleLessEqual,
    RuleBoolNegate, RuleIdempotent, RuleSubExtComm, RuleMultMult, RulePropagateCopy, RuleRangeAnd, RuleSborrow, RuleSelectCse, RuleShift2Mult, RuleTermOrder, RuleTrivialArith, RuleTrivialShift,
};

/// Build the CFG, dominators and SSA form (Ghidra's `ActionHeritage`, plus the CFG
/// construction Ghidra does in `followFlow`). Runs once — when the blocks aren't built yet.
pub struct ActionHeritage;

impl Action for ActionHeritage {
    fn name(&self) -> &str {
        "heritage"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        if data.num_blocks() != 0 {
            return 0;
        }
        super::stackvars::recover_stack(data);
        // wire return/argument candidates before heritage links them to reaching defs
        super::recover::recover_return(data);
        super::recover::recover_call_args(data);
        super::cfg::build_cfg(data);
        // Probe pass: fully simplify a copy (heritage + rules + dead-code, no call-guards), then run
        // Ghidra's AliasChecker on the resulting graph to find which stack slots are aliased — their
        // address escapes to a call. This decides which slots `recover_call_effects` guards, so a
        // non-aliased local (a spilled loop variable) is never guarded and its loop SSA is left
        // intact — without a calling-convention register scan.
        let boundary = {
            let mut probe = data.clone();
            let pdom = super::dominator::compute(&probe);
            super::heritage::heritage(&mut probe, &pdom);
            super::recover::resolve_return(&mut probe);
            super::recover::resolve_call_args(&mut probe);
            default_rule_pool().apply(&mut probe);
            super::deadcode::ActionDeadCode.apply(&mut probe);
            super::alias::alias_boundary(&probe)
        };
        // model each call's clobber of the caller-saved arg registers + the aliased stack locals
        super::recover::recover_call_effects(data, boundary);
        let dom = super::dominator::compute(data);
        super::heritage::heritage(data, &dom);
        // keep only the realistic return value / call arguments
        super::recover::resolve_return(data);
        super::recover::resolve_call_args(data);
        1
    }
}

/// The simplification rule pool (Ghidra's `oppool1`) — the core rules ported so far.
pub fn default_rule_pool() -> ActionPool {
    ActionPool::new("oppool")
        .with(RuleTermOrder)
        .with(RuleSelectCse)
        .with(RuleSubExtComm)
        .with(RuleIdempotent)
        .with(RuleConstFold)
        .with(RuleCollectTerms)
        .with(RuleMultMult)
        .with(RuleTrivialArith)
        .with(RuleIdentityEl)
        .with(RuleTrivialShift)
        .with(RuleShift2Mult)
        .with(RuleSborrow)
        .with(RuleEqual2Zero)
        .with(RuleLessEqual)
        .with(RuleBoolNegate)
        .with(RuleRangeAnd)
        .with(super::divopt::RuleDivOpt)
        .with(super::divopt::RuleModOpt)
        .with(super::divopt::RuleSignMod2nOpt)
        .with(super::divopt::RuleSignMod2nOpt2)
        .with(RulePropagateCopy)
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
pub fn ptrarith_pool() -> ActionPool {
    ActionPool::new("ptrarith").with(super::ptrarith::RulePtrArith)
}

/// The universal decompile action: heritage, simplification, dead-code removal, then type recovery
/// and the pointer-arithmetic rewrite (PTRADD/PTRSUB) followed by a final dead-code sweep.
pub fn universal_action() -> ActionGroup {
    ActionGroup::once("decompile")
        .then(ActionHeritage)
        .then(default_rule_pool())
        .then(super::deadcode::ActionDeadCode)
        .then(ActionInferTypes)
        .then(ptrarith_pool())
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
