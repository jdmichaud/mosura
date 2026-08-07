//! External-jump flow override (A6) — a port of the `checkForExternalJump` path of
//! Ghidra's `app/plugin/core/analysis/OperandReferenceAnalyzer.java` (lines 266-292,
//! 583-606).
//!
//! Ghidra iterates the flow references out of each code unit; for a non-indirect **jump**
//! reference whose target lies in the artificial `EXTERNAL` memory block, it applies a
//! `FlowOverride.CALL_RETURN` to the jumping instruction ("Any externals directly jumped
//! to should be looked at as a call … these don't return!"). The override re-types the
//! reference via `FlowOverride.getModifiedFlowType`: a PLT tail-call `jmp *[GOT]` whose
//! slot resolves to the external is `COMPUTED_JUMP` → `COMPUTED_CALL_TERMINATOR`.
//!
//! mosura has no per-instruction flow-override attribute, so the override is realized by
//! re-typing the reference in place ([`crate::analysis::flowtype::modified_flow_type`]) —
//! the same observable result Ghidra's reference fixup produces.

use crate::analysis::analyzer::{Analyzer, AnalyzerType};
use crate::analysis::flowtype::{modified_flow_type, FlowOverride};
use crate::analysis::manager::Scheduling;
use crate::analysis::priority::AnalysisPriority;
use crate::analysis::program::{AddressSet, Program};

pub struct ExternalJumpAnalyzer;

impl Default for ExternalJumpAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalJumpAnalyzer {
    pub fn new() -> ExternalJumpAnalyzer {
        ExternalJumpAnalyzer
    }
}

impl Analyzer for ExternalJumpAnalyzer {
    fn name(&self) -> &str {
        "External Jump Flow Override"
    }
    /// `INSTRUCTION_ANALYZER` (OperandReferenceAnalyzer.java:133) — the newly disassembled
    /// extent.
    ///
    /// ⚠️ **This has to move with [`ConstantPropagationAnalyzer`](super::ConstantPropagationAnalyzer),
    /// not after it.** This pass re-types the `COMPUTED_JUMP` the constant propagator creates into
    /// an external; the propagator re-creates that reference every time it runs. While this sat on
    /// the `Function` channel and the propagator moved to `Instruction`, a decoded extent that
    /// created no new function would re-run the propagator with nothing to re-type afterwards, and
    /// `ReferenceManager::add` keys on the reference TYPE — so the re-created `COMPUTED_JUMP`
    /// would sit alongside the `COMPUTED_CALL_TERMINATOR` instead of replacing it. On the same
    /// channel, at Ghidra's own `REFERENCE_ANALYSIS` against the propagator's
    /// `REFERENCE_ANALYSIS.before()x4`, every round runs both in that order.
    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Instruction
    }
    fn priority(&self) -> AnalysisPriority {
        // `setPriority(AnalysisPriority.REFERENCE_ANALYSIS)` (OperandReferenceAnalyzer.java:138).
        AnalysisPriority::REFERENCE
    }
    fn added(&self, program: &mut Program, _set: &AddressSet, _sched: &mut Scheduling) -> bool {
        // OperandReferenceAnalyzer: for each non-indirect JUMP reference whose target is in
        // the EXTERNAL block, the jump becomes a CALL_RETURN. Collect first (we re-type
        // while iterating the same manager).
        let overrides: Vec<(crate::decompile::space::Address, crate::decompile::space::Address, crate::analysis::program::RefType)> =
            program
                .reference_manager
                .references()
                .filter(|r| {
                    r.ref_type.is_flow()
                        && r.ref_type.is_jump_like()
                        && program.memory.is_external_block_address(r.to)
                })
                .map(|r| (r.from, r.to, modified_flow_type(r.ref_type, FlowOverride::CallReturn)))
                .collect();
        if overrides.is_empty() {
            return false;
        }
        for (from, to, new_type) in overrides {
            program.reference_manager.retype(from, to, new_type);
        }
        true
    }
}
