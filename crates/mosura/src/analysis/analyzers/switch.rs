//! `DecompilerSwitchAnalyzer` (A6) — a port of Ghidra's
//! `app/plugin/core/analysis/DecompilerSwitchAnalyzer`.
//!
//! For each function it runs the ported decompiler ([`crate::analysis::decompiler`]) and
//! reads back the recovered jump tables ([`Funcdata::jump_tables`]). Each switch's
//! indirect `BRANCHIND` becomes `COMPUTED_JUMP` references to the case targets, and those
//! targets are scheduled as code — so switch bodies, reachable only through the table,
//! get disassembled and structured into the function.

use crate::analysis::analyzer::{Analyzer, AnalyzerType};
use crate::analysis::manager::Scheduling;
use crate::analysis::priority::AnalysisPriority;
use crate::analysis::program::{AddressSet, Program, RefType};
use crate::decompile::space::{Address, SpaceId};

pub struct DecompilerSwitchAnalyzer {
    ram: SpaceId,
}

impl DecompilerSwitchAnalyzer {
    pub fn new(program: &Program) -> DecompilerSwitchAnalyzer {
        DecompilerSwitchAnalyzer { ram: program.default_space }
    }
}

impl Analyzer for DecompilerSwitchAnalyzer {
    fn name(&self) -> &str {
        "Decompiler Switch"
    }
    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Function
    }
    fn priority(&self) -> AnalysisPriority {
        // After disassembly (300), function creation (500) and reference recovery (600):
        // the function must be laid down before the decompiler can recover its switches.
        AnalysisPriority::REFERENCE.after()
    }
    fn added(&self, program: &mut Program, set: &AddressSet, sched: &mut Scheduling) -> bool {
        let ram = self.ram;
        // Only decompile functions that contain an unresolved indirect branch (Ghidra's
        // DecompilerSwitchAnalyzer collects dynamic-jump functions) — decompiling every
        // function is needlessly expensive. A function spans [entry, next entry).
        let entries: std::collections::BTreeSet<u64> =
            program.function_manager.functions().map(|f| f.entry_point().offset).collect();
        let mut case_targets = AddressSet::new();
        for r in set.ranges() {
            let entry_off = r.min;
            let next = entries.range((entry_off + 1)..).next().copied().unwrap_or(u64::MAX);
            if !program.indirect_branches.iter().any(|&b| b >= entry_off && b < next) {
                continue; // no switch candidate in this function
            }
            let entry = Address::new(ram, entry_off);
            let Some(f) = crate::analysis::decompiler::decompile_function(program, entry) else {
                continue;
            };
            for jt in f.jump_tables() {
                let from = Address::new(ram, jt.op_addr);
                for t in jt.targets {
                    // COMPUTED_JUMP from the BRANCHIND to each case target.
                    program.reference_manager.add(from, Address::new(ram, t), RefType::ComputedJump, -1);
                    case_targets.add_range(ram, t, t);
                }
            }
        }
        // The case targets are reachable code (only through the table) — disassemble them.
        if !case_targets.is_empty() {
            sched.code_defined(&case_targets);
        }
        true
    }
}
