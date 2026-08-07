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

    /// The functions in `set` to hand to the decompiler — Ghidra's `findLocations`
    /// (DecompilerSwitchAnalyzer.java:237) composed with `findFunctions` (:184). Ghidra walks the
    /// *instructions* in the set, keeps those whose flow type is a computed jump, and maps each to
    /// its CONTAINING function; mosura reaches the same set from the function side, testing each
    /// candidate's span against the recorded `indirect_branches` — decompiling every function is
    /// needlessly expensive. A function spans `[entry, next entry)`.
    ///
    /// **Every function entry in the set, ascending — not one per range.** `AddressSet` coalesces
    /// adjacent ranges, so functions at consecutive entries collapse into a single range and
    /// reading `r.min` analysed only the first (`docs/function-discovery-backlog.md`, CAUSE B).
    ///
    /// The entry filter matters on its own account too: `r.min` was used as a function entry —
    /// handed straight to `decompile_function` — without ever checking that a function was there.
    /// Ghidra cannot do that; `findFunctions` maps every location through `getFunctionContaining`,
    /// so what it decompiles is always a function.
    fn find_functions(&self, program: &Program, set: &AddressSet) -> Vec<u64> {
        let entries: std::collections::BTreeSet<u64> =
            program.function_manager.functions().map(|f| f.entry_point().offset).collect();
        entries
            .iter()
            .copied()
            .filter(|&off| set.contains(Address::new(self.ram, off)))
            .filter(|&off| {
                let next = entries.range((off + 1)..).next().copied().unwrap_or(u64::MAX);
                program.indirect_branches.iter().any(|&b| b >= off && b < next)
            })
            .collect()
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
        let mut case_targets = AddressSet::new();
        for entry_off in self.find_functions(program, set) {
            let entry = Address::new(ram, entry_off);
            let Some(mut f) = crate::analysis::decompiler::decompile_function(program, entry) else {
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

#[cfg(test)]
mod find_functions_tests {
    use super::*;
    use crate::analysis::program::AddressSet;
    use crate::decompile::space::{SpaceKind, SpaceManager};

    /// A bare x86-64 program with one 4 KiB `.text` block at `0x401000` — no bytes are decoded
    /// here, the selection under test reads only the function manager and `indirect_branches`.
    fn program() -> Program {
        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 8, 1);
        let base = Address::new(ram, 0x40_1000);
        let mut p = Program::new(spaces, ram, "x86:LE:64:default", "gcc", base, false, 64);
        p.memory.add_block(".text", base, 0x1000, true, false, true, Some(vec![0; 0x1000]));
        p
    }

    fn make_function(p: &mut Program, off: u64) {
        let ram = p.default_space;
        p.function_manager.create_function(
            Address::new(ram, off),
            &format!("FUN_{off:08x}"),
            AddressSet::new(),
        );
    }

    fn set_of(p: &Program, offs: &[u64]) -> AddressSet {
        let mut s = AddressSet::new();
        for &o in offs {
            s.add_range(p.default_space, o, o);
        }
        s
    }

    /// CAUSE B (`docs/function-discovery-backlog.md`): three functions at CONSECUTIVE entries
    /// coalesce into ONE `AddressSet` range, and reading `r.min` analyses only the first.
    ///
    /// `wprobe.watcom-x86-32` is the measured instance — `08048110 sink_` / `08048111 __CHK` /
    /// `08048112 p_leaf_` — so the shape is real, not hypothetical. Here the switch candidate is
    /// in the THIRD function, which `r.min` never reaches: with the entries adjacent, the range
    /// examined for the first is `[0x401010, 0x401011)`, one byte wide.
    #[test]
    fn every_function_entry_in_the_set_is_a_candidate_not_just_the_range_minimum() {
        let mut p = program();
        for off in [0x40_1010, 0x40_1011, 0x40_1012] {
            make_function(&mut p, off);
        }
        p.indirect_branches.insert(0x40_1020); // inside the third function's span

        let a = DecompilerSwitchAnalyzer::new(&p);
        let set = set_of(&p, &[0x40_1010, 0x40_1011, 0x40_1012]);
        assert_eq!(set.ranges().count(), 1, "the three entries must coalesce for this to bite");

        assert_eq!(
            a.find_functions(&p, &set),
            vec![0x40_1012],
            "the switch candidate sits in the function at 0x401012; taking only each range's \
             minimum stops at 0x401010 and never considers it"
        );
    }

    /// The other half of the same defect: `r.min` was passed to `decompile_function` as a function
    /// entry **without checking that a function is there**. Ghidra never does this — `findFunctions`
    /// (DecompilerSwitchAnalyzer.java:184) maps every location through `getFunctionContaining`, so
    /// what it decompiles is always a function.
    #[test]
    fn a_range_minimum_that_is_not_a_function_entry_is_not_decompiled() {
        let mut p = program();
        make_function(&mut p, 0x40_1000); // the only function, below the set
        p.indirect_branches.insert(0x40_1025);

        let a = DecompilerSwitchAnalyzer::new(&p);
        let set = set_of(&p, &[0x40_1020, 0x40_1021]);

        assert!(
            a.find_functions(&p, &set).is_empty(),
            "0x401020 is not a function entry — it must not be handed to the decompiler as one"
        );
    }
}
