//! `AutoAnalysisManager` / `Scheduling` — a port of Ghidra's
//! `core/analysis/AutoAnalysisManager.java` + `AnalysisScheduler.java` (A3).
//!
//! The fixpoint driver of the analysis pipeline. Each registered [`Analyzer`] owns an
//! [`AddressSet`] accumulator of locations of its [`AnalyzerType`] that have appeared.
//! Facts are routed by kind — `code_defined` feeds `Instruction` analyzers,
//! `function_defined` feeds `Function` analyzers, etc. (Ghidra's `codeDefined`/
//! `functionDefined`/… notifiers). [`AutoAnalysisManager::run`] repeatedly runs the
//! highest-priority analyzer with pending work; running one mutates the [`Program`] and
//! may schedule more, so the worklist drives to a fixpoint.
//!
//! (Ghidra propagates "X was defined" via the program's change-event queue; here the
//! analyzers notify [`Scheduling`] directly, the explicit-channel model from
//! `docs/analysis-port-plan.md` §2a — same structure, no hidden event bus.)

use crate::analysis::analyzer::{Analyzer, AnalyzerType};
use crate::analysis::program::{AddressSet, Program};

/// Per-analyzer scheduling state + the fact-routing notifiers, handed to an analyzer's
/// [`Analyzer::added`] so it can enqueue follow-on work.
#[derive(Default)]
pub struct Scheduling {
    /// Accumulated "added" locations awaiting each analyzer (indexed like the manager's
    /// analyzer list).
    pending: Vec<AddressSet>,
    priority: Vec<i32>,
    ty: Vec<AnalyzerType>,
}

impl Scheduling {
    fn register(&mut self, priority: i32, ty: AnalyzerType) {
        self.pending.push(AddressSet::new());
        self.priority.push(priority);
        self.ty.push(ty);
    }

    /// Route an added-location set to every analyzer consuming `ty`.
    fn notify(&mut self, ty: AnalyzerType, set: &AddressSet) {
        for i in 0..self.ty.len() {
            if self.ty[i] == ty {
                self.pending[i] = self.pending[i].union(set);
            }
        }
    }

    /// Newly disassembled instructions appeared (Ghidra `codeDefined`).
    pub fn code_defined(&mut self, set: &AddressSet) {
        self.notify(AnalyzerType::Instruction, set);
    }
    /// Newly created functions appeared (Ghidra `functionDefined`).
    pub fn function_defined(&mut self, set: &AddressSet) {
        self.notify(AnalyzerType::Function, set);
    }
    /// Newly created data appeared (Ghidra `dataDefined`).
    pub fn data_defined(&mut self, set: &AddressSet) {
        self.notify(AnalyzerType::Data, set);
    }
    /// New memory blocks appeared (Ghidra `blockAdded`).
    pub fn block_added(&mut self, set: &AddressSet) {
        self.notify(AnalyzerType::Byte, set);
    }

    /// The index of the highest-priority (lowest value) analyzer with pending work.
    fn next_task(&self) -> Option<usize> {
        (0..self.pending.len())
            .filter(|&i| !self.pending[i].is_empty())
            .min_by_key(|&i| self.priority[i])
    }

    /// Atomically take an analyzer's accumulated set, leaving it empty.
    fn take(&mut self, i: usize) -> AddressSet {
        std::mem::take(&mut self.pending[i])
    }
}

/// The auto-analysis manager (Ghidra `AutoAnalysisManager`).
#[derive(Default)]
pub struct AutoAnalysisManager {
    analyzers: Vec<Box<dyn Analyzer>>,
    sched: Scheduling,
}

impl AutoAnalysisManager {
    pub fn new() -> AutoAnalysisManager {
        AutoAnalysisManager::default()
    }

    /// Register an analyzer if it applies to the program (Ghidra `canAnalyze`).
    pub fn add_analyzer(&mut self, analyzer: Box<dyn Analyzer>, program: &Program) {
        if !analyzer.can_analyze(program) {
            return;
        }
        self.sched.register(analyzer.priority().0, analyzer.analysis_type());
        self.analyzers.push(analyzer);
    }

    /// Scheduling handle for seeding initial work (e.g. the loader's entry points).
    pub fn scheduling(&mut self) -> &mut Scheduling {
        &mut self.sched
    }

    /// Run the worklist to a fixpoint: repeatedly run the highest-priority analyzer with
    /// pending work; each run may schedule more (Ghidra `startAnalysis` loop).
    pub fn run(&mut self, program: &mut Program) {
        while let Some(i) = self.sched.next_task() {
            let set = self.sched.take(i);
            let analyzer = &self.analyzers[i];
            analyzer.added(program, &set, &mut self.sched);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::analyzer::AnalyzerType;
    use crate::analysis::priority::AnalysisPriority;
    use crate::decompile::space::{Address, SpaceId, SpaceManager, SpaceKind};
    use std::cell::Cell;
    use std::rc::Rc;

    const RAM: SpaceId = SpaceId(1);

    /// Instruction analyzer: records it ran, and promotes its set to a function fact —
    /// demonstrating re-triggering of a later-priority analyzer.
    struct Disasm {
        order: Rc<Cell<i32>>,
        ran_at: Rc<Cell<i32>>,
    }
    impl Analyzer for Disasm {
        fn name(&self) -> &str { "Disasm" }
        fn analysis_type(&self) -> AnalyzerType { AnalyzerType::Instruction }
        fn priority(&self) -> AnalysisPriority { AnalysisPriority::DISASSEMBLY }
        fn added(&self, _p: &mut Program, set: &AddressSet, sched: &mut Scheduling) -> bool {
            self.ran_at.set(self.order.get());
            self.order.set(self.order.get() + 1);
            sched.function_defined(set); // schedule the function analyzer
            true
        }
    }

    /// Function analyzer: just records the order in which it ran (must be after Disasm).
    struct Funcs {
        order: Rc<Cell<i32>>,
        ran_at: Rc<Cell<i32>>,
    }
    impl Analyzer for Funcs {
        fn name(&self) -> &str { "Funcs" }
        fn analysis_type(&self) -> AnalyzerType { AnalyzerType::Function }
        fn priority(&self) -> AnalysisPriority { AnalysisPriority::FUNCTION }
        fn added(&self, _p: &mut Program, _set: &AddressSet, _sched: &mut Scheduling) -> bool {
            self.ran_at.set(self.order.get());
            self.order.set(self.order.get() + 1);
            true
        }
    }

    #[test]
    fn worklist_runs_in_priority_order_and_retriggers() {
        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 8, 1);
        let mut program =
            Program::new(spaces, ram, "x86:LE:64:default", "gcc", Address::new(ram, 0), false, 64);

        let order = Rc::new(Cell::new(0));
        let disasm_at = Rc::new(Cell::new(-1));
        let funcs_at = Rc::new(Cell::new(-1));

        let mut mgr = AutoAnalysisManager::new();
        // Register out of priority order to prove the queue orders, not registration.
        mgr.add_analyzer(Box::new(Funcs { order: order.clone(), ran_at: funcs_at.clone() }), &program);
        mgr.add_analyzer(Box::new(Disasm { order: order.clone(), ran_at: disasm_at.clone() }), &program);

        // Seed: code defined at one address → Disasm runs → schedules Funcs.
        let mut seed = AddressSet::new();
        seed.add_range(RAM, 0x1000, 0x1000);
        mgr.scheduling().code_defined(&seed);
        mgr.run(&mut program);

        assert_eq!(disasm_at.get(), 0, "Disasm (priority 300) runs first");
        assert_eq!(funcs_at.get(), 1, "Funcs (priority 500) runs after, via re-trigger");
        assert_eq!(order.get(), 2, "fixpoint reached after both ran once");
    }
}
