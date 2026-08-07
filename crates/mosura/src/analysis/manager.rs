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

/// The analyzer that executes a [`Scheduling::disassemble`] command — mosura's stand-in for
/// Ghidra's `DisassembleCommand`, which is a free-standing command object rather than an analyzer.
pub const DISASSEMBLY_COMMAND: &str = "Disassembly";
/// The analyzer that executes a [`Scheduling::create_function`] command — mosura's stand-in for
/// Ghidra's `CreateFunctionCmd`.
pub const FUNCTION_COMMAND: &str = "Function";

/// Per-analyzer scheduling state + the fact-routing notifiers, handed to an analyzer's
/// [`Analyzer::added`] so it can enqueue follow-on work.
#[derive(Default)]
pub struct Scheduling {
    /// Accumulated "added" locations awaiting each analyzer (indexed like the manager's
    /// analyzer list).
    pending: Vec<AddressSet>,
    priority: Vec<i32>,
    ty: Vec<AnalyzerType>,
    names: Vec<String>,
}

impl Scheduling {
    fn register(&mut self, priority: i32, ty: AnalyzerType, name: &str) {
        self.pending.push(AddressSet::new());
        self.priority.push(priority);
        self.ty.push(ty);
        self.names.push(name.to_string());
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

    /// Schedule disassembly at each address of `set` — Ghidra
    /// `AutoAnalysisManager.disassemble(AddressSetView)` (AutoAnalysisManager.java:1128), which is
    /// `schedule(new DisassembleCommand(targetSet, null, true), getDisassemblyPriority())` (:860).
    ///
    /// ⚠️ **A COMMAND, NOT A NOTIFICATION — the distinction is load-bearing.** Ghidra's
    /// `codeDefined` (:262-272) announces that instructions were *actually laid down*; it is
    /// raised from real listing changes and Ghidra's own comment at :385 notes that disassembly
    /// deliberately does not go through change events. Nothing in Ghidra subscribes disassembly to
    /// `codeDefined` at all.
    ///
    /// mosura expressed both as `code_defined`, and that one substitution produced three defects
    /// at once (`docs/function-discovery-backlog.md` §9):
    ///
    ///  1. a request was only delivered to analyzers registered in *that* manager, so every
    ///     request the byte-pattern passes made evaporated — their manager has no disassembler;
    ///  2. requests were unioned into the same accumulator as the decoded EXTENT the disassembler
    ///     notifies back to itself, so seeds and decoded code shared one [`AddressSet`], adjacent
    ///     seeds coalesced into one range, and only the range minimum survived — `wprobe`'s
    ///     `p_leaf_` @`08048112` was dropped because `__CHK` sits at `08048111`;
    ///  3. a request echoed back to the requester, so the `Instruction`-typed pattern passes
    ///     re-fired forever and had to be held off with thread-local dedupes.
    ///
    /// This carries SEED addresses only and never mixes with a decoded extent, which is what makes
    /// per-address iteration safe at the far end.
    pub fn disassemble(&mut self, set: &AddressSet) {
        self.schedule_one_time(DISASSEMBLY_COMMAND, set);
    }

    /// Schedule function creation at each address of `set` — Ghidra
    /// `AutoAnalysisManager.createFunction(AddressSetView, boolean)`
    /// (AutoAnalysisManager.java:1132) → `schedule(new CreateFunctionCmd(targetSet, …), …)`.
    /// A command, for the same reasons as [`Scheduling::disassemble`]; `function_defined` remains
    /// the notification that functions *were created*.
    pub fn create_function(&mut self, set: &AddressSet) {
        self.schedule_one_time(FUNCTION_COMMAND, set);
    }

    /// Hand a set directly to one named analyzer (Ghidra
    /// `AutoAnalysisManager.scheduleOneTimeAnalysis(analyzer, set)`, AutoAnalysisManager.java:226)
    /// — the route for an analyzer that subscribes to no change channel. A no-op when that
    /// analyzer is not registered, matching Ghidra's "the caller holds the instance" contract:
    /// nothing else can trigger it, so nothing is silently dropped elsewhere.
    pub fn schedule_one_time(&mut self, name: &str, set: &AddressSet) {
        for i in 0..self.names.len() {
            if self.names[i] == name {
                self.pending[i] = self.pending[i].union(set);
            }
        }
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

    /// Register an analyzer if it applies to the program (Ghidra `canAnalyze`) and it is enabled.
    ///
    /// **Enablement** is Ghidra's own model: every analyzer has an on/off option under
    /// `Program.ANALYSIS_PROPERTIES` keyed by its name (`AbstractAnalyzer.setDefaultEnablement`),
    /// and that is how `analyzeHeadless` is told to skip one — a `-preScript` that flips the
    /// option. mosura has no per-program options database, so the same switch is read from
    /// `MOSURA_DISABLE_ANALYZERS`, a comma-separated list of analyzer names. It exists for the
    /// same reason Ghidra's does: measuring one analyzer's contribution means running with it off.
    /// Read through [`overrides`](crate::analysis::overrides) so an in-process caller sets it for
    /// its own thread; the environment variable remains the fallback.
    pub fn add_analyzer(&mut self, analyzer: Box<dyn Analyzer>, program: &Program) {
        if !analyzer.can_analyze(program) {
            return;
        }
        // Per-thread (see `analysis::overrides`): `std::env` here raced concurrent tests.
        if let Some(list) = crate::analysis::overrides::disabled_analyzers() {
            if list.split(',').any(|n| n.trim() == analyzer.name()) {
                return;
            }
        }
        self.sched.register(analyzer.priority().0, analyzer.analysis_type(), analyzer.name());
        self.analyzers.push(analyzer);
    }

    /// Scheduling handle for seeding initial work (e.g. the loader's entry points).
    pub fn scheduling(&mut self) -> &mut Scheduling {
        &mut self.sched
    }

    /// Run the worklist to a fixpoint: repeatedly run the highest-priority analyzer with
    /// pending work; each run may schedule more (Ghidra `startAnalysis` loop).
    /// `MOSURA_ANALYSIS_TRACE=1` prints one line per analyzer invocation (name, added-set size,
    /// wall time). The worklist is a fixpoint, so a mis-scheduled analyzer shows up as an endless
    /// repeating cycle rather than as a wrong answer — this makes that visible directly.
    pub fn run(&mut self, program: &mut Program) {
        let trace = std::env::var_os("MOSURA_ANALYSIS_TRACE").is_some();
        while let Some(i) = self.sched.next_task() {
            let set = self.sched.take(i);
            let analyzer = &self.analyzers[i];
            if trace {
                let t = std::time::Instant::now();
                let n = set.num_addresses();
                let r = set.ranges().count();
                analyzer.added(program, &set, &mut self.sched);
                eprintln!("[trace] {:>40} set={n} ranges={r} took={:?}", analyzer.name(), t.elapsed());
            } else {
                analyzer.added(program, &set, &mut self.sched);
            }
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
