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
//! (Ghidra propagates "X was defined" via the program's change-event queue, flushed after
//! every queue entry (`AnalysisTaskWrapper.run` → `flushPrivateEventQueue`,
//! AutoAnalysisManager.java:681); here the analyzers notify [`Scheduling`] directly during
//! their run — same delivery point, no hidden event bus.)

use crate::analysis::analyzer::{Analyzer, AnalyzerType};
use crate::analysis::priority::AnalysisPriority;
use crate::analysis::program::{AddressSet, Program};
use std::collections::BTreeMap;

/// One queued unit of work — Ghidra `BackgroundCommand` on the manager's ONE
/// `PriorityQueue<BackgroundCommand>` (AutoAnalysisManager.java:111). EVERY entry is a
/// command; an analyzer's run is just one kind (`AnalysisTask`). A command executes when
/// popped REGARDLESS of what is registered — commands have no subscribers to miss — and
/// each carries ITS OWN target set, never unioned with another entry's.
enum Command {
    /// `AnalysisTask` (AnalysisTask.java:35): run registered analyzer `i` over whatever its
    /// scheduler accumulated (`AnalysisScheduler.runAnalyzer`, AnalysisScheduler.java:171).
    Task(usize),
    /// `DisassembleCommand` (scheduled by `AutoAnalysisManager.disassemble`, :1128).
    Disassemble(AddressSet),
    /// `CreateFunctionCmd` (scheduled by `AutoAnalysisManager.createFunction`, :1132).
    CreateFunction(AddressSet),
    /// `OneShotAnalysisCommand` (`scheduleOneTimeAnalysis`, :226-236): a caller-held analyzer
    /// instance plus the set given at scheduling time.
    OneShot(Box<dyn Analyzer>, AddressSet),
}

impl Command {
    /// Display name for the trace, mirroring the Java class names.
    fn name<'a>(&'a self, analyzers: &'a [Box<dyn Analyzer>]) -> &'a str {
        match self {
            Command::Task(i) => analyzers[*i].name(),
            Command::Disassemble(_) => "DisassembleCommand",
            Command::CreateFunction(_) => "CreateFunctionCmd",
            Command::OneShot(a, _) => a.name(),
        }
    }
    fn set(&self, sched: &Scheduling) -> AddressSet {
        match self {
            Command::Task(i) => sched.pending[*i].clone(),
            Command::Disassemble(s) | Command::CreateFunction(s) | Command::OneShot(_, s) => {
                s.clone()
            }
        }
    }
}

/// The command queue + per-analyzer scheduling state, handed to an analyzer's
/// [`Analyzer::added`] so it can enqueue follow-on work.
#[derive(Default)]
pub struct Scheduling {
    /// Ghidra's `PriorityQueue<BackgroundCommand>` — a `TreeMap<Integer, LinkedList>`
    /// (PriorityQueue.java:30): lowest priority value first, FIFO within a priority. The
    /// `(priority, seq)` key encodes exactly that ordering.
    queue: BTreeMap<(i32, u64), Command>,
    seq: u64,
    /// The priority the currently-executing entry was queued at
    /// (`AnalysisTaskWrapper.taskPriority`, set from `queue.getFirstPriority()` at pop,
    /// AutoAnalysisManager.java:807-808) — the base of the active-relative command
    /// priorities (:1106-1118).
    active_priority: Option<i32>,
    // Per registered analyzer — Ghidra `AnalysisScheduler`:
    /// Accumulated "added" locations awaiting each analyzer (`AnalysisScheduler.addSet`).
    pending: Vec<AddressSet>,
    /// The one-task-in-queue dedup flag (`AnalysisScheduler.scheduled`,
    /// AnalysisScheduler.java:36): set when a `Task` is pushed, cleared when the set is
    /// swapped out at run — so notifications DURING a run queue a fresh task.
    scheduled: Vec<bool>,
    priority: Vec<i32>,
    ty: Vec<AnalyzerType>,
}

impl Scheduling {
    fn register(&mut self, priority: i32, ty: AnalyzerType) {
        self.pending.push(AddressSet::new());
        self.scheduled.push(false);
        self.priority.push(priority);
        self.ty.push(ty);
    }

    /// Push one entry onto the queue (Ghidra `PriorityQueue.add`, preserving FIFO within a
    /// priority).
    fn push(&mut self, priority: i32, cmd: Command) {
        self.queue.insert((priority, self.seq), cmd);
        self.seq += 1;
    }

    /// Route an added-location set to every analyzer consuming `ty`
    /// (`AnalysisTaskList.notifyAdded` → each `AnalysisScheduler.added`,
    /// AnalysisScheduler.java:74-82): union into the accumulator, then make sure one task is
    /// queued.
    fn notify(&mut self, ty: AnalyzerType, set: &AddressSet) {
        for i in 0..self.ty.len() {
            if self.ty[i] == ty {
                self.pending[i] = self.pending[i].union(set);
                self.schedule_task(i);
            }
        }
    }

    /// `AnalysisScheduler.schedule` (AnalysisScheduler.java:65-72): if no task for this
    /// analyzer is queued and it has pending work, queue one at the ANALYZER's own priority.
    fn schedule_task(&mut self, i: usize) {
        if !self.scheduled[i] && !self.pending[i].is_empty() {
            self.push(self.priority[i], Command::Task(i));
            self.scheduled[i] = true;
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
    ///
    /// Queued at `getDisassemblyPriority()` (:1106-1113): 2 less (= higher priority) than the
    /// task that is running, so a request made mid-analysis executes before the rest of the
    /// queue; plain `DISASSEMBLY` when nothing is running. An empty set is elided — Ghidra
    /// queues a command that then no-ops.
    pub fn disassemble(&mut self, set: &AddressSet) {
        if set.is_empty() {
            return;
        }
        let p = self.disassembly_priority();
        self.push(p, Command::Disassemble(set.clone()));
    }

    /// The explicit-priority variant — Ghidra
    /// `disassemble(AddressSetView, AnalysisPriority)` (AutoAnalysisManager.java:1136), used by
    /// `FunctionStartAnalyzer` (:844) to DELAY possible-function-start disassembly to the
    /// normal `DISASSEMBLY` band instead of the active-relative priority.
    pub fn disassemble_at(&mut self, set: &AddressSet, priority: AnalysisPriority) {
        if set.is_empty() {
            return;
        }
        self.push(priority.0, Command::Disassemble(set.clone()));
    }

    /// Schedule function creation at each address of `set` — Ghidra
    /// `AutoAnalysisManager.createFunction(AddressSetView, boolean)`
    /// (AutoAnalysisManager.java:1132) → `schedule(new CreateFunctionCmd(targetSet, …),
    /// getFunctionPriority())`, "1 higher [than disassembly], so disassembly happens first"
    /// (:1115-1118). A command, for the same reasons as [`Scheduling::disassemble`];
    /// `function_defined` remains the notification that functions *were created*.
    pub fn create_function(&mut self, set: &AddressSet) {
        if set.is_empty() {
            return;
        }
        let p = self.disassembly_priority() + 1;
        self.push(p, Command::CreateFunction(set.clone()));
    }

    /// Hand a caller-held analyzer instance one set — Ghidra
    /// `AutoAnalysisManager.scheduleOneTimeAnalysis(analyzer, set)` (AutoAnalysisManager.java:
    /// 226-236): each call wraps the instance and ITS set in a fresh `OneShotAnalysisCommand`
    /// queued at the analyzer's own priority. Two calls are two commands — sets are never
    /// unioned across calls.
    pub fn schedule_one_shot(&mut self, analyzer: Box<dyn Analyzer>, set: &AddressSet) {
        let p = analyzer.priority().0;
        self.push(p, Command::OneShot(analyzer, set.clone()));
    }

    /// `AutoAnalysisManager.getDisassemblyPriority` (:1106-1113): "a priority of 1 less than
    /// the current running task (a higher priority), or a normal disassembly priority if no
    /// task is running". (The Java comment says 1; the code subtracts 2, leaving room for the
    /// function-creation priority between.)
    fn disassembly_priority(&self) -> i32 {
        match self.active_priority {
            None => AnalysisPriority::DISASSEMBLY.0,
            Some(p) => p - 2,
        }
    }

    /// Swap out an analyzer's accumulated set and clear its `scheduled` flag — the atomic
    /// head of `AnalysisScheduler.runAnalyzer` (AnalysisScheduler.java:176-180). Clearing the
    /// flag BEFORE the run is load-bearing: work notified during the run queues a fresh task.
    fn take(&mut self, i: usize) -> AddressSet {
        self.scheduled[i] = false;
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
    /// option. mosura has no per-program options database, so the same switch is the program's
    /// [`Knobs::disabled_analyzers`](crate::switches::Knobs), a comma-separated list of analyzer
    /// names. It exists for the same reason Ghidra's does: measuring one analyzer's contribution
    /// means running with it off.
    pub fn add_analyzer(&mut self, analyzer: Box<dyn Analyzer>, program: &Program) {
        if !analyzer.can_analyze(program) {
            return;
        }
        // A value on the program, never the environment (which raced concurrent tests).
        if let Some(list) = program.knobs.disabled_analyzers.as_deref() {
            if list.split(',').any(|n| n.trim() == analyzer.name()) {
                return;
            }
        }
        self.sched.register(analyzer.priority().0, analyzer.analysis_type());
        self.analyzers.push(analyzer);
    }

    /// Scheduling handle for seeding initial work (e.g. the loader's entry points).
    pub fn scheduling(&mut self) -> &mut Scheduling {
        &mut self.sched
    }

    /// Drain the command queue (Ghidra `startAnalysis`'s loop, AutoAnalysisManager.java:
    /// 752-771 + `getNextTask` :798-809): pop the lowest-(priority, seq) entry, record its
    /// queued priority as the active priority (`AnalysisTaskWrapper.taskPriority`), execute
    /// it, repeat until empty. Executing an entry may push more — commands at
    /// active-relative priorities, analyzer tasks via the notifiers — so the queue drives to
    /// a fixpoint.
    ///
    /// `MOSURA_ANALYSIS_TRACE=1` prints one line per entry (name, set size, wall time). The
    /// queue is a fixpoint, so a mis-scheduled analyzer shows up as an endless repeating
    /// cycle rather than as a wrong answer — this makes that visible directly.
    pub fn run(&mut self, program: &mut Program) {
        let trace = crate::debug::on(crate::debug::Topic::Analysis);
        while let Some((&(prio, seq), _)) = self.sched.queue.first_key_value() {
            let cmd = self.sched.queue.remove(&(prio, seq)).expect("just observed");
            self.sched.active_priority = Some(prio);
            let t = trace.then(|| {
                let set = cmd.set(&self.sched);
                let name = cmd.name(&self.analyzers).to_string();
                // Printed on ENTRY as well as exit, so an entry that never returns names
                // itself. With only the exit line, a hang shows up as the *previous* entry
                // having finished and nothing after it, which points at the wrong one.
                debug!(crate::debug::Topic::Analysis,
                    "{:>40} set={} ranges={} ...",
                    name,
                    set.num_addresses(),
                    set.ranges().count()
                );
                (name, std::time::Instant::now())
            });
            match cmd {
                Command::Task(i) => {
                    let set = self.sched.take(i);
                    // `runAnalyzer` skips an empty added set (AnalysisScheduler.java:185).
                    if !set.is_empty() {
                        self.analyzers[i].added(program, &set, &mut self.sched);
                    }
                }
                // The free-standing commands construct their executor at run time, as Ghidra
                // constructs a fresh `DisassembleCommand`/`CreateFunctionCmd` object per
                // schedule — nothing here consults the registered-analyzer list.
                Command::Disassemble(set) => {
                    if let Some(d) = crate::analysis::analyzers::Disassembler::for_program(program)
                    {
                        crate::analysis::analyzer::Analyzer::added(
                            &d,
                            program,
                            &set,
                            &mut self.sched,
                        );
                    }
                }
                Command::CreateFunction(set) => {
                    let f = crate::analysis::analyzers::FunctionCreator::new(program);
                    crate::analysis::analyzer::Analyzer::added(&f, program, &set, &mut self.sched);
                }
                Command::OneShot(a, set) => {
                    a.added(program, &set, &mut self.sched);
                }
            }
            if let Some((name, t)) = t {
                debug!(crate::debug::Topic::Analysis, "{:>40} took={:?}", name, t.elapsed());
            }
        }
        self.sched.active_priority = None;
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

    /// ⭐ THE COMMAND-QUEUE MVE (command-queue-modelled-as-change-channel). Ghidra's
    /// `AutoAnalysisManager.createFunction` (AutoAnalysisManager.java:1132) schedules a
    /// free-standing `CreateFunctionCmd` onto the manager's ONE `PriorityQueue<BackgroundCommand>`
    /// (:860-865), and the drain loop (:752-771) executes it REGARDLESS of which analyzers are
    /// registered — a command is not a notification and has no subscribers to miss.
    ///
    /// mosura routed the command to a REGISTERED analyzer by name, so in a manager without that
    /// registration the request silently evaporated — the fs_mgr half of the 374-function WAR2
    /// listing hole.
    #[test]
    fn a_command_executes_in_a_manager_with_no_matching_analyzer() {
        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 8, 1);
        let base = Address::new(ram, 0x40_1000);
        let mut program =
            Program::new(spaces, ram, "x86:LE:64:default", "gcc", base, false, 64);
        program.memory.add_block(".text", base, 0x1000, true, false, true, Some(vec![0; 0x1000]));

        // NO analyzers registered at all.
        let mut mgr = AutoAnalysisManager::new();
        let mut seed = AddressSet::new();
        seed.add_range(ram, 0x40_1000, 0x40_1000);
        mgr.scheduling().create_function(&seed);
        mgr.run(&mut program);

        assert!(
            program.function_manager.function_at(Address::new(ram, 0x40_1000)).is_some(),
            "a scheduled CreateFunctionCmd must execute regardless of registered analyzers \
             (Ghidra AutoAnalysisManager.java:1132 + the :752 drain loop)"
        );
    }

    /// Recorder analyzer: appends each invocation's address list to a shared log.
    struct Recorder {
        log: Rc<std::cell::RefCell<Vec<Vec<u64>>>>,
    }
    impl Analyzer for Recorder {
        fn name(&self) -> &str { "Recorder" }
        fn analysis_type(&self) -> AnalyzerType { AnalyzerType::OneTime }
        fn priority(&self) -> AnalysisPriority { AnalysisPriority::FUNCTION }
        fn added(&self, _p: &mut Program, set: &AddressSet, _s: &mut Scheduling) -> bool {
            self.log.borrow_mut().push(set.ranges().flat_map(|r| r.min..=r.max).collect());
            true
        }
    }

    /// Ghidra `scheduleOneTimeAnalysis` (AutoAnalysisManager.java:226-236): EACH call wraps the
    /// analyzer and ITS OWN set in a fresh `OneShotAnalysisCommand` on the queue — two calls are
    /// two commands, executed FIFO within a priority (`PriorityQueue` is a
    /// `TreeMap<Integer, LinkedList>`, PriorityQueue.java:30). Sets are never unioned across
    /// calls: batching in Ghidra happens only in `AnalysisScheduler.addSet` for notification
    /// channels, never for commands.
    #[test]
    fn each_scheduled_command_keeps_its_own_set_in_fifo_order() {
        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 8, 1);
        let mut program =
            Program::new(spaces, ram, "x86:LE:64:default", "gcc", Address::new(ram, 0), false, 64);

        let log = Rc::new(std::cell::RefCell::new(Vec::new()));
        // NOTHING registered: the analyzer instances ride inside the commands, as Ghidra's
        // `OneShotAnalysisCommand` holds the instance the caller constructed.
        let mut mgr = AutoAnalysisManager::new();

        let mut a = AddressSet::new();
        a.add_range(RAM, 0x1000, 0x1000);
        let mut b = AddressSet::new();
        b.add_range(RAM, 0x2000, 0x2000);
        mgr.scheduling().schedule_one_shot(Box::new(Recorder { log: log.clone() }), &a);
        mgr.scheduling().schedule_one_shot(Box::new(Recorder { log: log.clone() }), &b);
        mgr.run(&mut program);

        assert_eq!(
            *log.borrow(),
            vec![vec![0x1000], vec![0x2000]],
            "two scheduled commands must execute as two, each with its own set, in FIFO order \
             (Ghidra OneShotAnalysisCommand — never unioned into one batch)"
        );
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
