//! The transformation framework — a port of Ghidra's `Action`/`ActionGroup`/`Rule`/
//! `ActionPool` (`action.hh`/`action.cc`). This is the pipeline spine: the decompiler is
//! a sequence of [`Action`]s mutating a [`Funcdata`] to a fixpoint, and most analysis is
//! [`Rule`]s applied to ops by an [`ActionPool`].
//!
//! The interactive breakpoint/debug/warning machinery is intentionally omitted; the
//! `apply → change-count → loop-while-changed` core is preserved exactly.

use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;

/// Rule-application trace (the mosura side of the Ghidra `OPACTION_DEBUG` diff, Task #2). Off by
/// default and completely inert unless the `MOSURA_TRACE` environment variable is set, so normal
/// decompilation (and the corpus) is byte-identical. When enabled, [`ActionPool::apply`] emits, for
/// every rule that changes an op, a block mirroring Ghidra's `debugModPrint` format so one differ
/// can parse both traces keyed on (rule name, op address, opcode):
/// ```text
/// DEBUG <n>: <rulename>
/// <op before>
///    <op after>
/// ```
mod trace {
    use super::Funcdata;
    use super::OpId;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    thread_local! {
        /// Set around the alias-probe rule-pool run (on a cloned Funcdata) so its firings do not
        /// double the trace — only the real pipeline's rule applications are recorded.
        static SUPPRESS: Cell<bool> = const { Cell::new(false) };
    }

    /// Whether `MOSURA_TRACE` is set (cached once) and we are not inside a suppressed scope.
    pub fn enabled() -> bool {
        static ON: OnceLock<bool> = OnceLock::new();
        let on = *ON.get_or_init(|| std::env::var_os("MOSURA_TRACE").is_some());
        on && !SUPPRESS.with(|s| s.get())
    }

    /// Run `f` with the trace suppressed (used for the alias-probe pool on a cloned function).
    pub fn suppressed<R>(f: impl FnOnce() -> R) -> R {
        SUPPRESS.with(|s| {
            let prev = s.replace(true);
            let r = f();
            s.set(prev);
            r
        })
    }

    /// Emit one before/after block for a rule that just modified `op`.
    pub fn emit(rulename: &str, op: OpId, data: &Funcdata, before: &str) {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        println!("DEBUG {n}: {rulename}\n{before}\n   {}", data.op_str(op));
    }
}

/// Run `f` (an alias-probe rule-pool pass on a cloned function) with the `MOSURA_TRACE` output
/// suppressed, so the probe's rule firings do not double the real pipeline's trace.
pub fn with_suppressed_trace<R>(f: impl FnOnce() -> R) -> R {
    trace::suppressed(f)
}

/// Wall-clock accounting for the pipeline (perf work). Off by default and completely inert
/// unless the `MOSURA_PERF` environment variable is set; when on, [`ActionGroup::apply`]
/// accumulates time per child action and [`ActionPool::apply`] per rule, and [`perf::dump`]
/// prints the totals to stderr. Never touches decompiler output.
pub mod perf {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::OnceLock;
    use std::time::Duration;

    thread_local! {
        static ACCUM: RefCell<HashMap<(&'static str, String), (Duration, u64)>> =
            RefCell::new(HashMap::new());
    }

    /// Whether `MOSURA_PERF` is set (cached once).
    pub fn enabled() -> bool {
        static ON: OnceLock<bool> = OnceLock::new();
        *ON.get_or_init(|| std::env::var_os("MOSURA_PERF").is_some())
    }

    /// Add `dur` under (`kind`, `name`) — kind is "action" or "rule".
    pub fn record(kind: &'static str, name: &str, dur: Duration) {
        ACCUM.with(|a| {
            let mut a = a.borrow_mut();
            let e = a.entry((kind, name.to_string())).or_insert((Duration::ZERO, 0));
            e.0 += dur;
            e.1 += 1;
        });
    }

    /// Print accumulated totals (sorted by time, worst first) to stderr and clear them.
    pub fn dump() {
        ACCUM.with(|a| {
            let mut rows: Vec<_> = a.borrow_mut().drain().collect();
            rows.sort_by(|x, y| y.1 .0.cmp(&x.1 .0));
            for ((kind, name), (dur, calls)) in rows {
                eprintln!("{:>10.3}ms  {:>8} calls  {kind:6} {name}", dur.as_secs_f64() * 1e3, calls);
            }
        });
    }
}

/// One transformation pass over a function. `apply` does the work and returns the number
/// of transformations made (0 ⇒ nothing changed). Composed by [`ActionGroup`].
pub trait Action {
    fn name(&self) -> &str;
    /// Apply once; return the count of changes made this call.
    fn apply(&mut self, data: &mut Funcdata) -> u32;
    /// Reset any per-function state before a fresh run (default: nothing).
    fn reset(&mut self, _data: &mut Funcdata) {}
}

/// An ordered list of actions (Ghidra's `ActionGroup`). When `restart` is set it behaves
/// as Ghidra's `ActionRestartGroup`: re-run the whole sequence until a full pass makes no
/// change (fixpoint).
pub struct ActionGroup {
    name: String,
    list: Vec<Box<dyn Action>>,
    restart: bool,
}

impl ActionGroup {
    /// A group run once, in order.
    pub fn once(name: impl Into<String>) -> ActionGroup {
        ActionGroup { name: name.into(), list: Vec::new(), restart: false }
    }
    /// A group re-run to fixpoint (`ActionRestartGroup`).
    pub fn restart(name: impl Into<String>) -> ActionGroup {
        ActionGroup { name: name.into(), list: Vec::new(), restart: true }
    }
    /// Append an action (builder style).
    pub fn then(mut self, a: impl Action + 'static) -> ActionGroup {
        self.list.push(Box::new(a));
        self
    }
    pub fn push(&mut self, a: Box<dyn Action>) {
        self.list.push(a);
    }
    pub fn len(&self) -> usize {
        self.list.len()
    }
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }
}

impl Action for ActionGroup {
    fn name(&self) -> &str {
        &self.name
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        let mut total = 0;
        let timing = perf::enabled();
        loop {
            let mut round = 0;
            for a in &mut self.list {
                if timing {
                    let t0 = std::time::Instant::now();
                    round += a.apply(data);
                    perf::record("action", a.name(), t0.elapsed());
                } else {
                    round += a.apply(data);
                }
            }
            total += round;
            if !self.restart || round == 0 {
                break;
            }
        }
        total
    }
    fn reset(&mut self, data: &mut Funcdata) {
        for a in &mut self.list {
            a.reset(data);
        }
    }
}

/// A peephole transformation matched against ops (Ghidra's `Rule`). Applied by an
/// [`ActionPool`] to every op whose opcode is in [`oplist`](Rule::oplist).
pub trait Rule {
    fn name(&self) -> &str;
    /// Opcodes this rule applies to. Empty ⇒ every op.
    fn oplist(&self) -> Vec<OpCode>;
    /// Try to transform `op`; return the count of changes (0 ⇒ no match).
    fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32;
    fn reset(&mut self, _data: &mut Funcdata) {}
}

/// An action that applies a set of [`Rule`]s to every op, repeating to fixpoint (Ghidra's
/// `ActionPool`). Dead ops are skipped; a rule that kills an op stops further rules on it.
pub struct ActionPool {
    name: String,
    rules: Vec<Box<dyn Rule>>,
}

impl ActionPool {
    pub fn new(name: impl Into<String>) -> ActionPool {
        ActionPool { name: name.into(), rules: Vec::new() }
    }
    pub fn with(mut self, r: impl Rule + 'static) -> ActionPool {
        self.rules.push(Box::new(r));
        self
    }
    pub fn len(&self) -> usize {
        self.rules.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl Action for ActionPool {
    fn name(&self) -> &str {
        &self.name
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        use std::collections::HashMap;
        let mut total = 0;
        let tracing = trace::enabled();
        let timing = perf::enabled();
        // `perop[opc]` = the indices of rules registered for opcode `opc`, in registration
        // (= priority) order — Ghidra's `ActionPool::addRule` appending each rule to
        // `perop[opcode]` (action.cc:740). Computed lazily per distinct opcode: a rule with an
        // empty oplist is universal (Ghidra `Rule::getOpList` default = every CPUI opcode), so it
        // is included in every opcode's list, still in priority order. Rebuilt per `apply` call
        // (cheap: ~40 rules × the opcodes that actually occur).
        let mut perop: HashMap<OpCode, Vec<usize>> = HashMap::new();
        loop {
            let mut round = 0;
            // Ghidra `ActionPool::apply` (action.cc:877) iterates `data.beginOpAll()..endOpAll()`,
            // i.e. the `optree` keyed by `SeqNum` — ops in (space index, address offset, uniq) order,
            // not op-creation order. `uniq` orders ops sharing a pc: original ops by their per-instr
            // p-code index, ops created mid-simplification by a monotonic counter (Funcdata::new_op*
            // sets `uniq = ops.len()`), so a rewritten op is visited in its address neighbourhood.
            let mut ids: Vec<OpId> = data.op_ids().collect();
            ids.sort_by_key(|&id| {
                let s = data.op(id).seqnum;
                (s.pc.space.0, s.pc.offset, s.uniq)
            });
            for id in ids {
                if data.op(id).is_dead() {
                    continue;
                }
                // Ghidra `ActionPool::processOp` (action.cc:822): try the op's rules in priority
                // order; when a firing changes the opcode, restart at index 0 on the *new* opcode's
                // list (a higher-priority rule always gets first crack at the rewritten op) — the
                // confluence that a flat fixpoint lacks. Tracks the live opcode; stops if the op dies.
                let mut opc = data.op(id).code();
                let mut rule_index = 0usize;
                loop {
                    let list = perop.entry(opc).or_insert_with(|| {
                        self.rules
                            .iter()
                            .enumerate()
                            .filter(|(_, r)| {
                                let l = r.oplist();
                                l.is_empty() || l.contains(&opc)
                            })
                            .map(|(i, _)| i)
                            .collect()
                    });
                    if rule_index >= list.len() {
                        break;
                    }
                    let r_idx = list[rule_index];
                    rule_index += 1;
                    let before = tracing.then(|| data.op_str(id));
                    let changed = if timing {
                        let t0 = std::time::Instant::now();
                        let changed = self.rules[r_idx].apply_op(id, data);
                        perf::record("rule", self.rules[r_idx].name(), t0.elapsed());
                        changed
                    } else {
                        self.rules[r_idx].apply_op(id, data)
                    };
                    round += changed;
                    if changed > 0 {
                        if let Some(before) = before {
                            trace::emit(self.rules[r_idx].name(), id, data, &before);
                        }
                        if data.op(id).is_dead() {
                            break; // op consumed by a rule; stop applying rules to it
                        }
                    }
                    // On an opcode change (Ghidra: whether or not the rule reported a change),
                    // restart from the top of the new opcode's priority list.
                    let new_opc = data.op(id).code();
                    if new_opc != opc {
                        opc = new_opc;
                        rule_index = 0;
                    }
                }
            }
            total += round;
            if round == 0 {
                break;
            }
        }
        total
    }
    fn reset(&mut self, data: &mut Funcdata) {
        for r in &mut self.rules {
            r.reset(data);
        }
    }
}

/// Ghidra's `rule_onceperfunc` flag (action.hh) as a wrapper: after its first `apply`, the wrapped
/// action is `status_end` — it returns 0 on every later call until `reset`, *regardless* of whether
/// that first application reported changes (`Action::perform`, action.cc:349-357: `if ((count>0) ||
/// ((flags&rule_onceperfunc)!=0)) status = status_end`, and `case status_end: return 0; // Rule
/// applied, do not repeat until reset`). Ghidra uses this for members of repeating groups that must
/// fire exactly once per function at their slot — e.g. `ActionLaneDivide` (coreaction.cc:585
/// constructor flags) inside the repeating `actstackstall` group (coreaction.cc:5652). Wrap a member
/// in this when it joins a `restart` group; `reset` re-arms it for the next function.
pub struct OncePerFunc<A: Action> {
    inner: A,
    done: bool,
}

impl<A: Action> OncePerFunc<A> {
    /// Wrap `inner` so it applies once per function (until `reset`).
    pub fn new(inner: A) -> OncePerFunc<A> {
        OncePerFunc { inner, done: false }
    }
}

impl<A: Action> Action for OncePerFunc<A> {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        if self.done {
            return 0; // status_end — do not repeat until reset (action.cc:343-344)
        }
        self.done = true; // rule_onceperfunc: end after the first perform even if count==0
        self.inner.apply(data)
    }
    fn reset(&mut self, data: &mut Funcdata) {
        self.done = false;
        self.inner.reset(data);
    }
}

/// The first action of the pipeline (Ghidra's `ActionStart`): a marker that does nothing
/// itself. The real phases (heritage, rules, …) are appended to the universal group as
/// they are ported.
pub struct ActionStart;

impl Action for ActionStart {
    fn name(&self) -> &str {
        "start"
    }
    fn apply(&mut self, _data: &mut Funcdata) -> u32 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::op::flags as opflags;
    use super::super::space::{Address, SpaceManager};
    use super::super::{OpCode, SeqNum};

    /// A tiny Funcdata: three INT_ADD ops in `ram`.
    fn three_adds() -> Funcdata {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        for i in 0..3 {
            let a = f.new_input(4, Address::new(reg, 8 * i));
            let seq = SeqNum { pc: Address::new(ram, i), uniq: i as u32 };
            f.new_op(OpCode::IntAdd, seq, vec![a]);
        }
        f
    }

    /// An action that marks one more non-dead op dead per pass — drives the restart loop
    /// to fixpoint (all ops dead), proving the group repeats and terminates.
    struct MarkOneDead;
    impl Action for MarkOneDead {
        fn name(&self) -> &str {
            "mark-one-dead"
        }
        fn apply(&mut self, data: &mut Funcdata) -> u32 {
            for id in data.op_ids() {
                if !data.op(id).is_dead() {
                    data.op_mut(id).flags |= opflags::DEAD;
                    return 1;
                }
            }
            0
        }
    }

    #[test]
    fn restart_group_runs_to_fixpoint() {
        let mut f = three_adds();
        let mut g = ActionGroup::restart("test").then(ActionStart).then(MarkOneDead);
        let changes = g.apply(&mut f);
        assert_eq!(changes, 3, "should mark all three ops dead, one per pass");
        assert!(f.op_ids().all(|id| f.op(id).is_dead()));
    }

    /// A rule that marks each INT_ADD dead — proves ActionPool dispatches by opcode and
    /// reaches fixpoint.
    struct KillAdds;
    impl Rule for KillAdds {
        fn name(&self) -> &str {
            "kill-adds"
        }
        fn oplist(&self) -> Vec<OpCode> {
            vec![OpCode::IntAdd]
        }
        fn apply_op(&mut self, op: OpId, data: &mut Funcdata) -> u32 {
            data.op_mut(op).flags |= opflags::DEAD;
            1
        }
    }

    #[test]
    fn action_pool_applies_rules_by_opcode() {
        let mut f = three_adds();
        let mut pool = ActionPool::new("pool").with(KillAdds);
        let changes = pool.apply(&mut f);
        assert_eq!(changes, 3);
        assert!(f.op_ids().all(|id| f.op(id).is_dead()));
    }

    /// An action that always reports a change and counts its applications — the shape that would
    /// hang a restart group without the `rule_onceperfunc` wrapper.
    struct AlwaysChanges {
        applied: std::rc::Rc<std::cell::Cell<u32>>,
    }
    impl Action for AlwaysChanges {
        fn name(&self) -> &str {
            "always-changes"
        }
        fn apply(&mut self, _data: &mut Funcdata) -> u32 {
            self.applied.set(self.applied.get() + 1);
            1
        }
    }

    /// `rule_onceperfunc` semantics (action.cc:349-357): the wrapped action applies exactly once —
    /// later calls return 0 without invoking it — and `reset` re-arms it.
    #[test]
    fn once_per_func_applies_once_until_reset() {
        let mut f = three_adds();
        let applied = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut once = OncePerFunc::new(AlwaysChanges { applied: applied.clone() });
        assert_eq!(once.apply(&mut f), 1);
        assert_eq!(once.apply(&mut f), 0, "status_end: no repeat until reset");
        assert_eq!(applied.get(), 1, "inner action must not be re-invoked");
        once.reset(&mut f);
        assert_eq!(once.apply(&mut f), 1, "reset re-arms the once-per-function action");
        assert_eq!(applied.get(), 2);
    }

    /// Inside a restart group, a `OncePerFunc` member fires on the first pass only; the group still
    /// runs to its fixpoint driven by the other members (Ghidra: ActionLaneDivide in the repeating
    /// actstackstall group, coreaction.cc:5652).
    #[test]
    fn once_per_func_in_restart_group_fires_once() {
        let mut f = three_adds();
        let applied = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut g = ActionGroup::restart("test")
            .then(OncePerFunc::new(AlwaysChanges { applied: applied.clone() }))
            .then(MarkOneDead);
        let changes = g.apply(&mut f);
        // Pass 1: once-member fires (+1) + one op marked dead (+1); passes 2-3: one op each;
        // pass 4: zero — fixpoint. The once-member contributed exactly one application.
        assert_eq!(changes, 4);
        assert_eq!(applied.get(), 1, "once-per-func member fired on the first pass only");
        assert!(f.op_ids().all(|id| f.op(id).is_dead()));
    }
}
