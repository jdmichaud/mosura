//! `AnalysisPriority` — a port of Ghidra's `app/services/AnalysisPriority.java` (A3).
//!
//! The fixed priority ladder for the auto-analysis worklist: analyzers run in
//! ascending priority value (lower = earlier = more certain), 100 apart, with
//! `before()`/`after()` for ±1 nudges. Lower runs first.

/// A scheduling priority within the analysis pipeline.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct AnalysisPriority(pub i32);

impl AnalysisPriority {
    /// Full-format analysis — the first analyzers after import.
    pub const FORMAT: AnalysisPriority = AnalysisPriority(100);
    /// Block analysis; initial entry-point disassembly happens at/after this.
    pub const BLOCK: AnalysisPriority = AnalysisPriority(200);
    /// Disassembly of code reached by solid flow.
    pub const DISASSEMBLY: AnalysisPriority = AnalysisPriority(300);
    /// Raw-code analysis (e.g. non-returning functions) before functions are laid down.
    pub const CODE: AnalysisPriority = AnalysisPriority(400);
    /// Function creation/analysis.
    pub const FUNCTION: AnalysisPriority = AnalysisPriority(500);
    /// Reference recovery.
    pub const REFERENCE: AnalysisPriority = AnalysisPriority(600);
    /// Data creation (strings, pointers).
    pub const DATA: AnalysisPriority = AnalysisPriority(700);
    /// Function identification (name/class).
    pub const FUNCTION_ID: AnalysisPriority = AnalysisPriority(800);
    /// Data-type propagation — as late as possible.
    pub const DATA_TYPE_PROPAGATION: AnalysisPriority = AnalysisPriority(900);
    /// Speculative, lowest-priority analysis.
    pub const LOW: AnalysisPriority = AnalysisPriority(10000);
    /// Highest priority.
    pub const HIGHEST: AnalysisPriority = AnalysisPriority(1);

    /// A priority slightly higher (runs a little earlier) than this one.
    pub const fn before(self) -> AnalysisPriority {
        AnalysisPriority(self.0 - 1)
    }
    /// A priority slightly lower (runs a little later) than this one.
    pub const fn after(self) -> AnalysisPriority {
        AnalysisPriority(self.0 + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ladder_orders_ascending() {
        assert!(AnalysisPriority::BLOCK < AnalysisPriority::FUNCTION);
        assert!(AnalysisPriority::DISASSEMBLY.before() < AnalysisPriority::DISASSEMBLY);
        assert!(AnalysisPriority::FUNCTION.after() > AnalysisPriority::FUNCTION);
        assert!(AnalysisPriority::HIGHEST < AnalysisPriority::FORMAT);
    }
}
