//! `Analyzer` / `AnalyzerType` — a port of Ghidra's `app/services/Analyzer.java`
//! and `AnalyzerType` (A3).
//!
//! An analyzer is a self-contained unit of the auto-analysis pipeline. The
//! [`AutoAnalysisManager`](crate::analysis::manager::AutoAnalysisManager) runs it
//! in priority order over an [`AddressSet`] of locations of its
//! [`AnalyzerType`] that "appeared" (code disassembled, a function created, …).
//! Running it mutates the [`Program`] and may, via the [`Scheduling`] handle,
//! enqueue work for other analyzers — the worklist runs to a fixpoint.

use crate::analysis::manager::Scheduling;
use crate::analysis::program::{AddressSet, Program};
use crate::analysis::priority::AnalysisPriority;

/// The kind of program change an analyzer consumes (Ghidra `AnalyzerType`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnalyzerType {
    /// Runs on newly added bytes / memory blocks.
    Byte,
    /// Runs on newly disassembled instructions (code).
    Instruction,
    /// Runs on newly created functions.
    Function,
    /// Runs when a function's modifiers change.
    FunctionModifiers,
    /// Runs when a function's signature changes.
    FunctionSignatures,
    /// Runs on newly created data.
    Data,
}

/// An auto-analysis pass (Ghidra `Analyzer`).
pub trait Analyzer {
    /// Unique analyzer name.
    fn name(&self) -> &str;

    /// The kind of change this analyzer consumes (which worklist it belongs to).
    fn analysis_type(&self) -> AnalyzerType;

    /// Scheduling priority (lower runs earlier).
    fn priority(&self) -> AnalysisPriority;

    /// Whether this analyzer applies to the program (e.g. architecture check).
    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }

    /// Process the locations in `set` that were just added. Mutates `program`, and may
    /// schedule follow-on work for other analyzers via `sched`. Returns whether it did
    /// useful work (Ghidra's `added` return).
    fn added(&self, program: &mut Program, set: &AddressSet, sched: &mut Scheduling) -> bool;
}
