//! The **auto-analysis port** (A0+; plan `docs/analysis-port-plan.md`).
//!
//! A faithful port of Ghidra's auto-analysis — the subsystem that takes a binary
//! *file* and decides *what to decompile*: loaders, the priority-worklist analyzer
//! framework, disassembly + function discovery, references + `SymbolicPropogator`,
//! and the decompiler-driven switch/parameter analyzers. Distinct from the
//! decompiler port (`crate::decompile`), which works on one already-located
//! function.
//!
//! **A0 (this module today): the oracle contract + harness only.** [`snapshot`]
//! defines the canonical converged-`Program` view captured from Ghidra and
//! committed under `goldens/analysis/`; [`analyze_binary`] is the entry point
//! mosura's analyzers will implement, returning [`Unimplemented`] until A1–A4
//! land. `tests/analysis_parity.rs` holds the red baseline against the goldens.

pub mod snapshot;

pub use snapshot::Snapshot;

use crate::Unimplemented;
use std::path::Path;

/// Run mosura's auto-analysis over a binary file and produce its converged
/// [`Snapshot`], to be diffed against the Ghidra golden.
///
/// Not yet ported: the loader (A2), the analyzer framework (A3), and disassembly
/// + function discovery (A4) do not exist. Returns [`Unimplemented`] so the
/// parity harness records a clean, intentional red baseline (exactly as the
/// SLEIGH engine did before stage 1b).
pub fn analyze_binary(_path: &Path) -> Result<Snapshot, Unimplemented> {
    Err(Unimplemented("analysis::analyze_binary (loader/framework — A1–A4)"))
}
