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

pub mod analyzer;
pub mod loader;
pub mod manager;
pub mod priority;
pub mod program;
pub mod snapshot;

pub use program::Program;
pub use snapshot::Snapshot;

use std::path::Path;

/// An error from [`analyze_binary`].
#[derive(Debug)]
pub enum AnalysisError {
    Io(std::io::Error),
    Load(loader::LoadError),
}
impl std::fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalysisError::Io(e) => write!(f, "io: {e}"),
            AnalysisError::Load(e) => write!(f, "load: {e}"),
        }
    }
}
impl std::error::Error for AnalysisError {}
impl From<std::io::Error> for AnalysisError {
    fn from(e: std::io::Error) -> Self {
        AnalysisError::Io(e)
    }
}
impl From<loader::LoadError> for AnalysisError {
    fn from(e: loader::LoadError) -> Self {
        AnalysisError::Load(e)
    }
}

/// Run mosura's auto-analysis over a binary file and produce its converged
/// [`Snapshot`], to be diffed against the Ghidra golden.
///
/// **A2 today:** the ELF loader builds the [`Program`] memory map; the analyzer
/// framework (A3) and disassembly + function discovery (A4) are not ported yet, so
/// the snapshot carries blocks but no functions. The parity harness scores the
/// memory map and functions separately, so this drives the *blocks* dimension green
/// while functions stay red until A4.
pub fn analyze_binary(path: &Path) -> Result<Snapshot, AnalysisError> {
    let data = std::fs::read(path)?;
    let program = loader::load(&data)?;
    Ok(program.snapshot())
}
