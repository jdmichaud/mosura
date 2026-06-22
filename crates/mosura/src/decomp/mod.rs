//! The decompiler stage (raw p-code → C), planned in `docs/decompiler-plan.md`.
//!
//! Built bottom-up against Ghidra's decompiler as the golden oracle, mirroring its
//! action pipeline: CFG → SSA → simplification → types → structuring → C.

pub mod ccompare;
pub mod cfg;
pub mod cprint;
pub mod divrecover;
pub mod jumptable;
pub mod simplify;
pub mod ssa;
pub mod types;

pub use cfg::Funcdata;
