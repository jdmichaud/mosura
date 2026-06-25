//! mosura — a Rust reimplementation of Ghidra's logic.
//!
//! Early-stage. The first port target is the **SLEIGH engine** (disassembler +
//! p-code). Until it lands, the engine entry points in [`sleigh`] return
//! [`Unimplemented`], and the conformance harness ([`conformance`]) uses them to
//! hold a *red baseline* against the Ghidra reference oracle (see
//! `docs/testing-baseline.md`).

pub mod analysis;
pub mod ccompare;
pub mod conformance;
pub mod datatest;
pub mod decompile;
pub mod golden;
pub mod lang;
pub mod paths;
pub mod sleigh;

/// Marker error for a pipeline stage that has not been ported yet.
///
/// The conformance baseline distinguishes "mosura produced a wrong answer" from
/// "mosura hasn't implemented this stage" — the latter is the expected state
/// early on, and is what keeps the baseline a clean, intentional red.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unimplemented(pub &'static str);

impl std::fmt::Display for Unimplemented {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "not yet ported: {}", self.0)
    }
}

impl std::error::Error for Unimplemented {}
