//! mosura — a Rust reimplementation of Ghidra's logic.
//!
//! Early-stage. The first port target is the **SLEIGH engine** (disassembler +
//! p-code). Until it lands, the engine entry points in [`sleigh`] return
//! [`Unimplemented`], and the conformance harness ([`conformance`]) uses them to
//! hold a *red baseline* against the Ghidra reference oracle (see
//! `docs/testing-baseline.md`).

// cosmetic; fires on prose doc-comment paragraphs that continue after a markdown list,
// where clippy's suggested 4-space indent would misrender the prose as an indented block.
#![allow(clippy::doc_lazy_continuation)]

#[macro_use]
pub mod debug;
pub mod switches;
pub mod resources;
pub mod analysis;
pub mod datatest;
pub mod decompile;
pub mod lang;
pub mod recompile;
pub mod sleigh;

// THE DEV TIER (`docs/product/architecture.md` §6.4): the workspace paths, the developer config,
// the oracle captures, the goldens, the conformance harness and the C-similarity scorer exist to
// develop mosura against its oracles, not to use it. They read the filesystem by workspace layout
// and spawn the oracle tools, so a release library (`cargo build --release -p mosura-capi`, no
// `dev` feature) compiles none of them; tests and examples get them through the crate's own
// dev-dependency (`mosura-core = { path = ".", features = ["dev"] }` in Cargo.toml).
#[cfg(any(test, feature = "dev"))]
pub mod ccompare;
#[cfg(any(test, feature = "dev"))]
pub mod conformance;
#[cfg(any(test, feature = "dev"))]
pub mod devcfg;
#[cfg(any(test, feature = "dev"))]
pub mod golden;
#[cfg(any(test, feature = "dev"))]
pub mod oraclecache;
#[cfg(any(test, feature = "dev"))]
pub mod paths;
#[cfg(any(test, feature = "dev"))]
pub mod speccache;

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
