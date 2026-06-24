//! A0 — the auto-analysis parity harness (plan `docs/analysis-port-plan.md` §3).
//!
//! The analog of `tests/disasm_golden.rs` for the analysis port: for each binary
//! in the real-binary corpus (`oracle/analysis-corpus/*.elf`) it parses the
//! committed Ghidra snapshot (`goldens/analysis/<name>.snapshot`), runs mosura's
//! [`analysis::analyze_binary`], and diffs the two **structurally exact**.
//!
//! mosura has no loader/framework/analyzers yet (A1–A4), so `analyze_binary`
//! returns `Unimplemented` and every case fails by construction — a clean,
//! intentional **red baseline**. As A1–A4 land, bump [`EXPECTED_ANALYSIS_PASS`];
//! the baseline turns from red toward full corpus parity, exactly as the SLEIGH
//! `EXPECTED_DISASM_PASS` ratchet did.

use mosura::analysis::{self, snapshot};
use mosura::conformance::Tally;
use mosura::paths::{analysis_corpus_dir, analysis_goldens_dir};

/// Number of corpus binaries mosura currently reproduces exactly. Ratchets up as
/// the loader (A2) → framework (A3) → disassembly/functions (A4) land. **0 today**
/// (no analysis ported). Never lower it for a faithful change.
const EXPECTED_ANALYSIS_PASS: usize = 0;

/// The corpus, paired with its committed golden. Kept explicit (not a glob) so a
/// missing/renamed golden is a loud failure rather than a silently skipped case.
const CORPUS: &[&str] = &["freestanding", "basic"];

#[test]
fn analysis_parity_red_baseline() {
    let corpus_dir = analysis_corpus_dir();
    let goldens_dir = analysis_goldens_dir();
    let mut tally = Tally::default();

    for name in CORPUS {
        // The golden must exist and parse — that part of the oracle is real today.
        let golden_path = goldens_dir.join(format!("{name}.snapshot"));
        let golden_text = std::fs::read_to_string(&golden_path)
            .unwrap_or_else(|e| panic!("missing golden {}: {e}", golden_path.display()));
        let golden = snapshot::parse(&golden_text);
        assert!(
            !golden.functions.is_empty() && !golden.blocks.is_empty(),
            "golden {name} parsed empty — snapshot format regression?"
        );
        assert!(golden.render().contains("mosura-analysis-snapshot v1"), "render header");

        // mosura's side: not ported yet → Unimplemented → records a miss.
        let bin = corpus_dir.join(format!("{name}.elf"));
        let produced = analysis::analyze_binary(&bin);
        tally.record(produced.as_ref() == Ok(&golden));
    }

    eprintln!("analysis parity: {tally} (expected {EXPECTED_ANALYSIS_PASS})");
    assert_eq!(
        tally.passed, EXPECTED_ANALYSIS_PASS,
        "analysis parity ratchet moved: passed={}, expected={EXPECTED_ANALYSIS_PASS} \
         (bump EXPECTED_ANALYSIS_PASS when a phase lands; investigate if it dropped)",
        tally.passed
    );
    assert_eq!(tally.total, CORPUS.len(), "every corpus binary must be evaluated");
}
