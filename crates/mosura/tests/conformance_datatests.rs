//! Conformance baseline against Ghidra's decompiler datatests.
//!
//! Two checks:
//! 1. `ingests_all_datatests` — every fixture parses (proves the harness reads
//!    Ghidra's corpus and command grammar). Green today.
//! 2. `decompile_parity_red_baseline` — a ratchet: how many reference assertions
//!    mosura currently reproduces. 0 today (the engine is unimplemented); when the
//!    port lands, bump `EXPECTED_DATATEST_PASS`. The reference oracle scores
//!    599/599 (`decomp_test_dbg`), which is the target.
//!
//! Both gracefully skip when the Ghidra checkout isn't present, so `cargo test`
//! works in a bare clone.

use mosura::{conformance, datatest, paths, sleigh};

fn datatests() -> Option<Vec<std::path::PathBuf>> {
    let dir = paths::datatests_dir();
    if !dir.is_dir() {
        eprintln!("skip: datatests dir not found at {} (set GHIDRA_SRC)", dir.display());
        return None;
    }
    Some(datatest::list(&dir).expect("listing datatests"))
}

#[test]
fn ingests_all_datatests() {
    let Some(files) = datatests() else { return };
    assert!(
        files.len() >= 70,
        "expected ~79 datatests, found {}",
        files.len()
    );

    let mut total_matches = 0usize;
    for f in &files {
        let dt = datatest::parse_file(f).unwrap_or_else(|e| panic!("parse {}: {e}", f.display()));
        assert!(!dt.arch.is_empty(), "{}: no arch", f.display());
        assert!(!dt.chunks.is_empty(), "{}: no byte chunks", f.display());
        assert!(!dt.matches.is_empty(), "{}: no stringmatch assertions", f.display());
        total_matches += dt.matches.len();
    }
    eprintln!(
        "ingested {} datatests, {} stringmatch assertions",
        files.len(),
        total_matches
    );
}

/// Bump this as the SLEIGH engine / decompiler land and reproduce assertions.
const EXPECTED_DATATEST_PASS: usize = 0;

#[test]
fn decompile_parity_red_baseline() {
    let Some(files) = datatests() else { return };

    let mut tally = conformance::Tally::default();
    for f in &files {
        let dt = datatest::parse_file(f).unwrap();
        // mosura has no decompiler yet → Unimplemented → nothing reproduced.
        let c = sleigh::decompile(&dt.arch, dt.primary_bytes(), dt.entry()).ok();
        for m in &dt.matches {
            let ok = c
                .as_deref()
                .map(|out| {
                    conformance::stringmatch(out, &m.pattern, m.min, m.max).unwrap_or(false)
                })
                .unwrap_or(false);
            tally.record(ok);
        }
    }
    eprintln!("datatest parity: {tally} reference assertions reproduced (reference oracle: 599/599)");
    assert_eq!(
        tally.passed, EXPECTED_DATATEST_PASS,
        "parity changed: {} reproduced vs expected {}. If this went up, bump \
         EXPECTED_DATATEST_PASS (progress!); if down, a regression.",
        tally.passed, EXPECTED_DATATEST_PASS
    );
}
