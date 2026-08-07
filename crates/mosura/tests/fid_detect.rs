//! Compiler-**version** detection by signature vote (`analysis/fid/detect.rs`).
//!
//! Ghidra-free, and the ground truth is that **we compiled the inputs**: the MSVC probe was
//! built by VC6 (`scripts/build-fid-probes.sh`), so the answer is known independently of
//! anything mosura or Ghidra computes.
//!
//! This tests the claim that matters: not "some database matched" but "the RIGHT one won, and
//! by a margin". A vote that ranked the correct release second would be useless.

use mosura::analysis::fid::detect::detect_version;
use mosura::paths;

/// Our VC6-built probe must be dated to Visual Studio 1998 — the release VC6 *is* — against
/// Ghidra's shipped databases, which span 1998 to 2019.
#[test]
fn a_vc6_binary_is_dated_to_visual_studio_1998() {
    let binary = paths::workspace_root().join("oracle/fid/binaries/crtprobe.msvc6-x86-32.exe");
    let dir = paths::fid_db_dir();
    if !binary.exists() || !dir.exists() {
        return;
    }
    let program = mosura::analysis::analyze_file(&binary).expect("analyze");
    let report = detect_version(&program, &dir);

    let best = report.best().expect("something matched");
    eprintln!(
        "vc6 probe: {} {} {} ({} of {} functions, score {:.0})",
        best.library_family, best.library_version, best.library_variant,
        best.matched, report.hashable_functions, best.score
    );

    assert_eq!(best.library_family, "Visual Studio");
    assert_eq!(best.library_version, "1998", "VC6 is Visual Studio 1998");

    // ...and it must WIN, not merely appear. A margin is what makes the answer usable.
    if let Some(second) = report.votes.get(1) {
        assert!(
            best.score > second.score * 2.0,
            "1998 must win clearly: {:.0} against {} at {:.0}",
            best.score,
            second.database,
            second.score
        );
    }
}

/// Only databases for the program's own language and compiler spec are scored, so a 16-bit
/// Borland runtime is never a candidate for a 32-bit PE.
#[test]
fn detection_does_not_cross_architectures() {
    let binary = paths::workspace_root().join("oracle/fid/binaries/crtprobe.msvc6-x86-32.exe");
    let dir = paths::workspace_root().join("oracle/fid/db");
    if !binary.exists() || !dir.exists() {
        return;
    }
    let program = mosura::analysis::analyze_file(&binary).expect("analyze");
    // Our own databases are Watcom/Borland/sdcc — none declares cspec `windows`, so a
    // Visual Studio PE must match nothing at all here.
    let report = detect_version(&program, &dir);
    assert!(
        report.votes.is_empty(),
        "a windows-cspec PE matched a non-windows database: {:?}",
        report.votes.iter().map(|v| &v.database).collect::<Vec<_>>()
    );
}
