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

/// A raw z80 `.com` carries no header, no sections and no symbol table, and sdcc embeds no
/// version string in compiled output — so signatures are the only evidence there is. The vote
/// must therefore be able to answer the *family* question, not just the version.
#[test]
fn the_vote_answers_the_family_question() {
    let dir = paths::workspace_root().join("oracle/fid/db");
    if !dir.exists() {
        return;
    }

    // A Turbo C binary we compiled: the family must come back, and be Borland.
    let binary = std::path::PathBuf::from("/tmp/uber_tc20_cl.exe");
    if binary.exists() {
        let program = mosura::analysis::analyze_file(&binary).expect("analyze");
        let report = detect_version(&program, &dir);
        assert_eq!(report.family(), Some("Borland"), "votes: {:?}", report.votes.len());
    }

    // And it must stay silent rather than guess when nothing matches: a binary of a language
    // no database covers produces no vote at all.
    let unrelated = paths::ground_truth_dir().join("arith.gcc-aarch64");
    if unrelated.exists() {
        let program = mosura::analysis::analyze_file(&unrelated).expect("analyze");
        let report = detect_version(&program, &dir);
        assert_eq!(report.family(), None, "no database claims AArch64");
    }
}

/// The refinement is **additive**: it records what signatures say without disturbing Ghidra's
/// faithful compiler opinion or the embedded-marker version. Where the two disagree, that
/// disagreement should be visible, not resolved silently.
#[test]
fn signature_detection_refines_without_overriding() {
    let binary = paths::workspace_root().join("oracle/fid/binaries/crtprobe.msvc6-x86-32.exe");
    let dir = paths::fid_db_dir();
    if !binary.exists() || !dir.exists() {
        return;
    }
    let mut program = mosura::analysis::analyze_file(&binary).expect("analyze");
    let before_compiler = program.compiler.clone();
    let before_version = program.compiler_version.clone();

    let label = mosura::analysis::fid::detect::apply_signature_detection(&mut program, &dir);

    assert_eq!(label.as_deref(), program.compiler_signature.as_deref());
    assert!(
        program.compiler_signature.as_deref().is_some_and(|l| l.starts_with("Visual Studio 1998")),
        "expected the VC6 probe to be dated to VS 1998, got {:?}",
        program.compiler_signature
    );
    assert_eq!(program.compiler, before_compiler, "Ghidra's CompilerOpinion is untouched");
    assert_eq!(program.compiler_version, before_version, "the embedded marker is untouched");
}

/// A program no database covers records nothing rather than a guess.
#[test]
fn signature_detection_is_silent_when_unsure() {
    let binary = paths::ground_truth_dir().join("arith.gcc-aarch64");
    let dir = paths::workspace_root().join("oracle/fid/db");
    if !binary.exists() || !dir.exists() {
        return;
    }
    let mut program = mosura::analysis::analyze_file(&binary).expect("analyze");
    assert_eq!(mosura::analysis::fid::detect::apply_signature_detection(&mut program, &dir), None);
    assert_eq!(program.compiler_signature, None);
}
