//! **Stage 5 gate — the product claim, tested without Ghidra.**
//!
//! Everything in Stages 1–3 measures *port fidelity*: does mosura compute what Ghidra
//! computes. This measures the thing a user actually wants: **given a stripped binary, are the
//! standard-library functions named, and are they named correctly?**
//!
//! Nothing here involves Ghidra at run time. The inputs are a program **we wrote**
//! (`oracle/fid/src/crtprobe.c`), compiled by a real MSVC 6 against its static CRT
//! (`scripts/build-fid-probes.sh`) and committed, plus the signature databases committed under
//! `third_party/ghidra-data/`. The expected names come from the source we wrote.
//!
//! Both directions are asserted:
//! - **recall** — a required set of CRT routines must be recovered;
//! - **precision** — the identified set must be *exactly* an expected list. A name we did not
//!   anticipate fails the test rather than passing silently, because a wrong name on a runtime
//!   function is worse than no name.

use std::collections::BTreeSet;

use mosura::analysis::fid::analyzer::{self, FidAnalyzer};
use mosura::analysis::fid::query::FidQueryService;
use mosura::analysis::analyzer::Analyzer;
use mosura::paths;

fn probe_path(name: &str) -> std::path::PathBuf {
    paths::workspace_root().join("oracle/fid/binaries").join(name)
}

const MSVC6_PROBE: &str = "crtprobe.msvc6-x86-32.exe";

/// Every name FID is expected to recover from the MSVC 6 probe.
///
/// Derived from `oracle/fid/src/crtprobe.c` plus the CRT internals its startup and heap paths
/// pull in. `strcpy`/`memcpy`/`memcmp`/`strcmp` are deliberately **absent**: at `/O2` MSVC
/// expands them inline as intrinsics, so there is no call and no function body to identify.
const MSVC6_EXPECTED: &[&str] = &[
    // Called directly by the probe.
    "_strncpy",
    "_strchr",
    "_strlen",
    "_memset",
    "_malloc",
    // CRT internals reached through those calls and through startup.
    "__nh_malloc",
    "__local_unwind2",
    "__global_unwind2",
    "__exit",
];

/// The subset that must always be found. Kept smaller than the full expected set so a
/// database refresh that shifts a marginal internal does not fail the build, while the
/// routines the probe calls by name stay mandatory.
const MSVC6_REQUIRED: &[&str] = &["_strncpy", "_strchr", "_strlen", "_memset", "_malloc"];

fn identify(binary: &std::path::Path) -> Option<(BTreeSet<String>, usize, usize)> {
    if !binary.exists() {
        eprintln!("skip: {} absent (regenerate: scripts/build-fid-probes.sh)", binary.display());
        return None;
    }
    let program = mosura::analysis::analyze_file(binary).expect("analyze the probe");
    let service = FidQueryService::load_matching(
        &paths::fid_db_dir(),
        &program.language_id,
        &program.compiler_spec_id,
    );
    if service.is_empty() {
        eprintln!("skip: no signature database matches {}", program.language_id);
        return None;
    }
    let results = analyzer::search_program(&program, &service);
    let names: BTreeSet<String> = results.into_iter().map(|r| r.name).collect();
    Some((names, program.function_manager.function_count(), service.function_count()))
}

/// The headline test: a stripped MSVC binary gets its CRT functions named, and **only** those.
#[test]
fn msvc6_crt_functions_are_identified() {
    let Some((found, total_functions, records)) = identify(&probe_path(MSVC6_PROBE)) else {
        return;
    };
    eprintln!(
        "FID identify (msvc6-x86-32): named {}/{} functions against {} signature records",
        found.len(),
        total_functions,
        records
    );
    for name in &found {
        eprintln!("    {name}");
    }

    // Recall: every routine the probe calls by name must come back.
    let missing: Vec<&str> =
        MSVC6_REQUIRED.iter().copied().filter(|n| !found.contains(*n)).collect();
    assert!(
        missing.is_empty(),
        "FID failed to identify {missing:?}\nfound: {found:?}"
    );

    // Precision: nothing unexpected. A new name is not automatically wrong, but it must be
    // examined and added deliberately — that is the point of pinning the exact set.
    let expected: BTreeSet<String> = MSVC6_EXPECTED.iter().map(|s| s.to_string()).collect();
    let unexpected: Vec<&String> = found.difference(&expected).collect();
    assert!(
        unexpected.is_empty(),
        "FID applied names that are not in the expected set: {unexpected:?}\n\
         If these are correct, add them to MSVC6_EXPECTED after checking each one."
    );
}

/// The analyzer must be **inert** with no database attached — no attachment, no renames, no
/// difference to the program at all. This is what makes shipping FID safe for a user who
/// removes the signature data.
#[test]
fn analyzer_is_inert_without_a_database() {
    let path = probe_path(MSVC6_PROBE);
    if !path.exists() {
        return;
    }
    let mut program = mosura::analysis::analyze_file(&path).expect("analyze");
    let before: Vec<String> =
        program.function_manager.functions().map(|f| f.name().to_string()).collect();

    let analyzer = FidAnalyzer::with_service(FidQueryService::new());
    assert!(!analyzer.can_analyze(&program), "an empty service cannot analyze");

    let set = mosura::analysis::program::AddressSet::new();
    let mut sched = mosura::analysis::manager::Scheduling::default();
    let did_work = analyzer.added(&mut program, &set, &mut sched);

    assert!(!did_work, "no database attached ⇒ no work reported");
    let after: Vec<String> =
        program.function_manager.functions().map(|f| f.name().to_string()).collect();
    assert_eq!(before, after, "no database attached ⇒ no function was renamed");
}

/// A database is attached only when its libraries declare the program's language **and**
/// compiler spec, so a match can never cross architectures. The x86-32 probe must not pull in
/// the x64 databases.
#[test]
fn databases_are_selected_by_language_and_compiler_spec() {
    let dir = paths::fid_db_dir();
    if !dir.exists() {
        return;
    }

    let x86 = FidQueryService::load_matching(&dir, "x86:LE:32:default", "windows");
    let x64 = FidQueryService::load_matching(&dir, "x86:LE:64:default", "windows");
    assert!(!x86.is_empty() && !x64.is_empty(), "both architectures have databases");
    for db in x86.databases() {
        assert!(db.name().ends_with("_x86"), "x86-32 attached {}", db.name());
    }
    for db in x64.databases() {
        assert!(db.name().ends_with("_x64"), "x86-64 attached {}", db.name());
    }

    // A language nothing was built for attaches nothing at all.
    let none = FidQueryService::load_matching(&dir, "AARCH64:LE:64:v8A", "default");
    assert!(none.is_empty(), "no Visual Studio database claims AArch64");

    // ...and the same language under a different compiler spec does not match either.
    let wrong_cspec = FidQueryService::load_matching(&dir, "x86:LE:32:default", "gcc");
    assert!(wrong_cspec.is_empty(), "the VS databases declare cspec `windows`, not `gcc`");
}
