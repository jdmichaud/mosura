//! **The Watcom column's recall gate — the product claim, without Ghidra and without WAR2.**
//!
//! Every other Watcom check in this repo is self-referential. `fid_detect_versions` scores each
//! database against its OWN records, so a database that has drifted out of agreement with real
//! linked code still out-scores its neighbours exactly as before; `fid_database_drift` proves a
//! database reproduces from its libraries, which says nothing about whether it matches a program.
//! The only end-to-end evidence was WAR2.EXE, and by standing rule mosura's development must not
//! depend on that binary: it is a development guide and post-release validation, never a gate.
//!
//! So this compiles a program **we wrote** (`oracle/fid/src/watprobe.c`) with a real Watcom 10.0a
//! against its static `clib3r`, and asserts that the routines it calls come back — with the
//! expected names derived from the source, not from any tool.
//!
//! # This gate has teeth, and that was checked rather than assumed
//!
//! A recall gate can easily measure nothing. The first attempt used `crtprobe.c` (the MSVC probe's
//! source) and named the same 17 functions against the databases from *before* and *after* the OMF
//! relocation fix — a predicate whose answer was fixed in advance. `watprobe.c` exists because of
//! that: its calls are chosen to land routines that read STATIC TABLES, the exact shape that used
//! to be unidentifiable. Measured across that fix, the same binary scores **30 names before, 38
//! after** (`strcspn_`, `_asctime_`, `gmtime_`, `raise_`, `utoa_`, `ultoa_`, `__setbits_`,
//! `__terminate_`).
//!
//! # Why `analyze_le_file`
//!
//! A 32-bit Watcom DOS program is a DOS/4GW **Linear Executable**. The default container dispatch
//! deliberately keeps a bound exe on the Ghidra-parity MZ-stub path, which sees only the 16-bit
//! stub — no 32-bit code at all, so FID would correctly identify nothing. The native LE loader is
//! the entry point that reads the real program.

use std::collections::BTreeSet;

use mosura::analysis::fid::analyzer;
use mosura::analysis::fid::query::FidQueryService;
use mosura::paths;

const PROBE: &str = "watprobe.watcom10.0a-x86-32.exe";

/// Routines the probe calls by name that MUST be recovered.
///
/// Deliberately smaller than the full identified set: these are the ones whose presence follows
/// directly from `watprobe.c`, so a database refresh that shifts a marginal CRT internal does not
/// fail the build, while the calls the source actually makes stay mandatory.
///
/// The trailing underscore is Watcom's symbol decoration, and the names are the *implementation's*
/// — `malloc` is `_nmalloc_` in the flat model, because Watcom implements the ANSI names on top of
/// the near/far/based allocators. `strcpy`/`strlen`/`memcpy`/`memcmp`/`strchr` are absent on
/// purpose: at `-otexan` Watcom expands them inline, so there is no call and no body to identify.
const REQUIRED: &[&str] = &[
    // the plain string/heap half
    "memset_",
    "strncpy_",
    "strcmp_",
    "_nmalloc_",
    "_nfree_",
    // the static-table half — the reason this probe exists
    "strcspn_",
    "_asctime_",
    "gmtime_",
    "raise_",
    "utoa_",
    "ultoa_",
];

/// Every name the probe is expected to yield: [`REQUIRED`] plus the CRT internals its startup,
/// heap and exit paths pull in. A name outside this set is not automatically wrong, but it must be
/// looked at and added deliberately — that is the point of pinning the whole set.
const EXPECTED: &[&str] = &[
    "memset_",
    "strncpy_",
    "strcmp_",
    "_nmalloc_",
    "_nfree_",
    "strcspn_",
    "_asctime_",
    "gmtime_",
    "raise_",
    "utoa_",
    "ultoa_",
    // time internals reached through gmtime/asctime
    "__brktime_",
    "_gmtime_",
    "__leapyear_",
    "__setbits_",
    // startup, heap and exit
    "__STOSB",
    "__STOSD",
    "__MemAllocator",
    "__MemFree",
    "__FreeDPMIBlocks_",
    "__LastFree_",
    "__ExpandDGROUP_",
    "__brk_",
    "__CMain",
    "__InitRtns",
    "__FiniRtns",
    "exit_",
    "__terminate_",
    "__do_exit_with_msg__",
    "__fatal_runtime_error_",
    // DOS interrupt and 80x87 plumbing the runtime installs
    "_chain_intr_",
    "_dos_setvect_",
    "__restore_int23_",
    "__restore_int_ctrl_break_",
    "__sigfpe_handler_",
    "FPEHandlerEnd_",
    "__EnterWVIDEO_",
    "__init_80x87",
];

#[test]
fn watcom_crt_functions_are_identified() {
    let binary = paths::workspace_root().join("oracle/fid/binaries").join(PROBE);
    if !binary.exists() {
        eprintln!("skip: {} absent (rebuild: scripts/build-fid-probes.sh watcom)", binary.display());
        return;
    }

    // The native LE loader — see the module docs. The default dispatch would analyze the MZ stub.
    let program = mosura::analysis::analyze_le_file(&binary).expect("analyze the Watcom probe");
    let service = FidQueryService::load_matching_all(
        &paths::fid_db_dirs(),
        &program.language_id,
        &program.compiler_spec_id,
    );
    if service.is_empty() {
        // Not a silent pass: the Watcom databases are committed, so this means the search path or
        // the language/cspec pairing is broken, which is worth failing on.
        panic!(
            "no signature database attaches for {}/{} — the Watcom column is committed under \
             oracle/fid/db but unreachable from the analyzer",
            program.language_id, program.compiler_spec_id
        );
    }

    let found: BTreeSet<String> =
        analyzer::search_program(&program, &service).into_iter().filter_map(|r| r.name).collect();

    eprintln!(
        "FID identify (watcom10.0a-x86-32): named {}/{} functions against {} signature records",
        found.len(),
        program.function_manager.function_count(),
        service.function_count()
    );
    for name in &found {
        eprintln!("    {name}");
    }

    let missing: Vec<&str> = REQUIRED.iter().copied().filter(|n| !found.contains(*n)).collect();
    assert!(
        missing.is_empty(),
        "FID failed to identify {missing:?} in a program we compiled ourselves\nfound: {found:?}"
    );

    let expected: BTreeSet<String> = EXPECTED.iter().map(|s| s.to_string()).collect();
    let unexpected: Vec<&String> = found.difference(&expected).collect();
    assert!(
        unexpected.is_empty(),
        "FID applied names that are not in the expected set: {unexpected:?}\n\
         If these are correct, add them to EXPECTED after checking each one."
    );
}
