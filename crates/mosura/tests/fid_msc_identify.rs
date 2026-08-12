//! The 16-bit Microsoft C column, end to end on a real program: does mosura load it, name the
//! compiler, and identify its run-time functions?
//!
//! Sibling of `fid_watcom_identify` / `fid_borland_identify`. Skip-if-absent on
//! `MOSURA_MSC16_EXE` (`docs/dependencies.md`), because the binary is user-provided.
//!
//! Why this gate exists at all: before the `msc-7.0-*` columns there was **no Microsoft 16-bit
//! database** — the committed 16-bit columns were Borland and Watcom, and Ghidra's shipped
//! `.fidb` are 32-bit Visual Studio — so a 16-bit MS C program identified nothing, and mosura's
//! version detector reported nothing either because it only knew the 32-bit-era runtime string.
//! Both are fixed; this keeps them fixed. See `docs/flashback-corpus-notes.md`.

use std::collections::HashSet;

/// Run-time functions the MS C 7.0 medium-model column identifies in the reference program.
/// A subset deliberately: the point is that identification works and stays working, not to
/// freeze a count that a loader or analyzer improvement may legitimately raise.
const EXPECTED: &[&str] = &["_printf", "_sprintf", "_strlen", "_exit"];

#[test]
fn microsoft_c_16bit_runtime_is_identified() {
    let path = mosura::paths::msc16_exe();
    let Ok(data) = std::fs::read(&path) else {
        eprintln!("skip fid_msc_identify: {} absent", path.display());
        return;
    };

    // 1. it loads through the ordinary MZ path — no opt-in view needed for a 16-bit program
    let program = mosura::analysis::analyze_file(&path).expect("analyze");
    assert_eq!(program.language_id, "x86:LE:16:Real Mode");
    assert!(
        program.function_manager.functions().count() > 200,
        "expected a substantial program, got {} functions",
        program.function_manager.functions().count()
    );

    // 2. the compiler names itself, and mosura records it
    let id = mosura::analysis::loader::compiler_version::detect(&data)
        .expect("the 16-bit Microsoft run-time banner");
    assert_eq!(id.label(), "msvc:16bit:1992", "evidence: {}", id.evidence);
    assert_eq!(program.compiler, "msvc:16bit:1992", "recorded as the Compiler opinion");

    // 3. FID identifies its run-time functions
    let service = mosura::analysis::fid::query::FidQueryService::load_matching_all(
        &mosura::paths::fid_db_dirs(),
        &program.language_id,
        &program.compiler_spec_id,
    );
    if service.function_count() == 0 {
        eprintln!("skip: no 16-bit signature database attached");
        return;
    }
    let results = mosura::analysis::fid::analyzer::search_program(&program, &service);
    let names: HashSet<String> = results.into_iter().filter_map(|r| r.name).collect();

    let missing: Vec<&str> = EXPECTED.iter().copied().filter(|n| !names.contains(*n)).collect();
    assert!(
        missing.is_empty(),
        "not identified: {missing:?} (named {} functions: {:?})",
        names.len(),
        {
            let mut v: Vec<&String> = names.iter().collect();
            v.sort();
            v.into_iter().take(40).collect::<Vec<_>>()
        }
    );
    assert!(names.len() >= 20, "expected the run-time to be broadly identified, got {}", names.len());
}
