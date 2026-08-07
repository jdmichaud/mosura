//! Stage 7, the Watcom column (`docs/fid-port-plan.md` §5): the shipped Watcom databases are
//! well-formed, describe the right target, and identify a function through the real matcher.
//!
//! Ghidra-free: the inputs are the committed `.mfid.gz` databases mosura built itself.
//! Rebuilding them needs the Watcom installs (`scripts`/`docs/fid-building-databases.md`);
//! *reading* them needs nothing.

use mosura::analysis::fid::matcher::{apply_name, HashFamily, Seeker};
use mosura::analysis::fid::query::FidQueryService;
use mosura::analysis::fid::store;
use mosura::paths;

fn db_dir() -> std::path::PathBuf {
    paths::workspace_root().join("oracle/fid/db")
}

/// Every Watcom version we hold is shipped, and each database is internally coherent.
#[test]
fn watcom_databases_are_complete_and_coherent() {
    let dir = db_dir();
    if !dir.exists() {
        return;
    }
    let mut versions: Vec<String> = std::fs::read_dir(&dir)
        .expect("db dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("watcom-"))
        .collect();
    versions.sort();

    // Every Watcom we hold — a closed set, which is what makes this column finishable at all
    // (unlike glibc). `ow2` is built from the Open Watcom source tree rather than a shipped
    // release; see its provenance note.
    assert_eq!(versions.len(), 6, "one database per installed Watcom: {versions:?}");
    for expected in ["9.01", "10.0a", "10.5", "10.6", "11.0", "ow2"] {
        assert!(
            versions.iter().any(|v| v.contains(expected)),
            "Watcom {expected} is missing from {versions:?}"
        );
    }

    for name in &versions {
        let store = store::read_file(&dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(store.language_id, "x86:LE:32:default", "{name}: language");
        assert_eq!(store.compiler_spec_id, "watcom", "{name}: compiler spec");
        assert_eq!(store.library_family, "Watcom", "{name}: family");
        assert!(store.functions.len() > 300, "{name}: only {} functions", store.functions.len());

        // Relations are what carry a small function over the score threshold. A column with
        // almost none means cross-module calls were not resolved — the state Watcom 9.01 was
        // in before Easy OMF-386 was handled (6 relations for 391 functions).
        assert!(
            store.superior.len() > store.functions.len() / 4,
            "{name}: {} relations for {} functions is too few — are fixups being applied?",
            store.superior.len(),
            store.functions.len()
        );

        for f in &store.functions {
            assert!(!f.name.is_empty(), "{name}: a record with no name identifies nothing");
            assert!(f.code_unit_size >= 0, "{name}: negative code unit size");
        }
    }
}

/// A database identifies its own functions through the real matcher — the same end-to-end path
/// the analyzer takes, over signatures we built rather than Ghidra's.
#[test]
fn a_watcom_database_identifies_its_own_functions() {
    let path = db_dir().join("watcom-11.0-x86-32.mfid.gz");
    if !path.exists() {
        return;
    }
    let store = store::read_file(&path).expect("read");
    // Pick records big enough to clear the score threshold on their own.
    let sample: Vec<_> = store
        .functions
        .iter()
        .filter(|f| f.code_unit_size >= 20)
        .take(25)
        .cloned()
        .collect();
    assert!(!sample.is_empty(), "the database has substantial functions");

    let mut service = FidQueryService::new();
    service.attach(store.into_database("watcom-11.0"));
    let seeker = Seeker::new(&service);

    let mut named = 0usize;
    let mut ambiguous = 0usize;
    for record in &sample {
        let family = HashFamily {
            hash: Some(mosura::analysis::fid::hash::FidHashQuad {
                code_unit_size: record.code_unit_size,
                full_hash: record.full_hash,
                specific_hash_additional_size: record.specific_hash_additional_size,
                specific_hash: record.specific_hash,
            }),
            ..Default::default()
        };

        // Recall: a record must always find itself.
        let found = seeker.process_matches(&family).expect("its own record matches");
        assert!(
            found.matches().iter().any(|m| m.record.name == record.name),
            "{} did not match its own signature",
            record.name
        );

        // Precision: when a single name IS applied it must be one of the tied candidates.
        //
        // Not every record yields one, and that is correct rather than a shortfall. Watcom
        // compiles `_mbscmp_` and `_mbsicmp_` to byte-identical bodies differing only in a
        // helper they call, so both share a full hash, tie at the top score, and cannot be
        // collapsed to one name — the apply gate then deliberately applies nothing. Telling
        // those apart is exactly what the caller/callee relations are for, and this family
        // deliberately supplies none.
        match apply_name(&found) {
            Some(name) => {
                assert!(
                    found.matches().iter().any(|m| m.record.name.trim_start_matches('_') == name
                        || m.record.name == name),
                    "{} produced the unrelated name {name}",
                    record.name
                );
                named += 1;
            }
            None => ambiguous += 1,
        }
    }
    eprintln!("watcom-11.0: {named} named, {ambiguous} ambiguous without relations");
    assert!(named > 0, "at least some records name unambiguously");
}

/// The recognisable C library is in there. These are the names a Watcom-built binary's
/// signatures should carry — with Watcom's trailing-underscore decoration.
#[test]
fn the_c_library_is_present() {
    let path = db_dir().join("watcom-11.0-x86-32.mfid.gz");
    if !path.exists() {
        return;
    }
    let store = store::read_file(&path).expect("read");
    let names: std::collections::HashSet<&str> =
        store.functions.iter().map(|f| f.name.as_str()).collect();

    // Names verified to be in CLIB3R.LIB. Watcom decorates with a trailing underscore, and
    // splits its runtime across several libraries — `malloc`/`memcpy` live elsewhere, so
    // expecting them here would be testing the wrong library rather than the code.
    for expected in ["strlen_", "printf_", "vsprintf_", "vcprintf_", "_freect_"] {
        assert!(
            names.contains(expected),
            "{expected} missing from the Watcom 11.0 database ({} names)",
            names.len()
        );
    }
}
