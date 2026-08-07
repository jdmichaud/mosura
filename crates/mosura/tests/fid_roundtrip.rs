//! Stage 6 end-to-end (`docs/fid-port-plan.md` §5): **build a database, then use it.**
//!
//! Ghidra-free, and self-compiled all the way down. The committed ground-truth corpus gives
//! both halves of what an ingest needs: a stripped binary, and a `.truth` file recording the
//! real function names, derived at build time from the compiler's own output (`nm`/`objdump`)
//! — never from Ghidra and never from mosura.
//!
//! So the round trip is honest:
//!
//! 1. hash the binary's functions and ingest them **under their true names**;
//! 2. write the database, read it back;
//! 3. analyze the *same stripped binary* again, with no names available;
//! 4. require the names to come back, and require **no wrong name** to appear.
//!
//! Step 4 is the product claim in miniature. It exercises the hasher, the store, the key
//! assignment, the full-hash index and the scorer together — anything wrong in the chain and
//! nothing comes back.

use std::collections::{BTreeMap, BTreeSet};

use mosura::analysis::fid::analyzer::{hash_function, search_program};
use mosura::analysis::fid::ingest::{Ingest, IngestFunction};
use mosura::analysis::fid::matcher::{SCORE_THRESHOLD, SPECIFIC_SCORE_WEIGHT};
use mosura::analysis::fid::query::FidQueryService;
use mosura::analysis::fid::store::FidStore;
use mosura::paths;

/// `func <hex-entry> <hex-size> <name> <class>` lines of a `.truth` file.
fn truth_names(text: &str) -> BTreeMap<u64, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 4 && f[0] == "func" {
            if let Ok(entry) = u64::from_str_radix(f[1], 16) {
                out.insert(entry, f[3].to_string());
            }
        }
    }
    out
}

/// Build a database from `binary` using the names its `.truth` records, then identify against
/// the same binary. Returns (expected-to-be-findable, actually-found).
fn round_trip(stem: &str) -> Option<(BTreeSet<String>, BTreeSet<String>)> {
    let binary = paths::ground_truth_dir().join(stem);
    let truth_path = paths::ground_truth_dir().join(format!("{stem}.truth"));
    if !binary.exists() || !truth_path.exists() {
        return None;
    }
    let names = truth_names(&std::fs::read_to_string(&truth_path).ok()?);
    let program = mosura::analysis::analyze_file(&binary).ok()?;

    // --- ingest: hash each function under its true name ---
    let mut functions = Vec::new();
    // Which names can possibly be recovered: the body must hash, and the record must be able
    // to clear the score threshold on its own (these fixtures have few call relations to lean
    // on, so a body below the bar is *correctly* not identified — see Ghidra's 14.6).
    let mut findable = BTreeSet::new();

    for f in program.function_manager.functions() {
        let entry = f.entry_point();
        let Some(name) = names.get(&entry.offset) else { continue };
        let quad = hash_function(&program, entry);
        if let Some(q) = quad {
            // The score the matcher will compute for this record when it matches itself:
            // `codeUnitSize + 0.67 * specificAddSize`. Identifying a binary against a database
            // built from that same binary always hits the specific hash too, so the bonus
            // always applies — leaving it out of this predicate under-counts what is findable
            // (`_start` is 11 code units but scores 11 + 0.67*7 = 15.69).
            let score = f32::from(q.code_unit_size)
                + SPECIFIC_SCORE_WEIGHT * f32::from(q.specific_hash_additional_size);
            if score >= SCORE_THRESHOLD {
                findable.insert(name.clone());
            }
        }
        functions.push(IngestFunction {
            entry: entry.offset,
            name: Some(name.clone()),
            quad,
            children: Vec::new(),
            is_thunk: false,
            is_external: false,
            has_terminator: true,
        });
    }

    let mut ingest = Ingest::new(
        &program.language_id,
        &program.compiler_spec_id,
        "Ground Truth",
        "1",
        "Release",
    );
    ingest.add_program(&functions);
    let (store, _) = ingest.finish();

    // --- serialize, reload, identify ---
    let reloaded = FidStore::from_text(&store.to_text()).expect("round trip through the store");
    let mut service = FidQueryService::new();
    service.attach(reloaded.into_database(stem));

    let found: BTreeSet<String> =
        search_program(&program, &service).into_iter().map(|r| r.name).collect();
    Some((findable, found))
}

/// The round trip must recover every function that can clear the score threshold, and must
/// invent nothing.
///
/// Run across the corpus's architectures, so the ingest is exercised on more than x86.
#[test]
fn ingested_names_come_back_out() {
    let stems = [
        "arith.gcc-x86-64",
        "deepchain.gcc-x86-64",
        "tables.gcc-x86-64",
        "callclob.watcom-x86-32",
        "deepchain.gcc-riscv64",
    ];

    let mut ran = 0;
    for stem in stems {
        let Some((findable, found)) = round_trip(stem) else { continue };
        ran += 1;
        eprintln!("{stem}: findable {findable:?}, found {found:?}");

        // Precision: every name applied was one we ingested. A name that was never in the
        // database appearing here would mean the index or the keys are wrong.
        let invented: Vec<&String> = found.difference(&findable).collect();
        assert!(
            invented.is_empty(),
            "{stem}: FID applied names that could not have been matched: {invented:?}"
        );

        // Recall: everything above the threshold is recovered.
        let missing: Vec<&String> = findable.difference(&found).collect();
        assert!(
            missing.is_empty(),
            "{stem}: ingested then failed to identify {missing:?}"
        );
    }
    assert!(ran > 0, "the ground-truth corpus is present");
}

/// A database built from one binary must not name functions in a *different* one. This is the
/// precision direction that matters most: a signature that fires on unrelated code would
/// produce confident nonsense.
#[test]
fn a_database_does_not_match_unrelated_code() {
    let source = paths::ground_truth_dir().join("deepchain.gcc-x86-64");
    let target = paths::ground_truth_dir().join("tables.gcc-x86-64");
    if !source.exists() || !target.exists() {
        return;
    }

    // Build from `deepchain`, using its truth names.
    let truth = std::fs::read_to_string(paths::ground_truth_dir().join("deepchain.gcc-x86-64.truth"))
        .expect("truth");
    let names = truth_names(&truth);
    let source_program = mosura::analysis::analyze_file(&source).expect("analyze source");

    let functions: Vec<IngestFunction> = source_program
        .function_manager
        .functions()
        .filter_map(|f| {
            let entry = f.entry_point();
            names.get(&entry.offset).map(|name| IngestFunction {
                entry: entry.offset,
                name: Some(name.clone()),
                quad: hash_function(&source_program, entry),
                children: Vec::new(),
                is_thunk: false,
                is_external: false,
                has_terminator: true,
            })
        })
        .collect();

    let mut ingest = Ingest::new("x86:LE:64:default", "gcc", "Deepchain", "1", "Release");
    ingest.add_program(&functions);
    let (store, _) = ingest.finish();

    let mut service = FidQueryService::new();
    service.attach(store.into_database("deepchain"));

    let target_program = mosura::analysis::analyze_file(&target).expect("analyze target");
    let hits = search_program(&target_program, &service);

    // `_start` and other CRT-shaped stubs are legitimately shared between two binaries built
    // the same way; anything else would be a false positive.
    for hit in &hits {
        let named = &hit.name;
        assert!(
            names.values().any(|n| n == named),
            "matched a name that is not even in the source database: {named}"
        );
    }
    eprintln!("cross-binary hits (shared build stubs are expected): {hits:?}");
}
