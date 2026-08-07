//! Stage 6 gate (`docs/fid-port-plan.md` §5): building a signature database from a runtime.
//!
//! Ghidra-free. The strongest assertion here is a **round trip**: ingest a set of functions,
//! write the database, read it back, and identify those same functions through the real
//! matcher. If any step — dedup, key assignment, relation keying, serialization — is wrong,
//! the names do not come back.

use mosura::analysis::fid::hash::FidHashQuad;
use mosura::analysis::fid::ingest::{ChildRef, Disposition, Ingest, IngestFunction};
use mosura::analysis::fid::matcher::{apply_name, HashFamily, Seeker};
use mosura::analysis::fid::query::FidQueryService;
use mosura::analysis::fid::store::{self, FidStore};

fn quad(size: i16, full: u64, add: i8, spec: u64) -> FidHashQuad {
    FidHashQuad {
        code_unit_size: size,
        full_hash: full,
        specific_hash_additional_size: add,
        specific_hash: spec,
    }
}

fn func(entry: u64, name: &str, q: FidHashQuad, children: Vec<ChildRef>) -> IngestFunction {
    IngestFunction {
        entry,
        name: Some(name.to_string()),
        quad: Some(q),
        children,
        is_thunk: false,
        is_external: false,
        has_terminator: true,
    }
}

/// A small runtime: `strlen`, `malloc`, and a `puts` that calls both.
fn sample_library() -> Vec<IngestFunction> {
    vec![
        func(0x1000, "strlen", quad(20, 0x1111, 2, 0xaaaa), vec![]),
        func(0x2000, "malloc", quad(30, 0x2222, 3, 0xbbbb), vec![]),
        func(0x3000, "puts", quad(25, 0x3333, 1, 0xcccc), vec![
            ChildRef::Local(0x1000),
            ChildRef::Local(0x2000),
        ]),
    ]
}

/// **The round trip.** Ingest → serialize → parse → query → identify. Every stage has to be
/// right for a name to come back out.
#[test]
fn ingest_round_trips_through_the_store_and_identifies() {
    let mut ingest = Ingest::new("x86:LE:32:default", "watcom", "Test Runtime", "1.0", "Release");
    ingest.add_program(&sample_library());
    let (built, result) = ingest.finish();
    assert_eq!(result.ingested, 3);
    assert!(result.relations >= 2, "puts→strlen and puts→malloc");

    // Serialize and parse back — the text form must survive the trip unchanged.
    let text = built.to_text();
    let reparsed = FidStore::from_text(&text).expect("parse");
    assert_eq!(reparsed.to_text(), text, "serialization is a fixed point");
    assert_eq!(reparsed.functions.len(), 3);

    // Query it through the real matcher.
    let mut service = FidQueryService::new();
    service.attach(reparsed.into_database("test"));
    let seeker = Seeker::new(&service);

    for (name, q) in [
        ("strlen", quad(20, 0x1111, 2, 0xaaaa)),
        ("malloc", quad(30, 0x2222, 3, 0xbbbb)),
        ("puts", quad(25, 0x3333, 1, 0xcccc)),
    ] {
        let family = HashFamily { hash: Some(q), ..Default::default() };
        let found = seeker.process_matches(&family).expect("a match for {name}");
        assert_eq!(apply_name(&found).as_deref(), Some(name), "identifying {name}");
    }
}

/// Relations survive the round trip and still score: `puts` alone is 25 code units, but with
/// its two callees recognised it scores 25 + 20 + 30.
#[test]
fn relations_survive_the_round_trip() {
    let mut ingest = Ingest::new("x86:LE:32:default", "watcom", "Test", "1", "R");
    ingest.add_program(&sample_library());
    let (built, _) = ingest.finish();

    let mut service = FidQueryService::new();
    service.attach(FidStore::from_text(&built.to_text()).unwrap().into_database("test"));

    let family = HashFamily {
        hash: Some(quad(25, 0x3333, 1, 0xcccc)),
        children: vec![quad(20, 0x1111, 2, 0xaaaa), quad(30, 0x2222, 3, 0xbbbb)],
        parents: vec![],
    };
    let found = Seeker::new(&service).process_matches(&family).expect("match");
    let m = &found.matches()[0];
    assert_eq!(m.child_score, 50.0, "both callee relations were stored and found");
}

/// The same routine appearing in two object files contributes **one** record — otherwise every
/// database would carry duplicates of every widely-used helper.
#[test]
fn identical_functions_are_deduplicated() {
    let mut ingest = Ingest::new("x86:LE:32:default", "watcom", "Test", "1", "R");
    ingest.add_program(&[func(0x1000, "strlen", quad(20, 0x1111, 2, 0xaaaa), vec![])]);
    ingest.add_program(&[func(0x9000, "strlen", quad(20, 0x1111, 2, 0xaaaa), vec![])]);
    let (built, result) = ingest.finish();

    assert_eq!(built.functions.len(), 1, "one record for the same routine");
    assert_eq!(result.excluded.get(&Disposition::Duplicate), Some(&1));

    // ...but a routine of the same name with a different body is a distinct record.
    let mut ingest = Ingest::new("x86:LE:32:default", "watcom", "Test", "1", "R");
    ingest.add_program(&[func(0x1000, "strlen", quad(20, 0x1111, 2, 0xaaaa), vec![])]);
    ingest.add_program(&[func(0x9000, "strlen", quad(22, 0x4444, 2, 0xdddd), vec![])]);
    let (built, _) = ingest.finish();
    assert_eq!(built.functions.len(), 2, "a different body is a different signature");
}

/// Functions Ghidra refuses to ingest: external, thunk, unnamed, or unhashable.
#[test]
fn unusable_functions_are_excluded() {
    let mut ingest = Ingest::new("x86:LE:32:default", "watcom", "Test", "1", "R");
    ingest.add_program(&[
        IngestFunction { is_external: true, ..func(0x1000, "ext", quad(20, 1, 0, 1), vec![]) },
        IngestFunction { is_thunk: true, ..func(0x2000, "thunk", quad(20, 2, 0, 2), vec![]) },
        IngestFunction { name: None, ..func(0x3000, "", quad(20, 3, 0, 3), vec![]) },
        IngestFunction { quad: None, ..func(0x4000, "tiny", quad(20, 4, 0, 4), vec![]) },
        func(0x5000, "good", quad(20, 5, 0, 5), vec![]),
    ]);
    let (built, result) = ingest.finish();

    assert_eq!(built.functions.len(), 1, "only the usable function is stored");
    assert_eq!(built.functions[0].name, "good");
    assert_eq!(result.excluded.get(&Disposition::External), Some(&1));
    assert_eq!(result.excluded.get(&Disposition::IsThunk), Some(&1));
    assert_eq!(result.excluded.get(&Disposition::NoDefinedSymbol), Some(&1));
    assert_eq!(result.excluded.get(&Disposition::FailsMinimumShortHashLength), Some(&1));
}

/// A symbol on the common list contributes no relation — a call to `memcpy` says nothing about
/// which function you are looking at, and storing it would only add noise and size.
#[test]
fn common_symbols_contribute_no_relations() {
    let library = vec![
        func(0x1000, "memcpy", quad(20, 0x1111, 2, 0xaaaa), vec![]),
        func(0x3000, "caller", quad(25, 0x3333, 1, 0xcccc), vec![ChildRef::Local(0x1000)]),
    ];

    let mut plain = Ingest::new("x86:LE:32:default", "watcom", "T", "1", "R");
    plain.add_program(&library);
    let (_, plain_result) = plain.finish();
    assert!(plain_result.relations >= 1, "control: the relation is normally stored");

    let mut marked = Ingest::new("x86:LE:32:default", "watcom", "T", "1", "R");
    marked.mark_common_symbols(["memcpy".to_string()]);
    marked.add_program(&library);
    let (built, result) = marked.finish();
    assert_eq!(result.relations, 0, "a very-common child is not a distinguisher");
    assert!(built.superior.is_empty() && built.inferior.is_empty());
}

/// **Regeneration is deterministic.** The same inputs in a different order produce a
/// byte-identical database, so a rebuild diff shows real change rather than reordering noise —
/// which is what makes these generated artifacts reviewable.
#[test]
fn output_is_byte_identical_regardless_of_input_order() {
    let mut forward = Ingest::new("x86:LE:32:default", "watcom", "T", "1", "R");
    forward.add_program(&sample_library());
    let (a, _) = forward.finish();

    let mut reversed_input = sample_library();
    reversed_input.reverse();
    let mut backward = Ingest::new("x86:LE:32:default", "watcom", "T", "1", "R");
    backward.add_program(&reversed_input);
    let (b, _) = backward.finish();

    assert_eq!(a.to_text(), b.to_text(), "record order and keys are content-derived");
}

/// Databases ship **compressed**, so the compressed path must round-trip and must be the one
/// a `.gz` name selects. The reader detects gzip by magic, not by extension, so a
/// hand-written plain `.mfid` still loads.
#[test]
fn databases_round_trip_compressed() {
    let mut ingest = Ingest::new("x86:LE:32:default", "watcom", "T", "1", "R");
    ingest.add_program(&sample_library());
    let (built, _) = ingest.finish();

    let dir = std::env::temp_dir().join(format!("mfid-gz-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let gz = dir.join("t.mfid.gz");
    let plain = dir.join("t.mfid");
    store::write_file(&gz, &built).expect("write gz");
    store::write_file(&plain, &built).expect("write plain");

    // The `.gz` really is gzip-framed, and really is smaller.
    let gz_bytes = std::fs::read(&gz).expect("read gz");
    let plain_bytes = std::fs::read(&plain).expect("read plain");
    assert_eq!(&gz_bytes[..2], &[0x1f, 0x8b], "gzip magic");
    assert!(gz_bytes.len() < plain_bytes.len(), "compression actually shrinks it");

    // Both decode to the same database.
    let from_gz = store::read_file(&gz).expect("read gz");
    let from_plain = store::read_file(&plain).expect("read plain");
    assert_eq!(from_gz.to_text(), built.to_text(), "compressed round trip is lossless");
    assert_eq!(from_gz.to_text(), from_plain.to_text(), "both forms agree");

    // Deterministic: a generated artifact must regenerate byte-identically, compressed too.
    store::write_file(&gz, &built).expect("rewrite gz");
    assert_eq!(std::fs::read(&gz).expect("reread"), gz_bytes, "same input, same bytes");

    std::fs::remove_dir_all(&dir).ok();
}

/// The store rejects a file it cannot read rather than silently producing an empty database.
#[test]
fn malformed_store_is_rejected() {
    assert!(FidStore::from_text("").is_err(), "no header");
    assert!(FidStore::from_text("mosura-fid 999\n").is_err(), "unknown version");
    assert!(
        FidStore::from_text("mosura-fid 1\nf notanumber\n").is_err(),
        "malformed record"
    );
    assert!(store::read_file(std::path::Path::new("/nonexistent.mfid")).is_err());
}
