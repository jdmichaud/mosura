//! Stage 2b gate (`docs/fid-port-plan.md` §5): reading Ghidra's `db` B-tree out of a `.fidb`.
//!
//! The self-check that makes this gate strong is **structural, not hand-derived**: each table
//! record in the master table stores the number of records that table holds, written by
//! Ghidra when it built the database. Walking the B-tree and arriving at exactly that count,
//! for every table of every shipped database, is something a wrong node layout, a wrong
//! header size, or a mis-decoded schema cannot fake — it would come out short, long, or fail.
//!
//! On top of that the FID schemas are pinned field-for-field against
//! `FunctionsTable.java` / `LibrariesTable.java` / `StringsTable.java` / `RelationsTable.java`,
//! and the library metadata is checked against what the file name claims to be.

use mosura::analysis::fid::db::{self, Database, FieldType};
use mosura::paths;

/// The smallest database, used wherever one representative suffices.
const SAMPLE: &str = "vs2017_x64.fidb";

fn open(name: &str) -> Option<Database> {
    let data = std::fs::read(paths::fid_db_dir().join(name)).ok()?;
    Some(db::open_packed(&data).unwrap_or_else(|e| panic!("{name}: {e}")))
}

fn shipped_databases() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(paths::fid_db_dir())
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".fidb"))
        .collect();
    names.sort();
    names
}

/// **The load-bearing assertion.** Walk every B-tree in every shipped database and require the
/// record count to match what Ghidra recorded in the master table.
///
/// This covers interior nodes, both leaf kinds, records spilled into chained buffers, and the
/// schema decode that sizes fixed-length records — all at once, across ~1.4 M records.
#[test]
fn record_counts_match_the_master_table() {
    let names = shipped_databases();
    assert_eq!(names.len(), 10, "the ten shipped databases");

    for name in names {
        let Some(database) = open(&name) else { continue };
        for table in database.tables() {
            // Index tables are var-key structures we deliberately do not decode (the full-hash
            // index is rebuilt in memory instead); only primary tables are walked.
            if table.indexed_column >= 0 {
                continue;
            }
            let records = database
                .records(table)
                .unwrap_or_else(|e| panic!("{name}/{}: {e}", table.name));
            assert_eq!(
                records.len() as i32,
                table.record_count,
                "{name}/{}: walked {} records, master table says {}",
                table.name,
                records.len(),
                table.record_count
            );
        }
    }
}

/// Every shipped database holds exactly the five FID tables (plus their index tables), with
/// the schemas Ghidra's table classes declare.
#[test]
fn fid_schemas_are_as_declared() {
    for name in shipped_databases() {
        let Some(database) = open(&name) else { continue };

        // `FunctionsTable.java:47-51`
        let functions = database.table("Functions Table").expect("functions table");
        assert_eq!(
            functions.schema.field_types,
            vec![
                FieldType::Short,  // code unit size
                FieldType::Long,   // full hash
                FieldType::Byte,   // specific hash additional size
                FieldType::Long,   // specific hash
                FieldType::Long,   // library ID
                FieldType::Long,   // name ID
                FieldType::Long,   // entry point
                FieldType::Long,   // domain path ID
                FieldType::Byte,   // flags
            ],
            "{name}: functions schema"
        );
        assert_eq!(functions.schema.column("Full Hash"), Some(1));
        assert_eq!(functions.schema.column("Specific Hash"), Some(3));

        // `LibrariesTable.java` — one language + compiler spec per library.
        let libraries = database.table("Libraries Table").expect("libraries table");
        assert_eq!(
            libraries.schema.field_types,
            vec![
                FieldType::String, // family
                FieldType::String, // version
                FieldType::String, // variant
                FieldType::String, // ghidra version
                FieldType::String, // language ID
                FieldType::Int,    // language version
                FieldType::Int,    // language minor version
                FieldType::String, // compiler spec ID
            ],
            "{name}: libraries schema"
        );

        // `StringsTable.java` — interned names and paths.
        let strings = database.table("Strings Table").expect("strings table");
        assert_eq!(strings.schema.field_types, vec![FieldType::String], "{name}: strings schema");

        // `RelationsTable.java` — no columns at all; presence of the key IS the relation.
        for relation in ["Superior Table", "Inferior Table"] {
            let t = database.table(relation).expect(relation);
            assert!(
                t.schema.field_types.is_empty(),
                "{name}/{relation}: a relation table stores no columns"
            );
            assert!(t.record_count > 0, "{name}/{relation}: relations were ingested");
        }
    }
}

/// The library metadata must describe the architecture the file name claims. This is what
/// keeps a match from ever crossing architectures: the matcher reads the language and compiler
/// spec off the library record.
#[test]
fn library_records_describe_the_right_architecture() {
    for name in shipped_databases() {
        let Some(database) = open(&name) else { continue };
        let table = database.table("Libraries Table").expect("libraries table");
        let records = database.records(table).expect("records");

        assert!(!records.is_empty(), "{name}: at least one library");
        let expected_lang = if name.contains("_x64") {
            "x86:LE:64:default"
        } else {
            "x86:LE:32:default"
        };

        for r in &records {
            assert_eq!(r.str_at(0), Some("Visual Studio"), "{name}: family");
            assert_eq!(r.str_at(4), Some(expected_lang), "{name}: language id");
            assert_eq!(r.str_at(7), Some("windows"), "{name}: compiler spec");
            // Ghidra ships a debug and a release variant per database.
            let variant = r.str_at(2).unwrap_or_default();
            assert!(
                variant == "Debug" || variant == "Release",
                "{name}: unexpected variant {variant:?}"
            );
        }
    }
}

/// Function records must be internally consistent: their name and path IDs resolve into the
/// strings table, their library ID resolves into the libraries table, and their code-unit size
/// respects the short-hash floor the hasher enforces.
///
/// A plausible-looking but wrong record decode — fields shifted by one, say — fails here,
/// because the cross-table IDs would not resolve.
#[test]
fn function_records_cross_reference_correctly() {
    let Some(database) = open(SAMPLE) else { return };

    let strings: std::collections::HashMap<i64, &str> = {
        let t = database.table("Strings Table").expect("strings");
        let recs = Box::leak(Box::new(database.records(t).expect("string records")));
        recs.iter().map(|r| (r.key, r.str_at(0).unwrap_or_default())).collect()
    };
    let library_ids: std::collections::HashSet<i64> = {
        let t = database.table("Libraries Table").expect("libraries");
        database.records(t).expect("library records").iter().map(|r| r.key).collect()
    };

    let functions = database.table("Functions Table").expect("functions");
    let records = database.records(functions).expect("function records");
    assert!(records.len() > 10_000, "a real database, not a stub");

    let mut named = 0usize;
    for r in &records {
        let code_unit_size = r.i64_at(0).expect("code unit size");
        let library_id = r.i64_at(4).expect("library id");
        let name_id = r.i64_at(5).expect("name id");
        let flags = r.i64_at(8).expect("flags");

        // NOT `>= 4`: the short-hash floor of 4 applies to the instruction *count*, while
        // `codeUnitSize = codeUnitIndex - callCount` has calls subtracted from it
        // (`MessageDigestFidHasher.java:214`). A 4-instruction body containing a call
        // legitimately stores 3, and one that is all calls would store 0.
        assert!(
            (0..=i64::from(i16::MAX)).contains(&code_unit_size),
            "code unit size {code_unit_size} outside the representable range"
        );
        assert!(library_ids.contains(&library_id), "library id {library_id} does not resolve");
        assert!(
            flags & !0b1_1111 == 0,
            "flags {flags:#b} outside the five defined bits (terminator/autoPass/autoFail/forceSpecific/forceRelation)"
        );

        if let Some(name) = strings.get(&name_id) {
            assert!(!name.is_empty(), "name id {name_id} resolves to an empty string");
            named += 1;
        } else {
            panic!("name id {name_id} does not resolve into the strings table");
        }
    }
    assert_eq!(named, records.len(), "every function record names a string");
}

/// A known function, spot-checked end to end: look up `memset` by name and confirm its record
/// carries a plausible quad. This is the shape Stage 3 will assert byte-exactly against our
/// own hasher.
#[test]
fn a_known_crt_function_is_present() {
    let Some(database) = open(SAMPLE) else { return };

    let strings_table = database.table("Strings Table").expect("strings");
    let string_records = database.records(strings_table).expect("string records");
    let memset_ids: Vec<i64> = string_records
        .iter()
        .filter(|r| r.str_at(0) == Some("memset"))
        .map(|r| r.key)
        .collect();
    assert!(!memset_ids.is_empty(), "the CRT database interns the name `memset`");

    let functions = database.table("Functions Table").expect("functions");
    let records = database.records(functions).expect("function records");
    let matches: Vec<_> =
        records.iter().filter(|r| memset_ids.contains(&r.i64_at(5).unwrap_or(-1))).collect();

    assert!(!matches.is_empty(), "at least one function record is named `memset`");
    for r in matches {
        assert!(r.i64_at(0).unwrap() >= 4, "code unit size");
        assert_ne!(r.i64_at(1).unwrap(), 0, "full hash is set");
        assert_ne!(r.i64_at(3).unwrap(), 0, "specific hash is set");
    }
}

/// Corruption and nonsense are reported rather than mis-decoded.
#[test]
fn malformed_input_is_rejected() {
    assert!(db::open_packed(&[0u8; 64]).is_err(), "not a packed item");

    let Some(data) = std::fs::read(paths::fid_db_dir().join(SAMPLE)).ok() else { return };
    let mut truncated = data;
    truncated.truncate(4096);
    assert!(db::open_packed(&truncated).is_err(), "a truncated database must not open");
}
