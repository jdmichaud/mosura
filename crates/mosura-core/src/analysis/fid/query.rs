//! `FidQueryService` — an in-memory index over one or more signature databases, answering the
//! three questions the matcher asks (`db/FidQueryService.java`, `db/FidDB.java`).
//!
//! Ghidra queries the B-tree's secondary index on every lookup. We build the equivalent index
//! once at load and keep it resident: a full-hash multimap plus the two relation key sets.
//! The records are identical either way — this is a storage decision, not a fidelity one, and
//! it is why the var-key index tables in the `.fidb` are deliberately not decoded
//! (`docs/fid-port-plan.md` §5 Stage 2).
//!
//! **Architecture safety is structural.** A library record pins one `languageID` +
//! `compilerSpecID`, and a database is only attached to a program whose language matches, so a
//! match can never cross architectures.

use std::collections::{HashMap, HashSet};

use super::db::{self, Database};
use super::matcher::{
    inferior_full_hash_smash, superior_full_hash_smash, FidQuery, FunctionRecord,
};

/// One library in a signature database (`db/LibraryRecord.java`).
#[derive(Debug, Clone)]
pub struct LibraryRecord {
    pub id: i64,
    pub family: String,
    pub version: String,
    pub variant: String,
    pub language_id: String,
    pub compiler_spec_id: String,
}

/// A loaded signature database, indexed for lookup.
#[derive(Clone)]
pub struct FidDatabase {
    name: String,
    libraries: Vec<LibraryRecord>,
    by_full_hash: HashMap<u64, Vec<FunctionRecord>>,
    superior: HashSet<i64>,
    inferior: HashSet<i64>,
}

impl FidDatabase {
    /// Build a database directly from records — the path the mosura-native store
    /// ([`super::store`]) takes. Same in-memory shape as a `.fidb` load; only the container
    /// the records came out of differs.
    pub fn new(
        name: &str,
        libraries: Vec<LibraryRecord>,
        functions: Vec<FunctionRecord>,
        superior: HashSet<i64>,
        inferior: HashSet<i64>,
    ) -> FidDatabase {
        let mut by_full_hash: HashMap<u64, Vec<FunctionRecord>> = HashMap::new();
        for record in functions {
            by_full_hash.entry(record.full_hash).or_default().push(record);
        }
        FidDatabase { name: name.to_string(), libraries, by_full_hash, superior, inferior }
    }

    /// Load a packed `.fidb` and build the lookup index.
    pub fn open_packed(name: &str, data: &[u8]) -> Result<FidDatabase, db::DbError> {
        Self::from_database(name, db::open_packed(data)?)
    }

    pub fn from_database(name: &str, database: Database) -> Result<FidDatabase, db::DbError> {
        // Interned names/paths, so a function record's name id can be resolved.
        let mut strings: HashMap<i64, String> = HashMap::new();
        if let Some(t) = database.table("Strings Table") {
            for r in database.records(t)? {
                if let Some(s) = r.str_at(0) {
                    strings.insert(r.key, s.to_string());
                }
            }
        }

        let mut libraries = Vec::new();
        if let Some(t) = database.table("Libraries Table") {
            for r in database.records(t)? {
                libraries.push(LibraryRecord {
                    id: r.key,
                    family: r.str_at(0).unwrap_or_default().to_string(),
                    version: r.str_at(1).unwrap_or_default().to_string(),
                    variant: r.str_at(2).unwrap_or_default().to_string(),
                    language_id: r.str_at(4).unwrap_or_default().to_string(),
                    compiler_spec_id: r.str_at(7).unwrap_or_default().to_string(),
                });
            }
        }

        // `FunctionsTable.java:47-60` — column order is the schema's.
        let mut by_full_hash: HashMap<u64, Vec<FunctionRecord>> = HashMap::new();
        if let Some(t) = database.table("Functions Table") {
            for r in database.records(t)? {
                let name_id = r.i64_at(5).unwrap_or(0);
                let record = FunctionRecord {
                    key: r.key,
                    code_unit_size: r.i64_at(0).unwrap_or(0) as i16,
                    full_hash: r.i64_at(1).unwrap_or(0) as u64,
                    specific_hash_additional_size: r.i64_at(2).unwrap_or(0) as i8,
                    specific_hash: r.i64_at(3).unwrap_or(0) as u64,
                    library_id: r.i64_at(4).unwrap_or(0),
                    name_id,
                    name: strings.get(&name_id).cloned().unwrap_or_default(),
                    flags: r.i64_at(8).unwrap_or(0) as u8,
                };
                by_full_hash.entry(record.full_hash).or_default().push(record);
            }
        }

        // The relation tables have no columns — the key's presence IS the relation.
        let relation_keys = |table: &str| -> Result<HashSet<i64>, db::DbError> {
            let Some(t) = database.table(table) else { return Ok(HashSet::new()) };
            Ok(database.records(t)?.into_iter().map(|r| r.key).collect())
        };

        Ok(FidDatabase {
            name: name.to_string(),
            libraries,
            by_full_hash,
            superior: relation_keys("Superior Table")?,
            inferior: relation_keys("Inferior Table")?,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn libraries(&self) -> &[LibraryRecord] {
        &self.libraries
    }

    pub fn function_count(&self) -> usize {
        self.by_full_hash.values().map(Vec::len).sum()
    }

    /// Whether this database describes the given language and compiler spec. A database whose
    /// libraries do not match is not attached, so no match can cross architectures.
    pub fn matches_program(&self, language_id: &str, compiler_spec_id: &str) -> bool {
        self.libraries
            .iter()
            .any(|l| l.language_id == language_id && l.compiler_spec_id == compiler_spec_id)
    }
}

/// The set of attached databases (`FidQueryService`), queried in order.
#[derive(Default, Clone)]
pub struct FidQueryService {
    databases: Vec<FidDatabase>,
}

impl FidQueryService {
    pub fn new() -> FidQueryService {
        FidQueryService::default()
    }

    pub fn attach(&mut self, database: FidDatabase) {
        self.databases.push(database);
    }

    pub fn is_empty(&self) -> bool {
        self.databases.is_empty()
    }

    pub fn databases(&self) -> &[FidDatabase] {
        &self.databases
    }

    pub fn function_count(&self) -> usize {
        self.databases.iter().map(FidDatabase::function_count).sum()
    }

    /// Load every database in `dir` whose libraries match the program's language and compiler
    /// spec — Ghidra's `.fidb` and mosura's `.mfid` / `.mfid.gz` alike. Returns an empty
    /// service when the directory is absent: with no database attached the analyzer is inert,
    /// which is the correct behaviour, not an error.
    /// Load every database in `dir` that declares this program's language and compiler spec.
    ///
    /// **Memoised per process.** Deciding whether a database matches requires OPENING it — the
    /// language and compiler spec live in its library records — and a packed `.fidb` is a
    /// DEFLATE'd Java ObjectStream, so the check costs a full unpack. With Ghidra's ten shipped
    /// Visual Studio databases that is ~2.2 s, and it was being paid on **every** `analyze()`
    /// including ones where nothing matches: analysing a gcc x86-64 ELF went 0.93 s -> 3.17 s to
    /// decompress ten Windows databases and discard all ten.
    ///
    /// The files are static for the life of the process, so the result is cached by
    /// `(dir, language, cspec)` — the same treatment `lang::load_cached` gives the SLEIGH tables,
    /// and for the same reason. First call pays; the rest are free, which is what matters for the
    /// ingest loops that analyse thousands of objects in one process.
    pub fn load_matching(
        dir: &std::path::Path,
        language_id: &str,
        compiler_spec_id: &str,
    ) -> FidQueryService {
        use std::sync::{Mutex, OnceLock};
        type Cache = Mutex<std::collections::HashMap<(std::path::PathBuf, String, String), FidQueryService>>;
        static CACHE: OnceLock<Cache> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
        let key = (dir.to_path_buf(), language_id.to_string(), compiler_spec_id.to_string());
        if let Ok(c) = cache.lock() {
            if let Some(hit) = c.get(&key) {
                return hit.clone();
            }
        }
        let service = Self::load_matching_uncached(dir, language_id, compiler_spec_id);
        if let Ok(mut c) = cache.lock() {
            c.insert(key, service.clone());
        }
        service
    }

    /// Load from every directory in a search path, merging the results.
    ///
    /// The databases live in two places (vendored Ghidra `.fidb` and the ones mosura builds), and
    /// a program can legitimately match in either. Each directory is cached independently by
    /// [`Self::load_matching`].
    /// Every distinct full hash and the records under it — the raw index, for callers that need
    /// to reason about collisions (a hash with several differently-named records is exactly the
    /// ambiguous case FID refuses to name).
    pub fn full_hash_groups(&self) -> impl Iterator<Item = (&u64, &Vec<FunctionRecord>)> {
        self.databases.iter().flat_map(|d| d.by_full_hash.iter())
    }

    pub fn load_matching_all(
        dirs: &[std::path::PathBuf],
        language_id: &str,
        compiler_spec_id: &str,
    ) -> FidQueryService {
        let mut merged = FidQueryService::new();
        for dir in dirs {
            for db in Self::load_matching(dir, language_id, compiler_spec_id).databases {
                merged.attach(db);
            }
        }
        merged
    }

    /// The databases the resource provider ([`crate::resources`]) holds under `fid/` — mosura's
    /// own `.mfid.gz` (embedded), Ghidra's vendored `.fidb` when compiled in (`fid-ghidra`) or
    /// present in an override directory or the workspace mount — filtered to the ones that match
    /// this program. This is what the analyzer uses; the directory forms above are for tests and
    /// dev tools that point at an explicit directory.
    ///
    /// Cached per `(language, compiler spec)` for the life of the process, like the directory
    /// form: the provider is set by the front-end before the first analysis and not changed after.
    pub fn load_matching_resources(language_id: &str, compiler_spec_id: &str) -> FidQueryService {
        use std::sync::{Mutex, OnceLock};
        type Cache = Mutex<HashMap<(String, String), FidQueryService>>;
        static CACHE: OnceLock<Cache> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        let key = (language_id.to_string(), compiler_spec_id.to_string());
        if let Ok(c) = cache.lock() {
            if let Some(hit) = c.get(&key) {
                return hit.clone();
            }
        }
        let res = crate::resources::get();
        let mut service = FidQueryService::new();
        for name in res.list("fid/") {
            if !(name.ends_with(".fidb") || name.ends_with(".mfid") || name.ends_with(".mfid.gz")) {
                continue;
            }
            let Some(data) = res.read(&name) else { continue };
            match load_if_matching(&name, &data, language_id, compiler_spec_id) {
                Ok(Some(db)) => service.attach(db),
                Ok(None) => {}
                Err(e) => warn!("fid: skipping {name}: {e}"),
            }
        }
        if let Ok(mut c) = cache.lock() {
            c.insert(key, service.clone());
        }
        service
    }

    fn load_matching_uncached(
        dir: &std::path::Path,
        language_id: &str,
        compiler_spec_id: &str,
    ) -> FidQueryService {
        let mut service = FidQueryService::new();
        let Ok(entries) = std::fs::read_dir(dir) else { return service };
        let mut paths: Vec<std::path::PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                let n = p.file_name().unwrap_or_default().to_string_lossy();
                n.ends_with(".fidb") || n.ends_with(".mfid") || n.ends_with(".mfid.gz")
            })
            .collect();
        paths.sort();

        for path in paths {
            let Ok(data) = std::fs::read(&path) else { continue };
            match load_if_matching(&path.to_string_lossy(), &data, language_id, compiler_spec_id) {
                Ok(Some(db)) => service.attach(db),
                Ok(None) => {}
                Err(e) => warn!("fid: skipping {}: {e}", path.display()),
            }
        }
        service
    }
}

/// A database file opened but not yet decoded: Ghidra's packed `.fidb` (a Java ObjectStream
/// header, first byte `0xac`) as its table directory, or mosura's `.mfid`/`.mfid.gz` text store
/// as its raw bytes. Opening is cheap next to decoding: the records (hundreds of thousands of
/// rows in a `.fidb`) are read by [`finish`] only.
enum Opened<'a> {
    Packed(Database),
    Text(&'a [u8]),
}

fn open_container(data: &[u8]) -> Result<Opened<'_>, String> {
    if data.first() == Some(&0xac) {
        db::open_packed(data).map(Opened::Packed).map_err(|e| e.0)
    } else {
        Ok(Opened::Text(data))
    }
}

/// The `(language, compiler spec)` pairs an opened database declares — its HEADER, without the
/// records: the Libraries Table alone for a `.fidb` (a handful of rows; the Functions Table is
/// not touched), the header lines for a store ([`super::store::header_targets`]). `None` when
/// the container does not say, and the caller decodes in full.
fn declared_targets(opened: &Opened<'_>) -> Option<Vec<(String, String)>> {
    match opened {
        Opened::Packed(database) => {
            let table = database.table("Libraries Table")?;
            let rows = database.records(table).ok()?;
            Some(
                rows.iter()
                    .map(|r| (r.str_at(4).unwrap_or_default().to_string(), r.str_at(7).unwrap_or_default().to_string()))
                    .collect(),
            )
        }
        Opened::Text(data) => super::store::header_targets(data).map(|pair| vec![pair]),
    }
}

/// Decode an opened database. It is named by the file's stem (`x86watcom` for
/// `x86watcom.mfid.gz`), whatever directory or resource name it came from.
fn finish(opened: Opened<'_>, file: &str) -> Result<FidDatabase, String> {
    let stem = file.rsplit('/').next().unwrap_or(file);
    let name = stem.trim_end_matches(".gz").trim_end_matches(".mfid").trim_end_matches(".fidb");
    match opened {
        Opened::Packed(database) => FidDatabase::from_database(name, database).map_err(|e| e.0),
        Opened::Text(data) => super::store::decompress(data)
            .and_then(|text| super::store::FidStore::from_text(&text).map_err(|e| e.0))
            .map(|store| store.into_database(name)),
    }
}

/// One database file for one program: `Ok(Some)` when it describes the program's language and
/// compiler spec, decoded; `Ok(None)` when it does not — decided from the HEADER, so a database
/// for another architecture is never decoded (before 2026-09-05 every database on disk was
/// decoded on every start and filtered afterwards: 2.9 s per program in the developer tree,
/// the same for a program nothing matches). The decoded database is still checked with
/// [`FidDatabase::matches_program`]: the header is a shortcut, not a second rule.
fn load_if_matching(
    file: &str,
    data: &[u8],
    language_id: &str,
    compiler_spec_id: &str,
) -> Result<Option<FidDatabase>, String> {
    let opened = open_container(data)?;
    if let Some(targets) = declared_targets(&opened) {
        if !targets.iter().any(|(l, c)| l == language_id && c == compiler_spec_id) {
            return Ok(None);
        }
    }
    let db = finish(opened, file)?;
    Ok(db.matches_program(language_id, compiler_spec_id).then_some(db))
}

#[cfg(test)]
mod header_tests {
    use super::*;

    fn shipped(name: &str) -> Vec<u8> {
        std::fs::read(crate::paths::workspace_root().join("data/fid").join(name)).expect("a shipped database")
    }

    /// The header decides, from a PREFIX of the file: the first 512 compressed bytes of a shipped
    /// `.mfid.gz` (hundreds of KB) name its language and compiler spec — proof the reader stops at
    /// the header and never needs the records.
    #[test]
    fn a_store_header_is_read_from_a_prefix_of_the_file() {
        let data = shipped("watcom-10.0a-x86-32.mfid.gz");
        assert!(data.len() > 20_000, "a real database (tens of KB compressed), not a stub");
        let whole = super::super::store::header_targets(&data);
        assert_eq!(whole, Some(("x86:LE:32:default".to_string(), "watcom".to_string())));
        assert_eq!(super::super::store::header_targets(&data[..512]), whole, "the header alone decides");
    }

    /// A database for another program is never decoded: a store whose header names another
    /// architecture and whose records are garbage loads as `Ok(None)` — decode-first would have
    /// tripped on the garbage (`Err`). The same garbage IS reached when the header matches.
    #[test]
    fn a_non_matching_database_is_not_decoded() {
        let text = "mosura-fid 1\nlanguage x86:LE:64:default\ncompilerspec gcc\nlibrary glibc|2.3|Release\nf this is not a record\n";
        assert_eq!(super::super::store::header_targets(text.as_bytes()), Some(("x86:LE:64:default".into(), "gcc".into())));
        match load_if_matching("garbage.mfid", text.as_bytes(), "x86:LE:32:default", "watcom") {
            Ok(None) => {}
            other => panic!("a non-matching header must skip without decoding, got {:?}", other.map(|o| o.is_some())),
        }
        assert!(load_if_matching("garbage.mfid", text.as_bytes(), "x86:LE:64:default", "gcc").is_err(), "the matching header decodes and meets the garbage");
        // a header without both fields does not decide: the full decode does (and here fails)
        assert_eq!(super::super::store::header_targets(b"mosura-fid 1\nf x\n"), None);
    }

    /// Ghidra's packed database: the Libraries Table read alone names the same targets the full
    /// decode does (gated on the vendored `.fidb` being present).
    #[test]
    fn a_packed_database_declares_its_libraries_without_the_functions_table() {
        let path = crate::paths::fid_db_dir().join("vs2012_x86.fidb");
        let Ok(data) = std::fs::read(&path) else { eprintln!("skip: {} absent", path.display()); return };
        let opened = open_container(&data).expect("a packed database");
        let declared = declared_targets(&opened).expect("a Libraries Table");
        assert!(declared.iter().any(|(l, c)| l == "x86:LE:32:default" && c == "windows"), "{declared:?}");
        let full = finish(opened, "vs2012_x86.fidb").expect("decodes");
        let mut from_full: Vec<(String, String)> = full.libraries.iter().map(|l| (l.language_id.clone(), l.compiler_spec_id.clone())).collect();
        let mut declared = declared;
        from_full.sort();
        declared.sort();
        assert_eq!(declared, from_full);
    }
}

impl FidQuery for FidQueryService {
    fn functions_by_full_hash(&self, full_hash: u64) -> Vec<FunctionRecord> {
        let mut out = Vec::new();
        for db in &self.databases {
            if let Some(records) = db.by_full_hash.get(&full_hash) {
                out.extend(records.iter().cloned());
            }
        }
        out
    }

    fn superior_full_relation(&self, superior: &FunctionRecord, inferior_full_hash: u64) -> bool {
        let key = superior_full_hash_smash(superior.key, inferior_full_hash);
        self.databases.iter().any(|db| db.superior.contains(&key))
    }

    fn inferior_full_relation(&self, superior_full_hash: u64, inferior: &FunctionRecord) -> bool {
        let key = inferior_full_hash_smash(inferior.key, superior_full_hash);
        self.databases.iter().any(|db| db.inferior.contains(&key))
    }
}
