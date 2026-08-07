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
#[derive(Default)]
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

    /// Load every `.fidb` in `dir` whose libraries match the program's language and compiler
    /// spec. Returns an empty service when the directory is absent — with no database attached
    /// the analyzer is inert, which is the correct behaviour, not an error.
    pub fn load_matching(
        dir: &std::path::Path,
        language_id: &str,
        compiler_spec_id: &str,
    ) -> FidQueryService {
        let mut service = FidQueryService::new();
        let Ok(entries) = std::fs::read_dir(dir) else { return service };
        let mut paths: Vec<std::path::PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("fidb"))
            .collect();
        paths.sort();

        for path in paths {
            let Ok(data) = std::fs::read(&path) else { continue };
            let name = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
            match FidDatabase::open_packed(&name, &data) {
                Ok(db) if db.matches_program(language_id, compiler_spec_id) => service.attach(db),
                Ok(_) => {}
                Err(e) => eprintln!("fid: skipping {}: {e}", path.display()),
            }
        }
        service
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
