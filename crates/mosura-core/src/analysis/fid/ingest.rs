//! Library ingest — a faithful port of `service/FidServiceLibraryIngest.java`.
//!
//! Turns a set of analyzed programs (one per object file of a runtime library) into a
//! signature database. This is what gives mosura signatures for every runtime Ghidra does not
//! ship: Watcom, gcc/glibc, sdcc, Borland — eight of our nine supported columns.
//!
//! The steps, in Ghidra's order:
//! 1. **Hash every named function.** Skip external functions, thunks, functions with no defined
//!    symbol, and anything below the short-hash floor.
//! 2. **Record its callees.** A call to a function in the same object resolves to that
//!    function's row; a call to an unresolved symbol is deferred by name.
//! 3. **Dedup.** A 64-bit digest over the specific hash, the full hash, the name and every
//!    child's full hash (`generateHash`, `:95-120`) decides whether this is a function already
//!    ingested. Two objects containing the same routine contribute one record.
//! 4. **Emit relations.** Each non-very-common child becomes a `DIRECT_CALL`, keyed by the hash
//!    smash. Deferred by-name calls are linked after every program is read.
//!
//! **Commonality.** A caller/callee edge only helps identification when it is *distinguishing*.
//! A supplied common-symbols list marks routines everything calls (`memcpy`, `malloc`) so they
//! contribute no relation, and a name that reaches more than
//! [`MAXIMUM_NUMBER_OF_NAME_RESOLUTION_RELATIONS`] distinct specific hashes is likewise dropped
//! — it is not telling us anything.

use std::collections::{HashMap, HashSet};

use super::hash::FidHashQuad;
use super::matcher::{
    flags, inferior_full_hash_smash, superior_full_hash_smash, FunctionRecord,
};
use super::store::FidStore;

/// `FidServiceLibraryIngest.MAXIMUM_NUMBER_OF_NAME_RESOLUTION_RELATIONS` (`:41`).
pub const MAXIMUM_NUMBER_OF_NAME_RESOLUTION_RELATIONS: usize = 12;

/// What a call site inside an ingested function points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildRef {
    /// A call to another function in the same program, by its entry offset.
    Local(u64),
    /// A call to a symbol not defined here — resolved by name once every program is read.
    Named(String),
}

/// One function offered to the ingest.
#[derive(Debug, Clone)]
pub struct IngestFunction {
    /// Entry offset within its program.
    pub entry: u64,
    /// The defined symbol name. `None` means a default name — excluded, as Ghidra excludes a
    /// `SourceType.DEFAULT` symbol: a database entry with no name identifies nothing.
    pub name: Option<String>,
    pub quad: Option<FidHashQuad>,
    pub children: Vec<ChildRef>,
    pub is_thunk: bool,
    pub is_external: bool,
    /// Whether the body ends in a terminator (`FunctionRecord` flag bit 1).
    pub has_terminator: bool,
}

/// Why a function was not ingested (`FidPopulateResult.Disposition`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Disposition {
    External,
    NoDefinedSymbol,
    IsThunk,
    FailsMinimumShortHashLength,
    Duplicate,
}

/// What one ingest run produced (`FidPopulateResult`).
#[derive(Debug, Clone, Default)]
pub struct IngestResult {
    pub ingested: usize,
    pub excluded: HashMap<Disposition, usize>,
    pub relations: usize,
    /// Names seen as a call target, with how many distinct specific hashes they reached.
    pub child_histogram: HashMap<String, usize>,
}

impl IngestResult {
    fn exclude(&mut self, why: Disposition) {
        *self.excluded.entry(why).or_insert(0) += 1;
    }
}

/// Java's `String.hashCode()` — `h = 31*h + c`, wrapping in `int`.
///
/// Ported exactly because it feeds `generateHash`, which decides deduplication. A different
/// string hash would silently change which duplicates collapse.
fn java_string_hash(s: &str) -> i32 {
    let mut h: i32 = 0;
    for c in s.encode_utf16() {
        h = h.wrapping_mul(31).wrapping_add(i32::from(c as i16));
    }
    h
}

/// A function accepted for ingest, before deduplication.
#[derive(Debug, Clone)]
struct FunctionRow {
    name: String,
    quad: FidHashQuad,
    has_terminator: bool,
    /// Resolved children: `Some(full_hash)` for a local call whose target was hashed,
    /// `None` with a name for a deferred one.
    children: Vec<ResolvedChild>,
}

#[derive(Debug, Clone)]
struct ResolvedChild {
    name: String,
    full_hash: Option<u64>,
    very_common: bool,
}

impl FunctionRow {
    /// `generateHash` (`:95-120`) — the deduplication key: specific hash, full hash, name, and
    /// every child's full hash (or its name where no hash is available).
    fn generate_hash(&self) -> i64 {
        let mut hash = self.quad.specific_hash as i64;
        hash = hash.wrapping_mul(31).wrapping_add(self.quad.full_hash as i64);
        hash = hash.wrapping_mul(31).wrapping_add(i64::from(java_string_hash(&self.name)));
        // Ghidra sorts children before hashing so the key does not depend on discovery order.
        let mut children = self.children.clone();
        children.sort_by(|a, b| {
            a.full_hash.is_none().cmp(&b.full_hash.is_none()).then(a.name.cmp(&b.name))
        });
        for child in &children {
            hash = hash.wrapping_mul(31);
            hash = match child.full_hash {
                Some(h) => hash.wrapping_add(h as i64),
                None => hash.wrapping_add(i64::from(java_string_hash(&child.name))),
            };
        }
        hash
    }
}

/// The ingest builder.
pub struct Ingest {
    language_id: String,
    compiler_spec_id: String,
    family: String,
    version: String,
    variant: String,
    /// Symbols so common that a call to them distinguishes nothing
    /// (`markCommonChildReferences`, `:204-214`).
    common_symbols: HashSet<String>,
    rows: Vec<FunctionRow>,
    /// `globalUniqueFunction` — dedup keys already committed.
    seen: HashSet<i64>,
    /// Deferred by-name children: (committed row index, child name).
    unresolved: Vec<(usize, String)>,
    /// name → the distinct specific hashes it resolved to, for the relation cap.
    name_specific_hashes: HashMap<String, HashSet<u64>>,
    result: IngestResult,
}

impl Ingest {
    pub fn new(
        language_id: &str,
        compiler_spec_id: &str,
        family: &str,
        version: &str,
        variant: &str,
    ) -> Ingest {
        Ingest {
            language_id: language_id.to_string(),
            compiler_spec_id: compiler_spec_id.to_string(),
            family: family.to_string(),
            version: version.to_string(),
            variant: variant.to_string(),
            common_symbols: HashSet::new(),
            rows: Vec::new(),
            seen: HashSet::new(),
            unresolved: Vec::new(),
            name_specific_hashes: HashMap::new(),
            result: IngestResult::default(),
        }
    }

    /// `markCommonChildReferences` (`:204-214`) — the "common symbols file" of Ghidra's
    /// populate dialog. Ghidra's own lists ship as
    /// `Features/FunctionID/data/common_symbols_win{32,64}.txt`.
    pub fn mark_common_symbols<I: IntoIterator<Item = String>>(&mut self, symbols: I) {
        self.common_symbols.extend(symbols);
    }

    /// Ingest one program's functions (`populateLibraryFromProgram`, `:266-321`).
    pub fn add_program(&mut self, functions: &[IngestFunction]) {
        // Entry → its accepted row, for resolving local calls.
        let mut local: HashMap<u64, (String, FidHashQuad)> = HashMap::new();
        for f in functions {
            if f.is_external || f.is_thunk || f.name.is_none() {
                continue;
            }
            if let Some(q) = f.quad {
                local.insert(f.entry, (f.name.clone().unwrap(), q));
            }
        }

        for f in functions {
            if f.is_external {
                self.result.exclude(Disposition::External);
                continue;
            }
            let Some(name) = f.name.clone() else {
                self.result.exclude(Disposition::NoDefinedSymbol);
                continue;
            };
            if f.is_thunk {
                self.result.exclude(Disposition::IsThunk);
                continue;
            }
            let Some(quad) = f.quad else {
                self.result.exclude(Disposition::FailsMinimumShortHashLength);
                continue;
            };

            let children: Vec<ResolvedChild> = f
                .children
                .iter()
                .map(|c| match c {
                    ChildRef::Local(entry) => match local.get(entry) {
                        Some((child_name, child_quad)) => ResolvedChild {
                            name: child_name.clone(),
                            full_hash: Some(child_quad.full_hash),
                            very_common: self.common_symbols.contains(child_name),
                        },
                        // A call to something in this program we could not hash.
                        None => ResolvedChild {
                            name: String::new(),
                            full_hash: None,
                            very_common: false,
                        },
                    },
                    ChildRef::Named(n) => ResolvedChild {
                        name: n.clone(),
                        full_hash: None,
                        very_common: self.common_symbols.contains(n),
                    },
                })
                .filter(|c| !c.name.is_empty() || c.full_hash.is_some())
                .collect();

            for child in &children {
                *self.result.child_histogram.entry(child.name.clone()).or_insert(0) += 1;
            }

            let row = FunctionRow { name: name.clone(), quad, has_terminator: f.has_terminator, children };

            // `globalUniqueFunction.add(hash)` — first writer wins, later identical copies are
            // recorded as duplicates rather than re-committed.
            if !self.seen.insert(row.generate_hash()) {
                self.result.exclude(Disposition::Duplicate);
                continue;
            }

            self.name_specific_hashes
                .entry(name)
                .or_default()
                .insert(quad.specific_hash);

            let index = self.rows.len();
            for child in &row.children {
                if child.full_hash.is_none() && !child.name.is_empty() {
                    self.unresolved.push((index, child.name.clone()));
                }
            }
            self.rows.push(row);
            self.result.ingested += 1;
        }
    }

    /// Finish: assign keys, emit relations, and produce the store.
    ///
    /// Keys are assigned from the **sorted** record order rather than insertion order, so a
    /// rebuild from the same inputs yields byte-identical output and a diff shows only real
    /// change.
    pub fn finish(mut self) -> (FidStore, IngestResult) {
        // Sort exactly as the store writes, so key N always denotes the same record.
        let mut order: Vec<usize> = (0..self.rows.len()).collect();
        order.sort_by(|&a, &b| {
            let (x, y) = (&self.rows[a], &self.rows[b]);
            x.quad
                .full_hash
                .cmp(&y.quad.full_hash)
                .then(x.quad.specific_hash.cmp(&y.quad.specific_hash))
                .then(x.name.cmp(&y.name))
        });
        let mut key_of = vec![0i64; self.rows.len()];
        for (rank, &row_index) in order.iter().enumerate() {
            key_of[row_index] = rank as i64 + 1;
        }

        let mut functions = Vec::with_capacity(self.rows.len());
        for &row_index in &order {
            let row = &self.rows[row_index];
            functions.push(FunctionRecord {
                key: key_of[row_index],
                code_unit_size: row.quad.code_unit_size,
                full_hash: row.quad.full_hash,
                specific_hash_additional_size: row.quad.specific_hash_additional_size,
                specific_hash: row.quad.specific_hash,
                library_id: 1,
                name_id: key_of[row_index],
                name: row.name.clone(),
                flags: if row.has_terminator { flags::HAS_TERMINATOR } else { 0 },
            });
        }

        // Name → the rows defining it, for resolving deferred calls.
        let mut by_name: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, row) in self.rows.iter().enumerate() {
            by_name.entry(row.name.as_str()).or_default().push(i);
        }

        let mut superior = HashSet::new();
        let mut inferior = HashSet::new();
        let mut relations = 0usize;

        let mut add_relation = |caller: usize, callee: usize, key_of: &[i64], rows: &[FunctionRow]| {
            let caller_key = key_of[caller];
            let callee_key = key_of[callee];
            let caller_hash = rows[caller].quad.full_hash;
            let callee_hash = rows[callee].quad.full_hash;
            superior.insert(superior_full_hash_smash(caller_key, callee_hash));
            inferior.insert(inferior_full_hash_smash(callee_key, caller_hash));
            relations += 1;
        };

        // Direct calls resolved within a program.
        for (caller, row) in self.rows.iter().enumerate() {
            for child in &row.children {
                if child.very_common || child.full_hash.is_none() {
                    continue;
                }
                let hash = child.full_hash.unwrap();
                if let Some(candidates) = by_name.get(child.name.as_str()) {
                    for &callee in candidates {
                        if self.rows[callee].quad.full_hash == hash {
                            add_relation(caller, callee, &key_of, &self.rows);
                        }
                    }
                }
            }
        }

        // `resolveNamedRelations` — deferred by-name calls, subject to the relation cap.
        for (caller, name) in &self.unresolved {
            if self.common_symbols.contains(name) {
                continue;
            }
            let distinct = self.name_specific_hashes.get(name).map_or(0, HashSet::len);
            if distinct > MAXIMUM_NUMBER_OF_NAME_RESOLUTION_RELATIONS {
                // The name is too ambiguous to be a distinguisher.
                continue;
            }
            if let Some(candidates) = by_name.get(name.as_str()) {
                for &callee in candidates {
                    add_relation(*caller, callee, &key_of, &self.rows);
                }
            }
        }

        self.result.relations = relations;
        let store = FidStore {
            language_id: self.language_id,
            compiler_spec_id: self.compiler_spec_id,
            library_family: self.family,
            library_version: self.version,
            library_variant: self.variant,
            functions,
            superior,
            inferior,
        };
        (store, self.result)
    }
}
