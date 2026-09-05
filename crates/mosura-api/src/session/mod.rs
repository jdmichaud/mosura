//! The session (design §5.1–5.2): a directory of immutable, content-addressed table sets plus
//! three mutable files (`manifest.tbl`, `inputs.tbl`, `config.tbl`), or the same in memory when
//! opened without a directory. Nothing here decides anything: keys come from `key::key`, tables
//! from the operations.

pub mod lock;
pub mod store;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::fingerprint::{build_id, Stage};
use crate::key::{digest, Key};
use crate::program::schemas::MANIFEST;
use crate::schema::{ColType as T, Column as C, Schema};
use crate::set::TableSet;
use crate::table::builder::TableBuilder;
use crate::table::Table;
use crate::tbl;
use lock::Lock;
use mosura_core::analysis::program::Program;
use mosura_core::recompile::round::EmitState;

/// The on-disk session format; a session written by another version is refused (D6).
pub const FORMAT_VERSION: u32 = 1;
/// The API version recorded in provenance.
pub const API_VERSION: &str = "0.1";

pub mod schemas {
    use super::*;
    pub static SESSION_MANIFEST: Schema = Schema { name: "session_manifest", version: 1, columns: &[C::new("format_version", T::U32), C::new("api_version", T::Str), C::new("build_id", T::Str), C::new("created", T::Str)] };
    pub static INPUTS: Schema = Schema { name: "inputs", version: 1, columns: &[C::new("label", T::Str), C::new("digest", T::Str), C::new("size", T::U64), C::new("filename", T::Str), C::new("added", T::Str)] };
    pub static CONFIG: Schema = Schema { name: "config", version: 1, columns: &[C::new("key", T::Str), C::new("value", T::Str)] };
    pub static SETS: Schema = Schema { name: "sets", version: 1, columns: &[C::new("kind", T::Str), C::new("key", T::Str), C::new("tables", T::U32), C::new("bytes", T::U64)] };
    pub static ALL: &[&Schema] = &[&SESSION_MANIFEST, &INPUTS, &CONFIG, &SETS];
    pub fn by_name(name: &str) -> Option<&'static Schema> {
        ALL.iter().copied().find(|s| s.name == name)
    }
}

/// Which directory a set lives in.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum SetKind {
    Program,
    Function,
}

impl SetKind {
    pub fn dir_name(self) -> &'static str {
        match self {
            SetKind::Program => "program",
            SetKind::Function => "functions",
        }
    }
}

/// What a set's `manifest.tbl` records about how it was produced.
pub struct Provenance<'a> {
    pub stage: Stage,
    pub op: &'a str,
    pub inputs: &'a [[u8; 32]],
    pub tag: &'a str,
    pub label: &'a str,
}

#[derive(Clone, Debug)]
struct InputRow {
    label: String,
    digest: [u8; 32],
    size: u64,
    filename: String,
    added: String,
}

pub struct Session {
    dir: Option<PathBuf>,
    mem_sets: BTreeMap<(SetKind, String), (TableSet, Table)>,
    mem_inputs: BTreeMap<[u8; 32], Vec<u8>>,
    inputs: Vec<InputRow>,
    config: BTreeMap<String, String>,
    /// The last program thawed or loaded (its key), reused by every operation on it.
    pub last_program: Option<(Key, Arc<Program>)>,
    /// The emit state (P0's `EmitState`) built for one passes set under one options tag.
    pub emit_state: Option<(Key, String, EmitState)>,
}

fn hex(d: &[u8; 32]) -> String {
    crate::fingerprint::hex(d)
}

impl Session {
    /// Open (creating when absent) the session at `dir`, or an in-memory session for `None`.
    pub fn open(dir: Option<&Path>) -> Result<Session> {
        let mut s = Session { dir: dir.map(Path::to_path_buf), mem_sets: BTreeMap::new(), mem_inputs: BTreeMap::new(), inputs: Vec::new(), config: BTreeMap::new(), last_program: None, emit_state: None };
        let Some(dir) = dir else { return Ok(s) };
        for sub in ["", "program", "functions", "inputs"] {
            let d = dir.join(sub);
            fs::create_dir_all(&d).map_err(|e| Error::io(e, d))?;
        }
        let manifest = dir.join("manifest.tbl");
        if manifest.is_file() {
            let m = tbl::open_mapped(&manifest, None, true)?;
            let found = if m.rows() == 1 && m.schema().name() == schemas::SESSION_MANIFEST.name { m.u64(0, 0)? as u32 } else { 0 };
            if found != FORMAT_VERSION {
                return Err(Error::Version { found: format!("session format {found}"), expected: format!("session format {FORMAT_VERSION}") });
            }
        } else {
            let mut b = TableBuilder::new(&schemas::SESSION_MANIFEST);
            b.row().u32(FORMAT_VERSION).str(API_VERSION).str(build_id()).str(&store::now_string());
            store::write_file_atomic(dir, "manifest.tbl", &tbl::write(&b.finish(false)))?;
        }
        let inputs = dir.join("inputs.tbl");
        if inputs.is_file() {
            let t = tbl::open_mapped(&inputs, Some(&schemas::INPUTS), true)?;
            for r in 0..t.rows() {
                let d = Key::from_hex(t.str(r, 1)?).ok_or_else(|| Error::Format("inputs.tbl: bad digest".into()))?;
                s.inputs.push(InputRow { label: t.str(r, 0)?.to_string(), digest: d.0, size: t.u64(r, 2)?, filename: t.str(r, 3)?.to_string(), added: t.str(r, 4)?.to_string() });
            }
        }
        let config = dir.join("config.tbl");
        if config.is_file() {
            let t = tbl::open_mapped(&config, Some(&schemas::CONFIG), true)?;
            for r in 0..t.rows() {
                s.config.insert(t.str(r, 0)?.to_string(), t.str(r, 1)?.to_string());
            }
        }
        Ok(s)
    }

    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    /// The session lock (None for an in-memory session).
    pub fn lock(&self, wait: Duration) -> Result<Option<Lock>> {
        self.dir.as_deref().map(|d| Lock::acquire(d, wait)).transpose()
    }

    // ── inputs ──

    /// Add an input by content; adding the same bytes again is a no-op (the first label stays).
    pub fn add_input(&mut self, bytes: &[u8], filename: &str, label: Option<&str>) -> Result<[u8; 32]> {
        let d = digest(bytes);
        if self.inputs.iter().any(|i| i.digest == d) {
            return Ok(d);
        }
        let label = label.map(str::to_string).unwrap_or_else(|| Path::new(filename).file_stem().and_then(|s| s.to_str()).unwrap_or(filename).to_string());
        let row = InputRow { label, digest: d, size: bytes.len() as u64, filename: filename.to_string(), added: store::now_string() };
        match &self.dir {
            Some(dir) => {
                let _lock = Lock::acquire(dir, Duration::from_secs(5))?;
                let path = dir.join("inputs").join(hex(&d));
                if !path.is_file() {
                    store::write_file_atomic(&dir.join("inputs"), &hex(&d), bytes)?;
                }
                self.inputs.push(row);
                let t = self.inputs_table();
                store::write_file_atomic(dir, "inputs.tbl", &tbl::write(&t))?;
            }
            None => {
                self.mem_inputs.insert(d, bytes.to_vec());
                self.inputs.push(row);
            }
        }
        Ok(d)
    }

    pub fn inputs_table(&self) -> Table {
        let mut b = TableBuilder::new(&schemas::INPUTS);
        for i in &self.inputs {
            b.row().str(&i.label).str(&hex(&i.digest)).u64(i.size).str(&i.filename).str(&i.added);
        }
        b.finish(false)
    }

    /// Resolve `label`, a full digest, or a unique digest prefix (≥ 6 hex digits) to an input.
    pub fn resolve_input(&self, name: &str) -> Result<[u8; 32]> {
        if let Some(i) = self.inputs.iter().find(|i| i.label == name) {
            return Ok(i.digest);
        }
        if name.len() >= 6 && name.chars().all(|c| c.is_ascii_hexdigit()) {
            let lower = name.to_ascii_lowercase();
            let hits: Vec<&InputRow> = self.inputs.iter().filter(|i| hex(&i.digest).starts_with(&lower)).collect();
            match hits.len() {
                1 => return Ok(hits[0].digest),
                0 => {}
                _ => return Err(Error::InvalidArg(format!("input `{name}` is ambiguous ({} match)", hits.len()))),
            }
        }
        if self.inputs.len() == 1 && name.is_empty() {
            return Ok(self.inputs[0].digest);
        }
        Err(Error::NotFound(format!("input `{name}`")))
    }

    /// The only input, when there is exactly one (D8: commands default to it).
    pub fn only_input(&self) -> Result<[u8; 32]> {
        match self.inputs.len() {
            1 => Ok(self.inputs[0].digest),
            0 => Err(Error::NotFound("the session has no input".into())),
            n => Err(Error::InvalidArg(format!("the session has {n} inputs; name one"))),
        }
    }

    pub fn input_filename(&self, d: &[u8; 32]) -> Option<&str> {
        self.inputs.iter().find(|i| i.digest == *d).map(|i| i.filename.as_str())
    }

    pub fn input_bytes(&self, d: &[u8; 32]) -> Result<Vec<u8>> {
        match &self.dir {
            Some(dir) => {
                let path = dir.join("inputs").join(hex(d));
                fs::read(&path).map_err(|e| Error::io(e, path))
            }
            None => self.mem_inputs.get(d).cloned().ok_or_else(|| Error::NotFound(format!("input {}", hex(d)))),
        }
    }

    // ── sets ──

    fn set_dir(&self, kind: SetKind, key: &Key) -> Option<PathBuf> {
        self.dir.as_ref().map(|d| d.join(kind.dir_name()).join(key.hex()))
    }

    pub fn has_set(&self, kind: SetKind, key: &Key) -> bool {
        match self.set_dir(kind, key) {
            Some(d) => d.join("manifest.tbl").is_file(),
            None => self.mem_sets.contains_key(&(kind, key.hex())),
        }
    }

    fn manifest_table(&self, set: &TableSet, prov: &Provenance) -> Table {
        let mut b = TableBuilder::new(&MANIFEST);
        b.row().str("format").str("set").str(&FORMAT_VERSION.to_string());
        b.row().str("api").str("version").str(API_VERSION);
        b.row().str("build").str("id").str(build_id());
        b.row().str("stage").str(prov.stage.name()).str(&hex(&crate::fingerprint::fp(prov.stage)));
        b.row().str("op").str(prov.op).str("");
        for i in prov.inputs {
            b.row().str("input").str("digest").str(&hex(i));
        }
        b.row().str("option").str("tag").str(prov.tag);
        if !prov.label.is_empty() {
            b.row().str("label").str("").str(prov.label);
        }
        b.row().str("created").str("").str(&store::now_string());
        for (name, t) in &set.tables {
            b.row().str("table").str(name).str(&format!("{} rows, {}", t.rows(), hex(&t.digest())));
        }
        for (name, blob) in &set.blobs {
            b.row().str("blob").str(name).str(&format!("{} bytes", blob.len()));
        }
        b.finish(false)
    }

    /// Store a set under `key`. Rename-atomic on disk; a set already there is left alone.
    pub fn write_set(&mut self, kind: SetKind, key: &Key, set: &TableSet, prov: &Provenance) -> Result<()> {
        let manifest = self.manifest_table(set, prov);
        match &self.dir {
            Some(dir) => store::write_set_dir(&dir.join(kind.dir_name()), &key.hex(), set, &manifest),
            None => {
                self.mem_sets.entry((kind, key.hex())).or_insert((set.clone(), manifest));
                Ok(())
            }
        }
    }

    /// Read a set back (tables mapped from disk, digests verified once).
    pub fn read_set(&self, kind: SetKind, key: &Key) -> Result<TableSet> {
        match self.set_dir(kind, key) {
            Some(d) => store::read_set_dir(&d),
            None => self.mem_sets.get(&(kind, key.hex())).map(|(s, _)| s.clone()).ok_or_else(|| Error::NotFound(format!("set {}/{}", kind.dir_name(), key.hex()))),
        }
    }

    /// The keys of every set of one kind (disk: the directories; memory: the map).
    pub fn set_keys(&self, kind: SetKind) -> Result<Vec<Key>> {
        match &self.dir {
            Some(dir) => {
                let d = dir.join(kind.dir_name());
                let mut keys: Vec<Key> = fs::read_dir(&d)
                    .map_err(|e| Error::io(e, d.clone()))?
                    .flatten()
                    .filter(|e| e.path().join("manifest.tbl").is_file())
                    .filter_map(|e| Key::from_hex(&e.file_name().to_string_lossy()))
                    .collect();
                keys.sort_by_key(|k| k.0);
                Ok(keys)
            }
            None => Ok(self.mem_sets.keys().filter(|(k, _)| *k == kind).filter_map(|(_, h)| Key::from_hex(h)).collect()),
        }
    }

    /// A set's provenance (`manifest.tbl`).
    pub fn explain(&self, kind: SetKind, key: &Key) -> Result<Table> {
        match self.set_dir(kind, key) {
            Some(d) => store::read_manifest(&d),
            None => self.mem_sets.get(&(kind, key.hex())).map(|(_, m)| m.clone()).ok_or_else(|| Error::NotFound(format!("set {}/{}", kind.dir_name(), key.hex()))),
        }
    }

    /// Every set in the session with its size — `cache gc` in P1 is this listing (dry run).
    pub fn sets(&self) -> Result<Table> {
        let mut b = TableBuilder::new(&schemas::SETS);
        match &self.dir {
            Some(dir) => {
                for kind in [SetKind::Program, SetKind::Function] {
                    let d = dir.join(kind.dir_name());
                    let mut entries: Vec<PathBuf> = fs::read_dir(&d).map_err(|e| Error::io(e, d.clone()))?.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.is_dir()).collect();
                    entries.sort();
                    for e in entries {
                        let Some(name) = e.file_name().and_then(|n| n.to_str()) else { continue };
                        if name.contains(".tmp-") {
                            continue;
                        }
                        let (mut tables, mut bytes) = (0u32, 0u64);
                        for f in fs::read_dir(&e).map_err(|err| Error::io(err, e.clone()))?.flatten() {
                            let p = f.path();
                            if p.extension().and_then(|x| x.to_str()) == Some("tbl") {
                                tables += 1;
                            }
                            bytes += f.metadata().map(|m| m.len()).unwrap_or(0);
                        }
                        b.row().str(kind.dir_name()).str(name).u32(tables).u64(bytes);
                    }
                }
            }
            None => {
                for ((kind, key), (set, _)) in &self.mem_sets {
                    let bytes: u64 = set.tables.values().map(|t| tbl::write(t).len() as u64).sum::<u64>() + set.blobs.values().map(|b| b.len() as u64).sum::<u64>();
                    b.row().str(kind.dir_name()).str(key).u32(set.tables.len() as u32).u64(bytes);
                }
            }
        }
        Ok(b.finish(false))
    }

    // ── config ──

    pub fn config(&self) -> &BTreeMap<String, String> {
        &self.config
    }

    pub fn config_table(&self) -> Table {
        let mut b = TableBuilder::new(&schemas::CONFIG);
        for (k, v) in &self.config {
            b.row().str(k).str(v);
        }
        b.finish(false)
    }

    /// Set (or, with an empty value, remove) a session config entry; persisted under the lock.
    pub fn config_set(&mut self, key: &str, value: &str) -> Result<()> {
        if value.is_empty() {
            self.config.remove(key);
        } else {
            self.config.insert(key.to_string(), value.to_string());
        }
        if let Some(dir) = &self.dir {
            let _lock = Lock::acquire(dir, Duration::from_secs(5))?;
            store::write_file_atomic(dir, "config.tbl", &tbl::write(&self.config_table()))?;
        }
        Ok(())
    }
}
