//! A table set: the tables (and sibling blobs) one operation produced for one key — what a
//! `program/<key>/` or `functions/<key>/` directory holds (design §5.2). In memory, a map of
//! tables by file stem; on disk, one `.tbl` per table and one `.blob` per blob.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::table::Table;

#[derive(Debug, Clone, Default)]
pub struct TableSet {
    pub tables: BTreeMap<String, Table>,
    pub blobs: BTreeMap<String, Vec<u8>>,
}

impl TableSet {
    pub fn table(&self, name: &str) -> Result<&Table> {
        self.tables.get(name).ok_or_else(|| Error::NotFound(format!("table `{name}` in the set")))
    }
    pub fn blob(&self, name: &str) -> Result<&[u8]> {
        self.blobs.get(name).map(Vec::as_slice).ok_or_else(|| Error::NotFound(format!("blob `{name}` in the set")))
    }
    pub fn insert(&mut self, name: &str, t: Table) {
        self.tables.insert(name.to_string(), t);
    }
    /// The digests of every table, by name — two sets are the same content iff these agree.
    pub fn digests(&self) -> BTreeMap<String, [u8; 32]> {
        let mut d: BTreeMap<String, [u8; 32]> = self.tables.iter().map(|(k, t)| (k.clone(), t.digest())).collect();
        for (k, b) in &self.blobs {
            d.insert(format!("{k}.blob"), *blake3::hash(b).as_bytes());
        }
        d
    }
}
