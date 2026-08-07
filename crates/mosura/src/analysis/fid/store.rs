//! The mosura-native signature-database format (`.mfid`).
//!
//! **The one deliberate deviation from Ghidra** (`docs/fid-port-plan.md` §3). Ghidra writes its
//! databases into a `.fidb` — a packed B-tree we can *read* (see [`super::db`]) but gain
//! nothing from *writing*: the hashes are what identify a function, and they are byte-identical
//! either way. The **schema** is ported faithfully; only the envelope differs.
//!
//! The format is deliberately **plain text, sorted, and self-describing**, because these files
//! are generated artifacts that get regenerated, reviewed and diffed:
//!
//! ```text
//! mosura-fid 1
//! language x86:LE:32:default
//! compilerspec watcom
//! library Open Watcom|10.0a|Release
//! # codeUnitSize fullHash specAddSize specificHash flags name
//! f 12 a1b2c3d4e5f60718 3 0011223344556677 1 strlen_
//! ...
//! s 1a2b3c4d5e6f7081        # superior relation key
//! i 90a1b2c3d4e5f607        # inferior relation key
//! ```
//!
//! Records are emitted in sorted order and keys are assigned deterministically from that
//! order, so **the same inputs always produce a byte-identical file**. That is what makes a
//! rebuild reviewable: a diff shows what actually changed in the runtime, not reordering noise.

use std::collections::HashSet;
use std::fmt::Write as _;

use super::matcher::FunctionRecord;
use super::query::{FidDatabase, LibraryRecord};

/// Current format version. Bump only on an incompatible change, and say why here.
pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mfid: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

/// A database in memory, ready to be written or queried.
#[derive(Debug, Clone, Default)]
pub struct FidStore {
    pub language_id: String,
    pub compiler_spec_id: String,
    pub library_family: String,
    pub library_version: String,
    pub library_variant: String,
    /// Function records. Keys are assigned on write from the sorted order.
    pub functions: Vec<FunctionRecord>,
    pub superior: HashSet<i64>,
    pub inferior: HashSet<i64>,
}

impl FidStore {
    /// Serialize to the `.mfid` text form. Deterministic: same input, same bytes.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "mosura-fid {FORMAT_VERSION}");
        let _ = writeln!(out, "language {}", self.language_id);
        let _ = writeln!(out, "compilerspec {}", self.compiler_spec_id);
        let _ = writeln!(
            out,
            "library {}|{}|{}",
            self.library_family, self.library_version, self.library_variant
        );
        let _ = writeln!(out, "# f codeUnitSize fullHash specAddSize specificHash flags name");

        let mut functions = self.functions.clone();
        functions.sort_by(|a, b| {
            a.full_hash
                .cmp(&b.full_hash)
                .then(a.specific_hash.cmp(&b.specific_hash))
                .then(a.name.cmp(&b.name))
        });
        for f in &functions {
            let _ = writeln!(
                out,
                "f {} {:016x} {} {:016x} {} {}",
                f.code_unit_size,
                f.full_hash,
                f.specific_hash_additional_size,
                f.specific_hash,
                f.flags,
                f.name
            );
        }

        let mut superior: Vec<i64> = self.superior.iter().copied().collect();
        superior.sort_unstable();
        for k in superior {
            let _ = writeln!(out, "s {:016x}", k as u64);
        }
        let mut inferior: Vec<i64> = self.inferior.iter().copied().collect();
        inferior.sort_unstable();
        for k in inferior {
            let _ = writeln!(out, "i {:016x}", k as u64);
        }
        out
    }

    /// Parse the `.mfid` text form.
    pub fn from_text(text: &str) -> Result<FidStore, StoreError> {
        let mut store = FidStore::default();
        let mut seen_header = false;
        let mut key = 0i64;

        for (lineno, line) in text.lines().enumerate() {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let err = |m: &str| StoreError(format!("line {}: {m}", lineno + 1));

            let (tag, rest) = line.split_once(' ').unwrap_or((line, ""));
            match tag {
                "mosura-fid" => {
                    let v: u32 = rest.trim().parse().map_err(|_| err("bad version"))?;
                    if v != FORMAT_VERSION {
                        return Err(err(&format!(
                            "format version {v}, this build reads {FORMAT_VERSION}"
                        )));
                    }
                    seen_header = true;
                }
                "language" => store.language_id = rest.trim().to_string(),
                "compilerspec" => store.compiler_spec_id = rest.trim().to_string(),
                "library" => {
                    let mut parts = rest.splitn(3, '|');
                    store.library_family = parts.next().unwrap_or_default().to_string();
                    store.library_version = parts.next().unwrap_or_default().to_string();
                    store.library_variant = parts.next().unwrap_or_default().to_string();
                }
                "f" => {
                    // codeUnitSize fullHash specAddSize specificHash flags name
                    let mut it = rest.splitn(6, ' ');
                    let mut next = || it.next().ok_or_else(|| err("truncated function record"));
                    let code_unit_size =
                        next()?.parse::<i16>().map_err(|_| err("bad codeUnitSize"))?;
                    let full_hash = u64::from_str_radix(next()?, 16)
                        .map_err(|_| err("bad fullHash"))?;
                    let spec_add =
                        next()?.parse::<i8>().map_err(|_| err("bad specAddSize"))?;
                    let specific_hash = u64::from_str_radix(next()?, 16)
                        .map_err(|_| err("bad specificHash"))?;
                    let flags = next()?.parse::<u8>().map_err(|_| err("bad flags"))?;
                    let name = next()?.to_string();
                    key += 1;
                    store.functions.push(FunctionRecord {
                        key,
                        code_unit_size,
                        full_hash,
                        specific_hash_additional_size: spec_add,
                        specific_hash,
                        library_id: 1,
                        name_id: key,
                        name,
                        flags,
                    });
                }
                "s" => {
                    store.superior.insert(
                        u64::from_str_radix(rest.trim(), 16).map_err(|_| err("bad key"))? as i64,
                    );
                }
                "i" => {
                    store.inferior.insert(
                        u64::from_str_radix(rest.trim(), 16).map_err(|_| err("bad key"))? as i64,
                    );
                }
                other => return Err(err(&format!("unknown record tag {other:?}"))),
            }
        }

        if !seen_header {
            return Err(StoreError("missing `mosura-fid` header".into()));
        }
        Ok(store)
    }

    /// Build the queryable form the matcher consults.
    pub fn into_database(self, name: &str) -> FidDatabase {
        let library = LibraryRecord {
            id: 1,
            family: self.library_family.clone(),
            version: self.library_version.clone(),
            variant: self.library_variant.clone(),
            language_id: self.language_id.clone(),
            compiler_spec_id: self.compiler_spec_id.clone(),
        };
        FidDatabase::new(name, vec![library], self.functions, self.superior, self.inferior)
    }
}

/// Read a `.mfid` file from disk.
pub fn read_file(path: &std::path::Path) -> Result<FidStore, StoreError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| StoreError(format!("{}: {e}", path.display())))?;
    FidStore::from_text(&text)
}

/// Write a `.mfid` file to disk.
pub fn write_file(path: &std::path::Path, store: &FidStore) -> Result<(), StoreError> {
    std::fs::write(path, store.to_text())
        .map_err(|e| StoreError(format!("{}: {e}", path.display())))
}
