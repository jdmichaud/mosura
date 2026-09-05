//! On-disk primitives of the store (design §5.2): rename-atomic files and set directories,
//! the known-schema lookup for reads, and the timestamp format of provenance rows.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::schema::Schema;
use crate::set::TableSet;
use crate::table::Table;
use crate::tbl;

static SEQ: AtomicU64 = AtomicU64::new(0);

fn tmp_name(stem: &str) -> String {
    format!("{stem}.tmp-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed))
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = File::create(path).map_err(|e| Error::io(e, path.to_path_buf()))?;
    f.write_all(bytes).map_err(|e| Error::io(e, path.to_path_buf()))?;
    f.sync_all().map_err(|e| Error::io(e, path.to_path_buf()))?;
    Ok(())
}

fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir).and_then(|d| d.sync_all()).map_err(|e| Error::io(e, dir.to_path_buf()))
}

/// Write `<dir>/<name>` whole: a temp sibling, fsync, rename over the old file.
pub fn write_file_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let tmp = dir.join(tmp_name(&format!(".{name}")));
    write_synced(&tmp, bytes)?;
    let final_path = dir.join(name);
    fs::rename(&tmp, &final_path).map_err(|e| Error::io(e, final_path.clone()))?;
    sync_dir(dir)
}

/// Write a set directory `<parent>/<key>/`: everything into a temp directory, each file and the
/// directory fsynced, then one rename. Losing the rename to another producer of the same key is
/// success (identical content by construction): the temp directory is removed.
pub fn write_set_dir(parent: &Path, key_hex: &str, set: &TableSet, manifest: &Table) -> Result<()> {
    let final_dir = parent.join(key_hex);
    if final_dir.is_dir() {
        return Ok(());
    }
    let tmp = parent.join(tmp_name(key_hex));
    fs::create_dir_all(&tmp).map_err(|e| Error::io(e, tmp.clone()))?;
    let result = (|| -> Result<()> {
        for (name, t) in &set.tables {
            write_synced(&tmp.join(format!("{name}.tbl")), &tbl::write(t))?;
        }
        for (name, b) in &set.blobs {
            write_synced(&tmp.join(format!("{name}.blob")), b)?;
        }
        write_synced(&tmp.join("manifest.tbl"), &tbl::write(manifest))?;
        sync_dir(&tmp)
    })();
    if let Err(e) = result {
        let _ = fs::remove_dir_all(&tmp);
        return Err(e);
    }
    match fs::rename(&tmp, &final_dir) {
        Ok(()) => sync_dir(parent),
        Err(_) if final_dir.is_dir() => {
            let _ = fs::remove_dir_all(&tmp);
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&tmp);
            Err(Error::io(e, final_dir))
        }
    }
}

/// Read a set directory back: every `<name>.tbl` (mapped, digest verified) except the set's own
/// `manifest.tbl` (served by `explain`), every `<name>.blob`.
pub fn read_set_dir(dir: &Path) -> Result<TableSet> {
    if !dir.is_dir() {
        return Err(Error::NotFound(format!("set {}", dir.display())));
    }
    let mut set = TableSet::default();
    let mut entries: Vec<PathBuf> = fs::read_dir(dir).map_err(|e| Error::io(e, dir.to_path_buf()))?.filter_map(|e| e.ok().map(|e| e.path())).collect();
    entries.sort();
    for path in entries {
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue };
        match path.extension().and_then(|e| e.to_str()) {
            Some("tbl") if stem != "manifest" => {
                set.insert(stem, tbl::open_mapped(&path, known_schema(stem), true)?);
            }
            Some("blob") => {
                set.blobs.insert(stem.to_string(), fs::read(&path).map_err(|e| Error::io(e, path.clone()))?);
            }
            _ => {}
        }
    }
    Ok(set)
}

/// Read one set's provenance table.
pub fn read_manifest(dir: &Path) -> Result<Table> {
    let path = dir.join("manifest.tbl");
    if !path.is_file() {
        return Err(Error::NotFound(format!("set {}", dir.display())));
    }
    tbl::open_mapped(&path, Some(&crate::program::schemas::MANIFEST), true)
}

/// The compiled schema a table name is expected to carry (D6: a known name with another version
/// is refused by the reader; an unknown name is served render-only with the file's own schema).
pub fn known_schema(name: &str) -> Option<&'static Schema> {
    if let Some(s) = crate::program::schemas::by_name(name) {
        return Some(s);
    }
    if name == crate::render::TEXT_SCHEMA {
        return Some(&crate::render::TEXT);
    }
    super::schemas::by_name(name)
}

/// `YYYY-MM-DDTHH:MM:SSZ`, now.
pub fn now_string() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format_time(secs)
}

/// Civil date from seconds since the epoch (Howard Hinnant's `civil_from_days`).
pub fn format_time(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, (rem % 3600) / 60, rem % 60)
}

#[cfg(test)]
mod tests {
    #[test]
    fn epoch_and_a_known_instant_format() {
        assert_eq!(super::format_time(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::format_time(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(super::format_time(1_757_116_799), "2025-09-05T23:59:59Z");
        assert_eq!(super::format_time(1_788_652_799), "2026-09-05T23:59:59Z");
    }
}
