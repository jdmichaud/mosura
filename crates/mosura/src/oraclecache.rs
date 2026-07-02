//! Disk cache for `oracle/capture` runs. The oracle's output is a pure function of the
//! capture binary, the pinned Ghidra source, the fixture bytes, and the arguments — but a
//! run costs 0.1–3s (Ghidra decompiles the fixture), and the corpus/ir-parity tests spawn
//! it for every fixture on every iteration. Cache stdout under `build/oracle-cache/`
//! (gitignored), keyed by a hash of (capture binary mtime+len, fixture contents, args), so
//! a warm test run never spawns the oracle. Editing `capture.cc` (rebuilding the binary)
//! or a fixture invalidates its entries automatically; `rm -rf build/oracle-cache` clears.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::paths;

fn cache_dir() -> PathBuf {
    paths::workspace_root().join("build/oracle-cache")
}

/// Run `oracle/capture <ghidra-src> <fixture> <args…>` through the cache, returning its
/// stdout. `None` when the capture binary is missing (callers skip, as before).
pub fn capture(fixture: &Path, args: &[&str]) -> Option<String> {
    let capture = paths::workspace_root().join("oracle/capture");
    if !capture.exists() {
        return None;
    }
    let fixture_bytes = std::fs::read(fixture).ok()?;

    let mut h = DefaultHasher::new();
    if let Ok(m) = capture.metadata() {
        m.len().hash(&mut h);
        if let Ok(t) = m.modified() {
            t.hash(&mut h);
        }
    }
    fixture_bytes.hash(&mut h);
    args.hash(&mut h);
    let stem = fixture.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let key = cache_dir().join(format!("{stem}-{:016x}.out", h.finish()));

    if let Ok(cached) = std::fs::read_to_string(&key) {
        return Some(cached);
    }
    let out = Command::new(&capture).arg(paths::ghidra_src()).arg(fixture).args(args).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    // only cache a successful, non-empty run — a failed spawn shouldn't poison future runs
    if out.status.success() && !text.trim().is_empty() {
        let _ = std::fs::create_dir_all(cache_dir());
        // unique tmp per process/thread so concurrent test threads can't interleave writes
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = key.with_extension(format!("tmp.{}.{n}", std::process::id()));
        if std::fs::write(&tmp, &text).is_ok() {
            let _ = std::fs::rename(&tmp, &key);
        }
    }
    Some(text)
}
