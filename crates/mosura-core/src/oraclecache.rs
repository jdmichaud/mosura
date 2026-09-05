//! Disk cache for `oracle/capture` runs. The oracle's output is a pure function of the
//! capture binary, the Ghidra root it is pointed at, the fixture bytes, and the arguments — but
//! a run costs 0.1–3s (Ghidra decompiles the fixture), and the corpus/ir-parity tests spawn
//! it for every fixture on every iteration. Cache stdout under `build/oracle-cache/`
//! (gitignored), keyed by a hash of (capture binary mtime+len, Ghidra-root fingerprint, fixture
//! contents, args), so a warm test run never spawns the oracle. Editing `capture.cc` (rebuilding
//! the binary), a fixture, or the root's compiler spec invalidates the affected entries
//! automatically; `rm -rf build/oracle-cache` clears everything.
//!
//! The root belongs in the key because the same fixture decompiles to *different C* under
//! different roots: a compiler id an `.ldefs` does not register falls back to the language
//! default silently, so `arch=…:watcom` yields watcall under one root and `__fastcall` under
//! another. Before the root was keyed, switching roots served the old root's captures back —
//! which is how a batch of the subject captures were read as watcom while they were Visual Studio's
//! convention. See `scripts/make-oracle-root.sh` for the root this repo intends.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::paths;

fn cache_dir() -> PathBuf {
    paths::workspace_root().join("build/oracle-cache")
}

/// Fold the identity of a Ghidra root into `h`: its *resolved* path (so two roots are distinct
/// even when one is reached through a symlink) plus the contents of the two files that decide
/// which calling convention a `…:watcom` capture actually gets. Reading them costs microseconds
/// and covers both halves of the failure: an `.ldefs` that never registers the compiler id, and
/// an edited `.cspec` behind an id that is registered. `None` — the file absent — is itself a
/// distinguishing value, because absence is exactly the case that falls back silently.
fn hash_ghidra_root(root: &Path, h: &mut DefaultHasher) {
    std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf()).hash(h);
    for rel in [
        "Ghidra/Processors/x86/data/languages/x86.ldefs",
        "Ghidra/Processors/x86/data/languages/x86-32-watcom.cspec",
    ] {
        std::fs::read(root.join(rel)).ok().hash(h);
    }
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
    hash_ghidra_root(&paths::oracle_root(), &mut h);
    fixture_bytes.hash(&mut h);
    args.hash(&mut h);
    let stem = fixture.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let key = cache_dir().join(format!("{stem}-{:016x}.out", h.finish()));

    if let Ok(cached) = std::fs::read_to_string(&key) {
        return Some(cached);
    }
    let out = Command::new(&capture).arg(paths::oracle_root()).arg(fixture).args(args).output().ok()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(root: &Path) -> u64 {
        let mut h = DefaultHasher::new();
        hash_ghidra_root(root, &mut h);
        h.finish()
    }

    /// Build a minimal root at `dir` carrying the two files the fingerprint reads.
    fn root(dir: &Path, ldefs: &str, cspec: &str) -> PathBuf {
        let langs = dir.join("Ghidra/Processors/x86/data/languages");
        std::fs::create_dir_all(&langs).unwrap();
        std::fs::write(langs.join("x86.ldefs"), ldefs).unwrap();
        std::fs::write(langs.join("x86-32-watcom.cspec"), cspec).unwrap();
        dir.to_path_buf()
    }

    /// The regression this key exists for: captures taken under one Ghidra root must not be
    /// served to a run pointed at another. Each half is a way the old key was blind — a
    /// different root at a different path, the same path with an edited spec, and the
    /// registration missing entirely (the silent `__fastcall` fallback).
    #[test]
    fn ghidra_root_fingerprint_separates_roots() {
        let base = std::env::temp_dir().join(format!("mosura-oraclecache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (with, without) = ("<compiler id=\"watcom\"/>", "<compiler id=\"gcc\"/>");

        let a = root(&base.join("a"), with, "SPEC-A");
        let b = root(&base.join("b"), with, "SPEC-A");
        let a_edited = root(&base.join("a-edited"), with, "SPEC-A-EDITED");
        let a_unregistered = root(&base.join("a-unreg"), without, "SPEC-A");

        assert_eq!(fingerprint(&a), fingerprint(&a), "same root must hit its own entries");
        assert_ne!(fingerprint(&a), fingerprint(&b), "a different root is a different key");
        assert_ne!(fingerprint(&a), fingerprint(&a_edited), "an edited cspec invalidates");
        assert_ne!(fingerprint(&a), fingerprint(&a_unregistered), "the ldefs registration counts");

        // a symlink to a root is that root, not a third one
        let link = base.join("link-to-a");
        std::os::unix::fs::symlink(&a, &link).unwrap();
        assert_eq!(fingerprint(&a), fingerprint(&link), "the resolved path is the identity");

        // a root missing the files is still distinct from one that has them
        let empty = base.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert_ne!(fingerprint(&a), fingerprint(&empty), "absent files are a distinct value");

        let _ = std::fs::remove_dir_all(&base);
    }
}
