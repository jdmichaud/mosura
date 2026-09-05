//! `Locked<T>`: one compile batch at a time per toolchain INSTALL — the runbook rule "never two
//! Watcom rounds concurrently" as code. The DOS-hosted compiler runs under one dosemu session
//! rooted at the install directory; two concurrent sessions corrupt each other's work. The lock
//! is an advisory file lock (`std::fs::File::lock`) on `<install>/.mosura-lock`, holding the
//! owner's pid and a note (the session), taken around every `compile_batch` and released after.
//! When the install directory is read-only the lock lives under a fallback directory (the
//! session's compile cache) keyed by the install path; with neither, the caller decides
//! (`Locked::new` reports the error).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use super::{CompileOutput, CompileUnit, Toolchain};

pub struct Locked<T: Toolchain> {
    inner: T,
    path: PathBuf,
    note: String,
}

/// Who holds a lock right now, as the file records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub pid: u32,
    pub note: String,
}

fn hash_path(p: &Path) -> String {
    // FNV-1a 64, the repo's hash for such names
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in p.to_string_lossy().as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

impl<T: Toolchain> Locked<T> {
    /// Wrap `inner`; the lock file is `<install>/.mosura-lock`, or `<fallback>/locks/<hash>.lock`
    /// when the install directory cannot hold a file. `note` names the holder (a session path).
    pub fn new(inner: T, install: &Path, note: &str, fallback: Option<&Path>) -> std::io::Result<Self> {
        let primary = install.join(".mosura-lock");
        let path = match OpenOptions::new().create(true).append(true).open(&primary) {
            Ok(_) => primary,
            Err(e) => match fallback {
                Some(dir) => {
                    let d = dir.join("locks");
                    std::fs::create_dir_all(&d)?;
                    d.join(format!("{}.lock", hash_path(install)))
                }
                None => return Err(std::io::Error::new(e.kind(), format!("{}: {e} (no fallback lock directory)", primary.display()))),
            },
        };
        Ok(Locked { inner, path, note: note.to_string() })
    }

    pub fn lock_path(&self) -> &Path {
        &self.path
    }

    fn open(&self) -> std::io::Result<File> {
        OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&self.path)
    }

    fn stamp(&self, f: &mut File) {
        let _ = f.set_len(0);
        let _ = f.rewind();
        let _ = writeln!(f, "{}\n{}", std::process::id(), self.note);
        let _ = f.flush();
    }

    /// Take the lock, waiting for a live holder; returns the guard (the lock is released on drop).
    pub fn acquire(&self) -> std::io::Result<Guard> {
        let mut f = self.open()?;
        f.lock()?;
        self.stamp(&mut f);
        Ok(Guard { file: f })
    }

    /// Take the lock only if free; `Err(Some(holder))` names who holds it, `Err(None)` when the
    /// holder could not be read.
    pub fn try_acquire(&self) -> std::io::Result<Result<Guard, Option<Holder>>> {
        let mut f = self.open()?;
        match f.try_lock() {
            Ok(()) => {
                self.stamp(&mut f);
                Ok(Ok(Guard { file: f }))
            }
            Err(std::fs::TryLockError::WouldBlock) => Ok(Err(self.holder())),
            Err(std::fs::TryLockError::Error(e)) => Err(e),
        }
    }

    /// The holder recorded in the lock file (whether or not the lock is currently held).
    pub fn holder(&self) -> Option<Holder> {
        let mut text = String::new();
        File::open(&self.path).ok()?.read_to_string(&mut text).ok()?;
        let mut lines = text.lines();
        let pid = lines.next()?.trim().parse().ok()?;
        Some(Holder { pid, note: lines.next().unwrap_or("").trim().to_string() })
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }
}

/// A held lock; released when dropped.
pub struct Guard {
    file: File,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl<T: Toolchain> Toolchain for Locked<T> {
    fn id(&self) -> String {
        self.inner.id()
    }

    /// Compile under the lock, waiting for a live holder (the runbook rule).
    fn compile_batch(&self, units: &[CompileUnit]) -> Vec<CompileOutput> {
        let guard = self.acquire();
        let out = self.inner.compile_batch(units);
        drop(guard);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// A toolchain that only counts; nothing is spawned.
    struct Counting(Arc<AtomicUsize>);
    impl Toolchain for Counting {
        fn id(&self) -> String {
            "counting".into()
        }
        fn compile_batch(&self, units: &[CompileUnit]) -> Vec<CompileOutput> {
            self.0.fetch_add(1, Ordering::SeqCst);
            units.iter().map(|u| CompileOutput { key: u.key.clone(), object: Some(vec![]), log: String::new(), adjudicated: true }).collect()
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mosura-locked-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_held_lock_blocks_a_second_batch_until_released_and_names_its_holder() {
        let install = scratch("install");
        let calls = Arc::new(AtomicUsize::new(0));
        let a = Locked::new(Counting(calls.clone()), &install, "session-a", None).unwrap();
        let b = Locked::new(Counting(calls.clone()), &install, "session-b", None).unwrap();
        assert_eq!(a.lock_path(), install.join(".mosura-lock"));
        let held = a.acquire().unwrap();
        // b cannot take it and reads who holds it
        let holder = b.try_acquire().unwrap().err().expect("held").expect("holder recorded");
        assert_eq!(holder, Holder { pid: std::process::id(), note: "session-a".into() });
        // b's compile waits for the release: run it on a thread, release after a moment
        let bt = std::thread::spawn(move || {
            let t0 = std::time::Instant::now();
            let out = b.compile_batch(&[CompileUnit { key: "X".into(), source: String::new(), flags: vec![] }]);
            (out.len(), t0.elapsed())
        });
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(calls.load(Ordering::SeqCst), 0, "b did not compile while a held the lock");
        drop(held);
        let (n, waited) = bt.join().unwrap();
        assert_eq!((n, calls.load(Ordering::SeqCst)), (1, 1));
        assert!(waited >= Duration::from_millis(250), "b waited for the release: {waited:?}");
        let _ = std::fs::remove_dir_all(&install);
    }

    #[test]
    fn a_read_only_install_falls_back_to_the_given_directory_or_reports() {
        let missing = PathBuf::from("/nonexistent/watcom-install");
        assert!(Locked::new(Counting(Arc::new(AtomicUsize::new(0))), &missing, "s", None).is_err());
        let fallback = scratch("fallback");
        let l = Locked::new(Counting(Arc::new(AtomicUsize::new(0))), &missing, "s", Some(&fallback)).unwrap();
        assert!(l.lock_path().starts_with(fallback.join("locks")));
        let g = l.acquire().unwrap();
        assert_eq!(l.holder().unwrap().note, "s");
        drop(g);
        let _ = std::fs::remove_dir_all(&fallback);
    }
}
