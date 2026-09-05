//! The session lock: an `O_EXCL` lock file holding the owner's pid. Mutable files (`inputs.tbl`,
//! `config.tbl`) are rewritten whole under it; sets never need it (they are immutable and
//! rename-atomic). A lock whose owner is gone is taken over.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crate::error::{Error, Result};

pub struct Lock {
    path: PathBuf,
}

/// A lock older than this whose owner cannot be checked (no `/proc`) is stale.
const STALE_AFTER: Duration = Duration::from_secs(5);

impl Lock {
    /// Take `<dir>/lock`, waiting up to `wait` for a live holder; a stale file is removed and
    /// retaken. A held lock answers `Error::Io(WouldBlock, ..)` naming the holder's pid.
    pub fn acquire(dir: &Path, wait: Duration) -> Result<Lock> {
        let path = dir.join("lock");
        let start = Instant::now();
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut f) => {
                    let _ = writeln!(f, "{}", std::process::id());
                    let _ = f.sync_all();
                    return Ok(Lock { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let holder = fs::read_to_string(&path).unwrap_or_default();
                    if Self::stale(&path, &holder) {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    if start.elapsed() >= wait {
                        let pid = holder.trim();
                        return Err(Error::Io(std::io::Error::new(std::io::ErrorKind::WouldBlock, format!("session locked by pid {pid}")), path));
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(Error::io(e, path)),
            }
        }
    }

    fn stale(path: &Path, holder: &str) -> bool {
        let pid: Option<u32> = holder.trim().parse().ok().filter(|p| *p != 0);
        if let Some(pid) = pid {
            if Path::new("/proc").is_dir() {
                return !Path::new(&format!("/proc/{pid}")).exists();
            }
        }
        match fs::metadata(path).and_then(|m| m.modified()) {
            Ok(t) => SystemTime::now().duration_since(t).map(|age| age > STALE_AFTER).unwrap_or(false),
            Err(_) => true,
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
