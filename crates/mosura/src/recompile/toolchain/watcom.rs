//! Watcom C/C++32 (`wcc386`) driven under dosemu2.
//!
//! The compiler is a 16-bit DOS program, so it runs in an emulator with two drives mounted: the
//! Watcom installation and a work directory. Everything awkward about that — 8.3 filenames, CRLF
//! batch files, the fact that the emulator's exit status says nothing about whether the compiler
//! succeeded — is contained here.
//!
//! Two behaviours are worth naming, because both have silently corrupted measurements before:
//!
//! - **An aborting unit takes its whole session down.** `wcc386` is invoked from a batch file, and
//!   a unit that makes it abort ends the batch: every later unit in that session produces no
//!   object, indistinguishable from a unit whose code was rejected. The driver detects a short
//!   session and re-runs the survivors in smaller groups, down to one unit at a time, so a
//!   failure is attributed to the unit that caused it.
//! - **Success is decided by the object, not by the exit code.** dosemu2 exits 0 whatever
//!   happened inside it.

use super::{CompileOutput, CompileUnit, Toolchain};
use std::path::{Path, PathBuf};

/// A Watcom installation reachable from dosemu2.
pub struct WatcomDos {
    /// Host path of the `WATCOM` directory (mounted as `F:`).
    pub watcom_dir: PathBuf,
    /// Host path of the work directory (mounted as `G:`), where sources and objects live.
    pub work_dir: PathBuf,
    /// Version string, for the toolchain identity and therefore the cache key.
    pub version: String,
    /// Text prepended to every unit — the type and intrinsic declarations the emitted C needs.
    pub prelude: String,
    /// Units per emulator session.
    pub batch_size: usize,
    /// Remove the work directory when this driver is dropped.
    owns_work_dir: bool,
}

impl Drop for WatcomDos {
    fn drop(&mut self) {
        // The work directory is scratch — sources copied in, objects taken back out — and a run
        // that ends early (a timeout, a kill) otherwise leaves the whole corpus behind. Nine such
        // directories had accumulated before this was noticed.
        if self.owns_work_dir {
            let _ = std::fs::remove_dir_all(&self.work_dir);
        }
    }
}

impl WatcomDos {
    pub fn new(watcom_dir: impl AsRef<Path>, work_dir: impl AsRef<Path>, version: &str) -> std::io::Result<Self> {
        let work_dir = work_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&work_dir)?;
        Ok(Self {
            watcom_dir: watcom_dir.as_ref().to_path_buf(),
            work_dir,
            version: version.to_string(),
            prelude: String::new(),
            batch_size: 200,
            owns_work_dir: false,
        })
    }

    pub fn with_prelude(mut self, prelude: impl Into<String>) -> Self {
        self.prelude = prelude.into();
        self
    }

    /// Delete the work directory when this driver is dropped. For a caller that created a
    /// throwaway directory for one run; not for one pointing at a directory it shares.
    pub fn owning_work_dir(mut self) -> Self {
        self.owns_work_dir = true;
        self
    }

    /// Run one emulator session over `units`, returning whatever objects appeared.
    fn run_session(&self, units: &[CompileUnit]) -> Vec<Option<Vec<u8>>> {
        let logfile = self.work_dir.join("WCCOUT.TXT");
        let _ = std::fs::remove_file(&logfile);
        for u in units {
            let path = self.work_dir.join(format!("{}.C", u.key));
            let mut text = String::with_capacity(self.prelude.len() + u.source.len() + 1);
            text.push_str(&self.prelude);
            text.push('\n');
            text.push_str(&u.source);
            let _ = std::fs::write(path, text);
            for ext in ["obj", "OBJ"] {
                let _ = std::fs::remove_file(self.work_dir.join(format!("{}.{ext}", u.key)));
            }
        }

        let mut bat = String::new();
        bat.push_str("@echo off\r\n");
        bat.push_str("SET WATCOM=F:\\\r\n");
        bat.push_str("SET PATH=F:\\BINB;F:\\BIN;F:\\BINP\r\n");
        bat.push_str("SET INCLUDE=F:\\H\r\n");
        bat.push_str("G:\r\n");
        for u in units {
            bat.push_str(&format!("WCC386 {} {}.C >>WCCOUT.TXT\r\n", u.flags.join(" "), u.key));
        }
        let _ = std::fs::write(self.work_dir.join("_BUILD.BAT"), bat);

        let _ = std::process::Command::new("dosemu")
            .args(["-td", "-d"])
            .arg(&self.watcom_dir)
            .arg("-d")
            .arg(&self.work_dir)
            .args(["-E", "G:\\_BUILD.BAT"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        units.iter().map(|u| self.read_object(&u.key)).collect()
    }

    fn read_object(&self, key: &str) -> Option<Vec<u8>> {
        for ext in ["obj", "OBJ"] {
            let p = self.work_dir.join(format!("{key}.{ext}"));
            if let Ok(b) = std::fs::read(&p) {
                let _ = std::fs::remove_file(&p);
                return Some(b);
            }
        }
        None
    }

    /// Per-unit diagnostics, split out of the session log.
    ///
    /// `wcc386` prints a banner and then, per file, its errors followed by a `NAME.C: n lines`
    /// summary — so the log is attributed by scanning for that terminator rather than assuming
    /// one block per unit, which breaks the moment a unit aborts mid-file.
    fn split_log(&self, units: &[CompileUnit]) -> Vec<String> {
        let text = std::fs::read_to_string(self.work_dir.join("WCCOUT.TXT")).unwrap_or_default();
        let mut out = vec![String::new(); units.len()];
        let mut current = String::new();
        for line in text.lines() {
            if line.starts_with("WATCOM C") || line.starts_with("Copyright") || line.starts_with("WATCOM is") {
                continue;
            }
            current.push_str(line);
            current.push('\n');
            // `NAME.C: 68 lines, 0 warnings, 0 errors` ends a unit's block.
            if let Some((name, _)) = line.split_once(".C: ") {
                let stem = name.trim().rsplit(['\\', '/']).next().unwrap_or("").to_ascii_uppercase();
                if let Some(i) = units.iter().position(|u| u.key.to_ascii_uppercase() == stem) {
                    out[i] = std::mem::take(&mut current);
                } else {
                    current.clear();
                }
            }
        }
        // Whatever is left belongs to the unit that stopped the session.
        if !current.trim().is_empty() {
            if let Some(i) = out.iter().position(|s| s.is_empty()) {
                out[i] = current;
            }
        }
        out
    }
}

impl Toolchain for WatcomDos {
    fn id(&self) -> String {
        format!("watcom-{}", self.version)
    }

    fn compile_batch(&self, units: &[CompileUnit]) -> Vec<CompileOutput> {
        let mut results: Vec<CompileOutput> =
            units.iter().map(|u| CompileOutput { key: u.key.clone(), object: None, log: String::new() }).collect();
        // Index list, so failure isolation can re-run a subset without losing positions.
        let mut pending: Vec<usize> = (0..units.len()).collect();
        let mut group = self.batch_size.max(1);

        while !pending.is_empty() {
            let mut next_round: Vec<usize> = Vec::new();
            for chunk in pending.chunks(group) {
                let batch: Vec<CompileUnit> = chunk.iter().map(|&i| units[i].clone()).collect();
                let objects = self.run_session(&batch);
                let logs = self.split_log(&batch);
                let produced = objects.iter().filter(|o| o.is_some()).count();
                for ((&i, obj), log) in chunk.iter().zip(objects).zip(logs) {
                    if obj.is_some() {
                        results[i].object = obj;
                        results[i].log = log;
                    } else if !log.trim().is_empty() {
                        // The compiler spoke about this unit and produced nothing: a genuine
                        // rejection, not a casualty of someone else's abort.
                        results[i].log = log;
                    } else {
                        next_round.push(i);
                    }
                }
                // A session that produced nothing at all, with more than one unit in it, is the
                // abort case; nothing can be attributed from it.
                let _ = produced;
            }
            if group == 1 {
                // Already isolated: an empty result now is this unit's own failure.
                for i in next_round {
                    if results[i].log.trim().is_empty() {
                        results[i].log = "no object and no diagnostic (compiler aborted)".into();
                    }
                }
                break;
            }
            group = (group / 8).max(1);
            pending = next_round;
        }
        results
    }
}
