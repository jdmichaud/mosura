//! THE RESOURCE PROVIDER — where the LIBRARY finds its data (plan WP5, decision 10): the SLEIGH
//! processor tree (`.ldefs`/`.sla`/`.pspec`/`.cspec`/`.opinion`), the pattern files, mosura's own
//! compiler specs and pattern files, the FID databases.
//!
//! Three sources, in precedence order:
//! 1. **override directories** (`Resources::with_dirs`, the design's `ctx.spec_dirs`/`fid_dirs`):
//!    a directory laid out like the resource tree (`<dir>/ghidra/Processors/…`, `<dir>/specs/…`,
//!    `<dir>/fid/…`) — a user's edited copy wins over the shipped file, file by file;
//! 2. **the workspace** (`Resources::workspace`, the dev tier's default): the repository's own
//!    `third_party/ghidra/Processors`, `specs`, `data/fid` and `third_party/ghidra-data/FunctionID`
//!    mounted as overrides, so `cargo test` reads exactly the files it always did;
//! 3. **the embedded table** (`build.rs` → `EMBEDDED`), always present: a shipped `libmosura`
//!    needs no path at all.
//!
//! Names are relative and `/`-separated (`ghidra/Processors/x86/data/languages/x86.sla`,
//! `specs/x86-32-watcom.cspec`, `fid/watcom-10.0a-x86-32.mfid.gz`). An ABSOLUTE path is read as-is
//! (a dev convenience for tests that build paths themselves). [`Resources::export`] writes the
//! embedded set out byte-identical to jump-start an override directory (`mosura data export`);
//! [`Resources::in_effect`] says which source serves each name (`mosura data list`).
//!
//! Until the product API owns a context, one provider is process-wide ([`set`]/[`get`]); its
//! default is the workspace when the build machine's checkout exists, else the embedded table.
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded.rs"));
}
pub use embedded::{EMBEDDED, EMBEDDED_BYTES};

/// The resource prefixes an override directory may carry.
pub const PREFIXES: &[&str] = &["ghidra/Processors", "specs", "fid"];

/// Where a name is served from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Embedded,
    Dir(PathBuf),
}

#[derive(Debug, Clone)]
struct Mount {
    prefix: String,
    dir: PathBuf,
}

/// The provider. Cheap to clone the handle (`Arc`), immutable once built.
#[derive(Debug, Clone)]
pub struct Resources {
    mounts: Vec<Mount>,
    index: BTreeMap<&'static str, &'static [u8]>,
}

impl Resources {
    /// The embedded table alone — what a shipped library sees with no configuration.
    pub fn embedded_only() -> Resources {
        Resources { mounts: Vec::new(), index: EMBEDDED.iter().map(|(n, b)| (*n, *b)).collect() }
    }

    /// Embedded + override directories, first dir wins. Each dir is laid out like the resource
    /// tree; only the [`PREFIXES`] that exist under it are mounted.
    pub fn with_dirs(dirs: &[PathBuf]) -> Resources {
        let mut r = Resources::embedded_only();
        for d in dirs {
            for p in PREFIXES {
                let sub = d.join(p);
                if sub.is_dir() {
                    r.mounts.push(Mount { prefix: p.to_string(), dir: sub });
                }
            }
        }
        r
    }

    /// The dev tier's default: the workspace's own copies mounted as overrides (the vendored
    /// Processors tree, `specs/`, `data/fid/`, and Ghidra's `third_party/ghidra-data/FunctionID`),
    /// each only if present, over the embedded table.
    pub fn workspace() -> Resources {
        let ws = crate::paths::workspace_root();
        let mut r = Resources::embedded_only();
        for (prefix, rel) in [
            ("ghidra/Processors", "third_party/ghidra/Processors"),
            ("specs", "specs"),
            ("fid", "data/fid"),
            ("fid", "third_party/ghidra-data/FunctionID"),
        ] {
            let dir = ws.join(rel);
            if dir.is_dir() {
                r.mounts.push(Mount { prefix: prefix.to_string(), dir });
            }
        }
        r
    }

    /// Add an override directory in front of the existing ones.
    pub fn with_override_first(mut self, dir: &Path) -> Resources {
        let mut front = Vec::new();
        for p in PREFIXES {
            let sub = dir.join(p);
            if sub.is_dir() {
                front.push(Mount { prefix: p.to_string(), dir: sub });
            }
        }
        front.append(&mut self.mounts);
        self.mounts = front;
        self
    }

    fn mounted_path(&self, name: &str) -> Option<PathBuf> {
        for m in &self.mounts {
            if let Some(rest) = name.strip_prefix(m.prefix.as_str()).and_then(|r| r.strip_prefix('/')) {
                let p = m.dir.join(rest);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
        None
    }

    /// The bytes of a resource, from the first source that has it. An absolute name is a file path.
    pub fn read(&self, name: &str) -> Option<Cow<'static, [u8]>> {
        if Path::new(name).is_absolute() {
            return std::fs::read(name).ok().map(Cow::Owned);
        }
        if let Some(p) = self.mounted_path(name) {
            return std::fs::read(p).ok().map(Cow::Owned);
        }
        self.index.get(name).map(|b| Cow::Borrowed(*b))
    }

    pub fn read_string(&self, name: &str) -> Option<String> {
        self.read(name).map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    pub fn exists(&self, name: &str) -> bool {
        if Path::new(name).is_absolute() {
            return Path::new(name).is_file();
        }
        self.mounted_path(name).is_some() || self.index.contains_key(name)
    }

    /// Which source serves `name`, by the same precedence as [`Self::read`].
    pub fn source(&self, name: &str) -> Option<Source> {
        if Path::new(name).is_absolute() {
            return Path::new(name).is_file().then(|| Source::Dir(PathBuf::from(name)));
        }
        for m in &self.mounts {
            if let Some(rest) = name.strip_prefix(m.prefix.as_str()).and_then(|r| r.strip_prefix('/')) {
                if m.dir.join(rest).is_file() {
                    return Some(Source::Dir(m.dir.clone()));
                }
            }
        }
        self.index.contains_key(name).then_some(Source::Embedded)
    }

    /// Every name under `prefix`, from every source, sorted and deduplicated — the walk a
    /// directory listing used to be (the `.ldefs` discovery, the pattern files, the FID databases).
    pub fn list(&self, prefix: &str) -> Vec<String> {
        if Path::new(prefix).is_absolute() {
            // a real directory (dev convenience, like an absolute `read`): its files, recursively
            let mut names = BTreeSet::new();
            let mut stack = vec![PathBuf::from(prefix.trim_end_matches('/'))];
            while let Some(d) = stack.pop() {
                let Ok(rd) = std::fs::read_dir(&d) else { continue };
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else {
                        names.insert(p.to_string_lossy().into_owned());
                    }
                }
            }
            return names.into_iter().collect();
        }
        let mut names: BTreeSet<String> = self.index.keys().filter(|n| n.starts_with(prefix)).map(|n| n.to_string()).collect();
        for m in &self.mounts {
            // the mount contributes names `<m.prefix>/<rel>`; only those under `prefix`
            let mut stack = vec![m.dir.clone()];
            while let Some(d) = stack.pop() {
                let Ok(rd) = std::fs::read_dir(&d) else { continue };
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else if let Ok(rel) = p.strip_prefix(&m.dir) {
                        let name = format!("{}/{}", m.prefix, slashed(rel));
                        if name.starts_with(prefix) {
                            names.insert(name);
                        }
                    }
                }
            }
        }
        names.into_iter().collect()
    }

    /// Every name known to this provider with the source that serves it (`mosura data list`).
    pub fn in_effect(&self) -> Vec<(String, Source)> {
        self.list("").into_iter().filter_map(|n| self.source(&n).map(|s| (n, s))).collect()
    }

    /// Write the EMBEDDED files under `what` (`"specs"` = the processor tree + our specs, `"fid"`,
    /// or `"all"`) into `dir`, laid out as the resource tree, byte-identical to the vendored
    /// originals — the jump start for an override directory. Existing files are kept unless
    /// `overwrite`. Returns the files written.
    pub fn export(&self, dir: &Path, what: &str, overwrite: bool) -> std::io::Result<Vec<PathBuf>> {
        let wanted = |name: &str| match what {
            "all" => true,
            "specs" => name.starts_with("ghidra/") || name.starts_with("specs/"),
            "fid" => name.starts_with("fid/"),
            _ => false,
        };
        if !matches!(what, "all" | "specs" | "fid") {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("export: `{what}` is not one of all, specs, fid")));
        }
        let mut written = Vec::new();
        for (name, bytes) in EMBEDDED {
            if !wanted(name) {
                continue;
            }
            let target = dir.join(name);
            if target.exists() && !overwrite {
                continue;
            }
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&target, bytes)?;
            written.push(target);
        }
        Ok(written)
    }
}

fn slashed(rel: &Path) -> String {
    rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("/")
}

static CURRENT: RwLock<Option<Arc<Resources>>> = RwLock::new(None);

/// Install the process-wide provider (a front-end, from its `--spec-dir`/`--fid-dir` flags).
pub fn set(r: Resources) {
    *CURRENT.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(r));
}

/// The provider a process gets when nothing was [`set`]: the workspace's vendored copies as
/// overrides when the build machine's checkout exists (so an edited `.cspec` or a rebuilt FID
/// database is picked up without a rebuild), else the embedded table alone.
pub fn default_for_process() -> Resources {
    let ws = crate::paths::workspace_root();
    if ws.join("third_party/ghidra/Processors").is_dir() {
        Resources::workspace()
    } else {
        Resources::embedded_only()
    }
}

/// The process-wide provider: what [`set`] installed, else [`default_for_process`].
pub fn get() -> Arc<Resources> {
    if let Some(r) = CURRENT.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        return Arc::clone(r);
    }
    static DEFAULT: OnceLock<Arc<Resources>> = OnceLock::new();
    Arc::clone(DEFAULT.get_or_init(|| Arc::new(default_for_process())))
}

/// The front-end half: take every `--data-dir <dir>` (or `--data-dir=<dir>`) out of an argument
/// list, install the default provider with those directories layered on top (the LAST one given
/// is resolved first, then the earlier ones, then the default), and return the remaining
/// arguments. One grammar for every example and, later, the CLI; nothing is read from the
/// environment. Errors: a `--data-dir` without a value, or a directory that does not exist.
pub fn from_args(args: Vec<String>) -> Result<Vec<String>, String> {
    let mut rest = Vec::with_capacity(args.len());
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--data-dir" {
            dirs.push(PathBuf::from(it.next().ok_or_else(|| "`--data-dir` wants a directory".to_string())?));
        } else if let Some(v) = a.strip_prefix("--data-dir=") {
            dirs.push(PathBuf::from(v));
        } else {
            rest.push(a);
        }
    }
    if !dirs.is_empty() {
        let mut r = default_for_process();
        for d in &dirs {
            if !d.is_dir() {
                return Err(format!("--data-dir {}: not a directory", d.display()));
            }
            r = r.with_override_first(d);
        }
        set(r);
    }
    Ok(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The embedded table IS the vendored tree: every entry byte-identical to the workspace file it
    /// was built from (the chain `pin → vendored copy → binary`; `verify-vendored-ghidra.sh` proves
    /// the first link, this the second).
    #[test]
    fn embedded_matches_the_workspace_files() {
        let ws = crate::paths::workspace_root();
        assert!(EMBEDDED.len() > 150, "the table holds the processor tree, the specs and our FID databases: {}", EMBEDDED.len());
        let mut checked = 0;
        for (name, bytes) in EMBEDDED {
            let rel = name
                .strip_prefix("ghidra/Processors/").map(|r| format!("third_party/ghidra/Processors/{r}"))
                .or_else(|| name.strip_prefix("specs/").map(|r| format!("specs/{r}")))
                .or_else(|| name.strip_prefix("fid/").map(|r| format!("data/fid/{r}")))
                .unwrap_or_else(|| panic!("unexpected embedded name {name}"));
            let disk = std::fs::read(ws.join(&rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
            assert!(disk.as_slice() == *bytes, "{name} differs from {rel}");
            checked += 1;
        }
        assert_eq!(checked, EMBEDDED.len());
        assert_eq!(EMBEDDED_BYTES, EMBEDDED.iter().map(|(_, b)| b.len() as u64).sum::<u64>());
    }

    #[test]
    fn embedded_only_resolves_the_core_names() {
        let r = Resources::embedded_only();
        assert!(r.exists("ghidra/Processors/x86/data/languages/x86.ldefs"));
        assert!(r.exists("ghidra/Processors/x86/data/languages/x86-64.sla"));
        assert!(r.exists("specs/x86-32-watcom.cspec"));
        assert!(r.list("fid/").iter().any(|n| n.ends_with(".mfid.gz")));
        assert_eq!(r.source("specs/x86-32-watcom.cspec"), Some(Source::Embedded));
        assert!(r.list("ghidra/Processors/x86/data/languages/").iter().any(|n| n.ends_with("/x86.ldefs")));
        assert!(!r.exists("specs/no-such.cspec") && r.read("nope").is_none());
    }

    #[test]
    fn an_override_directory_wins_file_by_file_and_export_round_trips() {
        let tmp = std::env::temp_dir().join(format!("mosura-resources-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        // export everything, then the exported tree must serve every name byte-identically
        let written = Resources::embedded_only().export(&tmp, "all", false).unwrap();
        assert_eq!(written.len(), EMBEDDED.len());
        let r = Resources::with_dirs(&[tmp.clone()]);
        for (name, bytes) in EMBEDDED.iter().take(40) {
            assert!(matches!(r.source(name), Some(Source::Dir(_))), "{name} must come from the override");
            assert_eq!(r.read(name).unwrap().as_ref(), *bytes, "{name} byte-identical after export");
        }
        // edit one exported file: the edit wins over the embedded copy, and only that file
        let edited = tmp.join("specs/x86-32-watcom.cspec");
        std::fs::write(&edited, b"<compiler_spec/>").unwrap();
        assert_eq!(r.read("specs/x86-32-watcom.cspec").unwrap().as_ref(), b"<compiler_spec/>");
        assert_eq!(Resources::embedded_only().read("specs/x86-32-watcom.cspec").unwrap().len() > 100, true);
        // a name only the override has is listed
        std::fs::write(tmp.join("specs/extra.cspec"), b"x").unwrap();
        assert!(r.list("specs/").contains(&"specs/extra.cspec".to_string()));
        // export without overwrite keeps the edit; with overwrite restores the original
        assert!(Resources::embedded_only().export(&tmp, "specs", false).unwrap().is_empty());
        Resources::embedded_only().export(&tmp, "specs", true).unwrap();
        assert!(r.read("specs/x86-32-watcom.cspec").unwrap().len() > 100);
        assert!(Resources::embedded_only().export(&tmp, "bogus", false).is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn absolute_paths_read_as_is_and_the_default_is_the_workspace_here() {
        let abs = crate::paths::workspace_root().join("specs/x86-32-watcom.cspec");
        let r = Resources::embedded_only();
        assert_eq!(r.read(abs.to_str().unwrap()).unwrap(), r.read("specs/x86-32-watcom.cspec").unwrap());
        assert!(matches!(get().source("specs/x86-32-watcom.cspec"), Some(Source::Dir(_))), "in the workspace the checkout is the override");
    }
}
