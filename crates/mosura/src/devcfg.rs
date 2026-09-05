//! THE DEVELOPER CONFIG — where the dev tier (the tests, `xtask`, the examples, and the scripts
//! through `scripts/devcfg.sh`) finds this machine's things: the pinned Ghidra checkout, the oracle
//! root the capture tools run against, the toolchain installs, the user-provided sample binaries.
//! One gitignored file, `<workspace>/dev-config.toml`; `dev-config.example.toml` (committed) lists
//! every key with its default. An absent file or an absent key means the default, so a clean clone
//! behaves as it always did.
//!
//! This replaces the environment variables that located these things (`GHIDRA_SRC`, `MOSURA_WATCOM`,
//! `MOSURA_*_EXE`, `WATCOM_WCC386`, `MOSURA_GT_BASELINE`, `MOSURA_FID_DIR`; 2026-09-05, the
//! environment-variable removal, WP4). The PRODUCT library never reads this file — its channel for
//! spec and FID data is the resource provider (WP5) — and the crate's guard test names this module
//! as the one place a location may come from. The two platform lookups left here are `HOME`, as the
//! base of the `$HOME`-relative defaults the dependency manifest promises, and the platform's
//! temporary directory (`std::env::temp_dir`) for the recompile cache default.
//!
//! The file is a small TOML subset — enough for this file and nothing more: `[section]` and
//! `[[subject]]` headers, `key = "string"`, `key = true|false`, `#` comment lines. Keys are
//! flattened to `section.key`. `scripts/devcfg.sh` reads the same subset with awk, so a script and
//! a test see one file.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::OnceLock;

/// A user-provided binary under study (`[[subject]]`): its id (a digest or a short name), where
/// it is, and the directory of everything that is ABOUT it (goldens, gates, expectations, notes)
/// — the subject profile, outside the repository (plan WP8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub id: String,
    pub path: PathBuf,
    pub profile: Option<PathBuf>,
}

/// The parsed file: flattened `section.key` → value, plus the subjects.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DevConfig {
    values: BTreeMap<String, String>,
    subjects: Vec<Subject>,
}

impl DevConfig {
    /// Parse the TOML subset. Every malformed line is an error naming its number — a config that
    /// silently loses a key would send a test to the wrong binary without a word.
    pub fn parse(text: &str) -> Result<DevConfig, String> {
        let mut cfg = DevConfig::default();
        let mut section = String::new();
        let mut in_subject = false;
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            let n = i + 1;
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line.strip_prefix("[[").and_then(|l| l.strip_suffix("]]")) {
                if name.trim() != "subject" {
                    return Err(format!("line {n}: only `[[subject]]` arrays are understood, not `[[{}]]`", name.trim()));
                }
                cfg.subjects.push(Subject { id: String::new(), path: PathBuf::new(), profile: None });
                in_subject = true;
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = name.trim().to_string();
                in_subject = false;
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(format!("line {n}: expected `key = value`, `[section]` or `[[subject]]`"));
            };
            let key = key.trim();
            if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                return Err(format!("line {n}: bad key `{key}`"));
            }
            let value = value.trim();
            let value = if let Some(s) = value.strip_prefix('"') {
                let Some(end) = s.find('"') else { return Err(format!("line {n}: unterminated string")) };
                s[..end].to_string()
            } else if value == "true" || value == "false" {
                value.to_string()
            } else {
                return Err(format!("line {n}: a value is a \"string\" or true/false, got `{value}`"));
            };
            if in_subject {
                let s = cfg.subjects.last_mut().expect("a [[subject]] header opened this block");
                match key {
                    "id" => s.id = value,
                    "path" => s.path = PathBuf::from(value),
                    "profile" => s.profile = Some(PathBuf::from(value)),
                    other => return Err(format!("line {n}: a subject has `id`, `path`, `profile` — not `{other}`")),
                }
            } else {
                let full = if section.is_empty() { key.to_string() } else { format!("{section}.{key}") };
                cfg.values.insert(full, value);
            }
        }
        for (i, s) in cfg.subjects.iter().enumerate() {
            if s.id.is_empty() || s.path.as_os_str().is_empty() {
                return Err(format!("subject #{}: `id` and `path` are required", i + 1));
            }
        }
        Ok(cfg)
    }

    pub fn str(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
    pub fn bool(&self, key: &str) -> bool {
        self.str(key) == Some("true")
    }
    /// A path value; a leading `~/` is the home directory (the example file spells defaults that way).
    pub fn path(&self, key: &str) -> Option<PathBuf> {
        self.str(key).map(|v| match v.strip_prefix("~/") {
            Some(rest) => home().join(rest),
            None => PathBuf::from(v),
        })
    }
    pub fn subjects(&self) -> &[Subject] {
        &self.subjects
    }
    /// Every key with its value, for `cargo xtask devcfg` and the tests.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.values.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

/// `<workspace>/dev-config.toml`.
pub fn file() -> PathBuf {
    crate::paths::workspace_root().join("dev-config.toml")
}

/// The developer config, parsed once per process. A malformed file is reported once (as a
/// warning) and treated as absent — the defaults — rather than aborting every test.
pub fn get() -> &'static DevConfig {
    static CFG: OnceLock<DevConfig> = OnceLock::new();
    CFG.get_or_init(|| match std::fs::read_to_string(file()) {
        Ok(text) => DevConfig::parse(&text).unwrap_or_else(|e| {
            warn!("{}: {e} — using the defaults", file().display());
            DevConfig::default()
        }),
        Err(_) => DevConfig::default(),
    })
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default()
}

/// `ghidra_src`: the pinned Ghidra source checkout (default `<workspace>/../ghidra`). The
/// Processors tree and the datatests are read from it when present, else from the vendored copy.
pub fn ghidra_src() -> PathBuf {
    get().path("ghidra_src").unwrap_or_else(|| {
        crate::paths::workspace_root().parent().expect("workspace should have a parent dir").join("ghidra")
    })
}

/// `oracle.ghidra_root`: the root the oracle capture tools are pointed at (`SLEIGHHOME`) —
/// the checkout, a distribution, or a root built by `scripts/make-oracle-root.sh`. Default: the
/// checkout.
pub fn oracle_root() -> PathBuf {
    get().path("oracle.ghidra_root").unwrap_or_else(ghidra_src)
}

/// `oracle.ghidra_dist`: a built Ghidra DISTRIBUTION (`analyzeHeadless`) for the analysis-golden
/// captures. Default `<ghidra_src>/build/dist/ghidra_*_DEV` (a glob the scripts expand).
pub fn oracle_dist() -> PathBuf {
    get().path("oracle.ghidra_dist").unwrap_or_else(|| ghidra_src().join("build/dist/ghidra_*_DEV"))
}

/// `watcom.install`: a Watcom C/C++32 installation directory (the one holding `BINW`, `H`,
/// `LIB386`). Default `$HOME/watcom`.
pub fn watcom_install() -> PathBuf {
    get().path("watcom.install").unwrap_or_else(|| home().join("watcom"))
}

/// `watcom.wcc386`: the DOS-hosted compiler executable itself (an LX, the LE loader's own test
/// subject). Default `<watcom.install>/BINB/WCC386.EXE`.
pub fn watcom_wcc386() -> PathBuf {
    get().path("watcom.wcc386").unwrap_or_else(|| watcom_install().join("BINB/WCC386.EXE"))
}

/// A user-provided binary by its `[binaries]` key (`war2`, `cnv`, `comcom32`, `msc16`, `x32`,
/// `vc6`, `vc5`, `vc4`, `bc45`, ..), with the dependency manifest's `$HOME`-relative default
/// where one is promised; `None` for a key that is neither configured nor defaulted — the test
/// then skips, saying which key to set.
pub fn binary(name: &str) -> Option<PathBuf> {
    if let Some(p) = get().path(&format!("binaries.{name}")) {
        return Some(p);
    }
    let default = match name {
        "war2" => "WAR2.EXE",
        "msc16" => "msc16.exe",
        "x32" => "x32.exe",
        "cnv" => "cnv.exe",
        "comcom32" => ".local/share/comcom32/comcom32.exe",
        _ => return None,
    };
    Some(home().join(default))
}

/// A historical toolchain by its `[toolchains]` key (`vc98`, `bc45`, ..): the install directory
/// the FID probe builder drives. No default — these are archived media, never a clean-clone thing.
pub fn toolchain(name: &str) -> Option<PathBuf> {
    get().path(&format!("toolchains.{name}"))
}

/// `gt.update_baseline`: rewrite the ground-truth recompile baseline instead of comparing against it.
pub fn gt_update_baseline() -> bool {
    get().bool("gt.update_baseline")
}

/// `recompile.cache`: the content-addressed object cache the recompile tools share. Default: the
/// platform's temporary directory + `mosura-recompile-cache`.
pub fn recompile_cache() -> PathBuf {
    get().path("recompile.cache").unwrap_or_else(|| std::env::temp_dir().join("mosura-recompile-cache"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sections_subjects_and_defaults() {
        let c = DevConfig::parse(
            "# comment\nghidra_src = \"/g\"\n[watcom]\ninstall = \"/w\"  \n[gt]\nupdate_baseline = true\n\
             [[subject]]\nid = \"abc\"\npath = \"/b.exe\"\nprofile = \"/p\"\n[[subject]]\nid = \"d\"\npath = \"/d\"\n",
        )
        .unwrap();
        assert_eq!(c.str("ghidra_src"), Some("/g"));
        assert_eq!(c.path("watcom.install"), Some(PathBuf::from("/w")));
        assert!(c.bool("gt.update_baseline") && !c.bool("nope"));
        assert_eq!(c.subjects().len(), 2);
        assert_eq!(c.subjects()[0].profile, Some(PathBuf::from("/p")));
        assert_eq!(c.subjects()[1].profile, None);
        assert!(DevConfig::parse("").unwrap().entries().next().is_none());
    }

    #[test]
    fn every_mistake_is_an_error_naming_the_line() {
        assert!(DevConfig::parse("[[thing]]\n").unwrap_err().contains("line 1"));
        assert!(DevConfig::parse("x\n").unwrap_err().contains("line 1"));
        assert!(DevConfig::parse("a = 5\n").unwrap_err().contains("line 1"));
        assert!(DevConfig::parse("a = \"open\n").unwrap_err().contains("unterminated"));
        assert!(DevConfig::parse("[[subject]]\nid = \"x\"\n").unwrap_err().contains("required"));
        assert!(DevConfig::parse("[[subject]]\nid = \"x\"\npath = \"/x\"\nfoo = \"y\"\n").unwrap_err().contains("subject has"));
    }

    /// The committed example is the documentation of every key: it must parse, and every key it
    /// names (commented out or not) must be one the code reads.
    #[test]
    fn the_committed_example_parses_and_names_only_known_keys() {
        let text = include_str!("../../../dev-config.example.toml");
        DevConfig::parse(text).unwrap();
        // Uncomment every `# key = "..."` line (a key at the line start, not prose that happens to
        // contain ` = `) and parse again: the example's defaults are valid values.
        let is_key = |s: &str| {
            let k = s.split(" = ").next().unwrap_or("");
            !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        };
        let uncommented: String = text
            .lines()
            .map(|l| l.strip_prefix("# ").filter(|r| is_key(r)).unwrap_or(l))
            .collect::<Vec<_>>()
            .join("\n");
        let c = DevConfig::parse(&uncommented).unwrap();
        const KNOWN: &[&str] = &[
            "ghidra_src", "oracle.ghidra_root", "oracle.ghidra_dist", "survey.manifest", "watcom.install", "watcom.wcc386", "gt.update_baseline",
            "recompile.cache", "binaries.war2", "binaries.cnv", "binaries.comcom32", "binaries.msc16",
            "binaries.x32", "binaries.vc6", "binaries.vc5", "binaries.vc4", "binaries.bc45",
            "toolchains.vc98", "toolchains.bc45",
        ];
        for (k, _) in c.entries() {
            assert!(KNOWN.contains(&k), "dev-config.example.toml names `{k}`, which nothing reads");
        }
        assert!(!c.subjects().is_empty(), "the example shows a [[subject]] block");
    }

    #[test]
    fn defaults_hold_without_a_file() {
        let empty = DevConfig::default();
        assert_eq!(empty.path("ghidra_src"), None);
        assert!(binary("no-such-binary").is_none());
        assert!(binary("cnv").is_some(), "a manifest default exists for cnv");
        let c = DevConfig::parse("[binaries]\nwar2 = \"~/x/WAR2.EXE\"\n").unwrap();
        assert_eq!(c.path("binaries.war2"), Some(home().join("x/WAR2.EXE")), "`~/` expands");
    }
}
