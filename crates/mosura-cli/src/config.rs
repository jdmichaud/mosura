//! The machine config: `--config <file>`, else `<home>/.config/mosura/config.toml`, in the TOML
//! subset dev-config.toml uses (`[section]`, `key = "string"`, `key = true|false`, `#` comments),
//! flattened to `section.key`. It may carry `Environment` keys only — tool locations that belong
//! to this machine (phase 3 adds them); a result-affecting key belongs in the session config, and
//! is refused here so a machine file can never change a result. The ONE environment read of the
//! CLI is `HOME`, to locate this file (the platform's home directory, not a mosura knob).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Parse the subset; every malformed line is an error naming its number.
pub fn parse(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    let mut section = String::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        let n = i + 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("[[") {
            return Err(format!("line {n}: arrays of tables are not understood in the machine config"));
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_string();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {n}: expected `key = value` or `[section]`"));
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
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
        let full = if section.is_empty() { key.to_string() } else { format!("{section}.{key}") };
        out.insert(full, value);
    }
    Ok(out)
}

/// Write a flat `section.key → value` map back as the subset (grouped by section, sorted).
pub fn render(map: &BTreeMap<String, String>) -> String {
    let mut by_section: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (k, v) in map {
        let (section, key) = match k.rsplit_once('.') {
            Some((s, key)) => (s.to_string(), key.to_string()),
            None => (String::new(), k.clone()),
        };
        by_section.entry(section).or_default().push((key, v.clone()));
    }
    let mut out = String::from("# mosura machine config: Environment keys only (tool locations); results never depend on it.\n");
    for (section, entries) in by_section {
        if !section.is_empty() {
            out.push_str(&format!("\n[{section}]\n"));
        }
        for (k, v) in entries {
            if v == "true" || v == "false" {
                out.push_str(&format!("{k} = {v}\n"));
            } else {
                out.push_str(&format!("{k} = \"{}\"\n", v.replace('"', "'")));
            }
        }
    }
    out
}

/// Store one key in the machine config file (created with its directory when absent).
pub fn set(path: &Path, key: &str, value: &str) -> Result<(), String> {
    let mut map = match std::fs::read_to_string(path) {
        Ok(text) => parse(&text).map_err(|e| format!("{}: {e}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    map.insert(key.to_string(), value.to_string());
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    std::fs::write(path, render(&map)).map_err(|e| format!("{}: {e}", path.display()))
}

/// The default location: `<home>/.config/mosura/config.toml`.
pub fn default_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| Path::new(&h).join(".config/mosura/config.toml"))
}

/// Load the machine config; an absent file (explicit or default) is an empty config —
/// `toolchain add` creates it.
pub fn load(explicit: Option<&Path>) -> Result<BTreeMap<String, String>, String> {
    let path = match explicit {
        Some(p) => p.to_path_buf(),
        None => match default_path() {
            Some(p) => p,
            None => return Ok(BTreeMap::new()),
        },
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => parse(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_subset_parses_and_refuses_the_rest() {
        let m = super::parse("# c\n[toolchains.watcom]\ninstall = \"/opt/w\"\nwait = true\n").unwrap();
        assert_eq!(m.get("toolchains.watcom.install").map(String::as_str), Some("/opt/w"));
        assert_eq!(m.get("toolchains.watcom.wait").map(String::as_str), Some("true"));
        assert!(super::parse("x = 5\n").unwrap_err().contains("line 1"));
        assert!(super::parse("[[a]]\n").unwrap_err().contains("arrays"));
        assert!(super::parse("nope\n").unwrap_err().contains("expected"));
        let back = super::parse(&super::render(&m)).unwrap();
        assert_eq!(back, m, "render → parse round-trips");
    }
}
