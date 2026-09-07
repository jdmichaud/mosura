//! The repository names no developer's home directory.
//!
//! Where a tool, a library or an archive sits is a property of the MACHINE, not of the project:
//! it belongs in `dev-config.toml` (gitignored) under `[toolchains]`, `[binaries]` or a
//! `[[subject]]` entry, and in the sources only as the KEY that names it. A hardcoded
//! `/home/<someone>/...` breaks that twice over — it pins whatever reads it to one machine, and,
//! because this repository is public and its tests print the paths they skip, it publishes that
//! person's home directory in the log of every CI run that touches them.
//!
//! That is not hypothetical. `tests/fid_database_drift.rs` carried eighteen such paths; every one
//! of them was printed, in full, into the public Actions log of thirteen consecutive runs.
//!
//! `/home/runner` is exempt: it is the CI runner's own home, so a workflow or a runbook that
//! quotes it is describing the CI machine rather than leaking a developer's.
//!
//! As in `no_subject_names.rs`, the pattern is spelled with a character class (`/h[o]me/`) so this
//! file does not trip itself, and the positive control builds the plain text at runtime so a
//! broken pattern cannot pass silently.
use std::process::Command;

/// `/home/<user>`, with the user captured so the exemption can be applied in code (this crate's
/// regex engine has no lookahead).
fn pattern() -> regex::Regex {
    regex::Regex::new(r"/h[o]me/([A-Za-z0-9_.-]+)").unwrap()
}

/// The homes a tracked file may legitimately name.
const EXEMPT: &[&str] = &["runner"];

fn offending_user(line: &str) -> Option<String> {
    pattern()
        .captures_iter(line)
        .map(|c| c[1].to_string())
        .find(|u| !EXEMPT.contains(&u.as_str()))
}

#[test]
fn the_pattern_sees_a_plain_home_path_and_exempts_the_runner() {
    let home: String = ['/', 'h', 'o', 'm', 'e', '/'].iter().collect();
    assert_eq!(offending_user(&format!("{home}alice/projects/x")).as_deref(), Some("alice"));
    assert_eq!(offending_user(&format!("sys.path.insert(0, \"{home}bob/tools\")")).as_deref(), Some("bob"));
    // the CI runner's own home is not a leak
    assert_eq!(offending_user(&format!("{home}runner/work/mosura")), None);
    // and a tilde — the form these paths should take — is not a match at all
    assert_eq!(offending_user("~/.dosemu/drive_c/WAT100A"), None);
}

#[test]
fn no_tracked_file_names_a_home_directory() {
    let root = mosura_core::paths::workspace_root();
    // `git` through PATH, else by its usual absolute paths — the compiler-free gate runs every
    // test binary with PATH pointing nowhere, and git is the repository's own tool.
    let out = ["git", "/usr/bin/git", "/bin/git"]
        .iter()
        .find_map(|g| Command::new(g).args(["ls-files", "-z"]).current_dir(&root).output().ok())
        .expect("git ls-files (no git found on PATH, /usr/bin or /bin)");
    assert!(out.status.success(), "git ls-files failed: {}", String::from_utf8_lossy(&out.stderr));
    let mut hits = Vec::new();
    for f in out.stdout.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let rel = String::from_utf8_lossy(f).into_owned();
        if let Some(u) = offending_user(&rel) {
            hits.push(format!("{rel} (the path itself, home of `{u}`)"));
        }
        let Ok(bytes) = std::fs::read(root.join(&rel)) else { continue };
        let Ok(text) = std::str::from_utf8(&bytes) else { continue }; // a binary file: its name was checked
        for (i, line) in text.lines().enumerate() {
            if let Some(u) = offending_user(line) {
                hits.push(format!("{rel}:{} (home of `{u}`)", i + 1));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "a tracked file hardcodes a developer's home directory. Move the location into \
         dev-config.toml (`[toolchains]` / `[binaries]` / `[[subject]]`) and name it here by its \
         KEY, or write it `~/`-relative if it is genuinely a per-user default:\n  {}",
        hits.join("\n  ")
    );
}
