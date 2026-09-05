//! The repository names no subject binary (decision 14, 2026-09-05): the binaries under study are
//! INPUTS, declared in `dev-config.toml` as `[[subject]]` entries with a profile directory outside
//! the repository that holds everything about them (goldens, gates, expectations, notes). This
//! guard walks every tracked file (`git ls-files`) — paths and text alike — and fails on a
//! case-insensitive occurrence of a subject's name, naming file:line.
//!
//! The names are spelled with a character class (`w[a]r2`) so this file does not trip itself; the
//! positive control builds the plain word at runtime and asserts the pattern sees it, so a broken
//! pattern cannot pass silently.
use std::process::Command;

fn pattern() -> regex::Regex {
    regex::Regex::new(r"(?i)w[a]r2|w[a]rcraft").unwrap()
}

#[test]
fn the_pattern_sees_the_plain_words() {
    let word: String = ['w', 'a', 'r', '2'].iter().collect();
    assert!(pattern().is_match(&word) && pattern().is_match(&word.to_uppercase()));
    let word2: String = ['W', 'a', 'r', 'c', 'r', 'a', 'f', 't'].iter().collect();
    assert!(pattern().is_match(&word2) && pattern().is_match(&format!("x_{}_y", word2.to_lowercase())));
    assert!(!pattern().is_match("warm war 2 craft"), "the pattern is the names, not their parts");
}

#[test]
fn no_tracked_file_names_a_subject() {
    let root = mosura::paths::workspace_root();
    let out = Command::new("git").args(["ls-files", "-z"]).current_dir(&root).output().expect("git ls-files");
    assert!(out.status.success(), "git ls-files failed: {}", String::from_utf8_lossy(&out.stderr));
    let re = pattern();
    let mut hits = Vec::new();
    for f in out.stdout.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let rel = String::from_utf8_lossy(f).into_owned();
        if re.is_match(&rel) {
            hits.push(format!("{rel} (the path itself)"));
        }
        let Ok(bytes) = std::fs::read(root.join(&rel)) else { continue };
        let Ok(text) = std::str::from_utf8(&bytes) else { continue }; // a binary file: its name was checked
        for (i, line) in text.lines().enumerate() {
            if re.is_match(line) {
                hits.push(format!("{rel}:{}", i + 1));
            }
        }
    }
    assert!(hits.is_empty(), "the repository names a subject binary in:\n  {}", hits.join("\n  "));
}
