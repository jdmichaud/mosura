//! The library reads no environment variable — the guard (plan `docs/product/plan-2026-09-05.md`,
//! WP6, decision D11: "environment variables leave the library entirely; no legacy fallback").
//!
//! Every knob is a value the caller passes (`switches::Knobs`), every diagnostic a `debug::Config`
//! field, every tool or input location a `dev-config.toml` key (`devcfg`), every spec or FID file
//! a resource (`resources`, embedded with a `--data-dir` override). So no `.rs` under
//! `crates/mosura/src`, `crates/mosura/examples`, `crates/mosura/tests` or `crates/xtask/src` may
//! read the process environment, with exactly two documented exceptions, each pinned to the ONE
//! variable it may read:
//!
//! - `src/devcfg.rs` reads `HOME`: the manifest's `$HOME`-relative defaults for user-provided
//!   binaries are a promise to the developer, and the home directory is the platform's, not a
//!   mosura knob.
//! - `tests/recompile_toolchain.rs` reads `PATH`: locating an installed tool (`dosemu`) through
//!   `PATH` is the platform's lookup mechanism, not configuration of mosura.
//!
//! Compile-time `env!("CARGO_MANIFEST_DIR")` (the workspace root for the dev tier) and
//! `std::env::args()` (the command line) are not environment reads and are not matched.
//!
//! The scanner is a function of the text so its own eyesight is pinned by a test below: the
//! review finding of 2026-09-05 was a guard that matched `env::var("MOSURA_` and let a
//! `var_os` read change emitted trees unstamped — this guard sees every spelling, not one name space.

use std::path::{Path, PathBuf};

/// The spellings of an environment read. `env::args` is deliberately not one of them.
const NEEDLES: &[&str] = &["env::var(", "env::var_os(", "env::vars(", "env::vars_os(", "option_env!("];

/// Every environment read in `src`, as `(1-based line, the read as written)` — `env::var("HOME")`,
/// `option_env!("X")`, `env::vars()`. Line comments (`//`, `///`, `//!`) are stripped first so
/// prose about a variable is not a read; string-literal content is NOT special-cased (a source
/// file carrying the pattern as data must be allowlisted, as this file is).
fn env_reads(src: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, usize, String)> = Vec::new(); // (line, column, read)
    for (i, raw) in src.lines().enumerate() {
        let line = match raw.find("//") {
            Some(p) => &raw[..p],
            None => raw,
        };
        for needle in NEEDLES {
            let mut from = 0;
            while let Some(pos) = line[from..].find(needle) {
                let col = from + pos;
                let after = &line[col + needle.len()..];
                // the read as written: up to and including the closing paren of the call
                let call = match after.find(')') {
                    Some(end) => format!("{needle}{}", &after[..=end]),
                    None => needle.to_string(),
                };
                out.push((i + 1, col, call));
                from = col + needle.len();
            }
        }
    }
    out.sort();
    out.into_iter().map(|(l, _, c)| (l, c)).collect()
}

/// The allowlist: `(file, the one variable it may read)`.
const ALLOWED: &[(&str, &str)] = &[("crates/mosura/src/devcfg.rs", "\"HOME\""), ("crates/mosura/tests/recompile_toolchain.rs", "\"PATH\"")];

fn rs_files(root: &Path, dirs: &[&str]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack: Vec<PathBuf> = dirs.iter().map(|d| root.join(d)).collect();
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                files.push(p);
            }
        }
    }
    files.sort();
    files
}

/// The guard: zero environment reads outside the two pinned exceptions, or fail naming
/// `file:line: the read`.
#[test]
fn nothing_reads_the_environment() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2).expect("workspace root").to_path_buf();
    let files = rs_files(&root, &["crates/mosura/src", "crates/mosura/examples", "crates/mosura/tests", "crates/xtask/src"]);
    assert!(files.len() > 100, "the scan found only {} files — wrong root?", files.len());
    let mut offenders: Vec<String> = Vec::new();
    let mut allowed_seen: Vec<&str> = Vec::new();
    for p in &files {
        let rel = p.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        if rel == "crates/mosura/tests/no_env.rs" {
            continue; // carries the needles as test data
        }
        let Ok(src) = std::fs::read_to_string(p) else { continue };
        let allowed_var = ALLOWED.iter().find(|(f, _)| *f == rel).map(|(_, v)| *v);
        for (line, read) in env_reads(&src) {
            match allowed_var {
                Some(var) if read.contains(var) => allowed_seen.push(var),
                _ => offenders.push(format!("{rel}:{line}: {read}")),
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "environment reads outside the allowlist (knobs are values, diagnostics are --debug, locations are \
         dev-config.toml, data is a resource):\n  {}",
        offenders.join("\n  ")
    );
    // the exceptions are real (the allowlist is not stale)
    for (f, v) in ALLOWED {
        assert!(allowed_seen.contains(v), "{f} no longer reads {v}: drop it from the allowlist");
    }
}

/// The scanner's eyesight, pinned: every spelling of a read is a read (the 2026-09-05 review
/// found a guard blind to `var_os`); a comment, `env!` and `env::args` are not.
#[test]
fn the_scanner_sees_every_spelling_and_nothing_else() {
    let src = "let a = std::env::var(\"FOO\");\n\
               let b = std::env::var_os(\"BAR\").is_some();\n\
               // env::var(\"COMMENTED\") is prose\n\
               /// so is env::var_os(\"DOC\")\n\
               let c = env!(\"CARGO_MANIFEST_DIR\"); let d = std::env::args();\n\
               let e = option_env!(\"OPT\"); for (k, v) in std::env::vars() {}\n\
               env::var(\"X\"); env::var_os(\"Y\"); // trailing env::var(\"Z\")\n";
    let reads = env_reads(src);
    assert_eq!(
        reads,
        vec![
            (1, "env::var(\"FOO\")".to_string()),
            (2, "env::var_os(\"BAR\")".to_string()),
            (6, "option_env!(\"OPT\")".to_string()),
            (6, "env::vars()".to_string()),
            (7, "env::var(\"X\")".to_string()),
            (7, "env::var_os(\"Y\")".to_string()),
        ],
        "line 2 is the var_os read the old guard missed; lines 3-5 must not be reported"
    );
}
