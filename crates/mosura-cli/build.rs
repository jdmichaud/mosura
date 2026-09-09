//! Stamp the git commit into the CLI binary at build time.
//!
//! Design decision E8 (docs/product/plan-wp7-2026-09-05.md): the library never shells out to git
//! — its `build_id` is content-derived (blake3 of the stage fingerprints) — and the CLI, a
//! front-end, adds the git commit as provenance when it is built inside a checkout. This runs at
//! build time (cargo's build-script protocol), not at the library's runtime; it reads no
//! environment variable, and `main.rs` picks the result up through the compile-time `env!` macro
//! (which the `no_env` guard does not treat as an environment read). A bare source tree with no
//! git, or a git that fails, stamps `unknown` — the clean-clone CI build still succeeds.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let stamp = match git(&["rev-parse", "--short=12", "HEAD"]) {
        Some(commit) => {
            // Re-stamp when HEAD moves or the index changes (a commit, a checkout).
            if let Some(git_dir) = git(&["rev-parse", "--absolute-git-dir"]) {
                println!("cargo:rerun-if-changed={git_dir}/HEAD");
                println!("cargo:rerun-if-changed={git_dir}/index");
            }
            // Mark a working tree with uncommitted tracked changes, so a binary built from an
            // edited checkout does not claim to be exactly its commit.
            let dirty = Command::new("git")
                .args(["status", "--porcelain", "--untracked-files=no"])
                .output()
                .ok()
                .is_some_and(|o| o.status.success() && !o.stdout.is_empty());
            if dirty {
                format!("{commit}-dirty")
            } else {
                commit
            }
        }
        None => "unknown".to_string(),
    };

    println!("cargo:rustc-env=MOSURA_GIT_COMMIT={stamp}");
}

/// Run `git <args>` and return its trimmed stdout, or `None` if git is absent, fails, or is not in
/// a repository.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!s.is_empty()).then_some(s)
}
