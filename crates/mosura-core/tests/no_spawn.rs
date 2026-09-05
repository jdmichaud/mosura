//! The release library spawns nothing but a declared toolchain. `Command::new(` may appear in the
//! product crates' sources only in `recompile/toolchain/driver.rs` (the compiler driver — the one
//! process a round runs, under a `CompilerSpec`) and in the dev-tier files compiled only under
//! `feature = "dev"` (the oracle capture, the gcc ground truth, the MVE twin build). Everything
//! else — the api, the C ABI, the binding, the CLI — is a library that computes.

use std::path::{Path, PathBuf};

/// `Command::new(` is allowed here; `dev` marks a file that the `dev` feature gates.
const ALLOWED: &[(&str, &str)] = &[
    ("crates/mosura-core/src/recompile/toolchain/driver.rs", "the compiler driver"),
    ("crates/mosura-core/src/oraclecache.rs", "dev"),
    ("crates/mosura-core/src/recompile/groundtruth.rs", "dev"),
    ("crates/mosura-core/src/recompile/twin.rs", "dev"),
];

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

#[test]
fn only_the_toolchain_driver_and_the_dev_tier_spawn_processes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2).expect("workspace root").to_path_buf();
    let files = rs_files(&root, &["crates/mosura-core/src", "crates/mosura-api/src", "crates/mosura-capi/src", "crates/mosura/src", "crates/mosura-cli/src"]);
    assert!(files.len() > 100, "the scan found only {} files — wrong root?", files.len());
    let mut offenders = Vec::new();
    let mut seen = Vec::new();
    for p in &files {
        let rel = p.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        let Ok(src) = std::fs::read_to_string(p) else { continue };
        let spawns: Vec<usize> = src.lines().enumerate().filter(|(_, l)| { let code = l.split("//").next().unwrap_or(""); code.contains("Command::new(") }).map(|(i, _)| i + 1).collect();
        if spawns.is_empty() {
            continue;
        }
        match ALLOWED.iter().find(|(f, _)| *f == rel) {
            Some((f, why)) => {
                seen.push(*f);
                if *why == "dev" {
                    // a dev-tier file must be gated: its module declaration carries the cfg
                    let module = Path::new(f).file_stem().unwrap().to_string_lossy().into_owned();
                    let parent = if rel.contains("/recompile/") { "crates/mosura-core/src/recompile/mod.rs" } else { "crates/mosura-core/src/lib.rs" };
                    let decl = std::fs::read_to_string(root.join(parent)).unwrap();
                    assert!(decl.contains(&format!("#[cfg(any(test, feature = \"dev\"))]\npub mod {module};")), "{f} spawns a process but `pub mod {module}` in {parent} is not gated behind the dev feature");
                }
            }
            None => offenders.push(format!("{rel}:{}", spawns.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(","))),
        }
    }
    assert!(offenders.is_empty(), "process spawns outside the toolchain driver and the dev tier:\n  {}", offenders.join("\n  "));
    for (f, _) in ALLOWED {
        assert!(seen.contains(f), "{f} no longer spawns a process: drop it from the allowlist");
    }
}
