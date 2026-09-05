//! The `dev-tools` build: the dev tier is registered when the context is built — `ops --dev`
//! lists it, `mosura dev <op>` runs it (with or without the `dev.` prefix) and so does `call`.
//! Compiled only with the feature (`cargo test -p mosura-cli --features dev-tools --test dev`).
#![cfg(feature = "dev-tools")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mosura")
}

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2).unwrap().to_path_buf()
}

fn run(args: &[&str]) -> (i32, String, String) {
    let o = Command::new(bin()).arg("-S").arg("-").args(args).output().expect("run mosura");
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

#[test]
fn the_dev_tier_is_built_in() {
    let (code, ops, err) = run(&["--format", "tsv", "ops", "--dev"]);
    assert_eq!(code, 0, "{err}");
    assert!(ops.contains("dev.omf.dump\tdev\t"), "{ops}");
    let (code, product, _) = run(&["--format", "tsv", "ops"]);
    assert_eq!(code, 0);
    assert!(!product.contains("\tdev\t"), "the product listing hides the dev tier: {product}");
    let obj = workspace().join("oracle/codegen-probes/watcom/10.0a.obj");
    let path = format!("dev.path={}", obj.display());
    let (code, out, err) = run(&["--format", "tsv", "dev", "omf.dump", &path]);
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("kind\tname\tseg\toff\tsize\tdetail\n") && out.contains("\npublic\t"), "{out}");
    let (code, out2, _) = run(&["--format", "tsv", "dev", "dev.omf.dump", &path]);
    assert_eq!(code, 0);
    assert_eq!(out, out2, "the dev. prefix is optional");
    let (code, out3, _) = run(&["--format", "tsv", "call", "dev.omf.dump", &path]);
    assert_eq!(code, 0);
    assert_eq!(out, out3, "call reaches the dev tier too");
    let (code, _, err) = run(&["dev", "nope"]);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("operation `dev.nope`"), "{err}");
    let (code, _, err) = run(&["dev", "omf.dump", "dev.path"]);
    assert_eq!(code, 2, "{err}");
}

/// `dev bench` over one x86-64 datatest: per-fixture rows worst first, then the two summary rows.
#[test]
fn bench_runs_over_one_fixture() {
    // the vendored datatests (what `paths::datatests_dir()` falls back to without a Ghidra checkout)
    let dir = workspace().join("third_party/ghidra/datatests");
    let stem = std::fs::read_dir(&dir).expect("datatests").filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "xml") && std::fs::read_to_string(p).unwrap_or_default().contains("x86:LE:64")).map(|p| p.file_stem().unwrap().to_string_lossy().into_owned()).min().expect("an x86-64 datatest");
    let (code, out, err) = run(&["--format", "tsv", "dev", "bench", &format!("dev.only={stem}")]);
    assert_eq!(code, 0, "{err}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "fixture\ttotal_ms\tbuild_ms\tdecompile_ms\tprint_ms", "{out}");
    assert!(lines[1].starts_with(&format!("{stem}\t")), "{out}");
    assert!(lines[2].starts_with("*total*\t") && lines[3].starts_with("*spec-load*\t"), "{out}");
    assert_eq!(lines.len(), 4);
}
