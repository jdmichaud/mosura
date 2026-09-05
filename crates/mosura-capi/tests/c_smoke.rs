//! The C smoke (`tests/c_smoke/smoke.c`) and the Python smoke (`tests/py_smoke/smoke.py`) run the
//! CLI's scenario across a REAL foreign boundary: the shipped header and the cdylib, from C and
//! from ctypes. Both are `#[ignore]`d (they need `cc` / `python3`; the default suite stays
//! compiler-free) and run at phase closure: `cargo test -p mosura-capi -- --ignored`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2).unwrap().to_path_buf()
}

/// The directory holding this test binary's sibling artifacts (`target/<profile>/`): the cdylib
/// built alongside the crate's tests.
fn artifact_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().to_path_buf()
}

fn expected(name: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

#[test]
#[ignore = "needs cc and the built cdylib; run at phase closure: cargo test -p mosura-capi -- --ignored"]
fn c_smoke() {
    let target = artifact_dir();
    let so = target.join("libmosura_capi.so");
    assert!(so.is_file(), "{} missing: build the crate first", so.display());
    let out_dir = target.join("c-smoke");
    std::fs::create_dir_all(&out_dir).unwrap();
    let exe = out_dir.join("smoke");
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/c_smoke/smoke.c");
    let cc = Command::new("cc").args(["-std=c99", "-Wall", "-Wextra", "-Werror", "-I"]).arg(workspace().join("include")).arg(&src).arg("-o").arg(&exe).arg("-L").arg(&target).arg("-l:libmosura_capi.so").arg(format!("-Wl,-rpath,{}", target.display())).output().expect("cc");
    assert!(cc.status.success(), "cc failed:\n{}", String::from_utf8_lossy(&cc.stderr));
    let run = Command::new(&exe).arg(workspace().join("oracle/analysis-corpus/basic.elf")).output().expect("run smoke");
    assert!(run.status.success(), "smoke failed ({}):\n{}", run.status, String::from_utf8_lossy(&run.stderr));
    let got = String::from_utf8_lossy(&run.stdout).into_owned();
    assert_eq!(got, expected("tests/c_smoke/smoke.expected"), "C smoke output drift");
    assert!(got.contains(&format!("sizeof(mosura_ctx_config) {}", std::mem::size_of::<mosura_capi::mosura_ctx_config>())), "the C struct size equals Rust's");
}

#[test]
#[ignore = "needs python3 and the built cdylib; run at phase closure: cargo test -p mosura-capi -- --ignored"]
fn py_smoke() {
    let target = artifact_dir();
    let so = target.join("libmosura_capi.so");
    assert!(so.is_file(), "{} missing", so.display());
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py_smoke/smoke.py");
    let run = Command::new("python3").arg(&script).arg(&so).arg(workspace().join("oracle/analysis-corpus/basic.elf")).output().expect("python3");
    assert!(run.status.success(), "python smoke failed ({}):\n{}", run.status, String::from_utf8_lossy(&run.stderr));
    let got = String::from_utf8_lossy(&run.stdout).into_owned();
    assert_eq!(got, expected("tests/py_smoke/smoke.expected"), "Python smoke output drift");
    assert!(got.contains(&format!("sizeof(mosura_ctx_config) {}", std::mem::size_of::<mosura_capi::mosura_ctx_config>())), "ctypes' struct size equals Rust's");
}
