//! CLI goldens: the recorded stdout of fixed commands over the committed corpus and fixtures —
//! `tests/goldens/<case>.stdout`. They pin what the retired examples used to print (`lift`,
//! `identify`, `dumpc`'s C and raw IR — byte-identical to dumpc's except the function name, which
//! the program bridge spells `FUN_<entry>` where dumpc said `func`) and tie the CLI's snapshot to
//! the analysis goldens. Re-record with `cargo test -p mosura-cli --test goldens -- --ignored record`
//! and review the diff like source.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mosura")
}

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2).unwrap().to_path_buf()
}

fn goldens_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/goldens")
}

struct Case {
    name: &'static str,
    /// Commands run first on the case's session (each a list of args), output discarded.
    setup: &'static [&'static [&'static str]],
    /// The golden command.
    args: &'static [&'static str],
}

const CORPUS: &str = "oracle/analysis-corpus";
const FIXTURES: &str = "oracle/fixtures";

const CASES: &[Case] = &[
    Case { name: "lift-x86-32", setup: &[], args: &["lift", "5589e58b450883c0015dc3", "--base", "0x401000"] },
    Case { name: "lift-x86-32-tsv", setup: &[], args: &["--format", "tsv", "lift", "5589e58b450883c0015dc3", "--base", "0x401000"] },
    Case { name: "disasm-bytes-tsv", setup: &[], args: &["--format", "tsv", "disasm", "--bytes", "5589e58b450883c0015dc3", "--language", "x86:LE:32:default", "--base", "0x401000"] },
    Case { name: "disasm-bytes-16bit-tsv", setup: &[], args: &["--format", "tsv", "disasm", "--bytes", "b834120000", "--language", "x86:LE:32:default", "--ctx", "addrsize=0;opsize=0"] },
    Case { name: "dumpc-watcom-struct-copy-globals", setup: &[&["add", "oracle/fixtures/x86_20258_struct_copy_globals.xml"], &["load", "--loader", "xml"]], args: &["decompile", "0x180000"] },
    Case { name: "dumpc-watcom-struct-copy-globals-raw", setup: &[&["add", "oracle/fixtures/x86_20258_struct_copy_globals.xml"], &["load", "--loader", "xml"]], args: &["decompile", "0x180000", "--as", "raw"] },
    Case { name: "dumpc-watcom-sparse-switch", setup: &[&["add", "oracle/fixtures/x86_14620_sparse_switch.xml"], &["load", "--loader", "xml"]], args: &["decompile", "0x170000"] },
    Case { name: "dumpc-gcc-call", setup: &[&["add", "oracle/fixtures/x86_64_call.xml"], &["load", "--loader", "xml"]], args: &["decompile", "0x100000"] },
    Case { name: "dumpc-gcc-call-raw", setup: &[&["add", "oracle/fixtures/x86_64_call.xml"], &["load", "--loader", "xml"]], args: &["decompile", "0x100000", "--as", "raw"] },
    Case { name: "identify-basic-elf", setup: &[], args: &["--format", "tsv", "identify", "oracle/analysis-corpus/basic.elf"] },
    Case { name: "identify-switchtab-elf", setup: &[], args: &["--format", "tsv", "identify", "oracle/analysis-corpus/switchtab.elf"] },
    Case { name: "identify-m68k-dyn-elf", setup: &[], args: &["--format", "tsv", "identify", "oracle/analysis-corpus/m68k_dyn.elf"] },
    Case { name: "identify-watcom-hello-exe", setup: &[], args: &["--format", "tsv", "identify", "oracle/analysis-corpus/watcom_hello.exe"] },
    Case { name: "identify-mingw-hello32-exe", setup: &[], args: &["--format", "tsv", "identify", "oracle/analysis-corpus/mingw_hello32.exe"] },
    Case { name: "identify-z80-com", setup: &[], args: &["--format", "tsv", "identify", "oracle/analysis-corpus/z80.com"] },
    Case { name: "identify-aarch64-elf", setup: &[], args: &["--format", "tsv", "identify", "oracle/analysis-corpus/aarch64.elf"] },
    Case { name: "identify-riscv-elf", setup: &[], args: &["--format", "tsv", "identify", "oracle/analysis-corpus/riscv.elf"] },
    Case { name: "snapshot-basic", setup: &[&["add", "oracle/analysis-corpus/basic.elf"], &["analyze"]], args: &["snapshot"] },
    Case { name: "functions-basic-tsv", setup: &[&["add", "oracle/analysis-corpus/basic.elf"], &["analyze"]], args: &["--format", "tsv", "functions"] },
    Case { name: "symbols-basic-json", setup: &[&["add", "oracle/analysis-corpus/basic.elf"], &["analyze"]], args: &["--format", "json", "symbols"] },
    Case { name: "decompile-basic-main", setup: &[&["add", "oracle/analysis-corpus/basic.elf"], &["analyze"]], args: &["decompile", "main"] },
    Case { name: "emit-watcom-first", setup: &[&["add", "oracle/analysis-corpus/watcom_hello.exe"], &["analyze", "--loader", "le"]], args: &["-o", "decompile.global-scope=standalone", "emit", "0x10088"] },
];

/// Relative corpus/fixture paths in the args become absolute (the binary runs from anywhere).
fn absolute(arg: &str) -> String {
    if arg.starts_with(CORPUS) || arg.starts_with(FIXTURES) {
        workspace().join(arg).to_string_lossy().into_owned()
    } else {
        arg.to_string()
    }
}

fn run_case(c: &Case) -> String {
    let session = workspace().join("target").join("cli-golden-sessions").join(c.name);
    let _ = std::fs::remove_dir_all(&session);
    for step in c.setup {
        let args: Vec<String> = step.iter().map(|a| absolute(a)).collect();
        let o = Command::new(bin()).arg("-S").arg(&session).args(&args).output().unwrap();
        assert!(o.status.success(), "{}: setup {step:?} failed: {}", c.name, String::from_utf8_lossy(&o.stderr));
    }
    let args: Vec<String> = c.args.iter().map(|a| absolute(a)).collect();
    let o = Command::new(bin()).arg("-S").arg(&session).args(&args).output().unwrap();
    assert!(o.status.success(), "{}: {:?} failed: {}", c.name, c.args, String::from_utf8_lossy(&o.stderr));
    let _ = std::fs::remove_dir_all(&session);
    String::from_utf8(o.stdout).unwrap()
}

#[test]
fn every_golden_matches() {
    let mut drift = Vec::new();
    for c in CASES {
        let got = run_case(c);
        let path = goldens_dir().join(format!("{}.stdout", c.name));
        let want = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e} (record with `cargo test -p mosura-cli --test goldens -- --ignored record`)", path.display()));
        if got != want {
            let first = got.lines().zip(want.lines()).position(|(a, b)| a != b).map(|i| i + 1).unwrap_or(got.lines().count().min(want.lines().count()) + 1);
            drift.push(format!("{}: differs from line {first}", c.name));
        }
    }
    assert!(drift.is_empty(), "golden drift (re-record and review the diff if intended):\n  {}", drift.join("\n  "));
}

/// `cargo test -p mosura-cli --test goldens -- --ignored record`: write every golden.
#[test]
#[ignore = "re-records the goldens; run on purpose and review the diff"]
fn record() {
    std::fs::create_dir_all(goldens_dir()).unwrap();
    for c in CASES {
        let got = run_case(c);
        std::fs::write(goldens_dir().join(format!("{}.stdout", c.name)), got).unwrap();
        eprintln!("recorded {}", c.name);
    }
}
