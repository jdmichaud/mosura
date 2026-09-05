//! The `mosura` binary end to end over a temporary session: identify, add/analyze/functions,
//! decompile by name, snapshot, disasm/lift over bytes, ops/schema/call, config, cache, version,
//! and the exit codes (usage 2, library 3).

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mosura")
}

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2).unwrap().to_path_buf()
}

fn corpus(name: &str) -> PathBuf {
    workspace().join("oracle/analysis-corpus").join(name)
}

fn scratch(name: &str) -> PathBuf {
    let d = workspace().join("target").join("cli-test-sessions").join(name);
    let _ = std::fs::remove_dir_all(&d);
    d
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(session: &Path, args: &[&str]) -> Out {
    let o = Command::new(bin()).arg("-S").arg(session).args(args).output().expect("run mosura");
    Out { code: o.status.code().unwrap_or(-1), stdout: String::from_utf8_lossy(&o.stdout).into_owned(), stderr: String::from_utf8_lossy(&o.stderr).into_owned() }
}

fn ok(session: &Path, args: &[&str]) -> String {
    let o = run(session, args);
    assert_eq!(o.code, 0, "mosura {args:?} failed: {}", o.stderr);
    o.stdout
}

#[test]
fn a_session_from_identify_to_decompile() {
    let s = scratch("basic");
    let id = ok(&s, &["identify", corpus("basic.elf").to_str().unwrap()]);
    assert!(id.contains("language") && id.contains("x86:LE:64:default"), "{id}");
    let init = ok(&s, &["init"]);
    assert!(init.starts_with("session:"));
    let added = ok(&s, &["add", corpus("basic.elf").to_str().unwrap()]);
    assert!(added.ends_with("\tbasic.elf\n"), "{added}");
    let inputs = ok(&s, &["--format", "tsv", "inputs"]);
    assert!(inputs.starts_with("label\tdigest\t") && inputs.lines().count() == 2);
    let summary = ok(&s, &["analyze"]);
    assert!(summary.contains("x86:LE:64:default"), "{summary}");
    // the current program is remembered across invocations
    let fns = ok(&s, &["--format", "tsv", "functions"]);
    assert!(fns.starts_with("space\tentry\tname\n") && fns.lines().count() > 13, "{fns}");
    assert!(fns.contains("\tmain\n"));
    let json = ok(&s, &["--format", "json", "blocks"]);
    assert!(json.trim_start().starts_with('['));
    let c = ok(&s, &["decompile", "main"]);
    assert!(c.contains("FUN_"), "{c}");
    let raw = ok(&s, &["decompile", "main", "--as", "raw"]);
    assert!(!raw.is_empty() && raw != c);
    let calls = ok(&s, &["--format", "tsv", "decompile", "main", "--as", "table:calls"]);
    assert!(calls.starts_with("op_pc\ttarget\thas_static_target\n"));
    let snap = ok(&s, &["snapshot"]);
    assert!(snap.starts_with("# mosura-analysis-snapshot v1"), "{}", &snap[..40.min(snap.len())]);
    assert!(snap.contains("func "));
    let read = ok(&s, &["read", "main", "4"]);
    assert_eq!(read.trim().len(), 8, "{read}");
    let dis = ok(&s, &["--format", "tsv", "disasm", "main"]);
    assert!(dis.lines().count() > 3);
    let all = ok(&s, &["decompile", "--all"]);
    assert!(all.matches("/* =====").count() >= 13, "{}", all.matches("/* =====").count());
    // plumbing: call, config, cache, ops, schema
    let via_call = ok(&s, &["--format", "tsv", "call", "program.tables", "table=functions"]);
    assert_eq!(via_call, fns);
    let cfg = ok(&s, &["--format", "tsv", "config"]);
    assert!(cfg.contains("program\t"), "{cfg}");
    let set = ok(&s, &["--format", "tsv", "config", "set", "decompile.global-scope=standalone"]);
    assert!(set.contains("decompile.global-scope\tstandalone"));
    let bad = run(&s, &["config", "set", "decompile.global-scope=sideways"]);
    assert_eq!(bad.code, 3, "{}", bad.stderr);
    assert!(bad.stderr.contains("decompile.global-scope"), "{}", bad.stderr);
    let gc = ok(&s, &["--format", "tsv", "cache", "gc"]);
    assert!(gc.lines().count() >= 3, "{gc}");
    let key = gc.lines().nth(1).unwrap().split('\t').nth(1).unwrap().to_string();
    let explain = ok(&s, &["--format", "tsv", "cache", "explain", &key]);
    assert!(explain.contains("build\tid\t"), "{explain}");
    let ops = ok(&s, &["--format", "tsv", "ops"]);
    assert!(ops.contains("function.decompile\tproduct"));
    let schema = ok(&s, &["--format", "tsv", "schema", "functions"]);
    assert_eq!(schema.lines().count(), 4);
    let _ = std::fs::remove_dir_all(&s);
}

#[test]
fn raw_decoding_registries_and_exit_codes() {
    let s = scratch("raw");
    let lift = ok(&s, &["lift", "5589e5c3"]);
    assert!(lift.contains("COPY") || lift.contains("STORE"), "{lift}");
    let dis = ok(&s, &["--format", "tsv", "disasm", "--bytes", "5589e5c3", "--language", "x86:LE:32:default", "--base", "0x1000"]);
    assert!(dis.contains("PUSH") && dis.contains("RET"), "{dis}");
    let dis16 = ok(&s, &["--format", "tsv", "disasm", "--bytes", "b834120000", "--language", "x86:LE:32:default", "--ctx", "addrsize=0;opsize=0"]);
    assert!(dis16.contains("AX,0x1234"), "{dis16}");
    let langs = ok(&s, &["--format", "tsv", "languages"]);
    assert!(langs.contains("x86:LE:32:default\t"));
    let regs = ok(&s, &["--format", "tsv", "registers", "--language", "x86:LE:32:default"]);
    assert!(regs.contains("\nEAX\t"), "{}", &regs[..200.min(regs.len())]);
    assert_eq!(ok(&s, &["--format", "tsv", "axes"]).lines().count(), 22);
    assert_eq!(ok(&s, &["--format", "tsv", "arms"]).lines().count(), 30);
    let data = ok(&s, &["--format", "tsv", "data", "list"]);
    assert!(data.lines().count() > 100);
    let version = ok(&s, &["version"]);
    assert!(version.starts_with("mosura 0.1.0"), "{version}");
    // exit codes: clap usage 2, a bad option key 3 (a library refusal with the registry's doc)
    let usage = run(&s, &["nosuchcommand"]);
    assert_eq!(usage.code, 2);
    let badkey = run(&s, &["-o", "load.loader=sideways", "ops"]);
    assert_eq!(badkey.code, 3, "{}", badkey.stderr);
    assert!(badkey.stderr.contains("load.loader"), "{}", badkey.stderr);
    let nofn = run(&s, &["decompile", "main"]);
    assert_eq!(nofn.code, 3, "{}", nofn.stderr);
    let missing = run(&s, &["decompile"]);
    assert_eq!(missing.code, 2);
    // an in-memory session works for one-shot commands
    let mem = run(Path::new("-"), &["lift", "90"]);
    assert_eq!(mem.code, 0, "{}", mem.stderr);
    // the machine config refuses a result-affecting key and an unknown one
    let cfg = s.join("machine.toml");
    std::fs::create_dir_all(&s).unwrap();
    std::fs::write(&cfg, "[load]\nloader = \"le\"\n").unwrap();
    let mc = run(&s, &["--config", cfg.to_str().unwrap(), "version"]);
    assert_eq!(mc.code, 2, "{}", mc.stderr);
    assert!(mc.stderr.contains("belongs in the session config"), "{}", mc.stderr);
    std::fs::write(&cfg, "[toolchains.watcom]\ninstall = \"/opt/w\"\n").unwrap();
    let mc2 = run(&s, &["--config", cfg.to_str().unwrap(), "version"]);
    assert_eq!(mc2.code, 2);
    assert!(mc2.stderr.contains("unknown key"), "{}", mc2.stderr);
    let _ = std::fs::remove_dir_all(&s);
}

#[test]
fn a_watcom_program_emits_a_tree() {
    let s = scratch("watcom");
    ok(&s, &["add", corpus("watcom_hello.exe").to_str().unwrap()]);
    ok(&s, &["analyze", "--loader", "le"]);
    let fns = ok(&s, &["--format", "tsv", "functions"]);
    let first = fns.lines().nth(1).unwrap().split('\t').nth(1).unwrap().to_string();
    let tu = ok(&s, &["-o", "decompile.global-scope=standalone", "emit", &format!("0x{first}")]);
    assert!(!tu.trim().is_empty(), "{tu}");
    let report = ok(&s, &["--format", "tsv", "-o", "decompile.global-scope=standalone", "emit", &format!("0x{first}"), "--report"]);
    assert!(report.contains("row\t"), "{report}");
    let out = s.join("tree");
    let o = run(&s, &["-o", "decompile.global-scope=standalone", "emit", "--all", "--out", out.to_str().unwrap()]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let files: Vec<_> = std::fs::read_dir(&out).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert!(files.len() >= 10, "{files:?}");
    assert!(files.iter().all(|f| f.len() == 7 && f.ends_with(".c")), "{files:?}");
    let off = ok(&s, &["-o", "decompile.global-scope=standalone", "emit", &format!("0x{first}"), "--arms-off", "cmp-sign,ret-split"]);
    assert!(!off.trim().is_empty());
    let _ = std::fs::remove_dir_all(&s);
}
