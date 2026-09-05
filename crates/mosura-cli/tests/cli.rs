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

/// A release build (no `dev-tools` feature): the dev tier is not built in — a `dev.*` operation
/// says so (a library error, not "unknown"), `ops --dev` lists no dev row, and there is no `dev`
/// subcommand.
#[cfg(not(feature = "dev-tools"))]
#[test]
fn the_dev_tier_is_not_built_in() {
    let s = scratch("nodev");
    let o = run(&s, &["call", "dev.omf.dump"]);
    assert_eq!(o.code, 3, "{}", o.stderr);
    assert!(o.stderr.contains("not built in"), "{}", o.stderr);
    // its option keys are not registered either — the registry refuses them before the op
    let key = run(&s, &["call", "dev.omf.dump", "dev.path=x.obj"]);
    assert_eq!(key.code, 3, "{}", key.stderr);
    assert!(key.stderr.contains("unknown option key `dev.path`"), "{}", key.stderr);
    let unknown = run(&s, &["call", "nope.zzz"]);
    assert_eq!(unknown.code, 3, "{}", unknown.stderr);
    assert!(unknown.stderr.contains("not found") || unknown.stderr.contains("operation `nope.zzz`"), "{}", unknown.stderr);
    let ops = ok(&s, &["--format", "tsv", "ops", "--dev"]);
    assert!(!ops.contains("\tdev\t"), "{ops}");
    let sub = run(&s, &["dev", "omf.dump"]);
    assert_ne!(sub.code, 0);
    assert!(sub.stderr.contains("unrecognized subcommand"), "{}", sub.stderr);
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
    let mc_tc = run(&s, &["--config", cfg.to_str().unwrap(), "version"]);
    assert_eq!(mc_tc.code, 0, "a toolchain install location is the CLI's own key: {}", mc_tc.stderr);
    std::fs::write(&cfg, "[foo]\nbar = \"x\"\n").unwrap();
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

#[test]
fn toolchains_rounds_and_verify_without_a_compiler() {
    let s = scratch("rounds");
    std::fs::create_dir_all(&s).unwrap();
    let machine = s.join("machine.toml");
    let cfg = ["--config", machine.to_str().unwrap()];
    let specs = ok(&s, &[&cfg[..], &["--format", "tsv", "toolchain", "specs"]].concat());
    assert_eq!(specs.lines().count(), 4, "{specs}");
    // add: the spec into the session config, the install into the machine file
    let added = ok(&s, &[&cfg[..], &["toolchain", "add", "cc", "--spec", "gcc-native", "--install", "cc"]].concat());
    assert!(added.starts_with("toolchain cc: spec gcc-native"), "{added}");
    let file = std::fs::read_to_string(&machine).unwrap();
    assert!(file.contains("[toolchains.cc]") && file.contains("install = \"cc\""), "{file}");
    let list = ok(&s, &[&cfg[..], &["toolchain", "list"]].concat());
    assert!(list.contains("cc\tgcc-native\tcc"), "{list}");
    // without the machine file the install is unknown: a usage error naming the fix
    let no_install = run(&s, &["--config", s.join("empty.toml").to_str().unwrap(), "recompile", "0x10", "--toolchain", "cc"]);
    assert!(no_install.code == 2 || no_install.code == 3, "{}", no_install.stderr);
    // an unknown toolchain name
    let unknown = run(&s, &[&cfg[..], &["recompile", "0x10", "--toolchain", "nope"]].concat());
    assert_eq!(unknown.code, 2, "{}", unknown.stderr);
    assert!(unknown.stderr.contains("has no spec"), "{}", unknown.stderr);
    // rounds through the CLI: import two legacy tables, list/show/compare/gates/export
    let a = s.join("a-rec.tsv");
    let b = s.join("b-rec.tsv");
    std::fs::write(&a, "idx\tva\tname\tverdict\tbytes\tprimary\tsim\tequal\torig_n\tcand_n\tclasses\tSIM=structural\n00001\t00010063\tF1\tEXACT\tIdentical\t\t1.000\t29\t29\t29\t\n00002\t00010100\tF2\tMISMATCH\tDifferent\textra\t0.250\t5\t20\t30\textra=10\n").unwrap();
    std::fs::write(&b, "idx\tva\tname\tverdict\tbytes\tprimary\tsim\tequal\torig_n\tcand_n\tclasses\tSIM=structural\n00001\t00010063\tF1\tEXACT\tIdentical\t\t1.000\t29\t29\t29\t\n00002\t00010100\tF2\tSAME_SHAPE\tDifferent\tregalloc\t0.750\t15\t20\t20\tregalloc=5\n").unwrap();
    let imported = ok(&s, &[&cfg[..], &["--format", "tsv", "round", "import", "ra", "--verdicts", a.to_str().unwrap(), "--label", "baseline"]].concat());
    assert!(imported.contains("census\tEXACT\t1"), "{imported}");
    ok(&s, &[&cfg[..], &["round", "import", "rb", "--verdicts", b.to_str().unwrap()]].concat());
    let listed = ok(&s, &[&cfg[..], &["--format", "tsv", "round", "list"]].concat());
    assert_eq!(listed.lines().count(), 3, "{listed}");
    assert!(listed.contains("\nra\t") && listed.contains("\nrb\t"));
    let shown = ok(&s, &[&cfg[..], &["--format", "tsv", "round", "show", "rb", "--table", "verdicts"]].concat());
    assert!(shown.contains("F2\tSAME_SHAPE"), "{shown}");
    let cmp = ok(&s, &[&cfg[..], &["--format", "tsv", "round", "compare", "ra", "rb"]].concat());
    assert!(cmp.contains("flip\t10100\tF2\tMISMATCH\tSAME_SHAPE"), "{cmp}");
    assert!(cmp.contains("summary\t0\tflips\t1"), "{cmp}");
    let gates = run(&s, &[&cfg[..], &["--format", "tsv", "gates", "rb", "--baseline", "ra"]].concat());
    assert_eq!(gates.code, 0, "{}\n{}", gates.stdout, gates.stderr);
    assert!(gates.stdout.contains("8 verdict-regressions\tOK"), "{}", gates.stdout);
    // the other way round F2 goes SAME_SHAPE → MISMATCH: a down is LISTED under gate 8, not a
    // failure (only an EXACT lost or a new failure verdict fails the gate)
    let gates_rev = run(&s, &[&cfg[..], &["--format", "tsv", "gates", "ra", "--baseline", "rb"]].concat());
    assert_eq!(gates_rev.code, 0, "{}", gates_rev.stdout);
    assert!(gates_rev.stdout.contains("1 down(s) listed") && gates_rev.stdout.contains("F2: SAME_SHAPE -> MISMATCH"), "{}", gates_rev.stdout);
    let out = s.join("ra-export.tsv");
    ok(&s, &[&cfg[..], &["round", "export", "ra", "--out", out.to_str().unwrap()]].concat());
    assert_eq!(std::fs::read_to_string(&out).unwrap(), std::fs::read_to_string(&a).unwrap());
    let dup = run(&s, &[&cfg[..], &["round", "import", "ra", "--verdicts", a.to_str().unwrap()]].concat());
    assert_eq!(dup.code, 3, "rounds are never overwritten: {}", dup.stderr);
    let _ = std::fs::remove_dir_all(&s);
}

#[test]
fn verify_and_emit_all_on_a_watcom_program() {
    let s = scratch("watcom-verify");
    ok(&s, &["add", corpus("watcom_hello.exe").to_str().unwrap()]);
    ok(&s, &["analyze", "--loader", "le"]);
    let junk = s.join("junk.obj");
    std::fs::write(&junk, b"not an object at all").unwrap();
    let v = ok(&s, &["--format", "tsv", "verify", "0x10088", junk.to_str().unwrap()]);
    assert!(v.contains("\tOBJ_ERROR\t"), "{v}");
    // emit --all --out: the emission in one operation, files by emit index
    let out = s.join("tree");
    let o = run(&s, &["emit", "--all", "--out", out.to_str().unwrap()]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let files: Vec<_> = std::fs::read_dir(&out).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert!(files.len() >= 10 && files.iter().all(|f| f.len() == 7 && f.ends_with(".c")), "{files:?}");
    assert!(files.contains(&"00000.c".to_string()));
    let report = ok(&s, &["--format", "tsv", "emit", "--all", "--report"]);
    assert!(report.starts_with("idx\tva\tname\tstatus\t"), "{}", &report[..60.min(report.len())]);
    let _ = std::fs::remove_dir_all(&s);
}
