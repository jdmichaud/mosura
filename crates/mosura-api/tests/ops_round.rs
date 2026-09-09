//! The recompile side of the operations: the toolchain registry and opening (no compiler run),
//! and `program.emit` — the whole recovered emission with the caller-side post-pass — equal to
//! the survey's live EmitState + patch_caller, byte for byte.

use std::collections::HashMap;

use mosura_api::ops::{dispatch, NoProgress};
use mosura_api::{Context, ContextConfig, Error, Format, Options, Session, SetKind};
use mosura_core::analysis;
use mosura_core::analysis::interface::{install_prototypes, mark_tail_return_writes};
use mosura_core::recompile::passes::{Entries, GlobalWidths, ParamOrders, Worlds};
use mosura_core::recompile::pragma::WatcomRegs;
use mosura_core::recompile::round::{EmitOpts, EmitState, ProgramFacts};
use mosura_core::switches::{Knobs, Switch};

const LANG: &str = "x86:LE:32:default";

fn ctx() -> Context {
    Context::new(ContextConfig::default()).unwrap()
}

fn corpus(name: &str) -> std::path::PathBuf {
    mosura_core::paths::analysis_corpus_dir().join(name)
}

fn opts(pairs: &[(&str, &str)]) -> Options {
    let mut o = Options::new();
    for (k, v) in pairs {
        o.set(k, v).unwrap();
    }
    o
}

fn scratch(name: &str) -> std::path::PathBuf {
    let d = mosura_core::paths::workspace_root().join("target").join("api-test-sessions").join(name);
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn toolchain_specs_and_open_without_running_anything() {
    let c = ctx();
    let mut mem = Session::open(None).unwrap();
    let specs = dispatch(&c, &mut mem, "toolchain.specs", &Options::new(), &mut NoProgress).unwrap();
    assert_eq!(specs.rows(), 3);
    let names: Vec<&str> = (0..3).map(|r| specs.str(r, 0).unwrap()).collect();
    assert_eq!(names, ["watcom-10.0a-dos", "open-watcom-2-native", "gcc-native"]);
    // a toolchain needs a session directory (its work files)
    let o = opts(&[("toolchain", "cc"), ("toolchain.spec", "gcc-native"), ("toolchain.install", "cc")]);
    assert!(matches!(dispatch(&c, &mut mem, "toolchain.open", &o, &mut NoProgress), Err(Error::Unsupported(_))));
    let dir = scratch("toolchain");
    let mut s = Session::open(Some(&dir)).unwrap();
    let t = dispatch(&c, &mut s, "toolchain.open", &o, &mut NoProgress).unwrap();
    assert_eq!(t.rows(), 1);
    assert_eq!((t.str(0, 0).unwrap(), t.str(0, 1).unwrap()), ("cc", "gcc-native"));
    assert!(t.str(0, 2).unwrap().starts_with("gcc-native-"), "the driver id: {}", t.str(0, 2).unwrap());
    assert!(t.str(0, 4).unwrap().ends_with("/compile"), "the default cache under the session: {}", t.str(0, 4).unwrap());
    assert!(dir.join("compile").is_dir() && dir.join("tmp").is_dir());
    let listed = dispatch(&c, &mut s, "toolchain.list", &Options::new(), &mut NoProgress).unwrap();
    assert_eq!(listed.rows(), 1);
    let bad = opts(&[("toolchain", "x"), ("toolchain.spec", "nope"), ("toolchain.install", "cc")]);
    assert!(matches!(dispatch(&c, &mut s, "toolchain.open", &bad, &mut NoProgress), Err(Error::NotFound(_))));
    let missing = opts(&[("toolchain", "x"), ("toolchain.spec", "gcc-native")]);
    assert!(matches!(dispatch(&c, &mut s, "toolchain.open", &missing, &mut NoProgress), Err(Error::InvalidArg(_))));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The survey's live emission over watcom_hello.exe: every entry through `EmitState`, then the
/// caller-side pragma post-pass — what `recovered/` held.
fn live_emission() -> Vec<(usize, u64, String, Option<String>)> {
    let knobs = Knobs::default();
    let mut prog = analysis::analyze_file_with(&corpus("watcom_hello.exe"), &knobs).unwrap();
    prog.global_scope_all_loaded = false;
    let _ = mark_tail_return_writes(&mut prog, LANG, &[]);
    let _ = install_prototypes(&mut prog, None);
    let worlds = Worlds::split(prog);
    let regs = WatcomRegs::for_lang(LANG);
    let ents = Entries::of(&worlds.landed);
    let orders = ParamOrders::collect(&worlds.landed, LANG, &ents, &regs).unwrap_or_default();
    let widths = if knobs.on(Switch::GlobalWidth) { GlobalWidths::collect(&worlds.landed, LANG, &ents) } else { GlobalWidths { store_w: HashMap::new(), read_w: HashMap::new() } };
    let (arm, rec) = mosura_core::recompile::recovery::measured_arms();
    let entries = ents.list.clone();
    let mut st = EmitState::new(ProgramFacts { lang: LANG, knobs, worlds, entries: ents, regs, orders, widths }, EmitOpts { arms: vec![arm], rec_arm: rec, arms_off: vec![], recovered: true, cons_probe: false });
    mosura_core::decompile::structure::set_force_loop_overflow(true);
    let mut out: Vec<(usize, u64, String, Option<String>)> = entries.iter().enumerate().map(|(i, (va, n))| (i, *va, n.clone(), st.emit_function(i, *va, n).ok().map(|e| e.recovered_tu.unwrap_or(e.reference_tu)))).collect();
    mosura_core::decompile::structure::set_force_loop_overflow(false);
    for (_, va, _, tu) in out.iter_mut() {
        if let Some(t) = tu {
            if let Some(p) = st.contracts.patch_caller(t, Some(*va)) {
                *t = p;
            }
        }
    }
    out
}

#[test]
fn program_emit_equals_the_live_emission_after_the_post_pass() {
    let c = ctx();
    let live = live_emission();
    let mut s = Session::open(None).unwrap();
    s.add_input(&std::fs::read(corpus("watcom_hello.exe")).unwrap(), "watcom_hello.exe", None).unwrap();
    dispatch(&c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
    s.last_program = None;
    let before = s.set_keys(SetKind::Program).unwrap().len();
    // no options: the emission defaults to the standalone scope the survey used
    let em = dispatch(&c, &mut s, "program.emit", &Options::new(), &mut NoProgress).unwrap();
    assert_eq!(em.rows() as usize, live.len(), "one row per emit entry");
    let mut ok = 0;
    for (r, (idx, va, name, tu)) in live.iter().enumerate() {
        let r = r as u64;
        assert_eq!(em.u64(r, 0).unwrap() as usize, *idx);
        assert_eq!(em.u64(r, 1).unwrap(), *va);
        assert_eq!(em.str(r, 2).unwrap(), name);
        match tu {
            Some(t) => {
                assert_eq!(em.str(r, 3).unwrap(), "OK");
                assert_eq!(em.str(r, 6).unwrap(), t, "{name}: TU after the post-pass");
                ok += 1;
            }
            None => assert_eq!(em.str(r, 3).unwrap(), "DECOMPILE_FAIL"),
        }
        assert!(em.str(r, 7).unwrap().starts_with(&format!("{idx:05}\t")), "the manifest row");
    }
    assert!(ok >= 10, "{ok} TUs");
    assert_eq!(s.set_keys(SetKind::Program).unwrap().len(), before + 2, "the passes set and the emission set");
    // served on the second call; the arms stamp is recorded
    let again = dispatch(&c, &mut s, "program.emit", &Options::new(), &mut NoProgress).unwrap();
    assert_eq!(mosura_api::render(&again, Format::Tsv).unwrap(), mosura_api::render(&em, Format::Tsv).unwrap());
    assert_eq!(s.set_keys(SetKind::Program).unwrap().len(), before + 2);
    let (_, rec) = mosura_core::recompile::recovery::measured_arms();
    let want_arms = mosura_core::recompile::manifest::arms_stamp(&rec, &[], &Knobs::default());
    let sets = s.set_keys(SetKind::Program).unwrap();
    let arms = sets.iter().filter_map(|k| s.read_set(SetKind::Program, k).ok()).find_map(|set| set.table("arms").ok().map(|t| t.str(0, 0).unwrap().to_string())).expect("the emission set carries the arms stamp");
    assert_eq!(arms, want_arms);
    assert!(want_arms.starts_with("return-width=recovered,"), "{want_arms}");
    // an explicit application scope is another options tag: its own passes set and emission
    let app = dispatch(&c, &mut s, "program.emit", &opts(&[("decompile.global-scope", "application")]), &mut NoProgress).unwrap();
    assert_eq!(s.set_keys(SetKind::Program).unwrap().len(), before + 4);
    assert_eq!(app.rows(), em.rows());
}

// ── the round store: import, compare, export, gates, list, show; buildconfig ──

const LEGACY_A: &str = "idx\tva\tname\tverdict\tbytes\tprimary\tsim\tequal\torig_n\tcand_n\tclasses\tSIM=structural
00000\t00010010\tFUN_00010010\tMISMATCH\tDifferent\textra\t0.043\t2\t25\t46\tregalloc=2,extra=21
00001\t00010063\tFUN_00010063\tEXACT\tIdentical\t\t1.000\t29\t29\t29\t
00002\t000100a0\tFUN_000100a0\tSAME_SHAPE\tDifferent\tregalloc\t0.800\t8\t10\t10\tregalloc=2
00003\t000100f0\tFUN_000100f0\tCOMPILE_FAIL\t\t\t\t0\t12\t0\t
";
const LEGACY_B: &str = "idx\tva\tname\tverdict\tbytes\tprimary\tsim\tequal\torig_n\tcand_n\tclasses\tSIM=structural
00000\t00010010\tFUN_00010010\tMISMATCH\tDifferent\textra\t0.043\t2\t25\t46\tregalloc=2,extra=21
00001\t00010063\tFUN_00010063\tEXACT\tIdentical\t\t1.000\t29\t29\t29\t
00002\t000100a0\tFUN_000100a0\tEXACT\tIdentical\t\t1.000\t10\t10\t10\t
00004\t00010200\tFUN_00010200\tMISMATCH\tDifferent\tselection\t0.500\t5\t10\t10\tselection=5
";
const LEGACY_DIV: &str = "idx\tfn_va\tclass\taddr\toi\tci\torig_n\tcand_n\torig_mn\tcand_mn\torig_regs\tcand_regs\torig_text\tcand_text
00000\t00010010\textra\t00010010\t-1\t0\t25\t46\t\tPUSH\t\t20:4,16:4\t\tPUSH EBP
00002\t000100a0\tregalloc\t000100a4\t2\t2\t10\t10\tMOV\tMOV\t0:4\t8:4\tMOV EAX,0x1\tMOV EDX,0x1
";
const GATES_FILE: &str = "# gate\tkey\trule\tvalue\tset_at
gate\tkey\trule\tvalue\tset_at
guard_frame\t00010063\tEXACT\t\ttest
guard_frame\t000100a0\tEXACT\t\ttest
";

fn write(dir: &std::path::Path, name: &str, text: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, text).unwrap();
    p.to_string_lossy().into_owned()
}

#[test]
fn rounds_import_compare_export_gates_list_show() {
    let c = ctx();
    let dir = scratch("rounds");
    std::fs::create_dir_all(&dir).unwrap();
    let mut s = Session::open(Some(&dir)).unwrap();
    let a = write(&dir, "a-rec.tsv", LEGACY_A);
    let b = write(&dir, "b-rec.tsv", LEGACY_B);
    let d = write(&dir, "a-div.tsv", LEGACY_DIV);
    let m = write(&dir, "manifest.tsv", "# corpus_emit emit @ deadbee\n# arms: return-width=recovered,shift-mask=hardware; off: cmp_sign\nidx\tva\n");
    let g = write(&dir, "corpus-gates.tsv", GATES_FILE);
    let ma = dispatch(&c, &mut s, "round.import", &opts(&[("round", "a"), ("verdicts", &a), ("divergences", &d), ("manifest", &m), ("label", "the baseline")]), &mut NoProgress).unwrap();
    let value = |t: &mosura_api::Table, kind: &str, name: &str| -> String { (0..t.rows()).find(|&r| t.str(r, 0).unwrap() == kind && (name.is_empty() || t.str(r, 1).unwrap() == name)).map(|r| t.str(r, 2).unwrap().to_string()).unwrap_or_default() };
    assert_eq!(value(&ma, "arms", ""), "return-width=recovered,shift-mask=hardware; off: cmp_sign");
    assert_eq!(value(&ma, "census", "EXACT"), "1");
    assert_eq!(value(&ma, "rows", ""), "4");
    assert_eq!(value(&ma, "sim", ""), "structural");
    // WGSS = Σ orig_n·sim / Σ orig_n = (25·0.043 + 29·1 + 10·0.8 + 12·0) / 76
    let want = (25.0 * 0.043 + 29.0 + 8.0) / 76.0;
    assert_eq!(value(&ma, "wgss", "structural"), format!("{want:.4}"));
    dispatch(&c, &mut s, "round.import", &opts(&[("round", "b"), ("verdicts", &b)]), &mut NoProgress).unwrap();
    assert!(matches!(dispatch(&c, &mut s, "round.import", &opts(&[("round", "b"), ("verdicts", &b)]), &mut NoProgress), Err(Error::InvalidArg(_))), "a round is never overwritten");
    // list + show
    let list = dispatch(&c, &mut s, "round.list", &Options::new(), &mut NoProgress).unwrap();
    assert_eq!(list.rows(), 2);
    assert_eq!((list.str(0, 0).unwrap(), list.u64(0, 5).unwrap(), list.u64(0, 6).unwrap()), ("a", 4, 1));
    let verdicts = dispatch(&c, &mut s, "round.show", &opts(&[("round", "a"), ("table", "verdicts")]), &mut NoProgress).unwrap();
    assert_eq!(verdicts.rows(), 4);
    assert_eq!(verdicts.str(3, 3).unwrap(), "COMPILE_FAIL");
    let divs = dispatch(&c, &mut s, "round.show", &opts(&[("round", "a"), ("table", "divergences")]), &mut NoProgress).unwrap();
    assert_eq!(divs.rows(), 2);
    assert_eq!(divs.i64(0, 4).unwrap(), -1);
    assert!(matches!(dispatch(&c, &mut s, "round.show", &opts(&[("round", "nope")]), &mut NoProgress), Err(Error::NotFound(_))));
    // compare a → b: one flip (000100a0 SAME_SHAPE → EXACT), one mover, membership drift both ways
    let cmp = dispatch(&c, &mut s, "round.compare", &opts(&[("a", "a"), ("b", "b")]), &mut NoProgress).unwrap();
    let rows: Vec<(String, String, String, String, String)> = (0..cmp.rows()).map(|r| (cmp.str(r, 0).unwrap().into(), cmp.str(r, 2).unwrap().into(), cmp.str(r, 3).unwrap().into(), cmp.str(r, 4).unwrap().into(), cmp.str(r, 5).unwrap().into())).collect();
    let flips: Vec<_> = rows.iter().filter(|r| r.0 == "flip").collect();
    assert_eq!(flips.len(), 1, "{rows:?}");
    assert_eq!((flips[0].1.as_str(), flips[0].2.as_str(), flips[0].3.as_str()), ("FUN_000100a0", "SAME_SHAPE", "EXACT"));
    assert_eq!(rows.iter().filter(|r| r.0 == "move").count(), 1);
    assert!(rows.iter().any(|r| r.0 == "summary" && r.1 == "flips" && r.2 == "1"));
    assert!(rows.iter().any(|r| r.0 == "summary" && r.1 == "membership" && r.2 == "1 only in a" && r.3 == "1 only in b"), "{rows:?}");
    // the weighted delta: the mover gained 0.2 × 10 insns over the 64 instructions of the rows
    // both rounds hold (the script's rule: weights over the common rows only)
    let wd = rows.iter().find(|r| r.0 == "summary" && r.1 == "wgss-delta").unwrap();
    assert_eq!(wd.2, format!("{:+.5}", 2.0 / 64.0));
    // gates: guard sets vs the file, regressions vs the baseline round
    let gates = dispatch(&c, &mut s, "round.gates", &opts(&[("round", "a"), ("gates.baseline", &g)]), &mut NoProgress).unwrap();
    let g7 = (0..gates.rows()).find(|&r| gates.str(r, 0).unwrap().starts_with("7 ")).unwrap();
    assert_eq!(gates.str(g7, 1).unwrap(), "FAIL", "000100a0 is SAME_SHAPE in a, the guard wants EXACT: {}", gates.str(g7, 2).unwrap());
    let gates_b = dispatch(&c, &mut s, "round.gates", &opts(&[("round", "b"), ("gates.baseline", &g), ("round.baseline", "a")]), &mut NoProgress).unwrap();
    for r in 0..gates_b.rows() {
        assert_eq!(gates_b.str(r, 1).unwrap(), "OK", "{}: {}", gates_b.str(r, 0).unwrap(), gates_b.str(r, 2).unwrap());
    }
    let gates_rev = dispatch(&c, &mut s, "round.gates", &opts(&[("round", "a"), ("round.baseline", "b")]), &mut NoProgress).unwrap();
    let g8 = (0..gates_rev.rows()).find(|&r| gates_rev.str(r, 0).unwrap().starts_with("8 ")).unwrap();
    assert_eq!(gates_rev.str(g8, 1).unwrap(), "FAIL", "an EXACT lost from b to a");
    // the smoke-drift gate
    let expect = write(&dir, "smoke.expected.tsv", "# idx\tva\tname\texpected\n00001\t00010063\tFUN_00010063\tEXACT\n00002\t000100a0\tFUN_000100a0\tEXACT\n");
    let smoke = dispatch(&c, &mut s, "round.gates", &opts(&[("round", "a"), ("round.expect", &expect)]), &mut NoProgress).unwrap();
    let g9 = (0..smoke.rows()).find(|&r| smoke.str(r, 0).unwrap().starts_with("9 ")).unwrap();
    assert!(smoke.str(g9, 1).unwrap() == "FAIL" && smoke.str(g9, 2).unwrap().contains("expected EXACT got SAME_SHAPE"), "{}", smoke.str(g9, 2).unwrap());
    // export round-trips the legacy files byte for byte
    let out = dir.join("a-export.tsv");
    let dout = dir.join("a-export-div.tsv");
    dispatch(&c, &mut s, "round.export", &opts(&[("round", "a"), ("out", out.to_str().unwrap()), ("divergences", dout.to_str().unwrap())]), &mut NoProgress).unwrap();
    assert_eq!(std::fs::read_to_string(&out).unwrap(), LEGACY_A);
    assert_eq!(std::fs::read_to_string(&dout).unwrap(), LEGACY_DIV);
    assert!(matches!(dispatch(&c, &mut s, "round.export", &opts(&[("round", "a")]), &mut NoProgress), Err(Error::InvalidArg(_))));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn buildconfig_reads_the_originals_prologue() {
    let c = ctx();
    let mut s = Session::open(None).unwrap();
    s.add_input(&std::fs::read(corpus("watcom_hello.exe")).unwrap(), "watcom_hello.exe", None).unwrap();
    dispatch(&c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
    let fns = dispatch(&c, &mut s, "program.tables", &opts(&[("table", "functions")]), &mut NoProgress).unwrap();
    let entry = fns.u64(0, 1).unwrap();
    let t = dispatch(&c, &mut s, "function.buildconfig", &opts(&[("entry", &format!("{entry:#x}"))]), &mut NoProgress).unwrap();
    let kinds: Vec<(String, String)> = (0..t.rows()).map(|r| (t.str(r, 0).unwrap().into(), t.str(r, 1).unwrap().into())).collect();
    assert!(kinds.iter().any(|(k, n)| k == "flag" && n == "-5r"), "{kinds:?}");
    assert!(kinds.iter().any(|(k, n)| k == "profile" && n == "watcom-10.0a"));
    // a toolchain is needed for recompile; verify needs an object input
    assert!(matches!(dispatch(&c, &mut s, "function.recompile", &opts(&[("entry", &format!("{entry:#x}"))]), &mut NoProgress), Err(Error::NotFound(_))));
    assert!(matches!(dispatch(&c, &mut s, "function.verify", &opts(&[("entry", &format!("{entry:#x}"))]), &mut NoProgress), Err(Error::InvalidArg(_))));
    assert!(matches!(dispatch(&c, &mut s, "round.run", &opts(&[("round", "r1")]), &mut NoProgress), Err(Error::NotFound(_))), "no toolchain open");
}
