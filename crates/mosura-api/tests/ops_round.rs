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
