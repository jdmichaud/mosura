//! `program.passes` and `function.emit`: the passes set round-trips the prototype-pass world, the
//! emitted translation unit of a thawed program equals the live EmitState's, `emit.arms-off`
//! changes the key, a non-x86-32 program is refused.

use std::collections::HashMap;

use mosura_api::ops::{dispatch, NoProgress};
use mosura_api::program::freeze;
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

fn text(t: &mosura_api::Table) -> String {
    mosura_api::render::render(t, Format::Text).unwrap()
}

/// The survey's live pass-1 world and emit state over watcom_hello.exe, standalone scope.
fn live_state() -> (mosura_core::analysis::program::Program, EmitState) {
    let knobs = Knobs::default();
    let mut prog = analysis::analyze_file_with(&corpus("watcom_hello.exe"), &knobs).unwrap();
    prog.global_scope_all_loaded = false;
    let _ = mark_tail_return_writes(&mut prog, LANG, &[]);
    let _ = install_prototypes(&mut prog, None);
    let pp = prog.clone();
    let worlds = Worlds::split(prog);
    let regs = WatcomRegs::for_lang(LANG);
    let ents = Entries::of(&worlds.landed);
    let orders = ParamOrders::collect(&worlds.landed, LANG, &ents, &regs).unwrap_or_default();
    let widths = if knobs.on(Switch::GlobalWidth) { GlobalWidths::collect(&worlds.landed, LANG, &ents) } else { GlobalWidths { store_w: HashMap::new(), read_w: HashMap::new() } };
    let (arm, rec) = mosura_core::recompile::recovery::measured_arms();
    let st = EmitState::new(ProgramFacts { lang: LANG, knobs, worlds, entries: ents, regs, orders, widths }, EmitOpts { arms: vec![arm], rec_arm: rec, arms_off: vec![], recovered: true, cons_probe: false, caller_parm_witnessed: false });
    (pp, st)
}

#[test]
fn passes_round_trip_and_emit_equals_the_live_state() {
    let c = ctx();
    let (live_pp, mut live) = live_state();
    let mut s = Session::open(None).unwrap();
    s.add_input(&std::fs::read(corpus("watcom_hello.exe")).unwrap(), "watcom_hello.exe", None).unwrap();
    dispatch(&c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
    let o = opts(&[("decompile.global-scope", "standalone")]);
    s.last_program = None; // thaw from the tables from here on
    let before = s.set_keys(SetKind::Program).unwrap().len();
    let summary = dispatch(&c, &mut s, "program.passes", &o, &mut NoProgress).unwrap();
    assert_eq!(s.set_keys(SetKind::Program).unwrap().len(), before + 1, "the passes set");
    assert_eq!(summary.str(0, 1).unwrap(), LANG);
    // the passes set's prototype tables equal a freeze of the live pass-1 world
    let pk = mosura_api::key::Key::from_hex(summary.str(0, 0).unwrap()).unwrap();
    let stored = s.read_set(SetKind::Program, &pk).unwrap();
    let fresh = freeze(&live_pp, "decompile.global-scope=standalone");
    for t in ["protos", "proto_slots", "proto_models", "param_lists", "param_entries", "sret_facts", "sret_fields", "sret_callers", "facts", "functions"] {
        assert_eq!(stored.tables[t].digest(), fresh.tables[t].digest(), "passes set table {t}");
    }
    assert!(stored.tables.contains_key("param_orders") && stored.tables.contains_key("global_widths"));
    // served on the second call
    let again = dispatch(&c, &mut s, "program.passes", &o, &mut NoProgress).unwrap();
    assert_eq!(text(&again), text(&summary));
    assert_eq!(s.set_keys(SetKind::Program).unwrap().len(), before + 1);
    // function.emit: the recovered TU of a thawed program equals the live EmitState's, for the
    // first five emit entries (the same thread-local render flag around both)
    let entries: Vec<(usize, u64, String)> = live.facts.entries.list.iter().enumerate().take(5).map(|(i, (va, n))| (i, *va, n.clone())).collect();
    assert_eq!(entries.len(), 5);
    let mut emitted = 0;
    for (idx, va, name) in &entries {
        mosura_core::decompile::structure::set_force_loop_overflow(true);
        let want = live.emit_function(*idx, *va, name);
        mosura_core::decompile::structure::set_force_loop_overflow(false);
        let e = format!("{va:#x}");
        let mut eo = o.clone();
        eo.set("entry", &e).unwrap();
        match want {
            Ok(w) => {
                let got = dispatch(&c, &mut s, "function.emit", &eo, &mut NoProgress).unwrap_or_else(|err| panic!("{e}: {err:?}"));
                assert_eq!(text(&got), w.recovered_tu.clone().unwrap_or(w.reference_tu.clone()) + if w.recovered_tu.as_deref().unwrap_or(&w.reference_tu).ends_with('\n') { "" } else { "\n" }, "{e}: recovered TU");
                eo.set("format", "c").unwrap();
                let got_c = dispatch(&c, &mut s, "function.emit", &eo, &mut NoProgress).unwrap();
                assert_eq!(text(&got_c).trim_end(), w.reference_c.trim_end(), "{e}: reference C");
                eo.set("format", "table:report").unwrap();
                let rep = dispatch(&c, &mut s, "function.emit", &eo, &mut NoProgress).unwrap();
                let row = (0..rep.rows()).find(|&r| rep.str(r, 0).unwrap() == "row").map(|r| rep.str(r, 1).unwrap().to_string()).unwrap();
                assert_eq!(row, w.row.render(), "{e}: manifest row");
                emitted += 1;
            }
            Err(_) => {
                assert!(matches!(dispatch(&c, &mut s, "function.emit", &eo, &mut NoProgress), Err(Error::Internal(_))), "{e}: a failed decompile is Internal");
            }
        }
    }
    assert!(emitted >= 3, "{emitted} functions emitted");
    let fsets = s.set_keys(SetKind::Function).unwrap().len();
    assert_eq!(fsets, emitted, "one function set per emitted function");
    // an arm switched off is another key; the switch half of the name space goes through knobs.off
    let (_, va, _) = &entries[0];
    let mut eo = o.clone();
    eo.set("entry", &format!("{va:#x}")).unwrap();
    eo.set("emit.arms-off", "cmp_sign").unwrap();
    dispatch(&c, &mut s, "function.emit", &eo, &mut NoProgress).unwrap();
    assert_eq!(s.set_keys(SetKind::Function).unwrap().len(), fsets + 1);
    assert!(matches!(dispatch(&c, &mut s, "function.emit", &opts(&[("entry", &format!("{va:#x}")), ("format", "pdf")]), &mut NoProgress), Err(Error::InvalidArg(_))));
}

#[test]
fn another_language_is_unsupported() {
    let c = ctx();
    let mut s = Session::open(None).unwrap();
    s.add_input(&std::fs::read(corpus("basic.elf")).unwrap(), "basic.elf", None).unwrap();
    dispatch(&c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
    assert!(matches!(dispatch(&c, &mut s, "program.passes", &Options::new(), &mut NoProgress), Err(Error::Unsupported(_))));
    assert!(matches!(dispatch(&c, &mut s, "function.emit", &opts(&[("entry", "0x1000")]), &mut NoProgress), Err(Error::Unsupported(_))));
}
