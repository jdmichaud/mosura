//! `function.decompile`: the thawed program decompiles exactly as the live one (C and raw IR,
//! every function of three binaries), the set is served on the second call, an `emit.*` key is a
//! different key, the fact tables agree with the Funcdata, bad entries and formats are refused.

use mosura_api::ops::{dispatch, NoProgress};
use mosura_api::{Context, ContextConfig, Error, Format, Options, Session, SetKind};
use mosura_core::analysis;
use mosura_core::analysis::decompiler::decompile_function;
use mosura_core::decompile::printc::print_c;
use mosura_core::switches::Knobs;

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

#[test]
fn a_thawed_decompile_is_the_live_one_for_every_function() {
    let c = ctx();
    for name in ["basic.elf", "switchtab.elf", "watcom_hello.exe"] {
        let live = analysis::analyze_file_with(&corpus(name), &Knobs::default()).unwrap();
        let mut s = Session::open(None).unwrap();
        s.add_input(&std::fs::read(corpus(name)).unwrap(), name, None).unwrap();
        dispatch(&c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
        // force the function ops to THAW (the analyze call cached the live program)
        s.last_program = None;
        let mut checked = 0;
        for f in live.function_manager.functions() {
            let entry = f.entry_point();
            let Some(lf) = decompile_function(&live, entry) else { continue };
            let want_c = print_c(&lf);
            let want_raw = lf.print_raw();
            let e = format!("{:#x}", entry.offset);
            let got_c = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e)]), &mut NoProgress).unwrap_or_else(|err| panic!("{name} {e}: {err:?}"));
            assert_eq!(text(&got_c), want_c, "{name} {e}: C");
            let got_raw = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e), ("format", "raw")]), &mut NoProgress).unwrap();
            assert_eq!(text(&got_raw), want_raw, "{name} {e}: raw IR");
            // the fact tables agree with the Funcdata
            let calls = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e), ("format", "table:calls")]), &mut NoProgress).unwrap();
            let live_calls = lf.op_ids().filter(|&id| !lf.op(id).is_dead() && matches!(lf.op(id).code(), mosura_core::decompile::opcode::OpCode::Call | mosura_core::decompile::opcode::OpCode::Callind)).count();
            assert_eq!(calls.rows() as usize, live_calls, "{name} {e}: calls");
            let jts = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e), ("format", "table:jumptables")]), &mut NoProgress).unwrap();
            let live_targets: usize = lf.jumptables.iter().map(|j| j.targets.len() + j.default.filter(|d| !j.targets.contains(d)).map(|_| 1).unwrap_or(0)).sum();
            assert_eq!(jts.rows() as usize, live_targets, "{name} {e}: jump-table rows");
            let proto = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e), ("format", "table:prototype")]), &mut NoProgress).unwrap();
            let lp = mosura_core::analysis::interface::prototype_of(&lf);
            assert_eq!(proto.rows() as usize, lp.params.len() + lp.output.is_some() as usize, "{name} {e}: prototype rows");
            checked += 1;
        }
        assert!(checked >= 3, "{name}: {checked} functions checked");
        // one set per function (all formats read the same set)
        assert_eq!(s.set_keys(SetKind::Function).unwrap().len(), checked, "{name}: function sets");
    }
}

#[test]
fn the_set_is_served_and_an_emit_key_is_another_key() {
    let c = ctx();
    let live = analysis::analyze_file_with(&corpus("switchtab.elf"), &Knobs::default()).unwrap();
    let mut s = Session::open(None).unwrap();
    s.add_input(&std::fs::read(corpus("switchtab.elf")).unwrap(), "switchtab.elf", None).unwrap();
    dispatch(&c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
    // the function with a jump table
    let (entry, lf) = live
        .function_manager
        .functions()
        .filter_map(|f| decompile_function(&live, f.entry_point()).map(|lf| (f.entry_point().offset, lf)))
        .find(|(_, lf)| !lf.jumptables.is_empty())
        .expect("switchtab has a switch");
    let e = format!("{entry:#x}");
    let t1 = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e)]), &mut NoProgress).unwrap();
    assert_eq!(s.set_keys(SetKind::Function).unwrap().len(), 1);
    let t2 = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e)]), &mut NoProgress).unwrap();
    assert_eq!(text(&t1), text(&t2));
    assert_eq!(s.set_keys(SetKind::Function).unwrap().len(), 1, "served from the set");
    let jt = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e), ("format", "table:jumptables")]), &mut NoProgress).unwrap();
    assert_eq!(jt.u64(0, 0).unwrap(), lf.jumptables[0].op_addr);
    assert_eq!(jt.u64(0, 2).unwrap(), lf.jumptables[0].targets[0]);
    // an emit axis: a second key (and the Ghidra-faithful default is what `print_c` prints)
    let t3 = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e), ("emit.arm-order", "address")]), &mut NoProgress).unwrap();
    assert_eq!(s.set_keys(SetKind::Function).unwrap().len(), 2, "another options tag, another set");
    let _ = t3;
    // refusals (a name is the front-end's to resolve: the key is typed Hex by the registry)
    assert!(matches!(dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", "0x1")]), &mut NoProgress), Err(Error::NotFound(_))));
    assert!(matches!(Options::new().set("entry", "nosuchfn"), Err(Error::InvalidArg(_))));
    assert!(matches!(dispatch(&c, &mut s, "function.decompile", &Options::new(), &mut NoProgress), Err(Error::InvalidArg(_))));
    assert!(matches!(dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e), ("format", "pdf")]), &mut NoProgress), Err(Error::InvalidArg(_))));
    assert!(matches!(dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e), ("emit.arms-off", "cmp_sign")]), &mut NoProgress), Err(Error::InvalidArg(_))), "arms-off belongs to function.emit");
}
