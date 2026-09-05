//! The binding end to end: identify → an in-memory session → add an input → open → analyze →
//! the functions table → decompile the first entry → C; the error carries the registry's doc;
//! progress and log callbacks; a Watcom TU; the session may be dropped before its program.

use mosura::{Ctx, CtxConfig, Format, Options, Session, Status};

fn corpus(name: &str) -> Vec<u8> {
    std::fs::read(mosura_core_paths::corpus_dir().join(name)).unwrap()
}

/// The analysis corpus lives at `oracle/analysis-corpus` under the workspace root (this test
/// runs in the binding crate, two directories below it).
mod mosura_core_paths {
    use std::path::{Path, PathBuf};
    pub fn corpus_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2).unwrap().join("oracle/analysis-corpus")
    }
}

#[test]
fn identify_open_analyze_decompile() {
    assert_eq!(mosura::abi_version(), 1);
    assert!(mosura::version().starts_with("0.1.0"));
    let ctx = Ctx::new(CtxConfig::default()).unwrap();
    let bytes = corpus("basic.elf");
    let id = ctx.identify(&bytes).unwrap();
    let lang = (0..id.rows()).find(|&r| id.str(r, 0).unwrap() == "language").map(|r| id.str(r, 1).unwrap().to_string()).unwrap();
    assert_eq!(lang, "x86:LE:64:default");
    let mut s = Session::open(&ctx, None, None).unwrap();
    let digest = s.add_input(&bytes, "basic.elf").unwrap();
    assert_eq!(digest.len(), 64);
    assert_eq!(s.inputs().unwrap().rows(), 1);
    let mut p = s.program_open(None, None).unwrap();
    let k1 = p.key().unwrap();
    let mut reports = 0u32;
    p.analyze(None, Some(&mut |_stage: &str, _d: u64, _t: u64| {
        reports += 1;
        true
    }))
    .unwrap();
    assert!(reports >= 2, "{reports} progress reports");
    let k2 = p.key().unwrap();
    assert_ne!(k1, k2);
    let fns = p.table("functions").unwrap();
    let (name, version, ncols) = fns.schema().unwrap();
    assert_eq!((name.as_str(), version, ncols), ("functions", 1, 3));
    assert!(fns.rows() >= 13);
    assert_eq!(fns.column_index("entry").unwrap(), 1);
    assert_eq!(fns.column_info(2).unwrap().1, mosura::ColType::MOSURA_COL_STR);
    let main_row = (0..fns.rows()).find(|&r| fns.str(r, 2).unwrap() == "main").expect("main");
    let entry = fns.u64(main_row, 1).unwrap();
    let head = p.read(entry, 4).unwrap();
    assert_eq!(head.len(), 4);
    assert!(p.read(1, 4).is_err());
    let dis = p.disassemble(entry, 8).unwrap();
    assert!(dis.rows() >= 1);
    assert_eq!(&dis.bytes(0, 2).unwrap()[..1], &head[..1]);
    assert!(p.snapshot().unwrap().starts_with("# mosura-analysis-snapshot v1"));
    let e = p.annotate("name", entry, "x").unwrap_err();
    assert_eq!(e.status, Status::MOSURA_ERR_UNSUPPORTED);
    // the session can go first: the program keeps its own reference
    drop(s);
    let f = p.decompile(entry, None).unwrap();
    let c = f.c().unwrap();
    assert!(c.contains(&format!("FUN_{entry:08x}")), "{c}");
    let raw = f.ir("post", Format::MOSURA_FMT_TEXT).unwrap();
    assert!(!raw.is_empty());
    assert_eq!(f.ir("pre", Format::MOSURA_FMT_TEXT).unwrap_err().status, Status::MOSURA_ERR_UNSUPPORTED);
    let calls = f.table("calls").unwrap();
    assert_eq!(calls.schema().unwrap().0, "calls");
    let choices = ctx.options().unwrap().with("emit.arm-order", "address").unwrap();
    assert!(f.render(&choices).unwrap().contains("FUN_"));
    assert_eq!(f.tu(None).unwrap_err().status, Status::MOSURA_ERR_UNSUPPORTED, "x86-64: no Watcom emitter");
    // tables round-trip through the .tbl image
    let img = fns.serialize().unwrap();
    let back = mosura::Table::open(&ctx, &img).unwrap();
    assert_eq!(back.render(Format::MOSURA_FMT_JSON).unwrap(), fns.render(Format::MOSURA_FMT_JSON).unwrap());
}

#[test]
fn errors_carry_the_registry_doc_and_the_registries_are_tables() {
    let ctx = Ctx::new(CtxConfig::default()).unwrap();
    let mut o: Options = ctx.options().unwrap();
    let e = o.set("load.loader", "sideways").unwrap_err();
    assert_eq!(e.status, Status::MOSURA_ERR_INVALID_ARG);
    assert!(e.message.contains("load.loader:") && e.message.contains("which loader"), "{}", e.message);
    assert!(o.set("no.such", "1").unwrap_err().message.contains("unknown option key"));
    o.set("load.loader", "le").unwrap();
    assert_eq!(o.get("load.loader").unwrap(), "le");
    assert_eq!(o.tag().unwrap(), "load.loader=le");
    o.assign("analysis.disable=Stack").unwrap();
    let c = o.try_clone().unwrap();
    o.unset("load.loader").unwrap();
    assert_eq!(c.get("load.loader").unwrap(), "le");
    assert_eq!(o.get("load.loader").unwrap(), "default");
    assert!(ctx.options_registry().unwrap().rows() > 40);
    assert!(ctx.ops(false).unwrap().rows() >= 11);
    assert_eq!(ctx.schema("program_summary").unwrap().rows(), 12);
    assert_eq!(ctx.schema("nope").unwrap_err().status, Status::MOSURA_ERR_NOT_FOUND);
    assert_eq!(ctx.emit_axes().unwrap().rows(), 21);
    assert_eq!(ctx.emit_arms().unwrap().rows(), 29);
    assert!(ctx.data_list().unwrap().rows() > 100);
    let l = ctx.language("x86:LE:32:default").unwrap();
    assert!(l.registers().unwrap().rows() > 20);
    let d = l.disassemble(&[0x55, 0xc3], 0x1000, None).unwrap();
    assert_eq!(d.rows(), 2);
    assert_eq!(d.str(0, 3).unwrap(), "PUSH");
    assert!(l.lift(&[0x55, 0xc3], 0x1000, None).unwrap().rows() >= 4);
    assert_eq!(ctx.language("nope:LE:32:default").unwrap_err().status, Status::MOSURA_ERR_NOT_FOUND);
    assert!(ctx.languages().unwrap().rows() > 50);
}

#[test]
fn a_watcom_program_emits_through_the_binding_and_call_reaches_every_op() {
    let ctx = Ctx::new(CtxConfig::default()).unwrap();
    let mut s = Session::open(&ctx, None, None).unwrap();
    s.add_input(&corpus("watcom_hello.exe"), "watcom_hello.exe").unwrap();
    let mut p = s.program_open(None, None).unwrap();
    p.analyze(None, None).unwrap();
    let standalone = ctx.options().unwrap().with("decompile.global-scope", "standalone").unwrap();
    p.passes(Some(&standalone), None).unwrap();
    let fns = p.table("functions").unwrap();
    let entry = fns.u64(0, 1).unwrap();
    let f = p.decompile(entry, None).unwrap();
    let tu = f.tu(None).unwrap();
    assert!(!tu.is_empty());
    let report = f.table("report").unwrap();
    assert!((0..report.rows()).any(|r| report.str(r, 0).unwrap() == "row"));
    // the plumbing: the same TU through `call`
    let params = ctx.options().unwrap().with("entry", &format!("{entry:#x}")).unwrap().with("decompile.global-scope", "standalone").unwrap();
    let via_call = s.call("function.emit", Some(&params), None).unwrap();
    assert_eq!(via_call.render(Format::MOSURA_FMT_TEXT).unwrap(), tu);
    let explained = s.explain(&p.key().unwrap()).unwrap();
    assert!(explained.rows() > 5);
    assert!(s.gc(true).unwrap().rows() >= 3, "program, passes and function sets");
    assert_eq!(s.gc(false).unwrap_err().status, Status::MOSURA_ERR_UNSUPPORTED);
    // a cancelling progress callback on a fresh key
    let mut s2 = Session::open(&ctx, None, None).unwrap();
    s2.add_input(&corpus("switchtab.elf"), "switchtab.elf").unwrap();
    let e = s2.call("program.analyze", None, Some(&mut |_: &str, _: u64, _: u64| false)).unwrap_err();
    assert_eq!(e.status, Status::MOSURA_ERR_CANCELLED);
}
