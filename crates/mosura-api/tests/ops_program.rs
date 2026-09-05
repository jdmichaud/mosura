//! The operation registry and the program operations: unknown op / parameter refused; analyze
//! writes the set and is served from it afterwards; the tables equal a fresh freeze; the
//! snapshot table is the live text; read and disassemble agree with the core; every corpus binary
//! identifies; the com, raw and xml loaders are selected by option.

use std::time::Instant;

use mosura_api::ops::{dispatch, NoProgress};
use mosura_api::program::freeze;
use mosura_api::{Context, ContextConfig, Error, Options, Session, SetKind};
use mosura_core::analysis;
use mosura_core::switches::Knobs;

fn ctx() -> Context {
    Context::new(ContextConfig::default()).unwrap()
}

fn corpus(name: &str) -> std::path::PathBuf {
    mosura_core::paths::analysis_corpus_dir().join(name)
}

fn session_with(name: &str) -> (Session, Vec<u8>) {
    let mut s = Session::open(None).unwrap();
    let bytes = std::fs::read(corpus(name)).unwrap();
    s.add_input(&bytes, name, None).unwrap();
    (s, bytes)
}

fn opts(pairs: &[(&str, &str)]) -> Options {
    let mut o = Options::new();
    for (k, v) in pairs {
        o.set(k, v).unwrap();
    }
    o
}

#[test]
fn unknown_op_and_foreign_parameter_are_refused() {
    let c = ctx();
    let (mut s, _) = session_with("basic.elf");
    assert!(matches!(dispatch(&c, &mut s, "program.nope", &Options::new(), &mut NoProgress), Err(Error::NotFound(_))));
    match dispatch(&c, &mut s, "program.load", &opts(&[("entry", "0x1000")]), &mut NoProgress) {
        Err(Error::InvalidArg(m)) => assert!(m.contains("`entry` is not a parameter of `program.load`"), "{m}"),
        other => panic!("{:?}", other.map(|_| ())),
    }
    // a diagnostic key is accepted by every op
    dispatch(&c, &mut s, "program.load", &opts(&[("debug.watch-call", "0x1000")]), &mut NoProgress).unwrap();
}

#[test]
fn analyze_writes_the_set_and_is_then_served_from_it() {
    let c = ctx();
    let (mut s, _) = session_with("basic.elf");
    assert!(s.set_keys(SetKind::Program).unwrap().is_empty());
    let t1 = dispatch(&c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
    assert_eq!(t1.rows(), 1);
    let keys = s.set_keys(SetKind::Program).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(t1.str(0, 0).unwrap(), keys[0].hex());
    assert_eq!(t1.str(0, 1).unwrap(), "x86:LE:64:default");
    assert!(t1.u64(0, 8).unwrap() >= 13, "functions");
    assert!(t1.u64(0, 11).unwrap() > 100, "instructions");
    // second call: a hit — the same summary, no re-analysis (well under a second)
    let start = Instant::now();
    let t2 = dispatch(&c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
    assert!(start.elapsed().as_millis() < 500, "a cache hit took {:?}", start.elapsed());
    assert_eq!(mosura_api::render::render(&t2, mosura_api::Format::Tsv).unwrap(), mosura_api::render::render(&t1, mosura_api::Format::Tsv).unwrap());
    // the stored tables equal a fresh freeze of a live analysis
    let live = analysis::analyze_file_with(&corpus("basic.elf"), &Knobs::default()).unwrap();
    let fresh = freeze(&live, "default");
    let stored = s.read_set(SetKind::Program, &keys[0]).unwrap();
    assert_eq!(stored.digests(), fresh.digests());
    // program.tables: the listing, one table by name, the virtual snapshot
    let list = dispatch(&c, &mut s, "program.tables", &Options::new(), &mut NoProgress).unwrap();
    assert!(list.rows() as usize == fresh.tables.len() + 1);
    let fns = dispatch(&c, &mut s, "program.tables", &opts(&[("table", "functions")]), &mut NoProgress).unwrap();
    assert_eq!(fns.digest(), fresh.tables["functions"].digest());
    let snap = dispatch(&c, &mut s, "program.tables", &opts(&[("table", "snapshot")]), &mut NoProgress).unwrap();
    assert_eq!(mosura_api::render::render(&snap, mosura_api::Format::Text).unwrap(), live.snapshot().render());
    assert!(matches!(dispatch(&c, &mut s, "program.tables", &opts(&[("table", "nope")]), &mut NoProgress), Err(Error::NotFound(_))));
    // load (no analysis) is a different key with fewer functions or equal
    let l = dispatch(&c, &mut s, "program.load", &Options::new(), &mut NoProgress).unwrap();
    assert_ne!(l.str(0, 0).unwrap(), t1.str(0, 0).unwrap());
    assert!(l.u64(0, 8).unwrap() <= t1.u64(0, 8).unwrap());
    assert_eq!(s.set_keys(SetKind::Program).unwrap().len(), 2);
    // two programs: an op without `program` must name one
    s.last_program = None;
    assert!(matches!(dispatch(&c, &mut s, "program.tables", &Options::new(), &mut NoProgress), Err(Error::InvalidArg(_))));
    let named = dispatch(&c, &mut s, "program.tables", &opts(&[("program", &keys[0].hex()), ("table", "blocks")]), &mut NoProgress).unwrap();
    assert_eq!(named.digest(), fresh.tables["blocks"].digest());
}

#[test]
fn read_and_disassemble_agree_with_the_core() {
    let c = ctx();
    let (mut s, bytes) = session_with("basic.elf");
    dispatch(&c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
    let live = analysis::analyze_file_with(&corpus("basic.elf"), &Knobs::default()).unwrap();
    let f = live.function_manager.functions().find(|f| f.name() == "main").expect("main");
    let entry = f.entry_point().offset;
    // read: the bytes at the entry equal the live memory's
    let r = dispatch(&c, &mut s, "program.read", &opts(&[("addr", &format!("{entry:#x}")), ("len", "16")]), &mut NoProgress).unwrap();
    assert_eq!(r.bytes(0, 1).unwrap(), live.memory.read_window(f.entry_point(), 16).as_slice());
    assert!(!bytes.is_empty());
    assert!(matches!(dispatch(&c, &mut s, "program.read", &opts(&[("addr", "0x1"), ("len", "4")]), &mut NoProgress), Err(Error::NotFound(_))));
    assert!(matches!(dispatch(&c, &mut s, "program.read", &opts(&[("len", "4")]), &mut NoProgress), Err(Error::InvalidArg(_))));
    // disassemble main's body: every row is a listing unit and its text is sleigh's
    let d = dispatch(&c, &mut s, "program.disassemble", &opts(&[("entry", &format!("{entry:#x}"))]), &mut NoProgress).unwrap();
    assert!(d.rows() > 3, "{}", d.rows());
    assert_eq!(d.u64(0, 0).unwrap(), entry);
    for row in 0..d.rows() {
        let a = d.u64(row, 0).unwrap();
        let (len, _) = live.listing.instruction_at(mosura_core::decompile::space::Address::new(live.default_space, a)).expect("a listing instruction");
        assert_eq!(d.u64(row, 1).unwrap() as u32, len);
        let ins = mosura_core::sleigh::disassemble(&live.language_id, d.bytes(row, 2).unwrap(), a).unwrap();
        assert_eq!(d.str(row, 3).unwrap(), ins[0].mnemonic);
        assert_eq!(d.str(row, 4).unwrap(), ins[0].body);
    }
    // the same over addr+len
    let d2 = dispatch(&c, &mut s, "program.disassemble", &opts(&[("addr", &format!("{entry:#x}")), ("len", "8")]), &mut NoProgress).unwrap();
    assert!(d2.rows() >= 1 && d2.rows() <= 8);
    assert_eq!(d2.u64(0, 0).unwrap(), entry);
}

#[test]
fn every_corpus_binary_identifies() {
    let c = ctx();
    for name in ["basic.elf", "switchtab.elf", "m68k_dyn.elf", "watcom_hello.exe", "z80.com", "mingw_hello32.exe", "aarch64.elf", "riscv.elf"] {
        let (mut s, _) = session_with(name);
        let t = dispatch(&c, &mut s, "identify", &Options::new(), &mut NoProgress).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let keys: Vec<&str> = (0..t.rows()).map(|r| t.str(r, 0).unwrap()).collect();
        for k in ["input", "container", "native.loader", "compiler.version", "load", "language", "cspec", "base", "functions", "fid.records"] {
            assert!(keys.contains(&k), "{name}: no `{k}` row in {keys:?}");
        }
        let lang = (0..t.rows()).find(|&r| t.str(r, 0).unwrap() == "language").map(|r| t.str(r, 1).unwrap()).unwrap();
        assert!(!lang.is_empty(), "{name}");
        if name == "watcom_hello.exe" {
            assert!(keys.contains(&"le.header"), "{name}: LE header row");
            assert!(keys.contains(&"compiler.watcom"), "{name}: watcom banner row");
        }
    }
}

#[test]
fn loaders_are_selected_by_option() {
    let c = ctx();
    // com: a raw Z80 image named without its extension still loads through load.loader=com
    let mut s = Session::open(None).unwrap();
    s.add_input(&std::fs::read(corpus("z80.com")).unwrap(), "z80image", None).unwrap();
    assert!(dispatch(&c, &mut s, "program.load", &Options::new(), &mut NoProgress).is_err(), "no magic: the default dispatch declines");
    let t = dispatch(&c, &mut s, "program.load", &opts(&[("load.loader", "com")]), &mut NoProgress).unwrap();
    assert_eq!(t.str(0, 1).unwrap(), "z80:LE:16:default");
    // raw: bytes + language + base; analysis finds the function at base
    let mut s = Session::open(None).unwrap();
    s.add_input(&[0x55, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3], "blob.bin", None).unwrap();
    assert!(matches!(dispatch(&c, &mut s, "program.load", &opts(&[("load.loader", "raw")]), &mut NoProgress), Err(Error::InvalidArg(_))));
    let t = dispatch(&c, &mut s, "program.analyze", &opts(&[("load.loader", "raw"), ("load.language", "x86:LE:32:default"), ("load.base", "0x1000")]), &mut NoProgress).unwrap();
    assert_eq!(t.str(0, 1).unwrap(), "x86:LE:32:default");
    assert_eq!(t.u64(0, 5).unwrap(), 0x1000);
    assert_eq!(t.u64(0, 7).unwrap(), 1, "one block");
    assert_eq!(t.u64(0, 8).unwrap(), 1, "the function at base");
    assert_eq!(t.u64(0, 11).unwrap(), 5, "five instructions");
    let d = dispatch(&c, &mut s, "program.disassemble", &opts(&[("entry", "0x1000")]), &mut NoProgress).unwrap();
    assert_eq!(d.rows(), 5);
    assert_eq!(d.str(0, 3).unwrap(), "PUSH");
    assert_eq!(d.str(4, 3).unwrap(), "RET");
    // xml: a Ghidra datatest from the oracle fixtures
    let fixture = mosura_core::paths::workspace_root().join("oracle/fixtures/aarch64_ccmp.xml");
    let mut s = Session::open(None).unwrap();
    s.add_input(&std::fs::read(&fixture).unwrap(), "aarch64_ccmp.xml", None).unwrap();
    let t = dispatch(&c, &mut s, "program.analyze", &opts(&[("load.loader", "xml")]), &mut NoProgress).unwrap();
    assert_eq!(t.str(0, 1).unwrap(), "AARCH64:LE:64:v8A");
    assert_eq!(t.str(0, 2).unwrap(), "default");
    assert_eq!(t.u64(0, 5).unwrap(), 0x42caec);
    assert!(t.u64(0, 8).unwrap() >= 1);
    assert!(t.u64(0, 11).unwrap() >= 7, "the fixture's instructions were decoded: {}", t.u64(0, 11).unwrap());
}
