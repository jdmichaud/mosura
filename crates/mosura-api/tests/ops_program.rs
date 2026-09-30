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

/// `load.entries` declares a raw image's entry points: a 68000 image starts with its vector table
/// (the initial stack pointer at 0, the reset address at 4), so the analysis must start at the
/// reset routine, not at the base. Declared, the functions are the reset routine and what it calls,
/// with nothing at 0; undeclared, the base is the entry as before. It needs load.loader=raw, and
/// an entry outside the image is refused.
#[test]
fn a_raw_image_is_analysed_from_the_entry_points_it_declares() {
    let c = ctx();
    let mut image = vec![0u8; 0x220];
    image[0..8].copy_from_slice(&[0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x02, 0x08]);
    // 208: jsr $210; rts      210: moveq #1,d0; rts
    image[0x208..0x214].copy_from_slice(&[0x4e, 0xb9, 0x00, 0x00, 0x02, 0x10, 0x4e, 0x75, 0x70, 0x01, 0x4e, 0x75]);
    let raw = [("load.loader", "raw"), ("load.language", "68000:BE:32:default"), ("load.base", "0")];
    let functions = |extra: &[(&str, &str)]| -> Result<Vec<u64>, Error> {
        let mut s = Session::open(None).unwrap();
        s.add_input(&image, "rom.bin", None).unwrap();
        let mut o = raw.to_vec();
        o.extend_from_slice(extra);
        dispatch(&c, &mut s, "program.analyze", &opts(&o), &mut NoProgress)?;
        let t = dispatch(&c, &mut s, "program.tables", &opts(&[("table", "functions")]), &mut NoProgress)?;
        let mut entries: Vec<u64> = (0..t.rows()).map(|r| t.u64(r, 1).unwrap()).collect();
        entries.sort_unstable();
        Ok(entries)
    };
    assert_eq!(functions(&[("load.entries", "0x208")]).unwrap(), [0x208, 0x210]);
    assert_eq!(functions(&[]).unwrap().first(), Some(&0), "undeclared: the base");
    assert!(matches!(functions(&[("load.entries", "0x400")]), Err(Error::Format(_))), "outside the image");
    let mut s = Session::open(None).unwrap();
    s.add_input(&image, "rom.bin", None).unwrap();
    assert!(matches!(dispatch(&c, &mut s, "program.analyze", &opts(&[("load.entries", "0x208")]), &mut NoProgress), Err(Error::InvalidArg(_))), "raw only");
}

/// `load.flows` declares computed flows the analysis cannot bound (Ghidra's user COMPUTED_JUMP and
/// COMPUTED_CALL references, what its switch recovery writes): a 68000 reset routine dispatches
/// through `jmp (2,pc,d0.w)` into a table of two `bra.w`, and case A calls through `jsr (a0)`.
/// Undeclared, the analysis stops at the `jmp`. Declared, the table and both cases are code and
/// inside the routine's body, and the call's target is a function of its own. A malformed
/// declaration or an address outside memory is refused.
#[test]
fn declared_flows_are_followed() {
    let c = ctx();
    let mut image = vec![0u8; 0x280];
    image[0..8].copy_from_slice(&[0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x02, 0x08]);
    // 208: moveq #0,d0   20a: jmp (2,pc,d0.w)   20e: bra.w $220   212: bra.w $230
    image[0x208..0x216].copy_from_slice(&[0x70, 0x00, 0x4e, 0xfb, 0x00, 0x02, 0x60, 0x00, 0x00, 0x10, 0x60, 0x00, 0x00, 0x1c]);
    image[0x220..0x224].copy_from_slice(&[0x4e, 0x90, 0x4e, 0x75]); // A: jsr (a0); rts
    image[0x230..0x234].copy_from_slice(&[0x72, 0x02, 0x4e, 0x75]); // B: moveq #2,d1; rts
    image[0x260..0x264].copy_from_slice(&[0x74, 0x03, 0x4e, 0x75]); // called: moveq #3,d2; rts
    let raw = [("load.loader", "raw"), ("load.language", "68000:BE:32:default"), ("load.base", "0"), ("load.entries", "0x208")];
    let run = |flows: &str| -> Result<(Vec<u64>, Vec<u64>), Error> {
        let mut s = Session::open(None).unwrap();
        s.add_input(&image, "rom.bin", None).unwrap();
        let mut o = raw.to_vec();
        if !flows.is_empty() {
            o.push(("load.flows", flows));
        }
        dispatch(&c, &mut s, "program.analyze", &opts(&o), &mut NoProgress)?;
        let t = dispatch(&c, &mut s, "program.tables", &opts(&[("table", "functions")]), &mut NoProgress)?;
        let mut functions: Vec<u64> = (0..t.rows()).map(|r| t.u64(r, 1).unwrap()).collect();
        functions.sort_unstable();
        let body = dispatch(&c, &mut s, "program.disassemble", &opts(&[("entry", "0x208")]), &mut NoProgress)?;
        let body: Vec<u64> = (0..body.rows()).map(|r| body.u64(r, 0).unwrap()).collect();
        Ok((functions, body))
    };
    let (functions, body) = run("").unwrap();
    assert_eq!((functions, body), (vec![0x208], vec![0x208, 0x20a]), "undeclared: the analysis stops at the jmp");
    let (functions, body) = run("jump:0x20a=0x20e,0x212; call:0x220=0x260").unwrap();
    assert_eq!(functions, [0x208, 0x260]);
    assert_eq!(body, [0x208, 0x20a, 0x20e, 0x212, 0x220, 0x222, 0x230, 0x232]);
    assert!(matches!(run("jump:0x20a"), Err(Error::InvalidArg(_))), "no targets");
    assert!(matches!(run("hop:0x20a=0x20e"), Err(Error::InvalidArg(_))), "unknown kind");
    assert!(matches!(run("jump:0x20a=0x9000"), Err(Error::InvalidArg(_))), "a target outside memory");
}

/// `load.data` declares data units — the tables a dispatch reads, as the program's own words:
/// `off16:ADDR*COUNT@BASE` (target = BASE + the signed word), `ptr16`/`ptr32` (target = the value,
/// plus @BASE when given), `u8`/`u16`/`u32` (plain values). Each element is a data unit in the
/// listing (Ghidra's type names), a pointer or offset element references its target, and a null
/// element (0) references nothing. The analysis leaves declared data alone: code never decodes
/// over it. An overlap or an element outside memory is refused.
#[test]
fn declared_data_is_in_the_listing_with_its_references() {
    let c = ctx();
    let mut image = vec![0u8; 0x300];
    image[0..8].copy_from_slice(&[0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x02, 0x08]);
    image[0x208..0x20a].copy_from_slice(&[0x60, 0x16]); // bra.s $220: flow runs into the table
    // 0x220: off16 table, base 0x220: +0x10, -0x20, 0 (null)
    image[0x220..0x226].copy_from_slice(&[0x00, 0x10, 0xff, 0xe0, 0x00, 0x00]);
    // 0x230: ptr32 table: 0x208, 0 (null)
    image[0x230..0x238].copy_from_slice(&[0x00, 0x00, 0x02, 0x08, 0x00, 0x00, 0x00, 0x00]);
    image[0x240] = 0x7f; // a plain byte
    let raw = [("load.loader", "raw"), ("load.language", "68000:BE:32:default"), ("load.base", "0"), ("load.entries", "0x208")];
    let run = |data: &str| -> Result<(Vec<(u64, u32, String)>, Vec<(u64, u64)>), Error> {
        let mut s = Session::open(None).unwrap();
        s.add_input(&image, "rom.bin", None).unwrap();
        let mut o = raw.to_vec();
        o.push(("load.data", data));
        dispatch(&c, &mut s, "program.analyze", &opts(&o), &mut NoProgress)?;
        let d = dispatch(&c, &mut s, "program.disassemble", &opts(&[("addr", "0x220"), ("len", "48")]), &mut NoProgress)?;
        let units = (0..d.rows()).map(|r| (d.u64(r, 0).unwrap(), d.u64(r, 1).unwrap() as u32, d.str(r, 3).unwrap().to_string())).collect();
        let t = dispatch(&c, &mut s, "program.tables", &opts(&[("table", "references")]), &mut NoProgress)?;
        let mut refs: Vec<(u64, u64)> = (0..t.rows()).map(|r| (t.u64(r, 1).unwrap(), t.u64(r, 3).unwrap())).filter(|(f, _)| (0x220..0x250).contains(f)).collect();
        refs.sort_unstable();
        Ok((units, refs))
    };
    let (units, refs) = run("off16:0x220*3@0x220; ptr32:0x230*2; u8:0x240").unwrap();
    let names = |v: &[(u64, u32, String)]| v.iter().map(|(a, l, n)| (*a, *l, n.clone())).collect::<Vec<_>>();
    assert_eq!(
        names(&units),
        [(0x220, 2, "word".into()), (0x222, 2, "word".into()), (0x224, 2, "word".into()), (0x230, 4, "pointer32".into()), (0x234, 4, "pointer32".into()), (0x240, 1, "byte".into())]
    );
    assert_eq!(refs, [(0x220, 0x230), (0x222, 0x200), (0x230, 0x208)]);
    let (undeclared, _) = run("u8:0x240").unwrap();
    assert!(undeclared.iter().any(|(a, _, n)| *a == 0x220 && n != "word"), "undeclared, the flow decodes the table as code: {undeclared:?}");
    assert!(matches!(run("u16:0x220; u8:0x221"), Err(Error::InvalidArg(_))), "overlap");
    assert!(matches!(run("u32:0x2fe"), Err(Error::InvalidArg(_))), "past the image");
    assert!(matches!(run("off16:0x220*3"), Err(Error::InvalidArg(_))), "an offset needs its base");
    assert!(matches!(run("f80:0x220"), Err(Error::InvalidArg(_))), "unknown kind");
    // COUNT is decimal: `*10` is ten words, 0x220..0x234 — clear of 0x236 (sixteen, read as
    // hex, would reach 0x240), overlapping 0x232.
    assert!(run("u16:0x220*10; ptr32:0x236").is_ok(), "ten words end at 0x234");
    assert!(matches!(run("u16:0x220*10; ptr32:0x232"), Err(Error::InvalidArg(_))), "and cover 0x232");
}

/// A branch's flow is decided by its SLEIGH template, as Ghidra's `walkTemplates` does, not by
/// where its target lands: a 68000 `bra.w` whose displacement reaches the next instruction and a
/// `bra.b *` that reaches itself are jumps with a reference (Ghidra: UNCONDITIONAL_JUMP), while
/// `dbf`'s internal `goto inst_next` is no flow edge — only its displacement target is referenced,
/// from the operand that names it.
#[test]
fn a_branch_is_typed_by_its_template_not_its_target() {
    let c = ctx();
    let mut image = vec![0u8; 0x220];
    image[0..8].copy_from_slice(&[0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x02, 0x00]);
    // 200: bra.w $204   204: moveq #2,d1   206: dbf d1,$206   20a: bra.b $20a
    image[0x200..0x20c].copy_from_slice(&[0x60, 0x00, 0x00, 0x02, 0x72, 0x02, 0x51, 0xc9, 0xff, 0xfe, 0x60, 0xfe]);
    let mut s = Session::open(None).unwrap();
    s.add_input(&image, "rom.bin", None).unwrap();
    let raw = [("load.loader", "raw"), ("load.language", "68000:BE:32:default"), ("load.base", "0"), ("load.entries", "0x200")];
    dispatch(&c, &mut s, "program.analyze", &opts(&raw), &mut NoProgress).unwrap();
    let d = dispatch(&c, &mut s, "program.disassemble", &opts(&[("addr", "0x200"), ("len", "12")]), &mut NoProgress).unwrap();
    let kinds: Vec<(u64, String)> = (0..d.rows()).map(|r| (d.u64(r, 0).unwrap(), d.str(r, 5).unwrap().to_string())).collect();
    assert_eq!(
        kinds,
        [(0x200, "UNCONDITIONAL_JUMP".to_string()), (0x204, "FALL_THROUGH".into()), (0x206, "CONDITIONAL_JUMP".into()), (0x20a, "UNCONDITIONAL_JUMP".into())]
    );
    let t = dispatch(&c, &mut s, "program.tables", &opts(&[("table", "references")]), &mut NoProgress).unwrap();
    // (from, to, operand): the reference sits on the operand that names the target
    let mut refs: Vec<(u64, u64, i64)> =
        (0..t.rows()).map(|r| (t.u64(r, 1).unwrap(), t.u64(r, 3).unwrap(), t.i64(r, 5).unwrap())).filter(|(f, _, _)| (0x200..0x20c).contains(f)).collect();
    refs.sort_unstable();
    assert_eq!(refs, [(0x200, 0x204, 0), (0x206, 0x206, 1), (0x20a, 0x20a, 0)]);
    // and the listing's flows are the same: no `inst_next` guard of `dbf`, the self-jump of `bra.b *`
    let flows: Vec<(u64, Vec<u64>)> = (0..d.rows()).map(|r| (d.u64(r, 0).unwrap(), d.list_u64(r, 9).unwrap().collect())).collect();
    assert_eq!(flows, [(0x200, vec![0x204]), (0x204, vec![]), (0x206, vec![0x206]), (0x20a, vec![0x20a])]);
}

/// The 68000's constant-propagation evaluator (Ghidra `Motorola68KAnalyzer.evaluateContext`): a
/// `lea` references the address it loads — a PC-relative one always, as operand 0's DATA
/// reference — and a `pea` references the constant it pushes. The displacement of a PC-relative
/// operand is no address: Ghidra makes no reference from a bare constant.
#[test]
fn a_68000_lea_and_pea_reference_the_address_they_compute() {
    let c = ctx();
    let mut image = vec![0u8; 0x1400];
    image[0..8].copy_from_slice(&[0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x02, 0x00]);
    // 200: lea (0x88,pc),a5 -> 0x28a   204: lea (0x1000,pc),a1 -> 0x1206   208: pea ($1234).l   20e: rts
    image[0x200..0x210].copy_from_slice(&[0x4b, 0xfa, 0x00, 0x88, 0x43, 0xfa, 0x10, 0x00, 0x48, 0x79, 0x00, 0x00, 0x12, 0x34, 0x4e, 0x75]);
    let mut s = Session::open(None).unwrap();
    s.add_input(&image, "rom.bin", None).unwrap();
    let raw = [("load.loader", "raw"), ("load.language", "68000:BE:32:default"), ("load.base", "0"), ("load.entries", "0x200")];
    dispatch(&c, &mut s, "program.analyze", &opts(&raw), &mut NoProgress).unwrap();
    let t = dispatch(&c, &mut s, "program.tables", &opts(&[("table", "references")]), &mut NoProgress).unwrap();
    let mut refs: Vec<(u64, u64, i64)> = (0..t.rows())
        .map(|r| (t.u64(r, 1).unwrap(), t.u64(r, 3).unwrap(), t.i64(r, 5).unwrap()))
        .filter(|(f, _, _)| (0x200..0x20e).contains(f))
        .collect();
    refs.sort_unstable();
    assert_eq!(refs, [(0x200, 0x28a, 0), (0x204, 0x1206, 0), (0x208, 0x1234, 0)]);
}

/// The listing shows the flow type analysis left, as Ghidra's `Instruction.getFlowType()` does:
/// the prototype's, modified by a flow override. `call_returns`' `middle` ends in `jmp device`, a
/// tail call to a function `_start` also calls; shared-return analysis overrides it to
/// CALL_RETURN, so it is a CALL_TERMINATOR, not an UNCONDITIONAL_JUMP.
#[test]
fn the_listing_shows_the_overridden_flow_type() {
    let c = ctx();
    let dir = mosura_core::paths::ground_truth_dir();
    let truth = std::fs::read_to_string(dir.join("call_returns.gcc-x86-32.truth")).unwrap();
    let middle = truth.lines().find_map(|l| l.strip_suffix(" middle code")).and_then(|l| l.split_whitespace().nth(1)).map(|a| u64::from_str_radix(a, 16).unwrap()).unwrap();
    let mut s = Session::open(None).unwrap();
    s.add_input(&std::fs::read(dir.join("call_returns.gcc-x86-32")).unwrap(), "call_returns", None).unwrap();
    dispatch(&c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
    let d = dispatch(&c, &mut s, "program.disassemble", &opts(&[("entry", &format!("{middle:#x}"))]), &mut NoProgress).unwrap();
    let last = d.rows() - 1;
    assert_eq!((d.str(last, 3).unwrap(), d.str(last, 5).unwrap(), d.bool(last, 6).unwrap()), ("JMP", "CALL_TERMINATOR", true));
}

#[test]
fn cached_program_configuration_is_request_local() {
    use mosura_api::ops::program::program_of;
    let c = ctx();
    let (mut s, _) = session_with("basic.elf");
    dispatch(&c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
    let (_, original) = program_of(&mut s, &Options::new()).unwrap();
    let requested = opts(&[("knobs.off", "global-width"),
        ("decompile.global-scope", "standalone"), ("decompile.proto-scope", "none")]);
    let settings = requested.decompile_settings().unwrap();
    for thaw in [false, true] {
        if thaw { s.last_program = None; }
        let (_, configured) = program_of(&mut s, &requested).unwrap();
        assert_eq!(configured.knobs, requested.knobs().unwrap(), "request knobs must reach the program");
        assert_eq!(configured.global_scope_all_loaded, settings.global_scope_all_loaded);
        assert_eq!(configured.proto_scope, settings.proto_scope);
        let (_, reset) = program_of(&mut s, &Options::new()).unwrap();
        assert_eq!(reset.knobs, original.knobs, "request settings must not leak into later requests");
        assert_eq!(reset.global_scope_all_loaded, original.global_scope_all_loaded);
        assert_eq!(reset.proto_scope, original.proto_scope);
    }
    assert_eq!(s.set_keys(SetKind::Program).unwrap().len(), 1,
        "decompile settings do not require another analysis set");
}
