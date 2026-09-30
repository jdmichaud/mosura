//! `sleigh.disassemble` / `sleigh.lift` over raw bytes: rows equal the core's `sleigh::disassemble`
//! (text, bytes, p-code render), `ctx` changes the decode, malformed parameters are refused.

use mosura_api::ops::{dispatch, NoProgress};
use mosura_api::{Context, ContextConfig, Error, Options, Session};

fn ctx() -> Context {
    Context::new(ContextConfig::default()).unwrap()
}

fn opts(pairs: &[(&str, &str)]) -> Options {
    let mut o = Options::new();
    for (k, v) in pairs {
        o.set(k, v).unwrap();
    }
    o
}

// push ebp; mov ebp,esp; mov eax,[ebp+8]; add eax,1; pop ebp; ret
const HEX: &str = "5589e58b450883c0015dc3";

#[test]
fn disassemble_and_lift_equal_the_core() {
    let c = ctx();
    let mut s = Session::open(None).unwrap();
    let live = mosura_core::sleigh::disassemble("x86:LE:32:default", &mosura_api::ops::sleigh::parse_bytes(HEX).unwrap(), 0x401000).unwrap();
    assert_eq!(live.len(), 6);
    let d = dispatch(&c, &mut s, "sleigh.disassemble", &opts(&[("lang", "x86:LE:32:default"), ("bytes", HEX), ("base", "0x401000")]), &mut NoProgress).unwrap();
    assert_eq!(d.rows() as usize, live.len());
    for (r, i) in live.iter().enumerate() {
        let r = r as u64;
        assert_eq!(d.u64(r, 0).unwrap(), i.address);
        assert_eq!(d.u64(r, 1).unwrap() as usize, i.bytes.len());
        assert_eq!(d.bytes(r, 2).unwrap(), i.bytes.as_slice());
        assert_eq!(d.str(r, 3).unwrap(), i.mnemonic);
        assert_eq!(d.str(r, 4).unwrap(), i.body);
    }
    assert_eq!(d.str(0, 3).unwrap(), "PUSH");
    assert_eq!(d.str(5, 3).unwrap(), "RET");
    let l = dispatch(&c, &mut s, "sleigh.lift", &opts(&[("lang", "x86:LE:32:default"), ("bytes", HEX), ("base", "0x401000")]), &mut NoProgress).unwrap();
    let total: usize = live.iter().map(|i| i.ops.len()).sum();
    assert_eq!(l.rows() as usize, total);
    let mut r = 0u64;
    for i in &live {
        for (seq, op) in i.ops.iter().enumerate() {
            assert_eq!(l.u64(r, 0).unwrap(), i.address);
            assert_eq!(l.u64(r, 1).unwrap() as usize, seq);
            assert_eq!(l.str(r, 3).unwrap(), op.name());
            assert_eq!(l.str(r, 11).unwrap(), op.render());
            assert_eq!(l.str(r, 11).unwrap(), i.pcode[seq], "the pcode text column is the golden form");
            r += 1;
        }
    }
    // spaces are ignored in the hex; base defaults to 0
    let d0 = dispatch(&c, &mut s, "sleigh.disassemble", &opts(&[("lang", "x86:LE:32:default"), ("bytes", "55 89 e5")]), &mut NoProgress).unwrap();
    assert_eq!(d0.rows(), 2);
    assert_eq!(d0.u64(0, 0).unwrap(), 0);
}

#[test]
fn the_context_changes_the_decode_and_bad_parameters_are_refused() {
    let c = ctx();
    let mut s = Session::open(None).unwrap();
    // b8 34 12 00 00: MOV EAX,0x1234 in 32-bit mode; in 16-bit mode MOV AX,0x1234 then ADD [BX+SI],AL
    let default = dispatch(&c, &mut s, "sleigh.disassemble", &opts(&[("lang", "x86:LE:32:default"), ("bytes", "b834120000")]), &mut NoProgress).unwrap();
    assert_eq!(default.rows(), 1);
    assert_eq!(default.str(0, 4).unwrap(), "EAX,0x1234");
    let sixteen = dispatch(&c, &mut s, "sleigh.disassemble", &opts(&[("lang", "x86:LE:32:default"), ("bytes", "b834120000"), ("ctx", "addrsize=0;opsize=0")]), &mut NoProgress).unwrap();
    assert_eq!(sixteen.rows(), 2, "16-bit: the immediate is two bytes");
    assert_eq!(sixteen.str(0, 4).unwrap(), "AX,0x1234");
    // an unknown context variable, odd hex, a missing language, an unknown language
    assert!(matches!(dispatch(&c, &mut s, "sleigh.disassemble", &opts(&[("lang", "x86:LE:32:default"), ("bytes", "90"), ("ctx", "nope=1")]), &mut NoProgress), Err(Error::InvalidArg(_))));
    assert!(matches!(dispatch(&c, &mut s, "sleigh.disassemble", &opts(&[("lang", "x86:LE:32:default"), ("bytes", "909")]), &mut NoProgress), Err(Error::InvalidArg(_))));
    assert!(matches!(dispatch(&c, &mut s, "sleigh.disassemble", &opts(&[("bytes", "90")]), &mut NoProgress), Err(Error::InvalidArg(_))));
    assert!(matches!(dispatch(&c, &mut s, "sleigh.lift", &opts(&[("lang", "nope:LE:32:default"), ("bytes", "90")]), &mut NoProgress), Err(Error::NotFound(_))));
}

/// `sleigh.emulate`: the outcome, the registers and the memory of a run, over the same bytes a
/// Rust caller would hand `sleigh::emu::run_with` (`docs/emulation.md`).
#[test]
fn emulate_reports_the_outcome_the_registers_and_the_memory() {
    let c = ctx();
    let mut s = Session::open(None).unwrap();
    let rows = |t: &mosura_api::table::Table| -> Vec<(String, String, String)> {
        (0..t.rows()).map(|r| (t.str(r, 0).unwrap().to_string(), t.str(r, 1).unwrap().to_string(), t.str(r, 2).unwrap().to_string())).collect()
    };
    let lang = ("lang", "x86:LE:32:default");
    // div ecx; ret — 100 / 7 returns; a zero divisor and a quotient too wide for EAX fault
    let div = ("bytes", "f7f1c3");
    let t = dispatch(&c, &mut s, "sleigh.emulate", &opts(&[lang, div, ("base", "0x1000"), ("emulate.registers", "EDX=0,EAX=0x64,ECX=7")]), &mut NoProgress).unwrap();
    let r = rows(&t);
    assert!(r.contains(&("outcome".into(), "stop".into(), "returned".into())), "{r:?}");
    assert!(r.contains(&("outcome".into(), "unmodeled".into(), "0".into())), "{r:?}");
    assert!(r.contains(&("register".into(), "EAX".into(), "0x0000000e".into())), "{r:?}");
    assert!(r.contains(&("register".into(), "EDX".into(), "0x00000002".into())), "{r:?}");
    assert!(!r.iter().any(|(k, n, _)| k == "register" && n == "AX"), "a register inside a reported one is not repeated: {r:?}");
    let steps: usize = r.iter().find(|(k, n, _)| k == "outcome" && n == "steps").unwrap().2.parse().unwrap();
    assert!(steps > 0 && steps < 20, "{steps}");
    for regs in ["EDX=0,EAX=0x64,ECX=0", "EDX=1,EAX=0,ECX=1"] {
        let t = dispatch(&c, &mut s, "sleigh.emulate", &opts(&[lang, div, ("emulate.registers", regs)]), &mut NoProgress).unwrap();
        assert!(rows(&t).contains(&("outcome".into(), "stop".into(), "fault".into())), "{regs}: {:?}", rows(&t));
    }
    // mov eax,[0x2000]; mov [0x2004],eax; ret — over seeded memory, and the memory it wrote
    let load = ("bytes", "a100200000a304200000c3");
    let t = dispatch(&c, &mut s, "sleigh.emulate", &opts(&[lang, load, ("emulate.memory", "0x2000=0a000000")]), &mut NoProgress).unwrap();
    let r = rows(&t);
    assert!(r.contains(&("register".into(), "EAX".into(), "0x0000000a".into())), "{r:?}");
    assert!(r.contains(&("memory".into(), "0x2000".into(), "0a0000000a000000".into())), "{r:?}");
    // call +2; inc eax; ret; mov eax,41; ret — the callee runs only when calls are followed
    let chain = ("bytes", "e80200000040c3b829000000c3");
    let stack = ("emulate.registers", "ESP=0x0f000000,EAX=0");
    let t = dispatch(&c, &mut s, "sleigh.emulate", &opts(&[lang, chain, ("base", "0x1000"), stack, ("emulate.follow-calls", "true")]), &mut NoProgress).unwrap();
    assert!(rows(&t).contains(&("register".into(), "EAX".into(), "0x0000002a".into())), "{:?}", rows(&t));
    let t = dispatch(&c, &mut s, "sleigh.emulate", &opts(&[lang, chain, ("base", "0x1000"), stack]), &mut NoProgress).unwrap();
    assert!(rows(&t).contains(&("register".into(), "EAX".into(), "0x00000001".into())), "{:?}", rows(&t));
    // a call whose target is outside the bytes names that target; entry starts inside the bytes
    let t = dispatch(&c, &mut s, "sleigh.emulate", &opts(&[lang, ("bytes", "e80300000040c3"), ("base", "0x1000"), stack, ("emulate.follow-calls", "true")]), &mut NoProgress).unwrap();
    let r = rows(&t);
    assert!(r.contains(&("outcome".into(), "stop".into(), "no-instruction".into())), "{r:?}");
    assert!(r.contains(&("outcome".into(), "address".into(), "0x1008".into())), "{r:?}");
    let t = dispatch(&c, &mut s, "sleigh.emulate", &opts(&[lang, chain, ("base", "0x1000"), stack, ("emulate.entry", "0x1007")]), &mut NoProgress).unwrap();
    assert!(rows(&t).contains(&("register".into(), "EAX".into(), "0x00000029".into())), "{:?}", rows(&t));
    // jmp $ spends the budget
    let t = dispatch(&c, &mut s, "sleigh.emulate", &opts(&[lang, ("bytes", "ebfe"), ("emulate.max-steps", "1000")]), &mut NoProgress).unwrap();
    let r = rows(&t);
    assert!(r.contains(&("outcome".into(), "stop".into(), "step-cap".into())), "{r:?}");
    assert!(r.contains(&("outcome".into(), "steps".into(), "1000".into())), "{r:?}");
    // malformed state is refused before anything runs: a non-hex entry by the option registry
    // itself, an unknown register, a bare name or an odd byte string by the operation
    assert!(matches!(Options::new().set("emulate.entry", "zz"), Err(Error::InvalidArg(_))));
    for (key, value) in [("emulate.registers", "NOPE=1"), ("emulate.registers", "EAX"), ("emulate.memory", "0x2000=0")] {
        let e = dispatch(&c, &mut s, "sleigh.emulate", &opts(&[lang, div, (key, value)]), &mut NoProgress).unwrap_err();
        assert!(matches!(e, Error::InvalidArg(_)), "{key}={value}: {e:?}");
    }
}

fn emulation_rows(t: &mosura_api::table::Table) -> Vec<(String, String, String)> {
    (0..t.rows()).map(|r| (t.str(r, 0).unwrap().to_string(), t.str(r, 1).unwrap().to_string(), t.str(r, 2).unwrap().to_string())).collect()
}

/// `sleigh.emulate`'s bytes are the machine's memory as well as its code, as a loaded program's
/// are: an instruction that reads data placed after it reads the bytes given. A seed over them
/// wins, and reading them writes nothing.
#[test]
fn emulate_reads_its_own_bytes_as_memory() {
    let c = ctx();
    let mut s = Session::open(None).unwrap();
    // mov eax,[0x1006]; ret — then the dword 0x11223344 at 0x1006
    let code = [("lang", "x86:LE:32:default"), ("bytes", "a106100000c344332211"), ("base", "0x1000")];
    let r = emulation_rows(&dispatch(&c, &mut s, "sleigh.emulate", &opts(&code), &mut NoProgress).unwrap());
    assert!(r.contains(&("outcome".into(), "stop".into(), "returned".into())), "{r:?}");
    assert!(r.contains(&("register".into(), "EAX".into(), "0x11223344".into())), "{r:?}");
    assert!(!r.iter().any(|(k, _, _)| k == "memory"), "reading the bytes writes nothing: {r:?}");
    let mut seeded = code.to_vec();
    seeded.push(("emulate.memory", "0x1006=78563412"));
    let r = emulation_rows(&dispatch(&c, &mut s, "sleigh.emulate", &opts(&seeded), &mut NoProgress).unwrap());
    assert!(r.contains(&("register".into(), "EAX".into(), "0x12345678".into())), "{r:?}");
}

/// `emulate.effects` on raw bytes: a port write is an `out` effect row.
#[test]
fn emulate_lists_a_port_write_as_an_effect() {
    let c = ctx();
    let mut s = Session::open(None).unwrap();
    // mov dx,0x3f8; mov al,0x41; out dx,al; ret
    let code = [("lang", "x86:LE:32:default"), ("bytes", "66baf803b041eec3"), ("emulate.effects", "true")];
    let r = emulation_rows(&dispatch(&c, &mut s, "sleigh.emulate", &opts(&code), &mut NoProgress).unwrap());
    let list: Vec<&str> = r.iter().filter(|(k, _, _)| k == "effect").map(|(_, _, v)| v.as_str()).collect();
    assert_eq!(list, ["out 0x3f8 1 0x41"], "{r:?}");
}

/// `sleigh.emulate` carries a state the same way: `inc eax; ret` twice through one state name.
#[test]
fn emulate_continues_from_a_stored_state() {
    let c = ctx();
    let mut s = Session::open(None).unwrap();
    let eax = |r: &[(String, String, String)]| r.iter().find(|(k, n, _)| k == "register" && n == "EAX").map(|(_, _, v)| v.clone());
    let code = [("lang", "x86:LE:32:default"), ("bytes", "40c3"), ("emulate.save-state", "n")];
    let r = emulation_rows(&dispatch(&c, &mut s, "sleigh.emulate", &opts(&code), &mut NoProgress).unwrap());
    assert_eq!(eax(&r).as_deref(), Some("0x00000001"), "{r:?}");
    let mut again = code.to_vec();
    again.push(("emulate.state", "n"));
    let r = emulation_rows(&dispatch(&c, &mut s, "sleigh.emulate", &opts(&again), &mut NoProgress).unwrap());
    assert_eq!(eax(&r).as_deref(), Some("0x00000002"), "{r:?}");
}

/// The processor spec's register groups: the language registers table names each register's
/// group (x86 marks CF, NT, VIP… FLAGS), and `emulate.uninitialized-ignore` leaves chosen groups or
/// registers out of the `uninitialized` rows. `pushfd` reads every flag nobody wrote; ignoring
/// FLAGS leaves the one read that matters here, an unset GS base.
#[test]
fn uninitialized_registers_can_leave_out_a_group() {
    let c = ctx();
    let mut s = Session::open(None).unwrap();
    let regs = mosura_api::ops::language::registers_table("x86:LE:32:default").unwrap();
    let group = regs.col("group").expect("a `group` column");
    let group_of = |name: &str| (0..regs.rows()).find(|&r| regs.str(r, 0).unwrap() == name).map(|r| regs.str(r, group).unwrap().to_string());
    assert_eq!((group_of("CF").as_deref(), group_of("NT").as_deref(), group_of("EAX").as_deref()), (Some("FLAGS"), Some("FLAGS"), Some("")));
    // pushfd; pop eax; mov eax,gs:[0x10]; ret
    let code = [("lang", "x86:LE:32:default"), ("bytes", "9c5865a110000000c3"), ("emulate.registers", "ESP=0x0f000000")];
    let named = |extra: &[(&str, &str)], s: &mut Session| {
        let mut o = code.to_vec();
        o.extend_from_slice(extra);
        emulation_rows(&dispatch(&c, s, "sleigh.emulate", &opts(&o), &mut NoProgress).unwrap())
            .into_iter()
            .filter(|(k, n, _)| k == "outcome" && n == "uninitialized")
            .map(|(_, _, v)| v)
            .collect::<Vec<String>>()
    };
    let all = named(&[], &mut s);
    assert!(all.len() > 5 && all.contains(&"CF".to_string()) && all.contains(&"GS_OFFSET".to_string()), "{all:?}");
    assert_eq!(named(&[("emulate.uninitialized-ignore", "FLAGS")], &mut s), ["GS_OFFSET"]);
    assert_eq!(named(&[("emulate.uninitialized-ignore", "FLAGS,GS_OFFSET")], &mut s), Vec::<String>::new());
}

/// A stub reached from a routine that is itself an entered call returns into that routine, and
/// the routine's own return then goes back to its caller: E calls A, A reaches the stub S (by a
/// call, or by a tail jump), and E's work after the call to A still runs. Raw bytes name no
/// compiler spec, so this also holds only if the stack pointer is found without one: the stub
/// must hand the stack back as S's return would leave it.
#[test]
fn a_stub_reached_from_an_entered_call_returns_into_it() {
    let c = ctx();
    let mut s = Session::open(None).unwrap();
    // E@0x1000: call A; mov ebx,0x11; ret    A@0x100b: call S | jmp S; ret    S@0x1011: mov eax,99; ret
    let call = "e806000000bb11000000c3e801000000c3b863000000c3";
    let jump = "e806000000bb11000000c3e901000000c3b863000000c3";
    for (lang, sp, bx) in [("x86:LE:32:default", "ESP", "EBX"), ("x86:LE:64:default", "RSP", "RBX")] {
        for (how, bytes) in [("call", call), ("jump", jump)] {
            let registers = format!("{sp}=0x0f000000");
            let o = opts(&[("lang", lang), ("bytes", bytes), ("base", "0x1000"), ("emulate.registers", &registers), ("emulate.follow-calls", "true"), ("emulate.effects", "true"), ("emulate.stubs", "0x1011")]);
            let r = emulation_rows(&dispatch(&c, &mut s, "sleigh.emulate", &o, &mut NoProgress).unwrap());
            let value = |kind: &str, name: &str| r.iter().find(|(k, n, _)| k == kind && n == name).map(|(_, _, v)| u64::from_str_radix(v.trim_start_matches("0x"), 16).unwrap_or(u64::MAX));
            let stubs = r.iter().filter(|(k, _, v)| k == "effect" && v.starts_with("stub ")).count();
            assert_eq!(r.iter().find(|(k, n, _)| k == "outcome" && n == "stop").map(|(_, _, v)| v.as_str()), Some("returned"), "{lang} {how}: {r:?}");
            assert_eq!((value("register", bx), stubs), (Some(0x11), 1), "{lang} {how}: E's work after the call ran; {r:?}");
            let word = if sp == "RSP" { 8 } else { 4 };
            assert_eq!(value("register", sp), Some(0x0f00_0000 + word), "{lang} {how}: E's return popped one word");
        }
    }
}

/// A raw-text ground-truth artifact (`<stem>.bin` + its `llvm-nm` list `<stem>.syms`): the text as
/// hex, where it loads (its first symbol, or `base` for an unlinked object), and a routine's address.
struct RawText {
    bytes: String,
    base: u64,
    syms: Vec<(u64, String)>,
}

impl RawText {
    fn load(stem: &str, base: Option<u64>) -> Self {
        let dir = mosura_core::paths::ground_truth_dir();
        let bytes = std::fs::read(dir.join(format!("{stem}.bin"))).unwrap().iter().map(|b| format!("{b:02x}")).collect();
        let syms: Vec<(u64, String)> = std::fs::read_to_string(dir.join(format!("{stem}.syms")))
            .unwrap()
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                (f.len() == 3 && f[1].eq_ignore_ascii_case("t")).then(|| (u64::from_str_radix(f[0], 16).unwrap(), f[2].to_string()))
            })
            .collect();
        let linked = syms.iter().map(|(a, _)| *a).min().unwrap();
        let base = base.unwrap_or(linked);
        let syms = syms.into_iter().map(|(a, n)| (a - linked + base, n)).collect();
        Self { bytes, base, syms }
    }
    fn at(&self, name: &str) -> String {
        format!("{:#x}", self.syms.iter().find(|(_, n)| n == name).unwrap().0)
    }
}

/// A big-endian language reads and writes memory and registers big-endian, as its spaces say
/// (Ghidra's MemoryState reads each space in the space's own byte order). Checked on two
/// big-endian ISAs, over routines a real toolchain built (`src/big_endian_*.S`): a word read from
/// the bytes `12 34` is 0x1234, a byte read of `a1 b2 c3 d4` is 0xa1, a stored long lays its bytes
/// out most significant first. On the 68000 a word lands in D0's low half and a byte in its low
/// byte, and `movea.w #$c000` addresses 0xffffc000; on MIPS the loads sit in `jr $ra`'s delay slot.
#[test]
fn a_big_endian_machine_reads_and_writes_big_endian() {
    let c = ctx();
    let mut s = Session::open(None).unwrap();
    let mut run = |lang: &str, text: &RawText, name: &str, sp: &str| {
        let (base, entry) = (format!("{:#x}", text.base), text.at(name));
        let o = opts(&[("lang", lang), ("bytes", &text.bytes), ("base", &base), ("emulate.entry", &entry), ("emulate.registers", sp)]);
        emulation_rows(&dispatch(&c, &mut s, "sleigh.emulate", &o, &mut NoProgress).unwrap())
    };
    let value = |r: &[(String, String, String)], kind: &str, name: &str| r.iter().find(|(k, n, _)| k == kind && n == name).map(|(_, _, v)| v.clone());

    let m68k = RawText::load("big_endian.clang-m68k", Some(0x1000));
    let m = |name: &str, run: &mut dyn FnMut(&str, &RawText, &str, &str) -> Vec<(String, String, String)>| run("68000:BE:32:default", &m68k, name, "SP=0x00fff000");
    let r = m("read_word", &mut run);
    assert_eq!(value(&r, "register", "D0").as_deref(), Some("0x00001234"), "{r:?}");
    let r = m("read_byte_view", &mut run);
    assert_eq!(value(&r, "register", "D0").as_deref(), Some("0xffffffa1"), "{r:?}");
    let r = m("store_long", &mut run);
    assert_eq!(value(&r, "memory", "0x2000").as_deref(), Some("11223344"), "{r:?}");
    let r = m("store_high", &mut run);
    assert_eq!(value(&r, "memory", "0xffffc000").as_deref(), Some("5678"), "{r:?}");

    let mips = RawText::load("big_endian.clang-mips", None);
    let p = |name: &str, run: &mut dyn FnMut(&str, &RawText, &str, &str) -> Vec<(String, String, String)>| run("MIPS:BE:32:default", &mips, name, "sp=0x7fff0000");
    let r = p("read_word", &mut run);
    assert_eq!(value(&r, "register", "v0").as_deref(), Some("0x00001234"), "{r:?}");
    let r = p("read_byte_view", &mut run);
    assert_eq!(value(&r, "register", "v0").as_deref(), Some("0x000000a1"), "{r:?}");
    let r = p("read_long", &mut run);
    assert_eq!(value(&r, "register", "v0").as_deref(), Some("0xa1b2c3d4"), "{r:?}");
    let r = p("store_long", &mut run);
    assert_eq!(value(&r, "memory", "0x2000").as_deref(), Some("11223344"), "{r:?}");
}

/// `emulate.address-mask` decodes only the address lines a CPU drives: the MC68000 drives 24, so
/// with `0xffffff` the short address `($C000).w` (0xffffc000) and the long `$FFC000` are one cell,
/// and a jump to `$0100xxxx` lands on `$xxxx`. Without the mask they are distinct addresses; a
/// zero mask is refused.
#[test]
fn an_address_mask_folds_the_addresses_a_narrow_bus_cannot_tell_apart() {
    let c = ctx();
    let mut s = Session::open(None).unwrap();
    // 1000: move.w #$1234,($C000).w   1006: move.w ($FFC000).l,d0   100c: jmp ($01001012).l
    // 1012: moveq #7,d1               1014: rts
    let bytes = "31fc1234c000303900ffc0004ef90100101272074e75";
    let mut run = |mask: &str| {
        let mut o = vec![("lang", "68000:BE:32:default"), ("bytes", bytes), ("base", "0x1000"), ("emulate.registers", "SP=0x00fff000")];
        if !mask.is_empty() {
            o.push(("emulate.address-mask", mask));
        }
        dispatch(&c, &mut s, "sleigh.emulate", &opts(&o), &mut NoProgress).map(|t| emulation_rows(&t))
    };
    let value = |r: &[(String, String, String)], kind: &str, name: &str| r.iter().find(|(k, n, _)| k == kind && n == name).map(|(_, _, v)| v.clone());
    let r = run("0xffffff").unwrap();
    assert_eq!((value(&r, "outcome", "stop").as_deref(), value(&r, "register", "D0w").as_deref(), value(&r, "register", "D1").as_deref()), (Some("returned"), Some("0x1234"), Some("0x00000007")), "{r:?}");
    assert_eq!(value(&r, "memory", "0xffc000").as_deref(), Some("1234"), "{r:?}");
    let r = run("").unwrap();
    assert_eq!((value(&r, "outcome", "stop").as_deref(), value(&r, "outcome", "address").as_deref()), (Some("no-instruction"), Some("0x1001012")), "{r:?}");
    assert_eq!(value(&r, "memory", "0xffffc000").as_deref(), Some("1234"), "{r:?}");
    assert!(matches!(run("0"), Err(mosura_api::error::Error::InvalidArg(_))));
}
