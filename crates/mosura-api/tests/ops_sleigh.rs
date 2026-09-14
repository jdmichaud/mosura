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
