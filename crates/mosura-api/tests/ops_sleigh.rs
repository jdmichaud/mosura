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
