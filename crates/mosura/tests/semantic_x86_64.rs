//! Stage-1b **semantic** test (design §3.5): execute the lifted raw p-code in
//! mosura's interpreter and assert the *computed result*, not just the text. This
//! catches semantically-wrong lifts that disassembly/p-code-text matching can't.
//!
//! `f(a,b) = a*3 + (b>>2) - 5`, compiled with gcc -O2 (straight-line). Args in
//! EDI/ESI (x86-64 SysV), result in EAX. The expected value is the C semantics,
//! computed in Rust — so the p-code interpreter is checked against ground truth.

use mosura::sleigh::emu;
use mosura::{datatest, paths};

// x86-64 register varnode offsets (Ghidra `register` space).
const EDI: u64 = 0x38;
const ESI: u64 = 0x30;
const EAX: u64 = 0x0;

#[test]
fn x86_64_pcode_computes_correct_result() {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        eprintln!("skip: {} not found", sla.display());
        return;
    }
    let spec = mosura::speccache::get(&sla).expect("x86-64 spec");
    let context = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);

    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_sem.xml")).expect("fixture");
    let code = &dt.chunks[0].bytes;
    let base = dt.chunks[0].offset;

    let reference = |a: i32, b: i32| a.wrapping_mul(3).wrapping_add(b >> 2).wrapping_sub(5);

    for (a, b) in [(7, 40), (-3, 17), (1000, -64), (i32::MIN, 5), (-1, -1), (123456, 789)] {
        let m = emu::run(
            spec,
            code,
            base,
            &context,
            &[("register", EDI, a as u32 as u64, 4), ("register", ESI, b as u32 as u64, 4)],
        );
        let got = m.read("register", EAX, 4) as u32 as i32;
        assert_eq!(got, reference(a, b), "f({a}, {b})");
    }
    eprintln!("p-code interpreter: f(a,b)=a*3+(b>>2)-5 verified for all inputs");
}

#[test]
fn x86_64_pcode_executes_a_loop() {
    // sumto(n) = 1+2+...+n — a real loop (TEST/JLE … ADD/CMP/JNZ). Exercises the
    // interpreter's branch-following + flag-derived conditions over many iterations.
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        eprintln!("skip: {} not found", sla.display());
        return;
    }
    let spec = mosura::speccache::get(&sla).expect("x86-64 spec");
    let context = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);

    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_loop.xml")).expect("fixture");
    let code = &dt.chunks[0].bytes;
    let base = dt.chunks[0].offset;

    let reference = |n: i32| if n <= 0 { 0 } else { n * (n + 1) / 2 };

    for n in [0, 1, 2, 5, 10, 100, 1000, -7] {
        let m = emu::run(spec, code, base, &context, &[("register", EDI, n as u32 as u64, 4)]);
        let got = m.read("register", EAX, 4) as u32 as i32;
        assert_eq!(got, reference(n), "sumto({n})");
    }
    eprintln!("p-code interpreter: sumto(n)=n*(n+1)/2 verified across loop iterations");
}
