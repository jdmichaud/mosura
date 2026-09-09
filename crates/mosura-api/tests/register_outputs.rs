//! docs/tasklist-2026-09-08.md items 8 and 11, on the regout MVE (oracle/ground-truth/regout.c +
//! regout_cstart.asm, Watcom x86-32): a callee that RETURNS its result in EBX — `add ebx,eax ; ret`
//! — must be declared so on BOTH sides of the call. The callee's own pragma carries `value [ebx]`,
//! and the caller's declaration of it carries `value [ebx]` and names EBX in `modify`: what the
//! caller's C reads as the call's product is what its declaration promises. Before this, the callee
//! recompiled to `ADD EAX,EBX` and the caller stored through EAX (both SAME_SHAPE, both wrong code).

use mosura_api::ops::{dispatch, NoProgress};
use mosura_api::{Context, ContextConfig, Format, Options, Session};

fn opts(pairs: &[(&str, &str)]) -> Options {
    let mut o = Options::new();
    for (k, v) in pairs {
        o.set(k, v).unwrap();
    }
    o
}

fn tu(c: &Context, s: &mut Session, entry: &str) -> String {
    let t = dispatch(c, s, "function.emit", &opts(&[("entry", entry), ("format", "tu")]), &mut NoProgress).unwrap();
    mosura_api::render::render(&t, Format::Text).unwrap()
}

#[test]
fn a_result_in_ebx_is_declared_on_both_sides_of_the_call() {
    if mosura_core::lang::load_cached("x86:LE:32:default").is_none() {
        return; // SLEIGH tables unavailable
    }
    let path = mosura_core::paths::ground_truth_dir().join("regout.watcom-x86-32");
    let c = Context::new(ContextConfig::default()).unwrap();
    let mut s = Session::open(None).unwrap();
    s.add_input(&std::fs::read(&path).unwrap(), "regout", None).unwrap();
    dispatch(&c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
    dispatch(&c, &mut s, "program.passes", &Options::new(), &mut NoProgress).unwrap();

    // the callee, bump_: `add ebx,eax ; ret` — takes EBX and EAX, returns the sum in EBX
    let callee = tu(&c, &mut s, "0x8048106");
    let own = callee.lines().find(|l| l.starts_with("#pragma aux FUN_08048106 ")).expect("the callee's own pragma");
    assert_eq!(own, "#pragma aux FUN_08048106 parm [ebx] [eax] value [ebx] modify [ebx];", "callee:\n{callee}");

    // the caller, use_: `pxVar1 = func_0x08048106(..); *pxVar1 = ..` reads the result from EBX
    let caller = tu(&c, &mut s, "0x8048109");
    let decl = caller.lines().find(|l| l.starts_with("#pragma aux func_0x08048106 ")).expect("the caller's declaration of it");
    assert!(decl.contains("value [ebx]"), "the caller declares where the result comes back: {decl}\n{caller}");
    let modify = decl.split("modify [").nth(1).and_then(|m| m.split(']').next()).unwrap_or("");
    assert!(modify.split(' ').any(|r| r == "ebx"), "and that the callee writes it: {decl}");
    assert!(caller.contains("func_0x08048106("), "the call is read as a value:\n{caller}");
}
