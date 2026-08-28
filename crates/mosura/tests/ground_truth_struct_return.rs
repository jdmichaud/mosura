//! The `struct-return` arm on the ground-truth program that motivated it (docs/struct-return-arm.md):
//! structval's `static struct pt mk(int a, int b)` in the 32-bit gcc column. Under the plain plan
//! (the reference rendering) `mk` is Ghidra's `void __regparm3 mk(xunknown4 *param_1, ..)` and the
//! program FAILs (the harness's cdecl caller expects the callee-pop `ret $4` of the hidden pointer);
//! under the arms plan the witness (both call sites drop the pointer and pass a local's address)
//! renders the struct-returning function and its caller's typed local, and the program PASSes.
//! One `gcc -m32` build, one analysis, two renders — seconds; the whole column is the opt-in
//! gt-arms test.
use mosura::recompile::groundtruth::{analyze_program, gcc_available, render_and_check, EmitPlan, GtReport, Target};

fn text_of<'r>(r: &'r GtReport, symbol: &str) -> &'r str {
    &r.functions.iter().find(|f| f.symbol == symbol).unwrap_or_else(|| panic!("{symbol} in {}", r.program)).c
}

#[test]
fn structval_32bit_returns_the_struct_under_the_arms_plan_only() {
    assert!(gcc_available(), "gcc is required by the development environment (ground-truth recompile gate)");
    let root = mosura::paths::workspace_root();
    let workdir = root.join("build/gt-recompile");
    std::fs::create_dir_all(&workdir).unwrap();
    let src = root.join("oracle/ground-truth/src/structval.c");
    let analyzed = analyze_program(&src, &workdir, Target::Gcc32).expect("structval 32-bit analysis");
    let plain = render_and_check(&analyzed, &workdir, &EmitPlan::plain()).expect("plain render");
    let arms = render_and_check(&analyzed, &workdir, &EmitPlan::arms()).expect("arms render");

    // the reference rendering is Ghidra's: the hidden pointer an explicit parameter, no return
    let mk_plain = text_of(&plain, "mk");
    assert!(mk_plain.contains("void __regparm3 FUN_08049000(xunknown4 * param_1, xunknown4 param_2, xunknown4 param_3)"), "{mk_plain}");
    assert!(plain.functional.starts_with("FAIL"), "plain-32 structval: {}", plain.functional);

    // the arm: the definition returns the struct through a local, the hidden parameter is gone
    let mk_arms = text_of(&arms, "mk");
    for expected in [
        "struct s8_x4x4 { xunknown4 f0; xunknown4 f4; };",
        "struct s8_x4x4 __regparm3 FUN_08049000(xunknown4 param_2, xunknown4 param_3)",
        "struct s8_x4x4 __ret;",
        "__ret.f0 = param_2;",
        "__ret.f4 = param_3;",
        "return __ret;",
    ] {
        assert!(mk_arms.contains(expected), "mk under arms lacks `{expected}`:\n{mk_arms}");
    }
    // the caller: the local is the struct, the calls assign it, its slots are its fields
    let start_arms = text_of(&arms, "_start");
    for expected in [
        "struct s8_x4x4 xStack_14;",
        "xStack_14 = func_0x08049000(3, 4);",
        "xStack_14 = func_0x08049000(5, 6);",
        "xStack_14.f0",
        "xStack_14.f4",
    ] {
        assert!(start_arms.contains(expected), "_start under arms lacks `{expected}`:\n{start_arms}");
    }
    assert!(!start_arms.contains("&xStack_14"), "the hidden pointer argument is gone:\n{start_arms}");
    assert_eq!(arms.functional, "PASS", "arms-32 structval");
}
