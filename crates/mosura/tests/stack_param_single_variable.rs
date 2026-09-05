//! A stack parameter reads as ONE variable across calls (the zc48 down class).
//!
//! The fixture is SELF-COMPILED (examples/watcom_mve_fixtures.rs: a `__cdecl` dispatch chain, wcc386
//! 10.0a in-house, source embedded in the fixture) — no game bytes. Like the subject's 0x6c390 it
//! takes two stack parameters and re-reads them after every call in a long dispatch chain. The call-crossing INDIRECTs on the parameter slots must collapse
//! (`RuleIndirectCollapse` on `nolocalalias`) so every read prints through the parameter —
//! Ghidra's shape for the same fixture. When the classification kept the slots merely
//! `mapped|addrtied` without recording the walk's unaliased verdict, the INDIRECTs survived
//! and each post-call read split into a fresh local (`iVar1 = param_2;`), 27 functions of
//! form regression. `varnodeprops::StackClass::ParamUnaliased` is the pinned answer: symbol
//! flags kept, `nolocalalias` recorded.
use mosura::decompile::printc::print_c;
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

#[test]
fn stack_params_do_not_split_across_calls() {
    let path = paths::oracle_fixtures_dir().join("x86_watcom_stack_param_single_var.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id)
        .expect("the vendored x86 SLEIGH tables load (third_party/ghidra/Processors/x86)");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);
    let c = print_c(&f);
    assert!(
        !c.contains("= param_1;") && !c.contains("= param_2;"),
        "no parameter-copy split — the slot's INDIRECTs must collapse:\n{c}"
    );
    let direct = c.matches("param_2 * 4").count();
    assert!(
        direct >= 10 && c.matches("param_1 + 0x").count() >= 10,
        "the dispatch chain reads the parameters directly at every site (got {direct}):\n{c}"
    );
}
