//! A Watcom callee-save PUSH is not a parameter (wc2src-reconciliation D1).
//!
//! The fixture is SELF-COMPILED (examples/watcom_mve_fixtures.rs: wcc386 10.0a in-house, the profile's own
//! flags with `-d1+` for WAR2's frame path; source embedded in the fixture) — no game bytes.
//! It reproduces `maphdr_TYPE`'s exact opening, `52 55 89e5 83ec10`: PUSH EDX — the callee
//! preserving a register it is about to clobber — before the frame. mosura recovered that save
//! as a second parameter plus a dead `xStack_4 = param_2;` store, because the alias
//! classification treated every stack slot above the `&local` escape as aliased: the save-slot
//! INDIRECTs stayed addrforce-live, the store survived, and `recover_input_params` saw a used
//! EDX input (verified: the pre-fix tree at 2a79119 prints exactly that on this fixture).
//!
//! Ghidra's own C for the same fixture is ONE parameter, through a chain the OPACTION trace
//! named: `ActionRestrictLocal` carves the saved-EBP slot (unaffected), and
//! `ScopeLocal::markUnaliased` (varmap.cc:1332) does not propagate an alias across the unmapped
//! hole — "Aliases shouldn't go thru unmapped regions of the local variables" — so the save
//! slots above the carve classify `nolocalalias`, `RuleIndirectCollapse` folds their call
//! INDIRECTs, and the dead saves vanish before the prototype is read. The fixture pins the
//! ported walk (`varnodeprops::mark_addrtied` over ownership = localrange ∪ paramrange minus
//! `not_mapped`).
use mosura::decompile::printc::print_c;
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

#[test]
fn watcom_callee_save_push_is_not_a_parameter() {
    let path = paths::oracle_fixtures_dir().join("x86_watcom_callee_save.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id)
        .expect("the vendored x86 SLEIGH tables load (third_party/ghidra/Processors/x86)");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);
    let c = print_c(&f);
    let sig = c.lines().find(|l| l.contains("func(")).unwrap_or_else(|| panic!("no signature in:\n{c}"));
    assert!(
        sig.contains("(xunknown4 param_1)"),
        "one parameter — the EDX save is not an argument; got:\n{sig}\n\nfull:\n{c}"
    );
    assert!(
        !c.contains("param_2"),
        "no phantom parameter from the PUSH EDX save:\n{c}"
    );
    assert!(
        !c.contains("xStack_4 ="),
        "the dead save store must be eliminated, not rendered:\n{c}"
    );
    // The REAL local one slot below the saves — written by the callee through &ck and read at
    // the end — must survive the same classification (it is genuinely aliased).
    assert!(
        c.contains("= xStack_c;"),
        "the aliased local's read-back stays:\n{c}"
    );
}
