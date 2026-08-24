//! An open stack range stops at the scope's ownership hole (wc2src-reconciliation-2 A2i).
//!
//! SELF-COMPILED fixture (examples/watcom_mve_fixtures.rs; source embedded): sfile_make_name's
//! frame shape byte-for-byte — `53 51 52 55 89e5 83ec0c`, three killed-register saves above
//! the EBP frame and a 12-byte buffer whose address escapes. `ActionRestrictLocal` carves the
//! saved-EBP slot out of the local window; Ghidra's `ScopeLocal::adjustFit` (`longestFit`)
//! then clips the buffer's open range at that hole, so it declares `[12]`. Without the clip the
//! range ran through the hole to the frame top — sfile's `[28]` and a `SUB ESP,0x1c` for the
//! original's `0xc`. The pre-campaign tree prints four parameters and `[16]` on this fixture.
use mosura::decompile::printc::print_c;
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

#[test]
fn open_range_is_clipped_at_the_callee_save_hole() {
    let path = paths::oracle_fixtures_dir().join("x86_watcom_frame_extent.xml");
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
        c.contains("axStack_1c [12];"),
        "the buffer is its 12 bytes, clipped at the saved-EBP hole (Ghidra's declaration):\n{c}"
    );
    assert!(
        !c.contains("param_2"),
        "the killed-register saves are not parameters (D1) on this shape either:\n{c}"
    );
}
