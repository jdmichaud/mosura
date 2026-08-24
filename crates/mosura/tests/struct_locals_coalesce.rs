//! The `struct-locals=coalesce` axis declares a half-written 4-byte stack local once
//! (wc2src-reconciliation-2 A2ii).
//!
//! SELF-COMPILED fixture (examples/watcom_mve_fixtures.rs; source embedded): check_attack's
//! and unit_set_target's shape — a two-short GPOINT returned in EAX, kept as a local and read
//! by field. Ghidra's restructure (the reference rendering) keeps a 2-byte slot for the high
//! half (`iStack_e = (int2)(uVar1 >> 0x10)`) — faithful C the source never wrote. The axis
//! declares the one 4-byte local, fuses the half-stores into `uStack_10 = uVar1` (the
//! original's single `MOV dword ptr [EBP-x],EAX`) and reads the high half through the local's
//! address, the form the probe took check_attack from 0.571 to 0.957 with.
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::printc::{print_c, print_c_with};
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

#[test]
fn half_written_local_is_declared_once_and_read_by_address() {
    let path = paths::oracle_fixtures_dir().join("x86_watcom_split_local.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id)
        .expect("the vendored x86 SLEIGH tables load (third_party/ghidra/Processors/x86)");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);

    let reference = print_c(&f);
    assert!(
        reference.contains("iStack_e = (int2)(") && !reference.contains("&uStack_10"),
        "the reference keeps Ghidra's 2-byte slot:\n{reference}"
    );

    let mut choices = EmitChoices::default();
    choices.set("struct-locals", "coalesce").unwrap();
    let c = print_c_with(&f, &choices);
    assert!(c.contains("uint4 uStack_10;"), "one 4-byte local declared:\n{c}");
    assert!(c.contains("uStack_10 = uVar1;"), "the halves fuse into one whole-value store:\n{c}");
    assert!(
        c.contains("*((int2 *)&uStack_10 + 1)") && !c.contains("iStack_e"),
        "the high half reads through the local's address, no second slot:\n{c}"
    );
}
