//! The `narrow-tests=rewiden` axis rewrites a shifted byte-of-word zero test to the operand's
//! own width (wc2src-reconciliation-2 A5).
//!
//! SELF-COMPILED fixture (examples/watcom_mve_fixtures.rs; source embedded): `*p & 0x200` on a
//! 16-bit field. The lifter recovers the predicate as `(*p >> 8 & 2) != 0` — the reference
//! rendering, which Watcom compiles with an extra shift; the axis prints `(*p & 0x200) != 0`,
//! value-identical and the form the compiler turns back into the original's sub-register test.
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::printc::{print_c, print_c_with};
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

#[test]
fn shifted_byte_test_rewidens_to_the_operand() {
    let path = paths::oracle_fixtures_dir().join("x86_watcom_narrow_test.xml");
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
        reference.contains(">> 8") && reference.contains("& 2"),
        "the reference keeps the lifter's shift-and-mask:\n{reference}"
    );

    let mut choices = EmitChoices::default();
    choices.set("narrow-tests", "rewiden").unwrap();
    let c = print_c_with(&f, &choices);
    assert!(
        c.contains("& 0x200") && !c.contains(">> 8"),
        "the axis tests the operand at width with the mask shifted up:\n{c}"
    );
}
