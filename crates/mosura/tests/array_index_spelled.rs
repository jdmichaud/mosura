//! The `array-index=spelled` axis renders a scaled-index access through a constant/global base
//! as an array subscript (wc2src-reconciliation-3 N3).
//!
//! SELF-COMPILED fixture (examples/watcom_mve_fixtures.rs; source embedded): `return gtbl[i]` —
//! a global table read once by a parameter. Ghidra's reference is the address arithmetic
//! `*(T *)(i*4 + &gtbl)`; the axis spells `((T *)&gtbl)[i]`, value-identical and the form Watcom
//! compiles to a scaled-index operand. The gate (single-deref, non-shared index) is satisfied by
//! the single read; a shared index or multi-deref pointer would keep the reference form (the
//! zc63 lottery losses).
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::printc::{print_c, print_c_with};
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

#[test]
fn scaled_index_global_access_spells_as_a_subscript() {
    let path = paths::oracle_fixtures_dir().join("x86_watcom_array_index.xml");
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
        reference.contains("* 4 + 0x9000)") && !reference.contains(")[param_1]"),
        "the reference keeps the address arithmetic:\n{reference}"
    );

    let mut choices = EmitChoices::default();
    choices.set("array-index", "spelled").unwrap();
    let c = print_c_with(&f, &choices);
    assert!(
        c.contains("0x9000)[param_1]") && !c.contains("* 4 + 0x9000"),
        "the axis spells the subscript:\n{c}"
    );
}
