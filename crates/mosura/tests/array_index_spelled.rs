//! The `array-index=spelled` axis, witnessed: a scaled-index access through a constant/global
//! base is spelled `((T *)base)[i]` ONLY where the original addresses it with a scaled-index
//! operand (wc2src-reconciliation-3 N3, the witness-first form).
//!
//! SELF-COMPILED fixture (examples/watcom_mve_fixtures.rs; source embedded): `gtbl[i]++` — a
//! global table incremented in place, which Watcom compiles to `INC dword ptr [EAX*4 + &gtbl]`
//! (a scaled-index operand). The reference is `piVar = (int *)(i*4 + &gtbl); *piVar = *piVar + 1`;
//! the axis inlines the temp and spells `((int *)&gtbl)[i]` at each deref — but only because the
//! byte witness (`buildconfig::array_index_sites_from_evidence`, run here on the fixture's own
//! bytes) sees the `*0x4` scaled operand. A pointer the original kept in a register would fail
//! the witness and keep the reference form (the zc63 lottery losses 0x19280 / 0x67950).
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::printc::{print_c, print_c_recovered, print_c_report, RecoveredChoices};
use mosura::decompile::{build, pipeline};
use mosura::recompile::buildconfig::array_index_sites_from_evidence;
use mosura::recompile::insn::{normalize, NoReloc};
use mosura::{datatest, paths};

#[test]
fn witnessed_scaled_index_access_spells_as_a_subscript() {
    let path = paths::oracle_fixtures_dir().join("x86_watcom_array_index.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id)
        .expect("the vendored x86 SLEIGH tables load (third_party/ghidra/Processors/x86)");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);

    let mut choices = EmitChoices::default();
    choices.set("array-index", "spelled").unwrap();

    // Reference: address arithmetic through a pointer temp (no recovered witness yet).
    let reference = print_c(&f);
    assert!(
        reference.contains("* 4 + 0x162000") && !reference.contains(")[param_1]"),
        "the reference keeps the pointer arithmetic:\n{reference}"
    );

    // The witness, run on the fixture's OWN bytes: the INC uses a *0x4 scaled operand.
    let (_, report) = print_c_report(&f, &choices);
    assert!(!report.array_index.candidates.is_empty(), "the access is an N3 candidate");
    let insns = normalize(lang_id, &dt.chunks[0].bytes, entry, &NoReloc).unwrap();
    let sites = array_index_sites_from_evidence(&report.array_index.candidates, &insns);
    assert!(!sites.is_empty(), "the witness accepts the scaled-index operand:\n{:x?}", report.array_index.candidates);

    let recovered = RecoveredChoices { array_index: mosura::decompile::emit::arms::array_index::Sites { sites: sites, ..Default::default() }, ..Default::default() };
    let c = print_c_recovered(&f, &choices, &recovered);
    assert!(
        c.contains("0x162000)[param_1]") && !c.contains("* 4 + 0x162000"),
        "the witnessed access spells the subscript:\n{c}"
    );
}
