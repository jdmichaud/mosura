//! The `arm-order=address` axis prints a two-arm if/else in the ORIGINAL's layout order
//! (wc2src-reconciliation-2 A1).
//!
//! SELF-COMPILED fixture (examples/watcom_mve_fixtures.rs; source embedded): attack_can_hit's
//! shape — a guard clause `if (flags & 4) return tbl[t] & 2;` written FIRST, then the general
//! case. The structurer's canonical order (the reference rendering, unchanged under the default
//! axis value) prints the guard as the trailing `else`; the compiler laid the guard's arm right
//! after the conditional jump, at the lower address, and the axis prints it first with the
//! condition negated to match. The single-block-condition gate keeps that negation exact.
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::printc::{print_c, print_c_with};
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

#[test]
fn address_order_prints_the_guard_arm_first() {
    let path = paths::oracle_fixtures_dir().join("x86_watcom_guard_order.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id)
        .expect("the vendored x86 SLEIGH tables load (third_party/ghidra/Processors/x86)");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);

    // Reference order: the general case first, the guard's `& 2` arm trailing.
    let reference = print_c(&f);
    let (r1, r2) = (reference.find("& 1").unwrap(), reference.find("& 2").unwrap());
    assert!(r1 < r2, "reference rendering keeps the structurer's order:\n{reference}");

    // Address order: the guard arm (lower address) first, condition negated to `!= 0`.
    let mut choices = EmitChoices::default();
    choices.set("arm-order", "address").unwrap();
    let laid = print_c_with(&f, &choices);
    let (a2, a1) = (laid.find("& 2").unwrap(), laid.find("& 1").unwrap());
    assert!(a2 < a1, "the arm the original compiled first prints first:\n{laid}");
    assert!(
        laid.contains("(param_1 & 4) != 0"),
        "the swapped arms carry an exactly negated condition:\n{laid}"
    );
}
