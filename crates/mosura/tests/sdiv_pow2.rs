//! `sdiv-pow2=div` (docs/sdiv-pow2-arm.md): Watcom's SBB template for a signed division by a power
//! of two, lifted by Ghidra to `(x + (x >> 0x1f) * -0x20 - (x >> 0x1f << 4 < 0)) >> 5`, renders as
//! `x / 0x20` when the original bytes witness `SBB` + `SAR 5` at the shift's pc.
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::printc::{print_c_recovered, print_c_report, RecoveredChoices};
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

#[test]
fn sbb_template_renders_signed_division() {
    let path = paths::oracle_fixtures_dir().join("x86_sdiv_pow2_sbb.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id).expect("x86 SLEIGH tables load");
    let image: Vec<(u64, &[u8])> =
        dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);

    let mut choices = EmitChoices::default();
    choices.set("sdiv-pow2", "div").unwrap();
    let (reference, report) = print_c_report(&f, &choices);
    // the shift sits at the SAR EAX,5 (0x600e); the report offers it with n = 5
    assert!(
        report.sdiv_pow2.candidates.iter().any(|&(pc, n)| pc == 0x600e && n == 5),
        "expected the shift at 0x600e (n=5) as a candidate: {:?}",
        report.sdiv_pow2.candidates
    );
    assert!(reference.contains(">> 5"), "unwitnessed: the reference shift stays:\n{reference}");
    let recovered = RecoveredChoices { sdiv_pow2: mosura::decompile::emit::arms::sdiv_pow2::Sites { sites: [0x600e].into_iter().collect(), ..Default::default() }, ..Default::default() };
    let c = print_c_recovered(&f, &choices, &recovered);
    assert!(c.contains("/ 0x20"), "expected `x / 0x20`, got:\n{c}");
    assert!(!c.contains(">> 0x1f"), "the sign-shift chain must be gone:\n{c}");
}
