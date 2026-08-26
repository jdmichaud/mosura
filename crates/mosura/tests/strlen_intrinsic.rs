//! `string-ops=intrinsic` V3 (docs/rep-string-intrinsic-arm.md): a lifted `REPNE SCASB` scan
//! seeded with `ECX = -1`, `AL = 0`, whose exit count feeds Watcom's `NOT ECX; DEC ECX` result
//! chain, is `strlen(s)`; witnessed on the original bytes `F2 AE`, it renders as `strlen(s)` in
//! place of the loop so Watcom's `#pragma intrinsic(strlen)` re-emits the template byte-for-byte.
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::printc::{print_c_recovered, print_c_report, RecoveredChoices};
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

#[test]
fn repne_scasb_renders_strlen() {
    let path = paths::oracle_fixtures_dir().join("x86_repne_scasb.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id).expect("x86 SLEIGH tables load");
    let image: Vec<(u64, &[u8])> =
        dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);

    let mut choices = EmitChoices::default();
    choices.set("string-ops", "intrinsic").unwrap();
    let (_, report) = print_c_report(&f, &choices);
    // The scan loop sits at the REPNE SCASB (0x600a); the report offers it as a candidate.
    assert!(
        report.rep_movs_candidates.iter().any(|&(pc, _)| pc == 0x600a),
        "the REPNE SCASB loop at 0x600a should be a string-ops candidate: {:?}",
        report.rep_movs_candidates
    );
    let recovered = RecoveredChoices { string_op_sites: [0x600a].into_iter().collect(), ..Default::default() };
    let c = print_c_recovered(&f, &choices, &recovered);
    assert!(c.contains("return strlen(param_1);"), "expected `return strlen(param_1);`, got:\n{c}");
    assert!(!c.contains("0xffffffff") && !c.contains("do {"), "loop and -1 seed must be gone:\n{c}");
}
