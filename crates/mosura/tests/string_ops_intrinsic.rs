//! `string-ops=intrinsic` (docs/rep-string-intrinsic-arm.md): a lifted `REP MOVSD` loop, when the
//! original instruction is witnessed to be `REP MOVS`, renders as `memcpy(dst, src, n*4)` instead of
//! the counted `for` loop — so Watcom's `-oi` re-inlines it to `REP MOVSD`. Witness-first, two-pass.
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::printc::{print_c_recovered, print_c_report, RecoveredChoices};
use mosura::decompile::{build, pipeline};
use mosura::recompile::insn::{normalize, NoReloc};
use mosura::{datatest, paths};

#[test]
fn rep_movsd_renders_memcpy_when_witnessed() {
    let path = paths::oracle_fixtures_dir().join("x86_repmovsd.xml");
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

    // Report pass: the rep-movsd loop is recorded as a candidate.
    let (_, report) = print_c_report(&f, &choices);
    assert!(
        !report.rep_movs_candidates.is_empty(),
        "the REP MOVSD loop should be a string-ops candidate"
    );

    // Witness: the original bytes at the candidate pc are `REP MOVS`.
    let insns = normalize("x86:LE:32:default", &dt.chunks[0].bytes, entry, &NoReloc).unwrap_or_default();
    let sites =
        mosura::recompile::buildconfig::string_ops_from_evidence(&report.rep_movs_candidates, &insns);
    assert!(!sites.is_empty(), "the candidate is witnessed as REP MOVS (F3 A5)");

    // Apply pass: the loop collapses to a memcpy call sized in bytes (n * 4 for movsd).
    let recovered = RecoveredChoices { string_op_sites: sites, ..Default::default() };
    let c = print_c_recovered(&f, &choices, &recovered);
    assert!(c.contains("memcpy("), "renders a memcpy call:\n{c}");
    assert!(c.contains("* 4"), "sized in bytes (dwords * 4):\n{c}");
    assert!(!c.contains("for ("), "the counted loop is gone:\n{c}");

    // Default (loop) arm is unchanged — still the for loop, no memcpy.
    let loop_c = mosura::decompile::printc::print_c(&f);
    assert!(loop_c.contains("for (") && !loop_c.contains("memcpy("), "default keeps the loop");
}

#[test]
fn rep_movs_pair_renders_one_memcpy() {
    let path = paths::oracle_fixtures_dir().join("x86_repmovs_pair.xml");
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
    assert_eq!(report.rep_movs_candidates.len(), 2, "both loops of the pair are candidates: {:?}", report.rep_movs_candidates);
    let insns = normalize("x86:LE:32:default", &dt.chunks[0].bytes, entry, &NoReloc).unwrap_or_default();
    let sites = mosura::recompile::buildconfig::string_ops_from_evidence(&report.rep_movs_candidates, &insns);
    assert_eq!(sites.len(), 2, "F2-prefixed MOVSD/MOVSB are both witnessed");
    let recovered = RecoveredChoices { string_op_sites: sites, ..Default::default() };
    let c = print_c_recovered(&f, &choices, &recovered);
    eprintln!("=== PAIR C ===\n{c}");
    assert_eq!(c.matches("memcpy(").count(), 1, "the pair collapses to ONE memcpy:\n{c}");
    assert!(!c.contains("while") && !c.contains("for ("), "no loops remain:\n{c}");
}

#[test]
fn repe_cmpsb_renders_memcmp_result() {
    let path = paths::oracle_fixtures_dir().join("x86_repe_cmpsb.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id).expect("x86 SLEIGH tables load");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);
    let mut choices = EmitChoices::default();
    choices.set("string-ops", "intrinsic").unwrap();
    let (_, report) = print_c_report(&f, &choices);
    assert_eq!(report.rep_movs_candidates.len(), 1, "the REPE CMPSB loop is a candidate: {:?}", report.rep_movs_candidates);
    let insns = normalize("x86:LE:32:default", &dt.chunks[0].bytes, entry, &NoReloc).unwrap_or_default();
    let sites = mosura::recompile::buildconfig::string_ops_from_evidence(&report.rep_movs_candidates, &insns);
    assert_eq!(sites.len(), 1, "F3 A6 is witnessed");
    let recovered = RecoveredChoices { string_op_sites: sites, ..Default::default() };
    let c = print_c_recovered(&f, &choices, &recovered);
    eprintln!("=== MEMCMP C ===\n{c}");
    assert!(c.contains("= memcmp(param_1, param_2, param_3);"), "renders the result assignment:\n{c}");
    assert!(!c.contains("do {") && !c.contains("while") && !c.contains("bVar"), "loop, flags and the if-block are gone:\n{c}");
}
