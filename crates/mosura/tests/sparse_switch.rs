//! `sparse-switch=switch` (docs/wc2src-reconciliation-4.md W5): Watcom compiles a sparse `switch`
//! into a balanced compare tree on the scrutinee (pivot = lower median of the sorted cases); Ghidra
//! structures it as nested if/else. The arm walks that tree with interval narrowing and prints the
//! `switch` the source wrote: the case set from the tree (empty cases and range-pruned singletons
//! included), bodies in address order, the single-use scrutinee load inlined.
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::printc::{print_c_recovered, print_c_report, RecoveredChoices};
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

#[test]
fn compare_tree_renders_as_the_sparse_switch() {
    let path = paths::oracle_fixtures_dir().join("x86_14620_sparse_switch.xml");
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id).expect("x86 SLEIGH tables load");
    let image: Vec<(u64, &[u8])> =
        dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);

    let (reference, _) = print_c_report(&f, &EmitChoices::default());
    assert!(!reference.contains("switch ("), "the reference rendering is the if/else tree:\n{reference}");
    let mut choices = EmitChoices::default();
    choices.set("sparse-switch", "switch").unwrap();
    // the compare witness from the specimen's own bytes (the survey builds it the same way)
    let insns = mosura::recompile::insn::normalize(lang_id, dt.chunks[0].bytes.as_slice(), entry, &mosura::recompile::insn::NoReloc).unwrap_or_default();
    let recovered = RecoveredChoices { sparse_switch: mosura::decompile::emit::arms::sparse_switch::Sites { sites: mosura::recompile::buildconfig::sparse_cmps_from_evidence(&insns), ..Default::default() }, ..Default::default() };
    assert!(!recovered.sparse_switch.sites.is_empty(), "the witness saw the tree's compares");
    let c = print_c_recovered(&f, &choices, &recovered);
    assert!(c.contains("switch (*((uint1 *)(param_1 + 6))) {"), "the scrutinee load is inlined:\n{c}");
    let mut cases: Vec<u64> = c
        .lines()
        .filter_map(|l| l.trim().strip_prefix("case ").and_then(|r| r.strip_suffix(':')))
        .map(|k| if let Some(h) = k.strip_prefix("0x") { u64::from_str_radix(h, 16).unwrap() } else { k.parse().unwrap() })
        .collect();
    cases.sort();
    assert_eq!(cases, vec![4, 0xc, 0xd, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x19, 0x1a], "the case set from the tree:\n{c}");
    assert!(c.contains("case 0xd:\n    break;"), "0xd is an explicit empty case:\n{c}");
    assert!(c.contains("case 4:\n  case 0x10:") || c.contains("case 4:\n    case 0x10:"), "4 and 0x10 share a body:\n{c}");
    assert!(c.contains("default:"), "the tree's remainder is the default:\n{c}");
}
