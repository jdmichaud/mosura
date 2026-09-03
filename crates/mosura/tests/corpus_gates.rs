//! `recompile::gates` (review R4) on hand-made strings: one positive and one negative case per
//! gate, the baseline's rules, the tree loader, and the report's shape.
use mosura::recompile::gates::*;
use std::collections::BTreeMap;

fn tu(va: u64, text: &str) -> Tu {
    Tu { va, name: format!("FUN_{va:08x}"), text: text.to_string(), columns: BTreeMap::new() }
}

const CLEAN: &str = "void f(void)\n{\n  int4 iStack_8;\n  xunknown1 axStack_d8 [204];\n  int4 * piVar2;\n  iStack_8 = 1;\n  axStack_d8[6] = 0x1f;\n  piVar2 = (int4 *)(axStack_d8 + 0x50);\n  return;\n}\n";

#[test]
fn declared_symbols_flags_a_use_without_a_declaration() {
    let clean = tu(0x1000, CLEAN);
    let bad = tu(0x2000, "void g(void)\n{\n  int4 iVar1;\n  iVar1 = aiStack_2c[0] + uStack_10;\n  return;\n}\n");
    let r = declared_symbols(&[clean.clone()]);
    assert!(!r.failed(), "{r}");
    let r = declared_symbols(&[bad, clean]);
    assert!(r.failed(), "{r}");
    assert_eq!(r.hits().len(), 1);
    let h = &r.hits()[0];
    assert_eq!(h.va, 0x2000);
    assert!(h.detail.contains("aiStack_2c") && h.detail.contains("uStack_10"), "{}", h.detail);
    assert!(h.detail.contains("iVar1 = aiStack_2c[0] + uStack_10;"), "the offending line rides along: {}", h.detail);
    // a statement is not a declaration of its identifier (fable-b's pre-read: a swallowed array whose
    // only remaining use is a return statement must not pass)
    let ret = tu(0x2100, "int4 h(void)\n{\n  return aiStack_2c[0];\n}\n");
    let goto = tu(0x2200, "void k(void)\n{\n  goto LAB_1;\nLAB_1:\n  return uStack_10;\n}\n");
    let r = declared_symbols(&[ret, goto]);
    assert_eq!(r.hits().iter().map(|h| h.va).collect::<Vec<_>>(), vec![0x2100, 0x2200], "{r}");
    let declared_then_returned = tu(0x2300, "int4 m(void)\n{\n  int4 iStack_8;\n  iStack_8 = 2;\n  return iStack_8;\n}\n");
    assert!(!declared_symbols(&[declared_then_returned]).failed());
}

#[test]
fn piece_on_field_and_call_as_argument() {
    let piece = tu(0x3000, "  uVar1 = (param_1->field_0x4)._0_2_;\n");
    let piece_ok = tu(0x3100, "  uVar1 = uVar2._0_2_;\n");
    let r = piece_on_field(&[piece_ok.clone(), piece]);
    assert!(r.failed() && r.hits().len() == 1 && r.hits()[0].va == 0x3000, "{r}");
    assert!(!piece_on_field(&[piece_ok]).failed());
    let call = tu(0x4000, "  memcpy(func_0x00012340(param_1), param_2, 0x30);\n");
    let strlen = tu(0x4100, "  iVar1 = strlen( func_0x00012340(param_1));\n");
    let ok = tu(0x4200, "  memcpy(auStack_44, param_1, 0x30);\n  iVar1 = strlen(param_2);\n");
    let r = call_as_argument(&[strlen, ok.clone(), call]);
    assert!(r.failed(), "{r}");
    assert_eq!(r.hits().iter().map(|h| h.va).collect::<Vec<_>>(), vec![0x4000, 0x4100], "sorted by va");
    assert!(!call_as_argument(&[ok]).failed());
}

#[test]
fn string_ops_bar_is_a_floor_over_the_scope() {
    let mut bar = BTreeMap::new();
    bar.insert("memcpy(".to_string(), 2usize);
    bar.insert("memset(".to_string(), 0usize);
    let a = tu(0x5000, "  memcpy(a, b, 4);\n");
    let b = tu(0x5100, "  memcpy(c, d, 8);\n");
    let r = string_ops_bar([&a, &b].into_iter(), &bar);
    assert!(!r.failed(), "{r}");
    assert!(r.note.contains("memcpy=2") && r.note.contains("bar 2/0"), "{}", r.note);
    let r = string_ops_bar([&a].into_iter(), &bar);
    assert!(r.failed(), "{r}");
    assert_eq!(r.hits()[0].detail, "1 < the bar 2");
    // the scope is the caller's: a predicate that drops `b` drops its count
    let tus = vec![a, b];
    let in_scope = |t: &Tu| t.va < 0x5100;
    let r = string_ops_bar(tus.iter().filter(|t| in_scope(t)), &bar);
    assert!(r.failed());
}

#[test]
fn chains_never_switch_and_missing_chain() {
    let chain_ok = tu(0x6000, "  if (x == 1) {\n  }\n  else if (x == 2) {\n  }\n");
    let chain_bad = tu(0x6100, "  switch (x) {\n  case 1:\n    break;\n  }\n");
    let r = chains_never_switch(&[chain_ok.clone(), chain_bad], &[0x6000, 0x6100, 0x6200]);
    assert!(r.failed(), "{r}");
    let hits = r.hits();
    assert_eq!(hits.len(), 2);
    assert!(hits[0].va == 0x6100 && hits[0].detail.starts_with("prints a switch — switch (x) {"), "{}", hits[0].detail);
    assert!(hits[1].va == 0x6200 && hits[1].detail == "missing from the tree");
    assert!(!chains_never_switch(&[chain_ok], &[0x6000]).failed());
}

#[test]
fn switch_labels_count_case_lines() {
    let sw = tu(0x7000, "  switch (x) {\n  case 1:\n  case 2:\n    f();\n    break;\n  default:\n    break;\n  }\n  /* case in a comment does not count */\n");
    let mut labels = BTreeMap::new();
    labels.insert(0x7000u64, 2usize);
    assert!(!switch_labels(&[sw.clone()], &labels).failed());
    labels.insert(0x7000, 3);
    let r = switch_labels(&[sw], &labels);
    assert!(r.failed() && r.hits()[0].detail == "2 case labels, expected 3", "{r}");
    labels.clear();
    labels.insert(0x7100, 0);
    assert!(switch_labels(&[], &labels).failed(), "a missing switch TU is a hit");
}

const HEADER: &str = "idx\tva\tname\tverdict\tbytes\tprimary\tsim\tequal\torig_n\tcand_n\tclasses\n";

fn table(rows: &[(u64, &str, f64, u64, u64)]) -> BTreeMap<u64, VerdictRow> {
    let mut t = HEADER.to_string();
    for (i, (va, v, sim, eq, n)) in rows.iter().enumerate() {
        t.push_str(&format!("{i:05}\t{va:08x}\tFUN_{va:08x}\t{v}\t-\t-\t{sim}\t{eq}\t{n}\t{n}\t\n"));
    }
    parse_verdicts(&t).unwrap()
}

#[test]
fn verdict_rows_parse_by_header_and_wgss_is_the_canonical_census() {
    // three hand rows (verdict, sim = equal/max(orig,cand), equal, orig_n; cand_n = orig_n in `table`):
    //   A: 10 insns, sim 1.0 (10 equal)          → orig·sim = 10
    //   B: 10 insns, sim 0.4 (8 equal of max 20) → orig·sim = 4   (Σ equal/Σ orig would say 0.8 here)
    //   C: 20 insns, COMPILE_FAIL, sim 0          → 0
    // canonical (scripts/war2-verdicts.sh): Σ orig·sim / Σ orig = 14 / 40 = 0.35;
    // the other two formulas give 18/40 = 0.45 (Σ equal/Σ orig) and 18/50 = 0.36 (Σ equal/Σ max).
    let rows = table(&[(0x100, "EXACT", 1.0, 10, 10), (0x200, "MISMATCH", 0.4, 8, 10), (0x300, "COMPILE_FAIL", 0.0, 0, 20)]);
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[&0x200].verdict, "MISMATCH");
    assert!((wgss(&rows) - 0.35).abs() < 1e-9, "canonical census, got {}", wgss(&rows));
    assert!((wgss(&rows) - 0.45).abs() > 1e-3 && (wgss(&rows) - 0.36).abs() > 1e-3);
    let stamped = HEADER.trim_end().to_string() + "\tEXCLUDE-FOREIGN=x\n00000\t00000100\tf\tEXACT\t-\t-\t1\t1\t1\t1\t\n";
    assert_eq!(parse_verdicts(&stamped).unwrap().len(), 1, "the foreign-scope header column is harmless");
    assert!(parse_verdicts("idx\tva\n").is_err(), "a table without a verdict column is refused");
}

#[test]
fn guard_sets_exact_skip_only_on_a_partial_table() {
    let rows = table(&[(0x100, "EXACT", 1.0, 10, 10), (0x200, "SAME_SHAPE", 0.8, 8, 10)]);
    let r = guard_sets_exact(&rows, &[0x100], &[0x200], &[], false);
    assert!(r.failed() && r.hits().len() == 1 && r.hits()[0].detail.starts_with("volatile guard is SAME_SHAPE"), "{r}");
    let r = guard_sets_exact(&rows, &[0x100, 0x300], &[], &[], false);
    assert!(r.failed() && r.hits()[0].detail == "frame guard not in the verdict table", "{r}");
    let r = guard_sets_exact(&rows, &[0x100, 0x300], &[], &[], true);
    assert!(!r.failed() && r.note.contains("1 outside --only skipped"), "{r}");
    let r = guard_sets_exact(&rows, &[0x300], &[0x400], &[], true);
    assert!(matches!(r.outcome, Outcome::Skip(_)), "all guards outside --only: SKIP, never a silent pass: {r}");
}

#[test]
fn verdict_regressions_fail_only_on_exact_lost_or_new_compile_fail() {
    let prev = table(&[
        (0x100, "EXACT", 1.0, 10, 10),
        (0x200, "SAME_SHAPE", 0.8, 8, 10),
        (0x300, "MISMATCH", 0.5, 5, 10),
        (0x400, "SAME_SHAPE", 0.9, 9, 10),
        (0x500, "MISMATCH", 0.4, 4, 10),
        (0x700, "MISMATCH", 0.3, 3, 10),
        (0x800, "COMPILE_FAIL", 0.0, 0, 10),
    ]);
    let cur = table(&[
        (0x100, "SAME_SHAPE", 0.9, 9, 10),     // EXACT lost: FAIL
        (0x200, "MISMATCH", 0.6, 6, 10),       // a down, listed
        (0x300, "COMPILE_FAIL", 0.0, 0, 10),   // new COMPILE_FAIL: FAIL
        (0x400, "SAME_SHAPE", 0.7, 7, 10),     // same verdict, lower sim: listed
        (0x500, "EXACT", 1.0, 10, 10),         // up
        (0x600, "EXACT", 1.0, 10, 10),         // new row
        (0x700, "DECOMPILE_FAIL", 0.0, 0, 10), // a decompiler crash where a candidate was measured: FAIL
        (0x800, "OBJ_ERROR", 0.0, 0, 10),      // one failure verdict for another: neither FAIL nor a down
    ]);
    let r = verdict_regressions(&prev, &cur);
    assert!(r.failed(), "{r}");
    let hits = r.hits();
    assert_eq!(hits.len(), 3, "{r}");
    assert!(hits[0].va == 0x100 && hits[0].detail.starts_with("EXACT lost: now SAME_SHAPE"), "{}", hits[0].detail);
    assert!(hits[1].va == 0x300 && hits[1].detail.starts_with("new COMPILE_FAIL (was MISMATCH"), "{}", hits[1].detail);
    assert!(hits[2].va == 0x700 && hits[2].detail.starts_with("new DECOMPILE_FAIL (was MISMATCH"), "{}", hits[2].detail);
    assert!(r.note.contains("2 down(s) listed"), "{}", r.note);
    assert!(r.note.contains("0x200 FUN_00000200: SAME_SHAPE -> MISMATCH, sim 0.800 -> 0.600"), "{}", r.note);
    assert!(r.note.contains("0x400 FUN_00000400: SAME_SHAPE -> SAME_SHAPE, sim 0.900 -> 0.700"), "{}", r.note);
    // the delta over the 7 common rows: prev (10+8+5+9+4+3+0)/70, cur (9+6+0+7+10+0+0)/70 — the new row 0x600 stays out
    assert!(r.note.contains("7 common rows, 1 new, 0 gone") && r.note.contains("WGSS over the common rows 0.5571 -> 0.4571 (-0.1000)"), "{}", r.note);
    let rendered = r.to_string();
    assert!(rendered.contains("FAIL 8 verdict-regressions: 3 hit(s)") && rendered.contains("    note:"), "{rendered}");
    // an unchanged round is OK with an empty listing
    let r = verdict_regressions(&prev, &prev);
    assert!(!r.failed() && r.note.contains("0 down(s) listed"), "{r}");
}

#[test]
fn baseline_parses_rules_and_rejects_the_wrong_ones() {
    let ok = "# c\ngate\tkey\trule\tvalue\tset_at\nstring_ops_bar\tmemcpy(\t>=\t62\tw6a\nchain\t0x429d0\tno-switch\t-\tw5c\nswitch_labels\t0x14620\t==\t12\tw5c\nguard_frame\t0x225e0\tEXACT\t-\tw4\nguard_volatile\t0x125bc\tEXACT\t-\tf695\n";
    let b = Baseline::parse(ok).unwrap();
    assert_eq!(b.string_ops_bar()["memcpy("], 62);
    assert_eq!(b.chains(), vec![0x429d0]);
    assert_eq!(b.switch_labels()[&0x14620], 12);
    assert_eq!(b.guards("guard_frame"), vec![0x225e0]);
    assert_eq!(b.guards("guard_volatile"), vec![0x125bc]);
    let wrong_rule = "gate\tkey\trule\tvalue\tset_at\nstring_ops_bar\tmemcpy(\t==\t62\tw6a\n";
    assert!(Baseline::parse(wrong_rule).unwrap_err().contains("takes rule `>=`"));
    let bad_count = "gate\tkey\trule\tvalue\tset_at\nswitch_labels\t0x14620\t==\ttwelve\tw5c\n";
    assert!(Baseline::parse(bad_count).unwrap_err().contains("not a count"));
    let no_stamp = "gate\tkey\trule\tvalue\tset_at\nchain\t0x429d0\tno-switch\t-\t\n";
    assert!(Baseline::parse(no_stamp).unwrap_err().contains("set_at is empty"));
    assert!(Baseline::parse("gate\tkey\n").unwrap_err().contains("header"));
    assert!(Baseline::parse("gate\tkey\trule\tvalue\tset_at\nfoo\tx\t>=\t1\tw\n").unwrap_err().contains("unknown gate"));
}

#[test]
fn the_committed_baseline_loads_with_the_expected_sets() {
    let b = Baseline::load(&mosura::paths::corpus_gates_file()).unwrap();
    assert_eq!(b.string_ops_bar().len(), 4);
    // 12 at w5c; 0x14b44 and 0x3d470 left the chain set when the narrow one-case switch printed
    // in them and recompiled closer (round e2: 0.455 -> 0.545, 0.438 -> 0.500)
    assert_eq!(b.chains().len(), 10);
    assert_eq!(b.switch_labels().len(), 19);
    assert_eq!(b.guards("guard_frame").len(), 16);
    assert_eq!(b.guards("guard_volatile").len(), 14);
    // the dropped-parameter (phantom) specimens, EXACT since round e10 (docs/exact-arms.md)
    assert_eq!(b.guards("guard_phantom").len(), 2);
    assert!(b.rows.iter().all(|r| !r.set_at.is_empty()));
}

#[test]
fn load_tree_joins_the_manifest_with_the_recovered_files() {
    let dir = std::env::temp_dir().join(format!("corpus_gates_tree_{}", std::process::id()));
    let rec = dir.join("recovered");
    std::fs::create_dir_all(&rec).unwrap();
    std::fs::write(
        dir.join("manifest.tsv"),
        "# war2_survey emit @ test\nidx\tva\tname\tstatus\tkind\n00000\t00010010\tFUN_00010010\tOK\tuser\n00001\t00010020\tFUN_00010020\tOK\tlibrary\n00002\t00010030\tFUN_00010030\tOK\tuser\n",
    )
    .unwrap();
    std::fs::write(rec.join("00000.c"), CLEAN).unwrap();
    std::fs::write(rec.join("00001.c"), "  memcpy(a, b, 4);\n").unwrap();
    // 00002.c absent: a partial emit leaves it out of the tree
    let tus = load_tree(&dir.join("manifest.tsv"), &rec).unwrap();
    assert_eq!(tus.iter().map(|t| t.va).collect::<Vec<_>>(), vec![0x10010, 0x10020]);
    assert_eq!(tus[0].name, "FUN_00010010");
    assert_eq!(tus[0].columns["kind"], "user");
    assert!(kind_is_user(&tus[0]) && !kind_is_user(&tus[1]));
    let mut old = tus[0].clone();
    old.columns.remove("kind");
    assert!(kind_is_user(&old), "a manifest without the column has no opinion");
    let mut bar = BTreeMap::new();
    bar.insert("memcpy(".to_string(), 1usize);
    let baseline = Baseline::parse("gate\tkey\trule\tvalue\tset_at\nstring_ops_bar\tmemcpy(\t>=\t1\tt\n").unwrap();
    let reports = run_text_gates(&tus, &kind_is_user, &baseline, true);
    assert_eq!(reports.len(), 6);
    assert!(reports[3].failed(), "the library TU's memcpy is out of scope: {}", reports[3]);
    let partial = run_text_gates(&tus, &kind_is_user, &baseline, false);
    assert!(partial[3..].iter().all(|r| matches!(r.outcome, Outcome::Skip(_))), "4-6 skip on a partial emit");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn reports_render_sorted_hits_and_never_a_silent_skip() {
    let a = tu(0x2000, "  x = aiStack_2c[0];\n");
    let b = tu(0x1000, "  y = uStack_10;\n");
    let r = declared_symbols(&[a, b]);
    let text = r.to_string();
    assert!(text.starts_with("FAIL 1 declared-symbols: 2 hit(s)\n    0x1000 FUN_00001000: undeclared uStack_10 — y = uStack_10;\n    0x2000 "), "{text}");
    let s = GateReport::skip("8 verdict-regressions", "no --prev");
    assert_eq!(s.to_string(), "SKIP 8 verdict-regressions (no --prev)\n");
    assert!(!any_failed(&[s]));
    let rows = table(&[(0x100, "EXACT", 1.0, 10, 10)]);
    let baseline = Baseline::parse("gate\tkey\trule\tvalue\tset_at\nguard_frame\t0x100\tEXACT\t-\tw4\n").unwrap();
    let vr = run_verdict_gates(&rows, None, &baseline, false);
    assert!(!vr[0].failed() && matches!(vr[1].outcome, Outcome::Skip(_)));
    assert_eq!(render(&vr), "OK   7 guard-sets-EXACT (1 frame + 0 volatile)\nSKIP 8 verdict-regressions (no --prev)\n");
}
