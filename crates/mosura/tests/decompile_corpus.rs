//! Diagnostic: run the *faithful* `decompile` track (not the old `decomp` prototype) over the
//! x86-64 decompiler datatests and score each against Ghidra's own C (`oracle/capture --c`) with
//! the structural comparator. This is a DIAGNOSTIC to surface the next-broadest gaps — per the
//! project's "ground against Ghidra's --c, don't chase the C-similarity gauge" rule it prints a
//! sorted report and asserts only a loose floor (so it can't silently rot), never a ratchet.

use mosura::ccompare;
use mosura::decompile::{build, pipeline, printc};
use mosura::{datatest, paths};

fn ghidra_c(fx: &std::path::Path) -> Option<String> {
    let c = mosura::oraclecache::capture(fx, &["--c"])?;
    (!c.trim().is_empty()).then_some(c)
}

#[test]
fn decompile_track_corpus_report() {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        eprintln!("skip: x86-64.sla not found");
        return;
    }
    let spec = mosura::speccache::get(&sla).unwrap();
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);

    let mut entries: Vec<_> = std::fs::read_dir(paths::datatests_dir())
        .map(|d| d.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default();
    entries.sort();

    let mut scored: Vec<(String, f64)> = Vec::new();
    let (mut total, mut decompiled, mut have_oracle) = (0, 0, false);
    for path in entries {
        if path.extension().map(|e| e != "xml").unwrap_or(true) {
            continue;
        }
        if !std::fs::read_to_string(&path).unwrap_or_default().contains("x86:LE:64") {
            continue;
        }
        let Ok(dt) = datatest::parse_file(&path) else { continue };
        if dt.chunks.is_empty() {
            continue;
        }
        total += 1;
        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
        let entry = dt.chunks[0].offset;
        let c = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut f = build::raw_funcdata_flow_image(&spec, "func", &image, entry, &ctx);
            pipeline::decompile(&mut f);
            printc::print_c(&f)
        }));
        let Ok(mosura) = c else { continue };
        decompiled += 1;
        if let Some(ghidra) = ghidra_c(&path) {
            have_oracle = true;
            scored.push((name, ccompare::similarity(&mosura, &ghidra)));
        }
    }

    eprintln!("decompile track: decompiled {decompiled}/{total} x86-64 datatests");
    if !have_oracle {
        eprintln!("skip scoring: oracle capture tool not built");
        return;
    }
    scored.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    let avg = scored.iter().map(|(_, s)| s).sum::<f64>() / scored.len() as f64;
    let good = scored.iter().filter(|(_, s)| *s >= 0.70).count();
    eprintln!("\n=== per-function similarity vs Ghidra --c (worst first) ===");
    for (n, s) in &scored {
        eprintln!("  {s:.3}  {n}");
    }
    eprintln!("\n=== decompile-track corpus: avg {avg:.4}, >=0.70: {good}/{} ===", scored.len());

    assert!(decompiled >= 40, "decompile track only handled {decompiled} datatests — regressed");
}

/// Regression for the `refineInput`/`guardInput` heritage fix (`heritage.cc:1836`/`:1952`): an XMM
/// float parameter read 8 bytes wide (`XMM0_Qa`) sits in a register range that a later `movaps`
/// return-setup writes in 4-byte lanes. `refine_overlaps` must keep this *input-like* read (no
/// dominating lane write) whole, so it links as one parameter — not `refineRead`'s
/// `CONCAT(input_hi, input_lo)` of two free pieces that nothing rejoins. Before the fix mixfloatint's
/// float param rendered as `CONCAT44(...)`; after it is a single clean register read.
#[test]
fn mixfloatint_float_param_stays_whole() {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        eprintln!("skip: x86-64.sla not found");
        return;
    }
    let spec = mosura::speccache::get(&sla).unwrap();
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    let path = paths::datatests_dir().join("mixfloatint.xml");
    let dt = datatest::parse_file(&path).expect("parse mixfloatint");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image(&spec, "func", &image, entry, &ctx);
    pipeline::decompile(&mut f);
    let c = printc::print_c(&f);
    assert!(
        !c.contains("CONCAT"),
        "mixfloatint's whole XMM float param was CONCAT-split (refineInput regression):\n{c}"
    );
}

/// Regression for the condition-flip normalization (Ghidra `ActionNormalizeBranches` /
/// `opFlipInPlaceTest`, funcdata_op.cc:1221): an `if`/`else` whose CBRANCH condition is in
/// non-normal form (here `INT_NOTEQUAL(param_2, 100)`) is rendered in the positive form —
/// `if (param_2 == 100) { then } else { else }` — not the raw `if (param_2 != 100) { else }
/// else { then }`. The structurer swaps the arms and `printc::render_negated` flips the
/// predicate. Matches `oracle/capture --c` for indproto.
#[test]
fn indproto_if_else_uses_positive_condition() {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        eprintln!("skip: x86-64.sla not found");
        return;
    }
    let spec = mosura::speccache::get(&sla).unwrap();
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    let path = paths::datatests_dir().join("indproto.xml");
    let dt = datatest::parse_file(&path).expect("parse indproto");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image(&spec, "func", &image, entry, &ctx);
    pipeline::decompile(&mut f);
    let c = printc::print_c(&f);
    assert!(
        c.contains("if (param_2 == 100)") && !c.contains("!= 100"),
        "indproto's if/else condition was not normalized to positive form (flipInPlaceExecute regression):\n{c}"
    );
}

/// Regression for the branchless-boolean `||` recovery (Ghidra `RuleOrCompare` /
/// `RuleShiftCompare` / `RuleZextEliminate` / `RuleBooleanNegate`, ruleaction.cc:10785/2044/2471/
/// 2937). orcompare's `if (a == 10 | b == 0x14)` is compiled branchlessly as a bit-packed
/// `(a==10)*2 | (b==0x14)<<7`; the rule chain peels the shifts/zexts/bit-pack back to the two
/// independent compares, and the `opFlipInPlaceTest`-gated De Morgan render (see
/// [`mosura::decompile::printc`]) prints the positive `a == 10 || b == 0x14`. Matches
/// `oracle/capture --c`.
#[test]
fn orcompare_recovers_logical_or() {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        eprintln!("skip: x86-64.sla not found");
        return;
    }
    let spec = mosura::speccache::get(&sla).unwrap();
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    let path = paths::datatests_dir().join("orcompare.xml");
    let dt = datatest::parse_file(&path).expect("parse orcompare");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image(&spec, "func", &image, entry, &ctx);
    pipeline::decompile(&mut f);
    let c = printc::print_c(&f);
    assert!(
        c.contains("if (param_1 == 10 || param_2 == 0x14)"),
        "orcompare did not recover the `||` condition (RuleOrCompare chain regression):\n{c}"
    );
    // the bit-packed flag-smear must be fully gone (no `<<`, `* 2`, or `| ...) != 0`)
    assert!(
        !c.contains("<< 7") && !c.contains(") * 2 |") && !c.contains(") != 0)"),
        "orcompare still shows the bit-packed flag form:\n{c}"
    );
}

/// Guard for the float NaN-guard collapse (Ghidra `RuleIgnoreNan` + `RuleFloatRange`,
/// ruleaction.cc): pointerrel's `ucomisd`-derived condition is `!(NAN(a)||NAN(b) || a<=b)`. The
/// two rules dissolve the redundant NaN checks and collapse the ordered compares into the single
/// `!(fStack_18 <= fRam...)` — a compact negated float comparison, not the De-Morgan-expanded
/// `(!NAN && !NAN) && ...` an ungated distribution would produce. (The residual vs Ghidra's
/// `fRam... < fStack_18` is only the `opFlipInPlaceTest` flip of `!(a<=b)` → `b<a`, a separate
/// normalization.)
#[test]
fn pointerrel_negated_condition_stays_compact() {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        eprintln!("skip: x86-64.sla not found");
        return;
    }
    let spec = mosura::speccache::get(&sla).unwrap();
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    let path = paths::datatests_dir().join("pointerrel.xml");
    let dt = datatest::parse_file(&path).expect("parse pointerrel");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image(&spec, "func", &image, entry, &ctx);
    pipeline::decompile(&mut f);
    let c = printc::print_c(&f);
    assert!(
        c.contains("if (!(fStack_18 <= fRam00000000001008b8))") && !c.contains("NAN"),
        "pointerrel's NaN-guarded condition did not collapse to the compact float compare:\n{c}"
    );
}

/// Regression for the bit-packing CONCAT recovery (Ghidra `RuleShiftPiece` ruleaction.cc:3753 +
/// `RuleAndZext` ruleaction.cc:1696). piecestruct assembles two struct fields from shifted bytes:
/// `(zext(hi) << 8*|lo|) | zext(lo)`. RuleShiftPiece folds each level to a PIECE (printed CONCAT),
/// and RuleAndZext first drops the `movsx`+`& 0xff` byte idiom so the bare byte is exposed. Matches
/// `oracle/capture --c`: `CONCAT22(param_2,param_1)` and
/// `CONCAT31(CONCAT21(CONCAT11(param_6,param_5),param_4),param_3)`.
#[test]
fn piecestruct_folds_shifts_to_concat() {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        eprintln!("skip: x86-64.sla not found");
        return;
    }
    let spec = mosura::speccache::get(&sla).unwrap();
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    let path = paths::datatests_dir().join("piecestruct.xml");
    let dt = datatest::parse_file(&path).expect("parse piecestruct");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image(&spec, "func", &image, entry, &ctx);
    pipeline::decompile(&mut f);
    let c = printc::print_c(&f);
    assert!(
        c.contains("CONCAT22(param_2,param_1)")
            && c.contains("CONCAT31(CONCAT21(CONCAT11(param_6,param_5),param_4),param_3)"),
        "piecestruct did not fold the shift-OR bit-packing into CONCAT (RuleShiftPiece/RuleAndZext regression):\n{c}"
    );
    // the raw `<< 0x10 |` / `<< 8 |` packing must be fully gone
    assert!(
        !c.contains("<< 0x10 |") && !c.contains("<< 8 |"),
        "piecestruct still shows the raw shift-OR packing:\n{c}"
    );
}
