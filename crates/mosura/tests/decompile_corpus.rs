//! Diagnostic: run the *faithful* `decompile` track (not the old `decomp` prototype) over the
//! x86-64 decompiler datatests and score each against Ghidra's own C (`oracle/capture --c`) with
//! the structural comparator. This is a DIAGNOSTIC to surface the next-broadest gaps — per the
//! project's "ground against Ghidra's --c, don't chase the C-similarity gauge" rule it prints a
//! sorted report and asserts only a loose floor (so it can't silently rot), never a ratchet.

use mosura::ccompare;
use mosura::decompile::{build, pipeline, printc};
use mosura::sleigh::engine::Spec;
use mosura::{datatest, paths};
use std::process::Command;

fn ghidra_c(fx: &std::path::Path) -> Option<String> {
    let capture = paths::workspace_root().join("oracle/capture");
    if !capture.exists() {
        return None;
    }
    let out = Command::new(capture).arg(paths::ghidra_src()).arg(fx).arg("--c").output().ok()?;
    let c = String::from_utf8_lossy(&out.stdout).to_string();
    (!c.trim().is_empty()).then_some(c)
}

#[test]
fn decompile_track_corpus_report() {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        eprintln!("skip: x86-64.sla not found");
        return;
    }
    let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
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
