//! D6 ratchet: run mosura's decompiler against the real x86-64 decompiler datatests
//! and score each against Ghidra's own C (via `oracle/capture --c`) with the D5
//! structural comparator. This is the bytes→C end-to-end metric — how much of the
//! datatest corpus mosura recovers, and how close it lands. Skips when the oracle
//! tool or `.sla` is absent. The asserted thresholds ratchet up as coverage grows.

use mosura::decomp::{ccompare, Funcdata};
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
    if c.trim().is_empty() {
        None
    } else {
        Some(c)
    }
}

#[test]
fn score_x86_64_datatest_corpus() {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        eprintln!("skip: x86-64.sla not found");
        return;
    }
    let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    // x86-64 SysV return registers: EAX, RAX, and XMM0 (8-byte float returns). XMM0 is
    // not added at 4 bytes: a float result is often XOR-zeroed (4-byte) then computed
    // (8-byte), and mosura's overlap-naive SSA would trace the 4-byte read to the zero.
    let lo = [
        ("register".to_string(), 0u64, 4u32),
        ("register".to_string(), 0u64, 8u32),
        ("register".to_string(), 0x1200u64, 8u32),
    ];

    let mut entries: Vec<_> = std::fs::read_dir(paths::datatests_dir())
        .map(|d| d.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default();
    entries.sort();

    let (mut total, mut decompiled, mut scored, mut have_oracle) = (0, 0, Vec::new(), false);
    for path in entries {
        if path.extension().map(|e| e != "xml").unwrap_or(true) {
            continue;
        }
        if !std::fs::read_to_string(&path).unwrap_or_default().contains("x86:LE:64") {
            continue;
        }
        total += 1;
        let Ok(dt) = datatest::parse_file(&path) else { continue };
        if dt.chunks.is_empty() {
            continue;
        }
        let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);
        // a few datatests stress paths mosura doesn't model yet; don't abort the run
        let Ok(Some(mosura)) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f.decompile(&lo))) else {
            continue;
        };
        decompiled += 1;
        if let Some(ghidra) = ghidra_c(&path) {
            have_oracle = true;
            scored.push(ccompare::similarity(&mosura, &ghidra));
        }
    }

    eprintln!("mosura decompiled {decompiled}/{total} x86-64 datatests");
    assert!(decompiled >= 50, "decompiled {decompiled}/{total} — coverage regressed");

    if !have_oracle {
        eprintln!("skip scoring: oracle capture tool not built");
        return;
    }
    let avg = scored.iter().sum::<f64>() / scored.len() as f64;
    let good = scored.iter().filter(|&&s| s >= 0.7).count();
    eprintln!("structural similarity vs Ghidra: avg {avg:.3}, >=0.70: {good}/{}", scored.len());
    assert!(avg >= 0.68, "average similarity {avg:.3} regressed");
    assert!(good >= 24, "only {good} datatests >= 0.70 — regressed");
}
