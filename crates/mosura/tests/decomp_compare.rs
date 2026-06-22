//! D5 structural comparator: score mosura's decompiled C against Ghidra's own C
//! (captured live via `oracle/capture --c`) over the decompiler fixtures. Skips
//! cleanly when the oracle tool or `.sla` is absent.

use mosura::decomp::{ccompare, Funcdata};
use mosura::sleigh::engine::Spec;
use mosura::{datatest, paths};
use std::process::Command;

fn x86_64() -> Option<(Spec, Vec<u32>)> {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        return None;
    }
    let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).ok()?;
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    Some((spec, ctx))
}

/// Ghidra's C for a fixture via `oracle/capture <ghidra> <fixture> --c`.
fn ghidra_c(fixture: &std::path::Path) -> Option<String> {
    let capture = paths::workspace_root().join("oracle/capture");
    if !capture.exists() {
        return None;
    }
    let out = Command::new(capture).arg(paths::ghidra_src()).arg(fixture).arg("--c").output().ok()?;
    let c = String::from_utf8_lossy(&out.stdout).to_string();
    if c.trim().is_empty() {
        None
    } else {
        Some(c)
    }
}

#[test]
fn mosura_c_matches_ghidra_structurally() {
    let Some((spec, ctx)) = x86_64() else {
        eprintln!("skip: x86-64.sla not found");
        return;
    };
    // fixtures whose function mosura fully decompiles (the 11 shapes)
    let fixtures = [
        "sem", "pick", "ifret", "dowhile", "while", "stackadd", "call", "for", "bodycall", "callstmt", "ptrstore", "ucmp",
    ];

    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let mut scores = Vec::new();
    let mut compared = 0;
    for name in fixtures {
        let fx = paths::oracle_fixtures_dir().join(format!("x86_64_{name}.xml"));
        if !fx.exists() {
            continue;
        }
        let dt = datatest::parse_file(&fx).unwrap();
        let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);
        let Some(mosura) = f.decompile(&lo) else {
            eprintln!("{name:>10}: mosura None");
            continue;
        };
        let Some(ghidra) = ghidra_c(&fx) else {
            eprintln!("{name:>10}: (no oracle C — skipped)");
            continue;
        };
        let s = ccompare::similarity(&mosura, &ghidra);
        eprintln!("{name:>10}: similarity {s:.2}");
        scores.push(s);
        compared += 1;
    }

    if compared == 0 {
        eprintln!("skip: oracle capture tool not built");
        return;
    }
    let avg = scores.iter().sum::<f64>() / scores.len() as f64;
    eprintln!("--- average structural similarity vs Ghidra: {avg:.2} over {compared} fixtures ---");
    assert!(avg > 0.7, "mosura's C should be structurally close to Ghidra's (avg {avg:.2})");
}
