//! Stage-1b (disasm + raw p-code) conformance ratchet — now engine-driven.
//!
//! Each `goldens/disasm/<name>.golden` (captured offline by `oracle/capture.cc`)
//! is paired with its `oracle/fixtures/<name>.xml`. mosura's SLEIGH runtime
//! (via the public `sleigh::disassemble`, language tables resolved from the
//! pinned Ghidra tree) must reproduce each golden instruction — disasm AND raw
//! p-code. Compared by address, so multi-function (multi-chunk) fixtures work.
//!
//! Skips cleanly when the language tables aren't present (Ghidra tree not set up).

use mosura::{datatest, golden, paths, sleigh};
use std::collections::HashMap;
use std::fs;

/// Floor on golden instructions mosura reproduces across all fixtures. Bump as the
/// engine widens; a drop is a regression.
const EXPECTED_DISASM_PASS: usize = 254;

fn norm(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn disasm_pcode_ratchet() {
    let gdir = paths::disasm_goldens_dir();
    if !gdir.is_dir() {
        eprintln!("skip: no goldens at {} (run `cargo xtask baseline`)", gdir.display());
        return;
    }
    let mut goldens: Vec<_> = fs::read_dir(&gdir)
        .expect("read goldens dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("golden"))
        .collect();
    goldens.sort();
    assert!(!goldens.is_empty(), "no .golden files (run `cargo xtask baseline`)");

    let mut passed = 0usize;
    let mut total = 0usize;
    let mut langs_loaded = 0usize;
    let mut misses: Vec<String> = Vec::new();
    for gp in &goldens {
        let g = golden::parse(&fs::read_to_string(gp).expect("read golden"));
        let stem = gp.file_stem().and_then(|s| s.to_str()).expect("golden stem");
        let fx = paths::oracle_fixtures_dir().join(format!("{stem}.xml"));
        let Ok(dt) = datatest::parse_file(&fx) else { continue };

        // Disassemble every code chunk through the public API and pool by address.
        let mut produced = Vec::new();
        let mut available = false;
        for c in &dt.chunks {
            if let Ok(insns) = sleigh::disassemble(&g.lang, &c.bytes, c.offset) {
                available = true;
                produced.extend(insns);
            }
        }
        if !available {
            eprintln!("  {stem}: skip (no tables for {})", g.lang);
            continue;
        }
        langs_loaded += 1;
        let by_addr: HashMap<u64, &_> = produced.iter().map(|i| (i.address, i)).collect();
        let mut hit = 0usize;
        for gi in &g.insns {
            total += 1;
            let p = by_addr.get(&gi.address);
            let ok = p.is_some_and(|p| {
                p.bytes == gi.bytes
                    && p.mnemonic.trim() == gi.mnemonic
                    && norm(&p.body) == norm(&gi.body)
                    && p.pcode == gi.pcode
            });
            if ok {
                passed += 1;
                hit += 1;
            } else {
                let what = match p {
                    None => "desync",
                    Some(p) if p.mnemonic.trim() != gi.mnemonic || norm(&p.body) != norm(&gi.body) => "disasm",
                    Some(_) => "pcode",
                };
                misses.push(format!("  [{what}] {stem} @{:08x} {} {}", gi.address, gi.mnemonic, gi.body));
            }
        }
        eprintln!("  {stem} [{}]: {hit}/{} reproduced", g.lang, g.insns.len());
    }

    if langs_loaded == 0 {
        eprintln!("skip: no language tables available (run scripts/setup-oracle.sh)");
        return;
    }
    eprintln!("disasm/pcode parity: {passed}/{total} golden instructions reproduced (engine-driven)");
    for m in misses.iter().take(25) {
        eprintln!("{m}");
    }
    assert!(
        passed >= EXPECTED_DISASM_PASS,
        "disasm parity regressed: {passed} < {EXPECTED_DISASM_PASS}"
    );
}
