//! x86-64 disassembly **coverage** — a differential test over real compiled
//! `.text` (100 instructions in `oracle/fixtures/x86_64_cov.xml`) against the
//! Ghidra oracle golden. This measures how much of x86 mosura actually decodes
//! correctly across diverse instructions/addressing modes — not just a few
//! hand-picked ones. Skips if the x86-64 `.sla` isn't present.

use mosura::{datatest, golden, paths};
use std::collections::HashMap;

/// Ratchet: minimum instructions mosura must match. Now 100% on this corpus
/// (after context-change, relative-branch, ValueMap, and OperandValue support).
const EXPECTED_MATCHES: usize = 127;

fn norm(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn x86_64_disasm_coverage() {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        eprintln!("skip: {} not found", sla.display());
        return;
    }
    let spec = mosura::speccache::get(&sla).expect("x86-64 spec");
    let context = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);

    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_cov.xml")).expect("fixture");
    let chunk = &dt.chunks[0];
    let insns = spec.disassemble_ctx(&chunk.bytes, chunk.offset, &context);
    let by_addr: HashMap<u64, &_> = insns.iter().map(|i| (i.address, i)).collect();

    let g = golden::parse(
        &String::from_utf8(std::fs::read(paths::disasm_goldens_dir().join("x86_64_cov.golden")).unwrap()).unwrap(),
    );

    // Per the plan (§2/§5), stage 1b is disasm AND raw p-code, exact match.
    let mut matched = 0usize;
    let mut misses = Vec::new();
    for gi in &g.insns {
        let m = by_addr.get(&gi.address);
        let disasm_ok = m.is_some_and(|m| m.mnemonic.trim() == gi.mnemonic && norm(&m.body) == norm(&gi.body));
        let pcode_ok = m.is_some_and(|m| m.pcode == gi.pcode);
        if disasm_ok && pcode_ok {
            matched += 1;
        } else {
            let what = if !disasm_ok { "disasm" } else { "pcode" };
            misses.push(m.map_or_else(
                || format!("  @{:08x}  [desync] oracle: {} {}", gi.address, gi.mnemonic, gi.body),
                |m| format!(
                    "  @{:08x}  [{what}] oracle: {} {} {:?} | mosura: {} {} {:?}",
                    gi.address, gi.mnemonic, gi.body, gi.pcode, m.mnemonic.trim(), m.body, m.pcode
                ),
            ));
        }
    }
    let total = g.insns.len();
    eprintln!("x86-64 disasm+pcode coverage: {matched}/{total} = {}%", matched * 100 / total.max(1));
    eprintln!("first misses:");
    for m in misses.iter().take(20) {
        eprintln!("{m}");
    }
    assert!(matched >= EXPECTED_MATCHES, "coverage regressed: {matched} < {EXPECTED_MATCHES}");
}
