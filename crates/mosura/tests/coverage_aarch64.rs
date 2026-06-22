//! Cross-arch coverage — the real test of the data-driven engine: disassemble +
//! lift **AARCH64** (a totally different ISA — fixed 4-byte instructions, no
//! prefixes) with *no arch-specific code*, diffing every instruction (disasm AND
//! raw p-code) against the Ghidra oracle. Corpus: byte-chunks from the 3 AARCH64
//! decompiler datatests (plan §4 Tier A). Skips if the AARCH64 `.sla` is absent.

use mosura::sleigh::engine::Spec;
use mosura::{datatest, golden, paths};
use std::collections::HashMap;

const EXPECTED_MATCHES: usize = 30; // 100% cross-arch, zero arch-specific code

fn norm(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn pspec_context(path: &std::path::Path) -> Vec<(String, u64)> {
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    let Ok(doc) = roxmltree::Document::parse(&text) else { return Vec::new() };
    doc.descendants()
        .filter(|n| n.tag_name().name() == "context_set")
        .flat_map(|cs| cs.children())
        .filter(|n| n.tag_name().name() == "set")
        .filter_map(|n| Some((n.attribute("name")?.to_string(), n.attribute("val")?.parse().ok()?)))
        .collect()
}

#[test]
fn aarch64_disasm_pcode_coverage() {
    let langdir = paths::ghidra_src().join("Ghidra/Processors/AARCH64/data/languages");
    let sla = langdir.join("AARCH64.sla");
    if !sla.exists() {
        eprintln!("skip: {} not found", sla.display());
        return;
    }
    let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).expect("AARCH64 spec");
    let sets = pspec_context(&langdir.join("AARCH64.pspec"));
    let set_refs: Vec<(&str, u64)> = sets.iter().map(|(n, v)| (n.as_str(), *v)).collect();
    let context = spec.context_from_sets(&set_refs);

    let mut matched = 0usize;
    let mut total = 0usize;
    let mut misses = Vec::new();
    for name in ["aarch64_ccmp", "aarch64_condconstsub", "aarch64_retspecial"] {
        let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join(format!("{name}.xml"))).expect("fixture");
        // a datatest may hold several code chunks (functions) — disassemble all.
        let insns: Vec<_> = dt
            .chunks
            .iter()
            .flat_map(|c| spec.disassemble_ctx(&c.bytes, c.offset, &context))
            .collect();
        let by_addr: HashMap<u64, &_> = insns.iter().map(|i| (i.address, i)).collect();

        let g = golden::parse(
            &String::from_utf8(std::fs::read(paths::disasm_goldens_dir().join(format!("{name}.golden"))).unwrap()).unwrap(),
        );
        for gi in &g.insns {
            total += 1;
            let m = by_addr.get(&gi.address);
            let ok = m.is_some_and(|m| {
                m.mnemonic.trim() == gi.mnemonic && norm(&m.body) == norm(&gi.body) && m.pcode == gi.pcode
            });
            if ok {
                matched += 1;
            } else {
                misses.push(m.map_or_else(
                    || format!("  @{:08x}  [desync] oracle: {} {}", gi.address, gi.mnemonic, gi.body),
                    |m| format!(
                        "  @{:08x}  oracle: {} {} {:?} | mosura: {} {} {:?}",
                        gi.address, gi.mnemonic, gi.body, gi.pcode, m.mnemonic.trim(), m.body, m.pcode
                    ),
                ));
            }
        }
    }
    eprintln!("AARCH64 disasm+pcode coverage: {matched}/{total} = {}%", matched * 100 / total.max(1));
    for m in misses.iter().take(20) {
        eprintln!("{m}");
    }
    assert!(matched >= EXPECTED_MATCHES, "coverage regressed: {matched} < {EXPECTED_MATCHES}");
}
