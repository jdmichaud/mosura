//! Cross-arch coverage — **Zilog Z80**, an 8-bit, 16-bit-address ISA whose
//! flag-heavy p-code (per-op INT_CARRY / INT_SCARRY / INT_SBORROW / INT_2COMP
//! flag synthesis) is a stress test for the lifter, decoded + lifted with *no
//! arch-specific code*, diffing every instruction (disasm AND raw p-code)
//! against the Ghidra oracle. Fixture: real `sdcc -mz80` `.text` (linked with
//! `sdldz80` at a `.COM`-style org) — indexed `SUB (IX+d)`, `ADD IX,SP` /
//! `ADD HL,DE`, `EX DE,HL`, `LD A,(HL)`, `JR NC`, `CALL`/`RET`, `PUSH`/`POP IX`,
//! `JP (HL)`. Skips if the Z80 `.sla` is absent.

use mosura::{datatest, golden, paths};
use std::collections::HashMap;

const EXPECTED_MATCHES: usize = 29; // 100% cross-arch, zero arch-specific code

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
fn z80_disasm_pcode_coverage() {
    let langdir = paths::ghidra_src().join("Ghidra/Processors/Z80/data/languages");
    let sla = langdir.join("z80.sla");
    if !sla.exists() {
        eprintln!("skip: {} not found", sla.display());
        return;
    }
    let spec = mosura::speccache::get(&sla).expect("Z80 spec");
    let sets = pspec_context(&langdir.join("z80.pspec"));
    let set_refs: Vec<(&str, u64)> = sets.iter().map(|(n, v)| (n.as_str(), *v)).collect();
    let context = spec.context_from_sets(&set_refs);

    let mut matched = 0usize;
    let mut total = 0usize;
    let mut misses = Vec::new();
    for name in ["z80_compute"] {
        let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join(format!("{name}.xml"))).expect("fixture");
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
    eprintln!("Z80 disasm+pcode coverage: {matched}/{total} = {}%", matched * 100 / total.max(1));
    for m in misses.iter().take(20) {
        eprintln!("{m}");
    }
    assert!(matched >= EXPECTED_MATCHES, "coverage regressed: {matched} < {EXPECTED_MATCHES}");
}
