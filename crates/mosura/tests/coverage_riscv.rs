//! Cross-arch coverage — **RISC-V** (RV64GC): a load/store ISA with a mix of
//! 4-byte and 2-byte *compressed* instructions, decoded + lifted with *no
//! arch-specific code*, diffing every instruction (disasm AND raw p-code)
//! against the Ghidra oracle. Fixture: real `riscv64-linux-gnu-gcc` `.text`
//! (arithmetic, load/store, compare, branch, call, return; C and full-width).
//! Skips if the RISC-V `.sla` is absent.

use mosura::{datatest, golden, paths};
use std::collections::HashMap;

const EXPECTED_MATCHES: usize = 31; // 100% cross-arch, zero arch-specific code

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
fn riscv_disasm_pcode_coverage() {
    let langdir = paths::language_dir("RISCV");
    let sla = langdir.join("riscv.lp64d.sla");
    if !sla.exists() {
        eprintln!("skip: {} not found", sla.display());
        return;
    }
    let spec = mosura::speccache::get(&sla).expect("RISCV spec");
    let sets = pspec_context(&langdir.join("RV64.pspec"));
    let set_refs: Vec<(&str, u64)> = sets.iter().map(|(n, v)| (n.as_str(), *v)).collect();
    let context = spec.context_from_sets(&set_refs);

    let mut matched = 0usize;
    let mut total = 0usize;
    let mut misses = Vec::new();
    for name in ["riscv_compute"] {
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
    eprintln!("RISCV disasm+pcode coverage: {matched}/{total} = {}%", matched * 100 / total.max(1));
    for m in misses.iter().take(20) {
        eprintln!("{m}");
    }
    assert!(matched >= EXPECTED_MATCHES, "coverage regressed: {matched} < {EXPECTED_MATCHES}");
}
