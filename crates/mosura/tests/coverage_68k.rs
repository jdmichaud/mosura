//! Cross-arch coverage — **Motorola 68000** (68040 model), a **big-endian**,
//! variable-length CISC ISA, decoded + lifted with *no arch-specific code*,
//! diffing every instruction (disasm AND raw p-code) against the Ghidra oracle.
//! Fixture: real `m68k-linux-gnu-gcc` `.text` (movem register lists, muls.l,
//! add/cmp, ble/bne/bra, jsr/rts). Exercises the big-endian decode path.
//! Skips if the 68k `.sla` is absent.

use mosura::{datatest, golden, paths};
use std::collections::HashMap;

const EXPECTED_MATCHES: usize = 24; // 100% cross-arch, zero arch-specific code

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
fn m68k_disasm_pcode_coverage() {
    let langdir = paths::language_dir("68000");
    let sla = langdir.join("68040.sla");
    if !sla.exists() {
        eprintln!("skip: {} not found", sla.display());
        return;
    }
    let spec = mosura::speccache::get(&sla).expect("68000 spec");
    let sets = pspec_context(&langdir.join("68000.pspec"));
    let set_refs: Vec<(&str, u64)> = sets.iter().map(|(n, v)| (n.as_str(), *v)).collect();
    let context = spec.context_from_sets(&set_refs);

    let mut matched = 0usize;
    let mut total = 0usize;
    let mut misses = Vec::new();
    for name in ["m68k_compute"] {
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
    eprintln!("68000 disasm+pcode coverage: {matched}/{total} = {}%", matched * 100 / total.max(1));
    for m in misses.iter().take(20) {
        eprintln!("{m}");
    }
    assert!(matched >= EXPECTED_MATCHES, "coverage regressed: {matched} < {EXPECTED_MATCHES}");
}

/// The ELF importer's variant choice is **output-neutral** — proof, gated.
///
/// Ghidra's 68000 ELF opinion (`primary=4`, no processor variant) matches all four
/// `68000:BE:32` variants; the importer collects them in a `HashSet` (QueryOpinionService)
/// and — with no sort and `QueryResult` not `Comparable` — takes them in a stable iteration
/// order that deterministically lands on **Coldfire** (what `analysis::loader::elf` mirrors),
/// while the disasm goldens above were captured under the `default` variant (= `68040.sla`).
/// Two different variant *labels* for the same bytes. This test proves the label never changes
/// the decode: across the committed gcc-m68k ground-truth corpus, `coldfire.sla` and
/// `68040.sla` disassemble every `.text` instruction **identically** — real `m68k-linux-gnu`
/// output stays in the integer subset both models decode the same way, so the loader's Coldfire
/// pick is faithful to Ghidra *and* costs nothing vs the golden variant. If a future SLEIGH
/// bump ever diverges them, this fails — and the variant choice would suddenly matter.
#[test]
fn m68k_coldfire_matches_default_variant() {
    use object::{Object, ObjectSection};
    let langdir = paths::language_dir("68000");
    let (cold_p, dflt_p) = (langdir.join("coldfire.sla"), langdir.join("68040.sla"));
    if !cold_p.exists() || !dflt_p.exists() {
        eprintln!("skip: 68000 .sla absent");
        return;
    }
    let cold = mosura::speccache::get(&cold_p).expect("coldfire spec");
    let dflt = mosura::speccache::get(&dflt_p).expect("68040 spec");
    let (cctx, dctx) = (cold.context_from_sets(&[]), dflt.context_from_sets(&[]));

    let mut programs = 0usize;
    let mut insns = 0usize;
    let mut diffs = Vec::new();
    for entry in std::fs::read_dir(paths::ground_truth_dir()).expect("ground-truth dir") {
        let p = entry.unwrap().path();
        if !p.file_name().is_some_and(|n| n.to_string_lossy().ends_with(".gcc-m68k")) {
            continue;
        }
        let data = std::fs::read(&p).unwrap();
        let obj = object::File::parse(&*data).unwrap();
        let Some(text) = obj.section_by_name(".text") else { continue };
        let (bytes, base) = (text.data().unwrap(), text.address());
        programs += 1;
        let render = |i: &mosura::sleigh::Instruction| format!("{} {}", i.mnemonic.trim(), i.body);
        let cmap: HashMap<u64, String> =
            cold.disassemble_ctx(bytes, base, &cctx).iter().map(|i| (i.address, render(i))).collect();
        for i in dflt.disassemble_ctx(bytes, base, &dctx) {
            insns += 1;
            if let Some(c) = cmap.get(&i.address) {
                if *c != render(&i) && diffs.len() < 20 {
                    diffs.push(format!("{} @{:08x}  coldfire[{c}]  default[{}]", p.display(), i.address, render(&i)));
                }
            }
        }
    }
    for d in &diffs {
        eprintln!("{d}");
    }
    eprintln!("m68k coldfire≡default: {programs} programs, {insns} instructions compared");
    assert!(programs > 0, "no ground-truth m68k binaries found");
    assert!(diffs.is_empty(), "coldfire vs default variant diverged on {} instruction(s)", diffs.len());
}
