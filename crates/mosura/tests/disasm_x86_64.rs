//! x86-64 bring-up: context + decode. Loads the compiled x86-64 `.sla` and the
//! `.pspec` default context from the pinned Ghidra tree (skips if absent), then
//! disassembles `89 f0` (MOV EAX,ESI). This is currently an *inspection* of how
//! far the decode gets — operand resolution is still to come.

use mosura::paths;

fn x86_64_langdir() -> std::path::PathBuf {
    paths::ghidra_src().join("Ghidra/Processors/x86/data/languages")
}

/// Read the `<context_set>` defaults from a `.pspec`.
fn pspec_context(path: &std::path::Path) -> Vec<(String, u64)> {
    let text = std::fs::read_to_string(path).expect("read pspec");
    let doc = roxmltree::Document::parse(&text).expect("parse pspec");
    doc.descendants()
        .filter(|n| n.tag_name().name() == "context_set")
        .flat_map(|cs| cs.children())
        .filter(|n| n.tag_name().name() == "set")
        .filter_map(|n| {
            let name = n.attribute("name")?.to_string();
            let val: u64 = n.attribute("val")?.parse().ok()?;
            Some((name, val))
        })
        .collect()
}

#[test]
fn x86_64_context_and_decode() {
    let sla = x86_64_langdir().join("x86-64.sla");
    if !sla.exists() {
        eprintln!("skip: {} not found (run scripts/setup-oracle.sh)", sla.display());
        return;
    }
    let spec = mosura::speccache::get(&sla).expect("build x86-64 spec");

    let sets = pspec_context(&x86_64_langdir().join("x86-64.pspec"));
    eprintln!("pspec context sets: {sets:?}");
    let set_refs: Vec<(&str, u64)> = sets.iter().map(|(n, v)| (n.as_str(), *v)).collect();
    let context = spec.context_from_sets(&set_refs);
    eprintln!("context register: {context:08x?}");
    // longMode=1 (bit0), addrsize=2 (bits4-5), opsize=1 (bits6-7) → 0x89000000
    assert_eq!(context.first().copied(), Some(0x8900_0000), "default 64-bit context");

    // 89 f0 = MOV EAX,ESI ; 83 e0 0f = AND EAX,0xf ; c3 = RET   @ 0x100000
    let code = [0x89u8, 0xf0, 0x83, 0xe0, 0x0f, 0xc3];
    let insns = spec.disassemble_ctx(&code, 0x100000, &context);
    for i in &insns {
        eprintln!(
            "{:#08x}  {:<8}  {} {}  pcode={:?}",
            i.address,
            i.bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            i.mnemonic,
            i.body,
            i.pcode
        );
    }
    // Context-driven decode + variable-length all correct.
    // MOV EAX,ESI (2 bytes) / AND EAX,0xf (3) / RET (1) — full disasm + p-code
    // (incl. operand resolution + 64-bit zero-extend) vs the Ghidra golden.
    let golden = mosura::golden::parse(
        &String::from_utf8(std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../goldens/disasm/x86_64_tiny.golden"),
        ).unwrap()).unwrap(),
    );
    assert_eq!(insns.len(), 3);
    for m in &insns {
        let g = golden.insns.iter().find(|g| g.address == m.address).expect("golden insn");
        assert_eq!(m.mnemonic.trim(), g.mnemonic, "mnemonic @ {:#x}", m.address);
        assert_eq!(m.bytes, g.bytes, "bytes @ {:#x}", m.address);
        assert_eq!(m.body.trim(), g.body, "operands @ {:#x}", m.address);
        assert_eq!(m.pcode, g.pcode, "p-code @ {:#x} ({})", m.address, g.mnemonic);
    }
}
