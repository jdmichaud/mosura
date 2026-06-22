//! Switch / jump-table recovery (S1): the `BRANCHIND` jump table is recognized and its
//! case target addresses recovered from the binary image.

use mosura::decomp::jumptable;
use mosura::decomp::Funcdata;
use mosura::sleigh::engine::Spec;
use mosura::sleigh::pcode::opcode_name;
use mosura::{datatest, paths};

#[test]
fn recovers_switchind_jump_table() {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        eprintln!("skip: {} not found", sla.display());
        return;
    }
    let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);

    let Ok(dt) = datatest::parse_file(&paths::datatests_dir().join("switchind.xml")) else { return };
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);
    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let ssa = f.ssa(&lo);

    // the binary image: every chunk (the jump table lives in a separate chunk)
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let indop = f.ops.iter().position(|o| opcode_name(o.op.opcode) == "BRANCHIND").expect("a BRANCHIND");

    let jt = jumptable::recover(&f, &ssa, &image, indop).expect("recovered jump table");
    eprintln!("switchind targets: {:#x?}", jt.targets);

    // 11 relative entries at 0x1000b8, target = 0x1000b8 + sext(entry) — verified by hand
    assert_eq!(
        jt.targets,
        vec![0x100058, 0x100068, 0x100078, 0x100088, 0x100048, 0x100048, 0x100098, 0x100098, 0x100098, 0x100098, 0x100048]
    );
}

#[test]
fn emits_switch_statement() {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        return;
    }
    let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    let Ok(dt) = datatest::parse_file(&paths::datatests_dir().join("switchind.xml")) else { return };
    // the whole image, so the jump table (in a separate chunk) is recovered (S2)
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let f = Funcdata::build_image(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx, &image);
    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32), ("register".to_string(), 0x1200u64, 8u32)];
    let c = f.decompile(&lo).expect("switchind decompile");
    eprintln!("=== switchind ===\n{c}");

    assert!(c.contains("switch ("), "must emit a switch, got:\n{c}");
    assert!(c.contains("case 0:") && c.contains("case 3:"), "case labels recovered, got:\n{c}");
    assert!(c.contains("default:"), "default case, got:\n{c}");
    // each recovered case body keeps its call
    assert!(c.contains("FUN_00101010"), "case 0's call recovered, got:\n{c}");
}
