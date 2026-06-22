//! Decompiler D0: control-flow graph shape. Builds `Funcdata` for functions whose
//! structure is known (a straight-line one and a loop) and checks the CFG matches.
//! Skips when the x86-64 `.sla` isn't present.

use mosura::decomp::Funcdata;
use mosura::sleigh::engine::Spec;
use mosura::{datatest, paths};

const RETURN: u32 = 10;

fn x86_64() -> Option<(Spec, Vec<u32>)> {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        eprintln!("skip: {} not found", sla.display());
        return None;
    }
    let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).ok()?;
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    Some((spec, ctx))
}

fn build(spec: &Spec, ctx: &[u32], fixture: &str) -> Funcdata {
    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join(fixture)).expect("fixture");
    Funcdata::build(spec, &dt.chunks[0].bytes, dt.chunks[0].offset, ctx)
}

#[test]
fn cfg_straight_line_and_loop() {
    let Some((spec, ctx)) = x86_64() else { return };

    // f(a,b)=a*3+(b>>2)-5 — straight-line: no loop, ends in RETURN.
    let f = build(&spec, &ctx, "x86_64_sem.xml");
    assert!(!f.ops.is_empty(), "no ops");
    assert!(!f.has_back_edge(), "straight-line fn must have no back-edge");
    assert!(
        f.blocks.iter().any(|b| b.end > b.start && f.ops[b.end - 1].op.opcode == RETURN),
        "must contain a block ending in RETURN"
    );

    // sumto(n) — a real loop: must split into several blocks with a back-edge,
    // and every block past the entry must be reachable (have a predecessor).
    let f = build(&spec, &ctx, "x86_64_loop.xml");
    assert!(f.blocks.len() >= 3, "loop fn should split into >=3 blocks, got {}", f.blocks.len());
    assert!(f.has_back_edge(), "loop fn must have a back-edge");
    for (b, blk) in f.blocks.iter().enumerate() {
        assert!(b == 0 || !blk.pred.is_empty(), "block {b} [{}..{}] is unreachable", blk.start, blk.end);
    }
    eprintln!("CFG: straight-line OK; loop = {} blocks, back-edge present", f.blocks.len());
}
