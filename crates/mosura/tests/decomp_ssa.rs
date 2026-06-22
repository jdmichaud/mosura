//! Decompiler D1: dominator tree + phi placement. Verifies the idom tree is rooted
//! at the entry and that a loop induces phi (MULTIEQUAL) nodes. Skips without the
//! x86-64 `.sla`.

use mosura::decomp::Funcdata;
use mosura::sleigh::engine::Spec;
use mosura::{datatest, paths};

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
fn dominators_form_a_tree_and_loop_induces_phis() {
    let Some((spec, ctx)) = x86_64() else { return };
    let f = build(&spec, &ctx, "x86_64_loop.xml");
    let dom = f.dominators();

    // The idom relation is a tree rooted at the entry: from every reachable block,
    // following idom reaches block 0 without cycling.
    for b in 0..f.blocks.len() {
        if dom.idom[b] == usize::MAX {
            continue; // unreachable
        }
        let mut x = b;
        let mut steps = 0;
        while x != 0 {
            x = dom.idom[x];
            steps += 1;
            assert!(x != usize::MAX, "block {b}: idom chain hit unreachable");
            assert!(steps <= f.blocks.len(), "block {b}: idom chain cycles");
        }
    }
    assert_eq!(dom.idom[0], 0, "entry must dominate itself");

    // A loop creates a join point reached by a back-edge ⇒ phi nodes.
    let phis = f.phi_sites(&dom);
    assert!(!phis.is_empty(), "loop must induce phi (MULTIEQUAL) nodes");

    // Full SSA: every phi has one argument per predecessor, and the loop-carried
    // value flows through a phi (some use resolves to a Phi def).
    use mosura::decomp::ssa::Def;
    let ssa = f.ssa(&[]);
    for ph in &ssa.phis {
        assert_eq!(ph.args.len(), f.blocks[ph.block].pred.len(), "phi arg count must match predecessors");
    }
    assert!(
        ssa.uses.values().any(|d| matches!(d, Def::Phi(_))),
        "a loop-carried value must reach a use via a phi"
    );
    eprintln!(
        "D1: idom tree rooted at entry; {} phi site(s); {} heritaged uses renamed",
        ssa.phis.len(),
        ssa.uses.len()
    );
}

#[test]
fn dead_code_prunes_dead_flags() {
    let Some((spec, ctx)) = x86_64() else { return };

    // x86-64 SysV returns in RAX; mark it live-out so DCE keeps the result.
    let rax = ("register".to_string(), 0u64, 8u32);

    // Straight-line f(a,b)=a*3+(b>>2)-5: no branch reads any flag, so the flag
    // computations are dead — DCE removes them but keeps the result chain into RAX.
    let f = build(&spec, &ctx, "x86_64_sem.xml");
    let live = f.dead_code(&f.ssa(&[rax.clone()]));
    let (kept, total) = (live.live_op_count(), f.ops.len());
    assert!(2 * kept < total, "most ops (flags) should be dead, kept {kept}/{total}");
    assert!(kept >= 4, "the a*3+(b>>2)-5 result chain must survive, kept only {kept}");
    // the RAX zero-extend feeding the return value must stay live (INT_ZEXT = 17).
    assert!(
        f.ops.iter().enumerate().any(|(i, fo)| {
            live.live_ops[i] && fo.op.opcode == 17 && fo.op.out.as_ref().is_some_and(|o| o.space == "register" && o.offset == 0)
        }),
        "result's RAX = ZEXT(EAX) must survive DCE"
    );
    eprintln!("D2: sem DCE kept {kept}/{total} ops (result preserved)");

    // Loop: flags feeding taken branches stay live; CBRANCH stays live.
    let f = build(&spec, &ctx, "x86_64_loop.xml");
    let live = f.dead_code(&f.ssa(&[rax]));
    let (kept, total) = (live.live_op_count(), f.ops.len());
    assert!(kept < total, "loop DCE must remove some ops");
    assert!(
        f.ops.iter().enumerate().any(|(i, fo)| fo.op.opcode == 5 && live.live_ops[i]),
        "CBRANCH must stay live"
    );
    eprintln!("D2: loop DCE kept {kept}/{total} ops");
}
