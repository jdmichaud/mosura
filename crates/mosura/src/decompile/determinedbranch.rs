//! CFG simplification: eliminate a CBRANCH whose condition has folded to a constant, then prune
//! any block left unreachable. A port of Ghidra's `ActionDeterminedBranch` (`coreaction.cc:3530`)
//! plus the block-graph surgery it drives — `Funcdata::removeBranch` / `branchRemoveInternal` /
//! `removeUnreachableBlocks` / `blockRemoveInternal` / `opZeroMulti` (`funcdata_block.cc`).
//!
//! switchmulti's leftover `if (!0) {…}` and dead `xVar1 = -2` come from a const-false CBRANCH
//! (`CBRANCH … #0x0:1`) that mosura never removed: the false edge's target block is unreachable,
//! but it stayed in the graph and the structurer rendered the determined branch verbatim.

use super::action::Action;
use super::block::{BlockBasic, BlockId};
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;

/// Ghidra `Funcdata::opZeroMulti` (funcdata_block.cc:177): a MULTIEQUAL whose input count has
/// dropped collapses — 1 input becomes a COPY; 0 inputs (its block became unreachable) becomes a
/// COPY from a fresh function-input Varnode.
fn op_zero_multi(f: &mut Funcdata, op: OpId) {
    match f.op(op).num_inputs() {
        0 => {
            let out = f.op(op).output.expect("MULTIEQUAL has an output");
            let (size, loc) = (f.vn(out).size, f.vn(out).loc);
            let inv = f.new_input(size, loc); // setInputVarnode
            f.op_set_all_input(op, &[inv]);
            f.op_set_opcode(op, OpCode::Copy);
        }
        1 => f.op_set_opcode(op, OpCode::Copy),
        _ => {}
    }
}

/// Ghidra `Funcdata::branchRemoveInternal` (funcdata_block.cc:195): remove out-edge `num` of `bb`.
/// If the block had two out-edges the decision is gone, so its terminating CBRANCH is destroyed.
/// MULTIEQUALs in the target block lose the input flowing in from `bb` (then collapse if ≤1 left).
fn branch_remove_internal(f: &mut Funcdata, bb: BlockId, num: usize) {
    // If there is no decision left, remove the branch instruction (the CBRANCH ending the block).
    if f.block(bb).out_edges.len() == 2 {
        if let Some(&last) = f.block(bb).ops.last() {
            if f.op(last).code() == OpCode::Cbranch {
                f.op_destroy(last);
                f.block_mut(bb).ops.pop();
            }
        }
    }
    let bbout = f.block(bb).out_edges[num];
    // blocknum = index of bb among bbout's in-edges (the MULTIEQUAL slot the dead edge feeds).
    let blocknum =
        f.block(bbout).in_edges.iter().position(|&p| p == bb).expect("severed edge is present");
    // Sever the one connection bb -> bbout.
    f.block_mut(bb).out_edges.remove(num);
    f.block_mut(bbout).in_edges.remove(blocknum);
    // Patch MULTIEQUALs in bbout: drop the input for the now-dead edge, then collapse.
    let multis: Vec<OpId> = f
        .block(bbout)
        .ops
        .iter()
        .copied()
        .filter(|&op| f.op(op).code() == OpCode::Multiequal)
        .collect();
    for op in multis {
        f.op_remove_input(op, blocknum);
        op_zero_multi(f, op);
    }
}

/// Ghidra `Funcdata::removeUnreachableBlocks` (funcdata_block.cc:346) + `blockRemoveInternal`
/// (funcdata_block.cc:254): drop every block not reachable from the entry, patching the data-flow
/// (MULTIEQUALs in surviving successors) and destroying the dead ops, then compact + renumber the
/// block list (entry stays block 0). Returns `true` if any block was removed.
fn remove_unreachable_blocks(f: &mut Funcdata) -> bool {
    let nb = f.num_blocks();
    if nb == 0 {
        return false;
    }
    // Reachability from the entry (build_cfg makes the entry block 0).
    let mut reachable = vec![false; nb];
    let mut stack = vec![0usize];
    reachable[0] = true;
    while let Some(b) = stack.pop() {
        for o in f.block(BlockId(b as u32)).out_edges.clone() {
            let o = o.0 as usize;
            if !reachable[o] {
                reachable[o] = true;
                stack.push(o);
            }
        }
    }
    if reachable.iter().all(|&r| r) {
        return false;
    }
    // Sever the out-edges of every unreachable block (patching successor MULTIEQUALs).
    for b in 0..nb {
        if reachable[b] {
            continue;
        }
        let bb = BlockId(b as u32);
        while !f.block(bb).out_edges.is_empty() {
            branch_remove_internal(f, bb, 0);
        }
    }
    // Destroy the ops of the unreachable blocks (they are detached from the graph now).
    for b in 0..nb {
        if reachable[b] {
            continue;
        }
        for op in f.block(BlockId(b as u32)).ops.clone() {
            f.op_destroy(op);
        }
    }
    renumber_reachable(f, &reachable);
    true
}

/// Compact the block list to the reachable blocks (entry stays block 0), remapping every edge and
/// op `parent`. In-edges are *remapped* (not rebuilt) so MULTIEQUAL input ordering — which is
/// positional by in-edge — is preserved. Mirrors the renumber tail of `cfg::build_cfg`, which is
/// monotonic, so the surviving predecessors keep their relative (ascending) order.
fn renumber_reachable(f: &mut Funcdata, reachable: &[bool]) {
    let nb = reachable.len();
    let mut order: Vec<usize> = vec![0];
    order.extend((1..nb).filter(|&b| reachable[b]));
    let mut newid = vec![u32::MAX; nb];
    for (new, &b) in order.iter().enumerate() {
        newid[b] = new as u32;
    }
    let remap = |edges: &[BlockId]| -> Vec<BlockId> {
        edges.iter().filter(|e| reachable[e.0 as usize]).map(|e| BlockId(newid[e.0 as usize])).collect()
    };
    let mut pruned: Vec<BlockBasic> = Vec::with_capacity(order.len());
    for &b in &order {
        let src = f.block(BlockId(b as u32));
        pruned.push(BlockBasic {
            ops: src.ops.clone(),
            in_edges: remap(&src.in_edges),
            out_edges: remap(&src.out_edges),
        });
    }
    for (bi, blk) in pruned.iter().enumerate() {
        for &opid in &blk.ops {
            f.op_mut(opid).parent = Some(BlockId(bi as u32));
        }
    }
    f.set_blocks(pruned);
}

/// Ghidra `ActionDeterminedBranch` (coreaction.cc:3530): a CBRANCH whose condition Varnode has
/// become constant takes a determined edge; the other edge is removed (and any block left
/// unreachable is pruned). mosura's CFG orders a CBRANCH's out-edges `[fallthrough, taken]`, so a
/// non-zero (true) condition takes the branch — the fallthrough (edge 0) dies — and a zero (false)
/// condition removes the branch edge (edge 1). (Ghidra additionally folds in an `isBooleanFlip`
/// flag; mosura has none, since the edge order already encodes branch-on-true.)
pub struct ActionDeterminedBranch;

impl Action for ActionDeterminedBranch {
    fn name(&self) -> &str {
        "determinedbranch"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        let mut count = 0;
        // Re-scan from scratch after each removal: removeUnreachableBlocks renumbers the blocks.
        loop {
            let found = (0..data.num_blocks()).find_map(|b| {
                let bb = BlockId(b as u32);
                if data.block(bb).out_edges.len() != 2 {
                    return None;
                }
                let last = *data.block(bb).ops.last()?;
                if data.op(last).code() != OpCode::Cbranch {
                    return None;
                }
                let cond = data.op(last).input(1)?;
                data.vn(cond).is_constant().then(|| (bb, data.vn(cond).constant_value()))
            });
            let Some((bb, val)) = found else { break };
            let num = if val != 0 { 0 } else { 1 }; // remove the not-taken edge
            branch_remove_internal(data, bb, num); // = Funcdata::removeBranch
            remove_unreachable_blocks(data);
            count += 1;
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::op::SeqNum;
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::Funcdata;

    /// entry block0 CBRANCHes on a const-false condition to block2; block1 (fallthrough) and block2
    /// (only reachable via the dead branch) both flow into block3, whose MULTIEQUAL merges their
    /// values. The determined branch removes the block0→block2 edge, block2 becomes unreachable and
    /// is pruned, and block3's MULTIEQUAL collapses to a COPY of block1's value.
    #[test]
    fn const_false_cbranch_prunes_unreachable_block_and_collapses_phi() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = |o: u64| SeqNum { pc: Address::new(ram, o), uniq: 0 };

        // block0: CBRANCH target=#0x20, cond=#0 (false) — out-edges [block1 fallthrough, block2 taken]
        let target = f.new_const(8, 0x20);
        let cond = f.new_const(1, 0);
        let cbr = f.new_op(OpCode::Cbranch, seq(0), vec![target, cond]);
        // block1: r0 = 10
        let c10 = f.new_const(8, 10);
        let cp1 = f.new_op(OpCode::Copy, seq(0x10), vec![c10]);
        let r1 = f.new_output(cp1, 8, Address::new(reg, 0));
        // block2 (unreachable once the branch is determined): r0 = 20
        let c20 = f.new_const(8, 20);
        let cp2 = f.new_op(OpCode::Copy, seq(0x20), vec![c20]);
        let r2 = f.new_output(cp2, 8, Address::new(reg, 0));
        // block3: r0 = MULTIEQUAL(r1 [from block1], r2 [from block2]); RETURN r0
        let phi = f.new_op(OpCode::Multiequal, seq(0x30), vec![r1, r2]);
        let rphi = f.new_output(phi, 8, Address::new(reg, 0));
        let ret = f.new_op(OpCode::Return, seq(0x34), vec![rphi]);

        f.set_blocks(vec![
            BlockBasic { ops: vec![cbr], in_edges: vec![], out_edges: vec![BlockId(1), BlockId(2)] },
            BlockBasic { ops: vec![cp1], in_edges: vec![BlockId(0)], out_edges: vec![BlockId(3)] },
            BlockBasic { ops: vec![cp2], in_edges: vec![BlockId(0)], out_edges: vec![BlockId(3)] },
            BlockBasic {
                ops: vec![phi, ret],
                in_edges: vec![BlockId(1), BlockId(2)],
                out_edges: vec![],
            },
        ]);
        for (bi, ops) in [(0u32, vec![cbr]), (1, vec![cp1]), (2, vec![cp2]), (3, vec![phi, ret])] {
            for op in ops {
                f.op_mut(op).parent = Some(BlockId(bi));
            }
        }

        ActionDeterminedBranch.apply(&mut f);

        assert_eq!(f.num_blocks(), 3, "the unreachable const-false target block is removed");
        assert_eq!(f.op(phi).code(), OpCode::Copy, "the one-input MULTIEQUAL collapses to a COPY");
        assert_eq!(f.op(phi).input(0), Some(r1), "the surviving value is block1's (10), not block2's");
        // The destroyed CBRANCH no longer terminates the entry block.
        assert!(
            f.block(BlockId(0)).ops.iter().all(|&o| f.op(o).code() != OpCode::Cbranch),
            "the determined CBRANCH is gone"
        );
    }

    /// A const-TRUE CBRANCH keeps the branch edge and drops the fallthrough.
    #[test]
    fn const_true_cbranch_drops_fallthrough() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = |o: u64| SeqNum { pc: Address::new(ram, o), uniq: 0 };
        let target = f.new_const(8, 0x20);
        let cond = f.new_const(1, 1); // true
        let cbr = f.new_op(OpCode::Cbranch, seq(0), vec![target, cond]);
        let ret1 = f.new_op(OpCode::Return, seq(0x10), vec![]); // block1 (fallthrough, becomes dead)
        let ret2 = f.new_op(OpCode::Return, seq(0x20), vec![]); // block2 (taken)
        f.set_blocks(vec![
            BlockBasic { ops: vec![cbr], in_edges: vec![], out_edges: vec![BlockId(1), BlockId(2)] },
            BlockBasic { ops: vec![ret1], in_edges: vec![BlockId(0)], out_edges: vec![] },
            BlockBasic { ops: vec![ret2], in_edges: vec![BlockId(0)], out_edges: vec![] },
        ]);
        for (bi, op) in [(0u32, cbr), (1, ret1), (2, ret2)] {
            f.op_mut(op).parent = Some(BlockId(bi));
        }
        ActionDeterminedBranch.apply(&mut f);
        // block1 (fallthrough) is now unreachable and pruned; entry + the taken target remain.
        assert_eq!(f.num_blocks(), 2, "the fallthrough block is removed for a const-true CBRANCH");
    }
}
