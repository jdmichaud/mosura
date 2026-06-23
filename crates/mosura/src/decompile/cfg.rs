//! Basic-block construction — the CFG part of Ghidra's `Funcdata::followFlow`
//! (`flow.cc`/`funcdata_block.cc`). The SLEIGH engine already lifted every instruction
//! linearly, so this cuts the flat op list into basic blocks at leaders and wires edges.
//!
//! Leaders: the entry, every branch target, and the op after any block terminator
//! (`BRANCH`/`CBRANCH`/`BRANCHIND`/`RETURN` — *not* calls). Edges follow the terminator:
//! `BRANCH`→target, `CBRANCH`→[fallthrough, target], `RETURN`/`BRANCHIND`→(none yet;
//! indirect jumps are resolved in P7), otherwise fall through to the next block.

use std::collections::{BTreeSet, HashMap};

use super::block::{BlockBasic, BlockId};
use super::funcdata::Funcdata;
use super::op::OpId;

/// Resolve a branch op's static target to an op index: a constant input is a p-code
/// relative offset (within the instruction); otherwise it's a code address.
fn branch_target(f: &Funcdata, i: usize, addr_index: &HashMap<u64, usize>) -> Option<usize> {
    let in0 = f.op(OpId(i as u32)).input(0)?;
    let vn = f.vn(in0);
    if vn.is_constant() {
        Some((i as i64 + vn.constant_value() as i64) as usize)
    } else {
        addr_index.get(&vn.loc.offset).copied()
    }
}

/// Cut the function's op list into basic blocks and wire the edges.
pub fn build_cfg(f: &mut Funcdata) {
    let n = f.num_ops();
    if n == 0 {
        return;
    }
    let switch_targets = f.switch_targets.clone();

    // first op index per instruction address (branch targets land on instruction starts)
    let mut addr_index: HashMap<u64, usize> = HashMap::new();
    for i in 0..n {
        let pc = f.op(OpId(i as u32)).seqnum.pc.offset;
        addr_index.entry(pc).or_insert(i);
    }

    // leaders
    let mut leaders: BTreeSet<usize> = BTreeSet::new();
    leaders.insert(0);
    for i in 0..n {
        let oc = f.op(OpId(i as u32)).code();
        if oc.is_branch() {
            if let Some(t) = branch_target(f, i, &addr_index) {
                if t < n {
                    leaders.insert(t);
                }
            }
        }
        if oc.terminates_block() && i + 1 < n {
            leaders.insert(i + 1);
        }
    }
    // recovered jump-table case targets are leaders too
    for targets in switch_targets.values() {
        for t in targets {
            if let Some(&idx) = addr_index.get(t) {
                leaders.insert(idx);
            }
        }
    }

    // cut: block bi spans [leader_vec[bi], leader_vec[bi+1])
    let leader_vec: Vec<usize> = leaders.iter().copied().collect();
    let nb = leader_vec.len();
    let mut block_of = vec![0usize; n];
    for (bi, &start) in leader_vec.iter().enumerate() {
        let end = leader_vec.get(bi + 1).copied().unwrap_or(n);
        for idx in start..end {
            block_of[idx] = bi;
        }
    }

    let mut blocks: Vec<BlockBasic> = vec![BlockBasic::default(); nb];
    for (bi, &start) in leader_vec.iter().enumerate() {
        let end = leader_vec.get(bi + 1).copied().unwrap_or(n);
        blocks[bi].ops = (start..end).map(|i| OpId(i as u32)).collect();
    }

    // out edges, by the block's last op
    for bi in 0..nb {
        let last_idx = blocks[bi].ops.last().unwrap().0 as usize;
        let oc = f.op(OpId(last_idx as u32)).code();
        let fallthrough = (bi + 1 < nb).then_some(bi + 1);
        let mut outs: Vec<usize> = Vec::new();
        match oc {
            super::OpCode::Return => {}
            super::OpCode::Branchind => {
                // switch: edges to the recovered case target blocks (unique, in case order)
                let pc = f.op(OpId(last_idx as u32)).seqnum.pc.offset;
                if let Some(targets) = switch_targets.get(&pc) {
                    let mut seen = BTreeSet::new();
                    for t in targets {
                        if let Some(&idx) = addr_index.get(t) {
                            let b = block_of[idx];
                            if seen.insert(b) {
                                outs.push(b);
                            }
                        }
                    }
                }
            }
            super::OpCode::Branch => {
                if let Some(t) = branch_target(f, last_idx, &addr_index) {
                    outs.push(block_of[t]);
                }
            }
            super::OpCode::Cbranch => {
                outs.extend(fallthrough); // slot 0: condition false / fallthrough
                if let Some(t) = branch_target(f, last_idx, &addr_index) {
                    outs.push(block_of[t]); // slot 1: condition true / taken
                }
            }
            _ => outs.extend(fallthrough),
        }
        blocks[bi].out_edges = outs.into_iter().map(|b| BlockId(b as u32)).collect();
    }

    // Reachability from the entry (block 0): Ghidra's followFlow only traces code
    // reachable from the entry, so trailing/other-function code the linear lifter swept
    // up is dropped here.
    let mut reachable = vec![false; nb];
    let mut stack = vec![0usize];
    reachable[0] = true;
    while let Some(b) = stack.pop() {
        for o in blocks[b].out_edges.clone() {
            let o = o.0 as usize;
            if !reachable[o] {
                reachable[o] = true;
                stack.push(o);
            }
        }
    }
    let mut newid = vec![u32::MAX; nb];
    let mut k = 0u32;
    for (b, &r) in reachable.iter().enumerate() {
        if r {
            newid[b] = k;
            k += 1;
        }
    }
    let mut pruned: Vec<BlockBasic> = Vec::with_capacity(k as usize);
    for b in 0..nb {
        if !reachable[b] {
            continue;
        }
        let mut blk = std::mem::take(&mut blocks[b]);
        blk.out_edges = blk
            .out_edges
            .iter()
            .filter(|o| reachable[o.0 as usize])
            .map(|o| BlockId(newid[o.0 as usize]))
            .collect();
        pruned.push(blk);
    }
    let mut blocks = pruned;
    let nb = blocks.len();

    // in edges = reverse of (pruned) out
    for bi in 0..nb {
        for o in blocks[bi].out_edges.clone() {
            blocks[o.0 as usize].in_edges.push(BlockId(bi as u32));
        }
    }

    // set each op's parent block, then install
    for (bi, blk) in blocks.iter().enumerate() {
        for &opid in &blk.ops {
            f.op_mut(opid).parent = Some(BlockId(bi as u32));
        }
    }
    f.set_blocks(blocks);
}
