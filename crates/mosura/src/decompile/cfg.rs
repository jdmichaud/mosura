//! Basic-block construction — the CFG part of Ghidra's `Funcdata::followFlow`
//! (`flow.cc`/`funcdata_block.cc`). The SLEIGH engine already lifted every instruction
//! linearly, so this cuts the flat op list into basic blocks at leaders and wires edges.
//!
//! Leaders: the entry, every branch target, and the op after any block terminator
//! (`BRANCH`/`CBRANCH`/`BRANCHIND`/`RETURN` — *not* calls). Edges follow the terminator:
//! `BRANCH`→target, `CBRANCH`→[fallthrough, target], `RETURN`/`BRANCHIND`→(none yet;
//! indirect jumps are resolved in P7), otherwise fall through to the next block.

use std::collections::{BTreeMap, BTreeSet};

use super::block::{BlockBasic, BlockId};
use super::funcdata::Funcdata;
use super::op::OpId;

/// Resolve a branch op's static target to an op index: a constant input is a p-code
/// relative offset (within the instruction); otherwise it's a code address. A code
/// address that has no op of its own (its instruction emitted zero p-code — e.g. a
/// tail-`jmp` into a function entry's `endbr64`) resolves to the first op at-or-after it,
/// the way Ghidra's instruction-addressed CFG begins the target block at that instruction
/// and lets the leading no-op instructions shift the first op forward.
fn branch_target(f: &Funcdata, i: usize, addr_index: &BTreeMap<u64, usize>) -> Option<usize> {
    let in0 = f.op(OpId(i as u32)).input(0)?;
    let vn = f.vn(in0);
    if vn.is_constant() {
        Some((i as i64 + vn.constant_value() as i64) as usize)
    } else {
        addr_index.range(vn.loc.offset..).next().map(|(_, &idx)| idx)
    }
}

/// Cut the function's op list into basic blocks and wire the edges.
pub fn build_cfg(f: &mut Funcdata) {
    let n = f.num_ops();
    if n == 0 {
        return;
    }
    let switch_targets = f.switch_targets.clone();
    let switch_defaults = f.switch_defaults.clone();

    // first op index per instruction address (branch targets land on instruction starts)
    let mut addr_index: BTreeMap<u64, usize> = BTreeMap::new();
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
        block_of[start..end].fill(bi);
    }

    let mut blocks: Vec<BlockBasic> = vec![BlockBasic::default(); nb];
    for (bi, &start) in leader_vec.iter().enumerate() {
        let end = leader_vec.get(bi + 1).copied().unwrap_or(n);
        // Defensive: skip any op already marked dead (none are at this point); never a leader.
        blocks[bi].ops = (start..end).map(|i| OpId(i as u32)).filter(|&op| !f.op(op).is_dead()).collect();
    }

    // out edges, by the block's last op
    for (bi, blk) in blocks.iter_mut().enumerate() {
        let last_idx = blk.ops.last().unwrap().0 as usize;
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
        blk.out_edges = outs.into_iter().map(|b| BlockId(b as u32)).collect();
    }

    // Fold the out-of-range guard into each switch (Ghidra `JumpBasic::foldInOneGuard` +
    // `Funcdata::pushBranch`). The compiled `if (x < N) goto switch; else goto default` leaves the
    // bounds-check as a separate CBRANCH block; Ghidra rewrites it so the `default` target becomes
    // an out-edge of the BRANCHIND itself (rendered `default:` inside the switch) and the guard
    // block flows unconditionally into the switch. We mirror that: add the default edge to the
    // switch head, drop the guard's branch to the default, and destroy the now-unconditional
    // CBRANCH (its comparison becomes dead code).
    for (&pc, &default_addr) in &switch_defaults {
        let Some(&didx) = addr_index.get(&default_addr) else { continue };
        let db = block_of[didx];
        // the switch head: the block whose terminating BRANCHIND is at `pc`
        let Some(ind_bi) = (0..nb).find(|&bi| {
            let last = blocks[bi].ops.last().map(|o| o.0 as usize);
            last.is_some_and(|l| {
                f.op(OpId(l as u32)).code() == super::OpCode::Branchind
                    && f.op(OpId(l as u32)).seqnum.pc.offset == pc
            })
        }) else {
            continue;
        };
        if db == ind_bi || !blocks[ind_bi].out_edges.iter().any(|e| e.0 as usize == db) {
            // add the default as the switch's last out-edge (Ghidra `addBlockToSwitch`)
            blocks[ind_bi].out_edges.push(BlockId(db as u32));
        }
        // rewrite each guard that branched into this switch and to the default (`pushBranch`)
        for (gb, blk) in blocks.iter_mut().enumerate() {
            if gb == ind_bi {
                continue;
            }
            let Some(&last) = blk.ops.last() else { continue };
            if f.op(last).code() != super::OpCode::Cbranch {
                continue;
            }
            let outs: Vec<usize> = blk.out_edges.iter().map(|e| e.0 as usize).collect();
            if outs.len() == 2 && outs.contains(&ind_bi) && outs.contains(&db) {
                blk.out_edges = vec![BlockId(ind_bi as u32)];
                blk.ops.retain(|&o| o != last);
                f.op_destroy(last);
            }
        }
    }

    // A switch inside a loop whose loop body has a *single* exit structures cleanly into
    // `while { switch }` (Ghidra recovers it). One with *multiple* loop exits is the case
    // Ghidra declines ("Too many branches. Treating indirect jump as call") — it won't
    // structure, so decline it too: drop the case edges, leaving a plain indirect jump.
    for bi in 0..nb {
        let last_idx = blocks[bi].ops.last().unwrap().0 as usize;
        if f.op(OpId(last_idx as u32)).code() != super::OpCode::Branchind || blocks[bi].out_edges.is_empty() {
            continue;
        }
        // the loop through this switch: blocks both reachable from bi and able to reach bi
        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); nb];
        for (b, blk) in blocks.iter().enumerate() {
            for e in &blk.out_edges {
                preds[e.0 as usize].push(b);
            }
        }
        let mut reach_bi = vec![false; nb];
        let mut st = vec![bi];
        reach_bi[bi] = true;
        while let Some(x) = st.pop() {
            for &p in &preds[x] {
                if !std::mem::replace(&mut reach_bi[p], true) {
                    st.push(p);
                }
            }
        }
        let mut from_bi = vec![false; nb];
        let mut st = vec![bi];
        from_bi[bi] = true;
        while let Some(x) = st.pop() {
            for e in &blocks[x].out_edges {
                if !std::mem::replace(&mut from_bi[e.0 as usize], true) {
                    st.push(e.0 as usize);
                }
            }
        }
        if !reach_bi.iter().enumerate().any(|(b, &r)| r && from_bi[b] && b != bi) {
            continue; // not a switch-in-loop — a forward switch, always recovered
        }
        let in_loop = |b: usize| reach_bi[b] && from_bi[b];
        let mut exit_targets = BTreeSet::new();
        for (b, blk) in blocks.iter().enumerate() {
            if in_loop(b) {
                for e in &blk.out_edges {
                    if !in_loop(e.0 as usize) {
                        exit_targets.insert(e.0 as usize);
                    }
                }
            }
        }
        if exit_targets.len() > 1 {
            blocks[bi].out_edges.clear();
        }
    }

    // Reachability from the entry (block 0): Ghidra's followFlow only traces code
    // reachable from the entry, so trailing/other-function code the linear lifter swept
    // up is dropped here.
    // Root at the block holding the function's entry address — not block 0, which is merely the
    // lowest-address block. gcc emits `.cold` fragments *below* the entry, so the entry block need
    // not be first; Ghidra's followFlow traces from the entry point, not the lowest address.
    let entry_off = f.addr.offset;
    let entry_block = (0..nb)
        .find(|&b| blocks[b].ops.first().is_some_and(|&op| f.op(op).seqnum.pc.offset == entry_off))
        .unwrap_or(0);
    let mut reachable = vec![false; nb];
    let mut stack = vec![entry_block];
    reachable[entry_block] = true;
    while let Some(b) = stack.pop() {
        for o in blocks[b].out_edges.clone() {
            let o = o.0 as usize;
            if !reachable[o] {
                reachable[o] = true;
                stack.push(o);
            }
        }
    }
    // Destroy the ops of unreachable blocks (e.g. declined switch cases, trailing code) so
    // heritage never sees an orphaned def with no parent block.
    let to_destroy: Vec<OpId> =
        (0..nb).filter(|&b| !reachable[b]).flat_map(|b| blocks[b].ops.clone()).collect();
    for op in to_destroy {
        f.op_destroy(op);
    }

    // Renumber reachable blocks with the entry block first, so it becomes block 0 — the dominator
    // and heritage root. (Address order otherwise; for an entry that is already the lowest address
    // this is a no-op.)
    let mut order: Vec<usize> = Vec::with_capacity(nb);
    if reachable[entry_block] {
        order.push(entry_block);
    }
    order.extend((0..nb).filter(|&b| reachable[b] && b != entry_block));
    let mut newid = vec![u32::MAX; nb];
    for (new, &b) in order.iter().enumerate() {
        newid[b] = new as u32;
    }
    let mut pruned: Vec<BlockBasic> = Vec::with_capacity(order.len());
    for &b in &order {
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
