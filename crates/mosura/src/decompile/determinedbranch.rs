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
use super::op::{OpId, SeqNum};
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

/// Ghidra `Funcdata::spliceBlockBasic` (funcdata_block.cc:908) + `BlockGraph::spliceBlock`
/// (block.cc:1597): merge a block with exactly one output into its successor with exactly one
/// input — destroy `bb`'s trailing branch, move the successor's ops into `bb`, give `bb` the
/// successor's out-edges, and remove the successor from the graph. Declines (returns `false`)
/// where Ghidra throws: the successor must not start with a MULTIEQUAL (with a single in-edge it
/// never should). The successor's `f_switch_out` character transfers with its terminating op.
fn splice_block_basic(f: &mut Funcdata, bb: BlockId) -> bool {
    if f.block(bb).out_edges.len() != 1 {
        return false;
    }
    let outbl = f.block(bb).out_edges[0];
    if f.block(outbl).in_edges.len() != 1 {
        return false;
    }
    if f.block(outbl).ops.first().is_some_and(|&o| f.op(o).code() == OpCode::Multiequal) {
        return false; // Ghidra: "Splicing block with MULTIEQUAL"
    }
    // Remove any jump op at the end of bb.
    if let Some(&last) = f.block(bb).ops.last() {
        if f.op(last).code().is_branch() {
            f.op_destroy(last);
            f.block_mut(bb).ops.pop();
        }
    }
    // Move the successor's ops to the end of bb.
    let moved = std::mem::take(&mut f.block_mut(outbl).ops);
    for &op in &moved {
        f.op_mut(op).parent = Some(bb);
    }
    f.block_mut(bb).ops.extend(moved);
    // Graph splice: bb takes outbl's out-edges; successors repoint their in-edge at bb.
    let outs = f.block(outbl).out_edges.clone();
    for &o in &outs {
        for e in f.block_mut(o).in_edges.iter_mut() {
            if *e == outbl {
                *e = bb;
            }
        }
    }
    f.block_mut(bb).out_edges = outs;
    f.block_mut(outbl).in_edges.clear();
    f.block_mut(outbl).out_edges.clear();
    // Remove the emptied block from the list (compact + renumber, entry stays block 0).
    let mut reachable = vec![true; f.num_blocks()];
    reachable[outbl.0 as usize] = false;
    renumber_reachable(f, &reachable);
    true
}

/// Ghidra `ActionRedundBranch` (coreaction.cc:3492, `actmainloop` slot :5658 "deadcontrolflow"):
/// remove redundant branches. Two arms: a block with a single out-edge whose successor has a
/// single in-edge is spliced into it (unless the successor is the entry or the block is a switch
/// exit — splicing a single-exit switch's target would block second-stage recovery); and a
/// multi-out block whose exits all reach the same block loses its branch (`removeBranch`), the
/// decision being vacuous.
pub struct ActionRedundBranch;

impl Action for ActionRedundBranch {
    fn name(&self) -> &str {
        "redundbranch"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        let mut count = 0;
        let mut i = 0;
        while i < data.num_blocks() {
            let bb = BlockId(i as u32);
            i += 1;
            if data.block(bb).out_edges.is_empty() {
                continue;
            }
            let bl = data.block(bb).out_edges[0];
            if data.block(bb).out_edges.len() == 1 {
                if data.block(bl).in_edges.len() == 1 && bl.0 != 0 && !is_switch_out(data, bb) {
                    // Do not splice a block coming from a single-exit switch, as this prevents
                    // possible second-stage recovery.
                    if splice_block_basic(data, bb) {
                        count += 1;
                        i = 0; // this removed one block, so restart the scan
                    }
                }
                continue;
            }
            // Are all exits to the same block?
            if data.block(bb).out_edges.iter().all(|&o| o == bl) {
                branch_remove_internal(data, bb, 1); // = Funcdata::removeBranch
                count += 1;
            }
        }
        count
    }
}

/// Ghidra `BlockBasic::hasOnlyMarkers` (block.cc:2580): only MULTIEQUAL/INDIRECT placeholders and
/// branch operations — nothing substantial.
fn has_only_markers(f: &Funcdata, bb: BlockId) -> bool {
    f.block(bb).ops.iter().all(|&op| {
        let o = f.op(op);
        o.is_marker() || o.code().is_branch()
    })
}

/// Ghidra `FlowBlock::isSwitchOut` — the block ends in a BRANCHIND with a recovered jump table.
/// (Ghidra sets `f_switch_out` on the block when the JumpTable links; mosura derives it from the
/// recovered-table map, keyed by the BRANCHIND's address.)
fn is_switch_out(f: &Funcdata, bb: BlockId) -> bool {
    f.block(bb).ops.last().is_some_and(|&op| {
        f.op(op).code() == OpCode::Branchind
            && f.switch_targets.contains_key(&f.op(op).seqnum.pc.offset)
    })
}

/// Ghidra `BlockBasic::isDoNothing` (block.cc:2596): a block with exactly one out-edge, at least
/// one in-edge, no BRANCHIND terminator, and only marker/branch ops. A switch target whose
/// successor joins other edges is kept (the switch edge may still propagate a unique value).
fn is_do_nothing(f: &Funcdata, bb: BlockId) -> bool {
    if f.block(bb).out_edges.len() != 1 {
        return false; // a do-nothing block has exactly one out (no return or cbranch)
    }
    if f.block(bb).in_edges.is_empty() {
        return false; // a starting block may need to be a placeholder for global vars
    }
    for &switchbl in &f.block(bb).in_edges {
        if !is_switch_out(f, switchbl) {
            continue;
        }
        if f.block(switchbl).out_edges.len() > 1 {
            // This block is a switch target; if multiple edges come together at the successor,
            // the switch edge may still be propagating a unique value — don't remove it.
            if f.block(f.block(bb).out_edges[0]).in_edges.len() > 1 {
                return false;
            }
        }
    }
    if f.block(bb).ops.last().is_some_and(|&op| f.op(op).code() == OpCode::Branchind) {
        return false; // don't remove single-out indirect jumps
    }
    has_only_markers(f, bb)
}

/// Ghidra `BlockBasic::unblockedMulti` (block.cc:2534): does removing `bb` (collapsing it into out
/// edge `outslot`) leave redundant MULTIEQUAL entries that are inconsistent? A MULTIEQUAL can hide
/// an implied copy, in which case `bb` is actually doing something and must not be removed.
fn unblocked_multi(f: &Funcdata, bb: BlockId, outslot: usize) -> bool {
    let blout = f.block(bb).out_edges[outslot];
    // Blocks which would end up with redundant branches into blout.
    let mut redundlist: Vec<BlockId> = Vec::new();
    for &bl in &f.block(bb).in_edges {
        for &o in &f.block(bl).out_edges {
            if o == blout {
                redundlist.push(bl);
            }
        }
    }
    if redundlist.is_empty() {
        return true;
    }
    for &multiop in &f.block(blout).ops {
        if f.op(multiop).code() != OpCode::Multiequal {
            continue;
        }
        for &bl in &redundlist {
            let slot_redund =
                f.block(blout).in_edges.iter().position(|&p| p == bl).expect("redundant in-edge");
            let slot_remove =
                f.block(blout).in_edges.iter().position(|&p| p == bb).expect("bb feeds blout");
            let vnredund = f.op(multiop).input(slot_redund).expect("phi input per in-edge");
            let mut vnremove = f.op(multiop).input(slot_remove).expect("phi input per in-edge");
            if let Some(def) = f.vn(vnremove).def {
                if f.op(def).code() == OpCode::Multiequal && f.op(def).parent == Some(bb) {
                    let s = f
                        .block(bb)
                        .in_edges
                        .iter()
                        .position(|&p| p == bl)
                        .expect("bl feeds bb too");
                    vnremove = f.op(def).input(s).expect("phi input per in-edge");
                }
            }
            if vnremove != vnredund {
                return false; // redundant branches must be identical
            }
        }
    }
    true
}

/// Ghidra `Funcdata::pushMultiequals` (funcdata_block.cc:84): assuming `bb` is being removed, force
/// any Varnode defined by a MULTIEQUAL in `bb` to be defined in the output block instead — an
/// artificial MULTIEQUAL at the head of the out-block whose `bb`-edge input is the original value
/// and every other input is itself (all alternate ins to the out-block are dominated by `bb`).
fn push_multiequals(f: &mut Funcdata, bb: BlockId) {
    if f.block(bb).out_edges.is_empty() {
        return;
    }
    // Take the first output block; for a do-nothing block it is the only one.
    let outblock = f.block(bb).out_edges[0];
    let outblock_ind =
        f.block(outblock).in_edges.iter().position(|&p| p == bb).expect("bb feeds its out-block");
    for origop in f.block(bb).ops.clone() {
        if f.op(origop).code() != OpCode::Multiequal {
            continue;
        }
        let Some(origvn) = f.op(origop).output else { continue };
        if f.vn(origvn).descend.is_empty() {
            continue;
        }
        let mut needreplace = false;
        let mut neednewunique = false;
        for &rop in &f.vn(origvn).descend {
            if f.op(rop).code() == OpCode::Multiequal && f.op(rop).parent == Some(outblock) {
                // Check for a reference to origvn NOT through the dead edge.
                let mut dead_edge = true;
                for i in 0..f.op(rop).num_inputs() {
                    if i == outblock_ind {
                        continue; // not going through the dead edge
                    }
                    if f.op(rop).input(i) == Some(origvn) {
                        dead_edge = false;
                        break;
                    }
                }
                if dead_edge {
                    // If origvn is addrtied and feeds a MULTIEQUAL at the same address in the
                    // out-block, any use beyond the out-block that did not go through that
                    // MULTIEQUAL must have propagated through some other register — so the new
                    // MULTIEQUAL writes to a unique.
                    if f.vn(origvn).loc
                        == f.vn(f.op(rop).output.expect("phi output")).loc
                        && f.vn(origvn).is_addrtied()
                    {
                        neednewunique = true;
                    }
                    continue;
                }
            }
            needreplace = true;
            break;
        }
        if !needreplace {
            continue;
        }
        // Construct the artificial MULTIEQUAL at the out-block's start.
        let size = f.vn(origvn).size;
        let start_pc =
            f.block(outblock).ops.first().map(|&o| f.op(o).seqnum.pc).unwrap_or(f.addr);
        let uniq = f.num_ops() as u32;
        let replaceop = f.new_op(OpCode::Multiequal, SeqNum { pc: start_pc, uniq }, vec![]);
        let replacevn = if neednewunique {
            f.new_output_unique(replaceop, size)
        } else {
            let loc = f.vn(origvn).loc;
            f.new_output(replaceop, size, loc)
        };
        let branches: Vec<_> = f
            .block(outblock)
            .in_edges
            .clone()
            .iter()
            .map(|&inb| if inb == bb { origvn } else { replacevn })
            .collect();
        f.op_set_all_input(replaceop, &branches);
        f.op_insert_begin(replaceop, outblock);
        // Replace obsolete origvn reads with replacevn — one input slot per descend entry, keeping
        // the dead-edge slot of out-block MULTIEQUALs (Ghidra's titer walk).
        for rop in f.vn(origvn).descend.clone() {
            if rop == replaceop {
                continue; // the artificial phi's own bb-edge input stays origvn
            }
            for i in 0..f.op(rop).num_inputs() {
                if f.op(rop).input(i) != Some(origvn) {
                    continue;
                }
                if i == outblock_ind
                    && f.op(rop).parent == Some(outblock)
                    && f.op(rop).code() == OpCode::Multiequal
                {
                    continue;
                }
                f.op_set_input(rop, i, replacevn);
                break;
            }
        }
    }
}

/// The dataflow-preserving arm of Ghidra `Funcdata::blockRemoveInternal(bb, unreachable=false)`
/// (funcdata_block.cc:254): push `bb`'s MULTIEQUALs into the out-block, expand the out-block's
/// MULTIEQUAL slot for the dead edge into one input per `bb` in-edge, rewire every in-edge of `bb`
/// directly to the out-block (Ghidra `BlockGraph::removeFromFlow`, appending in `bb`'s in order so
/// edge order matches the expanded phi inputs), destroy `bb`'s ops, and drop the block. (The
/// `unreachable=true` arm is [`remove_unreachable_blocks`] above.)
fn block_remove_internal_preserving(f: &mut Funcdata, bb: BlockId) {
    // A removed BRANCHIND drops its recovered jump table (Ghidra `Funcdata::removeJumpTable`).
    if let Some(&last) = f.block(bb).ops.last() {
        if f.op(last).code() == OpCode::Branchind {
            let pc = f.op(last).seqnum.pc.offset;
            f.switch_targets.remove(&pc);
            f.switch_defaults.remove(&pc);
        }
    }
    push_multiequals(f, bb); // make sure data flow is preserved

    let outs = f.block(bb).out_edges.clone();
    for &bbout in &outs {
        let blocknum =
            f.block(bbout).in_edges.iter().position(|&p| p == bb).expect("bb feeds its out-block");
        let phis: Vec<OpId> = f
            .block(bbout)
            .ops
            .iter()
            .copied()
            .filter(|&op| f.op(op).code() == OpCode::Multiequal)
            .collect();
        for op in phis {
            let deadvn = f.op(op).input(blocknum).expect("phi input per in-edge");
            f.op_remove_input(op, blocknum); // remove the deleted block's branch
            let deadop = f.vn(deadvn).def;
            let from_phi = deadop.is_some_and(|d| {
                f.op(d).code() == OpCode::Multiequal && f.op(d).parent == Some(bb)
            });
            let n_in = f.block(bb).in_edges.len();
            for j in 0..n_in {
                // Append the dead MULTIEQUAL's branches — otherwise copies of the dead value.
                let v = if from_phi {
                    f.op(deadop.expect("checked")).input(j).expect("phi input per in-edge")
                } else {
                    deadvn
                };
                let at = f.op(op).num_inputs();
                f.op_insert_input(op, at, v);
            }
            op_zero_multi(f, op);
        }
    }
    // BlockGraph::removeFromFlow — sever bb->out, then redirect each in-edge of bb to the
    // out-block, appending to the out-block's in list in bb's in order.
    while let Some(&bbout) = f.block(bb).out_edges.last() {
        f.block_mut(bb).out_edges.pop();
        let pos = f.block(bbout).in_edges.iter().position(|&p| p == bb).expect("edge exists");
        f.block_mut(bbout).in_edges.remove(pos);
        let ins = std::mem::take(&mut f.block_mut(bb).in_edges);
        for &inb in &ins {
            let opos =
                f.block(inb).out_edges.iter().position(|&o| o == bb).expect("in-edge exists");
            f.block_mut(inb).out_edges[opos] = bbout;
            f.block_mut(bbout).in_edges.push(inb);
        }
    }
    // Destroy the ops (all data flow through the block has been patched away). A surviving
    // descendant outside bb means the patch-up failed (Ghidra throws "Deleting op with
    // descendants").
    let ops = std::mem::take(&mut f.block_mut(bb).ops);
    for &op in &ops {
        if let Some(out) = f.op(op).output {
            assert!(
                f.vn(out).descend.iter().all(|&d| f.op(d).parent == Some(bb)),
                "deleting op with descendants"
            );
        }
    }
    for op in ops {
        f.op_destroy(op);
    }
    // Remove the block from the graph (mosura's renumbering removal pattern; bb's edges are
    // already severed so the remap drops nothing else).
    let mut keep = vec![true; f.num_blocks()];
    keep[bb.0 as usize] = false;
    renumber_reachable(f, &keep);
}

/// Ghidra `Funcdata::removeDoNothingBlock` (funcdata_block.cc:327): remove a reachable block that
/// contains only markers and an unconditional branch.
fn remove_do_nothing_block(f: &mut Funcdata, bb: BlockId) {
    assert!(f.block(bb).out_edges.len() <= 1, "cannot delete a reachable block with >1 out");
    block_remove_internal_preserving(f, bb);
}

/// Ghidra `ActionDoNothing` (coreaction.cc:3466), wired in the full-loop tail between
/// `ActionDeadCode` and `ActionSwitchNorm` (coreaction.cc:5683, group "deadcontrolflow"): remove
/// blocks that do nothing. Collapsing a marker-only join block pushes its MULTIEQUALs into the
/// successor's (e.g. a switch's common join: the per-case values become direct inputs of the loop
/// header phi), which is the IR shape the merge phase's cover trims key off. Ghidra removes one
/// block per application under `rule_repeatapply`; the internal loop here is equivalent.
pub struct ActionDoNothing;

impl Action for ActionDoNothing {
    fn name(&self) -> &str {
        "donothing"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        let mut count = 0;
        loop {
            let found = (0..data.num_blocks()).map(|b| BlockId(b as u32)).find(|&bb| {
                if !is_do_nothing(data, bb) {
                    return false;
                }
                // A do-nothing block looping to itself is an infinite loop (Ghidra warns and
                // keeps it).
                if data.block(bb).out_edges[0] == bb {
                    return false;
                }
                unblocked_multi(data, bb, 0)
            });
            let Some(bb) = found else { break };
            remove_do_nothing_block(data, bb);
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

    /// `ActionRedundBranch` arm 1 (coreaction.cc:3505): a single-out block whose successor has a
    /// single in-edge is spliced into it — the trailing branch dies and the two op lists join.
    #[test]
    fn redundbranch_splices_single_in_single_out_pair() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let s = |u: u32| SeqNum { pc: Address::new(ram, u as u64), uniq: u };
        let c = f.new_const(8, 1);
        let o1 = f.new_op(OpCode::IntAdd, s(0), vec![c, c]);
        let v1 = f.new_output(o1, 8, Address::new(reg, 0));
        let br = f.new_op(OpCode::Branch, s(1), vec![]);
        let o2 = f.new_op(OpCode::IntAdd, s(2), vec![v1, c]);
        let _v2 = f.new_output(o2, 8, Address::new(reg, 8));
        let ret = f.new_op(OpCode::Return, s(3), vec![]);
        let blocks = vec![
            BlockBasic { ops: vec![o1, br], in_edges: vec![], out_edges: vec![BlockId(1)] },
            BlockBasic { ops: vec![o2, ret], in_edges: vec![BlockId(0)], out_edges: vec![] },
        ];
        for (bi, blk) in blocks.iter().enumerate() {
            for &opid in &blk.ops {
                f.op_mut(opid).parent = Some(BlockId(bi as u32));
            }
        }
        f.set_blocks(blocks);

        let n = ActionRedundBranch.apply(&mut f);
        assert_eq!(n, 1, "one splice");
        assert_eq!(f.num_blocks(), 1, "the pair collapses to one block");
        assert!(f.op(br).is_dead(), "the trailing branch is destroyed");
        assert_eq!(f.block(BlockId(0)).ops, vec![o1, o2, ret]);
        assert!(f.block(BlockId(0)).out_edges.is_empty());
    }

    /// `ActionRedundBranch` arm 2 (coreaction.cc:3515): a CBRANCH both of whose exits reach the
    /// same block is vacuous — the branch is removed (`removeBranch`), leaving one edge.
    #[test]
    fn redundbranch_removes_branch_with_all_exits_equal() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let s = |u: u32| SeqNum { pc: Address::new(ram, u as u64), uniq: u };
        let c = f.new_const(1, 1);
        let cbr = f.new_op(OpCode::Cbranch, s(0), vec![c, c]);
        let o = f.new_op(OpCode::IntAdd, s(1), vec![c, c]);
        let _v = f.new_output(o, 8, Address::new(reg, 0));
        let ret = f.new_op(OpCode::Return, s(2), vec![]);
        let blocks = vec![
            BlockBasic { ops: vec![cbr], in_edges: vec![], out_edges: vec![BlockId(1), BlockId(1)] },
            BlockBasic { ops: vec![o, ret], in_edges: vec![BlockId(0), BlockId(0)], out_edges: vec![] },
        ];
        for (bi, blk) in blocks.iter().enumerate() {
            for &opid in &blk.ops {
                f.op_mut(opid).parent = Some(BlockId(bi as u32));
            }
        }
        f.set_blocks(blocks);

        let n = ActionRedundBranch.apply(&mut f);
        assert_eq!(n, 1, "the vacuous branch is removed");
        assert!(f.op(cbr).is_dead(), "the CBRANCH is destroyed");
        // A single edge remains (the splice of the now single-in/single-out pair happens on a
        // later invocation — Ghidra's scan does not restart after this arm).
        assert_eq!(f.block(BlockId(0)).out_edges, vec![BlockId(1)]);
        assert_eq!(f.block(BlockId(1)).in_edges, vec![BlockId(0)]);
    }

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

    /// A marker-only join block (a MULTIEQUAL + BRANCH) between two case blocks and a loop
    /// header: `ActionDoNothing` removes it, expanding the join's phi values directly into the
    /// header phi's slot for the removed edge (Ghidra `removeDoNothingBlock` →
    /// `blockRemoveInternal` → the dead-phi expansion), and rewiring the case blocks to the
    /// header — the switchloop accumulator flattening.
    #[test]
    fn do_nothing_join_block_pushes_phi_into_successor() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = |o: u64| SeqNum { pc: Address::new(ram, o), uniq: 0 };

        // block0 (entry): r0 = 1; branch to header (block4)
        let c1 = f.new_const(4, 1);
        let init = f.new_op(OpCode::Copy, seq(0x0), vec![c1]);
        let r_init = f.new_output(init, 4, Address::new(reg, 0));
        let t0 = f.new_const(8, 0x40);
        let br0 = f.new_op(OpCode::Branch, seq(0x4), vec![t0]);
        // block1 / block2 (cases): r0 = 2 / r0 = 3, both branch to the join (block3)
        let c2 = f.new_const(4, 2);
        let case1 = f.new_op(OpCode::Copy, seq(0x10), vec![c2]);
        let r_case1 = f.new_output(case1, 4, Address::new(reg, 0));
        let t1 = f.new_const(8, 0x30);
        let br1 = f.new_op(OpCode::Branch, seq(0x14), vec![t1]);
        let c3 = f.new_const(4, 3);
        let case2 = f.new_op(OpCode::Copy, seq(0x20), vec![c3]);
        let r_case2 = f.new_output(case2, 4, Address::new(reg, 0));
        let t2 = f.new_const(8, 0x30);
        let br2 = f.new_op(OpCode::Branch, seq(0x24), vec![t2]);
        // block3 (join, marker-only): rj = MULTIEQUAL(r_case1, r_case2); BRANCH header
        let join_phi = f.new_op(OpCode::Multiequal, seq(0x30), vec![r_case1, r_case2]);
        let r_join = f.new_output(join_phi, 4, Address::new(reg, 0));
        let t3 = f.new_const(8, 0x40);
        let br3 = f.new_op(OpCode::Branch, seq(0x34), vec![t3]);
        // block4 (header): rh = MULTIEQUAL(r_init, rj); RETURN rh — preds [block0, block3]
        let head_phi = f.new_op(OpCode::Multiequal, seq(0x40), vec![r_init, r_join]);
        let r_head = f.new_output(head_phi, 4, Address::new(reg, 0));
        let ret = f.new_op(OpCode::Return, seq(0x44), vec![r_head]);

        f.set_blocks(vec![
            BlockBasic {
                ops: vec![init, br0],
                in_edges: vec![],
                out_edges: vec![BlockId(4)],
            },
            BlockBasic { ops: vec![case1, br1], in_edges: vec![], out_edges: vec![BlockId(3)] },
            BlockBasic { ops: vec![case2, br2], in_edges: vec![], out_edges: vec![BlockId(3)] },
            BlockBasic {
                ops: vec![join_phi, br3],
                in_edges: vec![BlockId(1), BlockId(2)],
                out_edges: vec![BlockId(4)],
            },
            BlockBasic {
                ops: vec![head_phi, ret],
                in_edges: vec![BlockId(0), BlockId(3)],
                out_edges: vec![],
            },
        ]);
        for (bi, ops) in [
            (0u32, vec![init, br0]),
            (1, vec![case1, br1]),
            (2, vec![case2, br2]),
            (3, vec![join_phi, br3]),
            (4, vec![head_phi, ret]),
        ] {
            for op in ops {
                f.op_mut(op).parent = Some(BlockId(bi));
            }
        }

        let n = ActionDoNothing.apply(&mut f);
        assert_eq!(n, 1, "exactly the join block is removed");
        assert_eq!(f.num_blocks(), 4);
        // The header phi expanded: the join edge's slot was replaced by the join phi's inputs,
        // appended after the surviving slots (Ghidra appends at the end).
        assert_eq!(f.op(head_phi).code(), OpCode::Multiequal);
        assert_eq!(
            (0..f.op(head_phi).num_inputs()).filter_map(|i| f.op(head_phi).input(i)).collect::<Vec<_>>(),
            vec![r_init, r_case1, r_case2],
            "the join's per-case values become direct header-phi inputs"
        );
        // The case blocks now flow directly to the header (block indices shifted down by one).
        let head = BlockId(3);
        assert_eq!(f.block(BlockId(1)).out_edges, vec![head]);
        assert_eq!(f.block(BlockId(2)).out_edges, vec![head]);
        assert_eq!(f.block(head).in_edges, vec![BlockId(0), BlockId(1), BlockId(2)]);
        // The join phi itself is destroyed.
        assert!(f.op(join_phi).is_dead(), "the pushed MULTIEQUAL is destroyed with its block");
    }

    /// `unblockedMulti` (block.cc:2534) blocks the removal when a predecessor also branches
    /// directly to the successor with a DIFFERENT phi value — the do-nothing block's MULTIEQUAL
    /// hides an implied copy.
    #[test]
    fn do_nothing_removal_declines_on_inconsistent_redundant_edge() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = |o: u64| SeqNum { pc: Address::new(ram, o), uniq: 0 };

        // block0: rA = 1; CBRANCH — edges to block1 (the do-nothing candidate) AND block2.
        let c1 = f.new_const(4, 1);
        let defa = f.new_op(OpCode::Copy, seq(0x0), vec![c1]);
        let ra = f.new_output(defa, 4, Address::new(reg, 0));
        let cond = f.new_const(1, 0);
        let tcb = f.new_const(8, 0x10);
        let cbr = f.new_op(OpCode::Cbranch, seq(0x4), vec![tcb, cond]);
        // block1 (marker-only): rb = MULTIEQUAL(ra); BRANCH block2 — a 1-in do-nothing block.
        let mid_phi = f.new_op(OpCode::Multiequal, seq(0x10), vec![ra]);
        let rb = f.new_output(mid_phi, 4, Address::new(reg, 4));
        let t1 = f.new_const(8, 0x20);
        let br1 = f.new_op(OpCode::Branch, seq(0x14), vec![t1]);
        // block2: rc = MULTIEQUAL(rd [direct from block0], rb [thru block1]); RETURN — the direct
        // edge carries a DIFFERENT varnode, so collapsing block1 would leave inconsistent slots.
        let c9 = f.new_const(4, 9);
        let defd = f.new_op(OpCode::Copy, seq(0x6), vec![c9]);
        let rd = f.new_output(defd, 4, Address::new(reg, 8));
        let out_phi = f.new_op(OpCode::Multiequal, seq(0x20), vec![rd, rb]);
        let rc = f.new_output(out_phi, 4, Address::new(reg, 12));
        let ret = f.new_op(OpCode::Return, seq(0x24), vec![rc]);

        f.set_blocks(vec![
            BlockBasic {
                ops: vec![defa, defd, cbr],
                in_edges: vec![],
                out_edges: vec![BlockId(1), BlockId(2)],
            },
            BlockBasic {
                ops: vec![mid_phi, br1],
                in_edges: vec![BlockId(0)],
                out_edges: vec![BlockId(2)],
            },
            BlockBasic {
                ops: vec![out_phi, ret],
                in_edges: vec![BlockId(0), BlockId(1)],
                out_edges: vec![],
            },
        ]);
        for (bi, ops) in
            [(0u32, vec![defa, defd, cbr]), (1, vec![mid_phi, br1]), (2, vec![out_phi, ret])]
        {
            for op in ops {
                f.op_mut(op).parent = Some(BlockId(bi));
            }
        }

        assert!(is_do_nothing(&f, BlockId(1)), "marker-only single-out block qualifies");
        assert!(
            !unblocked_multi(&f, BlockId(1), 0),
            "the redundant direct edge carries a different value — removal must decline"
        );
        let n = ActionDoNothing.apply(&mut f);
        assert_eq!(n, 0, "ActionDoNothing leaves the implied-copy block in place");
        assert_eq!(f.num_blocks(), 3);
    }
}
