//! Conditional-constant propagation — a faithful port of Ghidra's `ActionConditionalConst`
//! (`coreaction.hh:569`, `coreaction.cc:4514`). When a CBRANCH tests a Varnode against a constant
//! (`if (x == c) …`), then down the equal edge `x` is known to equal `c`; every read of `x` in a
//! block dominated by that edge is replaced with the constant `c`, and reads through pure
//! arithmetic are constant-folded (`pushConstant`). Reads that flow into a MULTIEQUAL are handled
//! specially: the constant is pushed onto the phi edge only when the value does not rejoin the
//! non-constant flow (`handlePhiNodes`/`flowToAlternatePath`) — which is what keeps a value that
//! merges back (Ghidra's `condconst_conn`) un-propagated.
//!
//! Ghidra runs this as the last action in its mainloop (after block structuring / determined-branch
//! removal), so the surrounding rule pool re-runs afterward to fold the substituted constants
//! (`0 + y => y`, `7 + 9 => 0x10`). The graph edits here are data-flow only (`opSetInput`, plus
//! COPY insertion into existing blocks); the CFG edges are untouched, so the dominator tree computed
//! once at the top of `apply` stays valid throughout.

use std::collections::{HashSet, VecDeque};

use super::action::Action;
use super::block::BlockId;
use super::dominator::{self, Dominators};
use super::funcdata::Funcdata;
use super::jumpbasic::PcodeOpNode;
use super::op::{OpId, SeqNum};
use super::opcode::OpCode;
use super::rules::eval_const;
use super::varnode::VarnodeId;

/// Ghidra `ActionConditionalConst::ConstPoint` (`coreaction.hh:571`): a point in control-flow where
/// a Varnode propagates as a constant down a conditional branch.
#[derive(Clone)]
struct ConstPoint {
    /// The Varnode that is constant for some reads.
    vn: VarnodeId,
    /// The representative constant Varnode, created lazily (`None` until first needed).
    const_vn: Option<VarnodeId>,
    /// The constant value.
    value: u64,
    /// Block that dominates all reads where `vn` is constant (index into the block list).
    const_block: usize,
    /// Input edge from the condition block (the MULTIEQUAL slot the constant edge feeds).
    in_slot: i32,
    /// Is the block dominated by the constant path (the constant "holds" down the whole block)?
    block_is_dom: bool,
}

/// Ghidra `Varnode::loneDescend`: the single reading op, or `None` if read zero or many times.
fn lone_descend(f: &Funcdata, vn: VarnodeId) -> Option<OpId> {
    let d = &f.vn(vn).descend;
    (d.len() == 1).then(|| d[0])
}

/// The `special` eval-type ops (`typeop.cc`): LOAD/STORE/BRANCH/CBRANCH/BRANCHIND/CALL/CALLIND/
/// CALLOTHER/RETURN/MULTIEQUAL/INDIRECT/CAST/SEGMENTOP/CPOOLREF/NEW. None of these is foldable by
/// [`eval_const`], so `eval_const` returning `None` already subsumes Ghidra's `getEvalType() &
/// special` guard in `pushConstant`; the float guard there is kept explicit because `eval_const`
/// *does* fold floating-point ops, which Ghidra deliberately skips.
fn is_float_op(opc: OpCode) -> bool {
    use OpCode::*;
    matches!(
        opc,
        FloatEqual | FloatNotequal | FloatLess | FloatLessequal | FloatNan | FloatAdd | FloatSub
            | FloatMult | FloatDiv | FloatNeg | FloatAbs | FloatSqrt | FloatInt2float
            | FloatFloat2float | FloatTrunc | FloatCeil | FloatFloor | FloatRound
    )
}

/// Ghidra `FlowBlock::restrictedByConditional` (`block.cc:405`): is the constant value implied by
/// `cond` guaranteed to hold throughout `block`? True when the only way into `block` is directly
/// from `cond` (no sibling path reaches it that would carry a different value).
fn restricted_by_conditional(f: &Funcdata, dom: &Dominators, block: usize, cond: usize) -> bool {
    let in_edges: Vec<usize> = f.block(BlockId(block as u32)).in_edges.iter().map(|e| e.0 as usize).collect();
    if in_edges.len() == 1 {
        return true; // impossible for any path to come through a sibling to this
    }
    if dom.idom[block] != cond {
        return false; // not dominated by the conditional block at all
    }
    let mut seen_cond = false;
    for &in_block in &in_edges {
        if in_block == cond {
            if seen_cond {
                return false; // coming in from cond on multiple direct edges
            }
            seen_cond = true;
            continue;
        }
        let mut b = in_block;
        while b != block {
            if b == cond {
                return false; // must have come through a sibling
            }
            b = dom.idom[b];
        }
    }
    true
}

/// Ghidra `FlowBlock::getOutRevIndex(i)`: the input-edge index on out-edge `i`'s target that comes
/// back from `block`. mosura orders a MULTIEQUAL's inputs by its parent's in-edge order
/// (`heritage.rs`), so this reverse index *is* the phi input slot the edge feeds.
fn get_out_rev_index(f: &Funcdata, block: usize, out_i: usize) -> i32 {
    let target = f.block(BlockId(block as u32)).out_edges[out_i].0 as usize;
    f.block(BlockId(target as u32))
        .in_edges
        .iter()
        .position(|e| e.0 as usize == block)
        .expect("out-edge target has this block as a predecessor") as i32
}

/// Ghidra `ActionConditionalConst::collectReachable` (`coreaction.cc:4083`): collect the COPY,
/// INDIRECT, and MULTIEQUAL ops reachable from `vn` without going through an excised phi edge.
/// `phi_edges` must be sorted (for the excised-edge membership test); the reached ops are returned
/// and their ids added to `op_marks`.
fn collect_reachable(
    f: &Funcdata,
    vn: VarnodeId,
    phi_edges: &[PcodeOpNode],
    op_marks: &mut HashSet<OpId>,
) -> Vec<OpId> {
    let excised = |op: OpId, slot: usize| -> bool {
        phi_edges.binary_search_by(|n| (n.op.0, n.slot).cmp(&(op.0, slot as i32))).is_ok()
    };
    let mut reachable: Vec<OpId> = Vec::new();
    let mut count = 0;
    let mut vn = vn;
    if f.vn(vn).is_written() {
        let op = f.vn(vn).def.unwrap();
        if f.op(op).code() == OpCode::Multiequal {
            // Considering the defining MULTIEQUAL "reachable" lets flowToAlternatePath discover a
            // loop back to vn from the constBlock, even if no other non-constant path survives.
            op_marks.insert(op);
            reachable.push(op);
        }
    }
    loop {
        for op in f.vn(vn).descend.clone() {
            if op_marks.contains(&op) {
                continue;
            }
            let opc = f.op(op).code();
            if opc == OpCode::Multiequal {
                let ninput = f.op(op).num_inputs();
                let mut slot = 0;
                while slot < ninput {
                    if f.op(op).input(slot) != Some(vn) {
                        slot += 1;
                        continue; // find the incoming slot for the current Varnode
                    }
                    if !excised(op, slot) {
                        break; // reached via a non-excised edge
                    }
                    slot += 1;
                }
                if slot == ninput {
                    continue; // the MULTIEQUAL was not reached (all vn edges excised)
                }
            } else if opc != OpCode::Copy && opc != OpCode::Indirect {
                continue;
            }
            reachable.push(op);
            op_marks.insert(op);
        }
        if count >= reachable.len() {
            break;
        }
        vn = f.op(reachable[count]).output.expect("reachable op has an output");
        count += 1;
    }
    reachable
}

/// Ghidra `ActionConditionalConst::flowToAlternatePath` (`coreaction.cc:4129`): following `op`'s
/// output forward through MULTIEQUAL/INDIRECT/COPY, does it rejoin the alternate (non-constant) flow
/// marked in `op_marks`?
fn flow_to_alternate_path(f: &Funcdata, op: OpId, op_marks: &HashSet<OpId>) -> bool {
    if op_marks.contains(&op) {
        return true;
    }
    let mut vn_marks: HashSet<VarnodeId> = HashSet::new();
    let mut mark_set: Vec<VarnodeId> = Vec::new();
    let vn = f.op(op).output.expect("phi op has an output");
    mark_set.push(vn);
    vn_marks.insert(vn);
    let mut count = 0;
    let mut found_path = false;
    while count < mark_set.len() {
        let vn = mark_set[count];
        count += 1;
        for next_op in f.vn(vn).descend.clone() {
            let opc = f.op(next_op).code();
            if opc == OpCode::Multiequal {
                if op_marks.contains(&next_op) {
                    found_path = true;
                    break;
                }
            } else if opc != OpCode::Copy && opc != OpCode::Indirect {
                continue;
            }
            let out_vn = f.op(next_op).output.expect("copy/phi op has an output");
            if vn_marks.contains(&out_vn) {
                continue;
            }
            vn_marks.insert(out_vn);
            mark_set.push(out_vn);
        }
        if found_path {
            break;
        }
    }
    found_path
}

/// Ghidra `ActionConditionalConst::flowTogether` (`coreaction.cc:4174`): does flow from edge `i`
/// meet flow from any other still-disconnected edge? If so, mark both edges (result 2).
fn flow_together(f: &Funcdata, edges: &[PcodeOpNode], i: usize, result: &mut [i32]) -> bool {
    let mut op_marks: HashSet<OpId> = HashSet::new();
    let start = f.op(edges[i].op).output.expect("phi op has an output");
    collect_reachable(f, start, &[], &mut op_marks); // no edge excised
    let mut res = false;
    for j in 0..edges.len() {
        if i == j {
            continue;
        }
        if result[j] == 0 {
            continue; // check for a disconnected path
        }
        if op_marks.contains(&edges[j].op) {
            result[i] = 2; // disconnected paths which flow together
            result[j] = 2;
            res = true;
        }
    }
    res
}

/// Ghidra `ActionConditionalConst::placeCopy` (`coreaction.cc:4201`): place a `COPY constVn` at the
/// end of block `bl` (before any branch) and return its fresh unique output.
fn place_copy(f: &mut Funcdata, phi_op: OpId, bl: usize, const_vn: VarnodeId) -> VarnodeId {
    let size = f.vn(const_vn).size;
    let last = f.block(BlockId(bl as u32)).ops.last().copied();
    let branch_last = last.filter(|&o| f.op(o).code().terminates_block());
    let seq_pc = match (last, branch_last) {
        (_, Some(b)) => f.op(b).seqnum.pc,   // insert before the branch, at the branch's addr
        (Some(l), None) => f.op(l).seqnum.pc, // append at block end, at the last op's addr
        (None, None) => f.op(phi_op).seqnum.pc, // empty block: use the phi op's addr
    };
    let copy_op = f.new_op(OpCode::Copy, SeqNum { pc: seq_pc, uniq: 0 }, vec![const_vn]);
    let out_vn = f.new_output_unique(copy_op, size);
    match (branch_last, last) {
        (Some(b), _) => f.op_insert_before(copy_op, b),
        (None, Some(l)) => f.op_insert_after(copy_op, l),
        (None, None) => f.op_insert_begin(copy_op, BlockId(bl as u32)),
    }
    out_vn
}

/// Ghidra `FlowBlock::findCommonBlock` (`block.cc:796`): the most immediate dominator common to all
/// blocks in `block_set` (which must be non-empty).
pub(crate) fn find_common_block(dom: &Dominators, block_set: &[usize]) -> usize {
    let mut marked: Vec<usize> = Vec::new();
    let mut res = block_set[0];
    let mut best_index = res;
    let mut bl = res;
    loop {
        marked.push(bl);
        let idom = dom.idom[bl];
        if idom == bl {
            break; // entry (idom of entry is itself in mosura's Dominators)
        }
        bl = idom;
    }
    let marked_set: HashSet<usize> = marked.iter().copied().collect();
    let mut marks = marked_set;
    for &start in block_set.iter().skip(1) {
        if best_index == 0 {
            break;
        }
        let mut bl = start;
        while !marks.contains(&bl) {
            marks.insert(bl);
            let idom = dom.idom[bl];
            if idom == bl {
                bl = idom;
                break; // entry reached; it is already marked in the first walk
            }
            bl = idom;
        }
        if bl < best_index {
            res = bl;
            best_index = res;
        }
    }
    res
}

/// Ghidra `ActionConditionalConst::placeMultipleConstants` (`coreaction.cc:4236`): place one COPY at
/// the common ancestor of all edges marked as flowing together, and repoint those phi edges at it.
fn place_multiple_constants(
    f: &mut Funcdata,
    dom: &Dominators,
    phi_edges: &[PcodeOpNode],
    marks: &[i32],
    const_vn: VarnodeId,
) {
    let mut blocks: Vec<usize> = Vec::new();
    let mut phi_op: Option<OpId> = None;
    for (i, edge) in phi_edges.iter().enumerate() {
        if marks[i] != 2 {
            continue;
        }
        phi_op = Some(edge.op);
        let parent = f.op(edge.op).parent.expect("phi has a parent block").0 as usize;
        let bl = f.block(BlockId(parent as u32)).in_edges[edge.slot as usize].0 as usize;
        blocks.push(bl);
    }
    let root_block = find_common_block(dom, &blocks);
    let out_vn = place_copy(f, phi_op.expect("at least one flow-together edge"), root_block, const_vn);
    for (i, edge) in phi_edges.iter().enumerate() {
        if marks[i] != 2 {
            continue;
        }
        f.op_set_input(edge.op, edge.slot as usize, out_vn);
    }
}

/// Ghidra `ActionConditionalConst::pushConstant` (`coreaction.cc:4261`): try to push the front
/// point's constant through `op`; on success append a new ConstPoint on `op`'s output.
fn push_constant(f: &mut Funcdata, points: &mut VecDeque<ConstPoint>, op: OpId) {
    let opc = f.op(op).code();
    if is_float_op(opc) {
        return;
    }
    let Some(out_vn) = f.op(op).output else {
        return;
    };
    if f.vn(out_vn).size as usize > 8 {
        return;
    }
    let front = points.front().unwrap().clone();
    let slot = f.op(op).inrefs.iter().position(|&v| v == front.vn).expect("op reads the point's vn");
    let ninput = f.op(op).num_inputs();
    let mut inputs: Vec<(u64, u32)> = Vec::with_capacity(ninput);
    for i in 0..ninput {
        let in_vn = f.op(op).input(i).unwrap();
        if i == slot {
            inputs.push((front.value, f.vn(in_vn).size));
        } else {
            if f.vn(in_vn).size as usize > 8 {
                return;
            }
            if f.vn(in_vn).is_constant() {
                inputs.push((f.vn(in_vn).constant_value(), f.vn(in_vn).size));
            } else {
                return; // not all inputs are constant
            }
        }
    }
    let Some(out_val) = eval_const(opc, &inputs, f.vn(out_vn).size) else {
        return; // evalError (subsumes Ghidra's `special` eval-type guard)
    };
    points.push_back(ConstPoint {
        vn: out_vn,
        const_vn: None,
        value: out_val,
        const_block: front.const_block,
        in_slot: front.in_slot,
        block_is_dom: front.block_is_dom,
    });
}

/// Ghidra `ActionConditionalConst::testAlternatePath` (`coreaction.cc:4349`): can `vn` be reached
/// backtracking through a slot of the MULTIEQUAL `op` other than `slot` (through MULTIEQUALs up to
/// `depth`, and a final INT_ADD/PTRSUB/PTRADD)?
fn test_alternate_path(f: &Funcdata, vn: VarnodeId, op: OpId, slot: i32, depth: i32) -> bool {
    for i in 0..f.op(op).num_inputs() {
        if i as i32 == slot {
            continue;
        }
        let in_vn = f.op(op).input(i).unwrap();
        if in_vn == vn {
            return true;
        }
        if f.vn(in_vn).is_written() {
            let cur_op = f.vn(in_vn).def.unwrap();
            let opc = f.op(cur_op).code();
            if matches!(opc, OpCode::IntAdd | OpCode::Ptrsub | OpCode::Ptradd) {
                if f.op(cur_op).input(0) == Some(vn) || f.op(cur_op).input(1) == Some(vn) {
                    return true;
                }
            } else if opc == OpCode::Multiequal {
                if depth == 0 {
                    continue;
                }
                if test_alternate_path(f, vn, cur_op, -1, depth - 1) {
                    return true;
                }
            }
        }
    }
    false
}

/// Ghidra `ActionConditionalConst::handlePhiNodes` (`coreaction.cc:4299`): replace the constant on
/// each phi edge that has its own disconnected path forward; for edges that flow together, share a
/// single COPY placed at their common ancestor. Returns the number of changes made.
// `&mut Vec` mirrors Ghidra's `vector<PcodeOpNode> &phiNodeEdges` (sorted in place, passed on)
#[allow(clippy::ptr_arg)]
fn handle_phi_nodes(
    f: &mut Funcdata,
    dom: &Dominators,
    var_vn: VarnodeId,
    const_vn: VarnodeId,
    phi_edges: &mut Vec<PcodeOpNode>,
) -> u32 {
    let mut count = 0;
    // collectReachable sorts phiNodeEdges in place (for its excised-edge test); everything after
    // uses that sorted order, and results[] is indexed in lock-step with it.
    phi_edges.sort_by_key(|n| (n.op.0, n.slot));
    let mut op_marks: HashSet<OpId> = HashSet::new();
    collect_reachable(f, var_vn, phi_edges, &mut op_marks);
    let mut results = vec![0i32; phi_edges.len()];
    let mut alternate = 0;
    for i in 0..phi_edges.len() {
        if !flow_to_alternate_path(f, phi_edges[i].op, &op_marks) {
            results[i] = 1; // disconnecting
            alternate += 1;
        }
    }
    drop(op_marks); // clearMarks(alternateFlow)

    let mut has_flow_together = false;
    if alternate > 1 {
        // Multiple MULTIEQUALs are disjoint from the non-constant flow.
        for i in 0..results.len() {
            if results[i] == 0 {
                continue; // is this a disconnected path
            }
            if flow_together(f, phi_edges, i, &mut results) {
                has_flow_together = true;
            }
        }
    }
    // Add a COPY for each edge with its own disconnected path going forward.
    for i in 0..phi_edges.len() {
        if results[i] != 1 {
            continue; // disconnected path that does not flow into another path
        }
        let op = phi_edges[i].op;
        let slot = phi_edges[i].slot as usize;
        let parent = f.op(op).parent.expect("phi has a parent").0 as usize;
        let bl = f.block(BlockId(parent as u32)).in_edges[slot].0 as usize;
        let out_vn = place_copy(f, op, bl, const_vn);
        f.op_set_input(op, slot, out_vn);
        count += 1;
    }
    if has_flow_together {
        place_multiple_constants(f, dom, phi_edges, &results, const_vn);
        count += 1;
    }
    count
}

/// Ghidra `ActionConditionalConst::propagateConstant` (`coreaction.cc:4383`): drain the point queue,
/// replacing every dominated read of a point's Varnode with the constant (or folding it through
/// arithmetic, or queuing the phi edges). Returns the number of changes made.
fn propagate_constant(
    f: &mut Funcdata,
    dom: &Dominators,
    points: &mut VecDeque<ConstPoint>,
    use_multiequal: bool,
) -> u32 {
    let mut count = 0;
    while let Some(point) = points.front().cloned() {
        let var_vn = point.vn;
        let mut const_vn = point.const_vn;
        let const_block = point.const_block;
        let mut phi_edges: Vec<PcodeOpNode> = Vec::new();

        // Snapshot the read list and process each distinct reader once (Ghidra advances its live
        // descend iterator past all entries equal to the current op before processing it).
        let mut seen: HashSet<OpId> = HashSet::new();
        let descendants: Vec<OpId> = f.vn(var_vn).descend.clone();
        for op in descendants {
            if !seen.insert(op) {
                continue; // process each distinct reader once
            }
            let opc = f.op(op).code();
            if opc == OpCode::Indirect {
                continue; // don't propagate constants into INDIRECTs
            } else if opc == OpCode::Multiequal {
                if !use_multiequal {
                    continue;
                }
                if f.vn(var_vn).is_addrtied()
                    && f.vn(var_vn).loc == f.vn(f.op(op).output.unwrap()).loc
                {
                    continue;
                }
                let bl = f.op(op).parent.expect("phi has a parent").0 as usize;
                if bl == const_block {
                    // The immediate edge from the conditional block into a MULTIEQUAL.
                    if f.op(op).input(point.in_slot as usize) == Some(var_vn) {
                        // The compiler may still intend the same variable — decline when so, to not
                        // spuriously create a new variable.
                        if point.value > 1 {
                            continue;
                        }
                        if f.vn(f.op(op).output.unwrap()).is_addrtied() {
                            continue;
                        }
                        if test_alternate_path(f, var_vn, op, point.in_slot, 2) {
                            continue;
                        }
                        phi_edges.push(PcodeOpNode::new(op, point.in_slot));
                    }
                } else if point.block_is_dom {
                    let ninput = f.op(op).num_inputs();
                    for slot in 0..ninput {
                        if f.op(op).input(slot) == Some(var_vn) {
                            let pred = f.block(BlockId(bl as u32)).in_edges[slot].0 as usize;
                            if dom.dominates(const_block, pred) {
                                phi_edges.push(PcodeOpNode::new(op, slot as i32));
                            }
                        }
                    }
                }
                continue;
            } else if opc == OpCode::Copy {
                // Don't propagate into a COPY unless it feeds something more interesting.
                let Some(follow) = lone_descend(f, f.op(op).output.unwrap()) else {
                    continue;
                };
                if f.op(follow).is_marker() {
                    continue;
                }
                if f.op(follow).code() == OpCode::Copy {
                    continue;
                }
            }
            if !point.block_is_dom {
                continue;
            }
            let parent = f.op(op).parent.expect("live op has a parent").0 as usize;
            if dom.dominates(const_block, parent) {
                if const_vn.is_none() {
                    const_vn = Some(f.new_const(f.vn(var_vn).size, point.value));
                }
                let cvn = const_vn.unwrap();
                if opc == OpCode::Return {
                    // RETURN can't take a constant directly: COPY it into var_vn's storage first.
                    let addr = f.op(op).seqnum.pc;
                    let (size, loc) = (f.vn(var_vn).size, f.vn(var_vn).loc);
                    let copy_op = f.new_op(OpCode::Copy, SeqNum { pc: addr, uniq: 0 }, vec![cvn]);
                    let copy_out = f.new_output(copy_op, size, loc);
                    let slot = f.op(op).inrefs.iter().position(|&v| v == var_vn).unwrap();
                    f.op_set_input(op, slot, copy_out);
                    f.op_insert_before(copy_op, op);
                } else {
                    let slot = f.op(op).inrefs.iter().position(|&v| v == var_vn).unwrap();
                    f.op_set_input(op, slot, cvn); // replace the ref with the constant!
                }
                count += 1;
            } else {
                push_constant(f, points, op);
            }
        }
        if !phi_edges.is_empty() {
            if const_vn.is_none() {
                const_vn = Some(f.new_const(f.vn(var_vn).size, point.value));
            }
            count += handle_phi_nodes(f, dom, var_vn, const_vn.unwrap(), &mut phi_edges);
        }
        points.pop_front();
    }
    count
}

/// Ghidra `ActionConditionalConst::findConstCompare` (`coreaction.cc:4478`): if `bool_vn` is a
/// Varnode compared to a constant, record the ConstPoint saying the Varnode equals the constant down
/// the appropriate out edge.
fn find_const_compare(
    f: &mut Funcdata,
    points: &mut VecDeque<ConstPoint>,
    bool_vn: VarnodeId,
    bl: usize,
    block_dom: &[bool; 2],
    flip_edge: bool,
) {
    if !f.vn(bool_vn).is_written() {
        return;
    }
    let mut flip_edge = flip_edge;
    let mut bool_vn = bool_vn;
    let mut comp_op = f.vn(bool_vn).def.unwrap();
    let mut opc = f.op(comp_op).code();
    if opc == OpCode::BoolNegate {
        flip_edge = !flip_edge;
        bool_vn = f.op(comp_op).input(0).unwrap();
        if !f.vn(bool_vn).is_written() {
            return;
        }
        comp_op = f.vn(bool_vn).def.unwrap();
        opc = f.op(comp_op).code();
    }
    let mut const_edge: usize = match opc {
        OpCode::IntEqual => 1,
        OpCode::IntNotequal => 0,
        _ => return,
    };
    // Find the variable and verify it is compared to a constant.
    let mut var_vn = f.op(comp_op).input(0).unwrap();
    let mut const_vn = f.op(comp_op).input(1).unwrap();
    if !f.vn(const_vn).is_constant() {
        if !f.vn(var_vn).is_constant() {
            return;
        }
        std::mem::swap(&mut const_vn, &mut var_vn);
    }
    if lone_descend(f, var_vn).is_some() {
        return; // read only once (by the compare) — nothing to propagate to
    }
    if flip_edge {
        const_edge = 1 - const_edge;
    }
    points.push_back(ConstPoint {
        vn: var_vn,
        const_vn: Some(const_vn),
        value: f.vn(const_vn).constant_value(),
        const_block: f.block(BlockId(bl as u32)).out_edges[const_edge].0 as usize,
        in_slot: get_out_rev_index(f, bl, const_edge),
        block_is_dom: block_dom[const_edge],
    });
}

/// Ghidra `ActionConditionalConst` (`coreaction.cc:4514`): the mainloop action driving conditional
/// constant propagation over every CBRANCH.
pub struct ActionConditionalConst;

impl Action for ActionConditionalConst {
    fn name(&self) -> &str {
        "condconst"
    }

    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        // Ghidra gates propagation into MULTIEQUALs on the stack having been heritaged (flow
        // calculations depend on it). condconst runs after heritage is complete in mosura's
        // pipeline, so the stack is heritaged and this is always true here.
        let use_multiequal = super::heritage::heritage_complete(data);
        let dom = dominator::compute(data);
        let nb = data.num_blocks();
        let mut count = 0;
        for i in 0..nb {
            let bl = BlockId(i as u32);
            let Some(&cbranch) = data.block(bl).ops.last() else {
                continue;
            };
            if data.op(cbranch).code() != OpCode::Cbranch {
                continue;
            }
            if data.block(bl).out_edges.len() != 2 {
                continue;
            }
            let bool_vn = data.op(cbranch).input(1).unwrap();
            // The boolean constant must hold down each branch (no sibling path carries a different
            // value into the target).
            let block_dom = [
                restricted_by_conditional(data, &dom, data.block(bl).out_edges[0].0 as usize, i),
                restricted_by_conditional(data, &dom, data.block(bl).out_edges[1].0 as usize, i),
            ];
            let flip_edge = data.op(cbranch).is_boolean_flip();
            let mut points: VecDeque<ConstPoint> = VecDeque::new();
            if lone_descend(data, bool_vn).is_none() {
                // The boolean is read more than once: search for implied constants — bool=0 down the
                // false branch, bool=1 down the true branch.
                points.push_back(ConstPoint {
                    vn: bool_vn,
                    const_vn: None,
                    value: if flip_edge { 1 } else { 0 },
                    const_block: data.block(bl).out_edges[0].0 as usize,
                    in_slot: get_out_rev_index(data, i, 0),
                    block_is_dom: block_dom[0],
                });
                points.push_back(ConstPoint {
                    vn: bool_vn,
                    const_vn: None,
                    value: if flip_edge { 0 } else { 1 },
                    const_block: data.block(bl).out_edges[1].0 as usize,
                    in_slot: get_out_rev_index(data, i, 1),
                    block_is_dom: block_dom[1],
                });
            }
            find_const_compare(data, &mut points, bool_vn, i, &block_dom, flip_edge);
            count += propagate_constant(data, &dom, &mut points, use_multiequal);
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::block::BlockBasic;
    use crate::decompile::op::SeqNum;
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::Funcdata;

    fn func() -> Funcdata {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        Funcdata::new("t", Address::new(ram, 0), spaces)
    }
    fn seq(o: u64, f: &Funcdata) -> SeqNum {
        SeqNum { pc: Address::new(f.spaces.by_name("ram").unwrap(), o), uniq: 0 }
    }
    /// Wire a CFG onto `f`: `edges` are (from,to) in the order they should appear as out-edges;
    /// in-edges are derived positionally (matching `cfg::build_cfg`). `ops[bi]` are block `bi`'s ops.
    fn wire(f: &mut Funcdata, nb: usize, edges: &[(usize, usize)], ops: &[Vec<OpId>]) {
        let mut blocks: Vec<BlockBasic> = vec![BlockBasic::default(); nb];
        for &(a, b) in edges {
            blocks[a].out_edges.push(BlockId(b as u32));
        }
        for bi in 0..nb {
            for o in blocks[bi].out_edges.clone() {
                blocks[o.0 as usize].in_edges.push(BlockId(bi as u32));
            }
            blocks[bi].ops = ops.get(bi).cloned().unwrap_or_default();
        }
        f.set_blocks(blocks);
        for (bi, blk_ops) in ops.iter().enumerate() {
            for &op in blk_ops {
                f.op_mut(op).parent = Some(BlockId(bi as u32));
            }
        }
    }

    /// `if (x == 0) { y = x + 7; }` — down the equal edge x is 0, so the dominated read of x in the
    /// add is replaced with constant 0. The core condconst1 mechanism.
    #[test]
    fn direct_replace_dominated_read() {
        let mut f = func();
        let reg = f.spaces.by_name("register").unwrap();
        let x = f.new_input(4, Address::new(reg, 0x20));
        let zero = f.new_const(4, 0);
        let eq = f.new_op(OpCode::IntEqual, seq(0, &f), vec![x, zero]);
        f.new_output(eq, 1, Address::new(reg, 0x100));
        let eqout = f.op(eq).output.unwrap();
        let tgt = f.new_const(8, 0x10);
        let cbr = f.new_op(OpCode::Cbranch, seq(1, &f), vec![tgt, eqout]);
        let seven = f.new_const(4, 7);
        let add = f.new_op(OpCode::IntAdd, seq(0x10, &f), vec![x, seven]);
        f.new_output(add, 4, Address::new(reg, 0x28));
        let ret = f.new_op(OpCode::Return, seq(0x20, &f), vec![]);
        // out[0]=false(merge block2), out[1]=true(x==0 body block1)
        wire(&mut f, 3, &[(0, 2), (0, 1), (1, 2)], &[vec![eq, cbr], vec![add], vec![ret]]);

        let n = ActionConditionalConst.apply(&mut f);
        assert!(n >= 1, "at least the add's read of x was replaced");
        let in0 = f.op(add).input(0).unwrap();
        assert!(f.vn(in0).is_constant(), "the add's x operand became a constant");
        assert_eq!(f.vn(in0).constant_value(), 0, "the propagated constant is 0");
    }

    /// `if (x == 7) { y = x + 9; }` where the add is NOT in the dominated block but its output is
    /// read there — pushConstant folds `7 + 9 => 0x10` and the folded constant propagates. Mirrors
    /// condconst1's `param_1[4] = 0x10`.
    #[test]
    fn push_constant_folds_through_add() {
        let mut f = func();
        let reg = f.spaces.by_name("register").unwrap();
        let x = f.new_input(4, Address::new(reg, 0x20));
        let c7 = f.new_const(4, 7);
        let eq = f.new_op(OpCode::IntEqual, seq(0, &f), vec![x, c7]);
        f.new_output(eq, 1, Address::new(reg, 0x100));
        let eqout = f.op(eq).output.unwrap();
        let tgt = f.new_const(8, 0x10);
        let cbr = f.new_op(OpCode::Cbranch, seq(1, &f), vec![tgt, eqout]);
        // add lives in block0 (not dominated by the true edge) — so pushConstant must fold it.
        let c9 = f.new_const(4, 9);
        let add = f.new_op(OpCode::IntAdd, seq(2, &f), vec![x, c9]);
        f.new_output(add, 4, Address::new(reg, 0x28));
        let addout = f.op(add).output.unwrap();
        // block1 (x==7) reads the add's output.
        let use_op = f.new_op(OpCode::IntAnd, seq(0x10, &f), vec![addout, addout]);
        f.new_output(use_op, 4, Address::new(reg, 0x30));
        let ret = f.new_op(OpCode::Return, seq(0x20, &f), vec![]);
        wire(&mut f, 3, &[(0, 2), (0, 1), (1, 2)], &[vec![eq, add, cbr], vec![use_op], vec![ret]]);

        ActionConditionalConst.apply(&mut f);
        // the use in block1 now reads a constant 0x10 (7+9), not the add output.
        let in0 = f.op(use_op).input(0).unwrap();
        assert!(f.vn(in0).is_constant(), "the folded constant reached the dominated use");
        assert_eq!(f.vn(in0).constant_value(), 0x10);
    }

    /// findConstCompare recognizes INT_NOTEQUAL and peels a BOOL_NEGATE, orienting to the correct
    /// edge, and swaps a constant on the left. Also declines when the variable is read only once.
    #[test]
    fn find_const_compare_forms() {
        // INT_NOTEQUAL(x, 5): constant holds down the FALSE (edge 0) — the not-equal-is-false branch.
        let mut f = func();
        let reg = f.spaces.by_name("register").unwrap();
        let x = f.new_input(4, Address::new(reg, 0x20));
        let c5 = f.new_const(4, 5);
        let ne = f.new_op(OpCode::IntNotequal, seq(0, &f), vec![x, c5]);
        f.new_output(ne, 1, Address::new(reg, 0x100));
        let neout = f.op(ne).output.unwrap();
        let extra = f.new_op(OpCode::IntAdd, seq(1, &f), vec![x, c5]); // 2nd reader of x
        f.new_output(extra, 4, Address::new(reg, 0x30));
        wire(&mut f, 3, &[(0, 1), (0, 2)], &[vec![ne], vec![], vec![]]);
        let block_dom = [true, true];
        let mut pts = VecDeque::new();
        find_const_compare(&mut f, &mut pts, neout, 0, &block_dom, false);
        assert_eq!(pts.len(), 1);
        assert_eq!(pts[0].vn, x);
        assert_eq!(pts[0].value, 5);
        assert_eq!(pts[0].const_block, 1, "NOTEQUAL: constant down out-edge 0 (target block 1)");

        // lone read => decline (nothing to propagate to besides the compare).
        let mut f = func();
        let reg = f.spaces.by_name("register").unwrap();
        let x = f.new_input(4, Address::new(reg, 0x20));
        let c5 = f.new_const(4, 5);
        let eq = f.new_op(OpCode::IntEqual, seq(0, &f), vec![x, c5]);
        f.new_output(eq, 1, Address::new(reg, 0x100));
        let eqout = f.op(eq).output.unwrap();
        wire(&mut f, 3, &[(0, 1), (0, 2)], &[vec![eq], vec![], vec![]]);
        let mut pts = VecDeque::new();
        find_const_compare(&mut f, &mut pts, eqout, 0, &[true, true], false);
        assert!(pts.is_empty(), "x read only once => no ConstPoint");
    }

    /// restrictedByConditional: a block whose only entry is the conditional is restricted; a merge
    /// block reachable through a sibling is not.
    #[test]
    fn restricted_by_conditional_diamond() {
        let mut f = func();
        // 0 -> {1,2} -> 3
        wire(&mut f, 4, &[(0, 1), (0, 2), (1, 3), (2, 3)], &[vec![], vec![], vec![], vec![]]);
        let dom = dominator::compute(&f);
        assert!(restricted_by_conditional(&f, &dom, 1, 0), "arm reached only from cond");
        assert!(restricted_by_conditional(&f, &dom, 2, 0), "other arm too");
        assert!(!restricted_by_conditional(&f, &dom, 3, 0), "merge reached via a sibling");
    }

    /// findCommonBlock returns the nearest common dominator.
    #[test]
    fn find_common_block_nearest_dominator() {
        let mut f = func();
        // 0 -> 1 -> {2,3}; common dominator of {2,3} is 1.
        wire(&mut f, 4, &[(0, 1), (1, 2), (1, 3)], &[vec![], vec![], vec![], vec![]]);
        let dom = dominator::compute(&f);
        assert_eq!(find_common_block(&dom, &[2, 3]), 1);
        assert_eq!(find_common_block(&dom, &[1, 2, 3]), 1);
        assert_eq!(find_common_block(&dom, &[2]), 2);
    }

    /// A phi edge with no alternate path forward gets a COPY of the constant placed on its incoming
    /// edge and the edge repointed.
    #[test]
    fn phi_edge_propagated_when_disconnected() {
        let mut f = func();
        let reg = f.spaces.by_name("register").unwrap();
        let x = f.new_input(4, Address::new(reg, 0x20));
        let y = f.new_input(4, Address::new(reg, 0x28));
        // phi = MULTIEQUAL(x[from block1], y[from block2]) in block3; return(phi)
        let phi = f.new_op(OpCode::Multiequal, seq(0x30, &f), vec![x, y]);
        f.new_output(phi, 4, Address::new(reg, 0x40));
        let phiout = f.op(phi).output.unwrap();
        let ret = f.new_op(OpCode::Return, seq(0x34, &f), vec![phiout]);
        // 0 -> {1,2} -> 3 ; block3 preds = [1,2] so phi slot i matches in-edge i.
        wire(
            &mut f,
            4,
            &[(0, 1), (0, 2), (1, 3), (2, 3)],
            &[vec![], vec![], vec![], vec![phi, ret]],
        );
        let dom = dominator::compute(&f);
        let c5 = f.new_const(4, 5);
        let n = handle_phi_nodes(&mut f, &dom, x, c5, &mut vec![PcodeOpNode::new(phi, 0)]);
        assert_eq!(n, 1);
        let in0 = f.op(phi).input(0).unwrap();
        assert_ne!(in0, x, "phi edge 0 was repointed off x");
        let def = f.vn(in0).def.expect("repointed to a COPY output");
        assert_eq!(f.op(def).code(), OpCode::Copy);
        assert_eq!(f.op(def).input(0), Some(c5), "the COPY assigns the constant");
        assert_eq!(f.op(def).parent, Some(BlockId(1)), "COPY placed in the incoming block");
    }

    /// When the constant value rejoins the non-constant flow through a later MULTIEQUAL, the edge is
    /// declined (no COPY) — the condconst_conn case.
    #[test]
    fn phi_declined_when_value_rejoins() {
        let mut f = func();
        let reg = f.spaces.by_name("register").unwrap();
        let x = f.new_input(4, Address::new(reg, 0x20));
        let w = f.new_input(4, Address::new(reg, 0x28));
        // phi = MULTIEQUAL(x, w); c = COPY(x); phi2 = MULTIEQUAL(c, phi); return(phi2)
        let phi = f.new_op(OpCode::Multiequal, seq(0x30, &f), vec![x, w]);
        f.new_output(phi, 4, Address::new(reg, 0x40));
        let phiout = f.op(phi).output.unwrap();
        let c = f.new_op(OpCode::Copy, seq(0x10, &f), vec![x]);
        f.new_output(c, 4, Address::new(reg, 0x48));
        let cout = f.op(c).output.unwrap();
        let phi2 = f.new_op(OpCode::Multiequal, seq(0x50, &f), vec![cout, phiout]);
        f.new_output(phi2, 4, Address::new(reg, 0x40));
        let phi2out = f.op(phi2).output.unwrap();
        let ret = f.new_op(OpCode::Return, seq(0x54, &f), vec![phi2out]);
        // Minimal single block is enough — the decline never reaches place_copy.
        wire(&mut f, 1, &[], &[vec![c, phi, phi2, ret]]);
        let dom = dominator::compute(&f);
        let c5 = f.new_const(4, 5);
        let n = handle_phi_nodes(&mut f, &dom, x, c5, &mut vec![PcodeOpNode::new(phi, 0)]);
        assert_eq!(n, 0, "declined: the value rejoins non-constant flow at phi2");
        assert_eq!(f.op(phi).input(0), Some(x), "phi edge 0 left untouched");
    }

    /// testAlternatePath finds a value reachable back through another MULTIEQUAL slot.
    #[test]
    fn test_alternate_path_backtracks() {
        let mut f = func();
        let reg = f.spaces.by_name("register").unwrap();
        let x = f.new_input(4, Address::new(reg, 0x20));
        let y = f.new_input(4, Address::new(reg, 0x28));
        // phi = MULTIEQUAL(x, y): from slot 0, x is reachable through slot 1? no (that's y). But
        // x itself at slot0 vs a query slot 1 finds x directly.
        let phi = f.new_op(OpCode::Multiequal, seq(0, &f), vec![x, y]);
        f.new_output(phi, 4, Address::new(reg, 0x40));
        assert!(test_alternate_path(&f, x, phi, 1, 2), "x is at slot 0, reachable from query slot 1");
        assert!(!test_alternate_path(&f, x, phi, 0, 2), "from slot 0 excluded, only y remains");
    }
}
