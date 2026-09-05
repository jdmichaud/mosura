//! Ghidra `ConditionalJoin` (blockaction.cc:1898-2110) and `ActionNodeJoin` (blockaction.cc:2326).
//!
//! The mirror image of [`condexe`](super::condexe): where `ConditionalExecution` removes a join
//! that re-tests a condition, `ConditionalJoin` *creates* one. Two blocks that branch on the same
//! condition and have the same pair of exits are redundant — the condition is computed twice. The
//! duplicated tests are merged into a single new block, and the values that differed between the
//! two sides become MULTIEQUALs in it.

use std::collections::BTreeMap;

use super::action::Action;
use super::block::BlockId;
use super::funcdata::Funcdata;
use super::op::{OpId, SeqNum};
use super::opcode::OpCode;
use super::varnode::VarnodeId;

/// Ghidra's `ConditionalJoin::MergePair` key. Ghidra orders the map by
/// `(side1->getCreateIndex(), side2->getCreateIndex())` (blockaction.cc:1898); mosura keys a
/// `BTreeMap` on exactly that pair, so `setup_multiequals` visits the pairs in Ghidra's order —
/// which decides the creation order of the new MULTIEQUALs, and so must not be left to chance.
type MergeKey = (u32, u32);

/// Ghidra `ConditionalJoin` (blockaction.hh:234).
struct ConditionalJoin {
    /// Side 1 of the (putative) split.
    block1: BlockId,
    /// Side 2 of the (putative) split.
    block2: BlockId,
    /// First (common) exit point.
    exita: BlockId,
    /// Second (common) exit point.
    exitb: BlockId,
    /// In-edge of `exita` coming from `block1` / `block2`.
    a_in1: usize,
    a_in2: usize,
    /// In-edge of `exitb` coming from `block1` / `block2`.
    b_in1: usize,
    b_in2: usize,
    /// CBRANCH at the bottom of `block1` / `block2`.
    cbranch1: OpId,
    cbranch2: OpId,
    /// The new joined condition block.
    joinblock: BlockId,
    /// Map from a split Varnode pair to the merged Varnode that replaces it.
    mergeneed: BTreeMap<MergeKey, (VarnodeId, VarnodeId, Option<VarnodeId>)>,
}

impl ConditionalJoin {
    fn new() -> ConditionalJoin {
        ConditionalJoin {
            block1: BlockId(0),
            block2: BlockId(0),
            exita: BlockId(0),
            exitb: BlockId(0),
            a_in1: 0,
            a_in2: 0,
            b_in1: 0,
            b_in2: 0,
            cbranch1: OpId(0),
            cbranch2: OpId(0),
            joinblock: BlockId(0),
            mergeneed: BTreeMap::new(),
        }
    }

    /// Ghidra `ConditionalJoin::clear` (blockaction.cc:2104).
    fn clear(&mut self) {
        self.mergeneed.clear();
    }

    fn key(data: &Funcdata, vn1: VarnodeId, vn2: VarnodeId) -> MergeKey {
        (data.vn(vn1).create_index, data.vn(vn2).create_index)
    }

    fn note_merge(&mut self, data: &Funcdata, vn1: VarnodeId, vn2: VarnodeId) {
        self.mergeneed.insert(Self::key(data, vn1, vn2), (vn1, vn2, None));
    }

    /// Ghidra's `getOutRevIndex(i)` (block.hh): the in-edge index that `bb`'s `i`-th successor uses
    /// to reach `bb`. Ghidra stores it on the edge; mosura searches, as the rest of this crate's
    /// block surgery does.
    fn out_rev_index(data: &Funcdata, bb: BlockId, i: usize) -> usize {
        let outb = data.block(bb).out_edges[i];
        data.block(outb).in_edges.iter().position(|&b| b == bb).expect("edge is reciprocal")
    }

    /// Ghidra `ConditionalJoin::findDups` (blockaction.cc:1912): are the two conditional
    /// expressions equivalent, up to Varnodes that need merging?
    fn find_dups(&mut self, data: &Funcdata) -> bool {
        let Some(&c1) = data.block(self.block1).ops.last() else { return false };
        if data.op(c1).code() != OpCode::Cbranch {
            return false;
        }
        let Some(&c2) = data.block(self.block2).ops.last() else { return false };
        if data.op(c2).code() != OpCode::Cbranch {
            return false;
        }
        self.cbranch1 = c1;
        self.cbranch2 = c2;
        // A flip that has not propagated through yet would make the comparison meaningless.
        if data.op(c1).is_boolean_flip() || data.op(c2).is_boolean_flip() {
            return false;
        }
        let vn1 = data.op(c1).input(1).expect("CBRANCH condition");
        let vn2 = data.op(c2).input(1).expect("CBRANCH condition");
        if vn1 == vn2 {
            return true;
        }
        // Parallel to RulePushMulti, so we know that rule will apply once we do the join.
        if !data.vn(vn1).is_written() || !data.vn(vn2).is_written() {
            return false;
        }
        if data.vn(vn1).is_spacebase() || data.vn(vn2).is_spacebase() {
            return false;
        }
        let res = super::rules::functional_equality_level(data, vn1, vn2);
        if !(0..=1).contains(&res) {
            return false;
        }
        let op1 = data.vn(vn1).def.expect("written");
        if matches!(data.op(op1).code(), OpCode::Subpiece | OpCode::Copy) {
            return false;
        }
        self.note_merge(data, vn1, vn2);
        true
    }

    /// Ghidra `ConditionalJoin::checkExitBlock` (blockaction.cc:1954): collect the further Varnode
    /// pairs an exit block merges from our two sides.
    fn check_exit_block(&mut self, data: &Funcdata, exit: BlockId, in1: usize, in2: usize) {
        for op in data.block(exit).ops.clone() {
            if data.op(op).code() == OpCode::Multiequal {
                let vn1 = data.op(op).input(in1).expect("phi input per in-edge");
                let vn2 = data.op(op).input(in2).expect("phi input per in-edge");
                if vn1 != vn2 {
                    self.note_merge(data, vn1, vn2);
                }
            } else if data.op(op).code() != OpCode::Copy {
                break;
            }
        }
    }

    /// Ghidra `ConditionalJoin::match` (blockaction.cc:2065): do the two blocks meet the split
    /// conditions? On failure this cleans up so further calls can be made.
    fn matches(&mut self, data: &Funcdata, b1: BlockId, b2: BlockId) -> bool {
        self.block1 = b1;
        self.block2 = b2;
        if b1 == b2 {
            return false;
        }
        if data.block(b1).out_edges.len() != 2 || data.block(b2).out_edges.len() != 2 {
            return false;
        }
        self.exita = data.block(b1).out_edges[0];
        self.exitb = data.block(b1).out_edges[1];
        if self.exita == self.exitb {
            return false;
        }
        // Both the false exits and the true exits must match.
        if data.block(b2).out_edges[0] != self.exita || data.block(b2).out_edges[1] != self.exitb {
            return false;
        }
        self.a_in2 = Self::out_rev_index(data, b2, 0);
        self.b_in2 = Self::out_rev_index(data, b2, 1);
        self.a_in1 = Self::out_rev_index(data, b1, 0);
        self.b_in1 = Self::out_rev_index(data, b1, 1);

        if !self.find_dups(data) {
            self.clear();
            return false;
        }
        self.check_exit_block(data, self.exita, self.a_in1, self.a_in2);
        self.check_exit_block(data, self.exitb, self.b_in1, self.b_in2);
        true
    }

    /// Ghidra `ConditionalJoin::setupMultiequals` (blockaction.cc:2023): a new MULTIEQUAL in the
    /// join block for each pair that needs merging.
    fn setup_multiequals(&mut self, data: &mut Funcdata) {
        let pc = data.op(self.cbranch1).seqnum.pc;
        for (_, entry) in self.mergeneed.iter_mut() {
            if entry.2.is_some() {
                continue;
            }
            let (vn1, vn2) = (entry.0, entry.1);
            let size = data.vn(vn1).size;
            let uniq = data.num_ops() as u32;
            let multi = data.new_op(OpCode::Multiequal, SeqNum { pc, uniq }, vec![vn1, vn2]);
            let outvn = data.new_output_unique(multi, size);
            entry.2 = Some(outvn);
            data.op_insert_end(multi, self.joinblock);
        }
    }

    /// Ghidra `ConditionalJoin::moveCbranch` (blockaction.cc:2043): move one CBRANCH into the join
    /// block, reading the merged condition, and destroy the other.
    fn move_cbranch(&mut self, data: &mut Funcdata) {
        let vn1 = data.op(self.cbranch1).input(1).expect("CBRANCH condition");
        let vn2 = data.op(self.cbranch2).input(1).expect("CBRANCH condition");
        data.op_uninsert(self.cbranch1);
        data.op_insert_end(self.cbranch1, self.joinblock);
        let vn = if vn1 != vn2 {
            self.mergeneed
                .get(&Self::key(data, vn1, vn2))
                .and_then(|e| e.2)
                .expect("find_dups recorded this pair")
        } else {
            vn1
        };
        data.op_set_input(self.cbranch1, 1, vn);
        data.op_destroy(self.cbranch2);
    }

    /// Ghidra `ConditionalJoin::cutDownMultiequals` (blockaction.cc:1981): in an exit block, drop
    /// one of the two now-merged phi inputs and point the other at the merged Varnode.
    fn cut_down_multiequals(&mut self, data: &mut Funcdata, exit: BlockId, in1: usize, in2: usize) {
        let (hi, lo) = if in1 > in2 { (in1, in2) } else { (in2, in1) };
        for op in data.block(exit).ops.clone() {
            if data.op(op).code() == OpCode::Multiequal {
                let vn1 = data.op(op).input(in1).expect("phi input per in-edge");
                let vn2 = data.op(op).input(in2).expect("phi input per in-edge");
                if vn1 == vn2 {
                    data.op_remove_input(op, hi);
                } else {
                    let subvn = self
                        .mergeneed
                        .get(&Self::key(data, vn1, vn2))
                        .and_then(|e| e.2)
                        .expect("check_exit_block recorded this pair");
                    data.op_remove_input(op, hi);
                    data.op_set_input(op, lo, subvn);
                }
                if data.op(op).num_inputs() == 1 {
                    // A phi with one input is just a COPY, and moves to the top of the block.
                    data.op_uninsert(op);
                    data.op_set_opcode(op, OpCode::Copy);
                    data.op_insert_begin(op, exit);
                }
            } else if data.op(op).code() != OpCode::Copy {
                break;
            }
        }
    }

    /// Ghidra `ConditionalJoin::execute` (blockaction.cc:2094). All conditions have been met.
    fn execute(&mut self, data: &mut Funcdata) {
        self.joinblock = data.node_join_create_block(
            self.block1,
            self.block2,
            self.exita,
            self.exitb,
            self.a_in1 > self.a_in2,
            self.b_in1 > self.b_in2,
        );
        self.setup_multiequals(data);
        self.move_cbranch(data);
        self.cut_down_multiequals(data, self.exita, self.a_in1, self.a_in2);
        self.cut_down_multiequals(data, self.exitb, self.b_in1, self.b_in2);
    }
}

/// Ghidra `ActionNodeJoin` (blockaction.cc:2326, group `nodejoin`, slot :5674): find pairs of
/// blocks that duplicate the same conditional test into the same pair of exits, and merge them.
pub struct ActionNodeJoin;

impl Action for ActionNodeJoin {
    fn name(&self) -> &str {
        "nodejoin"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        if data.num_blocks() == 0 {
            return 0;
        }
        let mut count = 0;
        let mut condjoin = ConditionalJoin::new();
        let mut i = 0;
        while i < data.num_blocks() {
            let bb = BlockId(i as u32);
            if data.block(bb).out_edges.len() != 2 {
                i += 1;
                continue;
            }
            let out1 = data.block(bb).out_edges[0];
            let out2 = data.block(bb).out_edges[1];
            // Search from whichever exit has fewer inputs.
            let (leastout, inslot) = if data.block(out1).in_edges.len() < data.block(out2).in_edges.len() {
                (out1, ConditionalJoin::out_rev_index(data, bb, 0))
            } else {
                (out2, ConditionalJoin::out_rev_index(data, bb, 1))
            };
            if data.block(leastout).in_edges.len() == 1 {
                i += 1;
                continue;
            }
            let mut joined = false;
            for j in 0..data.block(leastout).in_edges.len() {
                if j == inslot {
                    continue;
                }
                let bb2 = data.block(leastout).in_edges[j];
                if condjoin.matches(data, bb, bb2) {
                    count += 1;
                    condjoin.execute(data);
                    condjoin.clear();
                    joined = true;
                    break;
                }
            }
            // The join appended a block and rewired edges, so re-examine this index rather than
            // walking past a graph that changed shape underneath us.
            if !joined {
                i += 1;
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::block::BlockBasic;
    use crate::decompile::space::{Address, SpaceManager};

    /// `ActionNodeJoin` declines blocks whose exits do not match: the merge is only valid when both
    /// sides branch to the SAME pair of exits, in the same true/false order (Ghidra
    /// `ConditionalJoin::match`, blockaction.cc:2074-2078).
    #[test]
    fn node_join_declines_mismatched_exits() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let at = Address::new(ram, 0);
        let mut f = Funcdata::new("t", at, spaces);
        let c = f.new_const(1, 1);
        let br0 = f.new_op(OpCode::Cbranch, SeqNum { pc: at, uniq: 0 }, vec![c, c]);
        let br1 = f.new_op(OpCode::Cbranch, SeqNum { pc: at, uniq: 1 }, vec![c, c]);

        // b0 -> {b2,b3}, b1 -> {b2,b4}: the exits differ, so no join.
        let mut b0 = BlockBasic::default();
        b0.ops.push(br0);
        b0.out_edges = vec![BlockId(2), BlockId(3)];
        let mut b1 = BlockBasic::default();
        b1.ops.push(br1);
        b1.out_edges = vec![BlockId(2), BlockId(4)];
        let mut b2 = BlockBasic::default();
        b2.in_edges = vec![BlockId(0), BlockId(1)];
        let mut b3 = BlockBasic::default();
        b3.in_edges = vec![BlockId(0)];
        let mut b4 = BlockBasic::default();
        b4.in_edges = vec![BlockId(1)];
        let _ = (&mut b2, &mut b3, &mut b4);
        f.set_blocks(vec![b0, b1, b2, b3, b4]);
        f.op_mut(br0).parent = Some(BlockId(0));
        f.op_mut(br1).parent = Some(BlockId(1));

        assert_eq!(ActionNodeJoin.apply(&mut f), 0, "exits must match on both sides");
        assert_eq!(f.num_blocks(), 5, "no join block is created");
    }

    /// A block whose exit has only one input has nothing to pair with, so the sweep skips it
    /// (Ghidra blockaction.cc:2349).
    #[test]
    fn node_join_skips_a_single_input_exit() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let at = Address::new(ram, 0);
        let mut f = Funcdata::new("t", at, spaces);
        let c = f.new_const(1, 1);
        let br0 = f.new_op(OpCode::Cbranch, SeqNum { pc: at, uniq: 0 }, vec![c, c]);
        let mut b0 = BlockBasic::default();
        b0.ops.push(br0);
        b0.out_edges = vec![BlockId(1), BlockId(2)];
        let mut b1 = BlockBasic::default();
        b1.in_edges = vec![BlockId(0)];
        let mut b2 = BlockBasic::default();
        b2.in_edges = vec![BlockId(0)];
        let _ = (&mut b1, &mut b2);
        f.set_blocks(vec![b0, b1, b2]);
        f.op_mut(br0).parent = Some(BlockId(0));

        assert_eq!(ActionNodeJoin.apply(&mut f), 0);
        assert_eq!(f.num_blocks(), 3);
    }
}

// ---------------------------------------------------------------------------
// Ghidra `ActionReturnSplit` (blockaction.cc:2205-2320).
// ---------------------------------------------------------------------------

/// Ghidra `ActionReturnSplit::isSplittable` (blockaction.cc:2241): a block ending in RETURN can be
/// split only if nothing substantive else happens in it.
fn is_splittable(data: &Funcdata, b: BlockId) -> bool {
    for &op in &data.block(b).ops {
        match data.op(op).code() {
            OpCode::Multiequal => continue,
            OpCode::Copy | OpCode::Return => {
                // RETURN's slot 0 is the flow marker: Ghidra models it as a CONSTANT (its
                // input scan passes it via isConstant), mosura as the return-address
                // varnode, which stays free — same semantic slot, exempt either way.
                let first = if data.op(op).code() == OpCode::Return { 1 } else { 0 };
                for i in first..data.op(op).num_inputs() {
                    let vn = data.op(op).input(i).expect("input");
                    if data.vn(vn).is_constant() || data.vn(vn).is_annotation() {
                        continue;
                    }
                    if data.vn(vn).is_free() {
                        debug!(crate::debug::Topic::RetSplit, "free input on {:?}@{:x}", data.op(op).code(), data.op(op).seqnum.pc.offset);
                        return false;
                    }
                }
            }
            other => {
                debug!(crate::debug::Topic::RetSplit, "non-copy op {:?}@{:x}", other, data.op(op).seqnum.pc.offset);
                return false;
            }
        }
    }
    true
}

/// Ghidra `ActionReturnSplit::gatherReturnGotos` (blockaction.cc:2205): does the flow arriving at
/// `parent` on its `i`-th in-edge get there by a **goto** that targets `parent`?
///
/// Ghidra walks the predecessor's `getCopyMap()` up the `getParent()` chain looking for a
/// `BlockGoto` that prints, or a `BlockIf` carrying a goto target, whose target resolves down
/// through `subBlock(0)` to `parent`. mosura's structurer records the same state in two maps —
/// [`Structured::gotos`], keyed by the basic block whose exit emits a conditional if-goto (Ghidra's
/// `BlockIf::gototarget`), and [`Structured::node_gotos`], keyed by the structured node wrapping an
/// unconditional goto (Ghidra's `BlockGoto`) — so the chain walk reads those instead of a copyMap.
fn in_edge_gotos_to(s: &super::structure::Structured, pred: BlockId, parent: BlockId) -> bool {
    let targets_parent = |recs: Option<&Vec<super::structure::GotoRecord>>| {
        recs.is_some_and(|v| v.iter().any(|g| g.target == parent))
    };
    // The conditional (BlockIf) form is keyed by the emitting basic block.
    if targets_parent(s.gotos.get(&pred)) {
        return true;
    }
    // The unconditional (BlockGoto) form is keyed by the structured node, so walk the chain from
    // the predecessor's leaf up through its enclosing composites.
    let Some(mut node) = s.blocks.iter().position(|fb| fb.kind == super::structure::FlowKind::Basic(pred))
    else {
        return false;
    };
    loop {
        if targets_parent(s.node_gotos.get(&node)) {
            return true;
        }
        match s.blocks[node].parent {
            Some(p) => node = p,
            None => return false,
        }
    }
}

/// Ghidra `ActionReturnSplit` (blockaction.cc:2264, group `returnsplit`, slot :5685): where several
/// paths reach one RETURN block and some of them get there by an explicit goto, duplicate the
/// RETURN block along those edges so each path returns directly instead of jumping to a shared
/// exit.
pub struct ActionReturnSplit;

thread_local! {
    /// Shared-return arm (survey recovered path): while set, `ActionReturnSplit` performs no
    /// split, so a re-decompile of the same world yields the pre-split rendering the arm
    /// compares against. Never set around a reference decompile.
    static SKIP_RETURN_SPLIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Set/clear the shared-return arm's skip switch for the current thread.
pub fn set_skip_return_split(on: bool) {
    SKIP_RETURN_SPLIT.with(|c| c.set(on));
}

impl Action for ActionReturnSplit {
    fn name(&self) -> &str {
        "returnsplit"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        if data.num_blocks() == 0 {
            return 0;
        }
        // Ghidra reads `data.getStructure()`, the graph `ActionBlockStructure` left on the
        // Funcdata at mainloop slot :5659 — and SKIPS when it is empty: "Some other
        // restructuring happened first" (blockaction.cc:2276). A fullloop-tail action that
        // removed blocks (DoNothing, SwitchNorm's folds) reset the structure, and Ghidra defers
        // the split to the next round rather than splitting against a stale view. mosura's old
        // fresh-build here could never take that gate; consuming the cache restores it.
        // Read IN PLACE (Ghidra never consumes the graph here): the collect-then-split shape
        // below ends the borrow before any mutation, and a performed split invalidates the cache
        // through `node_split`'s own `structure_reset`. (A `take()` without restore here made
        // every fullloop round consume the cache, whose rebuild then counted as a change — an
        // infinite fullloop.)
        // `--arms-off ret-split`: measurement switch for the shared-return arm investigation
        // (renders the pre-41a1665 unsplit shape); NOT a doctrine change — the action stays
        // on by default.
        if !data.knobs.on(crate::switches::Switch::RetSplit) || SKIP_RETURN_SPLIT.with(|c| c.get()) {
            return 0;
        }
        let Some(s) = data.structure.as_ref() else {
            debug!(crate::debug::Topic::RetSplit, "skip: no structure cache");
            return 0; // some other restructuring happened first
        };
        // Collect every edge to split first, then split — Ghidra accumulates across all RETURNs
        // before touching the graph (blockaction.cc:2287-2312).
        let mut splitedge: Vec<(BlockId, usize)> = Vec::new();
        let returns: Vec<OpId> = data
            .op_ids()
            .filter(|&op| !data.op(op).is_dead() && data.op(op).code() == OpCode::Return)
            .collect();
        for op in returns {
            let Some(parent) = data.op(op).parent else { continue };
            if data.block(parent).in_edges.len() <= 1 {
                debug!(crate::debug::Topic::RetSplit, "ret@{:x}: in-degree {} <= 1", data.op(op).seqnum.pc.offset, data.block(parent).in_edges.len());
                continue;
            }
            if !is_splittable(data, parent) {
                debug!(crate::debug::Topic::RetSplit, "ret@{:x}: not splittable", data.op(op).seqnum.pc.offset);
                continue;
            }
            let n = data.block(parent).in_edges.len();
            let marked: Vec<bool> = (0..n)
                .map(|i| in_edge_gotos_to(&s, data.block(parent).in_edges[i], parent))
                .collect();
            if crate::debug::on(crate::debug::Topic::RetSplit) {
                debug!(crate::debug::Topic::RetSplit, "candidate ret@{:x}: {} in-edges, {} marked", data.op(op).seqnum.pc.offset, n, marked.iter().filter(|&&m| m).count());
                for i in 0..n {
                    let pred = data.block(parent).in_edges[i];
                    let node = s.blocks.iter().position(|fb| fb.kind == super::structure::FlowKind::Basic(pred));
                    debug!(crate::debug::Topic::RetSplit, "edge {i}: pred {:?} node {:?} gotos_here {:?} parent_blk {:?}",
                        pred, node,
                        s.gotos.get(&pred).map(|v| v.iter().map(|g| g.target).collect::<Vec<_>>()),
                        parent);
                    if let Some(mut nd) = node {
                        loop {
                            if let Some(v) = s.node_gotos.get(&nd) {
                                debug!(crate::debug::Topic::RetSplit, "node {nd} records {:?}", v.iter().map(|g| (g.target, g.conditional)).collect::<Vec<_>>());
                            }
                            match s.blocks[nd].parent { Some(p) if p != nd => nd = p, _ => break }
                        }
                    }
                }
            }
            if !marked.iter().any(|&m| m) {
                continue;
            }
            // Descending index order, so removing an edge never shifts one still to be split.
            let mut here: Vec<(BlockId, usize)> =
                (0..n).rev().filter(|&i| marked[i]).map(|i| (parent, i)).collect();
            if here.len() == n {
                here.pop(); // can't split ALL in edges
            }
            splitedge.extend(here);
        }
        let mut count = 0;
        for (parent, inedge) in splitedge {
            data.node_split(parent, inedge);
            count += 1;
        }
        data.return_splits += count;
        count
    }
}

#[cfg(test)]
mod returnsplit_tests {
    use super::*;
    use crate::decompile::block::BlockBasic;
    use crate::decompile::space::{Address, SpaceManager};

    /// `isSplittable` accepts a RETURN block holding only markers and copies, and rejects one that
    /// does real work — Ghidra blockaction.cc:2241, the guard that keeps nodeSplit from having to
    /// clone a CALL or an INDIRECT.
    #[test]
    fn return_split_only_accepts_a_trivial_return_block() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let at = Address::new(ram, 0);
        let mut f = Funcdata::new("t", at, spaces);
        let v = f.new_input(4, Address::new(reg, 0));
        let ret = f.new_op(OpCode::Return, SeqNum { pc: at, uniq: 0 }, vec![v, v]);
        let mut b = BlockBasic::default();
        b.ops.push(ret);
        f.set_blocks(vec![b]);
        f.op_mut(ret).parent = Some(BlockId(0));
        assert!(is_splittable(&f, BlockId(0)), "a bare RETURN of a non-free value is splittable");

        // Add an INT_ADD and it is no longer splittable.
        let k = f.new_const(4, 1);
        let add = f.new_op(OpCode::IntAdd, SeqNum { pc: at, uniq: 1 }, vec![v, k]);
        f.new_output(add, 4, Address::new(reg, 8));
        f.block_mut(BlockId(0)).ops.insert(0, add);
        f.op_mut(add).parent = Some(BlockId(0));
        assert!(!is_splittable(&f, BlockId(0)), "a block that computes is not splittable");
    }

    /// A RETURN block with a single in-edge has nothing to split (Ghidra blockaction.cc:2277).
    #[test]
    fn return_split_skips_a_single_predecessor() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let at = Address::new(ram, 0);
        let mut f = Funcdata::new("t", at, spaces);
        let ret = f.new_op(OpCode::Return, SeqNum { pc: at, uniq: 0 }, vec![]);
        let mut b = BlockBasic::default();
        b.ops.push(ret);
        f.set_blocks(vec![b]);
        f.op_mut(ret).parent = Some(BlockId(0));

        assert_eq!(ActionReturnSplit.apply(&mut f), 0);
        assert_eq!(f.num_blocks(), 1, "no duplicate block is created");
    }
}
