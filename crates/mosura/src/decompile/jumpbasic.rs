//! JumpBasic switch-recovery internals — a port of Ghidra's `PathMeld` /
//! `JumpBasic::findDeterminingVarnodes` (`jumptable.{cc,hh}`).
//!
//! Stage 1 of the JumpBasic port (memory `task8-jumpbasic-port-plan`). This is the data-flow
//! machinery Ghidra uses to find the set of Varnodes a `BRANCHIND` target is computed from: a
//! depth-first walk of the input tree ([`find_determining_varnodes`], `jumptable.cc:554`) that
//! collects candidate switch Varnodes into a [`PathMeld`] (`jumptable.hh:72`) — the intersection
//! of Varnodes common to every data-flow path reaching the branch, together with the p-code ops
//! along those paths in execution order.
//!
//! The module is not yet wired into [`super::jumptable::recover`]; that swap is Stage 4. Everything
//! here is corpus-neutral. The [`super::circlerange::CircleRange`] range machinery (Stage 0) and the
//! guard analysis (Stage 2) build on top of the [`PathMeld`] produced here.

use super::block::BlockId;
use super::circlerange::CircleRange;
use super::funcdata::Funcdata;
use super::nzmask::{calc_mask, coveringmask, mostsigbit_set};
use super::op::OpId;
use super::opcode::OpCode;
use super::varnode::VarnodeId;

/// Ghidra `PcodeOpNode` (`expression.hh:28`): an edge in a data-flow path — a p-code op together
/// with the input slot naming the Varnode end-point of the edge. In a [`find_determining_varnodes`]
/// `path`, entries are created in reverse execution order (root branch op first).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcodeOpNode {
    /// The p-code op at this end of the edge.
    pub op: OpId,
    /// The input slot naming the Varnode at the other end.
    pub slot: i32,
}

impl PcodeOpNode {
    pub fn new(op: OpId, slot: i32) -> Self {
        PcodeOpNode { op, slot }
    }
}

/// Ghidra `PathMeld::RootedOp` (`jumptable.hh:77`): a p-code op in the melded path set, linked to
/// the index within [`PathMeld::common_vn`] of the Varnode where its flow path split from the
/// common path. `op` is `None` for an op that split but did not rejoin (transient, during
/// [`PathMeld::meld_ops`]); after a meld completes no `None` remains.
#[derive(Clone, Copy, Debug)]
struct RootedOp {
    op: Option<OpId>,
    root_vn: i32,
}

/// Ghidra `PathMeld` (`jumptable.hh:72`): the Varnodes common to all data-flow paths reaching a
/// branch target, plus every p-code op across those paths (in execution order), each rooted at its
/// split point in `common_vn`.
#[derive(Clone, Debug, Default)]
pub struct PathMeld {
    /// Varnodes in common with all paths (Ghidra `commonVn`).
    common_vn: Vec<VarnodeId>,
    /// All the ops for the melded paths (Ghidra `opMeld`).
    op_meld: Vec<RootedOp>,
}

impl PathMeld {
    /// Ghidra `PathMeld::internalIntersect` (`jumptable.cc:794`): intersect the current `common_vn`
    /// with the *marked* Varnodes of a new path, replacing `common_vn` with the intersection. Fills
    /// `parent_map` mapping each old `common_vn` index to its new index (`-1` if cut, then
    /// back-filled with the next-earliest surviving index).
    fn internal_intersect(&mut self, data: &mut Funcdata, parent_map: &mut Vec<i32>) {
        let mut new_vn: Vec<VarnodeId> = Vec::new();
        for i in 0..self.common_vn.len() {
            let vn = self.common_vn[i];
            if data.vn(vn).is_mark() {
                // Previously marked varnode: it is in both lists.
                let last_intersect = new_vn.len() as i32;
                parent_map.push(last_intersect);
                new_vn.push(vn);
                data.vn_mut(vn).clear_mark();
            } else {
                parent_map.push(-1);
            }
        }
        self.common_vn = new_vn;
        let mut last_intersect = -1;
        for i in (0..parent_map.len()).rev() {
            let val = parent_map[i];
            if val == -1 {
                // Fill cut-out varnodes with the next earliest surviving intersection index.
                parent_map[i] = last_intersect;
            } else {
                last_intersect = val;
            }
        }
    }

    /// Ghidra `PathMeld::meldOps` (`jumptable.cc:832`): merge the new path's ops into `op_meld`
    /// keeping execution order, recomputing each op's split point via `parent_map`. Ops that split
    /// and do not rejoin are dropped. Returns a new cut point (`>= 0`) when two ops from different
    /// non-`last_block` blocks cannot be ordered, else `-1`.
    ///
    /// Ghidra's within-block ordering is `getSeqNum().getOrder()`; mosura has no scalar op order, so
    /// the same-block comparison uses [`op_order`] (position within the parent block's op list). The
    /// numeric compare is same-parent-guarded, so the index is exact; cross-block decisions use
    /// block identity ([`BlockId`]) and `last_block`, never a number.
    fn meld_ops(&mut self, data: &Funcdata, path: &[PcodeOpNode], cut_off: i32, parent_map: &[i32]) -> i32 {
        // First update op_meld rootVn with the new intersection information.
        for i in 0..self.op_meld.len() {
            let pos = parent_map[self.op_meld[i].root_vn as usize];
            if pos == -1 {
                self.op_meld[i].op = None; // Op split but did not rejoin
            } else {
                self.op_meld[i].root_vn = pos; // New index
            }
        }

        // Do a merge sort, keeping ops in execution order.
        let mut new_meld: Vec<RootedOp> = Vec::new();
        let mut cur_root: i32 = -1;
        let mut meld_pos: usize = 0;
        let mut last_block: Option<BlockId> = None;
        let mut i = 0i32;
        while i < cut_off {
            let op = path[i as usize].op; // Current op in the new path
            let op_parent = data.op(op).parent;
            let mut cur_op: Option<OpId> = None;
            while meld_pos < self.op_meld.len() {
                let trial_op = match self.op_meld[meld_pos].op {
                    None => {
                        meld_pos += 1;
                        continue;
                    }
                    Some(t) => t,
                };
                let trial_parent = data.op(trial_op).parent;
                if trial_parent != op_parent {
                    if op_parent == last_block {
                        cur_op = None; // op comes AFTER trialOp
                        break;
                    } else if trial_parent != last_block {
                        // Both come from different blocks that are not lastBlock: new cut point.
                        let res = self.op_meld[meld_pos].root_vn;
                        self.op_meld = new_meld;
                        return res;
                    }
                } else if op_order(data, trial_op) <= op_order(data, op) {
                    cur_op = Some(trial_op); // op is equal to or comes later than trialOp
                    break;
                }
                last_block = data.op(trial_op).parent;
                new_meld.push(self.op_meld[meld_pos]); // Old op moved into newMeld
                cur_root = self.op_meld[meld_pos].root_vn;
                meld_pos += 1;
            }
            if cur_op == Some(op) {
                new_meld.push(self.op_meld[meld_pos]);
                cur_root = self.op_meld[meld_pos].root_vn;
                meld_pos += 1;
            } else {
                new_meld.push(RootedOp { op: Some(op), root_vn: cur_root });
            }
            last_block = op_parent;
            i += 1;
        }
        self.op_meld = new_meld;
        -1
    }

    /// Ghidra `PathMeld::truncatePaths` (`jumptable.cc:901`): drop every op and Varnode executed
    /// before the given cut point (an index into `common_vn`).
    fn truncate_paths(&mut self, cut_point: i32) {
        while self.op_meld.len() > 1 {
            if self.op_meld.last().unwrap().root_vn < cut_point {
                break; // op uses a varnode earlier than the cut point: keep it and all after
            }
            self.op_meld.pop();
        }
        self.common_vn.truncate(cut_point.max(0) as usize);
    }

    /// Ghidra `PathMeld::set(const PathMeld&)` (`jumptable.cc:913`): copy paths from another container.
    pub fn set_meld(&mut self, op2: &PathMeld) {
        self.common_vn = op2.common_vn.clone();
        self.op_meld = op2.op_meld.clone();
    }

    /// Ghidra `PathMeld::set(const vector<PcodeOpNode>&)` (`jumptable.cc:922`): initialize to a
    /// single data-flow path (edges in reverse execution order).
    pub fn set_path(&mut self, data: &Funcdata, path: &[PcodeOpNode]) {
        for (i, node) in path.iter().enumerate() {
            let vn = data.op(node.op).input(node.slot as usize).expect("path slot in range");
            self.op_meld.push(RootedOp { op: Some(node.op), root_vn: i as i32 });
            self.common_vn.push(vn);
        }
    }

    /// Ghidra `PathMeld::set(PcodeOp*,Varnode*)` (`jumptable.cc:935`): initialize to a single-node
    /// "path" (one op reading one Varnode).
    pub fn set_node(&mut self, op: OpId, vn: VarnodeId) {
        self.common_vn.push(vn);
        self.op_meld.push(RootedOp { op: Some(op), root_vn: 0 });
    }

    /// Ghidra `PathMeld::append` (`jumptable.cc:947`): prepend another set of paths that share this
    /// container's common start point, renumbering the moved root references.
    pub fn append(&mut self, op2: &PathMeld) {
        let mut common = op2.common_vn.clone();
        common.extend_from_slice(&self.common_vn);
        self.common_vn = common;
        let mut meld = op2.op_meld.clone();
        meld.extend_from_slice(&self.op_meld);
        self.op_meld = meld;
        let shift = op2.common_vn.len() as i32;
        for i in op2.op_meld.len()..self.op_meld.len() {
            self.op_meld[i].root_vn += shift;
        }
    }

    /// Ghidra `PathMeld::clear` (`jumptable.cc:957`).
    pub fn clear(&mut self) {
        self.common_vn.clear();
        self.op_meld.clear();
    }

    /// Ghidra `PathMeld::meld` (`jumptable.cc:968`): meld a new path into this container,
    /// recomputing the Varnodes common to all paths. Paths that split from the common intersection
    /// but never rejoin are trimmed. `path` is truncated to the recomputed cut-off.
    pub fn meld(&mut self, data: &mut Funcdata, path: &mut Vec<PcodeOpNode>) {
        let mut parent_map: Vec<i32> = Vec::new();

        for node in path.iter() {
            // Mark varnodes in the new path, so the intersection is easy to see.
            let vn = data.op(node.op).input(node.slot as usize).expect("path slot in range");
            data.vn_mut(vn).set_mark();
        }
        self.internal_intersect(data, &mut parent_map); // old intersection -> new
        let mut cut_off: i32 = -1;

        // Calculate where the cut-off point is in the new path.
        for (i, node) in path.iter().enumerate() {
            let vn = data.op(node.op).input(node.slot as usize).expect("path slot in range");
            if !data.vn(vn).is_mark() {
                // Mark already cleared: this varnode is in the intersection.
                cut_off = i as i32 + 1;
            } else {
                data.vn_mut(vn).clear_mark();
            }
        }
        let new_cutoff = self.meld_ops(data, path, cut_off, &parent_map);
        if new_cutoff >= 0 {
            // Not all ops could be ordered: cut off where they couldn't.
            self.truncate_paths(new_cutoff);
        }
        path.truncate(cut_off.max(0) as usize);
    }

    /// Ghidra `PathMeld::markPaths` (`jumptable.cc:1000`): (un)mark every op from the start of the
    /// container up to and including the earliest op rooted at `start_varnode` (an index into
    /// `common_vn`). Used by the Stage 2 guard analysis to fence off the on-path ops.
    pub fn mark_paths(&mut self, data: &mut Funcdata, val: bool, start_varnode: i32) {
        let mut start_op: i32 = -1;
        for i in (0..self.op_meld.len()).rev() {
            if self.op_meld[i].root_vn == start_varnode {
                start_op = i as i32;
                break;
            }
        }
        if start_op < 0 {
            return;
        }
        for i in 0..=start_op as usize {
            if let Some(op) = self.op_meld[i].op {
                if val {
                    data.op_mut(op).set_mark();
                } else {
                    data.op_mut(op).clear_mark();
                }
            }
        }
    }

    /// Ghidra `PathMeld::getEarliestOp` (`jumptable.cc:1023`): the earliest-executed op in the
    /// container using the `pos`-th common Varnode as input.
    pub fn get_earliest_op(&self, pos: i32) -> Option<OpId> {
        for i in (0..self.op_meld.len()).rev() {
            if self.op_meld[i].root_vn == pos {
                return self.op_meld[i].op;
            }
        }
        None
    }

    /// Ghidra `PathMeld::numCommonVarnode` (`jumptable.hh:95`).
    pub fn num_common_varnode(&self) -> i32 {
        self.common_vn.len() as i32
    }

    /// Ghidra `PathMeld::numOps` (`jumptable.hh:96`).
    pub fn num_ops(&self) -> i32 {
        self.op_meld.len() as i32
    }

    /// Ghidra `PathMeld::getVarnode` (`jumptable.hh:97`): the `i`-th common Varnode.
    pub fn get_varnode(&self, i: i32) -> VarnodeId {
        self.common_vn[i as usize]
    }

    /// Ghidra `PathMeld::getOpParent` (`jumptable.hh:98`): the split-point Varnode for the `i`-th op.
    pub fn get_op_parent(&self, i: i32) -> VarnodeId {
        self.common_vn[self.op_meld[i as usize].root_vn as usize]
    }

    /// Ghidra `PathMeld::getOp` (`jumptable.hh:99`): the `i`-th op.
    pub fn get_op(&self, i: i32) -> OpId {
        self.op_meld[i as usize].op.expect("melded op is non-null")
    }

    /// Ghidra `PathMeld::empty` (`jumptable.hh:101`).
    pub fn empty(&self) -> bool {
        self.common_vn.is_empty()
    }
}

/// Ghidra `PcodeOp::getSeqNum().getOrder()` for the same-block comparison in [`PathMeld::meld_ops`]:
/// the op's position within its parent block's op list. The compare that uses this is always
/// same-parent-guarded, so within-block index reproduces Ghidra's per-block order exactly.
fn op_order(data: &Funcdata, op: OpId) -> usize {
    if let Some(bid) = data.op(op).parent {
        if let Some(pos) = data.block(bid).ops.iter().position(|&o| o == op) {
            return pos;
        }
    }
    0
}

/// Ghidra `JumpBasic::isprune` (`jumptable.cc:424`): a Varnode is a leaf of the switch-variable
/// input tree if it is not written, or is written by a call/marker, or by an op with no inputs.
fn isprune(data: &Funcdata, vn: VarnodeId) -> bool {
    if !data.vn(vn).is_written() {
        return true;
    }
    let op = data.vn(vn).def.expect("written varnode has a def");
    let o = data.op(op);
    if o.is_call() || o.is_marker() {
        return true;
    }
    if o.num_inputs() == 0 {
        return true;
    }
    false
}

/// Ghidra `JumpBasic::ispoint` (`jumptable.cc:436`): a leaf Varnode could be the switch variable
/// unless it is a constant, an annotation, or a read-only value.
fn ispoint(data: &Funcdata, vn: VarnodeId) -> bool {
    let v = data.vn(vn);
    if v.is_constant() {
        return false;
    }
    if v.is_annotation() {
        return false;
    }
    if v.is_readonly() {
        return false;
    }
    true
}

/// Ghidra `JumpBasic::getStride` (`jumptable.cc:449`): if some least-significant bits of `vn` are
/// known zero, turn that into a jumptable stride (1,2,4,...), capped at 32.
pub fn get_stride(data: &Funcdata, vn: VarnodeId) -> i32 {
    let mut mask = data.vn(vn).get_nzmask();
    if (mask & 0x3f) == 0 {
        // Limit the maximum stride we can return.
        return 32;
    }
    let mut stride = 1i32;
    while (mask & 1) == 0 {
        mask >>= 1;
        stride <<= 1;
    }
    stride
}

/// Ghidra `JumpBasic::getMaxValue` (`jumptable.cc:512`): if `vn`'s range is restricted by an
/// `INT_AND` mask (directly, or duplicated across an `INT_MULTIEQUAL`), return the maximum value of
/// that range; otherwise 0 (all values possible).
pub fn get_max_value(data: &Funcdata, vn: VarnodeId) -> u64 {
    let mut max_value: u64 = 0; // 0 indicates maximum possible value
    if !data.vn(vn).is_written() {
        return max_value;
    }
    let op = data.vn(vn).def.expect("written varnode has a def");
    match data.op(op).code() {
        OpCode::IntAnd => {
            let constvn = data.op(op).input(1).expect("INT_AND has two inputs");
            if data.vn(constvn).is_constant() {
                max_value = coveringmask(data.vn(constvn).constant_value());
                max_value = max_value.wrapping_add(1) & calc_mask(data.vn(vn).size);
            }
        }
        OpCode::Multiequal => {
            // The AND may be duplicated across multiple blocks.
            let n = data.op(op).num_inputs();
            let mut i = 0;
            while i < n {
                let subvn = data.op(op).input(i).expect("input in range");
                if !data.vn(subvn).is_written() {
                    break;
                }
                let and_op = data.vn(subvn).def.expect("written varnode has a def");
                if data.op(and_op).code() != OpCode::IntAnd {
                    break;
                }
                let constvn = data.op(and_op).input(1).expect("INT_AND has two inputs");
                if !data.vn(constvn).is_constant() {
                    break;
                }
                if max_value < data.vn(constvn).constant_value() {
                    max_value = data.vn(constvn).constant_value();
                }
                i += 1;
            }
            if i == n {
                max_value = coveringmask(max_value);
                max_value = max_value.wrapping_add(1) & calc_mask(data.vn(vn).size);
            } else {
                max_value = 0;
            }
        }
        _ => {}
    }
    max_value
}

/// Ghidra `matching_constants` (`jumptable.cc:598`): true if both Varnodes are constants of equal
/// value.
fn matching_constants(data: &Funcdata, vn1: VarnodeId, vn2: VarnodeId) -> bool {
    if !data.vn(vn1).is_constant() {
        return false;
    }
    if !data.vn(vn2).is_constant() {
        return false;
    }
    data.vn(vn1).constant_value() == data.vn(vn2).constant_value()
}

/// Ghidra `GuardRecord::oneOffMatch` (`jumptable.cc:684`): return 1 if `op1` and `op2` produce
/// exactly the same value — one level of a binary op whose second operand is a matching constant.
pub fn one_off_match(data: &Funcdata, op1: OpId, op2: OpId) -> i32 {
    if data.op(op1).code() != data.op(op2).code() {
        return 0;
    }
    match data.op(op1).code() {
        OpCode::IntAnd
        | OpCode::IntAdd
        | OpCode::IntXor
        | OpCode::IntOr
        | OpCode::IntLeft
        | OpCode::IntRight
        | OpCode::IntSright
        | OpCode::IntMult
        | OpCode::Subpiece => {
            if data.op(op2).input(0) != data.op(op1).input(0) {
                return 0;
            }
            if let (Some(a), Some(b)) = (data.op(op2).input(1), data.op(op1).input(1)) {
                if matching_constants(data, a, b) {
                    return 1;
                }
            }
        }
        _ => {}
    }
    0
}

/// Ghidra `GuardRecord::quasiCopy` (`jumptable.cc:719`): the earliest ancestor Varnode for which
/// `vn` is a \e quasi-copy — a sequence of ops that always hold the value in the least significant
/// bits of their output (upper bits may differ). Returns `(base, bits_preserved)`.
pub fn quasi_copy(data: &Funcdata, mut vn: VarnodeId) -> (VarnodeId, i32) {
    let bits_preserved = mostsigbit_set(data.vn(vn).get_nzmask()) + 1;
    if bits_preserved == 0 {
        return (vn, bits_preserved);
    }
    // mask = low `bits_preserved` bits set (`2 << (bits_preserved-1)) - 1`, with Ghidra's wrapping).
    let mask = (2u64 << (bits_preserved - 1)).wrapping_sub(1);
    let mut op = data.vn(vn).def;
    while let Some(o) = op {
        match data.op(o).code() {
            OpCode::Copy => {
                vn = data.op(o).input(0).expect("COPY has an input");
                op = data.vn(vn).def;
            }
            OpCode::IntAnd => {
                let const_vn = data.op(o).input(1).expect("INT_AND has two inputs");
                if data.vn(const_vn).is_constant() && data.vn(const_vn).constant_value() == mask {
                    vn = data.op(o).input(0).unwrap();
                    op = data.vn(vn).def;
                } else {
                    op = None;
                }
            }
            OpCode::IntOr => {
                let const_vn = data.op(o).input(1).expect("INT_OR has two inputs");
                let c = data.vn(const_vn).constant_value();
                if data.vn(const_vn).is_constant() && (c | mask) == (c ^ mask) {
                    vn = data.op(o).input(0).unwrap();
                    op = data.vn(vn).def;
                } else {
                    op = None;
                }
            }
            OpCode::IntSext | OpCode::IntZext => {
                let inv = data.op(o).input(0).expect("extension has an input");
                if data.vn(inv).size as i32 * 8 >= bits_preserved {
                    vn = inv;
                    op = data.vn(vn).def;
                } else {
                    op = None;
                }
            }
            OpCode::Piece => {
                let lo = data.op(o).input(1).expect("PIECE has two inputs");
                if data.vn(lo).size as i32 * 8 >= bits_preserved {
                    vn = lo;
                    op = data.vn(vn).def;
                } else {
                    op = None;
                }
            }
            OpCode::Subpiece => {
                let const_vn = data.op(o).input(1).expect("SUBPIECE has two inputs");
                if data.vn(const_vn).is_constant() && data.vn(const_vn).constant_value() == 0 {
                    vn = data.op(o).input(0).unwrap();
                    op = data.vn(vn).def;
                } else {
                    op = None;
                }
            }
            _ => op = None,
        }
    }
    (vn, bits_preserved)
}

/// Ghidra `GuardRecord` (`jumptable.hh:137`): a Varnode plus the range constraint imposed on it by
/// a guarding CBRANCH — if the branch is followed toward the switch's BRANCHIND, the Varnode is
/// known to lie in `range`.
#[derive(Clone, Debug)]
pub struct GuardRecord {
    /// The CBRANCH that branches around the switch (`None` once [`clear`](GuardRecord::clear)ed).
    cbranch: Option<OpId>,
    /// The immediate op causing the restriction.
    read_op: OpId,
    /// The Varnode being restricted.
    vn: VarnodeId,
    /// The value being (quasi-)copied into `vn`.
    base_vn: VarnodeId,
    /// The specific CBRANCH path going toward the switch.
    indpath: i32,
    /// Number of least-significant bits copied (all others zero).
    bits_preserved: i32,
    /// Range of values causing the CBRANCH to take the path to the switch.
    range: CircleRange,
    /// True if the guarding CBRANCH is duplicated across multiple blocks.
    unrolled: bool,
}

impl GuardRecord {
    /// Ghidra `GuardRecord::GuardRecord` (`jumptable.cc:613`).
    pub fn new(
        data: &Funcdata,
        cbranch: Option<OpId>,
        read_op: OpId,
        indpath: i32,
        range: CircleRange,
        vn: VarnodeId,
        unrolled: bool,
    ) -> Self {
        let (base_vn, bits_preserved) = quasi_copy(data, vn);
        GuardRecord { cbranch, read_op, vn, base_vn, indpath, bits_preserved, range, unrolled }
    }

    /// Ghidra `GuardRecord::isUnrolled` (`jumptable.hh:148`).
    pub fn is_unrolled(&self) -> bool {
        self.unrolled
    }

    /// Ghidra `GuardRecord::getBranch` (`jumptable.hh:149`).
    pub fn get_branch(&self) -> Option<OpId> {
        self.cbranch
    }

    /// Ghidra `GuardRecord::getReadOp` (`jumptable.hh:150`).
    pub fn get_read_op(&self) -> OpId {
        self.read_op
    }

    /// Ghidra `GuardRecord::getPath` (`jumptable.hh:151`).
    pub fn get_path(&self) -> i32 {
        self.indpath
    }

    /// Ghidra `GuardRecord::getRange` (`jumptable.hh:152`).
    pub fn get_range(&self) -> &CircleRange {
        &self.range
    }

    /// Ghidra `GuardRecord::clear` (`jumptable.hh:153`): mark this guard as unused.
    pub fn clear(&mut self) {
        self.cbranch = None;
    }

    /// Ghidra `GuardRecord::valueMatch` (`jumptable.cc:637`): does this guard apply to `vn2`?
    /// Returns 0 (values not clearly equal), 1 (clearly equal), or 2 (equal pending no intervening
    /// writes). `base_vn2` / `bits_preserved2` come from [`quasi_copy`] on `vn2`.
    pub fn value_match(&self, data: &Funcdata, vn2: VarnodeId, base_vn2: VarnodeId, bits_preserved2: i32) -> i32 {
        if self.vn == vn2 {
            return 1; // Same varnode, same value
        }
        let (load_op, load_op2) = if self.bits_preserved == bits_preserved2 {
            // Same number of bits being copied.
            if self.base_vn == base_vn2 {
                return 1; // Bits copied from the same varnode
            }
            (data.vn(self.base_vn).def, data.vn(base_vn2).def)
        } else {
            (data.vn(self.vn).def, data.vn(vn2).def)
        };
        let (Some(load_op), Some(load_op2)) = (load_op, load_op2) else {
            return 0;
        };
        if one_off_match(data, load_op, load_op2) == 1 {
            return 1; // Simple duplicate calculation
        }
        if data.op(load_op).code() != OpCode::Load {
            return 0;
        }
        if data.op(load_op2).code() != OpCode::Load {
            return 0;
        }
        // Same space (getIn(0) is the space-id constant).
        let sp = data.op(load_op).input(0).unwrap();
        let sp2 = data.op(load_op2).input(0).unwrap();
        if data.vn(sp).constant_value() != data.vn(sp2).constant_value() {
            return 0;
        }
        let ptr = data.op(load_op).input(1).unwrap();
        let ptr2 = data.op(load_op2).input(1).unwrap();
        if ptr == ptr2 {
            return 2;
        }
        if !data.vn(ptr).is_written() || !data.vn(ptr2).is_written() {
            return 0;
        }
        let addop = data.vn(ptr).def.unwrap();
        if data.op(addop).code() != OpCode::IntAdd {
            return 0;
        }
        let constvn = data.op(addop).input(1).unwrap();
        if !data.vn(constvn).is_constant() {
            return 0;
        }
        let addop2 = data.vn(ptr2).def.unwrap();
        if data.op(addop2).code() != OpCode::IntAdd {
            return 0;
        }
        let constvn2 = data.op(addop2).input(1).unwrap();
        if !data.vn(constvn2).is_constant() {
            return 0;
        }
        if data.op(addop).input(0).unwrap() != data.op(addop2).input(0).unwrap() {
            return 0;
        }
        if data.vn(constvn).constant_value() != data.vn(constvn2).constant_value() {
            return 0;
        }
        2
    }
}

/// Ghidra `JumpBasic::analyzeGuards` (`jumptable.cc:1046`): walk the CBRANCHs leading up to the
/// switch block and build a [`GuardRecord`] for each range restriction on a path variable. The
/// initial boolean range at the CBRANCH condition is pulled back (up to `maxpullback` steps) through
/// each defining op via [`CircleRange::pull_back`], recording the restricted Varnode + range at each
/// step — this is the mechanism that turns `INT_LESS(INT_ADD(index,-1),8)` into a `[1,9)` bound on
/// `index`.
///
/// Adapted to mosura's canonical CFG: a CBRANCH's out-edges are `[fallthrough=cond-false,
/// target=cond-true]` with no boolean-flip and no structuring flip-path, so `toswitchval =
/// (indpath == 1)` and `indpathstore = indpath`. The unrolled-guard case (`sizeIn > 1`,
/// Ghidra's `checkUnrolledGuard`) is deferred (cited) — it returns with the guards found so far.
// In the pathout branch Ghidra also sets `bl = prevbl->getOut(pathout)`, a dead store overwritten
// by `bl = prevbl` before any read; kept for line-faithfulness, hence the allow below.
#[allow(unused_assignments)]
pub fn analyze_guards(
    data: &Funcdata,
    mut bl: BlockId,
    mut pathout: i32,
    indop: OpId,
    usenzmask: bool,
) -> Vec<GuardRecord> {
    let maxbranch = 2; // Maximum number of CBRANCHs to consider
    let maxpullback = 2;
    let mut selectguards: Vec<GuardRecord> = Vec::new();

    for i in 0..maxbranch {
        let prevbl: BlockId;
        let indpath: i32;
        if pathout >= 0 && data.block(bl).out_edges.len() == 2 {
            let prev = bl;
            bl = data.block(prev).out_edges[pathout as usize];
            indpath = pathout;
            pathout = -1;
            prevbl = prev;
        } else {
            pathout = -1; // Make sure not to use pathout next time around
            loop {
                if data.block(bl).in_edges.len() != 1 {
                    // sizeIn > 1 is the unrolled-guard case (checkUnrolledGuard), deferred.
                    return selectguards;
                }
                // Only one flow path to the switch.
                let pb = data.block(bl).in_edges[0];
                if data.block(pb).out_edges.len() != 1 {
                    prevbl = pb; // prevbl can deviate from the switch path: a guard candidate
                    break;
                }
                bl = pb; // Single out: back up to the next block
            }
            // indpath = bl->getInRevIndex(0): which out-edge of prevbl leads to bl.
            indpath = data
                .block(prevbl)
                .out_edges
                .iter()
                .position(|&o| o == bl)
                .map(|p| p as i32)
                .unwrap_or(-1);
        }
        let Some(&cbranch) = data.block(prevbl).ops.last() else {
            break;
        };
        if data.op(cbranch).code() != OpCode::Cbranch {
            break;
        }
        if i != 0 {
            // Check that this CBRANCH isn't protecting some other switch.
            let otherbl = data.block(prevbl).out_edges[(1 - indpath) as usize];
            if let Some(&otherop) = data.block(otherbl).ops.last() {
                if data.op(otherop).code() == OpCode::Branchind && otherop != indop {
                    break;
                }
            }
        }
        let toswitchval = indpath == 1; // no isBooleanFlip in mosura's canonical CFG
        bl = prevbl;
        let mut vn = data.op(cbranch).input(1).expect("CBRANCH has a condition");
        let mut rng = CircleRange::from_bool(toswitchval);

        // The boolean variable could conceivably be the switch variable.
        let indpathstore = indpath; // no getFlipPath in mosura
        selectguards.push(GuardRecord::new(data, Some(cbranch), cbranch, indpathstore, rng, vn, false));
        for _ in 0..maxpullback {
            if !data.vn(vn).is_written() {
                break;
            }
            let read_op = data.vn(vn).def.expect("written varnode has a def");
            match rng.pull_back(data, read_op, usenzmask) {
                None => break,
                Some(nv) => vn = nv,
            }
            if rng.is_empty() {
                break;
            }
            selectguards.push(GuardRecord::new(data, Some(cbranch), read_op, indpathstore, rng, vn, false));
        }
    }
    selectguards
}

/// Ghidra `JumpBasic::findDeterminingVarnodes` (`jumptable.cc:554`): compute the initial set of
/// Varnodes that might be switch variables. Paths terminating at `(op, slot)` are traversed and
/// organized into a [`PathMeld`] holding the Varnodes common to every path.
///
/// A depth-first walk of the input tree: at each leaf (`isprune`) that could be a switch variable
/// (`ispoint`), the current path is taken as the result (first) or melded (subsequent). If no
/// likely point is ever found, the address is uniquely determined and the single input edge is used.
pub fn find_determining_varnodes(data: &mut Funcdata, op: OpId, slot: i32) -> PathMeld {
    let mut path: Vec<PcodeOpNode> = Vec::new();
    let mut path_meld = PathMeld::default();
    let mut firstpoint = false; // Have not seen a likely switch variable yet

    path.push(PcodeOpNode::new(op, slot));

    // Traverse the tree of inputs to the final address (do-while: body runs before the size check).
    loop {
        let node = *path.last().unwrap();
        let curvn = data.op(node.op).input(node.slot as usize).expect("path slot in range");
        if isprune(data, curvn) {
            // Here is a node (leaf) of the tree.
            if ispoint(data, curvn) {
                // A possible switch variable.
                if !firstpoint {
                    path_meld.set_path(data, &path); // Take the current path as the result
                    firstpoint = true;
                } else {
                    path_meld.meld(data, &mut path);
                }
            }
            path.last_mut().unwrap().slot += 1;
            loop {
                let back = path.last().unwrap();
                if (back.slot as usize) < data.op(back.op).num_inputs() {
                    break;
                }
                path.pop();
                if path.is_empty() {
                    break;
                }
                path.last_mut().unwrap().slot += 1;
            }
        } else {
            // This varnode is not pruned: descend into its defining op.
            let def = data.vn(curvn).def.expect("non-pruned varnode is written");
            path.push(PcodeOpNode::new(def, 0));
        }
        if path.len() <= 1 {
            break;
        }
    }
    if path_meld.empty() {
        // Never found a likely point: the address is uniquely determined but the
        // constants/readonlys have not been collapsed.
        let invn = data.op(op).input(slot as usize).expect("slot in range");
        path_meld.set_node(op, invn);
    }
    path_meld
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::block::BlockBasic;
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::{Funcdata, SeqNum};

    fn fd() -> Funcdata {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        Funcdata::new("t", Address::new(ram, 0), spaces)
    }

    /// A single-path input tree: `BRANCHIND(INT_ADD(index, c))`. `findDeterminingVarnodes` walks to
    /// the free input `index`, the lone switch-variable candidate, and records the path.
    #[test]
    fn linear_chain_finds_the_single_switch_var() {
        let mut f = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        let index = f.new_input(4, Address::new(reg, 0x10)); // free input => ispoint
        let c = f.new_const(4, 0x10);
        let add = f.new_op(OpCode::IntAdd, seq, vec![index, c]);
        let target = f.new_output(add, 4, Address::new(reg, 0x18));
        let br = f.new_op(OpCode::Branchind, seq, vec![target]);
        f.set_blocks(vec![BlockBasic {
            ops: vec![add, br],
            in_edges: vec![],
            out_edges: vec![],
        }]);
        for op in [add, br] {
            f.op_mut(op).parent = Some(BlockId(0));
        }

        let pm = find_determining_varnodes(&mut f, br, 0);
        // common_vn = [target, index]: the branch target and the switch variable.
        assert_eq!(pm.num_common_varnode(), 2);
        assert_eq!(pm.get_varnode(0), target);
        assert_eq!(pm.get_varnode(1), index);
        // The earliest op reading `index` is the INT_ADD.
        assert_eq!(pm.get_earliest_op(1), Some(add));
        // Every leftover mark must be cleared.
        assert!(!f.vn(index).is_mark());
        assert!(!f.vn(target).is_mark());
    }

    /// A diamond in the *data* flow: `target = INT_XOR(index+1, index-2)`, both operands rooted at
    /// the single free input `index`. The DFS reaches `index` along two paths that split at the XOR
    /// and rejoin at `index`, so `set` runs on the first and `meld` (→ internalIntersect + meldOps)
    /// on the second. The melded common set must collapse to exactly `[target, index]`.
    #[test]
    fn diamond_dataflow_melds_two_paths_to_common_varnodes() {
        let mut f = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        let index = f.new_input(4, Address::new(reg, 0x10));
        let c1 = f.new_const(4, 1);
        let c2 = f.new_const(4, 2);
        let addy = f.new_op(OpCode::IntAdd, seq, vec![index, c1]);
        let y = f.new_output(addy, 4, Address::new(reg, 0x18));
        let addz = f.new_op(OpCode::IntSub, seq, vec![index, c2]);
        let z = f.new_output(addz, 4, Address::new(reg, 0x1c));
        let xor = f.new_op(OpCode::IntXor, seq, vec![y, z]);
        let target = f.new_output(xor, 4, Address::new(reg, 0x20));
        let br = f.new_op(OpCode::Branchind, seq, vec![target]);
        // One straight-line block, ops in execution order (order = index within the block).
        let ops = vec![addy, addz, xor, br];
        f.set_blocks(vec![BlockBasic { ops: ops.clone(), in_edges: vec![], out_edges: vec![] }]);
        for &op in &ops {
            f.op_mut(op).parent = Some(BlockId(0));
        }

        let pm = find_determining_varnodes(&mut f, br, 0);
        // The two paths share exactly the branch target and the switch variable.
        assert_eq!(pm.num_common_varnode(), 2, "meld collapses to the common varnodes");
        assert_eq!(pm.get_varnode(0), target);
        assert_eq!(pm.get_varnode(1), index);
        // `index` (common index 1) is read earliest by one of the addend ops (addz survives the meld).
        assert_eq!(pm.get_earliest_op(1), Some(addz));
        // All transient marks cleared.
        for v in [index, y, z, target] {
            assert!(!f.vn(v).is_mark(), "no leftover varnode marks");
        }
    }

    /// `mark_paths` marks (then unmarks) every op from the container start up to the earliest op
    /// rooted at the given common Varnode.
    #[test]
    fn mark_paths_sets_and_clears_op_marks() {
        let mut f = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        let index = f.new_input(4, Address::new(reg, 0x10));
        let c = f.new_const(4, 0x10);
        let add = f.new_op(OpCode::IntAdd, seq, vec![index, c]);
        let target = f.new_output(add, 4, Address::new(reg, 0x18));
        let br = f.new_op(OpCode::Branchind, seq, vec![target]);
        f.set_blocks(vec![BlockBasic { ops: vec![add, br], in_edges: vec![], out_edges: vec![] }]);
        for op in [add, br] {
            f.op_mut(op).parent = Some(BlockId(0));
        }

        let mut pm = find_determining_varnodes(&mut f, br, 0);
        // start_varnode = 1 (index): earliest op rooted there is the INT_ADD, so both ops mark.
        pm.mark_paths(&mut f, true, 1);
        assert!(f.op(br).is_mark());
        assert!(f.op(add).is_mark());
        pm.mark_paths(&mut f, false, 1);
        assert!(!f.op(br).is_mark());
        assert!(!f.op(add).is_mark());
    }

    /// `getStride` reads the trailing-zero bits of the nzmask; `getMaxValue` reads an INT_AND mask.
    #[test]
    fn stride_and_maxvalue_from_masks() {
        let mut f = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // getStride: nzmask 0x6 (bits 1..2) => stride 2.
        let raw = f.new_input(4, Address::new(reg, 0x10));
        f.vn_mut(raw).nzm = 0x6;
        assert_eq!(get_stride(&f, raw), 2);
        // nzmask with all low 6 bits zero => capped stride 32.
        let raw2 = f.new_input(4, Address::new(reg, 0x14));
        f.vn_mut(raw2).nzm = 0xc0;
        assert_eq!(get_stride(&f, raw2), 32);

        // getMaxValue: masked = INT_AND(x, 0xff) => coveringmask(0xff)+1 = 0x100.
        let x = f.new_input(4, Address::new(reg, 0x18));
        let mask = f.new_const(4, 0xff);
        let and = f.new_op(OpCode::IntAnd, seq, vec![x, mask]);
        let masked = f.new_output(and, 4, Address::new(reg, 0x1c));
        assert_eq!(get_max_value(&f, masked), 0x100);
        // An unmasked (free) varnode has no restriction => 0.
        assert_eq!(get_max_value(&f, x), 0);
    }

    /// `isprune`/`ispoint` classify leaves: a free input is a pruned candidate; a constant is pruned
    /// but not a candidate; a written arithmetic result is not pruned.
    #[test]
    fn prune_and_point_classification() {
        let mut f = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        let inp = f.new_input(4, Address::new(reg, 0x10));
        assert!(isprune(&f, inp), "free input is a leaf");
        assert!(ispoint(&f, inp), "free input is a switch candidate");

        let c = f.new_const(4, 5);
        assert!(isprune(&f, c), "constant is a leaf");
        assert!(!ispoint(&f, c), "constant is not a switch candidate");

        let add = f.new_op(OpCode::IntAdd, seq, vec![inp, c]);
        let sum = f.new_output(add, 4, Address::new(reg, 0x18));
        assert!(!isprune(&f, sum), "arithmetic result is not a leaf");
    }

    /// The task-defining guard: a switch block guarded by `if (INT_LESS(INT_ADD(index,-1), 8))`.
    /// `analyzeGuards` pulls the boolean back through INT_LESS then INT_ADD, producing a GuardRecord
    /// on `index` with range `[1,9)` — the ADD-form bound mosura's old normalize could not relate.
    #[test]
    fn analyze_guards_add_form_bounds_index_to_1_9() {
        let mut f = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = |o: u64| SeqNum { pc: Address::new(ram, o), uniq: 0 };

        // block0 (guard): idxm1 = index - 1; cond = idxm1 < 8; CBRANCH(->switch, cond).
        let index = f.new_input(4, Address::new(reg, 0x10));
        let negone = f.new_const(4, 0xffff_ffff);
        let add = f.new_op(OpCode::IntAdd, seq(0), vec![index, negone]);
        let idxm1 = f.new_output(add, 4, Address::new(reg, 0x18));
        let eight = f.new_const(4, 8);
        let less = f.new_op(OpCode::IntLess, seq(0), vec![idxm1, eight]);
        let cond = f.new_output(less, 1, Address::new(reg, 0x20));
        let brtarget = f.new_const(8, 0x100);
        let cbr = f.new_op(OpCode::Cbranch, seq(4), vec![brtarget, cond]);
        // block1 (switch): BRANCHIND. block2 (default): RETURN.
        let swvn = f.new_input(8, Address::new(reg, 0x28));
        let branchind = f.new_op(OpCode::Branchind, seq(0x100), vec![swvn]);
        let ret = f.new_op(OpCode::Return, seq(0x200), vec![]);

        // out-edges [fallthrough=default(block2), taken=switch(block1)] => indpath 1 => toswitchval true.
        f.set_blocks(vec![
            BlockBasic { ops: vec![add, less, cbr], in_edges: vec![], out_edges: vec![BlockId(2), BlockId(1)] },
            BlockBasic { ops: vec![branchind], in_edges: vec![BlockId(0)], out_edges: vec![] },
            BlockBasic { ops: vec![ret], in_edges: vec![BlockId(0)], out_edges: vec![] },
        ]);
        for (bi, ops) in [(0u32, vec![add, less, cbr]), (1, vec![branchind]), (2, vec![ret])] {
            for op in ops {
                f.op_mut(op).parent = Some(BlockId(bi));
            }
        }

        let guards = analyze_guards(&f, BlockId(1), -1, branchind, true);
        // Three records: the boolean cond, then idxm1 ([0,8)), then index ([1,9)).
        assert_eq!(guards.len(), 3);
        assert_eq!(guards[0].vn, cond);
        assert_eq!(guards[1].vn, idxm1);
        assert_eq!(guards[1].range.get_min(), 0);
        assert_eq!(guards[1].range.get_end(), 8);
        assert_eq!(guards[2].vn, index, "the innermost guard restricts the switch variable");
        assert_eq!(guards[2].range.get_min(), 1);
        assert_eq!(guards[2].range.get_end(), 9);
        assert_eq!(guards[2].get_path(), 1);
        // valueMatch of the index guard against index itself is a definite match.
        let (base, bits) = quasi_copy(&f, index);
        assert_eq!(guards[2].value_match(&f, index, base, bits), 1);
    }

    /// `quasiCopy` strips a COPY chain to the source and reports the preserved-bit count from the
    /// nzmask; `one_off_match` recognizes two identical const-operand binary ops.
    #[test]
    fn quasi_copy_and_one_off_match() {
        let mut f = fd();
        let reg = f.spaces.by_name("register").unwrap();
        let ram = f.spaces.by_name("ram").unwrap();
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // t = COPY(x): quasiCopy(t) walks back to x; full 4-byte nzmask => 32 bits preserved.
        let x = f.new_input(4, Address::new(reg, 0x10));
        let cp = f.new_op(OpCode::Copy, seq, vec![x]);
        let t = f.new_output(cp, 4, Address::new(reg, 0x14));
        let (base, bits) = quasi_copy(&f, t);
        assert_eq!(base, x);
        assert_eq!(bits, 32);
        // A plain input is its own quasi-copy source.
        let (b2, _) = quasi_copy(&f, x);
        assert_eq!(b2, x);

        // one_off_match: INT_ADD(x,5) matches INT_ADD(x,5) but not INT_ADD(x,6).
        let c5 = f.new_const(4, 5);
        let c6 = f.new_const(4, 6);
        let a1 = f.new_op(OpCode::IntAdd, seq, vec![x, c5]);
        f.new_output(a1, 4, Address::new(reg, 0x18));
        let a2 = f.new_op(OpCode::IntAdd, seq, vec![x, c5]);
        f.new_output(a2, 4, Address::new(reg, 0x1c));
        let a3 = f.new_op(OpCode::IntAdd, seq, vec![x, c6]);
        f.new_output(a3, 4, Address::new(reg, 0x20));
        assert_eq!(one_off_match(&f, a1, a2), 1);
        assert_eq!(one_off_match(&f, a1, a3), 0);
    }
}
