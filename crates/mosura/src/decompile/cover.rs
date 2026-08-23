//! Liveness ranges — Ghidra's `Cover`/`CoverBlock` (`cover.cc`). A [`Cover`] records, per
//! basic block, the range of program points where a varnode is live (from its definition
//! to its last use along the control flow). Two varnodes can share storage (merge into one
//! variable) only if their covers do not intersect.
//!
//! Positions use a half-point scheme within a block of `n` ops: entry = 0; op `i` reads at
//! `2i+1` and writes at `2i+2`; exit = `2n+2`. So a value defined and a value used at the
//! *same* op don't intersect (the read at `2i+1` precedes the write at `2i+2`) — exactly
//! what makes `x = x + 1`'s two SSA versions mergeable.

use super::fasthash::{FxHashMap, FxHashSet};
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::varnode::VarnodeId;
use std::collections::HashMap;

/// The live range of one varnode: a convex `[lo, hi]` position range per block it's live in.
#[derive(Default, Clone)]
pub struct Cover {
    blocks: FxHashMap<usize, (i32, i32)>,
    /// The individual live ranges per block, un-merged. `blocks` keeps their CONVEX HULL, which is
    /// what merging has always used and what every mergeability decision is calibrated against;
    /// this keeps the pieces so a point query can be exact.
    ///
    /// Ghidra's `Cover` is a set of intervals throughout. The hull is an over-approximation: a
    /// value live at [4,6] and [20,22] reads as live at 12. That is SAFE for merging (it only
    /// refuses merges Ghidra would allow) but wrong for `contains_point`, whose whole purpose is
    /// asking whether a specific op falls inside a value's life — an op at 12 is not.
    spans: FxHashMap<usize, Vec<(i32, i32)>>,
}

impl Cover {
    fn extend(&mut self, block: usize, lo: i32, hi: i32) {
        let e = self.blocks.entry(block).or_insert((i32::MAX, i32::MIN));
        e.0 = e.0.min(lo);
        e.1 = e.1.max(hi);
        let v = self.spans.entry(block).or_default();
        v.push((lo, hi));
        // keep them disjoint and ordered so the point query is a simple scan
        v.sort_unstable();
        let mut merged: Vec<(i32, i32)> = Vec::with_capacity(v.len());
        for &(a, b) in v.iter() {
            match merged.last_mut() {
                Some(last) if a <= last.1 + 1 => last.1 = last.1.max(b),
                _ => merged.push((a, b)),
            }
        }
        *v = merged;
    }

    /// Do these two covers overlap at any live point?
    pub fn intersects(&self, other: &Cover) -> bool {
        for (b, &(lo1, hi1)) in &self.blocks {
            if let Some(&(lo2, hi2)) = other.blocks.get(b) {
                if lo1 <= hi2 && lo2 <= hi1 {
                    return true;
                }
            }
        }
        false
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// The live `[lo, hi]` position range in `block`, if the varnode is live there.
    pub fn block_range(&self, block: usize) -> Option<(i32, i32)> {
        self.blocks.get(&block).copied()
    }

    /// Union another cover into this one (Ghidra `Cover::merge`, cover.cc) — per block, the
    /// combined `[lo, hi]` range.
    pub fn merge_from(&mut self, other: &Cover) {
        for (&b, ranges) in &other.spans {
            for &(lo, hi) in ranges {
                self.extend(b, lo, hi);
            }
        }
    }

    /// Is the given position inside this cover in `block`? (Ghidra `Cover::contain`, cover.cc —
    /// the point query `checkCopyPair` uses to detect an intervening write inside a range.)
    /// The single (lo,hi) span this cover records for `block`, if any. Diagnostic only — its
    /// existence is the point: Ghidra's `Cover` is a set of INTERVALS, so a value with two distant
    /// uses in one block has two ranges there, while this collapses them into one span that
    /// swallows everything between.
    pub fn span_of(&self, block: usize) -> Option<(i32, i32)> {
        self.blocks.get(&block).copied()
    }

    pub fn contains_point(&self, block: usize, point: i32) -> bool {
        // Exact: the individual ranges, not their hull. See `spans`.
        self.spans.get(&block).is_some_and(|v| v.iter().any(|&(lo, hi)| lo <= point && point <= hi))
    }

    /// Ghidra `Cover::contain(op, 2)` (cover.cc): the op is contained AND not on the cover
    /// boundary (`boundary(op) == 0`). The tail exclusion (`point < hi`) is load-bearing: a
    /// single-use LOAD feeding directly into the same-address STORE has that store AS its cover's
    /// stop point, and Ghidra deliberately lets it stay implied — the `iRam = iRam + 1` increment
    /// idiom. (The def-point boundary can't collide here: reads sit at odd positions `2i+1`, defs
    /// at even `2i+2`.)
    pub fn contains_op_interior(&self, block: usize, point: i32) -> bool {
        self.spans.get(&block).is_some_and(|v| v.iter().any(|&(lo, hi)| lo <= point && point < hi))
    }
}

/// The single-read cover of `v`: its live range from its def to exactly one read `read_op`
/// (Ghidra's `eliminateIntersect` builds `single` from one descend — cover.cc, merge.cc:502).
/// A copy of [`cover_of`]'s liveness restricted to the one use, used by the addrtied snip
/// ([`super::mergesnip`]) to test whether that read crosses another same-address def.
pub fn cover_to_read(f: &Funcdata, v: VarnodeId, read_op: OpId, pos: &OpPositions) -> Cover {
    let mut cov = Cover::default();
    let vn = f.vn(v);
    let (def_block, def_wpos) = if vn.is_written() {
        let (db, di) = op_index(f, vn.def.unwrap(), pos).expect("def op is positioned");
        (Some(db), 2 * di as i32 + 2)
    } else if vn.is_input() {
        (Some(0usize), 0)
    } else {
        return cov;
    };

    let mut liveout: Vec<usize> = Vec::new();
    let Some((ub, ui)) = op_index(f, read_op, pos) else { return cov };
    if f.op(read_op).code() == OpCode::Multiequal {
        for (slot, &iv) in f.op(read_op).inrefs.iter().enumerate() {
            if iv == v {
                if let Some(p) = f.block(super::block::BlockId(ub as u32)).in_edges.get(slot) {
                    liveout.push(p.0 as usize);
                }
            }
        }
    } else {
        let rpos = 2 * ui as i32 + 1;
        if def_block == Some(ub) && def_wpos <= rpos {
            cov.extend(ub, def_wpos, rpos);
        } else {
            cov.extend(ub, 0, rpos);
            for p in &f.block(super::block::BlockId(ub as u32)).in_edges {
                liveout.push(p.0 as usize);
            }
        }
    }

    let mut seen: FxHashSet<usize> = FxHashSet::default();
    while let Some(b) = liveout.pop() {
        if !seen.insert(b) {
            continue;
        }
        let end = 2 * f.blocks()[b].ops.len() as i32 + 2;
        let lo = if def_block == Some(b) { def_wpos } else { 0 };
        cov.extend(b, lo, end);
        if def_block != Some(b) {
            for p in &f.blocks()[b].in_edges {
                if !seen.contains(&(p.0 as usize)) {
                    liveout.push(p.0 as usize);
                }
            }
        }
    }
    cov
}

/// `(block index, op index within the block)` for every op, dense-indexed by [`OpId`] (op ids are
/// arena indices, so a flat vector replaces the former `HashMap` — the map's hashing was a
/// measurable share of the WAR2 profile). Ops not in any block report `None` from [`get`].
///
/// [`get`]: OpPositions::get
pub struct OpPositions {
    pos: Vec<(u32, u32)>,
}

/// Sentinel for an op that sits in no block's op list.
const UNPOSITIONED: (u32, u32) = (u32::MAX, u32::MAX);

impl OpPositions {
    #[inline]
    pub fn get(&self, op: OpId) -> Option<(usize, usize)> {
        match self.pos.get(op.0 as usize) {
            Some(&(b, i)) if b != u32::MAX => Some((b as usize, i as usize)),
            _ => None,
        }
    }
}

/// `(block index, op index within the block)` for every op.
pub fn op_positions(f: &Funcdata) -> OpPositions {
    let mut pos = vec![UNPOSITIONED; f.num_ops()];
    for b in 0..f.num_blocks() {
        for (i, &op) in f.blocks()[b].ops.iter().enumerate() {
            pos[op.0 as usize] = (b as u32, i as u32);
        }
    }
    OpPositions { pos }
}

/// The `(block, op-index)` used for `op`'s cover half-points, mapping an INDIRECT to its guarded
/// (causing) op — Ghidra `CoverBlock::getUIndex` (`cover.cc`) treats an INDIRECT as living at the op
/// it is indirect for (via its `iop` annotation), so all the INDIRECTs around one call collapse to
/// that call's position and don't spuriously intersect the values flowing across it. Falls back to
/// the INDIRECT's own position if it has no recorded [`guarded_op`](super::op::PcodeOp::guarded_op)
/// or that op is no longer positioned (removed).
pub fn op_index(f: &Funcdata, op: OpId, pos: &OpPositions) -> Option<(usize, usize)> {
    if f.op(op).code() == OpCode::Indirect {
        if let Some(g) = f.op(op).guarded_op() {
            if let Some(p) = pos.get(g) {
                return Some(p);
            }
        }
    }
    pos.get(op)
}

/// Compute the [`Cover`] of one varnode via backward liveness from its uses to its def.
pub fn cover_of(f: &Funcdata, v: VarnodeId, pos: &OpPositions) -> Cover {
    let mut cov = Cover::default();
    let vn = f.vn(v);
    // where the value comes alive: def op (write at 2i+2), or function entry (block 0, pos 0)
    let (def_block, def_wpos) = if vn.is_written() {
        let (db, di) = op_index(f, vn.def.unwrap(), pos).expect("def op is positioned");
        (Some(db), 2 * di as i32 + 2)
    } else if vn.is_input() {
        (Some(0usize), 0)
    } else {
        return cov; // free / constant — no storage life
    };

    let descend: Vec<OpId> = {
        let mut d = vn.descend.clone();
        d.sort_unstable();
        d.dedup();
        d
    };
    let mut liveout: Vec<usize> = Vec::new();
    for u in descend {
        let Some((ub, ui)) = op_index(f, u, pos) else { continue };
        if f.op(u).code() == OpCode::Multiequal {
            // a phi input is live at the *exit* of the matching predecessor edge
            for (slot, &iv) in f.op(u).inrefs.iter().enumerate() {
                if iv == v {
                    if let Some(p) = f.block(super::block::BlockId(ub as u32)).in_edges.get(slot) {
                        liveout.push(p.0 as usize);
                    }
                }
            }
        } else {
            let rpos = 2 * ui as i32 + 1;
            if def_block == Some(ub) && def_wpos <= rpos {
                cov.extend(ub, def_wpos, rpos); // def then use, same block
            } else {
                cov.extend(ub, 0, rpos); // live from entry to use
                for p in &f.block(super::block::BlockId(ub as u32)).in_edges {
                    liveout.push(p.0 as usize);
                }
            }
        }
    }

    // propagate "live at block exit" backward to the def
    let mut seen: FxHashSet<usize> = FxHashSet::default();
    while let Some(b) = liveout.pop() {
        if !seen.insert(b) {
            continue;
        }
        let end = 2 * f.blocks()[b].ops.len() as i32 + 2;
        let lo = if def_block == Some(b) { def_wpos } else { 0 };
        cov.extend(b, lo, end);
        if def_block != Some(b) {
            for p in &f.blocks()[b].in_edges {
                if !seen.contains(&(p.0 as usize)) {
                    liveout.push(p.0 as usize);
                }
            }
        }
    }
    cov
}

/// The Cover a value defined at `def_vn`'s def point would have if it replaced `read_vn` at every
/// one of `read_vn`'s read sites — Ghidra's dominant-COPY replacement test cover
/// (`Merge::buildDominantCopy`, merge.cc:1201-1207: `aCover.addDefPoint(domVn)` +
/// `aCover.addRefPoint(op, outVn)` per descendant of the COPY being replaced). Phi reads follow
/// `read_vn`'s slots (live at the matching predecessor's exit).
pub fn cover_replacing(
    f: &Funcdata,
    def_vn: VarnodeId,
    read_vn: VarnodeId,
    pos: &OpPositions,
) -> Cover {
    let mut cov = Cover::default();
    let dv = f.vn(def_vn);
    let (def_block, def_wpos) = if dv.is_written() {
        let (db, di) = op_index(f, dv.def.unwrap(), pos).expect("def op is positioned");
        (Some(db), 2 * di as i32 + 2)
    } else if dv.is_input() {
        (Some(0usize), 0)
    } else {
        return cov;
    };

    let mut liveout: Vec<usize> = Vec::new();
    let descend: Vec<OpId> = {
        let mut d = f.vn(read_vn).descend.clone();
        d.sort_unstable();
        d.dedup();
        d
    };
    for u in descend {
        let Some((ub, ui)) = op_index(f, u, pos) else { continue };
        if f.op(u).code() == OpCode::Multiequal {
            for (slot, &iv) in f.op(u).inrefs.iter().enumerate() {
                if iv == read_vn {
                    if let Some(p) = f.block(super::block::BlockId(ub as u32)).in_edges.get(slot) {
                        liveout.push(p.0 as usize);
                    }
                }
            }
        } else {
            let rpos = 2 * ui as i32 + 1;
            if def_block == Some(ub) && def_wpos <= rpos {
                cov.extend(ub, def_wpos, rpos);
            } else {
                cov.extend(ub, 0, rpos);
                for p in &f.block(super::block::BlockId(ub as u32)).in_edges {
                    liveout.push(p.0 as usize);
                }
            }
        }
    }
    let mut seen: FxHashSet<usize> = FxHashSet::default();
    while let Some(b) = liveout.pop() {
        if !seen.insert(b) {
            continue;
        }
        let end = 2 * f.blocks()[b].ops.len() as i32 + 2;
        let lo = if def_block == Some(b) { def_wpos } else { 0 };
        cov.extend(b, lo, end);
        if def_block != Some(b) {
            for p in &f.blocks()[b].in_edges {
                if !seen.contains(&(p.0 as usize)) {
                    liveout.push(p.0 as usize);
                }
            }
        }
    }
    cov
}

/// The single-point Cover of a varnode's definition (Ghidra `Cover::addDefPoint`): the write
/// half-point of its def op (or the entry point for an input). Empty for a free/constant varnode.
/// Used where Ghidra tests a never-read write against other covers (`Merge::shadowedVarnode`) —
/// mosura's [`cover_of`] yields an empty cover for an unread value, but the def point still
/// occupies its program point.
pub fn def_point_cover(f: &Funcdata, v: VarnodeId, pos: &OpPositions) -> Cover {
    let mut cov = Cover::default();
    let vn = f.vn(v);
    if vn.is_written() {
        if let Some((db, di)) = op_index(f, vn.def.unwrap(), pos) {
            let p = 2 * di as i32 + 2;
            cov.extend(db, p, p);
        }
    } else if vn.is_input() {
        cov.extend(0, 0, 0);
    }
    cov
}

/// Covers for every non-constant varnode that has storage life.
/// Ghidra `Cover::rebuild` (cover.cc:477): the cover of `v` EXTENDED through implied consumers.
/// When a reading op's output is implied, the expression built over `v` prints at that output's
/// own use sites, so the ref-point walk continues through it (cover.cc:487-494) and `v` is live
/// all the way to wherever the printed expression lands. `is_implied` is the classification state
/// at query time — Ghidra decides descendants first (`ActionMarkImplied::apply`,
/// coreaction.cc:3432) and rebuilds covers lazily under a dirty bit, which this reproduces by
/// passing the decision state in. Direct reads come from [`cover_of`]; each deeper ref point is
/// `v`'s single-read cover to that op ([`cover_to_read`] = Ghidra's `addRefPoint(op, vn)`).
pub fn extended_cover(
    f: &Funcdata,
    v: VarnodeId,
    pos: &OpPositions,
    is_implied: &dyn Fn(VarnodeId) -> bool,
) -> Cover {
    let mut cov = cover_of(f, v, pos);
    let mut path: Vec<VarnodeId> = vec![v];
    let mut seen: FxHashSet<VarnodeId> = FxHashSet::default();
    seen.insert(v);
    let mut i = 0;
    while i < path.len() {
        let cur = path[i];
        i += 1;
        for &op in &f.vn(cur).descend {
            if f.op(op).is_dead() {
                continue;
            }
            if cur != v {
                cov.merge_from(&cover_to_read(f, v, op, pos));
            }
            if let Some(out) = f.op(op).output {
                if is_implied(out) && seen.insert(out) {
                    path.push(out);
                }
            }
        }
    }
    cov
}

/// Every varnode's cover as Ghidra's `Cover::rebuild` (cover.cc:477) leaves it once the
/// explicit/implied classification is known: extended through every consumer whose output is
/// IMPLIED, because an implied expression is evaluated where its consumer is, not where it was
/// defined. This is the cover the merge tests (`Merge::intersection` → `HighVariable::getCover`)
/// compare; the plain [`all_covers`] is the pre-classification view. `explicit[i]` is the
/// decision for varnode `i`.
pub fn all_covers_extended(f: &Funcdata, explicit: &[bool]) -> HashMap<VarnodeId, Cover> {
    let pos = op_positions(f);
    let is_implied = |x: VarnodeId| !explicit.get(x.0 as usize).copied().unwrap_or(true);
    let mut out = HashMap::new();
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        let c = extended_cover(f, v, &pos, &is_implied);
        if !c.is_empty() {
            out.insert(v, c);
        }
    }
    out
}

pub fn all_covers(f: &Funcdata) -> HashMap<VarnodeId, Cover> {
    let pos = op_positions(f);
    let mut out = HashMap::new();
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        let c = cover_of(f, v, &pos);
        if !c.is_empty() {
            out.insert(v, c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::{BlockBasic, Funcdata, SeqNum};

    /// Build a single block: `r1=#5; t1=r1+x; r2=#7; t2=r2+(x or r1)`. With the last op
    /// reading `r1`, the two same-storage values `r1`/`r2` overlap; otherwise they don't.
    fn build(last_reads_r1: bool) -> (Funcdata, VarnodeId, VarnodeId) {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let uniq = spaces.by_name("unique").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        // r1 and r2 share storage reg:0
        let c5 = f.new_const(8, 5);
        let o0 = f.new_op(OpCode::Copy, seq, vec![c5]);
        let r1 = f.new_output(o0, 8, Address::new(reg, 0));
        let c1 = f.new_const(8, 1);
        let o1 = f.new_op(OpCode::IntAdd, seq, vec![r1, c1]);
        let _t1 = f.new_output(o1, 8, Address::new(uniq, 0x10));
        let c7 = f.new_const(8, 7);
        let o2 = f.new_op(OpCode::Copy, seq, vec![c7]);
        let r2 = f.new_output(o2, 8, Address::new(reg, 0));
        let second = if last_reads_r1 { r1 } else { f.new_const(8, 1) };
        let o3 = f.new_op(OpCode::IntAdd, seq, vec![r2, second]);
        let _t2 = f.new_output(o3, 8, Address::new(uniq, 0x18));
        f.set_blocks(vec![BlockBasic { ops: vec![o0, o1, o2, o3], ..Default::default() }]);
        (f, r1, r2)
    }

    #[test]
    fn disjoint_lives_do_not_intersect() {
        let (f, r1, r2) = build(false); // r1 dies at op1, before r2 is born at op2
        let pos = op_positions(&f);
        assert!(!cover_of(&f, r1, &pos).intersects(&cover_of(&f, r2, &pos)));
    }

    #[test]
    fn overlapping_lives_intersect() {
        let (f, r1, r2) = build(true); // r1 still read at op3, after r2's def at op2
        let pos = op_positions(&f);
        assert!(cover_of(&f, r1, &pos).intersects(&cover_of(&f, r2, &pos)));
    }

    /// `op_index` maps an INDIRECT to its guarded (causing) op's position; a non-INDIRECT and an
    /// INDIRECT with no recorded guarded op fall back to their own position.
    #[test]
    fn op_index_maps_indirect_to_guarded_op() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        // op0: a CALL; op1: an INDIRECT caused by it; op2: an unrelated COPY.
        let call = f.new_op(OpCode::Call, seq, vec![]);
        let zero = f.new_const(8, 0);
        let ind = f.new_op(OpCode::Indirect, seq, vec![zero]);
        f.op_mut(ind).guarded_op = Some(call);
        f.new_output(ind, 8, Address::new(reg, 0));
        let c = f.new_const(8, 1);
        let cpy = f.new_op(OpCode::Copy, seq, vec![c]);
        f.new_output(cpy, 8, Address::new(reg, 8));
        f.set_blocks(vec![BlockBasic { ops: vec![call, ind, cpy], ..Default::default() }]);

        let pos = op_positions(&f);
        // the INDIRECT reports the CALL's position (0), not its own (1)
        assert_eq!(op_index(&f, ind, &pos), Some((0, 0)));
        // an INDIRECT with no guarded op falls back to its own position
        f.op_mut(ind).guarded_op = None;
        assert_eq!(op_index(&f, ind, &pos), Some((0, 1)));
        // a non-INDIRECT uses its own position
        assert_eq!(op_index(&f, cpy, &pos), Some((0, 2)));
    }
}
