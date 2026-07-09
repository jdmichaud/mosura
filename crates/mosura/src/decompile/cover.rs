//! Liveness ranges — Ghidra's `Cover`/`CoverBlock` (`cover.cc`). A [`Cover`] records, per
//! basic block, the range of program points where a varnode is live (from its definition
//! to its last use along the control flow). Two varnodes can share storage (merge into one
//! variable) only if their covers do not intersect.
//!
//! Positions use a half-point scheme within a block of `n` ops: entry = 0; op `i` reads at
//! `2i+1` and writes at `2i+2`; exit = `2n+2`. So a value defined and a value used at the
//! *same* op don't intersect (the read at `2i+1` precedes the write at `2i+2`) — exactly
//! what makes `x = x + 1`'s two SSA versions mergeable.

use std::collections::{HashMap, HashSet};

use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::varnode::VarnodeId;

/// The live range of one varnode: a convex `[lo, hi]` position range per block it's live in.
#[derive(Default, Clone)]
pub struct Cover {
    blocks: HashMap<usize, (i32, i32)>,
}

impl Cover {
    fn extend(&mut self, block: usize, lo: i32, hi: i32) {
        let e = self.blocks.entry(block).or_insert((i32::MAX, i32::MIN));
        e.0 = e.0.min(lo);
        e.1 = e.1.max(hi);
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
}

/// The single-read cover of `v`: its live range from its def to exactly one read `read_op`
/// (Ghidra's `eliminateIntersect` builds `single` from one descend — cover.cc, merge.cc:502).
/// A copy of [`cover_of`]'s liveness restricted to the one use, used by the addrtied snip
/// ([`super::mergesnip`]) to test whether that read crosses another same-address def.
pub fn cover_to_read(f: &Funcdata, v: VarnodeId, read_op: OpId, pos: &HashMap<OpId, (usize, usize)>) -> Cover {
    let mut cov = Cover::default();
    let vn = f.vn(v);
    let (def_block, def_wpos) = if vn.is_written() {
        let (db, di) = pos[&vn.def.unwrap()];
        (Some(db), 2 * di as i32 + 2)
    } else if vn.is_input() {
        (Some(0usize), 0)
    } else {
        return cov;
    };

    let mut liveout: Vec<usize> = Vec::new();
    let Some(&(ub, ui)) = pos.get(&read_op) else { return cov };
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

    let mut seen: HashSet<usize> = HashSet::new();
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

/// `(block index, op index within the block)` for every op.
pub fn op_positions(f: &Funcdata) -> HashMap<OpId, (usize, usize)> {
    let mut pos = HashMap::new();
    for b in 0..f.num_blocks() {
        for (i, &op) in f.blocks()[b].ops.iter().enumerate() {
            pos.insert(op, (b, i));
        }
    }
    pos
}

/// The `(block, op-index)` used for `op`'s cover half-points, mapping an INDIRECT to its guarded
/// (causing) op — Ghidra `CoverBlock::getUIndex` (`cover.cc`) treats an INDIRECT as living at the op
/// it is indirect for (via its `iop` annotation), so all the INDIRECTs around one call collapse to
/// that call's position and don't spuriously intersect the values flowing across it. Falls back to
/// the INDIRECT's own position if it has no recorded [`guarded_op`](super::op::PcodeOp::guarded_op)
/// or that op is no longer positioned (removed).
pub fn op_index(f: &Funcdata, op: OpId, pos: &HashMap<OpId, (usize, usize)>) -> Option<(usize, usize)> {
    if f.op(op).code() == OpCode::Indirect {
        if let Some(g) = f.op(op).guarded_op() {
            if let Some(&p) = pos.get(&g) {
                return Some(p);
            }
        }
    }
    pos.get(&op).copied()
}

/// Compute the [`Cover`] of one varnode via backward liveness from its uses to its def.
pub fn cover_of(f: &Funcdata, v: VarnodeId, pos: &HashMap<OpId, (usize, usize)>) -> Cover {
    let mut cov = Cover::default();
    let vn = f.vn(v);
    // where the value comes alive: def op (write at 2i+2), or function entry (block 0, pos 0)
    let (def_block, def_wpos) = if vn.is_written() {
        let (db, di) = pos[&vn.def.unwrap()];
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
        let Some(&(ub, ui)) = pos.get(&u) else { continue };
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
    let mut seen: HashSet<usize> = HashSet::new();
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

/// Covers for every non-constant varnode that has storage life.
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
