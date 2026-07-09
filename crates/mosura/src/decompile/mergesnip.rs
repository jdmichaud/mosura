//! Ghidra's `ActionMergeRequired` / `Merge::mergeAddrTied` address-tied cover-intersection snip
//! (`merge.cc:609`/`581`/`489`/`443`, run by `coreaction.cc:5718`).
//!
//! A read of an address-tied location (a global, or a stack local whose address escapes) whose
//! live range crosses a *later* write to the same — or an overlapping — address must be snapshotted
//! into a temporary. Otherwise the printer re-reads the post-write memory value at the use site,
//! losing the sequence point: partialmerge's `a_simple = glob1.a; return a_simple + 10;` degrades to
//! `glob1 = param_1; return glob1.a + 10;` (the returned value observes the store, which is wrong).
//!
//! Ghidra forces all address-tied Varnodes at one storage address into a single HighVariable
//! (`mergeAddrTied`) and resolves the resulting Cover intersections by *snipping*: for each read
//! whose single-read Cover contains another same-address Varnode's def point, insert a COPY of the
//! read value at the value's def point and repoint that read to the COPY's `unique` output
//! (`eliminateIntersect` → `snipReads`). mosura's own `merge::merge` only *detects* the intersection
//! (and declines to merge) — it never snips; this pass adds the snip as a graph-mutating action.
//!
//! Placement: after `ActionInferTypes` + the cleanup pool (Ghidra's late "merge" phase runs after
//! `ActionInferTypes`/cleanup, before naming/casts/print), before the read-only merge in printc; a
//! `deadcode` sweep follows. This is a once-pass approximation of Ghidra's iterating merge phase
//! (tied to the mainloop-repeat backlog). The candidate set is gated on the real `addrtied` flag
//! (Ghidra `Merge::mergeAddrTied`, `merge.cc:631`), which [`super::varnodeprops::mark_addrtied`]
//! sets before the first pool (and again just before this pass, so pool-created ram/stack varnodes
//! are marked — a once-pass approximation of Ghidra's addrtied-at-creation; see the pipeline note).
//! So a ram global or an aliased stack slot is snipped, while a non-aliased stack SSA temp is not.
//! See [[task-sb-spacebase-placeholder]].

use std::collections::HashMap;

use super::cover::{cover_to_read, op_index, op_positions, Cover};
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::space::SpaceId;
use super::varnode::VarnodeId;

/// Ghidra `Varnode::characterizeOverlap` (`varnode.cc`): storage overlap between two varnodes —
/// `0` none, `1` partial, `2` identical (same offset and size).
fn characterize_overlap(f: &Funcdata, a: VarnodeId, b: VarnodeId) -> i32 {
    let (va, vb) = (f.vn(a), f.vn(b));
    if va.loc.space != vb.loc.space {
        return 0;
    }
    let (ao, bo) = (va.loc.offset, vb.loc.offset);
    if ao == bo {
        return if va.size == vb.size { 2 } else { 1 };
    }
    if ao < bo {
        let aright = ao + (va.size as u64 - 1);
        if aright < bo {
            0
        } else {
            1
        }
    } else {
        let bright = bo + (vb.size as u64 - 1);
        if bright < ao {
            0
        } else {
            1
        }
    }
}

/// Follow a COPY chain to its source (Ghidra's `while (isWritten && def==COPY) vn = def->getIn(0)`).
fn skip_copies(f: &Funcdata, mut vn: VarnodeId) -> VarnodeId {
    while f.vn(vn).is_written() && f.op(f.vn(vn).def.unwrap()).code() == OpCode::Copy {
        vn = f.op(f.vn(vn).def.unwrap()).input(0).unwrap();
    }
    vn
}

/// Ghidra `Varnode::findSubpieceShadow` (`varnode.cc`): is `vn` the SUBPIECE (at byte `least_byte`)
/// shadow of `whole` — i.e. the same value, so not a genuine new value at that storage.
fn find_subpiece_shadow(f: &Funcdata, vn: VarnodeId, least_byte: i32, whole: VarnodeId, recurse: i32) -> bool {
    let vn = skip_copies(f, vn);
    if !f.vn(vn).is_written() {
        if f.vn(vn).is_constant() {
            let whole = skip_copies(f, whole);
            if !f.vn(whole).is_constant() {
                return false;
            }
            let shift = (least_byte as u32).saturating_mul(8);
            let off = f.vn(whole).constant_value().checked_shr(shift).unwrap_or(0)
                & super::nzmask::calc_mask(f.vn(vn).size);
            return off == f.vn(vn).constant_value();
        }
        return false;
    }
    let def = f.vn(vn).def.unwrap();
    match f.op(def).code() {
        OpCode::Subpiece => {
            let tmpvn = f.op(def).input(0).unwrap();
            let off = f.vn(f.op(def).input(1).unwrap()).constant_value() as i32;
            if off != least_byte || f.vn(tmpvn).size != f.vn(whole).size {
                return false;
            }
            if tmpvn == whole {
                return true;
            }
            let mut tmpvn = tmpvn;
            while f.vn(tmpvn).is_written() && f.op(f.vn(tmpvn).def.unwrap()).code() == OpCode::Copy {
                tmpvn = f.op(f.vn(tmpvn).def.unwrap()).input(0).unwrap();
                if tmpvn == whole {
                    return true;
                }
            }
            false
        }
        OpCode::Multiequal => {
            let recurse = recurse + 1;
            if recurse > 1 {
                return false; // truncate recursion at maximum depth (Ghidra)
            }
            let whole = skip_copies(f, whole);
            if !f.vn(whole).is_written() {
                return false;
            }
            let big_op = f.vn(whole).def.unwrap();
            if f.op(big_op).code() != OpCode::Multiequal {
                return false;
            }
            if f.op(big_op).parent != f.op(def).parent {
                return false;
            }
            for i in 0..f.op(def).num_inputs() {
                let small_in = f.op(def).input(i).unwrap();
                let big_in = f.op(big_op).input(i).unwrap();
                if !find_subpiece_shadow(f, small_in, least_byte, big_in, recurse) {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}

/// Ghidra `Varnode::findPieceShadow` (`varnode.cc`): is `vn` a PIECE tree whose byte-`least_byte`
/// component is `piece` (a copy shadow) — again the same value, not a genuine new one.
fn find_piece_shadow(f: &Funcdata, vn: VarnodeId, least_byte: i32, piece: VarnodeId) -> bool {
    let vn = skip_copies(f, vn);
    if !f.vn(vn).is_written() {
        return false;
    }
    let def = f.vn(vn).def.unwrap();
    if f.op(def).code() != OpCode::Piece {
        return false;
    }
    let mut tmpvn = f.op(def).input(1).unwrap(); // least significant part
    let mut least_byte = least_byte;
    if least_byte >= f.vn(tmpvn).size as i32 {
        least_byte -= f.vn(tmpvn).size as i32;
        tmpvn = f.op(def).input(0).unwrap();
    } else if f.vn(piece).size as i32 + least_byte > f.vn(tmpvn).size as i32 {
        return false;
    }
    if least_byte == 0 && f.vn(tmpvn).size == f.vn(piece).size {
        if tmpvn == piece {
            return true;
        }
        let mut tmpvn = tmpvn;
        while f.vn(tmpvn).is_written() && f.op(f.vn(tmpvn).def.unwrap()).code() == OpCode::Copy {
            tmpvn = f.op(f.vn(tmpvn).def.unwrap()).input(0).unwrap();
            if tmpvn == piece {
                return true;
            }
        }
        return false;
    }
    find_piece_shadow(f, tmpvn, least_byte, piece)
}

/// Ghidra `Varnode::partialCopyShadow` (`varnode.cc`): for a partial overlap, whether the smaller
/// varnode is literally a piece/subpiece of the larger (same value) — so their covers touching is
/// not a real intersection. x86-64 is little-endian, so `least_byte == relOff`.
fn partial_copy_shadow(f: &Funcdata, a: VarnodeId, b: VarnodeId, rel_off: i32) -> bool {
    // `vn` becomes the smaller of the two (Ghidra swaps and negates relOff when `this` is bigger).
    let (vn, op2, rel_off) = if f.vn(a).size < f.vn(b).size {
        (a, b, rel_off)
    } else if f.vn(a).size > f.vn(b).size {
        (b, a, -rel_off)
    } else {
        return false;
    };
    if rel_off < 0 {
        return false; // not proper containment
    }
    if rel_off + f.vn(vn).size as i32 > f.vn(op2).size as i32 {
        return false; // not proper containment
    }
    let least_byte = rel_off; // little-endian
    if find_subpiece_shadow(f, vn, least_byte, op2, 0) {
        return true;
    }
    find_piece_shadow(f, op2, least_byte, vn)
}

/// The `(block, position)` of `vn2`'s def in the cover half-point scheme (`super::cover`): a written
/// varnode's def is its op's write position `2i+2`; a MULTIEQUAL is at the block beginning (`0`,
/// Ghidra's `getUIndex` treats it as "very beginning"); an input/free varnode is `(0, 0)`. An
/// INDIRECT def is positioned at its guarded (causing) op via [`op_index`] — Ghidra `getUIndex`
/// treats an INDIRECT as living at the op it is indirect for, so an INDIRECT-created value's def
/// sits just after the call (`2i+2`) rather than at the INDIRECT's own later slot.
fn def_point(f: &Funcdata, vn2: VarnodeId, pos: &HashMap<OpId, (usize, usize)>) -> (usize, i32) {
    if let Some(def) = f.vn(vn2).def {
        let (b, i) = op_index(f, def, pos).expect("def op is positioned");
        match f.op(def).code() {
            OpCode::Multiequal => (b, 0),
            _ => (b, 2 * i as i32 + 2),
        }
    } else {
        (0, 0)
    }
}

/// Ghidra `Cover::containVarnodeDef` (`cover.cc`): does the single-read cover contain `vn2`'s def
/// point? Returns `0` (not contained), `1` (interior), `2` (at the cover start boundary), `3` (at
/// the cover stop boundary). A cover starting at position 0 is the "live from block beginning"
/// case (Ghidra's `start == (PcodeOp*)0`), which is never a start boundary.
fn contain_varnode_def(f: &Funcdata, single: &Cover, vn2: VarnodeId, pos: &HashMap<OpId, (usize, usize)>) -> i32 {
    let (blk, point) = def_point(f, vn2, pos);
    let Some((lo, hi)) = single.block_range(blk) else {
        return 0;
    };
    if point < lo || point > hi {
        return 0;
    }
    if point == lo && lo != 0 {
        return 2; // boundary at a real def-start op
    }
    if point == hi {
        return 3; // boundary at the cover stop (the read)
    }
    1 // interior
}

/// Ghidra `Merge::eliminateIntersect` (`merge.cc:489`): find the reads of `vn` whose single-read
/// Cover crosses another same-address varnode's def (a genuine intersection), returning those read
/// ops to be snipped.
fn eliminate_intersect(
    f: &Funcdata,
    vn: VarnodeId,
    group: &[VarnodeId],
    pos: &HashMap<OpId, (usize, usize)>,
) -> Vec<OpId> {
    let mut marked = Vec::new();
    let descend = f.vn(vn).descend.clone();
    for op in descend {
        let single = cover_to_read(f, vn, op, pos);
        if single.is_empty() {
            continue;
        }
        let mut insertop = false;
        for &vn2 in group {
            if vn2 == vn || f.vn(vn2).is_free() {
                continue;
            }
            let boundtype = contain_varnode_def(f, &single, vn2, pos);
            if boundtype == 0 {
                continue;
            }
            let overlaptype = characterize_overlap(f, vn, vn2);
            if overlaptype == 0 {
                continue; // no overlap in storage
            }
            if overlaptype == 1 {
                let off = f.vn(vn).loc.offset as i64 - f.vn(vn2).loc.offset as i64;
                if partial_copy_shadow(f, vn, vn2, off as i32) {
                    continue; // SUBPIECE/PIECE shadow, not a new value
                }
            }
            if boundtype == 2 {
                // Defined at the same place: keep an arbitrary/earlier-def ordering so only one
                // side of the pair is snipped (Ghidra merge.cc:528-541).
                match (f.vn(vn2).def, f.vn(vn).def) {
                    (None, None) => {
                        if vn.0 < vn2.0 {
                            continue;
                        }
                    }
                    (None, Some(_)) => continue,
                    (Some(d2), Some(d1)) => {
                        if pos[&d2] < pos[&d1] {
                            continue;
                        }
                    }
                    (Some(_), None) => {}
                }
            } else if boundtype == 3 {
                // Tail intersection: only real for an addrforce INDIRECT linked to the read op
                // (merge.cc:543-561). mosura's 1-input INDIRECT lacks that link, so conservatively
                // skip — never over-snips a tail case.
                continue;
            }
            insertop = true;
            break;
        }
        if insertop {
            marked.push(op);
        }
    }
    marked
}

/// Ghidra `Merge::snipReads` + `allocateCopyTrim` (`merge.cc:443`/`656`-style): snapshot `vn` into a
/// fresh `unique` via a COPY at `vn`'s def point (block-0 begin for an input, just after the def
/// otherwise) and repoint every `marked` read to the COPY output.
fn snip_reads(f: &mut Funcdata, vn: VarnodeId, marked: &[OpId]) {
    if marked.is_empty() {
        return;
    }
    let size = f.vn(vn).size;
    let copyop = if f.vn(vn).is_input() {
        let pc = f.blocks()[0].ops.first().map(|&o| f.op(o).seqnum.pc).unwrap_or(f.addr);
        let uniq = f.num_ops() as u32;
        let op = f.new_op(OpCode::Copy, super::op::SeqNum { pc, uniq }, vec![vn]);
        f.new_output_unique(op, size);
        f.op_insert_begin(op, super::block::BlockId(0));
        op
    } else {
        let def = f.vn(vn).def.unwrap();
        let pc = f.op(def).seqnum.pc;
        let uniq = f.num_ops() as u32;
        let op = f.new_op(OpCode::Copy, super::op::SeqNum { pc, uniq }, vec![vn]);
        f.new_output_unique(op, size);
        f.op_insert_after(op, def);
        op
    };
    let cout = f.op(copyop).output.unwrap();
    for &op in marked {
        for slot in 0..f.op(op).num_inputs() {
            if f.op(op).input(slot) == Some(vn) {
                f.op_set_input(op, slot, cout);
            }
        }
    }
}

/// Ghidra `Merge::mergeAddrTied` + `unifyAddress` (`merge.cc:609`/`581`): for each memory-space
/// (ram/stack = processor/spacebase; the addrtied set) address group, snip every read whose cover
/// crosses another same-address def. The read-only HighVariable merge (`merge::merge`) then unifies
/// the now-non-intersecting values.
pub fn merge_required(f: &mut Funcdata) {
    if f.num_blocks() == 0 {
        return;
    }
    // Candidate groups: the address-tied non-free varnodes, grouped by space (Ghidra
    // `Merge::mergeAddrTied` gates the snip on `flags & addrtied`, merge.cc:631). The real ADDRTIED
    // flag (set by `ActionMarkAddrTied`) is what excludes the non-aliased stack SSA temps a space
    // proxy would wrongly include. `characterize_overlap` filters non-overlapping pairs inside
    // `eliminate_intersect`, so a per-space group is equivalent to Ghidra's maximal-overlap ranges.
    let mut by_space: HashMap<SpaceId, Vec<VarnodeId>> = HashMap::new();
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        let vn = f.vn(v);
        if vn.is_free() || !vn.is_addrtied() {
            continue;
        }
        by_space.entry(vn.loc.space).or_default().push(v);
    }
    let mut spaces: Vec<SpaceId> = by_space.keys().copied().collect();
    spaces.sort_by_key(|s| s.0);
    for sp in spaces {
        let group = &by_space[&sp];
        if group.len() < 2 {
            continue;
        }
        let group = group.clone();
        for &vn in &group {
            if f.vn(vn).is_free() {
                continue;
            }
            let pos = op_positions(f); // recompute: snipReads mutates the block op lists
            let marked = eliminate_intersect(f, vn, &group, &pos);
            snip_reads(f, vn, &marked);
        }
    }
}

/// Graph-mutating pipeline action wrapping [`merge_required`] — the mosura analogue of Ghidra's
/// `ActionMergeRequired` (`coreaction.cc:5718`).
pub struct ActionMergeRequired;

impl super::action::Action for ActionMergeRequired {
    fn name(&self) -> &str {
        "mergerequired"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        let before = data.num_ops();
        merge_required(data);
        (data.num_ops() - before) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::block::BlockBasic;
    use super::super::op::SeqNum;
    use super::super::space::{Address, SpaceManager};

    fn seq(off: u64) -> SeqNum {
        SeqNum { pc: Address { space: SpaceId(0), offset: off }, uniq: 0 }
    }

    /// The partialmerge shape: an input-version read of a global (ram) location whose live range
    /// crosses a same-address store must be snipped into a COPY-to-`unique`, so the read no longer
    /// reads the address directly. `t = COPY glob; glob = x; use(t)` — the use must read `t`.
    #[test]
    fn snips_addrtied_read_crossing_a_same_address_store() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let uniq = spaces.by_name("unique").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0x1000), spaces);

        // glob (ram:0x2000:4) read as an input; then a store overwrites it; then it is used.
        let g_read = f.new_input(4, Address::new(ram, 0x2000));
        // store: glob = param  (writes ram:0x2000:4, a NEW version)
        let param = f.new_input(4, Address::new(reg, 0x38));
        let store = f.new_op(OpCode::Copy, seq(0x1004), vec![param]);
        let _gstore = f.new_output(store, 4, Address::new(ram, 0x2000));
        // use: t = g_read + 1  (reads the pre-store value)
        let one = f.new_const(4, 1);
        let add = f.new_op(OpCode::IntAdd, seq(0x1008), vec![g_read, one]);
        let _t = f.new_output(add, 4, Address::new(uniq, 0x10));

        f.set_blocks(vec![BlockBasic { ops: vec![store, add], ..Default::default() }]);

        // The snip is gated on the real ADDRTIED flag, which the pipeline sets before this pass.
        super::super::varnodeprops::mark_addrtied(&mut f);
        merge_required(&mut f);

        // The ADD must now read a unique COPY of the pre-store value, not the ram varnode directly.
        let add_in0 = f.op(add).input(0).unwrap();
        assert_ne!(add_in0, g_read, "read was not snipped");
        let cin = f.vn(add_in0);
        assert_eq!(cin.loc.space, uniq, "snip target must be a unique");
        let cdef = cin.def.expect("snip output must be COPY-defined");
        assert_eq!(f.op(cdef).code(), OpCode::Copy);
        assert_eq!(f.op(cdef).input(0), Some(g_read), "COPY must snapshot the pre-store read");
    }

    /// No store crossing the read ⇒ no intersection ⇒ no snip (the read is left untouched).
    #[test]
    fn no_snip_when_read_does_not_cross_a_store() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let uniq = spaces.by_name("unique").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0x1000), spaces);

        let g_read = f.new_input(4, Address::new(ram, 0x2000));
        let one = f.new_const(4, 1);
        let add = f.new_op(OpCode::IntAdd, seq(0x1008), vec![g_read, one]);
        let _t = f.new_output(add, 4, Address::new(uniq, 0x10));
        f.set_blocks(vec![BlockBasic { ops: vec![add], ..Default::default() }]);

        super::super::varnodeprops::mark_addrtied(&mut f);
        merge_required(&mut f);

        assert_eq!(f.op(add).input(0), Some(g_read), "unrelated read must not be snipped");
    }
}
