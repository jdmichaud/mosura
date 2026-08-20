//! Heritage — building SSA form over the Varnode graph (Ghidra's `Heritage`, `heritage.cc`).
//!
//! Links every free read to its reaching definition and inserts MULTIEQUAL (phi) ops at
//! control-flow joins, via Cytron's algorithm using the dominance frontiers. Phi placement
//! is semi-pruned: only *global* locations (read in some block before being written there)
//! get phis, which keeps block-local temporaries (the `unique` space) phi-free, as Ghidra's
//! result is.
//!
//! SSA identity is the heritaged RANGE, not the individual access width. Each pass builds a
//! disjoint [`TaskList`] of MERGED ranges ([`LocationMap::add`] unions overlapping footprints, so an
//! `AL` write and an `EAX` read are ONE range), and [`place_multiequals`] runs `guard()` per range
//! to normalize every narrower access to the range's exact `(base, size)` — reads become SUBPIECEs
//! of a whole-range read, narrow writes are widened and PIECEd back. Only after that invariant holds
//! do phi placement and renaming run, which is why keying them on `(space, offset, size)` names the
//! same thing Ghidra's address-keyed rename stacks do (`heritage.cc:2498`).

use std::collections::{BTreeMap, HashMap, HashSet};

use super::dominator::Dominators;
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::space::{Address, SpaceId};
use super::varnode::VarnodeId;

/// An SSA location key: `(space, offset, size)`.
type Loc = (SpaceId, u64, u32);

/// Ghidra `LocationMap` (`heritage.hh:38`): a fine-grained record of which `(addr, size)` ranges
/// have been brought into SSA form and in which heritage pass. This is Ghidra's `globaldisjoint`;
/// it replaces a per-*space* "done" flag so an individual location can be (re-)heritaged in a later
/// pass while the rest of its space is left intact. Keyed per space; within a space the recorded
/// ranges are kept disjoint — an [`add`](LocationMap::add) overlapping existing ranges unions them.
#[derive(Clone, Debug, Default)]
pub struct LocationMap {
    /// Per-space map from a range's start offset to its [`SizePass`].
    themap: HashMap<SpaceId, BTreeMap<u64, SizePass>>,
}

/// Ghidra `LocationMap::SizePass` (`heritage.hh:41`): the extent and heritage-pass of a range.
#[derive(Clone, Copy, Debug)]
struct SizePass {
    size: u32,
    pass: i32,
}

impl LocationMap {
    /// Ghidra `LocationMap::add` (`heritage.cc:33`): mark `[off, off+size)` in `space` as heritaged
    /// at `pass`, unioning it with any overlapping ranges already present.
    ///
    /// Returns `(base, size, intersect)` — the MERGED range the location now lives in, plus the
    /// *intersect* code describing the overlap with PRE-EXISTING (earlier-pass) ranges:
    ///   - `0` — the range is new, or only meets ranges from the same pass;
    ///   - `1` — it partially overlaps a range from an earlier pass;
    ///   - `2` — it is wholly contained in a range from an earlier pass (already heritaged).
    ///
    /// The merged extent is what Ghidra's caller actually consumes: `heritage()` feeds
    /// `(*liter).first, (*liter).second.size` — the map element's own base and size, NOT the
    /// varnode's — into the `disjoint` task list (`heritage.cc:2708-2722`). That merge is the
    /// mechanism by which an `AL` write and an `EAX` read become ONE heritaged range; C++ passes it
    /// back as the map iterator, which in Rust is the `(base, size)` pair.
    ///
    /// `Address::overlap(0, base, sz)` (`address.cc:153`) is `this - base` when `base <= this <
    /// base+sz` (same space) else `-1`; the predecessor walk and forward merge mirror the C++
    /// iterator dance against the per-space `BTreeMap` (a left-overlapping new range that starts
    /// *before* an existing one is, faithfully, NOT merged — Ghidra's `++iter` skips it).
    pub fn add(&mut self, space: SpaceId, off: u64, size: u32, pass: i32) -> (u64, u32, i32) {
        use std::ops::Bound::{Excluded, Unbounded};
        let map = self.themap.entry(space).or_default();
        let mut addr = off;
        let mut size = size as u64;
        let mut pass = pass;
        let mut intersect = 0i32;
        // First range strictly after key `k` (avoids `k+1` overflowing at the top of the space).
        let after = |map: &BTreeMap<u64, SizePass>, k: u64| {
            map.range((Excluded(k), Unbounded)).next().map(|(kk, _)| *kk)
        };

        // Predecessor candidate: greatest range start strictly less than `addr` (C++
        // `lower_bound(addr)` then `--`); if there is none, the first range at/after `addr`.
        let mut start = match map.range(..addr).next_back().map(|(k, _)| *k) {
            Some(p) => Some(p),
            None => map.range(addr..).next().map(|(k, _)| *k),
        };
        // If that candidate does not actually contain `addr`, step forward (C++ `++iter`).
        // Containment uses wrapping subtraction, mirroring `Address::overlap`'s `wrapOffset`
        // (`address.cc:153`) so negative spacebase offsets (stored as large unsigned) work.
        if let Some(k) = start {
            if addr.wrapping_sub(k) >= map[&k].size as u64 {
                start = after(map, k);
            }
        }
        // `addr` falls inside the candidate range: wholly contained ⇒ done; else absorb it and
        // extend `[addr, addr+size)` back to its start, then keep merging forward.
        if let Some(k) = start {
            let ks = map[&k].size as u64;
            let off_in = addr.wrapping_sub(k);
            if off_in < ks {
                if off_in + size <= ks {
                    // Completely contained in a previous element: the merged range IS that element
                    // (Ghidra returns `iter` unchanged, heritage.cc:45-47).
                    return (k, map[&k].size, if map[&k].pass < pass { 2 } else { 0 });
                }
                addr = k;
                size += off_in;
                if map[&k].pass < pass {
                    intersect = 1;
                    pass = map[&k].pass;
                }
                map.remove(&k);
                start = after(map, k);
            }
        }
        // Absorb every following range the (possibly extended) `[addr, addr+size)` overlaps.
        let mut cur = start;
        while let Some(k) = cur {
            let rel = k.wrapping_sub(addr);
            if rel < size {
                let ks = map[&k].size as u64;
                if rel + ks > size {
                    size = rel + ks;
                }
                if map[&k].pass < pass {
                    intersect = 1;
                    pass = map[&k].pass;
                }
                map.remove(&k);
                cur = after(map, k);
            } else {
                break;
            }
        }
        map.insert(addr, SizePass { size: size as u32, pass });
        (addr, size as u32, intersect)
    }

    /// Ghidra `LocationMap::findPass` (`heritage.cc:90`): the pass when the range covering `off` in
    /// `space` was heritaged, or `-1` if `off` is not yet heritaged.
    pub fn find_pass(&self, space: SpaceId, off: u64) -> i32 {
        let Some(map) = self.themap.get(&space) else { return -1 };
        match map.range(..=off).next_back() {
            Some((&k, sp)) if off.wrapping_sub(k) < sp.size as u64 => sp.pass,
            _ => -1,
        }
    }

    /// The merged range `(base, size)` covering `off` in `space`, or `None` if `off` is not covered.
    /// Ghidra's `disjoint` task-list entry for a heritaged location — `(*liter).first,
    /// (*liter).second.size` (`heritage.cc:2708`) — the cumulative union of every overlapping
    /// access footprint. (Formerly consumed by the retired `refine_ranges` re-entry stand-in;
    /// the general [`refinement`] now partitions directly off the task list.)
    pub fn merged_range(&self, space: SpaceId, off: u64) -> Option<(u64, u32)> {
        let map = self.themap.get(&space)?;
        match map.range(..=off).next_back() {
            Some((&k, sp)) if off.wrapping_sub(k) < sp.size as u64 => Some((k, sp.size)),
            _ => None,
        }
    }

    /// Ghidra `LocationMap::clear`: reset to empty.
    pub fn clear(&mut self) {
        self.themap.clear();
    }

    /// Ghidra's `globaldisjoint.find(addr)` + `erase(iter)` pair in `Heritage::refinement`
    /// (heritage.cc:1929-1931): remove the range starting EXACTLY at `off`, returning the pass it
    /// was heritaged on so the refined pieces can be re-added at the same pass.
    pub fn erase(&mut self, space: SpaceId, off: u64) -> Option<i32> {
        self.themap.get_mut(&space)?.remove(&off).map(|sp| sp.pass)
    }
}

/// Ghidra `MemRange` (`heritage.hh:60`): one address range queued for SSA conversion, carrying
/// whether it covers addresses NEW this pass, addresses seen in a PREVIOUS pass, or both. The
/// `new_addresses` bit is what gates `guard()`'s INDIRECT placement (`heritage.cc:2629`) — re-adding
/// guards for an already-guarded address "confuses the renaming algorithm" (`heritage.cc:1186`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemRange {
    /// Starting address of the range.
    pub space: SpaceId,
    /// Offset of the range start within `space`.
    pub off: u64,
    /// Number of bytes in the range.
    pub size: u32,
    /// Property flags — [`MemRange::NEW_ADDRESSES`] / [`MemRange::OLD_ADDRESSES`].
    pub flags: u32,
}

impl MemRange {
    /// `MemRange::new_addresses` — the range covers addresses not seen in previous passes.
    pub const NEW_ADDRESSES: u32 = 1;
    /// `MemRange::old_addresses` — the range covers addresses seen in previous passes.
    pub const OLD_ADDRESSES: u32 = 2;

    /// Ghidra `MemRange::newAddresses`.
    pub fn new_addresses(&self) -> bool {
        self.flags & Self::NEW_ADDRESSES != 0
    }

    /// Ghidra `MemRange::oldAddresses`.
    pub fn old_addresses(&self) -> bool {
        self.flags & Self::OLD_ADDRESSES != 0
    }

    /// Ghidra `MemRange::clearProperty`.
    pub fn clear_property(&mut self, val: u32) {
        self.flags &= !val;
    }

    /// This range as an SSA location key. After `guard()` has normalized the range, EVERY active
    /// free access in it is exactly this `(space, base, size)` — the invariant that lets the
    /// per-location phi/rename machinery reconstruct Ghidra's whole-range SSA.
    fn loc(&self) -> Loc {
        (self.space, self.off, self.size)
    }
}

/// Ghidra `TaskList` (`heritage.hh:78`, `heritage.cc:108-136`): the disjoint list of address ranges
/// to convert to SSA form this pass — Ghidra's `disjoint`. Ranges are fed in ADDRESS ORDER and may
/// overlap; [`add`](TaskList::add) takes the union with the last element, so the list stays disjoint
/// and sorted.
#[derive(Clone, Debug, Default)]
pub struct TaskList {
    tasklist: Vec<MemRange>,
}

impl TaskList {
    /// Ghidra `TaskList::add` (`heritage.cc:108`). Addresses must already be sorted: if the given
    /// range intersects the LAST range in the list that range is extended to cover it (and the new
    /// flags are ORed in), otherwise the range is appended. Note `Address::overlap` is `-1` for an
    /// exactly-adjacent range, so abutting ranges are faithfully NOT merged.
    pub fn add(&mut self, space: SpaceId, off: u64, size: u32, fl: u32) {
        if let Some(entry) = self.tasklist.last_mut() {
            if entry.space == space {
                let over = off.wrapping_sub(entry.off);
                if over < entry.size as u64 {
                    let relsize = size as u64 + over;
                    if relsize > entry.size as u64 {
                        entry.size = relsize as u32;
                    }
                    entry.flags |= fl;
                    return;
                }
            }
        }
        self.tasklist.push(MemRange { space, off, size, flags: fl });
    }

    /// Ghidra `TaskList::insert` (`heritage.cc:132`): splice an already-disjoint range in at `pos`.
    /// Used by `refinement` to replace a range with its partition pieces.
    pub fn insert(&mut self, pos: usize, space: SpaceId, off: u64, size: u32, fl: u32) {
        self.tasklist.insert(pos, MemRange { space, off, size, flags: fl });
    }

    /// The ranges, in address order.
    pub fn ranges(&self) -> &[MemRange] {
        &self.tasklist
    }

    /// Ghidra `disjoint.erase(memiter)` in `Heritage::refinement` (heritage.cc:1928): remove the
    /// range at `pos` (about to be replaced by its partition pieces).
    pub fn remove(&mut self, pos: usize) -> MemRange {
        self.tasklist.remove(pos)
    }

    /// Number of ranges.
    pub fn len(&self) -> usize {
        self.tasklist.len()
    }

    /// Ghidra `TaskList::clear`.
    pub fn clear(&mut self) {
        self.tasklist.clear();
    }

    /// Whether the list holds no ranges.
    pub fn is_empty(&self) -> bool {
        self.tasklist.is_empty()
    }
}




/// Per-space heritage bookkeeping (Ghidra's `HeritageInfo`, `heritage.cc:179`). Heritage is
/// an *iterating* process in Ghidra: `heritage()` is called once per pass, and a space only
/// enters SSA construction once `pass >= delay` (`heritage.cc:2687`). This struct carries the
/// per-space state across those passes — the delays, how much dead code has been removed, and
/// (for the stack spacebase) whether call placeholders are present.
///
/// This is the scaffolding for the multi-pass rewrite; the current single-pass [`heritage`]
/// does not yet consult it. Built by [`build_info_list`].
#[derive(Clone, Debug)]
pub struct HeritageInfo {
    /// The space this info tracks, or `None` if the space is not heritaged (Ghidra nulls the
    /// `space` field for non-heritaged spaces but keeps their delays — `heritage.cc:188`).
    pub space: Option<SpaceId>,
    /// Passes to wait before first heritaging this space (`AddrSpace::getDelay`).
    pub delay: i32,
    /// Passes to wait before dead-code removal is allowed (`AddrSpace::getDeadcodeDelay`).
    pub deadcodedelay: i32,
    /// How many times dead code has been removed from this space (drives the re-heritage
    /// warning + `bumpDeadcodeDelay`).
    pub deadremoved: i32,
    /// True for the stack spacebase: it carries call placeholders that must be cleared each
    /// pass (`hasCallPlaceholders`, set when `type == IPTR_SPACEBASE`).
    pub has_call_placeholders: bool,
}

impl HeritageInfo {
    /// Build the info for one space (Ghidra's `HeritageInfo::HeritageInfo`, `heritage.cc:179`).
    fn new(spaces: &super::space::SpaceManager, id: SpaceId) -> HeritageInfo {
        let s = spaces.get(id);
        let heritaged = s.is_heritaged();
        HeritageInfo {
            space: heritaged.then_some(id),
            delay: s.delay,
            deadcodedelay: s.deadcodedelay,
            deadremoved: 0,
            has_call_placeholders: heritaged && s.kind == super::space::SpaceKind::Spacebase,
        }
    }

    /// Whether this space participates in heritage (`HeritageInfo::isHeritaged`).
    pub fn is_heritaged(&self) -> bool {
        self.space.is_some()
    }
}

/// Build the per-space heritage info list (Ghidra's `Heritage::buildInfoList`,
/// `heritage.cc:2650`): one [`HeritageInfo`] per registered space, in space-index order.
pub fn build_info_list(spaces: &super::space::SpaceManager) -> Vec<HeritageInfo> {
    (0..spaces.num_spaces()).map(|i| HeritageInfo::new(spaces, SpaceId(i as u32))).collect()
}

/// The location an input slot reads, or `None` if it is not heritaged (a constant, a
/// branch/call destination address, or a space annotation).
fn read_loc(f: &Funcdata, op: OpId, slot: usize) -> Option<Loc> {
    let o = f.op(op);
    if slot == 0
        && matches!(
            o.code(),
            OpCode::Branch | OpCode::Cbranch | OpCode::Call | OpCode::Callother | OpCode::Return
        )
    {
        // A *direct* destination is a constant code address, not dataflow. An *indirect*
        // target (BRANCHIND/CALLIND slot 0) is a computed value and IS heritaged.
        return None;
    }
    let vn = f.vn(o.input(slot)?);
    if vn.is_constant() {
        return None;
    }
    Some((vn.loc.space, vn.loc.offset, vn.size))
}

/// The location an op writes, or `None` if it has no (non-constant) output.
fn write_loc(f: &Funcdata, op: OpId) -> Option<Loc> {
    let vn = f.vn(f.op(op).output?);
    if vn.is_constant() {
        return None;
    }
    Some((vn.loc.space, vn.loc.offset, vn.size))
}





/// Faithful port of Ghidra's `Heritage::removeRevisitedMarkers` (`heritage.cc:244`), driven per
/// range from [`place_multiequals`] (`heritage.cc:2626-2627`) with the `remove` list [`collect`]
/// built (`heritage.cc:329-333`).
///
/// A marker (MULTIEQUAL/INDIRECT) or return-form COPY left by a PREVIOUS pass's heritage of this
/// range, narrower than the range is now, is rewritten IN PLACE as `narrow = SUBPIECE(big, #offset)`
/// where `big = newVarnode(size, addr)` is a fresh whole-range read marked `activeHeritage`; the
/// narrow output is write-masked so `collect` no longer counts it as a write of the narrow location.
/// A return-form COPY is simply unlinked — `guardReturns` re-guards the widened range.
///
/// The `info->deadremoved > 0` branch (`heritage.cc:248-257`) IS ported: re-heritaging a range in a
/// space that has already had Varnodes eliminated means the earlier SSA was built on incomplete
/// information, so the space's dead-code removal is delayed a pass and the decompile restarts.
/// (Ghidra also emits a "Heritage AFTER dead removal" warning header here, once per space; mosura
/// has no warning-header channel, so only the delay lands.)
fn remove_revisited_markers_at(f: &mut Funcdata, remove: &[VarnodeId], range: &MemRange) {
    if dead_removed(f, range.space) {
        bump_deadcode_delay(f, range.space);
    }
    for &out in remove {
        let op = f.vn(out).def.expect("a collected marker output has a def");
        // Return-form COPY (heritage.cc:281): unlink in preparation for a wider re-guarded COPY.
        if !f.op(op).is_marker() {
            f.op_uninsert(op);
            f.op_destroy(op);
            continue;
        }
        // MULTIEQUAL / INDIRECT -> `narrow = SUBPIECE(big, #offset)`. Capture the INDIRECT's causing
        // op (Ghidra `getIn(1)` iop = mosura `guarded_op`) for placement before mutating.
        let is_indirect = f.op(op).code() == OpCode::Indirect;
        let target = if is_indirect { f.op(op).guarded_op() } else { None };
        let bid = f.op(op).parent;
        let offset = f.vn(out).loc.offset.wrapping_sub(range.off);
        f.op_uninsert(op);
        let big = f.new_varnode(range.size, super::space::Address::new(range.space, range.off));
        f.vn_mut(big).set_active_heritage(); // heritage.cc:289
        let cst = f.new_const(4, offset);
        f.op_set_opcode(op, OpCode::Subpiece);
        f.op_set_all_input(op, &[big, cst]);
        f.vn_mut(out).set_write_mask();
        // Placement (heritage.cc:265-280): after the INDIRECT's causing op (after the INDIRECT's old
        // spot if the target is dead), else — for a MULTIEQUAL — after the block's leading MULTIEQUALs.
        let placed_after_target = matches!(
            (is_indirect, target),
            (true, Some(t)) if !f.op(t).is_dead() && f.op(t).parent.is_some()
        );
        if placed_after_target {
            f.op_insert_after(op, target.unwrap());
        } else if let Some(b) = bid {
            f.op_insert_begin(op, b);
        }
        // An INDIRECT also drops the narrow output's addr-force — the replacement wide varnode holds
        // the address (heritage.cc:273).
        if is_indirect {
            f.vn_mut(out).clear_addr_force();
        }
    }
}

/// `Heritage::remove13Refinement` (`heritage.cc:1857`): a 4-byte span split 1+3 or 3+1 is almost
/// always artificial, so merge it back to a single 4-byte piece.
fn remove13_refinement(refine: &mut [u32]) {
    if refine.is_empty() {
        return;
    }
    let mut pos = 0usize;
    let mut lastsize = refine[0] as usize;
    pos += lastsize;
    while pos < refine.len() {
        let cursize = refine[pos] as usize;
        if cursize == 0 {
            break;
        }
        if (lastsize == 1 && cursize == 3) || (lastsize == 3 && cursize == 1) {
            refine[pos - lastsize] = 4;
            lastsize = 4;
            pos += cursize;
        } else {
            lastsize = cursize;
            pos += lastsize;
        }
    }
}



/// Faithful port of `Heritage::normalizeWriteSize` (`heritage.cc:416`). A written Varnode narrower
/// than the heritaged range `[base, base+size)` is widened into a write of the whole range so phi
/// placement and renaming see uniform-width accesses. The bytes of the range above (`mostsig`) and
/// below (`overlap`) the write are pulled from a fresh read of the range's *previous* value via
/// `SUBPIECE`, then `PIECE`d back together with the narrow write. `RuleDumptyHump` /
/// `RuleHumptyDumpty` later collapse the introduced `PIECE`/`SUBPIECE` where they tile cleanly (so a
/// `sete dl` write rejoined into `RDX` and immediately sub-read back simplifies to the byte itself).
///
/// Ghidra keeps the original narrow Varnode as the op's output and sets its write-mask
/// (`heritage.cc:493`), so the sub-register location stays visible in the IR but is no longer a
/// *write* as far as `collect` is concerned. The intermediate pieces live at their real addresses
/// (`pieceaddr`, `midvn` at the range base) exactly as Ghidra places them.
///
/// The CALL `newIndirectCreation` branch (`heritage.cc:434`/`455`, when the narrow write's def is a
/// CALL with an indirect effect on the missing piece) is not ported: mosura has no indirect-creation
/// infrastructure and no fixture writes a register sub-piece directly from a call into a guarded
/// range. The pieces are taken from the plain `SUBPIECE`-of-old-value path (Ghidra's `else`).
///
/// Little-endian only, like [`concat_pieces`]: Ghidra's `addr.isBigEndian()` branches
/// (`heritage.cc:430`/`451`/`472`) are unrepresentable in mosura's decompiler today (task #5).
fn normalize_write_size(f: &mut Funcdata, vn: VarnodeId, range: &MemRange) -> VarnodeId {
    use super::space::Address;
    let op = f.vn(vn).def.expect("a collected write has a def");
    let seq = f.op(op).seqnum;
    let vnsize = f.vn(vn).size;
    let base = Address::new(range.space, range.off);
    let acs = f.spaces.get(range.space).addr_size;
    let overlap = f.vn(vn).loc.offset.wrapping_sub(range.off) as u32; // range bytes below the write
    let mostsig = range.size - (overlap + vnsize); // range bytes above the write

    // High piece (`mostsigsize != 0`, heritage.cc:428): SUBPIECE the range's *previous* whole value
    // at offset `overlap + vn->getSize()`. The fresh whole-range read is itself marked
    // activeHeritage (heritage.cc:442) so renaming links it to the range's reaching def.
    let mostvn = if mostsig > 0 {
        let pieceaddr = Address::new(range.space, range.off + (overlap + vnsize) as u64);
        let big = f.new_varnode(range.size, base);
        f.vn_mut(big).set_active_heritage();
        let cst = f.new_const(acs, (overlap + vnsize) as u64);
        let subop = f.new_op(OpCode::Subpiece, seq, vec![big, cst]);
        let v = f.new_output(subop, mostsig, pieceaddr);
        f.op_insert_before(subop, op);
        Some(v)
    } else {
        None
    };

    // Low piece (`overlap != 0`, heritage.cc:449) + the middle rejoin (:470): SUBPIECE the previous
    // value's low bytes, then PIECE the narrow write above them.
    let midvn = if overlap > 0 {
        let big = f.new_varnode(range.size, base);
        f.vn_mut(big).set_active_heritage();
        let cst = f.new_const(acs, 0);
        let subop = f.new_op(OpCode::Subpiece, seq, vec![big, cst]);
        let leastvn = f.new_output(subop, overlap, base);
        f.op_insert_before(subop, op);
        let pieceop = f.new_op(OpCode::Piece, seq, vec![vn, leastvn]);
        let mid = f.new_output(pieceop, overlap + vnsize, base);
        f.op_insert_after(pieceop, op);
        mid
    } else {
        vn
    };

    // Final rejoin (`mostsigsize != 0`, heritage.cc:483): PIECE the high piece above the middle,
    // inserted after the middle's own def.
    let bigout = if let Some(mostvn) = mostvn {
        let pieceop = f.new_op(OpCode::Piece, seq, vec![mostvn, midvn]);
        let out = f.new_output(pieceop, range.size, base);
        let middef = f.vn(midvn).def.expect("midvn is written");
        f.op_insert_after(pieceop, middef);
        out
    } else {
        midvn
    };

    f.vn_mut(vn).set_write_mask();
    bigout // Replace small write with big write
}




/// Gather the candidate heritage locations for the pass at `pass`: every distinct read/write
/// `(space, offset, size)` whose space is heritaged and whose delay has been reached, mapped to
/// whether the location is read through a still-free (un-heritaged) Varnode. That flag is Ghidra's
/// signal (`heritage.cc:2711`, `!isHeritageKnown() && !hasNoDescend()`) that an already-heritaged
/// location must be RE-heritaged because a later simplification freed a read of it. mosura iterates
/// ops (not the address-sorted Varnode list), which naturally excludes Ghidra's orphan-free skips.
///
/// Write-masked varnodes are skipped (Ghidra's `collect`, `heritage.cc:326`): a marker rewritten to a
/// SUBPIECE of a wider range by [`remove_revisited_markers`] is neither a write of its narrow location
/// nor a free read of it, so it must not re-enter the candidate set (dormant today — nothing is
/// write-masked without a widening re-entry).
fn gather_candidates(f: &Funcdata, pass: i32) -> HashMap<Loc, bool> {
    let infos = build_info_list(&f.spaces);
    let eligible = |sp: SpaceId| {
        let info = &infos[sp.0 as usize];
        info.is_heritaged() && info.delay <= pass
    };
    let mut cand: HashMap<Loc, bool> = HashMap::new();
    for b in 0..f.num_blocks() {
        for &op in &f.blocks()[b].ops {
            for slot in 0..f.op(op).num_inputs() {
                if let Some(l) = read_loc(f, op, slot) {
                    let vn = f.vn(f.op(op).input(slot).unwrap());
                    if eligible(l.0) && !vn.is_write_mask() {
                        *cand.entry(l).or_insert(false) |= !vn.is_heritage_known();
                    }
                }
            }
            if let Some(l) = write_loc(f, op) {
                if eligible(l.0) && !f.vn(f.op(op).output.unwrap()).is_write_mask() {
                    cand.entry(l).or_insert(false);
                }
            }
        }
    }
    cand
}

/// True while some heritaged location still needs to enter SSA form: a location not yet recorded in
/// `globaldisjoint` (never heritaged), or one read through a freed Varnode (heritaged before, but a
/// later simplification re-introduced a free read of it). The driver loop stops once neither holds —
/// the termination implicit in Ghidra's heritage loop (`heritage.cc:2702`, which finds no new work).
pub fn heritage_complete(f: &Funcdata) -> bool {
    // A space that has not yet reached its DELAY always has work outstanding, whatever the current
    // graph happens to look like. Ghidra needs no such statement because it has no completion
    // predicate at all: `ActionHeritage` calls `heritage()` unconditionally every mainloop iteration,
    // and `heritage()` heritages whichever spaces satisfy `pass >= info->delay` (heritage.cc:
    // 2686-2687). The delay is precisely a promise that the space WILL be heritaged on a later pass.
    //
    // The candidate-shape test below cannot see that promise, and inferring completion from graph
    // shape is unsound while the shape is still changing: mainloop iteration 1's rule pool runs
    // before the stack pass, so it legitimately removes ram/stack accesses that nothing anchors yet
    // — and with those gone the test found no candidates and reported heritage FINISHED. The stack
    // pass then never ran, and floatcast (a function whose entire body hangs off two ram globals)
    // rendered as `void func(void) { return; }`. Ghidra's own trace for that fixture is
    // `heritage, deadcode, earlyremoval x55, heritage, earlyremoval x4` — it takes the same removals
    // in the same window and still runs its second pass, because the delay says so.
    if build_info_list(&f.spaces).iter().any(|i| i.is_heritaged() && f.heritage_pass <= i.delay) {
        return false;
    }
    !gather_candidates(f, f.heritage_pass)
        .iter()
        .any(|(l, &has_free)| f.globaldisjoint.find_pass(l.0, l.1) == -1 || has_free)
}

/// Ghidra `Heritage::guardStores` (heritage.cc:1538). A STORE through a computed pointer may modify
/// any location its target space aliases, so for the heritaged range `(space, off, size)` insert an
/// INDIRECT before every such STORE — prepopulating data-flow across it — whose output then joins
/// the range's writes (here: collected by [`heritage_spaces`]' def-block scan) so MULTIEQUAL
/// placement accounts for the possible modification.
///
/// A STORE aliases the range when its destination space (its `in(0)` space-const, decoded like
/// Ghidra's `getSpaceFromConst`) equals the range's space (`spc == storeSpace`). Ghidra's other
/// disjunct — a store into the range space's *container* that `usesSpacebasePtr()` (a
/// spacebase-relative store aliasing a stack range) — cannot fire here: that op flag is set only by
/// the LoadGuard / `discoverIndexedStackPointers` subsystem (heritage.cc:915/932), which mosura
/// lacks (Task #19). With no op ever marked spacebase-ptr, `usesSpacebasePtr()` is definitionally
/// false, so the disjunct is a no-op; it re-enables faithfully once #19 lands.
///
/// Gated by `highPtrPossible` (heritage.cc:1194): the `unique`/internal space admits no high
/// pointer, and mosura's x86-64 spec declares no `<nohighptr>` range, so every other space qualifies.
fn guard_stores(f: &mut Funcdata, range: Loc) {
    let (spc, off, size) = range;
    // highPtrPossible: no pointer can target the internal (`unique`) space.
    if f.spaces.get(spc).kind == super::space::SpaceKind::Internal {
        return;
    }
    // Collect matching STOREs under an immutable borrow, then insert INDIRECTs (mutable) —
    // Ghidra iterates `beginOp(CPUI_STORE)`; mosura has no per-opcode index, so scan block ops.
    let mut stores: Vec<OpId> = Vec::new();
    for b in 0..f.num_blocks() {
        for op in f.blocks()[b].ops.clone() {
            if f.op(op).is_dead() || f.op(op).code() != OpCode::Store {
                continue;
            }
            // STORE in(0) is a constant whose offset encodes the destination `SpaceId`
            // (built in `build.rs`, Ghidra's `AddrSpace*` encoded as a constant on LOAD/STORE in0).
            let Some(in0) = f.op(op).input(0) else { continue };
            if SpaceId(f.vn(in0).loc.offset as u32) == spc {
                stores.push(op);
            }
        }
    }
    for op in stores {
        let ind = f.new_indirect_op(op, super::space::Address::new(spc, off), size);
        // Ghidra passes `PcodeOp::indirect_store` to newIndirectOp here (heritage.cc:1553): the
        // INDIRECT is caused by a STORE, which `ActionLikelyTrash::traceTrash` distinguishes.
        f.op_mut(ind).set_indirect_store();
        // heritage.cc:1554-1555 — both ends of the passthrough join this round's renaming.
        let in0 = f.op(ind).input(0).expect("INDIRECT has an input");
        f.vn_mut(in0).set_active_heritage();
        let out = f.op(ind).output.expect("INDIRECT has an output");
        f.vn_mut(out).set_active_heritage();
    }
}

/// Ghidra `Heritage::guardCalls` (heritage.cc:1443). For the heritaged range `(spc, off, size)`,
/// model each CALL's effect on it with an INDIRECT, driven by the calling convention's `EffectRecord`
/// list ([`super::fspec::lookup_effect`], the `FuncProto::hasEffect` query, heritage.cc:1467):
///   - `killedbycall` (caller-saved volatile registers `RAX,RCX,RDX,RSI,RDI,R8,R9,XMM0..7`) ⇒ an
///     indirect *creation* (`newIndirectCreation`, heritage.cc:1521): a value out of nothing with no
///     realistic ancestor — the RAX/... clobber. mosura's 1-input form (input(0) = indirect-zero `#0`).
///   - `unknown_effect`/`return_address` ⇒ a *passthrough* INDIRECT (`newIndirectOp`,
///     heritage.cc:1511): the range's value flows across the call. Used for the aliased stack locals
///     — a call with an unknown prototype may modify any slot a passed pointer can reach, so the
///     local does not constant-fold to its pre-call value (collapsing e.g. switchhide's switch index).
///   - `unaffected` (callee-saved) ⇒ no guard; the value flows across untouched.
///
/// Ghidra runs this inside `guard()` (heritage.cc:1192) with `addIndirects = newAddresses()`, so it
/// fires only for ranges NEW this pass — driven here by [`heritage_spaces`]' `new_addrs`. Each INDIRECT
/// output joins the range's writes (picked up by the def-block scan) so phi placement accounts for the
/// modification. INDIRECTs are spliced right BEFORE the call — faithful to Ghidra's `newIndirectCreation`
/// / `newIndirectOp` (`opInsertBefore`, funcdata_op.cc:696/726); [`super::recover::resolve_call_output`]
/// gathers the output trials by walking BACKWARD from the call, as Ghidra's `collectOutputTrialVarnodes`
/// (fspec.cc:5543) does.
///
/// The stack side is gated by [`Funcdata::alias_boundary`] (Ghidra's `AliasChecker`): only slots at or
/// above the shallowest escaped offset are reachable by the callee, so a non-aliased local (a spilled
/// loop variable) is left untouched and its loop SSA is undisturbed. The output/input trial branches
/// (`characterizeAsOutput`/`characterizeAsInputParam`, heritage.cc:1468-1509) need FuncProto/ParamActive
/// prototype recovery (P6) and are a documented gap, like guardStores' `usesSpacebasePtr` (#19).
fn guard_calls(f: &mut Funcdata, range: Loc) {
    if !f.call_guards_active {
        return;
    }
    let (spc, off, size) = range;
    let Some(reg) = f.spaces.by_name("register") else { return };
    let stack = f.spaces.by_name("stack");
    let ram = f.spaces.by_name("ram");

    // Ghidra `fc->hasEffect(transAddr,size)`: the effect a call has on this range. Ghidra does NOT
    // special-case any space — `ProtoModel::lookupEffect` (fspec.cc:2472-2485) returns `unknown_effect`
    // for any address not covered by the model's (register-only) EffectRecord list. So registers query
    // the SysV list; a stack local at/above the alias boundary and a ram global both fall through to
    // the default `unknown_effect` (a passthrough guard) — a call with an unknown prototype may modify
    // any global its callee can reach, so the global's value does not constant-fold to its pre-call
    // version (the post-call read reads through the INDIRECT, not the stale pre-call write).
    use super::fspec::effect;
    let aliased_stack = Some(spc) == stack && f.alias_boundary.is_some_and(|b| (off as i64) >= b);
    let effecttype = if spc == reg {
        // Ghidra `fc->hasEffect` — the convention's EffectRecord list (decoded from the compiler
        // spec's `<default_proto>`, carried on the function as `proto_model`). Note this is the
        // DEFAULT model; the per-call override for a callee that does not honour it is applied
        // inside the loop below, where the call — and so its CallSpec — is known.
        f.proto_model.has_effect(super::space::Address::new(reg, off), size)
    } else if aliased_stack || Some(spc) == ram {
        // An aliased stack slot and a ram global both fall through to Ghidra's default unknown_effect.
        effect::UNKNOWN_EFFECT
    } else if f.spaces.get(spc).kind == super::space::SpaceKind::Spacebase {
        // A NON-aliased stack slot. mosura's alias-boundary adaptation suppresses the passthrough
        // INDIRECT here (Ghidra would emit one — every stack address falls through its register-only
        // effect list to unknown_effect); that adaptation is unchanged. What changed is that the
        // range no longer bails out of the whole function: Ghidra decides the INDIRECT and decides
        // the input trial SEPARATELY, and a stack slot holding an outgoing argument must still reach
        // the trial branch below. Spelling it as `unaffected` keeps the INDIRECT suppressed, because
        // the guarding tail only fires for unknown_effect/return_address/killedbycall.
        effect::UNAFFECTED
    } else {
        return;
    };
    // holdind = (fl & addrtied): a mapped (addr-tied) range keeps its passthrough INDIRECT auto-live
    // via setAddrForce, so dead-code preserves the across-call chain and the write feeding it. Faithful
    // to `queryProperties` (heritage.cc:1191) + [`super::varnodeprops::mark_addrtied`]: an unmapped ram
    // global and an aliased stack slot are addr-tied; a register passthrough is not.
    let holdind = Some(spc) == ram || aliased_stack;

    let calls: Vec<OpId> = (0..f.num_blocks() as u32)
        .flat_map(|b| f.block(super::block::BlockId(b)).ops.clone())
        .filter(|&op| matches!(f.op(op).code(), OpCode::Call | OpCode::Callind))
        .collect();
    // An offset only names a location modulo its space's size, and the SAME stack slot reaches
    // here spelled two ways: once canonical (`0xffffffec`) and once sign-extended to 64 bits
    // (`0xffffffffffffffe8`), because the offsets are computed with wrapping arithmetic on `u64`
    // and only some paths mask afterwards. Two spellings are two `Address`es, so the trial created
    // under one never matches the varnode under the other and the argument is silently dropped at
    // commit — measured on WAR2's FUN_00023514, whose fifth (stack) argument flickers in and out of
    // the trial container across rounds and is absent from the final one.
    //
    // Canonicalizing here rather than at each use is what makes the property hold: `addr`, the
    // spacebase translation below, and every trial built from them then share one spelling by
    // construction. This is a property of address spaces, not of x86 — any space narrower than 64
    // bits (a 16-bit segment, a 20-bit harvard code space) has the same two-spellings hazard.
    let off = f.spaces.get(spc).wrap_offset(off);
    let addr = super::space::Address::new(spc, off);
    for call in calls {
        // Skip a call whose own output already IS this range (Ghidra heritage.cc:1453 isAssignment).
        if f.op(call).output.is_some_and(|o| f.vn(o).loc == addr && f.vn(o).size == size) {
            continue;
        }
        let Some(bid) = f.op(call).parent else { continue };

        // PER-CALL EFFECT OVERRIDE. `<unaffected>` is a property of the DEFAULT convention, and in
        // this binary it is a per-function property: a callee that overwrites a "preserved"
        // register — measured on 245 WAR2 functions — leaves the caller's pre-call value stale,
        // because an unaffected range gets NO guard here and flows across untouched. Where the
        // callee's own body says otherwise, that evidence wins over the model.
        let overwritten = f.call_specs.get(&call).is_some_and(|cs| {
            cs.overwrites.iter().any(|&(a, sz)| a.space == reg && a.offset == off && sz == size)
        });
        // The DOWNGRADE evidence: a COMPLETE walk of the callee's reachable body that never writes
        // this register. `overwrites` cannot serve — it is a straight-line list, so absence from it
        // means "not seen", not "never written".
        let never_written = f
            .call_specs
            .get(&call)
            .and_then(|cs| cs.writes_all.as_ref())
            .is_some_and(|w| !w.contains(&off));
        // No complete walk of this callee: an indirect call, or one whose body the walk could not
        // establish (nested call, unresolvable target, budget).
        let no_evidence =
            f.call_specs.get(&call).and_then(|cs| cs.writes_all.as_ref()).is_none();
        let effecttype = if spc == reg && overwritten {
            effect::KILLEDBYCALL
        } else if spc == reg
            && effecttype == effect::KILLEDBYCALL
            // Positive evidence of preservation, OR no evidence at all. mosura has no
            // `ActionDefaultParams` (coreaction.cc:2311), so `guard_calls` asks the CONTAINING
            // FUNCTION's model what a call kills rather than the CALL's own prototype; the watcall
            // cspec compensated by calling the argument registers `<unaffected>` GLOBALLY, which
            // is what made a saved register's exit value observable and turned it into a parameter.
            //
            // Those two are separable. The model's effect list decides the FUNCTION's own exit
            // liveness (so correcting it kills the save/restore chain), while this per-call
            // override decides what a CALL clobbers. Keeping the optimism only where there is no
            // evidence — an indirect call, or a callee whose walk bailed — preserves the behaviour
            // `indirect_call_does_not_clobber_loop_variable` pins (WAR2's FUN_00057034) without
            // paying for it at every function entry.
            && (never_written || no_evidence)
            // NEVER downgrade the convention's RETURN storage. The evidence "this callee writes no
            // value into the register" is about ARGUMENT preservation; the call's OUTPUT lives in
            // the return register by definition of the convention, and `guard_calls`' INDIRECT
            // there is what return recovery reads. Downgrading it lets the caller's pre-call EAX
            // flow across the call untouched, and the caller then recovers that pass-through as
            // its OWN return value — the regout MVE's `use_` turned from `void` into a
            // value-returning function on exactly this.
            && !f
                .proto_model
                .output
                .as_ref()
                .is_some_and(|o| o.possible_param(addr, size))
        {
            // The symmetric half of the upgrade above: a callee that demonstrably PRESERVES a
            // killedbycall register must not clobber the caller's value at this site.
            effect::UNAFFECTED
        } else {
            effecttype
        };

        // Ghidra heritage.cc:1457-1467 — translate the range into the CALLEE's frame before asking
        // the convention anything about it. A register translates to itself; a SPACEBASE range must
        // be shifted by the stack-pointer offset at this call site, and when that offset is unknown
        // Ghidra declines to try the range as a trial at all, because it cannot say which parameter
        // slot the range would be. The offset is what the stack-pointer placeholder recovers
        // ([`super::fspec::create_placeholder`]); before that subsystem existed this was
        // permanently unknown, so mosura registered zero stack trials anywhere.
        let mut tryregister = true;
        let mut trans_off = off;
        if f.spaces.get(spc).kind == super::space::SpaceKind::Spacebase {
            match super::fspec::spacebase_offset(f, call) {
                Some(so) => trans_off = f.spaces.get(spc).wrap_offset(off.wrapping_sub(so)),
                None => tryregister = false,
            }
            // INSTRUMENT (`MOSURA_STACKARG=1`): 423 WAR2 functions pass call arguments on the
            // stack (`push imm ; call ; add esp,4`) and only 5 are byte-clean, so whether a stack
            // range ever reaches the trial branch is a measurement, not a guess.
            if std::env::var("MOSURA_STACKARG").is_ok() {
                eprintln!(
                    "STACKARG call@{:#x} (op {}) range={:#x}+{} sp_off={:?} trans={:#x} tryregister={tryregister}",
                    f.op(call).seqnum.pc.offset, call.0, off, size,
                    super::fspec::spacebase_offset(f, call), trans_off
                );
            }
        }
        let trans_addr = super::space::Address::new(spc, trans_off);

        // Input-parameter branch (Ghidra `Heritage::guardCalls`, heritage.cc:1494-1509). While
        // argument recovery is open for this call, ask the convention how this heritaged range
        // relates to its PARAMETER storage — `FuncProto::characterizeAsInputParam`, i.e. the
        // compiler spec's `<input>` pentries. A range that IS parameter storage (justified) takes a
        // fresh input on the CALL and registers one trial, so renaming links it to the value the
        // caller left there; a range that SWALLOWS parameter storage goes through
        // [`guard_call_overlapping_input`]. **The candidates are a QUERY, never a fixed register
        // list** — this retires `recover_call_args`, which appended hardcoded x86-64 `RDI..R9` at
        // width 8 to every CALL pre-heritage. On x86-32 those offsets are not the argument
        // registers at all: `0x10:8` spans ESP *and* EBP and `0x8:8` spans EDX *and* EBX, so every
        // call site grew six spurious wide reads over ranges nothing writes — the same
        // spurious-range mechanism that severed narrow-switch recovery on the return side.
        //
        // The TRIAL address is the callee-frame `trans_addr`, but the VARNODE that carries it is at
        // the caller-frame `addr` — the two differ by exactly the stack offset for a stack argument,
        // and `build_input_from_trials` translates back (fspec.cc:5713) when it commits the list.
        // Ghidra `ActionRestrictLocal` (coreaction.cc:1957), the saved-register loop: for each
        // register the convention does NOT kill, find its input varnode and mark the storage where
        // that value gets SAVED as not-mapped —
        //     if (op->code() != CPUI_COPY) continue;
        //     if (!data.getScopeLocal()->isUnaffectedStorage(outvn)) continue;
        //     data.getScopeLocal()->markNotMapped(outvn->getSpace(), outvn->getOffset(), …);
        // mosura does not port that action, so a callee-save slot stays an ordinary stack range and
        // `guard_calls` registers it as an OUTGOING ARGUMENT once the call's stack-pointer offset
        // resolves and the slot translates into the callee's parameter area.
        //
        // FUN_000100b9's prologue is `push ecx ; push esi ; push edi ; push ebp`; its call came out
        // with a fifth argument `stack+0xfffffff4 <- Copy register+0x1c[i]` — the saved EDI. The
        // trial survives every realism test because the varnode IS written (by the save) and DOES
        // trace to a real input, which is why guards keyed on unwritten/free/register all failed.
        let is_saved_slot = f.spaces.get(spc).kind == super::space::SpaceKind::Spacebase && {
            (0..f.num_varnodes() as u32).any(|i| {
                let src = f.vn(super::varnode::VarnodeId(i));
                if !src.is_input() || Some(src.loc.space) != f.spaces.by_name("register") {
                    return false;
                }
                // A register the convention PRESERVES is a save by definition. A register the
                // convention KILLS is normally a spill — but not when this function demonstrably
                // saves and restores it, which is what the save/restore walk records in
                // `own_saved`. The convention's opinion is about calls in general; the walk is
                // evidence about THIS function.
                //
                // `FUN_00013160` is the specimen: `PUSH EDX ; PUSH EBP ; MOV EBP,ESP ; … ; POP EBP ;
                // POP EDX ; RET`. Under watcall EDX is an argument register and therefore
                // killedbycall, so the convention alone reads its save slot as outgoing argument
                // storage — and once the call's stack-pointer offset resolves, that slot translates
                // to the callee's first stack-argument address and becomes a spurious trial. The
                // spurious trial then extends the range `force_inactive_chain` fills holes over,
                // promoting register holes into parameters of this function.
                let preserved = f.proto_model.has_effect(src.loc, src.size) == effect::UNAFFECTED;
                let saved_here = f.own_saved.as_ref().is_some_and(|s| s.contains(&src.loc.offset));
                if !preserved && !saved_here {
                    return false;
                }
                let copy_found = src.descend.iter().any(|&d| {
                    f.op(d).code() == super::opcode::OpCode::Copy
                        && f.op(d).output.is_some_and(|o| {
                            let ov = f.vn(o);
                            ov.loc.space == spc && ov.loc.offset == off && ov.size == size
                        })
                });
                if std::env::var_os("MOSURA_SAVEDSLOT").is_some() {
                    eprintln!(
                        "[savedslot] call@{:#x} slot={}+{:#x}/{} src={}+{:#x} preserved={preserved} saved_here={saved_here} copy_found={copy_found} ndesc={}",
                        f.op(call).seqnum.pc.offset,
                        f.spaces.get(spc).name, off, size,
                        f.spaces.get(src.loc.space).name, src.loc.offset,
                        src.descend.len()
                    );
                }
                copy_found
            })
        };
        if std::env::var_os("MOSURA_ARG_DEBUG").is_some()
            && f.spaces.get(spc).kind != super::space::SpaceKind::Spacebase
            && f.is_input_active(call)
        {
            // Which register ranges are even OFFERED as argument trials, and what the convention
            // says about each. A trial that is never registered looks identical, in every later
            // instrument, to one registered and then rejected — and the two have opposite fixes.
            eprintln!(
                "[offer] call@{:#x} range={}+{:#x}/{} tryregister={tryregister} saved={is_saved_slot} char={:?}",
                f.op(call).seqnum.pc.offset,
                f.spaces.get(spc).name,
                off,
                size,
                characterize_for_call(f, call, trans_addr, size)
            );
        }
        if tryregister && !is_saved_slot && f.is_input_active(call) {
            match characterize_for_call(f, call, trans_addr, size) {
                super::fspec::Containment::ContainsJustified => {
                    let active = f.active_inputs.get_mut(&call).unwrap();
                    if active.which_trial(trans_addr, size).is_none() {
                        if std::env::var_os("MOSURA_ARG_DEBUG").is_some() {
                            eprintln!(
                                "[register] call@{:#x} {}+{:#x}/{}",
                                f.op(call).seqnum.pc.offset,
                                f.spaces.get(trans_addr.space).name,
                                trans_addr.offset,
                                size
                            );
                        }
                        let active = f.active_inputs.get_mut(&call).unwrap();
                        let ti = active.register_trial(trans_addr, size);
                        let invn = f.new_varnode(size, addr);
                        // heritage.cc:1503 — the new CALL input joins THIS round's renaming, so it
                        // binds to the value the caller left in the argument register. Without it
                        // the varnode is not activeHeritage, `rename_recurse` skips it (:2496) and
                        // it stays free at an argument location forever.
                        f.vn_mut(invn).set_active_heritage();
                        f.op_append_input(call, invn);
                        let slot = f.op(call).num_inputs() - 1;
                        f.active_inputs.get_mut(&call).unwrap().trial[ti].op_slot = slot as u32;
                    }
                }
                super::fspec::Containment::ContainedBy => {
                    guard_call_overlapping_input(f, call, addr, trans_addr, size)
                }
                _ => {}
            }
        }

        if effecttype == effect::KILLEDBYCALL {
            // newIndirectCreation (mosura 1-input): out@range = INDIRECT(#0), output marked
            // indirect-creation (no realistic ancestor / the clobber). Ghidra `newIndirectCreation`
            // (funcdata_op.cc:726) splices the INDIRECT BEFORE the call with `opInsertBefore`, and
            // `collectOutputTrialVarnodes` (fspec.cc:5543) walks BACKWARD from the call to gather the
            // output trials — `resolve_call_output` mirrors that backward scan.
            //
            // POSSIBLE-OUTPUT creations (Ghidra heritage.cc:1468-1484 + funcdata_op.cc:726): a
            // killed-by-call range that the model characterizes as potential RETURN storage of a
            // call whose output recovery is still open is a possible output, and its creation's
            // constant is NOT flagged `indirect_creation` — which is exactly what lets a LATER
            // call's argument trial walk through it as a realistic ancestor
            // (`AncestorRealistic::enterNode` CPUI_INDIRECT, funcdata_varnode.cc:2045-2050:
            // creation with a non-indirect-zero input pops SUCCESS). Ghidra's gate is
            // `fc->isOutputActive()` on the call's own output ParamActive; mosura's call-output
            // recovery is the `calls_awaiting_output` backward scan with no per-call active, so
            // the composition-faithful spelling of "output recovery still open" is "the call has
            // no committed output varnode yet". Measured on WAR2 FUN_00011954: the EAX argument
            // of the third call is the second call's return, whose creation this gate keeps
            // walkable — without it the trial is marked definitely-not-used and BOTH arguments
            // (the return and the constant 0x2b behind it) are dropped from the emitted call.
            let possibleoutput = f.op(call).output.is_none()
                && f.proto_model.characterize_as_output(trans_addr, size)
                    == super::fspec::Containment::ContainsJustified;
            let seq = f.op(call).seqnum;
            let zero = f.new_const(size, 0);
            if !possibleoutput {
                // funcdata_op.cc:726: `if (!possibleout) newin->setFlags(Varnode::indirect_creation)`
                // — the flagged constant IS Ghidra's `isIndirectZero`, the definite clobber.
                f.vn_mut(zero).set_indirect_creation();
            }
            let ind = f.new_op(OpCode::Indirect, seq, vec![zero]);
            f.op_mut(ind).guarded_op = Some(call); // Ghidra's iop: the causing call
            let out = f.new_output(ind, size, addr);
            f.vn_mut(out).set_indirect_creation();
            f.vn_mut(out).set_active_heritage(); // heritage.cc:1531
            f.op_mut(ind).parent = Some(bid);
            f.op_insert_before(ind, call);
        } else if effecttype == effect::UNKNOWN_EFFECT || effecttype == effect::RETURN_ADDRESS {
            // newIndirectOp (passthrough): out@range = INDIRECT(before@range), the value flowing
            // across. Ghidra `newIndirectOp` (funcdata_op.cc:696) splices the INDIRECT BEFORE the call
            // with `opInsertBefore`.
            let seq = f.op(call).seqnum;
            let before = f.new_varnode(size, addr);
            let ind = f.new_op(OpCode::Indirect, seq, vec![before]);
            f.op_mut(ind).guarded_op = Some(call); // Ghidra's iop: the causing call
            let out = f.new_output(ind, size, addr);
            f.vn_mut(before).set_active_heritage(); // heritage.cc:1524
            f.vn_mut(out).set_active_heritage(); // heritage.cc:1525
            f.op_mut(ind).parent = Some(bid);
            f.op_insert_before(ind, call);
            if holdind {
                f.vn_mut(out).set_addr_force();
            }
            if effecttype == effect::RETURN_ADDRESS {
                f.vn_mut(out).set_return_address();
            }
        }
    }
}

/// Guard a call where the heritaged range properly CONTAINS the parameter storage — a port of
/// Ghidra `Heritage::guardCallOverlappingInput` (heritage.cc:1210). The call may be taking part of
/// this range as an argument, so a SUBPIECE truncates the range down to the storage the convention
/// actually passes in, and that truncated piece becomes the call's new input and its trial.
///
/// Two addresses, as in Ghidra: `trans_addr` is the range from the CALLEE's stack perspective and is
/// what the convention is queried with; `addr` is the same range in the caller, and is where the
/// varnodes actually live. They coincide for a register range and differ by the call's stack offset
/// for a spacebase range.
///
/// One asymmetry is Ghidra's, ported as written rather than "corrected": the containment query uses
/// `trans_addr`, but `registerTrial` is then called with the truncated address converted BACK to the
/// caller's perspective (heritage.cc:1232), where the `contains_justified` branch above registers
/// its trial in callee-frame coordinates. It makes no difference for a register range, which is the

/// Ghidra `FuncCallSpecs::getProto().characterizeAsInputParam` at `Heritage::guardCalls`
/// (heritage.cc:1495) — the CALL'S OWN model's verdict, which is the default convention's
/// except at a caller-cleaned (`__cdecl`) call
/// ([`Funcdata::input_list_for_call`](super::funcdata::Funcdata::input_list_for_call)): there
/// the stack-only list characterizes every register range `NoContainment`, so `__watcall`'s
/// register pentries seed no trials at a call that passes nothing in registers.
fn characterize_for_call(
    f: &Funcdata,
    call: OpId,
    trans_addr: super::space::Address,
    size: u32,
) -> super::fspec::Containment {
    match f.input_list_for_call(call) {
        Some(pl) => pl.characterize_as_param(trans_addr, size),
        None => super::fspec::Containment::NoContainment,
    }
}

/// only kind that reaches here today.
fn guard_call_overlapping_input(
    f: &mut Funcdata,
    call: OpId,
    addr: super::space::Address,
    trans_addr: super::space::Address,
    size: u32,
) {
    let Some((trunc_trans, trunc_size)) =
        f.proto_model.get_biggest_contained_input_param(trans_addr, size)
    else {
        return;
    };
    // heritage.cc:1218-1220 — convert the truncated address to the caller's perspective.
    let diff = trunc_trans.offset.wrapping_sub(trans_addr.offset);
    let trunc_addr = super::space::Address::new(addr.space, addr.offset.wrapping_add(diff));
    if f.active_inputs.get(&call).is_some_and(|a| a.which_trial(trunc_addr, trunc_size).is_some()) {
        return;
    }
    // Bytes to truncate off the least-significant end (little-endian; Ghidra's `justifiedContain`).
    let truncate_amount = trunc_addr.offset - addr.offset;
    let seq = f.op(call).seqnum;
    let whole = f.new_varnode(size, addr);
    // heritage.cc:1226 — the SUBPIECE's whole-range READ joins this round's renaming. (Ghidra does
    // NOT mark the truncated output: it is a written varnode, and `rename_recurse` only gates FREE
    // varnodes on the flag.)
    f.vn_mut(whole).set_active_heritage();
    let off_const = f.new_const(4, truncate_amount);
    let subop = f.new_op(OpCode::Subpiece, seq, vec![whole, off_const]);
    if let Some(bid) = f.op(call).parent {
        f.op_mut(subop).parent = Some(bid);
    }
    f.op_insert_before(subop, call);
    let piece = f.new_output(subop, trunc_size, trunc_addr);
    f.op_append_input(call, piece);
    let slot = f.op(call).num_inputs() - 1;
    let active = f.active_inputs.get_mut(&call).unwrap();
    let ti = active.register_trial(trunc_addr, trunc_size);
    active.trial[ti].op_slot = slot as u32;
}

/// The live RETURN ops, in block/op order — Ghidra's `beginOp(CPUI_RETURN)`..`endOp(CPUI_RETURN)`
/// walk. (Ghidra additionally skips ops with `getHaltType() != 0`; mosura does not model special
/// halt points, so every live RETURN is a real one.)
fn live_returns(f: &Funcdata) -> Vec<OpId> {
    (0..f.num_blocks() as u32)
        .flat_map(|b| f.block(super::block::BlockId(b)).ops.clone())
        .filter(|&op| f.op(op).code() == OpCode::Return && !f.op(op).is_dead())
        .collect()
}

/// Guard data-flow at RETURN ops where the heritaged range properly CONTAINS the return storage —
/// a port of Ghidra `Heritage::guardReturnsOverlapping` (heritage.cc:1609). The RETURN must take an
/// input for the potential return value, but the range is too wide, so a SUBPIECE truncates it down
/// to the storage the convention actually returns in (e.g. a heritaged `EAX:ECX` 8-byte range on a
/// convention that returns in `EAX:4`). One trial is registered, at the TRUNCATED location.
fn guard_returns_overlapping(f: &mut Funcdata, addr: super::space::Address, size: u32) {
    let Some((trunc_addr, trunc_size)) = f.proto_model.get_biggest_contained_output(addr, size) else {
        return;
    };
    let ti = f.active_output.as_mut().expect("caller checked").register_trial(trunc_addr, trunc_size);
    // Number of least-significant bytes to truncate. (Ghidra flips this for a big-endian space,
    // heritage.cc:1624; mosura's spaces are little-endian.)
    let offset = trunc_addr.offset - addr.offset;
    for ret in live_returns(f) {
        let invn = f.new_varnode(size, addr);
        let seq = f.op(ret).seqnum;
        let off_const = f.new_const(4, offset);
        let subop = f.new_op(OpCode::Subpiece, seq, vec![invn, off_const]);
        f.op_insert_before(subop, ret);
        let retval = f.new_output(subop, trunc_size, trunc_addr);
        // heritage.cc:1684 — `invn->setActiveHeritage()`. The whole-range read this manufactures must
        // join THIS round's renaming, or `rename_recurse` skips it (:2496) and it stays FREE at a
        // register location forever. A free ancestor then stops `ancestorOpUse` dead
        // (`if (!invn->isInput()) return false`, funcdata_varnode.cc), so the return trial is never
        // marked active, the RETURN loses its value, and every op feeding it is correctly dead-coded:
        // floatcast rendered `void func(void) { return; }`. Invisible while heritage ran to
        // completion before anything else, because the SECOND pass linked the varnode anyway.
        f.vn_mut(invn).set_active_heritage();
        f.op_append_input(ret, retval);
        f.active_output.as_mut().unwrap().trial[ti].op_slot = (f.op(ret).num_inputs() - 1) as u32;
    }
}

/// Guard data-flow at RETURN ops — a port of Ghidra `Heritage::guardReturns` (heritage.cc:1652).
/// Two independent branches run for every heritaged range:
///
/// 1. **The return-value branch** (heritage.cc:1657-1675). While return-prototype recovery is open
///    (`Funcdata::active_output` live), the convention is asked how this range relates to its return
///    storage — `FuncProto::characterizeAsOutput`, i.e. the compiler spec's `<output>` pentries. A
///    range that IS return storage (either `contains_*` code) registers ONE output trial and takes a
///    fresh input on every RETURN, so renaming links it to the value reaching that return; a range
///    that SWALLOWS the return storage goes through [`guard_returns_overlapping`]. A range the
///    convention doesn't return in is left alone. **The candidates are a QUERY over the heritaged
///    ranges, never a fixed register list** — this is what makes return recovery architecture- and
///    convention-independent (the retired `recover_return` appended hardcoded x86-64 `RAX:8`/`XMM0:8`
///    varnodes pre-heritage, which on any 32-bit convention match no storage at all, so every
///    function recovered a `void` return).
/// 2. **The persist branch** (heritage.cc:1676-1691). A persistent global's value must persist to
///    (past) the end of the function, so a COPY is inserted right before every RETURN: its input
///    renames to the store version reaching the return (giving that write a real reader — and hence a
///    Cover), and its output is `addrForce`d and `markReturnCopy`'d so dead-code keeps it and
///    `RulePropagateCopy` won't fold it. This is what lets `Merge::mergeAddrTied` unify the store
///    version into the global's whole HighVariable, so the merge phase can tell a pre-store snapshot
///    apart from the post-store value.
///
/// Ghidra derives `persist` fresh at guard time via `queryProperties` (heritage.cc:1191). mosura's
/// decompile corpus has no populated scope, so — like [`super::varnodeprops::mark_addrtied`] and
/// [`guard_calls`] — persist is determined by space: an unmapped `ram` (global) location is
/// persistent.
fn guard_returns(f: &mut Funcdata, range: Loc) {
    let (spc, off, size) = range;
    let addr = super::space::Address::new(spc, off);

    // 1. Return-value branch (heritage.cc:1657-1675).
    if f.active_output.is_some() {
        match f.proto_model.characterize_as_output(addr, size) {
            super::fspec::Containment::NoContainment => {}
            super::fspec::Containment::ContainedBy => guard_returns_overlapping(f, addr, size),
            _ => {
                let ti = f.active_output.as_mut().unwrap().register_trial(addr, size);
                for ret in live_returns(f) {
                    let invn = f.new_varnode(size, addr);
                    f.vn_mut(invn).set_active_heritage(); // heritage.cc:1671
                    f.op_append_input(ret, invn);
                    f.active_output.as_mut().unwrap().trial[ti].op_slot = (f.op(ret).num_inputs() - 1) as u32;
                }
            }
        }
    }

    // 2. Persist branch (heritage.cc:1676-1691).
    let Some(ram) = f.spaces.by_name("ram") else { return };
    if spc != ram {
        return; // only persistent globals get the return-copy; stack/register are not persist
    }
    for ret in live_returns(f) {
        // COPY: out@(addr,size)[addrForce, returnCopy] = in@(addr,size), inserted before RETURN.
        let seq = f.op(ret).seqnum;
        let invn = f.new_varnode(size, addr);
        f.vn_mut(invn).set_active_heritage(); // heritage.cc:1688
        let copyop = f.new_op(OpCode::Copy, seq, vec![invn]);
        let out = f.new_output(copyop, size, addr);
        f.vn_mut(out).set_addr_force();
        f.vn_mut(out).set_active_heritage(); // heritage.cc:1684
        f.op_mut(copyop).mark_return_copy();
        f.op_insert_before(copyop, ret);
    }
}

/// mosura's stand-in for Ghidra's `VarnodeLocSet` — the location-ordered set `fd->beginLoc(space)`
/// that `Heritage::collect` (`heritage.cc:324`) range-queries. Ghidra keeps this set live on the
/// Funcdata; mosura's varnodes are reachable only through the op graph, so the equivalent set is
/// materialized once per [`place_multiequals`] and range-queried per [`MemRange`].
///
/// Entries are sorted in Ghidra's `VarnodeCompareLocDef` order (`varnode.cc:34`): address, then
/// size, then `input` < `written` < `free`. Ghidra's final tiebreak is the def's `SeqNum` (written)
/// or the create index (free); mosura uses the create index throughout — that tiebreak orders only
/// the *creation* of the SUBPIECE/PIECE ops `guard()` splices in (op numbering), never which ops are
/// created, so the two orders are semantically identical. Address order is the part that carries
/// meaning: `guardInput` (`heritage.cc:1951`) requires its input list in address order.
/// One [`LocSet`] entry: `(offset, size, class, create-index, varnode)`, where class is 0=input,
/// 1=written, 2=free (Ghidra's `(f1-1) < (f2-1)` unsigned trick, which forces frees last).
type LocEntry = (u64, u32, u8, u32, VarnodeId);

#[derive(Default)]
struct LocSet {
    /// Per space, ascending in `VarnodeCompareLocDef` order.
    per_space: HashMap<SpaceId, Vec<LocEntry>>,
}

impl LocSet {
    /// Materialize the set from the op graph: every varnode that is an op output or an op input.
    /// (Ghidra's set additionally holds free varnodes attached to no op — inputs and `unaffected`
    /// registers with no descendants. Those are the `heritage.cc:2704` cover members mosura does not
    /// yet see; collecting them is Stage B of task #6.)
    fn build(f: &Funcdata) -> LocSet {
        let mut seen: HashSet<VarnodeId> = HashSet::new();
        let mut set = LocSet::default();
        let mut push = |set: &mut LocSet, f: &Funcdata, vid: VarnodeId| {
            if !seen.insert(vid) {
                return;
            }
            let vn = f.vn(vid);
            if vn.is_constant() || vn.is_annotation() {
                return;
            }
            let class = if vn.is_input() {
                0
            } else if vn.is_written() {
                1
            } else {
                2
            };
            set.per_space.entry(vn.loc.space).or_default().push((
                vn.loc.offset,
                vn.size,
                class,
                vid.0,
                vid,
            ));
        };
        for b in 0..f.num_blocks() {
            for i in 0..f.blocks()[b].ops.len() {
                let op = f.blocks()[b].ops[i];
                if let Some(out) = f.op(op).output {
                    push(&mut set, f, out);
                }
                for slot in 0..f.op(op).num_inputs() {
                    // `read_loc` applies the same exclusions Ghidra gets for free from the
                    // per-space set: constants live in `const`, and a direct branch/call
                    // destination is a code address annotation, not dataflow.
                    if read_loc(f, op, slot).is_some() {
                        push(&mut set, f, f.op(op).input(slot).unwrap());
                    }
                }
            }
        }
        for v in set.per_space.values_mut() {
            v.sort_unstable();
        }
        set
    }

    /// The varnodes whose ADDRESS lies in `[off, off+size)` of `space`, in set order — Ghidra's
    /// `fd->beginLoc(memrange.addr) .. fd->beginLoc(endaddr)` walk (`heritage.cc:314-324`),
    /// including its wraparound case (`heritage.cc:317`).
    fn in_range(&self, space: SpaceId, off: u64, size: u32) -> Vec<VarnodeId> {
        let Some(v) = self.per_space.get(&space) else { return Vec::new() };
        match off.checked_add(size as u64) {
            Some(end) => {
                let start = v.partition_point(|e| e.0 < off);
                v[start..].iter().take_while(|e| e.0 < end).map(|e| e.4).collect()
            }
            // Wraparound: the range runs to the top of the space and continues at 0.
            None => v
                .iter()
                .filter(|e| e.0.wrapping_sub(off) < size as u64)
                .map(|e| e.4)
                .collect(),
        }
    }
}

/// The free reads, writes, inputs and stale markers of one heritaged range — the four output
/// vectors of Ghidra's `Heritage::collect` (`heritage.cc:307`).
#[derive(Default)]
struct Collected {
    /// Free Varnodes read from the range (Ghidra `read`).
    read: Vec<VarnodeId>,
    /// Written Varnodes in the range (Ghidra `write`).
    write: Vec<VarnodeId>,
    /// Varnodes in the range already marked as function input (Ghidra `input`).
    input: Vec<VarnodeId>,
    /// Markers from a PREVIOUS pass's heritage that are narrower than the (now wider) range, so
    /// they must be rewritten as SUBPIECEs of it (Ghidra `remove`).
    remove: Vec<VarnodeId>,
}

/// Faithful port of `Heritage::collect` (`heritage.cc:307`): classify every Varnode whose address
/// falls in `range` into free reads / writes / inputs / stale markers, and return the maximum write
/// size (Ghidra's `maxsize`, which drives the refinement carve-out at `heritage.cc:2610`).
///
/// `range` is taken by `&mut` because Ghidra's collect clears the range's `new_addresses` property
/// when it finds a FULL-width marker from a previous pass (`heritage.cc:334`: "Previous pass covered
/// everything") — which then suppresses re-guarding at `heritage.cc:2629`.
/// Ghidra `Heritage::buildRefinement` (heritage.cc:1704): mark each Varnode's start and
/// one-past-end positions in the refinement array.
fn build_refinement(refine: &mut [u32], range_off: u64, f: &Funcdata, vnlist: &[VarnodeId]) {
    for &v in vnlist {
        let vn = f.vn(v);
        let diff = vn.loc.offset.wrapping_sub(range_off) as usize;
        refine[diff] = 1;
        refine[diff + vn.size as usize] = 1;
    }
}

/// Ghidra `Heritage::splitByRefinement` (heritage.cc:1733): cut `vn` into free VARNODE pieces
/// whose boundaries match the refinement partition (the arithmetic-only sibling above serves the
/// retired `refine_ranges` re-entry path once did). Empty result = already refined.
fn split_varnode_by_refinement(
    f: &mut Funcdata,
    vn: VarnodeId,
    range_off: u64,
    refine: &[u32],
) -> Vec<VarnodeId> {
    let (spc, mut curoff, mut sz) = {
        let v = f.vn(vn);
        (v.loc.space, v.loc.offset, v.size as i64)
    };
    let space_high = f.spaces.get(spc).highest();
    // `Space::wrap_offset` replicated without holding the `f.spaces` borrow (signed remainder,
    // as in Ghidra's `AddrSpace::wrapOffset`).
    let wrap = move |off: u64| -> u64 {
        if off <= space_high {
            return off;
        }
        let Some(m) = (space_high as i64).checked_add(1) else { return off };
        if m == 0 {
            return off;
        }
        let mut r = (off as i64) % m;
        if r < 0 {
            r += m;
        }
        r as u64
    };
    let mut split = Vec::new();
    let diff = wrap(curoff.wrapping_sub(range_off)) as usize;
    let mut cutsz = refine[diff] as i64;
    if sz <= cutsz {
        return split; // already refined
    }
    split.push(f.new_varnode(cutsz as u32, Address::new(spc, curoff)));
    sz -= cutsz;
    while sz > 0 {
        curoff = curoff.wrapping_add(cutsz as u64);
        let diff = wrap(curoff.wrapping_sub(range_off)) as usize;
        cutsz = refine[diff] as i64;
        if cutsz > sz {
            cutsz = sz; // final piece
        }
        split.push(f.new_varnode(cutsz as u32, Address::new(spc, curoff)));
        sz -= cutsz;
    }
    split
}

/// Ghidra `Heritage::splitPieces` (heritage.cc:563), little-endian arm (mosura's decompiler
/// carries no endianness flag — same reduction as `concat_pieces`/`normalize_write_size`): give
/// each piece a defining SUBPIECE of `startvn`, inserted AFTER the defining op (or at the start
/// block's head for an input).
fn split_pieces(
    f: &mut Funcdata,
    vnlist: &[VarnodeId],
    insertop: Option<OpId>,
    baseoff: u64,
    startvn: VarnodeId,
) {
    let seq = match insertop {
        Some(op) => f.op(op).seqnum,
        None => super::op::SeqNum { pc: f.addr, uniq: 0 },
    };
    let mut prev = insertop;
    for &vn in vnlist {
        let diff = f.vn(vn).loc.offset.wrapping_sub(baseoff);
        let c = f.new_const(4, diff);
        let newop = f.new_op(OpCode::Subpiece, seq, vec![startvn, c]);
        f.op_set_output(newop, vn);
        match prev {
            Some(op) => f.op_insert_after(newop, op),
            None => f.op_insert_begin(newop, super::block::BlockId(0)),
        }
        // keep the SUBPIECEs in piece order after the write, as Ghidra's advancing insertiter does
        prev = Some(newop);
    }
}

/// Ghidra `Heritage::refineRead` (heritage.cc:1772): replace a free read with the concatenation
/// of its refined pieces.
fn refine_read(f: &mut Funcdata, vn: VarnodeId, range_off: u64, refine: &[u32]) {
    let newvn = split_varnode_by_refinement(f, vn, range_off, refine);
    if newvn.is_empty() {
        return;
    }
    let size = f.vn(vn).size;
    let replacevn = f.new_unique(size);
    debug_assert_eq!(f.vn(vn).descend.len(), 1, "refining a free read with one descendant");
    let op = f.vn(vn).descend[0];
    let slot = (0..f.op(op).num_inputs())
        .find(|&i| f.op(op).input(i) == Some(vn))
        .expect("read is an input of its lone descendant");
    concat_pieces(f, &newvn, Some(op), replacevn);
    f.op_set_input(op, slot, replacevn);
    if f.vn(vn).descend.is_empty() {
        f.delete_varnode(vn);
    }
}

/// Ghidra `Heritage::refineWrite` (heritage.cc:1806): retarget the def onto a temporary and
/// SUBPIECE it into the refined pieces.
fn refine_write(f: &mut Funcdata, vn: VarnodeId, range_off: u64, refine: &[u32]) {
    let newvn = split_varnode_by_refinement(f, vn, range_off, refine);
    if newvn.is_empty() {
        return;
    }
    let size = f.vn(vn).size;
    let baseoff = f.vn(vn).loc.offset;
    let replacevn = f.new_unique(size);
    let def = f.vn(vn).def.expect("write has a def");
    f.op_set_output(def, replacevn);
    split_pieces(f, &newvn, Some(def), baseoff, replacevn);
    f.total_replace(vn, replacevn);
    f.delete_varnode(vn);
}

/// Ghidra `Heritage::refineInput` (heritage.cc:1836): SUBPIECE an input into its refined pieces
/// and mask it out of later heritage collection.
fn refine_input(f: &mut Funcdata, vn: VarnodeId, range_off: u64, refine: &[u32]) {
    let newvn = split_varnode_by_refinement(f, vn, range_off, refine);
    if newvn.is_empty() {
        return;
    }
    let baseoff = f.vn(vn).loc.offset;
    split_pieces(f, &newvn, None, baseoff, vn);
    f.vn_mut(vn).set_write_mask();
}

/// Ghidra `Heritage::refinement` (heritage.cc:1890) at its real slot — the `placeMultiequals`
/// carve-out (heritage.cc:2610-2616): find the common refinement of every read/write/input in
/// the range, split them all to match, and replace the range in BOTH the local task list and
/// `globaldisjoint` with the partition pieces (same pass). Returns the task-list position of the
/// first piece, or `None` for no non-trivial refinement. General over every space — the
/// restriction that held this port was the interception POINT, not the space set
/// (docs/compilable-c-remediation.md, "Mechanism A scoped").
fn refinement(
    f: &mut Funcdata,
    disjoint: &mut TaskList,
    pos: usize,
    c: &Collected,
) -> Option<usize> {
    let range = disjoint.ranges()[pos];
    let size = range.size as usize;
    if size > 1024 {
        return None;
    }
    let mut refine = vec![0u32; size + 1]; // fencepost for the one-past-end position
    build_refinement(&mut refine, range.off, f, &c.read);
    build_refinement(&mut refine, range.off, f, &c.write);
    build_refinement(&mut refine, range.off, f, &c.input);
    refine.pop();
    // boundary points -> partition sizes
    let mut lastpos = 0usize;
    for curpos in 1..size {
        if refine[curpos] != 0 {
            refine[lastpos] = (curpos - lastpos) as u32;
            lastpos = curpos;
        }
    }
    if lastpos == 0 {
        return None; // no non-trivial refinement
    }
    refine[lastpos] = (size - lastpos) as u32;
    remove13_refinement(&mut refine);
    for &v in &c.read {
        refine_read(f, v, range.off, &refine);
    }
    for &v in &c.write {
        refine_write(f, v, range.off, &refine);
    }
    for &v in &c.input {
        refine_input(f, v, range.off, &refine);
    }
    // Alter the disjoint cover (both locally and globally) to reflect the refinement.
    let removed = disjoint.remove(pos);
    let cur_pass = f.globaldisjoint.erase(removed.space, removed.off).unwrap_or(f.heritage_pass);
    let mut cut = 0usize;
    let mut addr = removed.off;
    let mut at = pos;
    while cut < size {
        let sz = refine[cut];
        disjoint.insert(at, removed.space, addr, sz, removed.flags);
        f.globaldisjoint.add(removed.space, addr, sz, cur_pass);
        at += 1;
        cut += sz as usize;
        addr = addr.wrapping_add(sz as u64);
    }
    Some(pos)
}

fn collect(f: &Funcdata, locset: &LocSet, range: &mut MemRange) -> (Collected, u32) {
    let mut c = Collected::default();
    let mut maxsize = 0u32;
    for vid in locset.in_range(range.space, range.off, range.size) {
        let vn = f.vn(vid);
        if vn.is_write_mask() {
            continue;
        }
        if vn.is_written() {
            let op = vn.def.expect("written varnode has a def");
            if f.op(op).is_marker() || f.op(op).is_return_copy() {
                // Evidence of previous heritage in this range (heritage.cc:329).
                if vn.size < range.size {
                    c.remove.push(vid);
                    continue;
                }
                range.clear_property(MemRange::NEW_ADDRESSES);
            }
            if vn.size > maxsize {
                maxsize = vn.size;
            }
            c.write.push(vid);
        } else if !vn.is_heritage_known() && !vn.descend.is_empty() {
            c.read.push(vid);
        } else if vn.is_input() {
            c.input.push(vid);
        }
    }
    (c, maxsize)
}







/// Faithful port of `Heritage::normalizeReadSize` (`heritage.cc:382`): a free read narrower than the
/// range it belongs to is redefined as `SUBPIECE(whole, overlap)` of a fresh whole-range free read,
/// which is returned and takes the narrow varnode's place in the range's read list.
///
/// The narrow varnode KEEPS its own address and becomes the SUBPIECE's output, write-masked
/// (`heritage.cc:396-397`) — it is no longer a free read, and `collect` will skip it from now on.
/// This is the single mechanism by which an `AL` read and an `EAX` read become one SSA variable.
fn normalize_read_size(f: &mut Funcdata, vn: VarnodeId, op: OpId, range: &MemRange) -> VarnodeId {
    use super::space::Address;
    let seq = f.op(op).seqnum;
    let whole = f.new_varnode(range.size, Address::new(range.space, range.off));
    let overlap = f.vn(vn).loc.offset.wrapping_sub(range.off);
    let cst = f.new_const(f.spaces.get(range.space).addr_size, overlap);
    let newop = f.new_op(OpCode::Subpiece, seq, vec![whole, cst]);
    // `opSetOutput(newop, vn)` — the OLD varnode becomes the SUBPIECE's output (heritage.cc:396).
    f.op_set_output(newop, vn);
    f.vn_mut(vn).set_write_mask();
    f.op_insert_before(newop, op);
    whole
}

/// Faithful port of `Heritage::guard` (`heritage.cc:1156`), the per-range normalization that makes
/// phi placement and renaming work: every free read and every write in the range narrower than the
/// range is widened to the range's exact `(base, size)`, and the resulting whole-range Varnodes are
/// marked `activeHeritage` so `rename` picks up exactly them.
///
/// There is NO widening condition here and no batch pre-pass — normalization fires for EVERY
/// heritaged range on EVERY pass, because `placeMultiequals` hands `guard()` that range's own read
/// and write sets. (The pass-0 batch heuristics mosura carried instead could not do this: a global
/// pre-pass has no per-range read/write sets to key on.)
///
/// `add_indirects` is the range's `newAddresses()` property (`heritage.cc:2629`): the INDIRECT
/// guards go in only for a range with addresses new this pass, because "having multiple INDIRECT
/// guards for the same address confuses the renaming algorithm" (`heritage.cc:1186`).
fn guard(
    f: &mut Funcdata,
    range: &MemRange,
    add_indirects: bool,
    read: &mut [VarnodeId],
    write: &mut [VarnodeId],
) {
    let mut slot = 0;
    while slot < read.len() {
        let vn = read[slot];
        let descend = f.vn(vn).descend.clone();
        // `removeRevisitedMarkers` may have eliminated the descendant (heritage.cc:1167).
        let Some(&op) = descend.first() else { continue };
        if descend.len() > 1 {
            // Ghidra throws LowlevelError("Free varnode with multiple reads") here. mosura's op
            // graph can legitimately hold the same free varnode in two slots of one op (a
            // self-compare `x == x`), which Ghidra's set also admits, so take the first reader:
            // the SUBPIECE it defines replaces the varnode for ALL its readers anyway, because
            // `op_set_output` re-points the varnode's def rather than any single use.
        }
        if f.vn(vn).size < range.size {
            read[slot] = normalize_read_size(f, vn, op, range);
        }
        let v = read[slot];
        f.vn_mut(v).set_active_heritage();
        slot += 1;
    }
    let mut slot = 0;
    while slot < write.len() {
        let vn = write[slot];
        if f.vn(vn).size < range.size {
            write[slot] = normalize_write_size(f, vn, range);
        }
        let v = write[slot];
        f.vn_mut(v).set_active_heritage();
        slot += 1;
    }

    // The full syntax tree may form over several stages, so we see a new free for an address that
    // has already been guarded before (heritage.cc:1184-1198).
    if add_indirects {
        let loc = range.loc();
        guard_calls(f, loc);
        guard_returns(f, loc);
        guard_stores(f, loc);
    }
}

/// Faithful port of `Heritage::concatPieces` (`heritage.cc:507`): PIECE a list of Varnodes (ordered
/// most- to least-significant) into `finalvn`. With `insertop = None` the expression is built at the
/// start of the entry block, at the function's own address — Ghidra's `guardInput` case.
fn concat_pieces(
    f: &mut Funcdata,
    vnlist: &[VarnodeId],
    insertop: Option<OpId>,
    finalvn: VarnodeId,
) -> VarnodeId {
    let mut preexist = vnlist[0];
    let seq = match insertop {
        Some(op) => f.op(op).seqnum,
        None => super::op::SeqNum { pc: f.addr, uniq: 0 },
    };
    for i in 1..vnlist.len() {
        let vn = vnlist[i];
        // Little-endian input order (Ghidra's `else` at heritage.cc:542): the running high half is
        // PIECE's least-significant input. mosura's decompiler carries no endianness flag — the
        // big-endian branch (`heritage.cc:539`) is unrepresentable here, exactly as in
        // [`normalize_write_size`]; it re-enables with the multi-arch work (task #5).
        let newop = f.new_op(OpCode::Piece, seq, vec![vn, preexist]);
        let newvn = if i == vnlist.len() - 1 {
            f.op_set_output(newop, finalvn);
            finalvn
        } else {
            f.new_output_unique(newop, f.vn(preexist).size + f.vn(vn).size)
        };
        match insertop {
            Some(op) => f.op_insert_before(newop, op),
            None => f.op_insert_begin(newop, super::block::BlockId(0)),
        }
        preexist = newvn;
    }
    preexist
}

/// Faithful port of `Heritage::guardInput` (`heritage.cc:1952`): make sure the Varnodes already
/// marked as function input cover the range ENTIRELY, creating input Varnodes for any holes, then
/// PIECE them all into a single whole-range Varnode so the renaming algorithm sees one Varnode.
///
/// This is the mechanism behind Ghidra's cover including input varnodes (`heritage.cc:2704`): a
/// range that a callee reads at several widths is presented to rename as ONE input.
fn guard_input(f: &mut Funcdata, range: &MemRange, input: &[VarnodeId]) {
    use super::space::Address;
    if input.is_empty() {
        return;
    }
    // A single input that fills everything gets linked in automatically (heritage.cc:1956-1958).
    if input.len() == 1 && f.vn(input[0]).size == range.size {
        return;
    }
    let mut i = 0usize;
    let mut cur = range.off;
    let end = range.off.wrapping_add(range.size as u64);
    let mut newinput: Vec<VarnodeId> = Vec::new();
    while cur < end {
        let vn = if i < input.len() {
            let existing = input[i];
            if f.vn(existing).loc.offset > cur {
                let sz = (f.vn(existing).loc.offset - cur) as u32;
                let hole = f.new_varnode(sz, Address::new(range.space, cur));
                f.set_input_varnode(hole)
            } else {
                i += 1;
                existing
            }
        } else {
            let sz = (end - cur) as u32;
            let tail = f.new_varnode(sz, Address::new(range.space, cur));
            f.set_input_varnode(tail)
        };
        cur += f.vn(vn).size as u64;
        newinput.push(vn);
    }
    if newinput.len() == 1 {
        return; // Will get linked in automatically (heritage.cc:1996).
    }
    for &v in &newinput {
        f.vn_mut(v).set_write_mask();
    }
    let newout = f.new_varnode(range.size, Address::new(range.space, range.off));
    let joined = concat_pieces(f, &newinput, None, newout);
    f.vn_mut(joined).set_active_heritage();
}

/// Faithful port of `Heritage::placeMultiequals` (`heritage.cc:2599`): ONE loop over the disjoint
/// task list, doing all of a range's SSA preparation in Ghidra's order before moving to the next —
/// `collect` (:2609), the refinement carve-out (:2610), the empty-range early-outs (:2619-2625),
/// `removeRevisitedMarkers` (:2627), `guardInput` (:2628), `guard` (:2629), then phi placement
/// (:2630-2642). Renaming happens once afterwards, over all ranges (`heritage.cc:2749-2750`).
///
/// THE INVARIANT THIS ESTABLISHES: after `guard()`, every `activeHeritage` Varnode of a range sits
/// at exactly `(range.space, range.off, range.size)`. Ghidra then keys its rename stacks on the
/// ADDRESS alone (`varstack[vn->getAddr()]`, `heritage.cc:2498`); mosura's stacks are keyed on the
/// full `(space, offset, size)` tuple, which — given the invariant — names the same thing. That is
/// why the phi/rename machinery below needs no change to reconstruct Ghidra's whole-range SSA:
/// the merge happens HERE, in the cover, not in the renamer.
fn place_multiequals(f: &mut Funcdata, dom: &Dominators, disjoint: &mut TaskList) -> u32 {
    let internal = super::space::SpaceKind::Internal;
    // The ranges actually brought into SSA form this pass — the cover the phi/rename walk uses.
    let mut cover: Vec<MemRange> = Vec::new();
    let mut locset = LocSet::build(f);
    let mut i = 0usize;
    while i < disjoint.len() {
        let mut memrange = disjoint.ranges()[i];
        let (mut c, maxsize) = collect(f, &locset, &mut memrange);
        // THE REFINEMENT CARVE-OUT at its real slot (heritage.cc:2610-2616): a range wider than
        // 4 bytes that no single write covers is partitioned at the common access boundaries
        // BEFORE guard/normalize see it — the interception point whose absence produced the
        // mechanism-A wide values (PIECE + INT_RIGHT from `normalize_write_size` servicing
        // overlapping stack accesses; docs/compilable-c-remediation.md). The hold on this wiring
        // is RESOLVED: the downstream consumers it waited for — `ParamListStandard::fillinMap`
        // (recover.rs `fillin_map`) and the call-output `findPreexistingWhole` 2-trial reassembly
        // (ActionActiveReturn) — are both ported now.
        if memrange.size > 4 && maxsize < memrange.size {
            if let Some(newpos) = refinement(f, disjoint, i, &c) {
                // varnodes were split and replaced — the collection snapshot is stale
                locset = LocSet::build(f);
                i = newpos;
                memrange = disjoint.ranges()[i];
                let (c2, _) = collect(f, &locset, &mut memrange);
                c = c2;
            }
        }
        if c.read.is_empty() {
            if c.write.is_empty() && c.input.is_empty() {
                i += 1;
                continue;
            }
            if f.spaces.get(memrange.space).kind == internal || memrange.old_addresses() {
                i += 1;
                continue;
            }
        }
        if !c.remove.is_empty() {
            remove_revisited_markers_at(f, &c.remove, &memrange);
            locset = LocSet::build(f);
        }
        guard_input(f, &memrange, &c.input);
        guard(f, &memrange, memrange.new_addresses(), &mut c.read, &mut c.write);
        cover.push(memrange);
        i += 1;
    }
    if cover.is_empty() {
        return 0;
    }
    place_phis_and_rename(f, dom);
    cover.len() as u32
}

/// Perform ONE heritage pass (Ghidra's `Heritage::heritage`, `heritage.cc:2663` — one call is one
/// pass). Brings into SSA form the per-LOCATION cover newly eligible at the current `f.heritage_pass`:
/// each candidate location is classified by `globaldisjoint.add` and added to the cover when it is
/// new (intersect 0/1) or when an already-heritaged location is read through a freed Varnode
/// (intersect 2 with a free read — Ghidra's re-heritage path, `heritage.cc:2711`). Registers
/// (delay 0) heritage before `ram`/`stack` (delay 1). Returns the number of locations heritaged.
///
/// State persists on `f` across calls, so the outer mainloop can interleave param recovery /
/// simplification between passes (that interleaving is the payoff). Run back-to-back via
/// [`heritage`] the passes reproduce the full single-pass SSA — a location heritaged in an earlier
/// pass is recorded in `globaldisjoint` and skipped, so the per-location split is output-identical.
/// Ghidra `Heritage::deadRemovalAllowed` (heritage.cc:2829): may dead-code removal touch this space
/// yet? A space is protected until it has actually been through heritage — before that its Varnodes
/// are still free, nothing links them to their reaching defs, and "nothing reads this" is evidence
/// that SSA has not been built, not that the value is dead. Ghidra's own comment at the call site
/// (coreaction.cc:3954) is "Mark consumed if we have NOT heritaged".
///
/// Read by BOTH removal mechanisms, exactly as in Ghidra: `ActionDeadCode`'s pre-live seeding
/// (coreaction.cc:3950) and `RuleEarlyRemoval` (ruleaction.cc:38, via `deadRemovalAllowedSeen` —
/// whose extra job is latching the `deadremoved` flag for a re-heritage warning mosura does not
/// model, so only the predicate is shared).
pub fn dead_removal_allowed(f: &Funcdata, spc: SpaceId) -> bool {
    f.heritage_pass > f.spaces.get(spc).deadcodedelay
}

/// Ghidra `Heritage::deadRemovalAllowedSeen` (heritage.cc:2843): the same predicate, but it also
/// LATCHES that Varnodes have now been eliminated in this space.
///
/// Ghidra keeps the latch on the per-space `HeritageInfo`; mosura rebuilds those on every
/// `build_info_list`, so the flag lives on the Funcdata. Only `RuleEarlyRemoval` (ruleaction.cc:39)
/// uses this variant — `ActionDeadCode` (coreaction.cc:3952/4028) uses the non-latching one.
///
/// The latch is what makes [`bump_deadcode_delay`] reachable: a range re-heritaged AFTER dead code
/// was removed from its space means the earlier SSA was built on incomplete information, and the
/// only sound response is to delay dead-code removal for that space and start the decompile over.
pub fn dead_removal_allowed_seen(f: &mut Funcdata, spc: SpaceId) -> bool {
    let res = dead_removal_allowed(f, spc);
    if res {
        if f.deadremoved.len() <= spc.0 as usize {
            f.deadremoved.resize(spc.0 as usize + 1, 0);
        }
        f.deadremoved[spc.0 as usize] = 1;
    }
    res
}

/// Ghidra `Heritage::bumpDeadcodeDelay` (heritage.cc:2571): delay dead-code removal one more pass
/// for this space and ask for a whole-decompile restart.
///
/// The delay is installed as an OVERRIDE precisely because `Funcdata::clear` preserves overrides
/// (funcdata.cc:106) — it has to survive the restart, or the restart would rediscover the same
/// problem and spin.
pub fn bump_deadcode_delay(f: &mut Funcdata, spc: SpaceId) {
    // Only a processor or spacebase space gets a delay.
    if !f.spaces.get(spc).is_heritaged() {
        return;
    }
    if f.spaces.get(spc).delay != f.spaces.get(spc).deadcodedelay {
        return; // there is already a global delay
    }
    if f.deadcode_delay_override.contains_key(&spc) {
        return; // a delay has already been installed
    }
    if std::env::var("MOSURA_RESTART_DEBUG").is_ok() {
        eprintln!("RESTART bump on space {}", f.spaces.get(spc).name);
    }
    let bumped = f.spaces.get(spc).deadcodedelay + 1;
    f.deadcode_delay_override.insert(spc, bumped);
    f.restart_pending = true;
}

/// Has this space had dead code removed from it already (Ghidra `HeritageInfo::deadremoved`)?
fn dead_removed(f: &Funcdata, spc: SpaceId) -> bool {
    f.deadremoved.get(spc.0 as usize).copied().unwrap_or(0) > 0
}

/// Ghidra `Heritage::clearStackPlaceholders` (heritage.cc:2048): tear down every call site's
/// stack-pointer tracker. Called once per space carrying placeholders, immediately before that space
/// is heritaged — by then the tracker has either done its job (`RuleLoadVarnode` resolved it during
/// the rule pool and it removed itself) or it never will, and either way the artificial CALL input
/// must not be present while the stack space is renamed.
///
/// The walk is over the live CALL ops in block order rather than over `call_specs`' keys: the map is
/// a `HashMap`, and this function creates and destroys ops, so iterating it would make op numbering —
/// and therefore the output — depend on hash order.
pub fn clear_stack_placeholders(f: &mut Funcdata) {
    let calls: Vec<OpId> = (0..f.num_blocks() as u32)
        .flat_map(|b| f.block(super::block::BlockId(b)).ops.clone())
        .filter(|&op| matches!(f.op(op).code(), OpCode::Call | OpCode::Callind))
        .collect();
    for call in calls {
        super::fspec::abort_spacebase_relative(f, call);
    }
}

pub fn heritage_pass(f: &mut Funcdata, dom: &Dominators) -> u32 {
    if f.num_blocks() == 0 {
        return 0;
    }
    let pass = f.heritage_pass;
    // (The pass-0 `refine_overlaps` laned pre-partition is RETIRED: it was the hand-scoped
    // stand-in for the `refinement()` carve-out, which now runs at its real slot inside
    // `place_multiequals` — general over spaces, laned registers included. Ghidra has exactly
    // one refinement mechanism; so does mosura now.)
    let _ = pass;
    // (The hoisted `refine_ranges` re-entry pre-partition is RETIRED with `refine_overlaps`:
    // both were stand-ins for the `refinement()` carve-out, which now runs at Ghidra's slot
    // inside `place_multiequals` on every pass — re-entry ranges included, with no
    // pre-granulation needed.)

    // Build `disjoint` — Ghidra's per-pass task list (`Heritage::heritage`, heritage.cc:2684-2748).
    // For every eligible space in index order, walk its Varnodes in ADDRESS order, feed each into
    // `globaldisjoint` and queue the MERGED range it lands in. The merge is the whole point: an `AL`
    // write and an `EAX` read return the SAME `(base, size)`, so they become ONE task, and `guard()`
    // then normalizes both to it.
    let infos = build_info_list(&f.spaces);
    // Ghidra `Heritage::heritage` (heritage.cc:2688-2689): a space that carries call placeholders has
    // them cleared just before that space enters SSA construction. Hoisted ahead of the `LocSet`
    // build below: Ghidra walks each space's locations lazily, AFTER clearing that space, while
    // mosura collects every space's locations up front — so the clear has to precede the collection
    // for both to see the same graph.
    //
    // Ghidra latches `info->hasCallPlaceholders = false` so this happens once; mosura rebuilds the
    // info list each pass, so it re-runs on every pass at or after the delay. That is harmless
    // because `abort_spacebase_relative` is a no-op once the slot has been released.
    if infos.iter().any(|info| info.is_heritaged() && pass >= info.delay && info.has_call_placeholders)
    {
        clear_stack_placeholders(f);
    }
    let t0 = std::time::Instant::now();
    let locset = LocSet::build(f);
    let mut disjoint = TaskList::default();
    for (i, info) in infos.iter().enumerate() {
        if !info.is_heritaged() || pass < info.delay {
            continue; // Not heritaged, or too soon to heritage this space (heritage.cc:2686-2687).
        }
        let space = SpaceId(i as u32);
        let Some(entries) = locset.per_space.get(&space) else { continue };
        for &(off, size, _, _, vid) in entries {
            let vn = f.vn(vid);
            // heritage.cc:2704 — the cover keeps a Varnode that is written, or read, or unaffected,
            // or an input. (mosura's op-derived LocSet cannot yet see a free input / unaffected
            // register with NO descendants; that is Stage B of task #6.)
            if !vn.is_written() && vn.descend.is_empty() && !vn.is_unaffected() && !vn.is_input() {
                continue;
            }
            if vn.is_write_mask() {
                continue; // heritage.cc:2706
            }
            let (base, msize, prev) = f.globaldisjoint.add(space, off, size, pass);
            if prev == 0 {
                // All new location being heritaged, or intersecting with something new (:2709).
                disjoint.add(space, base, msize, MemRange::NEW_ADDRESSES);
            } else if prev == 2 {
                // Completely contained in a range from a previous pass (:2711).
                let vn = f.vn(vid);
                if vn.is_heritage_known() {
                    continue; // Don't heritage if we don't have to (:2712)
                }
                if vn.descend.is_empty() {
                    continue; // :2713
                }
                // Re-heritaging a location in a space that has already had Varnodes eliminated
                // (heritage.cc:2714-2718): the earlier SSA was built on incomplete information, so
                // delay this space's dead-code removal a pass and restart the decompile. Ghidra
                // gates on `!isJumptableRecoveryOn()`, which is mosura's `table_recovery_probe`:
                // a recovery partial is throwaway, so restarting the real decompile for it would
                // be wrong.
                if dead_removed(f, space) && !f.table_recovery_probe {
                    bump_deadcode_delay(f, space);
                }
                disjoint.add(space, base, msize, MemRange::OLD_ADDRESSES);
            } else {
                // Partially contained in an old range, but may contain new stuff (:2722).
                disjoint.add(
                    space,
                    base,
                    msize,
                    MemRange::OLD_ADDRESSES | MemRange::NEW_ADDRESSES,
                );
            }
        }
    }
    if super::action::perf::enabled() {
        super::action::perf::record("heritage", "build_disjoint", t0.elapsed());
    }
    f.heritage_pass += 1;
    if disjoint.is_empty() {
        return 0;
    }
    let t0 = std::time::Instant::now();
    let n = place_multiequals(f, dom, &mut disjoint);
    if super::action::perf::enabled() {
        super::action::perf::record("heritage", "place_multiequals", t0.elapsed());
    }
    n
}

/// Locations that still owe SSA form — the candidate half of [`heritage_complete`], counted
/// rather than tested, so the driver can tell a pass that made progress from one that did not.
fn outstanding(f: &Funcdata) -> usize {
    gather_candidates(f, f.heritage_pass)
        .iter()
        .filter(|(l, &has_free)| f.globaldisjoint.find_pass(l.0, l.1) == -1 || has_free)
        .count()
}

/// Build the SSA form for `f` to completion in one call — the convenience driver for the alias
/// probe and unit tests. Drives [`heritage_pass`] over every delay group back-to-back; the
/// iterating mainloop instead re-invokes `heritage_pass` one pass at a time so other actions run
/// between passes.
///
/// # Why this stops on stalled progress
///
/// Ghidra has no such driver: `Heritage::heritage` (heritage.cc:2663) is a **single** pass that
/// ends with `pass += 1`, and the repetition comes from `ActionHeritage` being re-entered by the
/// mainloop, whose restart group is itself bounded (`ActionRestartGroup(...,"universal",1)`,
/// coreaction.cc:5474 — Ghidra allows exactly one restart, then warns and gives up). This loop is
/// ours, so the bound has to be ours too.
///
/// Without one it can spin forever, and does. A `signl.c` module of Open Watcom's `clib3r.lib`
/// reaches heritage with overlapping unaligned stack locations (offsets 512/514/518/519/523) that
/// stay `has_free` after being heritaged: every pass manufactures ~10 more ops for the same five
/// locations, the block count never moves, and the op count climbs without limit. Nothing
/// downstream could recover — a whole database build hung on one 569-byte module.
///
/// So the loop stops when a pass fails to reduce the outstanding set *and* no space is still
/// waiting for its delay. Progress is the loop's own termination argument, and the delay check is
/// what keeps the register→stack handover — which legitimately introduces new candidates — from
/// reading as a stall. A function that stops here leaves some locations out of SSA, exactly as
/// Ghidra's exhausted restart group leaves a function partly analyzed.
/// Returns whether SSA was actually reached. **Check it.** The graph a stalled run leaves behind
/// is half-built, so anything derived from it is derived from nothing — see the alias probe in
/// `pipeline.rs`, whose caller falls back to the conservative boundary rather than believing a
/// result computed on such a graph.
#[must_use]
pub fn heritage(f: &mut Funcdata, dom: &Dominators) -> bool {
    if f.num_blocks() == 0 {
        return true;
    }
    let mut previous = usize::MAX;
    while !heritage_complete(f) {
        let pending_delay =
            build_info_list(&f.spaces).iter().any(|i| i.is_heritaged() && f.heritage_pass <= i.delay);
        let remaining = outstanding(f);
        if !pending_delay && remaining >= previous {
            return false; // a pass that removed nothing will not remove anything next time either
        }
        previous = remaining;
        heritage_pass(f, dom);
    }
    true
}

/// Place the MULTIEQUALs for this pass's cover and run the renaming walk — the tail of Ghidra's
/// `placeMultiequals` (`heritage.cc:2630-2642`) plus `rename` (`:2587`).
///
/// Membership is the `activeHeritage` flag, not a location set: `guard()` marked exactly the
/// Varnodes it normalized into a range (plus the whole-range reads it manufactured, and the INDIRECT
/// / RETURN-COPY ends the three `guard_*` helpers created — `heritage.cc:1524`, `:1554`, `:1671`,
/// `:1684`). That is precisely Ghidra's own test (`renameRecurse`, `heritage.cc:2496/2526`), and it
/// is what makes an already-linked Varnode at the same address safe to leave alone.
fn place_phis_and_rename(f: &mut Funcdata, dom: &Dominators) {
    let nb = f.num_blocks();

    // 1. Global locations + their defining blocks (semi-pruned SSA: a location is global
    //    if some block reads it before defining it), restricted to this pass's cover.
    //    Ghidra instead feeds `calcMultiequals` the `write` vector directly and prunes nothing; the
    //    extra phis that produces are dead by construction and `ActionDeadCode` removes them, so the
    //    surviving phi set is the same. Every Varnode consulted here is `activeHeritage`, so — by
    //    the `guard()` invariant — its location IS its range.
    let mut globals: HashSet<Loc> = HashSet::new();
    let mut defblocks: HashMap<Loc, HashSet<usize>> = HashMap::new();
    for b in 0..nb {
        let mut killed: HashSet<Loc> = HashSet::new();
        for i in 0..f.blocks()[b].ops.len() {
            let op = f.blocks()[b].ops[i];
            for slot in 0..f.op(op).num_inputs() {
                let Some(vid) = f.op(op).input(slot) else { continue };
                if !f.vn(vid).is_active_heritage() {
                    continue;
                }
                let l = (f.vn(vid).loc.space, f.vn(vid).loc.offset, f.vn(vid).size);
                if !killed.contains(&l) {
                    globals.insert(l);
                }
            }
            if let Some(vid) = f.op(op).output {
                if f.vn(vid).is_active_heritage() {
                    let l = (f.vn(vid).loc.space, f.vn(vid).loc.offset, f.vn(vid).size);
                    killed.insert(l);
                    defblocks.entry(l).or_default().insert(b);
                }
            }
        }
    }

    // 2. Place MULTIEQUALs at iterated dominance frontiers of each global's def-blocks. Iterate the
    //    global locations in address order to match Ghidra: `Heritage::placeMultiequals`
    //    (heritage.cc:2599) walks the address-ordered `disjoint` cover, creating each MULTIEQUAL as
    //    it goes, and the `VarnodeLocSet` comparator `VarnodeCompareLocDef` (varnode.cc:34) orders
    //    by `getAddr()` (space, offset) then `getSize()`. Sorting `globals` by (space, offset, size)
    //    reproduces that order, replacing the randomized-per-process HashSet iteration (a non-Ghidra
    //    approximation). Output is invariant either way — this is an ordering-fidelity alignment.
    let mut globals_sorted: Vec<Loc> = globals.iter().copied().collect();
    globals_sorted.sort_by_key(|&(sp, off, sz)| (sp.0, off, sz));
    let mut phis: HashMap<(usize, Loc), OpId> = HashMap::new();
    for &l in &globals_sorted {
        let Some(defs) = defblocks.get(&l) else { continue };
        // Sorted def-block worklist so the per-location frontier walk is likewise deterministic; the
        // phi *set* is fixpoint-invariant, only the creation order (op numbering) is pinned here.
        let mut worklist: Vec<usize> = defs.iter().copied().collect();
        worklist.sort_unstable();
        let mut placed: HashSet<usize> = HashSet::new();
        while let Some(x) = worklist.pop() {
            for &d in &dom.frontier[x] {
                if placed.insert(d) {
                    let npreds = f.blocks()[d].in_edges.len();
                    let phi = f.new_multiequal(super::block::BlockId(d as u32), l.0, l.1, l.2, npreds);
                    // heritage.cc:2635 — the MULTIEQUAL's output joins this round's renaming, so the
                    // loop-carried value is pushed on the rename stack for the blocks it dominates.
                    let out = f.op(phi).output.expect("MULTIEQUAL has an output");
                    f.vn_mut(out).set_active_heritage();
                    phis.insert((d, l), phi);
                    if !defs.contains(&d) {
                        worklist.push(d);
                    }
                }
            }
        }
    }

    // 3. Rename: dominator-tree walk maintaining a per-location stack of current defs.
    // Index the phis by block up front (rename wired them by scanning the whole map per CFG
    // edge), ordered by location so the wiring order — and any SUBPIECE splice it creates —
    // is deterministic rather than HashMap-iteration order.
    let mut phis_by_block: HashMap<usize, Vec<(Loc, OpId)>> = HashMap::new();
    for (&(b, l), &op) in &phis {
        phis_by_block.entry(b).or_default().push((l, op));
    }
    for list in phis_by_block.values_mut() {
        list.sort_by_key(|&((sp, off, sz), _)| (sp.0, off, sz));
    }
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); nb];
    for c in 0..nb {
        if dom.idom[c] != c {
            children[dom.idom[c]].push(c);
        }
    }
    let mut stack: HashMap<Loc, Vec<VarnodeId>> = HashMap::new();
    let mut inputs: HashMap<Loc, VarnodeId> = HashMap::new();
    rename(f, 0, dom, &children, &phis_by_block, &mut stack, &mut inputs);
}

/// The reaching definition for `loc`: the top of its rename stack, or a (cached) function
/// input varnode if nothing defines it on this path.
fn current_def(
    f: &mut Funcdata,
    loc: Loc,
    stack: &HashMap<Loc, Vec<VarnodeId>>,
    inputs: &mut HashMap<Loc, VarnodeId>,
) -> VarnodeId {
    if let Some(top) = stack.get(&loc).and_then(|s| s.last()) {
        return *top;
    }
    *inputs
        .entry(loc)
        .or_insert_with(|| f.new_input(loc.2, super::space::Address::new(loc.0, loc.1)))
}

/// The current definition of `loc` read by op `op`, honoring Ghidra's "INDIRECTs and their op
/// really happen AT SAME TIME" rule (`renameRecurse`, heritage.cc:2506-2517). guardCalls places a
/// call's INDIRECT (both the killedbycall clobber-creation and the passthrough) immediately BEFORE
/// the call, so at the call's own reads the top-of-stack version for a range is that INDIRECT's
/// output (the post-call value). When the INDIRECT's causing op (`guarded_op`, Ghidra's `getIn(1)`
/// iop) is this very op, the op must read the value BELOW the INDIRECT — its PRE-call value — so a
/// register that is both an argument and killedbycall (RDI/RSI/…) feeds the call the argument, not
/// the clobber. With only the INDIRECT on the stack, the pre-call value is the function input, so a
/// fresh input varnode is synthesized at the stack bottom (Ghidra `stack.insert(begin,·)`).
fn current_def_at_op(
    f: &mut Funcdata,
    op: OpId,
    loc: Loc,
    stack: &mut HashMap<Loc, Vec<VarnodeId>>,
    inputs: &mut HashMap<Loc, VarnodeId>,
) -> VarnodeId {
    let Some(top) = stack.get(&loc).and_then(|s| s.last()).copied() else {
        return *inputs
            .entry(loc)
            .or_insert_with(|| f.new_input(loc.2, super::space::Address::new(loc.0, loc.1)));
    };
    let same_time = f
        .vn(top)
        .def
        .is_some_and(|d| f.op(d).code() == OpCode::Indirect && f.op(d).guarded_op() == Some(op));
    if !same_time {
        return top;
    }
    let s = stack.get(&loc).unwrap();
    if s.len() >= 2 {
        return s[s.len() - 2];
    }
    // The INDIRECT is the only def ⇒ the pre-call value is the function input; synthesize one at the
    // stack bottom (Ghidra heritage.cc:2510-2512).
    let inp = f.new_input(loc.2, super::space::Address::new(loc.0, loc.1));
    stack.get_mut(&loc).unwrap().insert(0, inp);
    inp
}


#[allow(clippy::too_many_arguments)]
// `dom` is carried down the SSA rename recursion (faithful port of Funcdata's renaming walk)
#[allow(clippy::only_used_in_recursion)]
fn rename(
    f: &mut Funcdata,
    b: usize,
    dom: &Dominators,
    children: &[Vec<usize>],
    phis: &HashMap<usize, Vec<(Loc, OpId)>>,
    stack: &mut HashMap<Loc, Vec<VarnodeId>>,
    inputs: &mut HashMap<Loc, VarnodeId>,
) {
    let mut pushed: Vec<Loc> = Vec::new();
    let ops = f.blocks()[b].ops.clone();

    for op in ops {
        // Ghidra `renameRecurse` (heritage.cc:2489-2530). A MULTIEQUAL's inputs come from its
        // predecessors, not from the stack, so only its OUTPUT is processed here.
        if f.op(op).code() != OpCode::Multiequal {
            for slot in 0..f.op(op).num_inputs() {
                let Some(vid) = f.op(op).input(slot) else { continue };
                if f.vn(vid).is_heritage_known() {
                    continue; // not free (:2495)
                }
                if !f.vn(vid).is_active_heritage() {
                    continue; // Not being heritaged this round (:2496)
                }
                f.vn_mut(vid).clear_active_heritage();
                let l = (f.vn(vid).loc.space, f.vn(vid).loc.offset, f.vn(vid).size);
                let def = current_def_at_op(f, op, l, stack, inputs);
                f.op_set_input(op, slot, def);
            }
        }
        // Then push writes onto the stack (:2523-2529) — only a normalized write.
        if let Some(out) = f.op(op).output {
            if f.vn(out).is_active_heritage() {
                f.vn_mut(out).clear_active_heritage();
                let l = (f.vn(out).loc.space, f.vn(out).loc.offset, f.vn(out).size);
                stack.entry(l).or_default().push(out);
                pushed.push(l);
            }
        }
    }

    // Fill the phi argument each successor expects from this block (heritage.cc:2531-2552).
    let succs: Vec<usize> = f.blocks()[b].out_edges.iter().map(|e| e.0 as usize).collect();
    for (i, &s) in succs.iter().enumerate() {
        // Ghidra `FlowBlock::getOutRevIndex(i)` (heritage.cc:2533): the in-edge index of THIS
        // out-edge — not of the first in-edge that happens to name the same predecessor.
        //
        // The two differ whenever an edge is DUPLICATED, which a CBRANCH whose taken and
        // fall-through targets are the same block produces: the successor lists that predecessor
        // twice, and this loop visits it twice. Matching on the predecessor alone returns index 0
        // both times, so slot 0 is written twice and the second slot is never written at all. Its
        // input stays the free placeholder `new_multiequal` created, the location never becomes
        // heritage-known, and the range re-enters `disjoint` on every subsequent pass — heritage
        // never reaches a fixpoint (task #8: `guard_calls` then re-adds an INDIRECT per call per
        // pass, growing the graph without bound).
        //
        // Pairing the k-th duplicate out-edge with the k-th matching in-edge reproduces the
        // reverse index without storing one: CFG construction appends both lists in the same
        // order, so occurrence k on one side is occurrence k on the other.
        let duplicates_before = succs[..i].iter().filter(|&&t| t == s).count();
        let Some(j) = f.blocks()[s]
            .in_edges
            .iter()
            .enumerate()
            .filter(|(_, e)| e.0 as usize == b)
            .map(|(k, _)| k)
            .nth(duplicates_before)
        else {
            continue; // in/out edge lists disagree; nothing sound to wire
        };
        let phi_locs: Vec<(Loc, OpId)> = phis.get(&s).cloned().unwrap_or_default();
        for (l, phi) in phi_locs {
            // Ghidra tests the placeholder input itself (`if (!vnin->isHeritageKnown())`); mosura's
            // phi inputs are created free by `new_multiequal` and wired exactly once, per edge.
            let def = current_def(f, l, stack, inputs);
            f.op_set_input(phi, j, def);
        }
    }

    for c in &children[b] {
        rename(f, *c, dom, children, phis, stack, inputs);
    }

    for l in pushed {
        stack.get_mut(&l).unwrap().pop();
    }
}

#[cfg(test)]
mod tests {

    /// The restart chain end to end: `deadRemovalAllowedSeen` latches the space, a later
    /// `bumpDeadcodeDelay` installs a one-pass delay as an override and asks for a restart. The
    /// override is the piece Ghidra's `Funcdata::clear` preserves, so a restart converges instead
    /// of rediscovering the same problem (heritage.cc:2843/2571).
    #[test]
    fn deadcode_delay_bump_requests_one_restart_and_latches_an_override() {
        use crate::decompile::space::{Address, SpaceManager};
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);

        // Nothing latched yet, so no bump is warranted.
        assert!(!dead_removed(&f, reg));
        f.heritage_pass = f.spaces.get(reg).deadcodedelay + 1;
        assert!(dead_removal_allowed_seen(&mut f, reg), "removal is allowed past the delay");
        assert!(dead_removed(&f, reg), "and the space is now latched");

        let before = f.spaces.get(reg).deadcodedelay;
        bump_deadcode_delay(&mut f, reg);
        assert!(f.restart_pending, "a restart is requested");
        assert_eq!(f.deadcode_delay_override.get(&reg), Some(&(before + 1)), "delayed one pass");

        // A second bump is a no-op: the delay is already installed, which is what makes the
        // restart converge rather than loop.
        f.restart_pending = false;
        bump_deadcode_delay(&mut f, reg);
        assert!(!f.restart_pending, "the installed override suppresses a second request");
    }

    /// The override is what survives a rebuild, and applying it really does delay removal.
    #[test]
    fn deadcode_delay_override_applies_to_the_space() {
        use crate::decompile::space::{Address, SpaceManager};
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let base = f.spaces.get(reg).deadcodedelay;

        f.heritage_pass = base + 1;
        assert!(dead_removal_allowed(&f, reg), "allowed at the original delay");

        f.deadcode_delay_override.insert(reg, base + 1);
        f.apply_deadcode_delay_override();
        assert!(!dead_removal_allowed(&f, reg), "the delayed pass now blocks removal");
    }
    use super::*;
    use super::super::space::{SpaceKind, SpaceManager};

    /// `build_info_list` produces one faithful [`HeritageInfo`] per space: registers at
    /// delay 0, `ram`/`stack` at delay 1, the const space non-heritaged, and the stack
    /// spacebase carrying call placeholders. This is the per-space ordering the multi-pass
    /// heritage rewrite will consult (`heritage.cc:2687`).
    #[test]
    fn info_list_carries_faithful_delays() {
        let spaces = SpaceManager::standard();
        let infos = build_info_list(&spaces);
        assert_eq!(infos.len(), spaces.num_spaces());
        for (name, delay, heritaged) in
            [("const", 0, false), ("register", 0, true), ("ram", 1, true), ("stack", 1, true)]
        {
            let id = spaces.by_name(name).unwrap();
            let info = &infos[id.0 as usize];
            assert_eq!(info.delay, delay, "{name} delay");
            assert_eq!(info.deadcodedelay, delay, "{name} deadcodedelay");
            assert_eq!(info.is_heritaged(), heritaged, "{name} heritaged");
            assert_eq!(
                info.has_call_placeholders,
                spaces.get(id).kind == SpaceKind::Spacebase,
                "{name} call placeholders",
            );
        }
    }

    /// A CBRANCH whose taken and fall-through targets are the SAME block gives that block a
    /// duplicated in-edge, and its MULTIEQUAL one input per edge — including two for the one
    /// predecessor. Renaming must fill BOTH, which means using the reverse index of each out-edge
    /// (Ghidra `FlowBlock::getOutRevIndex`, heritage.cc:2533) rather than the first in-edge naming
    /// that predecessor.
    ///
    /// Matching on the predecessor alone wrote slot 0 twice and left the later slot holding the
    /// free placeholder forever: the location never became heritage-known, so its range re-entered
    /// `disjoint` every pass and heritage never reached a fixpoint (task #8 — observed on Open
    /// Watcom's `signl.c`, where each pass added another INDIRECT per call and the graph grew
    /// without bound).
    #[test]
    fn duplicate_edge_fills_every_phi_slot() {
        use super::super::block::{BlockBasic, BlockId};
        use super::super::op::SeqNum;
        use super::super::space::Address;

        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("dup", Address::new(ram, 0), spaces);
        let at = |o: u64| SeqNum { pc: Address::new(ram, o), uniq: 0 };

        // A diamond whose right arm reaches the join on BOTH of its edges:
        //     0 -> 1 -> 3
        //     0 -> 2 -> 3   (twice)
        // Block 3's in-edges are therefore [1, 2, 2] and it needs a 3-input MULTIEQUAL, because
        // blocks 1 and 2 write the same register differently. That is the exact shape observed on
        // Open Watcom's `signl.c`.
        let c = f.new_const(1, 0);
        let br0 = f.new_op(OpCode::Cbranch, at(0), vec![c]);

        let c1 = f.new_const(1, 7);
        let w1 = f.new_op(OpCode::Copy, at(1), vec![c1]);
        f.new_output(w1, 1, Address::new(reg, 0x200));

        let c2 = f.new_const(1, 9);
        let w2 = f.new_op(OpCode::Copy, at(2), vec![c2]);
        f.new_output(w2, 1, Address::new(reg, 0x200));
        let br2 = f.new_op(OpCode::Cbranch, at(3), vec![c]);

        let free = f.new_varnode(1, Address::new(reg, 0x200));
        let r = f.new_op(OpCode::Copy, at(4), vec![free]);
        f.new_output(r, 1, Address::new(reg, 0x300));

        let mut blocks = vec![BlockBasic::default(); 4];
        blocks[0].out_edges = vec![BlockId(1), BlockId(2)];
        blocks[1].out_edges = vec![BlockId(3)];
        blocks[2].out_edges = vec![BlockId(3), BlockId(3)]; // the duplicated edge
        blocks[1].in_edges = vec![BlockId(0)];
        blocks[2].in_edges = vec![BlockId(0)];
        blocks[3].in_edges = vec![BlockId(1), BlockId(2), BlockId(2)];
        let per_block: [Vec<OpId>; 4] = [vec![br0], vec![w1], vec![w2, br2], vec![r]];
        for (bi, ops) in per_block.iter().enumerate() {
            blocks[bi].ops = ops.clone();
        }
        f.set_blocks(blocks);
        for (bi, ops) in per_block.iter().enumerate() {
            for &op in ops {
                f.op_mut(op).parent = Some(BlockId(bi as u32));
            }
        }

        let dom = super::super::dominator::compute(&f);
        assert!(heritage(&mut f, &dom), "heritage must converge on a duplicated edge");

        // The join must carry a MULTIEQUAL, and EVERY one of its slots must have been renamed.
        // Without the reverse-index wiring, slot 0 is written twice and the last slot keeps the
        // free placeholder — which is the non-termination.
        let mut phis = 0usize;
        for op in f.op_ids().collect::<Vec<_>>() {
            if f.op(op).code() != OpCode::Multiequal || f.op(op).is_dead() {
                continue;
            }
            phis += 1;
            for slot in 0..f.op(op).num_inputs() {
                let vid = f.op(op).input(slot).expect("phi input present");
                assert!(
                    f.vn(vid).is_heritage_known(),
                    "MULTIEQUAL slot {slot} left free — the duplicated edge was not renamed",
                );
            }
        }
        assert!(phis > 0, "the join needs a MULTIEQUAL or this test proves nothing");
    }

    /// `LocationMap::add` reports the Ghidra intersect codes and unions overlapping ranges, while
    /// `find_pass` recovers the pass a covered address was heritaged in.
    #[test]
    fn location_map_intersect_codes() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let mut m = LocationMap::default();

        // A brand-new range ⇒ intersect 0; unheritaged elsewhere ⇒ find_pass -1.
        assert_eq!(m.add(reg, 0x10, 8, 0), (0x10, 8, 0), "new range");
        assert_eq!(m.find_pass(reg, 0x10), 0);
        assert_eq!(m.find_pass(reg, 0x14), 0, "interior address is covered");
        assert_eq!(m.find_pass(reg, 0x18), -1, "just past the range is uncovered");
        assert_eq!(m.find_pass(ram, 0x10), -1, "other space uncovered");

        // Same offset, a LATER pass, wholly contained ⇒ intersect 2 (already heritaged earlier).
        assert_eq!(m.add(reg, 0x10, 8, 1), (0x10, 8, 2), "contained in an older-pass range");
        // A sub-range from a later pass is also contained ⇒ 2.
        assert_eq!(
            m.add(reg, 0x12, 2, 1),
            (0x10, 8, 2),
            "sub-range returns the MERGED extent, not its own footprint",
        );
        // Same range re-added at the SAME pass ⇒ 0 (only meets same-pass coverage).
        assert_eq!(m.add(reg, 0x10, 8, 0), (0x10, 8, 0), "same-pass re-add");

        // A later-pass range that extends PAST an older range partially overlaps ⇒ 1.
        assert_eq!(
            m.add(reg, 0x14, 8, 2),
            (0x10, 12, 1),
            "partial overlap unions to [0x10,0x1c) and reports intersect 1",
        );
        // The union now covers [0x10, 0x1c); the merged entry keeps the older pass.
        assert_eq!(m.find_pass(reg, 0x1b), 0, "merged range covers the extension, oldest pass wins");
    }

    /// `guard_stores` (Ghidra `Heritage::guardStores`, heritage.cc:1538) inserts an INDIRECT before
    /// every STORE whose destination space equals the heritaged range's space, and only those: a
    /// `ram` range guards the `ram` STORE (not the `stack` STORE), the INDIRECT's output lands at
    /// the range with a free before-value input, and the `highPtrPossible` gate suppresses guards on
    /// the `unique` space. No corpus fixture reads a global across an aliasing indirect store in a
    /// way that survives dead-code removal, so this constructs the firing input directly.
    #[test]
    fn guard_stores_indirects_aliasing_stores() {
        use super::super::block::{BlockBasic, BlockId};
        use super::super::op::SeqNum;
        use super::super::space::Address;

        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let stack = spaces.by_name("stack").unwrap();
        let uniq = spaces.by_name("unique").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };

        // STORE(space=ram, ptr, val) and STORE(space=stack, ptr, val): in(0) is the space-const.
        let ram_sid = f.new_const(8, ram.0 as u64);
        let ram_ptr = f.new_input(8, Address::new(reg, 0x10));
        let ram_val = f.new_input(4, Address::new(reg, 0x18));
        let store_ram = f.new_op(OpCode::Store, seq, vec![ram_sid, ram_ptr, ram_val]);
        let stk_sid = f.new_const(8, stack.0 as u64);
        let stk_ptr = f.new_input(8, Address::new(reg, 0x20));
        let stk_val = f.new_input(4, Address::new(reg, 0x28));
        let store_stk = f.new_op(OpCode::Store, seq, vec![stk_sid, stk_ptr, stk_val]);

        f.set_blocks(vec![BlockBasic { ops: vec![store_ram, store_stk], ..Default::default() }]);
        for &op in &[store_ram, store_stk] {
            f.op_mut(op).parent = Some(BlockId(0));
        }

        // A `ram` range guards only the `ram` STORE, with an INDIRECT spliced right before it.
        let range = (ram, 0x4000u64, 4u32);
        guard_stores(&mut f, range);
        let ind: Vec<OpId> = f.blocks()[0]
            .ops
            .iter()
            .copied()
            .filter(|&op| f.op(op).code() == OpCode::Indirect)
            .collect();
        assert_eq!(ind.len(), 1, "exactly one INDIRECT (ram STORE only; stack STORE not guarded)");
        let indop = ind[0];
        let out = f.op(indop).output.expect("INDIRECT has an output");
        assert_eq!((f.vn(out).loc.space, f.vn(out).loc.offset, f.vn(out).size), range, "output at range");
        let before = f.op(indop).input(0).expect("INDIRECT before-value input");
        assert!(!f.vn(before).is_constant(), "before-value is a free varnode, not a constant");
        assert_eq!((f.vn(before).loc.space, f.vn(before).loc.offset, f.vn(before).size), range);
        let ops = &f.blocks()[0].ops;
        assert_eq!(ops.iter().position(|&o| o == indop).unwrap() + 1,
            ops.iter().position(|&o| o == store_ram).unwrap(), "INDIRECT is immediately before the STORE");

        // highPtrPossible: no pointer can target the `unique` space, so it is never guarded.
        guard_stores(&mut f, (uniq, 0, 4));
        assert_eq!(
            f.blocks()[0].ops.iter().filter(|&&op| f.op(op).code() == OpCode::Indirect).count(),
            1,
            "unique range adds no INDIRECT (highPtrPossible gate)",
        );
    }

    /// `guard_calls` (Ghidra `Heritage::guardCalls`, heritage.cc:1443) models each call's effect on a
    /// heritaged range: a `killedbycall` register becomes an indirect *creation* (`#0` input, an
    /// indirect-creation output — the clobber), an aliased stack slot (offset >= the alias boundary)
    /// a *passthrough* (free before-value, addr-forced output), a callee-saved register nothing, and
    /// the whole pass is inert unless `call_guards_active` (Ghidra guards only in the true heritage).
    #[test]
    fn guard_calls_models_call_effects() {
        use super::super::block::{BlockBasic, BlockId};
        use super::super::op::SeqNum;
        use super::super::space::Address;

        let Some(pm) = crate::decompile::build::test_sysv_proto_model() else { return };
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let stack = spaces.by_name("stack").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        f.proto_model = pm;
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let target = f.new_const(8, 0x400430);
        let call = f.new_op(OpCode::Call, seq, vec![target]);
        f.set_blocks(vec![BlockBasic { ops: vec![call], ..Default::default() }]);
        f.op_mut(call).parent = Some(BlockId(0));

        const RAX: u64 = 0x0; // killedbycall (caller-saved)
        const RBX: u64 = 0x18; // unaffected (callee-saved)
        let indirects = |f: &Funcdata| -> Vec<OpId> {
            f.blocks()[0].ops.iter().copied().filter(|&op| f.op(op).code() == OpCode::Indirect).collect()
        };

        // Off until enabled.
        guard_calls(&mut f, (reg, RAX, 8));
        assert!(indirects(&f).is_empty(), "no guard while call_guards_active is false");
        f.call_guards_active = true;
        f.alias_boundary = Some(-16);

        // killedbycall RAX ⇒ indirect creation: `#0` const input, indirect-creation output at range.
        guard_calls(&mut f, (reg, RAX, 8));
        let inds = indirects(&f);
        assert_eq!(inds.len(), 1, "one creation for the killedbycall register");
        let out = f.op(inds[0]).output.unwrap();
        assert!(f.vn(out).is_indirect_creation(), "output marked indirect-creation");
        assert_eq!((f.vn(out).loc.space, f.vn(out).loc.offset, f.vn(out).size), (reg, RAX, 8));
        assert!(f.vn(f.op(inds[0]).input(0).unwrap()).is_constant(), "creation input is the indirect-zero const");
        let pos = |op: OpId| f.blocks()[0].ops.iter().position(|&o| o == op).unwrap();
        assert_eq!(pos(inds[0]), pos(call) - 1, "creation spliced right before the call (Ghidra newIndirectCreation)");

        // unaffected (callee-saved) register ⇒ no guard.
        guard_calls(&mut f, (reg, RBX, 8));
        assert_eq!(indirects(&f).len(), 1, "callee-saved register is not guarded");

        // aliased stack slot (offset -8 >= boundary -16) ⇒ passthrough: free before-value, addr-forced.
        guard_calls(&mut f, (stack, (-8i64) as u64, 8));
        let inds = indirects(&f);
        assert_eq!(inds.len(), 2, "passthrough for the aliased stack slot");
        let pass = *inds.iter().find(|&&op| f.op(op).output.is_some_and(|o| f.vn(o).loc.space == stack)).unwrap();
        assert!(f.vn(f.op(pass).output.unwrap()).is_addr_force(), "passthrough output addr-forced (mapped local, holdind)");
        let before = f.op(pass).input(0).unwrap();
        assert!(!f.vn(before).is_constant() && f.vn(before).loc.space == stack, "passthrough before-value is a free stack read");

        // a stack slot below the boundary (offset -32 < -16) ⇒ not aliased ⇒ no guard.
        guard_calls(&mut f, (stack, (-32i64) as u64, 8));
        assert_eq!(indirects(&f).len(), 2, "non-aliased stack slot is left untouched");

        // a ram global ⇒ passthrough (Ghidra `lookupEffect` returns `unknown_effect` for any address
        // not in the register-only EffectRecord list): free before-value, and addr-forced because an
        // unmapped ram global is addr-tied (holdind = fl & addrtied).
        guard_calls(&mut f, (ram, 0x100074, 4));
        let inds = indirects(&f);
        assert_eq!(inds.len(), 3, "passthrough for the ram global across the call");
        let gpass = *inds.iter().find(|&&op| f.op(op).output.is_some_and(|o| f.vn(o).loc.space == ram)).unwrap();
        let gout = f.op(gpass).output.unwrap();
        assert!(!f.vn(gout).is_indirect_creation(), "ram passthrough is not a creation");
        assert!(f.vn(gout).is_addr_force(), "ram passthrough output addr-forced (global is addr-tied, holdind)");
        assert_eq!((f.vn(gout).loc.space, f.vn(gout).loc.offset, f.vn(gout).size), (ram, 0x100074, 4));
        let gbefore = f.op(gpass).input(0).unwrap();
        assert!(!f.vn(gbefore).is_constant() && f.vn(gbefore).loc.space == ram, "ram passthrough before-value is a free ram read");
        let ipos = |op: OpId| f.blocks()[0].ops.iter().position(|&o| o == op).unwrap();
        assert_eq!(ipos(gpass), ipos(call) - 1, "ram passthrough spliced right before the call (Ghidra newIndirectOp)");
    }

    /// A second range disjoint from the first is recorded independently (intersect 0), and a new
    /// range bridging two older ones reports the older overlap.
    #[test]
    fn location_map_disjoint_and_bridge() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let mut m = LocationMap::default();
        assert_eq!(m.add(reg, 0x0, 4, 0), (0x0, 4, 0));
        assert_eq!(m.add(reg, 0x10, 4, 0), (0x10, 4, 0), "disjoint new range");
        assert_eq!(m.find_pass(reg, 0x0), 0);
        assert_eq!(m.find_pass(reg, 0x10), 0);
        assert_eq!(m.find_pass(reg, 0x8), -1, "gap between ranges is uncovered");
        // A later-pass range starting inside the first and reaching into the gap ⇒ partial (1).
        assert_eq!(m.add(reg, 0x2, 6, 1), (0x0, 8, 1), "overlaps the older [0,4) on the left");
    }

    /// `guard()` (Ghidra `Heritage::guard`, heritage.cc:1156) unifies the widths of a range's
    /// accesses: the revisit shape — a RAM range `[0x100074, +4)` with a 4-byte covering write, a
    /// free 2-byte read and a 2-byte write at the base. The narrow read is REDEFINED as
    /// `SUBPIECE(r74:4, #0)` (keeping its own address, write-masked — `normalizeReadSize`,
    /// heritage.cc:396) and the narrow write is widened into a whole-range
    /// `PIECE(SUBPIECE(r74:4,#2), <write>)` (`normalizeWriteSize`, heritage.cc:416).
    ///
    /// There is NO widening precondition: normalization fires for every heritaged range on every
    /// pass, because `placeMultiequals` hands `guard()` that range's own read and write sets.
    #[test]
    fn guard_normalizes_mixed_width_range() {
        use super::super::block::{BlockBasic, BlockId};
        use super::super::op::SeqNum;
        use super::super::space::Address;

        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let base = 0x100074u64;

        // A 4-byte covering write `r74:4 = COPY in`.
        let cov_in = f.new_input(4, Address::new(reg, 0x40));
        let op_cover = f.new_op(OpCode::Copy, seq, vec![cov_in]);
        f.new_output(op_cover, 4, Address::new(ram, base));
        // A free 2-byte read at the base feeding `AX = r74:2 + #0x64`.
        let narrow_read = f.new_varnode(2, Address::new(ram, base));
        let addc = f.new_const(2, 0x64);
        let op_read = f.new_op(OpCode::IntAdd, seq, vec![narrow_read, addc]);
        let ax = f.new_output(op_read, 2, Address::new(reg, 0x0));
        // A 2-byte write at the base `r74:2 = COPY AX`.
        let op_write = f.new_op(OpCode::Copy, seq, vec![ax]);
        let narrow_write = f.new_output(op_write, 2, Address::new(ram, base));

        f.set_blocks(vec![BlockBasic { ops: vec![op_cover, op_read, op_write], ..Default::default() }]);
        for &op in &[op_cover, op_read, op_write] {
            f.op_mut(op).parent = Some(BlockId(0));
        }

        let mut range = MemRange { space: ram, off: base, size: 4, flags: MemRange::NEW_ADDRESSES };
        let locset = LocSet::build(&f);
        let (mut c, maxsize) = collect(&f, &locset, &mut range);
        assert_eq!(maxsize, 4, "the covering write sets collect's maxsize");
        assert_eq!(c.read.len(), 1, "one free read in the range");
        assert_eq!(c.write.len(), 2, "both writes are in the range");
        guard(&mut f, &range, false, &mut c.read, &mut c.write);

        // normalizeReadSize: the 2-byte read is now DEFINED by `SUBPIECE(r74:4, #0)` and write-masked.
        let read_sub = f.vn(narrow_read).def.expect("narrow read is now a SUBPIECE output");
        assert_eq!(f.op(read_sub).code(), OpCode::Subpiece, "narrow read normalized to SUBPIECE");
        assert!(f.vn(narrow_read).is_write_mask(), "normalized read is write-masked (heritage.cc:397)");
        let whole = f.op(read_sub).input(0).unwrap();
        assert_eq!(
            (f.vn(whole).loc.space, f.vn(whole).loc.offset, f.vn(whole).size),
            (ram, base, 4),
            "SUBPIECE reads the whole 4-byte range",
        );
        assert!(f.vn(whole).is_active_heritage(), "the whole-range read joins this round's renaming");
        assert_eq!(f.vn(f.op(read_sub).input(1).unwrap()).loc.offset, 0, "read overlap is 0");

        // normalizeWriteSize: the narrow write is write-masked and a whole-range PIECE now exists,
        // whose high input is `SUBPIECE(r74:4, #2)` of the range's previous value.
        assert!(f.vn(narrow_write).is_write_mask(), "narrow write is write-masked (heritage.cc:493)");
        let piece = f.blocks()[0]
            .ops
            .iter()
            .copied()
            .find(|&op| {
                f.op(op).code() == OpCode::Piece
                    && f.op(op)
                        .output
                        .is_some_and(|o| f.vn(o).loc == Address::new(ram, base) && f.vn(o).size == 4)
            })
            .expect("narrow write widened to a whole-range PIECE at r74:4");
        let most = f.op(piece).input(0).unwrap();
        let mostdef = f.vn(most).def.expect("high piece has a def");
        assert_eq!(f.op(mostdef).code(), OpCode::Subpiece, "high piece is a SUBPIECE of the old value");
        assert_eq!(f.vn(f.op(mostdef).input(1).unwrap()).loc.offset, 2, "high piece SUBPIECE at overlap 2");
    }

    /// `guard()` inserts nothing when a range's accesses already fill its width: Ghidra normalizes
    /// only `vn->getSize() < size` (heritage.cc:1172/1179), so a uniform-width range is untouched.
    #[test]
    fn guard_uniform_width_range_is_noop() {
        use super::super::block::{BlockBasic, BlockId};
        use super::super::op::SeqNum;
        use super::super::space::Address;

        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let base = 0x2000u64;

        let cov_in = f.new_input(4, Address::new(reg, 0x40));
        let op_cover = f.new_op(OpCode::Copy, seq, vec![cov_in]);
        f.new_output(op_cover, 4, Address::new(ram, base));
        let read4 = f.new_varnode(4, Address::new(ram, base));
        let addc = f.new_const(4, 1);
        let op_read = f.new_op(OpCode::IntAdd, seq, vec![read4, addc]);
        f.new_output(op_read, 4, Address::new(reg, 0x0));

        f.set_blocks(vec![BlockBasic { ops: vec![op_cover, op_read], ..Default::default() }]);
        for &op in &[op_cover, op_read] {
            f.op_mut(op).parent = Some(BlockId(0));
        }
        let before = f.blocks()[0].ops.len();
        let mut range = MemRange { space: ram, off: base, size: 4, flags: MemRange::NEW_ADDRESSES };
        let locset = LocSet::build(&f);
        let (mut c, _) = collect(&f, &locset, &mut range);
        guard(&mut f, &range, false, &mut c.read, &mut c.write);
        assert_eq!(f.blocks()[0].ops.len(), before, "no ops inserted");
        assert!(
            !f.blocks()[0].ops.iter().any(|&op| matches!(f.op(op).code(), OpCode::Subpiece | OpCode::Piece)),
            "uniform-width range untouched",
        );
    }

    /// THE HEADLINE PROPERTY of the heritage core: a sub-register write and a containing wide read
    /// land in ONE heritaged range. `LocationMap::add` returns the MERGED extent (heritage.cc:2708),
    /// and `TaskList::add` keeps the task list disjoint — so an `AL:1` write and an `EAX:4` read
    /// become a single `register:0x0:4` task rather than two independent SSA variables.
    ///
    /// This is the mechanism behind the multi-width AL/EAX wrong-code class: with the two split
    /// apart, the wide read bound to a stale def and everything downstream correctly deleted real
    /// code. Abutting-but-disjoint accesses are faithfully NOT merged (`Address::overlap` is -1 for
    /// an exactly-adjacent range), which the `0x10:4` / `0x14:4` pair pins.
    #[test]
    fn merged_cover_unifies_subregister_and_containing_read() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let mut m = LocationMap::default();
        let mut tasks = TaskList::default();

        // Address order, as the cover walk feeds them: AL:1 then EAX:4, both at register offset 0.
        let (b0, s0, _) = m.add(reg, 0x0, 1, 0);
        tasks.add(reg, b0, s0, MemRange::NEW_ADDRESSES);
        let (b1, s1, _) = m.add(reg, 0x0, 4, 0);
        assert_eq!((b1, s1), (0x0, 4), "the EAX read merges AL into a 4-byte range");
        tasks.add(reg, b1, s1, MemRange::NEW_ADDRESSES);
        assert_eq!(
            tasks.ranges(),
            &[MemRange { space: reg, off: 0x0, size: 4, flags: MemRange::NEW_ADDRESSES }],
            "AL and EAX are ONE heritage task, not two",
        );

        // Two abutting 4-byte locations stay separate (overlap is -1 for adjacency).
        let (b2, s2, _) = m.add(reg, 0x10, 4, 0);
        tasks.add(reg, b2, s2, MemRange::NEW_ADDRESSES);
        let (b3, s3, _) = m.add(reg, 0x14, 4, 0);
        tasks.add(reg, b3, s3, MemRange::NEW_ADDRESSES);
        assert_eq!(tasks.ranges().len(), 3, "abutting ranges are NOT merged");
        assert_eq!(tasks.ranges()[1].size, 4);
        assert_eq!(tasks.ranges()[2].off, 0x14);
    }

/// The `placeMultiequals` refinement carve-out (heritage.cc:2610, ported at its real slot in
    /// [`place_multiequals`] via [`refinement`]) partitions a range no single write covers —
    /// concatsplit's shape: two 8-byte lane writes plus a 16-byte re-load. The partition is
    /// [8,8]; `refineRead`/`concatPieces` rewrite the 16-byte read as `PIECE(hi, lo)` of free
    /// 8-byte piece reads; the lane writes already fit their pieces and are untouched.
    #[test]
    fn refinement_partitions_stack_range_by_lane_boundaries() {
        use super::super::block::{BlockBasic, BlockId};
        use super::super::op::SeqNum;
        use super::super::space::Address;

        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let stack = spaces.by_name("stack").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let base = 0u64.wrapping_sub(0x18); // s-0x18, a realistic negative stack offset

        let lo_in = f.new_input(8, Address::new(reg, 0x40));
        let w_lo = f.new_op(OpCode::Copy, seq, vec![lo_in]);
        f.new_output(w_lo, 8, Address::new(stack, base));
        let hi_in = f.new_input(8, Address::new(reg, 0x48));
        let w_hi = f.new_op(OpCode::Copy, seq, vec![hi_in]);
        f.new_output(w_hi, 8, Address::new(stack, base + 8));
        let read16 = f.new_varnode(16, Address::new(stack, base));
        let op_read = f.new_op(OpCode::Copy, seq, vec![read16]);
        f.new_output(op_read, 16, Address::new(reg, 0x1200));

        f.set_blocks(vec![BlockBasic { ops: vec![w_lo, w_hi, op_read], ..Default::default() }]);
        for &op in &[w_lo, w_hi, op_read] {
            f.op_mut(op).parent = Some(BlockId(0));
        }

        let mut disjoint = TaskList::default();
        disjoint.add(stack, base, 16, MemRange::NEW_ADDRESSES);
        let locset = LocSet::build(&f);
        let mut range = disjoint.ranges()[0];
        let (c, maxsize) = collect(&f, &locset, &mut range);
        assert!(range.size > 4 && maxsize < range.size, "the carve-out gate fires");
        let pos = refinement(&mut f, &mut disjoint, 0, &c);
        assert_eq!(pos, Some(0), "refinement replaced the range");
        let sizes: Vec<u32> = disjoint.ranges().iter().map(|r| r.size).collect();
        assert_eq!(sizes, vec![8, 8], "partition [8,8]");

        let r_in = f.op(op_read).input(0).unwrap();
        let concat = f.vn(r_in).def.expect("read input now has a def");
        assert_eq!(f.op(concat).code(), OpCode::Piece, "16-byte read split into a CONCAT");
        assert_eq!(f.vn(r_in).size, 16, "CONCAT output keeps the read's width");
        let hi = f.op(concat).input(0).unwrap();
        let lo = f.op(concat).input(1).unwrap();
        assert_eq!(
            (f.vn(hi).loc.space, f.vn(hi).loc.offset, f.vn(hi).size),
            (stack, base + 8, 8),
            "most-significant piece reads the upper lane",
        );
        assert_eq!(
            (f.vn(lo).loc.space, f.vn(lo).loc.offset, f.vn(lo).size),
            (stack, base, 8),
            "least-significant piece reads the lower lane",
        );
        assert!(!f.vn(hi).is_heritage_known() && !f.vn(lo).is_heritage_known(), "pieces are free reads");
        assert_eq!(write_loc(&f, w_lo), Some((stack, base, 8)), "lo lane write untouched");
        assert_eq!(write_loc(&f, w_hi), Some((stack, base + 8, 8)), "hi lane write untouched");
    }

    /// A range one write fully covers fails the carve-out's own gate (`max < size`,
    /// heritage.cc:2610) — that is `guard()`-normalize domain, not refinement, and
    /// `place_multiequals` never calls [`refinement`] for it.
    #[test]
    fn refinement_gate_skips_covered_range() {
        use super::super::block::{BlockBasic, BlockId};
        use super::super::op::SeqNum;
        use super::super::space::Address;

        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let stack = spaces.by_name("stack").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let base = 0u64.wrapping_sub(0x18);

        let w_in = f.new_input(16, Address::new(reg, 0x1200));
        let w = f.new_op(OpCode::Copy, seq, vec![w_in]);
        f.new_output(w, 16, Address::new(stack, base));
        let read8 = f.new_varnode(8, Address::new(stack, base));
        let op_read = f.new_op(OpCode::Copy, seq, vec![read8]);
        f.new_output(op_read, 8, Address::new(reg, 0x40));

        f.set_blocks(vec![BlockBasic { ops: vec![w, op_read], ..Default::default() }]);
        for &op in &[w, op_read] {
            f.op_mut(op).parent = Some(BlockId(0));
        }

        let mut disjoint = TaskList::default();
        disjoint.add(stack, base, 16, MemRange::NEW_ADDRESSES);
        let locset = LocSet::build(&f);
        let mut range = disjoint.ranges()[0];
        let (_c, maxsize) = collect(&f, &locset, &mut range);
        assert!(
            !(range.size > 4 && maxsize < range.size),
            "covered range fails the gate — refinement is never called",
        );
        assert_eq!(
            f.op(op_read).input(0),
            Some(read8),
            "read of a covered range untouched (normalize domain, not refinement)",
        );
    }

    /// The 1-3/3-1 partition repair (`remove13Refinement`, heritage.cc:1857) inside
    /// [`refinement`]: an 8-byte range accessed 4+1+3 partitions as [4,1,3], the artificial 1-3
    /// split is merged back to 4, and the 8-byte read is CONCAT-split at [4,4] — never into 1-
    /// or 3-byte pieces.
    #[test]
    fn refinement_merges_13_partition() {
        use super::super::block::{BlockBasic, BlockId};
        use super::super::op::SeqNum;
        use super::super::space::Address;

        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let stack = spaces.by_name("stack").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let base = 0u64.wrapping_sub(0x10);

        let in0 = f.new_input(4, Address::new(reg, 0x40));
        let w0 = f.new_op(OpCode::Copy, seq, vec![in0]);
        f.new_output(w0, 4, Address::new(stack, base));
        let in1 = f.new_input(1, Address::new(reg, 0x48));
        let w1 = f.new_op(OpCode::Copy, seq, vec![in1]);
        f.new_output(w1, 1, Address::new(stack, base + 4));
        let in2 = f.new_input(3, Address::new(reg, 0x50));
        let w2 = f.new_op(OpCode::Copy, seq, vec![in2]);
        f.new_output(w2, 3, Address::new(stack, base + 5));
        let read8 = f.new_varnode(8, Address::new(stack, base));
        let op_read = f.new_op(OpCode::Copy, seq, vec![read8]);
        f.new_output(op_read, 8, Address::new(reg, 0x0));

        f.set_blocks(vec![BlockBasic { ops: vec![w0, w1, w2, op_read], ..Default::default() }]);
        for &op in &[w0, w1, w2, op_read] {
            f.op_mut(op).parent = Some(BlockId(0));
        }

        let mut disjoint = TaskList::default();
        disjoint.add(stack, base, 8, MemRange::NEW_ADDRESSES);
        let locset = LocSet::build(&f);
        let mut range = disjoint.ranges()[0];
        let (c, maxsize) = collect(&f, &locset, &mut range);
        assert!(range.size > 4 && maxsize < range.size, "the carve-out gate fires");
        let pos = refinement(&mut f, &mut disjoint, 0, &c);
        assert_eq!(pos, Some(0));
        let sizes: Vec<u32> = disjoint.ranges().iter().map(|r| r.size).collect();
        assert_eq!(sizes, vec![4, 4], "the 1-3 split merged back (remove13Refinement)");

        let r_in = f.op(op_read).input(0).unwrap();
        let concat = f.vn(r_in).def.expect("read input now has a def");
        assert_eq!(f.op(concat).code(), OpCode::Piece, "8-byte read split into a CONCAT");
        let hi = f.op(concat).input(0).unwrap();
        let lo = f.op(concat).input(1).unwrap();
        assert_eq!(
            (f.vn(lo).loc.offset, f.vn(lo).size, f.vn(hi).loc.offset, f.vn(hi).size),
            (base, 4, base + 4, 4),
            "pieces are [4,4]",
        );
        // The 1-byte write fits inside the merged piece — untouched; the 3-byte write straddles
        // nothing either (it lies inside [4,8)).
        assert_eq!(write_loc(&f, w1), Some((stack, base + 4, 1)), "1-byte write untouched");
        assert_eq!(write_loc(&f, w2), Some((stack, base + 5, 3)), "3-byte write untouched");
    }

    /// `remove_revisited_markers` (Ghidra `Heritage::removeRevisitedMarkers`, heritage.cc:244, with the
    /// `collect()` marker-detection, heritage.cc:327-338) on a widening re-entry rewrites a prior-pass
    /// MULTIEQUAL marker narrower than the widened range: the marker op becomes `SUBPIECE(big, #0)` of a
    /// fresh FREE whole-range varnode, its narrow output is write-masked, and the fresh whole read is
    /// picked up by `gather_candidates` while the narrow location is NOT re-collected — the bridge from
    /// the pass-1 `r74:2` marker to revisit's oracle `r74:2 = SUB42(r74:4, #0)`.
    #[test]
    fn remove_revisited_markers_rewrites_narrow_multiequal() {
        use super::super::block::{BlockBasic, BlockId};
        use super::super::op::SeqNum;
        use super::super::space::Address;

        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let base = 0x100074u64;

        // A free 4-byte read of the range base (the LOAD→COPY read freed by the restart) forces the
        // widening 2→4.
        let read4 = f.new_varnode(4, Address::new(ram, base));
        let use4 = f.new_op(OpCode::Copy, seq, vec![read4]);
        f.new_output(use4, 4, Address::new(reg, 0x0));
        f.set_blocks(vec![BlockBasic { ops: vec![use4], ..Default::default() }]);
        f.op_mut(use4).parent = Some(BlockId(0));
        // A prior-pass MULTIEQUAL marker at the narrow `(ram, base, 2)` (prepended to block 0).
        let phi = f.new_multiequal(BlockId(0), ram, base, 2, 2);
        let phi_out = f.op(phi).output.unwrap();

        // The 2-byte location was heritaged on an earlier pass; this pass widens to 4 — a widening
        // re-entry, the only case the brick fires (dormant otherwise).
        f.globaldisjoint.add(ram, base, 2, 0);
        // `collect` classifies the narrow prior-pass marker into `remove` (heritage.cc:329-333);
        // `placeMultiequals` then hands that list to `removeRevisitedMarkers` (:2627).
        let mut range = MemRange { space: ram, off: base, size: 4, flags: MemRange::OLD_ADDRESSES | MemRange::NEW_ADDRESSES };
        let locset = LocSet::build(&f);
        let (c, _) = collect(&f, &locset, &mut range);
        assert_eq!(c.remove.len(), 1, "the narrow prior-pass marker is collect's `remove` domain");
        remove_revisited_markers_at(&mut f, &c.remove, &range);

        // The MULTIEQUAL op is rewritten in place as `SUBPIECE(big, #0)`.
        assert_eq!(f.op(phi).code(), OpCode::Subpiece, "MULTIEQUAL marker rewritten to SUBPIECE");
        let big = f.op(phi).input(0).unwrap();
        assert_eq!(
            (f.vn(big).loc.space, f.vn(big).loc.offset, f.vn(big).size),
            (ram, base, 4),
            "SUBPIECE reads a fresh whole 4-byte range",
        );
        assert!(!f.vn(big).is_heritage_known(), "the whole-range read is a fresh FREE varnode");
        assert_eq!(f.vn(f.op(phi).input(1).unwrap()).constant_value(), 0, "overlap offset is 0");
        // The output is the SAME narrow varnode (identity preserved), now write-masked.
        assert_eq!(f.op(phi).output.unwrap(), phi_out, "output identity preserved");
        assert_eq!((f.vn(phi_out).loc.space, f.vn(phi_out).loc.offset, f.vn(phi_out).size), (ram, base, 2));
        assert!(f.vn(phi_out).is_write_mask(), "narrow output write-masked (excluded from re-collection)");
        // The SUBPIECE is placed after the block's leading MULTIEQUALs (none remain), before `use4`.
        assert!(f.blocks()[0].ops.contains(&phi), "rewritten op stays in the block");
        // The fresh whole read is a candidate; the write-masked narrow location is NOT re-collected.
        let cand = gather_candidates(&f, 1);
        assert!(cand.contains_key(&(ram, base, 4)), "fresh whole-range read is a heritage candidate");
        assert!(
            !cand.contains_key(&(ram, base, 2)),
            "write-masked narrow location not re-collected as its own candidate",
        );
    }

    /// The INDIRECT-marker case of `remove_revisited_markers`: a prior-pass passthrough INDIRECT at the
    /// narrow range is rewritten to `SUBPIECE(big, #off)`, positioned right after its causing op
    /// (Ghidra `getIn(1)` iop = mosura `guarded_op`, heritage.cc:265-272), the narrow output
    /// write-masked and its addr-force cleared (the replacement wide varnode holds the address).
    #[test]
    fn remove_revisited_markers_rewrites_narrow_indirect() {
        use super::super::block::{BlockBasic, BlockId};
        use super::super::op::SeqNum;
        use super::super::space::Address;

        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let base = 0x100074u64;

        let target = f.new_const(8, 0x400430);
        let call = f.new_op(OpCode::Call, seq, vec![target]);
        let read4 = f.new_varnode(4, Address::new(ram, base));
        let use4 = f.new_op(OpCode::Copy, seq, vec![read4]);
        f.new_output(use4, 4, Address::new(reg, 0x0));
        f.set_blocks(vec![BlockBasic { ops: vec![call, use4], ..Default::default() }]);
        f.op_mut(call).parent = Some(BlockId(0));
        f.op_mut(use4).parent = Some(BlockId(0));
        // A prior-pass passthrough INDIRECT marker at `(ram, base, 2)`, addr-forced, guarded by the call.
        let before = f.new_varnode(2, Address::new(ram, base));
        let ind = f.new_op(OpCode::Indirect, seq, vec![before]);
        f.op_mut(ind).guarded_op = Some(call);
        let ind_out = f.new_output(ind, 2, Address::new(ram, base));
        f.vn_mut(ind_out).set_addr_force();
        f.op_mut(ind).parent = Some(BlockId(0));
        f.op_insert_after(ind, call);

        f.globaldisjoint.add(ram, base, 2, 0);
        // `collect` classifies the narrow prior-pass marker into `remove` (heritage.cc:329-333);
        // `placeMultiequals` then hands that list to `removeRevisitedMarkers` (:2627).
        let mut range = MemRange { space: ram, off: base, size: 4, flags: MemRange::OLD_ADDRESSES | MemRange::NEW_ADDRESSES };
        let locset = LocSet::build(&f);
        let (c, _) = collect(&f, &locset, &mut range);
        assert_eq!(c.remove.len(), 1, "the narrow prior-pass marker is collect's `remove` domain");
        remove_revisited_markers_at(&mut f, &c.remove, &range);

        assert_eq!(f.op(ind).code(), OpCode::Subpiece, "INDIRECT marker rewritten to SUBPIECE");
        let big = f.op(ind).input(0).unwrap();
        assert_eq!(
            (f.vn(big).loc.space, f.vn(big).loc.offset, f.vn(big).size),
            (ram, base, 4),
            "SUBPIECE reads a fresh whole 4-byte range",
        );
        assert!(!f.vn(big).is_heritage_known(), "the whole-range read is a fresh FREE varnode");
        assert!(f.vn(ind_out).is_write_mask(), "narrow output write-masked");
        assert!(!f.vn(ind_out).is_addr_force(), "addr-force cleared (wide varnode holds the address)");
        let ops = &f.blocks()[0].ops;
        let pos = |op: OpId| ops.iter().position(|&o| o == op).unwrap();
        assert_eq!(pos(ind), pos(call) + 1, "SUBPIECE placed right after the causing call");
    }

    /// The return-form COPY case of `remove_revisited_markers` (heritage.cc:281): a prior-pass
    /// `guardReturns` COPY narrower than the widened range is simply unlinked (a wider return COPY is
    /// re-guarded by `guardReturns` on the widened range), leaving no SUBPIECE.
    #[test]
    fn remove_revisited_markers_unlinks_narrow_return_copy() {
        use super::super::block::{BlockBasic, BlockId};
        use super::super::op::SeqNum;
        use super::super::space::Address;

        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let base = 0x100074u64;

        // A prior-pass return-form COPY at the narrow `(ram, base, 2)`, addr-forced + return-copy marked.
        let ret_in = f.new_varnode(2, Address::new(ram, base));
        let rcopy = f.new_op(OpCode::Copy, seq, vec![ret_in]);
        let rcopy_out = f.new_output(rcopy, 2, Address::new(ram, base));
        f.vn_mut(rcopy_out).set_addr_force();
        f.op_mut(rcopy).mark_return_copy();
        // A free 4-byte read forces the widening 2→4.
        let read4 = f.new_varnode(4, Address::new(ram, base));
        let use4 = f.new_op(OpCode::Copy, seq, vec![read4]);
        f.new_output(use4, 4, Address::new(reg, 0x0));
        f.set_blocks(vec![BlockBasic { ops: vec![rcopy, use4], ..Default::default() }]);
        f.op_mut(rcopy).parent = Some(BlockId(0));
        f.op_mut(use4).parent = Some(BlockId(0));

        f.globaldisjoint.add(ram, base, 2, 0);
        // `collect` classifies the narrow prior-pass marker into `remove` (heritage.cc:329-333);
        // `placeMultiequals` then hands that list to `removeRevisitedMarkers` (:2627).
        let mut range = MemRange { space: ram, off: base, size: 4, flags: MemRange::OLD_ADDRESSES | MemRange::NEW_ADDRESSES };
        let locset = LocSet::build(&f);
        let (c, _) = collect(&f, &locset, &mut range);
        assert_eq!(c.remove.len(), 1, "the narrow prior-pass marker is collect's `remove` domain");
        remove_revisited_markers_at(&mut f, &c.remove, &range);

        assert!(!f.blocks()[0].ops.contains(&rcopy), "return-copy removed from the block");
        assert!(f.op(rcopy).is_dead(), "return-copy op destroyed (dead)");
        assert!(
            !f.blocks()[0].ops.iter().any(|&op| f.op(op).code() == OpCode::Subpiece),
            "return-copy unlinked, not rewritten to a SUBPIECE",
        );
    }
}
