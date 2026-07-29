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
use super::space::SpaceId;
use super::varnode::VarnodeId;

/// An SSA location key: `(space, offset, size)`.
type Loc = (SpaceId, u64, u32);

/// The per-pass widening re-entry computation ([`widening_ranges`]): the merged ranges, the set of
/// range bases `(space, base)` that widened vs their prior-pass heritage, and each merged range's
/// maximum contained write size (Ghidra's `collect` `maxsize`, keyed by range base).
type WideningRanges = (LocationMap, HashSet<(SpaceId, u64)>, HashMap<(SpaceId, u64), u32>);

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
    /// access footprint. [`refine_ranges`] keys its re-entry partition on this so a location widened
    /// on a later pass takes its cumulative width.
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

    /// Ghidra `TaskList::clear`.
    pub fn clear(&mut self) {
        self.tasklist.clear();
    }

    /// Whether the list holds no ranges.
    pub fn is_empty(&self) -> bool {
        self.tasklist.is_empty()
    }
}

/// The x86-64 vector (XMM/YMM/ZMM) register file begins at register offset `0x1200`; everything
/// below it (GP/flags/segment/x87) is scalar. `movaps`/`xorps` write these *laned* registers in
/// 4-byte lanes while floats read 8 bytes, so they need Ghidra's `refinement` partition
/// ([`refine_overlaps`]) rather than the whole-range `guard()` normalize ([`normalize_ranges`]).
const XMM_BASE: u64 = 0x1200;

/// Whether a register offset falls in the laned (XMM) vector file, so its overlapping accesses are
/// partitioned by [`refine_overlaps`] and skipped by [`normalize_ranges`].
fn is_laned_register(spaces: &super::space::SpaceManager, sp: SpaceId, off: u64) -> bool {
    spaces.by_name("register") == Some(sp) && off >= XMM_BASE
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


/// This pass's merged ranges, the range bases that WIDENED vs their prior-pass heritage, and each
/// merged range's maximum contained write size — the widening re-entry computation shared by
/// [`normalize_ranges`] and [`remove_revisited_markers`] so both act on EXACTLY the same widening,
/// non-refinement ranges (a divergence would leave the hybrid IR of half-normalized re-heritage).
///
/// Builds the merged ranges in a clone of `globaldisjoint` (Ghidra's `disjoint` task list): the
/// cumulative prior-pass ranges, plus every eligible free-access footprint this pass in address order
/// (matching `beginLoc`'s address-ordered walk, `heritage.cc:2699`), so a re-entered range takes its
/// cumulative width and the LocationMap left-overlap merge is faithful. Write-masked varnodes are
/// excluded (Ghidra's `collect` skips them, `heritage.cc:326`) — a marker already rewritten to a
/// SUBPIECE by [`remove_revisited_markers`] is no longer a write of its narrow location.
///
/// A base is *widened* when its merged range is wider than the prior range covering it (`globaldisjoint`
/// holds only prior-pass ranges, so a wider merge is a genuine re-heritage of a grown range,
/// `heritage.cc:2711`). `max_write` is Ghidra's `collect` `maxsize` (`heritage.cc:336`); a range wider
/// than 4 bytes that no single write covers is Ghidra's *refinement* (partition) case
/// (`placeMultiequals`, `heritage.cc:2610`: `size > 4 && max < size`), which both callers skip (mosura
/// keeps non-laned refinement a deliberate no-op — see [`refine_overlaps`]).
fn widening_ranges(f: &Funcdata, pass: i32) -> WideningRanges {
    let infos = build_info_list(&f.spaces);
    let eligible = |sp: SpaceId| {
        let info = &infos[sp.0 as usize];
        info.is_heritaged() && info.delay <= pass
    };
    let mut footprints: Vec<Loc> = Vec::new();
    let mut writes: Vec<Loc> = Vec::new();
    for b in 0..f.num_blocks() {
        for &op in &f.blocks()[b].ops {
            for slot in 0..f.op(op).num_inputs() {
                if let Some((sp, off, sz)) = read_loc(f, op, slot) {
                    let vn = f.vn(f.op(op).input(slot).unwrap());
                    if eligible(sp)
                        && !is_laned_register(&f.spaces, sp, off)
                        && !vn.is_heritage_known()
                        && !vn.is_write_mask()
                    {
                        footprints.push((sp, off, sz));
                    }
                }
            }
            if let Some((sp, off, sz)) = write_loc(f, op) {
                if eligible(sp)
                    && !is_laned_register(&f.spaces, sp, off)
                    && !f.vn(f.op(op).output.unwrap()).is_write_mask()
                {
                    footprints.push((sp, off, sz));
                    writes.push((sp, off, sz));
                }
            }
        }
    }
    if footprints.is_empty() {
        return (LocationMap::default(), HashSet::new(), HashMap::new());
    }
    footprints.sort_unstable_by_key(|&(sp, off, sz)| (sp.0, off, sz));
    let mut merged = f.globaldisjoint.clone();
    for &(sp, off, sz) in &footprints {
        merged.add(sp, off, sz, pass);
    }
    let widened: HashSet<(SpaceId, u64)> = footprints
        .iter()
        .filter_map(|&(sp, off, _)| {
            let (base, size) = merged.merged_range(sp, off)?;
            match f.globaldisjoint.merged_range(sp, base) {
                Some((_, prior)) if size > prior => Some((sp, base)),
                _ => None,
            }
        })
        .collect();
    let mut max_write: HashMap<(SpaceId, u64), u32> = HashMap::new();
    for (sp, off, sz) in writes {
        if let Some((base, _)) = merged.merged_range(sp, off) {
            let e = max_write.entry((sp, base)).or_insert(0);
            *e = (*e).max(sz);
        }
    }
    (merged, widened, max_write)
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
/// The `info->deadremoved > 0` warning + `bumpDeadcodeDelay` branch (`heritage.cc:248-257`) is
/// omitted: mosura removes no dead code inside heritage, so the branch is unreachable here.
fn remove_revisited_markers_at(f: &mut Funcdata, remove: &[VarnodeId], range: &MemRange) {
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

/// `Heritage::splitByRefinement` (`heritage.cc:1733`): the partition pieces (in address order)
/// covering `[off, off+sz)` of a range based at `base`, or empty if the access already fits one
/// piece. `part[i]` is the size of the piece starting `i` bytes into the range.
fn split_by_refinement(base: u64, part: &[u32], off: u64, sz: u32) -> Vec<(u64, u32)> {
    let mut pieces = Vec::new();
    let mut cur = off;
    let first = part[(cur - base) as usize];
    if sz <= first {
        return pieces; // already refined — a single piece covers it
    }
    let mut rem = sz;
    pieces.push((cur, first));
    rem -= first;
    cur += first as u64;
    while rem > 0 {
        let mut c = part[(cur - base) as usize];
        if c > rem {
            c = rem; // final piece
        }
        pieces.push((cur, c));
        rem -= c;
        cur += c as u64;
    }
    pieces
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

/// Faithful port of Ghidra's heritage *refinement* for ranges materializing on a RE-ENTRY pass —
/// `Heritage::refinement` (`heritage.cc:1890`), invoked per merged range from `placeMultiequals`
/// (`heritage.cc:2608-2616`) whenever `size > 4 && max_write < size` (no single write covers the
/// range, so whole-range SSA cannot link it as one variable). The range is partitioned at the
/// boundary points of ALL its accesses (`buildRefinement`, `heritage.cc:1704`; boundary→size
/// conversion, `heritage.cc:1911-1918`; `remove13Refinement`, `heritage.cc:1857`) and every
/// boundary-crossing access is rewritten onto the partition:
///   - a *free read* spanning several pieces becomes a CONCAT of piece reads feeding a `unique`
///     that replaces it in its reader (`refineRead` :1772 + `concatPieces` :507);
///   - a *write* spanning several pieces is retargeted to a `unique` with a defining SUBPIECE per
///     piece (`refineWrite` :1806 + `splitPieces` :563), and readers of the old output are
///     re-pointed at the temp (Ghidra `totalReplace`);
///   - an *input-like* read — one no write dominates — is kept whole: mosura's landed realization
///     of `refineInput`/`guardInput` (`heritage.cc:1836`/`:1952`; see [`refine_overlaps`] and the
///     mixfloatint regression test).
///
/// The piece accesses then heritage per piece this same pass, each free piece read linking to its
/// matching-width write — reconstructing Ghidra's post-refinement SSA. This is the mechanism that
/// links concatsplit's 8-byte stack re-load to its two 4-byte lane writes
/// (`CONCAT44(param_6,param_5)`), whose absence left a read-never-written free stack varnode whose
/// lane writes dead-coded (wrong code).
///
/// SCOPE: fires only on a space's re-entry passes (`pass > delay`) — a range materializing
/// mid-mainloop when the pool's RuleLoadVarnode/RuleStoreVarnode conversions free mixed-width
/// stack/ram accesses. A space's initial pass keeps the pass-0 batch behavior
/// ([`refine_overlaps`]' laned-only partition, GP ranges skipped), so first-pass output is
/// unchanged; retiring the laned-only restriction at pass 0 is its own later gated brick (the
/// rule-pool-explosion risk named in refine_overlaps).
///
/// Range identity is the shared [`widening_ranges`] merged map, so this,
/// [`remove_revisited_markers`] and [`normalize_ranges`] act on identical range extents — Ghidra
/// sequences all three in the same `placeMultiequals` body (refinement :2611 FIRST, then
/// `removeRevisitedMarkers` :2627, then `guard()`'s normalize :2629), the order [`heritage_pass`]
/// preserves. After the partition the piece accesses are no longer refine-domain, so the
/// `is_refine_range` skips in the other two never fire on them; those skips remain as the
/// >1024/trivial-refinement guard, matching Ghidra's own bails (`heritage.cc:1896/1915`).
///
/// Ghidra's rewrite of `disjoint`/`globaldisjoint` (`heritage.cc:1926-1946`, erase the wide range
/// and re-insert the pieces at the same pass) needs no analog: mosura refines BEFORE
/// [`gather_candidates`] records this pass's locations, so only the piece-width locations ever
/// enter `globaldisjoint`. A write whose def is a heritage marker narrower than its range is
/// `removevars` domain (`collect`, heritage.cc:327-333) — excluded from the partition boundaries,
/// from the gate's max-write, and from the rewrite, exactly as Ghidra's collect segregates it —
/// and handled by [`remove_revisited_markers`] after.
fn refine_ranges(f: &mut Funcdata, dom: &Dominators, pass: i32) {
    if f.num_blocks() == 0 || pass == 0 {
        return;
    }
    let infos = build_info_list(&f.spaces);
    let reentry = |sp: SpaceId| {
        let info = &infos[sp.0 as usize];
        info.is_heritaged() && info.delay < pass
    };
    // 1. Collect the accesses (Ghidra `collect`, heritage.cc:307): free reads, and writes with
    //    their marker-ness plus block index + intra-block position for the dominating-write
    //    (input-like) test. Write-masked and laned varnodes excluded like [`widening_ranges`], so
    //    range extents match. (The rewrite step re-walks the blocks, so no op handles are kept.)
    struct RAcc {
        sp: SpaceId,
        off: u64,
        size: u32,
    }
    struct WAcc {
        sp: SpaceId,
        off: u64,
        size: u32,
        blk: usize,
        pos: usize,
        marker: bool,
    }
    let mut reads: Vec<RAcc> = Vec::new();
    let mut writes: Vec<WAcc> = Vec::new();
    for b in 0..f.num_blocks() {
        for (pos, op) in f.blocks()[b].ops.clone().into_iter().enumerate() {
            for slot in 0..f.op(op).num_inputs() {
                let Some((sp, off, sz)) = read_loc(f, op, slot) else { continue };
                let vn = f.vn(f.op(op).input(slot).unwrap());
                if reentry(sp)
                    && !is_laned_register(&f.spaces, sp, off)
                    && !vn.is_heritage_known()
                    && !vn.is_write_mask()
                {
                    reads.push(RAcc { sp, off, size: sz });
                }
            }
            if let Some((sp, off, sz)) = write_loc(f, op) {
                if reentry(sp)
                    && !is_laned_register(&f.spaces, sp, off)
                    && !f.vn(f.op(op).output.unwrap()).is_write_mask()
                {
                    let o = f.op(op);
                    let marker = o.is_marker() || o.is_return_copy();
                    writes.push(WAcc { sp, off, size: sz, blk: b, pos, marker });
                }
            }
        }
    }
    if reads.is_empty() && writes.is_empty() {
        return;
    }
    // 2. Group the accesses by their merged range and apply Ghidra's refinement gate per range
    //    (`placeMultiequals` heritage.cc:2610 `size > 4 && max < size`; `refinement` :1896
    //    `size > 1024` bail). `max` is collect()'s maxsize: every non-write-masked write except a
    //    marker narrower than the range (those hit the `remove.push_back` branch BEFORE the
    //    maxsize update, heritage.cc:329-336 — a FULL-width marker does count).
    let (merged, _, _) = widening_ranges(f, pass);
    #[derive(Default)]
    struct RangeAccs {
        size: u32,
        reads: Vec<usize>,
        writes: Vec<usize>,
    }
    let mut per_range: HashMap<(SpaceId, u64), RangeAccs> = HashMap::new();
    for (i, r) in reads.iter().enumerate() {
        if let Some((base, size)) = merged.merged_range(r.sp, r.off) {
            let e = per_range.entry((r.sp, base)).or_default();
            e.size = size;
            e.reads.push(i);
        }
    }
    for (i, w) in writes.iter().enumerate() {
        if let Some((base, size)) = merged.merged_range(w.sp, w.off) {
            let e = per_range.entry((w.sp, base)).or_default();
            e.size = size;
            e.writes.push(i);
        }
    }
    // Partition each qualifying range: buildRefinement boundary marks → piece sizes →
    // remove13Refinement, bailing when there is no internal boundary (`lastpos == 0`,
    // heritage.cc:1915 — the trivial refinement).
    let mut parts: HashMap<(SpaceId, u64), Vec<u32>> = HashMap::new();
    let mut keys: Vec<(SpaceId, u64)> = per_range.keys().copied().collect();
    keys.sort_unstable_by_key(|&(sp, base)| (sp.0, base));
    for key in keys {
        let accs = &per_range[&key];
        let size = accs.size;
        if size <= 4 || size > 1024 {
            continue;
        }
        let narrow_marker = |w: &WAcc| w.marker && w.size < size;
        let max_write = accs
            .writes
            .iter()
            .map(|&i| &writes[i])
            .filter(|w| !narrow_marker(w))
            .map(|w| w.size)
            .max()
            .unwrap_or(0);
        if max_write >= size {
            continue;
        }
        let base = key.1;
        let mut refine = vec![0u32; size as usize + 1]; // fencepost for the end position
        for &i in &accs.reads {
            let r = &reads[i];
            let d = r.off.wrapping_sub(base) as usize;
            refine[d] = 1;
            refine[d + r.size as usize] = 1;
        }
        for &i in &accs.writes {
            let w = &writes[i];
            if narrow_marker(w) {
                continue;
            }
            let d = w.off.wrapping_sub(base) as usize;
            refine[d] = 1;
            refine[d + w.size as usize] = 1;
        }
        let mut lastpos = 0usize;
        for curpos in 1..size as usize {
            if refine[curpos] != 0 {
                refine[lastpos] = (curpos - lastpos) as u32;
                lastpos = curpos;
            }
        }
        if lastpos == 0 {
            continue; // no non-trivial refinement
        }
        refine[lastpos] = size - lastpos as u32;
        refine.truncate(size as usize); // drop the fencepost
        remove13_refinement(&mut refine);
        parts.insert(key, refine);
    }
    if parts.is_empty() {
        return;
    }
    // 3. Rewrite each block: a CONCAT chain spliced before a split read, SUBPIECEs after a split
    //    write (same splice pattern as [`refine_overlaps`] step 4).
    for b in 0..f.num_blocks() {
        let ops = f.blocks()[b].ops.clone();
        let mut new_ops: Vec<OpId> = Vec::with_capacity(ops.len());
        let bid = super::block::BlockId(b as u32);
        for (pos, op) in ops.iter().copied().enumerate() {
            let seq = f.op(op).seqnum;
            // refineRead + concatPieces (heritage.cc:1772/:507, little-endian): the pieces are in
            // address order, so each next (higher) piece is the more-significant PIECE input; the
            // final unique replaces the wide free read in its reader.
            for slot in 0..f.op(op).num_inputs() {
                let Some((sp, off, sz)) = read_loc(f, op, slot) else { continue };
                if !reentry(sp) || is_laned_register(&f.spaces, sp, off) {
                    continue;
                }
                let vn = f.vn(f.op(op).input(slot).unwrap());
                if vn.is_heritage_known() || vn.is_write_mask() {
                    continue;
                }
                let Some((base, _)) = merged.merged_range(sp, off) else { continue };
                let Some(part) = parts.get(&(sp, base)) else { continue };
                let pieces = split_by_refinement(base, part, off, sz);
                if pieces.is_empty() {
                    continue; // already refined — fits a single piece
                }
                // refineInput realization (see [`refine_overlaps`]): a read no write dominates has
                // no reaching def — it is a function-input/uninitialized-stack read and stays
                // whole, linking as ONE input rather than a CONCAT of free pieces nothing rejoins.
                let has_dom_write = writes.iter().any(|w| {
                    w.sp == sp
                        && w.off < off + sz as u64
                        && off < w.off + w.size as u64
                        && dom.dominates(w.blk, b)
                        && (w.blk != b || w.pos < pos)
                });
                if !has_dom_write {
                    continue;
                }
                let pvns: Vec<VarnodeId> = pieces
                    .iter()
                    .map(|&(po, ps)| f.new_varnode(ps, super::space::Address::new(sp, po)))
                    .collect();
                let mut preexist = pvns[0];
                for (i, &pvn) in pvns.iter().enumerate().skip(1) {
                    let pieceop = f.new_op(OpCode::Piece, seq, vec![pvn, preexist]);
                    f.op_mut(pieceop).parent = Some(bid);
                    let outsz =
                        if i == pvns.len() - 1 { sz } else { f.vn(preexist).size + f.vn(pvn).size };
                    preexist = f.new_output_unique(pieceop, outsz);
                    new_ops.push(pieceop);
                }
                f.op_set_input(op, slot, preexist);
            }
            // refineWrite + splitPieces (heritage.cc:1806/:563): the op is retargeted to a unique
            // temp; each piece is a SUBPIECE of it at its byte offset, spliced after the op; the
            // old output's readers are re-pointed at the temp (Ghidra `totalReplace`).
            let mut after: Vec<OpId> = Vec::new();
            if let Some((sp, off, sz)) = write_loc(f, op) {
                if reentry(sp)
                    && !is_laned_register(&f.spaces, sp, off)
                    && !f.vn(f.op(op).output.unwrap()).is_write_mask()
                    && !f.op(op).is_marker()
                    && !f.op(op).is_return_copy()
                {
                    if let Some((base, _)) = merged.merged_range(sp, off) {
                        if let Some(part) = parts.get(&(sp, base)) {
                            let pieces = split_by_refinement(base, part, off, sz);
                            if !pieces.is_empty() {
                                let old = f.op(op).output.unwrap();
                                let old_descend = f.vn(old).descend.clone();
                                let temp = f.new_output_unique(op, sz);
                                for &(po, ps) in &pieces {
                                    let cst = f.new_const(4, po.wrapping_sub(off));
                                    let subop = f.new_op(OpCode::Subpiece, seq, vec![temp, cst]);
                                    f.op_mut(subop).parent = Some(bid);
                                    f.new_output(subop, ps, super::space::Address::new(sp, po));
                                    after.push(subop);
                                }
                                for d in old_descend {
                                    for dslot in 0..f.op(d).num_inputs() {
                                        if f.op(d).input(dslot) == Some(old) {
                                            f.op_set_input(d, dslot, temp);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            new_ops.push(op);
            new_ops.extend(after);
        }
        f.set_block_ops(bid, new_ops);
    }
}

/// Ghidra heritage *refinement* (`heritage.cc`: `refinement`/`buildRefinement`/`splitByRefinement`/
/// `refineRead`/`refineWrite`/`concatPieces`/`splitPieces`). A pre-SSA pass run over the register
/// space: in a range that no single *write* covers — so SSA cannot link it as one variable, e.g. a
/// SIMD register written in 4-byte `movaps` lanes but read as an 8-byte float — split every
/// overlapping access onto a common byte partition so each piece links cleanly. A free read wider
/// than its piece becomes a `PIECE` (CONCAT) of piece reads; a write wider than its piece becomes
/// the source of `SUBPIECE`s, one per piece. [`super::rules::RuleHumptyDumpty`] later rejoins
/// `CONCAT(SUB(V,hi), SUB(V,lo))` back to `V`.
///
/// Fires only where Ghidra's guard holds (`placeMultiequals`, `heritage.cc:2610`: range `size > 4`
/// and the largest *write* in the range is smaller than the range), so ordinary aligned
/// sub-register access (EAX of RAX, where the wide write covers the range) is untouched and most
/// functions see no change.
pub fn refine_overlaps(f: &mut Funcdata, dom: &Dominators) {
    let Some(reg) = f.spaces.by_name("register") else { return };
    // The vector (XMM/YMM/ZMM) register file begins at register offset `XMM_BASE`; everything below
    // it (GP/flags/segment/x87) is scalar. Lane refinement is needed only for these *laned* registers
    // (Ghidra's `LanedRegister`/`ActionLaneDivide` model) — `movaps`/`xorps` write them in 4-byte
    // lanes while floats read 8 bytes. Restricting the *partition* to them keeps the existing scalar
    // `Normalize` path (and the whole scalar SSA) untouched, so the change is a no-op outside SIMD code.
    let is_laned = |off: u64| off >= XMM_BASE;
    // 1. Collect every laned-register access (free reads as (op,slot); writes as op outputs).
    struct Acc {
        is_write: bool,
        off: u64,
        size: u32,
        // Block index and intra-block op position, so a read can be tested for a *dominating* write
        // to its range (Ghidra's `read` vs `input` split in `Heritage::collect`, `heritage.cc:340`).
        blk: usize,
        pos: usize,
    }
    let mut acc: Vec<Acc> = Vec::new();
    for b in 0..f.num_blocks() {
        for (pos, op) in f.blocks()[b].ops.clone().into_iter().enumerate() {
            for slot in 0..f.op(op).num_inputs() {
                if let Some((sp, off, sz)) = read_loc(f, op, slot) {
                    if sp == reg {
                        acc.push(Acc { is_write: false, off, size: sz, blk: b, pos });
                    }
                }
            }
            if let Some((sp, off, sz)) = write_loc(f, op) {
                if sp == reg {
                    acc.push(Acc { is_write: true, off, size: sz, blk: b, pos });
                }
            }
        }
    }
    if acc.is_empty() {
        return;
    }
    // 2. Union overlapping [off, off+size) intervals into the disjoint cover (Ghidra
    //    `LocationMap::add`): two accesses share a range iff their byte intervals overlap (a merely
    //    adjacent access starts a new range).
    let mut ivs: Vec<(u64, u64)> = acc.iter().map(|a| (a.off, a.off + a.size as u64)).collect();
    ivs.sort_unstable();
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for (s, e) in ivs {
        match ranges.last_mut() {
            Some(last) if s < last.1 => {
                if e > last.1 {
                    last.1 = e;
                }
            }
            _ => ranges.push((s, e)),
        }
    }
    // 3. Per range, classify: `Refine` (a PARTITION — no single write covers it, Ghidra's
    //    `placeMultiequals` guard `size > 4 && max_write < size`, kept laned-only) or `Skip`.
    //    A range a single write covers needs no partition: `guard()`'s whole-range normalize
    //    (`heritage.cc:1172-1182`, driven per range from [`place_multiequals`]) handles it, so the
    //    scalar `Normalize` mode this pass used to carry has no work left and is gone.
    enum Mode {
        Refine(Vec<u32>),
        Skip,
    }
    let modes: Vec<Mode> = ranges
        .iter()
        .map(|&(base, end)| {
            let size = (end - base) as usize;
            let max_write = acc
                .iter()
                .filter(|a| a.is_write && a.off >= base && a.off + a.size as u64 <= end)
                .map(|a| a.size as usize)
                .max()
                .unwrap_or(0);
            if is_laned(base) && size > 4 && max_write < size {
                // buildRefinement: mark each access's start and end boundary. Ghidra's `refinement`
                // (heritage.cc:2611) runs on every range that no single write covers; mosura keeps
                // the *partition* (CONCAT/SUBPIECE split) scoped to laned/XMM registers — the
                // justified subset — because the broad GP partition is what explodes the rule pool.
                // A GP range no single write covers falls through to `Skip` (left un-refined).
                let mut refine = vec![0u32; size + 1];
                for a in acc.iter().filter(|a| a.off >= base && a.off + a.size as u64 <= end) {
                    refine[(a.off - base) as usize] = 1;
                    refine[(a.off - base) as usize + a.size as usize] = 1;
                }
                // Convert boundary marks to piece sizes; bail if there is no internal boundary.
                let mut lastpos = 0usize;
                for curpos in 1..size {
                    if refine[curpos] != 0 {
                        refine[lastpos] = (curpos - lastpos) as u32;
                        lastpos = curpos;
                    }
                }
                if lastpos != 0 {
                    refine[lastpos] = (size - lastpos) as u32;
                    refine.truncate(size); // drop the fencepost
                    remove13_refinement(&mut refine);
                    return Mode::Refine(refine);
                }
            }
            Mode::Skip
        })
        .collect();
    if modes.iter().all(|m| matches!(m, Mode::Skip)) {
        return;
    }
    let range_of = |off: u64| ranges.iter().position(|&(b, e)| off >= b && off < e);
    // 4. Rewrite each block: a CONCAT before a split read, SUBPIECEs after a split write, or a
    //    SUBPIECE before a sub-read of a fully-covered range.
    for b in 0..f.num_blocks() {
        let ops = f.blocks()[b].ops.clone();
        let mut new_ops: Vec<OpId> = Vec::with_capacity(ops.len());
        let bid = super::block::BlockId(b as u32);
        for (pos, op) in ops.iter().copied().enumerate() {
            let seq = f.op(op).seqnum;
            for slot in 0..f.op(op).num_inputs() {
                let Some((sp, off, sz)) = read_loc(f, op, slot) else { continue };
                if sp != reg {
                    continue;
                }
                let Some(ri) = range_of(off) else { continue };
                let base = ranges[ri].0;
                match &modes[ri] {
                    Mode::Refine(part) => {
                        let pieces = split_by_refinement(base, part, off, sz);
                        if pieces.is_empty() {
                            continue;
                        }
                        // refineInput vs refineRead (`heritage.cc`: `refineInput@1836`/`guardInput@1952`
                        // vs `refineRead@1772`). `Heritage::collect` (`heritage.cc:340`) classifies a
                        // free Varnode with no reaching definition into `inputvars`, not `readvars`:
                        // it is a function input. `refineInput`/`guardInput` keep such an input *whole*
                        // (deriving lanes as SUBPIECEs only where separately read) instead of
                        // `refineRead`'s CONCAT of independent piece-reads. A read with no *dominating*
                        // write to its byte range has no reaching def, so it is input-like; in mosura's
                        // exact-(space,offset,size) SSA the realization is simply to leave the wide read
                        // intact, so it links as a single `param_N` rather than `CONCAT(input_hi,
                        // input_lo)` of two free pieces that nothing rejoins. Only a read fed by a
                        // dominating lane write (e.g. a return read over lane writes) is CONCAT-split so
                        // each piece links to its writer.
                        let has_dom_write = acc.iter().any(|w| {
                            w.is_write
                                && w.off < off + sz as u64
                                && off < w.off + w.size as u64
                                && dom.dominates(w.blk, b)
                                && (w.blk != b || w.pos < pos)
                        });
                        if !has_dom_write {
                            continue;
                        }
                        // refineRead + concatPieces (little-endian): pieces are in address order, so
                        // each next (higher) piece is the more-significant PIECE input.
                        let pvns: Vec<VarnodeId> = pieces
                            .iter()
                            .map(|&(po, ps)| f.new_varnode(ps, super::space::Address::new(reg, po)))
                            .collect();
                        let mut preexist = pvns[0];
                        for (i, &vn) in pvns.iter().enumerate().skip(1) {
                            let pieceop = f.new_op(OpCode::Piece, seq, vec![vn, preexist]);
                            f.op_mut(pieceop).parent = Some(bid);
                            let outsz = if i == pvns.len() - 1 {
                                sz
                            } else {
                                f.vn(preexist).size + f.vn(vn).size
                            };
                            preexist = f.new_output_unique(pieceop, outsz);
                            new_ops.push(pieceop);
                        }
                        f.op_set_input(op, slot, preexist);
                    }
                    Mode::Skip => {}
                }
            }
            // Writes: a refined write splits into SUBPIECEs after the op, spliced in `after`.
            let mut after: Vec<OpId> = Vec::new();
            if let Some((sp, off, sz)) = write_loc(f, op) {
                if sp == reg {
                    if let Some(ri) = range_of(off) {
                        let base = ranges[ri].0;
                        match &modes[ri] {
                            Mode::Refine(part) => {
                                let pieces = split_by_refinement(base, part, off, sz);
                                if !pieces.is_empty() {
                                    // refineWrite + splitPieces (little-endian): the op writes a
                                    // temp, each piece is a SUBPIECE of it at its byte offset.
                                    let temp = f.new_output_unique(op, sz);
                                    for &(po, ps) in &pieces {
                                        let cst = f.new_const(4, po - off);
                                        let subop = f.new_op(OpCode::Subpiece, seq, vec![temp, cst]);
                                        f.op_mut(subop).parent = Some(bid);
                                        f.new_output(subop, ps, super::space::Address::new(reg, po));
                                        after.push(subop);
                                    }
                                }
                            }
                            Mode::Skip => {}
                        }
                    }
                }
            }
            new_ops.push(op);
            new_ops.extend(after);
        }
        f.set_block_ops(bid, new_ops);
    }
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
        // spec's `<default_proto>`, carried on the function as `proto_model`).
        f.proto_model.has_effect(super::space::Address::new(reg, off), size)
    } else if aliased_stack || Some(spc) == ram {
        // An aliased stack slot and a ram global both fall through to Ghidra's default unknown_effect.
        effect::UNKNOWN_EFFECT
    } else {
        return;
    };
    if effecttype == effect::UNAFFECTED {
        return;
    }
    // holdind = (fl & addrtied): a mapped (addr-tied) range keeps its passthrough INDIRECT auto-live
    // via setAddrForce, so dead-code preserves the across-call chain and the write feeding it. Faithful
    // to `queryProperties` (heritage.cc:1191) + [`super::varnodeprops::mark_addrtied`]: an unmapped ram
    // global and an aliased stack slot are addr-tied; a register passthrough is not.
    let holdind = Some(spc) == ram || aliased_stack;

    let calls: Vec<OpId> = (0..f.num_blocks() as u32)
        .flat_map(|b| f.block(super::block::BlockId(b)).ops.clone())
        .filter(|&op| matches!(f.op(op).code(), OpCode::Call | OpCode::Callind))
        .collect();
    let addr = super::space::Address::new(spc, off);
    for call in calls {
        // Skip a call whose own output already IS this range (Ghidra heritage.cc:1453 isAssignment).
        if f.op(call).output.is_some_and(|o| f.vn(o).loc == addr && f.vn(o).size == size) {
            continue;
        }
        let Some(bid) = f.op(call).parent else { continue };
        if effecttype == effect::KILLEDBYCALL {
            // newIndirectCreation (mosura 1-input): out@range = INDIRECT(#0), output marked
            // indirect-creation (no realistic ancestor / the clobber). Ghidra `newIndirectCreation`
            // (funcdata_op.cc:726) splices the INDIRECT BEFORE the call with `opInsertBefore`, and
            // `collectOutputTrialVarnodes` (fspec.cc:5543) walks BACKWARD from the call to gather the
            // output trials — `resolve_call_output` mirrors that backward scan.
            let seq = f.op(call).seqnum;
            let zero = f.new_const(size, 0);
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
fn place_multiequals(f: &mut Funcdata, dom: &Dominators, disjoint: &TaskList) -> u32 {
    let internal = super::space::SpaceKind::Internal;
    // The ranges actually brought into SSA form this pass — the cover the phi/rename walk uses.
    let mut cover: Vec<MemRange> = Vec::new();
    let mut locset = LocSet::build(f);
    for r in disjoint.ranges() {
        let mut memrange = *r;
        let (mut c, _maxsize) = collect(f, &locset, &mut memrange);
        // THE REFINEMENT CARVE-OUT (heritage.cc:2610-2616) IS NOT WIRED HERE YET. Ghidra
        // partitions a range wider than 4 bytes that no single write covers, and its own
        // post-heritage IR for mixfloatint confirms the split (`CONCAT44(XMM0_Db(i),XMM0_Da(i))`).
        // The port is written and measured (held on task #6, with its per-fixture numbers): it
        // takes stackreturn to 1.000 and restores deindirect2, but its DOWNSTREAM consumer — the
        // param recovery that re-joins two adjacent input trials landing in one ParamEntry
        // (`ParamListStandard::fillinMap`) — is unported, so the split params reach the printer as
        // a CONCAT with a bogus high half. Landing it alone would be half a subsystem (AGENT.md
        // rule 2), so it waits on that consumer. Until then `refine_overlaps` covers the laned case.
        if c.read.is_empty() {
            if c.write.is_empty() && c.input.is_empty() {
                continue;
            }
            if f.spaces.get(memrange.space).kind == internal || memrange.old_addresses() {
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
pub fn heritage_pass(f: &mut Funcdata, dom: &Dominators) -> u32 {
    if f.num_blocks() == 0 {
        return 0;
    }
    let pass = f.heritage_pass;
    if pass == 0 {
        // The laned (XMM) partition. Ghidra reaches this shape through `refinement()` per range
        // (heritage.cc:2610); mosura's hand-scoped laned partition stands in until that carve-out
        // lands with its downstream param input-join consumer — see the module note above.
        let t0 = std::time::Instant::now();
        refine_overlaps(f, dom);
        if super::action::perf::enabled() {
            super::action::perf::record("heritage", "refine_overlaps", t0.elapsed());
        }
    }
    // The refinement partition for ranges materializing on a re-entry pass (Ghidra's `refinement`,
    // heritage.cc:1890, called from `placeMultiequals` :2611). Hoisted ahead of the cover build so a
    // partitioned range enters `disjoint` already piece-granular; see [`place_multiequals`].
    let t0 = std::time::Instant::now();
    refine_ranges(f, dom, pass);
    if super::action::perf::enabled() {
        super::action::perf::record("heritage", "refine_ranges", t0.elapsed());
    }

    // Build `disjoint` — Ghidra's per-pass task list (`Heritage::heritage`, heritage.cc:2684-2748).
    // For every eligible space in index order, walk its Varnodes in ADDRESS order, feed each into
    // `globaldisjoint` and queue the MERGED range it lands in. The merge is the whole point: an `AL`
    // write and an `EAX` read return the SAME `(base, size)`, so they become ONE task, and `guard()`
    // then normalizes both to it.
    let t0 = std::time::Instant::now();
    let locset = LocSet::build(f);
    let infos = build_info_list(&f.spaces);
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
                // The `deadremoved` re-heritage warning + `bumpDeadcodeDelay` (:2714-2718) is a
                // diagnostic path mosura does not model (it removes no dead code inside heritage).
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
    let n = place_multiequals(f, dom, &disjoint);
    if super::action::perf::enabled() {
        super::action::perf::record("heritage", "place_multiequals", t0.elapsed());
    }
    n
}

/// Build the SSA form for `f` to completion in one call — the convenience driver for the alias
/// probe and unit tests. Drives [`heritage_pass`] over every delay group back-to-back; the
/// iterating mainloop instead re-invokes `heritage_pass` one pass at a time so other actions run
/// between passes.
pub fn heritage(f: &mut Funcdata, dom: &Dominators) {
    if f.num_blocks() == 0 {
        return;
    }
    while !heritage_complete(f) {
        heritage_pass(f, dom);
    }
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
    for s in succs {
        let j = f.blocks()[s].in_edges.iter().position(|e| e.0 as usize == b).unwrap();
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

    /// [`refine_ranges`] (Ghidra `Heritage::refinement`, heritage.cc:1890, from `placeMultiequals`
    /// :2610) on a re-entry pass partitions a stack range no single write covers — concatsplit's
    /// shape: two 8-byte lane writes plus a 16-byte re-load, all materialized mid-mainloop by the
    /// pool's STORE/LOAD conversions. The partition is [8,8]; `refineRead`/`concatPieces` rewrite
    /// the 16-byte read as `PIECE(hi_piece, lo_piece)` of free 8-byte piece reads that heritage
    /// against the matching lane writes (the writes already fit their pieces and are untouched).
    /// On the space's INITIAL pass the same shape is left alone (the re-entry scope).
    #[test]
    fn refine_ranges_partitions_stack_range_by_lane_boundaries() {
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

        // Two 8-byte lane writes `s-0x18:8 = COPY lo` / `s-0x10:8 = COPY hi` ...
        let lo_in = f.new_input(8, Address::new(reg, 0x40));
        let w_lo = f.new_op(OpCode::Copy, seq, vec![lo_in]);
        f.new_output(w_lo, 8, Address::new(stack, base));
        let hi_in = f.new_input(8, Address::new(reg, 0x48));
        let w_hi = f.new_op(OpCode::Copy, seq, vec![hi_in]);
        f.new_output(w_hi, 8, Address::new(stack, base + 8));
        // ... and a free 16-byte re-load of the whole range feeding a register.
        let read16 = f.new_varnode(16, Address::new(stack, base));
        let op_read = f.new_op(OpCode::Copy, seq, vec![read16]);
        f.new_output(op_read, 16, Address::new(reg, 0x1200));

        f.set_blocks(vec![BlockBasic { ops: vec![w_lo, w_hi, op_read], ..Default::default() }]);
        for &op in &[w_lo, w_hi, op_read] {
            f.op_mut(op).parent = Some(BlockId(0));
        }
        let dom = super::super::dominator::compute(&f);

        // Stack's INITIAL heritage pass (pass == delay == 1): the re-entry scope leaves the range
        // to the pass-0/batch machinery — nothing is rewritten.
        refine_ranges(&mut f, &dom, 1);
        assert!(
            !f.blocks()[0].ops.iter().any(|&op| f.op(op).code() == OpCode::Piece),
            "initial pass untouched (re-entry scope)",
        );

        // Re-entry pass 2 (the mid-mainloop materialization): partition [8,8] fires.
        refine_ranges(&mut f, &dom, 2);
        // The read now goes through a CONCAT of the two piece reads: PIECE(in0 = hi more-significant
        // piece, in1 = lo piece) — little-endian concatPieces order — output a 16-byte unique.
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
        // The lane writes already match the partition — untouched.
        assert_eq!(write_loc(&f, w_lo), Some((stack, base, 8)), "lo lane write untouched");
        assert_eq!(write_loc(&f, w_hi), Some((stack, base + 8, 8)), "hi lane write untouched");
    }

    /// [`refine_ranges`] leaves a range alone when a single write covers it (`max_write == size`
    /// fails Ghidra's `placeMultiequals` gate, heritage.cc:2610) — that is `guard()`-normalize
    /// domain, not refinement.
    #[test]
    fn refine_ranges_skips_covered_range() {
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

        // A single 16-byte write covers the range; an 8-byte free read sits inside it.
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
        let dom = super::super::dominator::compute(&f);
        let before = f.blocks()[0].ops.len();
        refine_ranges(&mut f, &dom, 2);
        assert_eq!(f.blocks()[0].ops.len(), before, "no ops inserted");
        assert_eq!(
            f.op(op_read).input(0),
            Some(read8),
            "read of a covered range untouched (normalize domain, not refinement)",
        );
    }

    /// The 1-3/3-1 partition repair (`remove13Refinement`, heritage.cc:1857) inside
    /// [`refine_ranges`]: an 8-byte range accessed 4+1+3 partitions as [4,1,3], the artificial
    /// 1-3 split is merged back to 4, and the 8-byte read is CONCAT-split at [4,4] — never into
    /// 1- or 3-byte pieces.
    #[test]
    fn refine_ranges_merges_13_partition() {
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

        // Writes at +0:4, +4:1, +5:3 and a free 8-byte read over all of them: boundaries
        // {0,4,5,8} → partition [4,1,3] → remove13Refinement → [4,4].
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
        let dom = super::super::dominator::compute(&f);
        refine_ranges(&mut f, &dom, 2);

        let r_in = f.op(op_read).input(0).unwrap();
        let concat = f.vn(r_in).def.expect("read input now has a def");
        assert_eq!(f.op(concat).code(), OpCode::Piece, "8-byte read split into a CONCAT");
        let hi = f.op(concat).input(0).unwrap();
        let lo = f.op(concat).input(1).unwrap();
        assert_eq!(
            (f.vn(lo).loc.offset, f.vn(lo).size, f.vn(hi).loc.offset, f.vn(hi).size),
            (base, 4, base + 4, 4),
            "pieces are [4,4] — the 1-3 split merged back (remove13Refinement)",
        );
        // The 1- and 3-byte writes fit INSIDE the merged 4-byte piece — untouched by the rewrite.
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
