//! Heritage — building SSA form over the Varnode graph (Ghidra's `Heritage`, `heritage.cc`).
//!
//! Links every free read to its reaching definition and inserts MULTIEQUAL (phi) ops at
//! control-flow joins, via Cytron's algorithm using the dominance frontiers. Phi placement
//! is semi-pruned: only *global* locations (read in some block before being written there)
//! get phis, which keeps block-local temporaries (the `unique` space) phi-free, as Ghidra's
//! result is.
//!
//! This first pass treats each distinct `(space, offset, size)` as one SSA variable. Size
//! *overlap* (a location read at a different width than written — sub-registers, CONCAT)
//! is Ghidra's heritage *refinement* and is a later P1 sub-task; until then overlapping
//! accesses are independent variables (an under-linking, not a miswiring).

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
    /// at `pass`, unioning it with any overlapping ranges already present. Returns the *intersect*
    /// code describing the overlap with PRE-EXISTING (earlier-pass) ranges:
    ///   - `0` — the range is new, or only meets ranges from the same pass;
    ///   - `1` — it partially overlaps a range from an earlier pass;
    ///   - `2` — it is wholly contained in a range from an earlier pass (already heritaged).
    ///
    /// `Address::overlap(0, base, sz)` (`address.cc:153`) is `this - base` when `base <= this <
    /// base+sz` (same space) else `-1`; the predecessor walk and forward merge mirror the C++
    /// iterator dance against the per-space `BTreeMap` (a left-overlapping new range that starts
    /// *before* an existing one is, faithfully, NOT merged — Ghidra's `++iter` skips it).
    pub fn add(&mut self, space: SpaceId, off: u64, size: u32, pass: i32) -> i32 {
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
                    return if map[&k].pass < pass { 2 } else { 0 };
                }
                addr = k;
                size = off_in + size;
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
        intersect
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
    /// access footprint. [`normalize_ranges`] keys the per-range width normalization on this so a
    /// location widened on a later pass takes its cumulative width.
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

/// Pass-0 batch read-normalization (Ghidra's `normalizeReadSize`, heritage.cc:382). Where a
/// location is written at a single width `S` but also *read* at a smaller width `s` at the same
/// offset (a sub-register: EAX of a wider RAX def), rewrite each narrow read as `SUBPIECE(W, 0)` of
/// a full-width read `W`, so every access to the location is uniform width and SSA links it cleanly.
/// Conservative: only locations whose writes are all one width are touched; partial writes (the
/// PIECE / write side) and cross-offset overlap (CONCAT) are not handled, so those reads remain
/// independent (an under-linking, never a miswiring).
///
/// INTERIM — this is the pass-0 batch adaptation the faithful per-range [`normalize_ranges`] will
/// replace. It is single-write-width-keyed (bails on a range with two write widths) and read-only,
/// so it cannot normalize a re-heritaged range's now-narrow accesses — the gap `normalize_ranges`
/// closes for re-entry. Its RETIREMENT is coupled to the call-output-in-RAX fix (task #6): retiring
/// it now surfaces that separate adaptation (mosura's CALLIND output lands in RAX, so a whole-range
/// `guard()` normalize PIECEs a merge Ghidra never makes — deindirect2). Both land with mainloop S8-2.
fn normalize_read_size(f: &mut Funcdata) {
    let nb = f.num_blocks();
    let mut write_sizes: HashMap<(SpaceId, u64), HashSet<u32>> = HashMap::new();
    let mut read_sizes: HashMap<(SpaceId, u64), HashSet<u32>> = HashMap::new();
    for b in 0..nb {
        for op in f.blocks()[b].ops.clone() {
            for slot in 0..f.op(op).num_inputs() {
                if let Some((sp, off, sz)) = read_loc(f, op, slot) {
                    read_sizes.entry((sp, off)).or_default().insert(sz);
                }
            }
            if let Some((sp, off, sz)) = write_loc(f, op) {
                write_sizes.entry((sp, off)).or_default().insert(sz);
            }
        }
    }
    // canonical width per location: a single write width that is also read narrower
    let mut canonical: HashMap<(SpaceId, u64), u32> = HashMap::new();
    for (k, ws) in &write_sizes {
        if ws.len() == 1 {
            let s = *ws.iter().next().unwrap();
            if read_sizes.get(k).is_some_and(|rs| rs.iter().any(|&r| r < s)) {
                canonical.insert(*k, s);
            }
        }
    }
    // A register carrying the x86-64 self-zero-extension idiom `O:W = ZEXT(O:N)` is, like
    // Ghidra's full-register heritage range, canonical at `O:W`: writing the 32-bit register
    // zeroes the upper bits, so `O:W` always reflects the narrow write. Narrow reads then
    // read `SUBPIECE(O:W)` and the otherwise-parallel sub-register SSA chains unify.
    // (8/16-bit sub-registers partial-overwrite and lack this idiom, so they are untouched.)
    for b in 0..nb {
        for op in f.blocks()[b].ops.clone() {
            if f.op(op).code() != OpCode::IntZext {
                continue;
            }
            if let (Some((osp, ooff, osz)), Some((isp, ioff, isz))) = (write_loc(f, op), read_loc(f, op, 0)) {
                if osp == isp && ooff == ioff && osz > isz {
                    canonical.insert((osp, ooff), osz);
                }
            }
        }
    }
    if canonical.is_empty() {
        return;
    }
    for b in 0..nb {
        let ops = f.blocks()[b].ops.clone();
        let mut new_ops: Vec<OpId> = Vec::with_capacity(ops.len());
        for op in ops {
            for slot in 0..f.op(op).num_inputs() {
                let Some((sp, off, sz)) = read_loc(f, op, slot) else { continue };
                let Some(&s) = canonical.get(&(sp, off)) else { continue };
                if sz >= s {
                    continue;
                }
                // keep the self-zero-extension's own input (`O:W = ZEXT(O:N)`): rewriting it
                // to `SUBPIECE(O:W)` would be circular and drop the narrow value it widens
                if f.op(op).code() == OpCode::IntZext
                    && write_loc(f, op).is_some_and(|(wsp, woff, wsz)| wsp == sp && woff == off && wsz == s)
                {
                    continue;
                }
                let seq = f.op(op).seqnum;
                let w = f.new_varnode(s, super::space::Address::new(sp, off));
                let zero = f.new_const(4, 0);
                let sub = f.new_op(OpCode::Subpiece, seq, vec![w, zero]);
                let subout = f.new_output_unique(sub, sz);
                f.op_mut(sub).parent = Some(super::block::BlockId(b as u32));
                f.op_set_input(op, slot, subout);
                new_ops.push(sub); // splice the SUBPIECE in just before its reader
            }
            new_ops.push(op);
        }
        f.set_block_ops(super::block::BlockId(b as u32), new_ops);
    }
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

/// Faithful port of Ghidra's per-range width normalization — `Heritage::guard`'s read/write
/// normalize step (`heritage.cc:1172-1182`), driven for every heritaged range by
/// `Heritage::placeMultiequals` (`heritage.cc:2608-2629`), EVERY pass. For each merged range
/// `[base, base+size)` that this pass's eligible free accesses span, every *free read* narrower
/// than `size` is rewritten `SUBPIECE(whole, overlap)` (`normalizeReadSize`, `heritage.cc:382`)
/// and every *write* narrower than `size` is widened into a whole-range write reassembled by
/// PIECE (`normalizeWriteSize`, `heritage.cc:416`, via [`normalize_write_size`]), so every access
/// to the range is uniform `size` and the per-location SSA links it as one variable.
///
/// The range `size` is the cumulative `globaldisjoint` merge (`heritage.cc:2618`), queried via
/// [`LocationMap::merged_range`] on a clone seeded with `f.globaldisjoint` (the prior passes'
/// ranges) and this pass's free-access footprints — Ghidra's `disjoint` task list. Because it is
/// keyed on the cumulative width, a location WIDENED on a later pass (re-heritage) re-normalizes its
/// now-narrow accesses to the new width — e.g. revisit's RAM range `r0x100074:4`, where the 2-byte
/// `AX` write becomes `CONCAT22(SUB42(r74:4,#2), AX)` and the 2-byte reads become `SUB42(r74:4,…)`.
/// This is the mechanism the pass-0 batch heuristics (`normalize_read_size`'s single-write-width read
/// hack + [`refine_overlaps`]' register-only Normalize mode) cannot reach.
///
/// SCOPE (S8-1): this fires ONLY on **widening re-entry** — a range already heritaged at some width
/// in an earlier pass, now merged WIDER (Ghidra re-heritages a grown range, heritage.cc:2711). The
/// pass-0 batch still does all first-pass normalization, and a same-width re-read of an already-
/// heritaged range (a 2-byte `AX` inside an 8-byte `RAX` call output — deindirect2) is left to it,
/// its retirement coupled to the call-output-in-RAX fix (task #6). No range widens without the
/// mainloop restart, so this is a dormant no-op today (byte-identical) — it is the mainloop brick
/// that makes S8-2's scoped re-heritage-after-pool restart correct (revisit's `r74:2`→`r74:4`).
///
/// Structure vs Ghidra: mosura heritages each exact `(space, offset, size)` as its own SSA
/// location and runs this BEFORE candidate gathering (rather than inside `guard()`), so afterward
/// every in-range access is at the merged width and the existing per-location cover / phi / rename
/// reconstructs Ghidra's whole-range MULTIEQUAL identically. Laned/XMM ranges — Ghidra's
/// `refinement` *partition* — are excluded here and handled by [`refine_overlaps`].
fn normalize_ranges(f: &mut Funcdata, pass: i32) {
    if f.num_blocks() == 0 {
        return;
    }
    let infos = build_info_list(&f.spaces);
    let eligible = |sp: SpaceId| {
        let info = &infos[sp.0 as usize];
        info.is_heritaged() && info.delay <= pass
    };
    // Merged ranges + the widening re-entry gate (shared with [`remove_revisited_markers`]): normalize
    // only ranges that WIDENED vs a prior pass — a location already heritaged at some width, now merged
    // wider (Ghidra re-heritages a grown range, heritage.cc:2711, and `guard()` re-normalizes its
    // now-narrow accesses to the new width; revisit's `r74:2` grown to `r74:4`). A SAME-width re-read of
    // an already-heritaged range (a 2-byte `AX` contained in an 8-byte `RAX` call output — deindirect2)
    // is NOT widening and stays with the pass-0 batch. No widening happens without the mainloop restart,
    // so this is a dormant no-op on the current pipeline (byte-identical) — the brick for S8-2.
    let (merged, widened, max_write) = widening_ranges(f, pass);
    if widened.is_empty() {
        return;
    }
    // A range wider than 4 bytes that no single write covers is Ghidra's *refinement* (partition) case
    // (`placeMultiequals`, heritage.cc:2610: `size > 4 && max < size`), NOT the whole-range `guard()`
    // normalize — skipped here (mosura keeps non-laned refinement a deliberate no-op; the laned
    // partition is [`refine_overlaps`]). Normalize fires only where `guard()` would: a single write
    // covers the range, or the range is <= 4 bytes.
    let is_refine_range = |sp: SpaceId, base: u64, size: u32| {
        size > 4 && max_write.get(&(sp, base)).copied().unwrap_or(0) < size
    };
    // Apply normalizeReadSize / normalizeWriteSize per block, driven by the merged range width.
    for b in 0..f.num_blocks() {
        let ops = f.blocks()[b].ops.clone();
        let mut new_ops: Vec<OpId> = Vec::with_capacity(ops.len());
        let bid = super::block::BlockId(b as u32);
        for op in ops {
            let seq = f.op(op).seqnum;
            // Reads: a free read narrower than its merged range becomes `SUBPIECE(whole, overlap)`
            // of a fresh whole-range read, which the per-location rename links to the covering def.
            for slot in 0..f.op(op).num_inputs() {
                let Some((sp, off, sz)) = read_loc(f, op, slot) else { continue };
                if !eligible(sp) || is_laned_register(&f.spaces, sp, off) {
                    continue;
                }
                if f.vn(f.op(op).input(slot).unwrap()).is_heritage_known() {
                    continue;
                }
                let Some((base, size)) = merged.merged_range(sp, off) else { continue };
                if sz >= size || is_refine_range(sp, base, size) || !widened.contains(&(sp, base)) {
                    continue;
                }
                let whole = f.new_varnode(size, super::space::Address::new(sp, base));
                let cst = f.new_const(4, off - base);
                let subop = f.new_op(OpCode::Subpiece, seq, vec![whole, cst]);
                f.op_mut(subop).parent = Some(bid);
                let subout = f.new_output_unique(subop, sz);
                f.op_set_input(op, slot, subout);
                new_ops.push(subop); // splice the SUBPIECE in just before its reader
            }
            // Writes: a write narrower than its merged range is widened into a whole-range write,
            // pulling the surrounding bytes from the range's previous value and PIECE-ing them back.
            // A write-masked output (a marker already rewritten to a SUBPIECE by
            // [`remove_revisited_markers`]) is not a write in heritage (heritage.cc:326) — skip it.
            let mut after: Vec<OpId> = Vec::new();
            if let Some((sp, off, sz)) = write_loc(f, op) {
                if eligible(sp)
                    && !is_laned_register(&f.spaces, sp, off)
                    && !f.vn(f.op(op).output.unwrap()).is_write_mask()
                {
                    if let Some((base, size)) = merged.merged_range(sp, off) {
                        if size > sz && !is_refine_range(sp, base, size) && widened.contains(&(sp, base)) {
                            normalize_write_size(
                                f, op, sp, base, off, sz, size, bid, seq, &mut new_ops, &mut after,
                            );
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

/// Faithful port of Ghidra's `Heritage::removeRevisitedMarkers` (`heritage.cc:244`) together with the
/// prior-heritage marker detection in `collect()` (`heritage.cc:327-338`). On a WIDENING re-entry
/// pass, a WRITTEN varnode inside the widened merged range whose def is a heritage marker
/// (MULTIEQUAL/INDIRECT) or a return-form COPY and that is NARROWER than the range is "evidence of a
/// previous pass's heritage" of that range. Ghidra rewrites the marker op *in place* as
/// `narrow = SUBPIECE(big, #offset)`, where `big = newVarnode(size, addr)` is a fresh FREE whole-range
/// varnode, and sets the narrow output's write-mask so `collect()` no longer treats it as a write of
/// the narrow location; a return-form COPY is simply unlinked (a wider return COPY is re-guarded by
/// `guardReturns` on the widened range). The fresh `big` reads then flow through the existing
/// [`gather_candidates`]/cover/[`rename`] into the whole-range SSA, so the narrower access reads
/// `SUB42(whole, off)` — revisit's oracle `r74:2 = SUB42(r74:4, #0)`, the write becoming `CONCAT22`
/// once [`normalize_ranges`] widens the real narrow writes.
///
/// mosura-shape translation: mosura heritages each exact `(space, offset, size)` as its own SSA
/// location, so a pass-1 marker for `0x100074:2` lives at a SEPARATE location from the widened
/// `0x100074:4` range. This bridges them — the narrower location's markers are rewritten as SUBPIECEs
/// of a fresh whole-range read based at the widened range's base, and their outputs write-masked so
/// the candidate/cover scan does not re-heritage the narrow location on its own (Ghidra's `collect`
/// simply skips write-masked varnodes, `heritage.cc:326`; the `intersect == 2` cover logic then keeps
/// the narrow location out of `new_addrs`, so no INDIRECT guards refire).
///
/// SCOPE: like [`normalize_ranges`], fires ONLY on a widening re-entry (shared [`widening_ranges`]
/// gate) and skips laned/refinement ranges — so it is a dormant no-op on the current once-pass
/// pipeline (no range widens without the mainloop restart) and byte-identical. Runs BEFORE
/// [`normalize_ranges`] each pass (Ghidra's `removeRevisitedMarkers` precedes `guard()`), so the fresh
/// whole reads and write-masks are in place before the read/write normalize and the candidate scan.
///
/// The `info->deadremoved > 0` warning + `bumpDeadcodeDelay` branch (`heritage.cc:248`) is omitted:
/// mosura rebuilds per-space info each pass and this brick removes no dead code, so the branch is
/// unreachable here (documented like [`guard_calls`]' prototype-recovery gaps). A full-width marker
/// (the `clearProperty(new_addresses)` case, `heritage.cc:334`) is left untouched — mosura's
/// `intersect == 2` cover logic already keeps such a covered location out of `new_addrs`.
fn remove_revisited_markers(f: &mut Funcdata, pass: i32) {
    if f.num_blocks() == 0 {
        return;
    }
    let (merged, widened, max_write) = widening_ranges(f, pass);
    if widened.is_empty() {
        return;
    }
    let is_refine_range = |sp: SpaceId, base: u64, size: u32| {
        size > 4 && max_write.get(&(sp, base)).copied().unwrap_or(0) < size
    };
    // collect() marker-detection (heritage.cc:327-338): a written, non-write-masked varnode in a
    // widened non-refinement range whose def is a marker (MULTIEQUAL/INDIRECT) or a return-form COPY,
    // narrower than the range, is scheduled for rewrite. `(op, out, sp, base, size, offset)`.
    let mut removals: Vec<(OpId, VarnodeId, SpaceId, u64, u32, u32)> = Vec::new();
    for b in 0..f.num_blocks() {
        for op in f.blocks()[b].ops.clone() {
            let o = f.op(op);
            if !(o.is_marker() || o.is_return_copy()) {
                continue;
            }
            let Some(out) = o.output else { continue };
            let vn = f.vn(out);
            if vn.is_write_mask() {
                continue;
            }
            let (sp, off, sz) = (vn.loc.space, vn.loc.offset, vn.size);
            if is_laned_register(&f.spaces, sp, off) {
                continue;
            }
            let Some((base, size)) = merged.merged_range(sp, off) else { continue };
            if !widened.contains(&(sp, base)) || is_refine_range(sp, base, size) || sz >= size {
                continue;
            }
            removals.push((op, out, sp, base, size, (off - base) as u32));
        }
    }
    // removeRevisitedMarkers (heritage.cc:244-297): rewrite each scheduled marker in place.
    for (op, out, sp, base, size, offset) in removals {
        // Return-form COPY (heritage.cc:281): unlink in preparation for a wider re-guarded COPY.
        if f.op(op).is_return_copy() {
            f.op_uninsert(op);
            f.op_destroy(op);
            continue;
        }
        // MULTIEQUAL / INDIRECT → `narrow = SUBPIECE(big, #offset)`. Capture the INDIRECT's causing op
        // (Ghidra `getIn(1)` iop = mosura `guarded_op`) for placement before mutating.
        let is_indirect = f.op(op).code() == OpCode::Indirect;
        let target = if is_indirect { f.op(op).guarded_op() } else { None };
        let bid = f.op(op).parent;
        f.op_uninsert(op);
        let big = f.new_varnode(size, super::space::Address::new(sp, base));
        let cst = f.new_const(4, offset as u64);
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
/// mosura adaptation: Ghidra keeps the original narrow Varnode as the op's output and sets its
/// write-mask; mosura instead retargets the op to a `unique` temp of its own size, so the narrow
/// sub-register location is never heritaged on its own — only the rejoined whole-range Varnode is.
/// All intermediates are `unique`; only the final whole-range result lives at the register address.
///
/// The CALL `newIndirectCreation` branch (`heritage.cc:434`/`455`, when the narrow write's def is a
/// CALL with an indirect effect on the missing piece) is not ported: mosura has no indirect-creation
/// infrastructure and no fixture writes a register sub-piece directly from a call into a guarded
/// range. The pieces are taken from the plain `SUBPIECE`-of-old-value path (Ghidra's `else`).
#[allow(clippy::too_many_arguments)]
fn normalize_write_size(
    f: &mut Funcdata,
    op: OpId,
    reg: SpaceId,
    base: u64,
    off: u64,
    sz: u32,
    size: u32,
    bid: super::block::BlockId,
    seq: super::op::SeqNum,
    before: &mut Vec<OpId>,
    after: &mut Vec<OpId>,
) -> VarnodeId {
    use super::space::Address;
    let overlap = (off - base) as u32; // bytes of the range below the write (Ghidra `overlap`)
    let mostsig = size - overlap - sz; // bytes of the range above the write (Ghidra `mostsigsize`)

    // op now writes a unique temp of its own size (Ghidra's write-masked `vn`).
    let vn = f.new_output_unique(op, sz);

    // High piece (`mostsigsize != 0`, heritage.cc:428): SUBPIECE the old whole-range value's high
    // bytes (`big = newVarnode(size, addr)`; offset `overlap + vn->getSize()`).
    let mostvn = if mostsig > 0 {
        let big = f.new_varnode(size, Address::new(reg, base));
        let cst = f.new_const(4, (overlap + sz) as u64);
        let subop = f.new_op(OpCode::Subpiece, seq, vec![big, cst]);
        f.op_mut(subop).parent = Some(bid);
        let v = f.new_output_unique(subop, mostsig);
        before.push(subop); // SUBPIECE inserted before the write
        Some(v)
    } else {
        None
    };

    // Low piece (`overlap != 0`, heritage.cc:449): SUBPIECE the old value's low bytes, then PIECE
    // the narrow write above it (little-endian: the write is the most-significant input).
    let midvn = if overlap > 0 {
        let big = f.new_varnode(size, Address::new(reg, base));
        let cst = f.new_const(4, 0);
        let subop = f.new_op(OpCode::Subpiece, seq, vec![big, cst]);
        f.op_mut(subop).parent = Some(bid);
        let leastvn = f.new_output_unique(subop, overlap);
        before.push(subop);
        let pieceop = f.new_op(OpCode::Piece, seq, vec![vn, leastvn]);
        f.op_mut(pieceop).parent = Some(bid);
        // The middle piece is the final whole-range write iff there is no high piece (covers `size`).
        let mid = if mostsig == 0 {
            f.new_output(pieceop, overlap + sz, Address::new(reg, base))
        } else {
            f.new_output_unique(pieceop, overlap + sz)
        };
        after.push(pieceop); // PIECE inserted after the write
        mid
    } else {
        vn
    };

    // Final rejoin (`mostsigsize != 0`, heritage.cc:483): PIECE the high piece above the middle.
    if let Some(mostvn) = mostvn {
        let pieceop = f.new_op(OpCode::Piece, seq, vec![mostvn, midvn]);
        f.op_mut(pieceop).parent = Some(bid);
        let bigout = f.new_output(pieceop, size, Address::new(reg, base));
        after.push(pieceop);
        bigout
    } else {
        midvn
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
    // 3. Per range, classify: `Refine` (a partition — no single write covers it, Ghidra's
    //    `placeMultiequals` guard `size > 4 && max_write < size`, kept laned-only) or `Normalize`
    //    (a single write covers the whole range, so Ghidra's `guard` normalizes every narrow read to
    //    a `SUBPIECE` of the whole and every narrow write to a `normalizeWriteSize` `PIECE` into it).
    //    The laned partition is what the whole-range normalize cannot express; the scalar `Normalize`
    //    is the pass-0 batch's uniform `guard()`, retired once the faithful [`normalize_ranges`] takes
    //    over first-pass normalization (coupled to the call-output-in-RAX fix, with mainloop S8-2).
    enum Mode {
        Refine(Vec<u32>),
        Normalize { size: u32 },
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
            // A range a single write fully covers: every sub-read/sub-write is normalized to the
            // whole (Ghidra's `guard` → normalizeReadSize/normalizeWriteSize). This is the pass-0
            // batch's scalar `Normalize` half; the faithful per-pass whole-range normalize
            // ([`normalize_ranges`]) is wired re-entry-only for now (S8-1), so first-pass
            // normalization stays here until the batch is retired with the call-output-in-RAX fix.
            if size > 1 && max_write == size {
                return Mode::Normalize { size: size as u32 };
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
                    &Mode::Normalize { size } => {
                        // normalizeReadSize (heritage.cc:382): every read narrower than the covering
                        // range becomes a SUBPIECE of the whole, so it links to the single covering
                        // write (and to `normalizeWriteSize`'s widened narrow writes). This is the
                        // faithful guard() read half — it subsumes the offset-keyed
                        // `normalize_read_size` hack for every location it covers (the reads it
                        // rewrites are no longer narrow register reads, so that pass skips them).
                        // Ghidra applies this to EVERY free narrow read including the input of a
                        // self-zero/sign-extension `RDX:8 = ZEXT48(EDX:4)`: the `EDX:4` read becomes
                        // `SUBPIECE(RDX:8_prev, 0)`, linking to the *previous* whole-range write (the
                        // widened narrow writes), not this op's own output — not circular post-SSA.
                        if sz >= size {
                            continue;
                        }
                        let whole = f.new_varnode(size, super::space::Address::new(reg, base));
                        let cst = f.new_const(4, off - base);
                        let subop = f.new_op(OpCode::Subpiece, seq, vec![whole, cst]);
                        f.op_mut(subop).parent = Some(bid);
                        let subout = f.new_output_unique(subop, sz);
                        new_ops.push(subop);
                        f.op_set_input(op, slot, subout);
                    }
                    Mode::Skip => {}
                }
            }
            // Writes: a refined write splits into SUBPIECEs after the op; a partial write into a
            // covered (`Normalize`) range is widened by `normalizeWriteSize` so it reads back the
            // surrounding bytes and PIECEs the new whole. `after` ops are spliced after the op.
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
                            &Mode::Normalize { size } => {
                                // Faithful `normalizeWriteSize` (heritage.cc:1179): every write
                                // narrower than the covering range is widened to a whole-range write,
                                // pulling the surrounding bytes from the range's previous value. This
                                // is guard()'s uniform write half — it keeps a narrow write (e.g.
                                // `sete dl`) linked through the whole-range varnode instead of
                                // orphaning it, and `RuleDumptyHump` collapses the introduced
                                // PIECE/SUBPIECE where they tile back together.
                                if size > sz {
                                    normalize_write_size(
                                        f, op, reg, base, off, sz, size, bid, seq, &mut new_ops,
                                        &mut after,
                                    );
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
        f.new_indirect_op(op, super::space::Address::new(spc, off), size);
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
/// modification. INDIRECTs are spliced right after the call (matching mosura's established call-guard
/// placement, which [`super::recover::resolve_call_output`] consumes).
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
        let efflist = super::fspec::sysv_effect_list(&f.spaces);
        super::fspec::lookup_effect(&efflist, super::space::Address::new(reg, off), size)
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
            // newIndirectCreation (mosura 1-input): out@range = INDIRECT(#0), spliced after the call,
            // output marked indirect-creation (no realistic ancestor / the clobber).
            let seq = f.op(call).seqnum;
            let zero = f.new_const(size, 0);
            let ind = f.new_op(OpCode::Indirect, seq, vec![zero]);
            f.op_mut(ind).guarded_op = Some(call); // Ghidra's iop: the causing call
            let out = f.new_output(ind, size, addr);
            f.vn_mut(out).set_indirect_creation();
            f.op_mut(ind).parent = Some(bid);
            f.op_insert_after(ind, call);
        } else if effecttype == effect::UNKNOWN_EFFECT || effecttype == effect::RETURN_ADDRESS {
            // newIndirectOp (passthrough): out@range = INDIRECT(before@range), the value flowing
            // across. new_indirect_op splices before the call; move it to just after to match the
            // established placement resolve_call_output consumes.
            let seq = f.op(call).seqnum;
            let before = f.new_varnode(size, addr);
            let ind = f.new_op(OpCode::Indirect, seq, vec![before]);
            f.op_mut(ind).guarded_op = Some(call); // Ghidra's iop: the causing call
            let out = f.new_output(ind, size, addr);
            f.op_mut(ind).parent = Some(bid);
            f.op_insert_after(ind, call);
            if holdind {
                f.vn_mut(out).set_addr_force();
            }
            if effecttype == effect::RETURN_ADDRESS {
                f.vn_mut(out).set_return_address();
            }
        }
    }
}

/// Guard global (persistent) data-flow at RETURN ops (Ghidra `Heritage::guardReturns` persist branch,
/// heritage.cc:1676-1691). A persistent global's value must persist to (past) the end of the function,
/// so for each range whose space marks it persistent, a COPY is inserted right before every RETURN:
/// its input renames to the store version reaching the return (giving that write a real reader — and
/// hence a Cover), and its output is `addrForce`d and `markReturnCopy`'d so dead-code keeps it and
/// `RulePropagateCopy` won't fold it. This is what lets `Merge::mergeAddrTied` unify the store version
/// into the global's whole HighVariable, so the merge phase can tell a pre-store snapshot apart from
/// the post-store value.
///
/// Ghidra derives `persist` fresh at guard time via `queryProperties` (heritage.cc:1191). mosura's
/// decompile corpus has no populated scope, so — like [`super::varnodeprops::mark_addrtied`] and
/// [`guard_calls`] — persist is determined by space: an unmapped `ram` (global) location is
/// persistent. (The active-output/return-value branch of guardReturns, heritage.cc:1658-1675, is a
/// separate prototype-recovery concern, P6.)
fn guard_returns(f: &mut Funcdata, range: Loc) {
    let (spc, off, size) = range;
    let Some(ram) = f.spaces.by_name("ram") else { return };
    if spc != ram {
        return; // only persistent globals get the return-copy; stack/register are not persist
    }
    let addr = super::space::Address::new(spc, off);
    let returns: Vec<OpId> = (0..f.num_blocks() as u32)
        .flat_map(|b| f.block(super::block::BlockId(b)).ops.clone())
        .filter(|&op| f.op(op).code() == OpCode::Return && !f.op(op).is_dead())
        .collect();
    for ret in returns {
        // COPY: out@(addr,size)[addrForce, returnCopy] = in@(addr,size), inserted before RETURN.
        let seq = f.op(ret).seqnum;
        let invn = f.new_varnode(size, addr);
        let copyop = f.new_op(OpCode::Copy, seq, vec![invn]);
        let out = f.new_output(copyop, size, addr);
        f.vn_mut(out).set_addr_force();
        f.op_mut(copyop).mark_return_copy();
        f.op_insert_before(copyop, ret);
    }
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
        // Pass-0 setup, like Ghidra's `splitmanage.split()` / refinement at `pass == 0`: the laned
        // (XMM) partition, then the batch read-normalization that makes overlapping scalar
        // sub-register accesses uniform width. This is the interim first-pass normalization; the
        // faithful per-range `normalize_ranges` (below) takes it over — coupled to task #6 — with S8-2.
        let t0 = std::time::Instant::now();
        refine_overlaps(f, dom);
        if super::action::perf::enabled() {
            super::action::perf::record("heritage", "refine_overlaps", t0.elapsed());
        }
        let t0 = std::time::Instant::now();
        normalize_read_size(f);
        if super::action::perf::enabled() {
            super::action::perf::record("heritage", "normalize_read_size", t0.elapsed());
        }
    }
    // Widening re-entry gate (Ghidra's `placeMultiequals` per-pass re-heritage of a grown range):
    // probe once for any range that widened vs its prior-pass heritage. On the current once-pass
    // pipeline nothing widens, so both the marker rewrite and the per-range normalize are dormant and
    // this is a single footprint scan (unchanged cost). A range only widens under the S8-2 restart.
    let t0 = std::time::Instant::now();
    let widens = !widening_ranges(f, pass).1.is_empty();
    if widens {
        // Prior-heritage marker rewrite (Ghidra's `removeRevisitedMarkers`, before `guard()`): a pass's
        // MULTIEQUAL/INDIRECT markers narrower than the now-widened range become SUBPIECEs of a fresh
        // whole-range read (which heritages into the widened SSA below), narrow outputs write-masked.
        // Runs BEFORE normalize_ranges so its write-masks and whole reads are in place.
        remove_revisited_markers(f, pass);
        // Per-pass, per-range width normalization (Ghidra's `guard()` normalizeReadSize/normalizeWriteSize):
        // every free read / real write narrower than its widened merged range becomes a SUBPIECE / PIECE
        // of the whole range — recomputed after the marker rewrite so it sees the post-rewrite footprints.
        normalize_ranges(f, pass);
    }
    if super::action::perf::enabled() {
        super::action::perf::record("heritage", "widening_reentry", t0.elapsed());
    }
    // The per-location cover heritaged this pass — Ghidra's `disjoint` task list, built from
    // `globaldisjoint.add`. Process candidates in address order (as Ghidra's `beginLoc` does) so the
    // disjoint cover is deterministic.
    let t0 = std::time::Instant::now();
    let mut candidates: Vec<(Loc, bool)> = gather_candidates(f, pass).into_iter().collect();
    if super::action::perf::enabled() {
        super::action::perf::record("heritage", "gather_candidates", t0.elapsed());
    }
    candidates.sort_by_key(|&((sp, off, sz), _)| (sp.0, off, sz));
    let mut cover: HashSet<Loc> = HashSet::new();
    // Locations with addresses *new* to this pass — Ghidra's `MemRange::newAddresses()`, which
    // gates `guard()`'s `addIndirects` (`placeMultiequals`, heritage.cc:2629). A location wholly
    // contained in an earlier pass (`intersect == 2`) re-enters the cover only via a freed read
    // (re-heritage); its INDIRECT guards were placed on the first pass and must NOT be re-added
    // (heritage.cc:1187: "multiple INDIRECT guards for the same address confuses renaming").
    let mut new_addrs: HashSet<Loc> = HashSet::new();
    for (loc, has_free) in candidates {
        let intersect = f.globaldisjoint.add(loc.0, loc.1, loc.2, pass);
        if intersect != 2 {
            cover.insert(loc);
            new_addrs.insert(loc);
        } else if has_free {
            cover.insert(loc);
        }
    }
    f.heritage_pass += 1;
    if cover.is_empty() {
        return 0;
    }
    let t0 = std::time::Instant::now();
    heritage_spaces(f, dom, &cover, &new_addrs);
    if super::action::perf::enabled() {
        super::action::perf::record("heritage", "heritage_spaces", t0.elapsed());
    }
    cover.len() as u32
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

/// Heritage the locations in `cover` (the disjoint cover of this pass) into SSA form — the per-pass
/// body of [`heritage`]. Locations outside `cover` are ignored: their reads are left free for a
/// later pass, or were already linked by an earlier one. Because distinct SSA locations never
/// interact (a read belongs to exactly one `(space, offset, size)`), heritaging only the cover
/// reconstructs the same SSA as one combined walk over them.
fn heritage_spaces(f: &mut Funcdata, dom: &Dominators, cover: &HashSet<Loc>, new_addrs: &HashSet<Loc>) {
    let nb = f.num_blocks();

    // 0. Guard CALL and STORE ops (Ghidra `guard()` with `addIndirects = newAddresses()`,
    //    heritage.cc:1192-1195). For each range with addresses new this pass, `guard_calls` inserts
    //    an INDIRECT per call that clobbers/passes-through it and `guard_stores` one per aliasing
    //    STORE, so the possible modification becomes an SSA def. The new outputs are picked up as
    //    writes by the def-block scan below (Ghidra appends them to `placeMultiequals`' `write` list
    //    before `calcMultiequals`). Ranges sorted so op numbering is deterministic.
    let mut guarded: Vec<Loc> = new_addrs.iter().copied().collect();
    guarded.sort_by_key(|&(sp, off, sz)| (sp.0, off, sz));
    for l in guarded {
        guard_calls(f, l);
        guard_returns(f, l);
        guard_stores(f, l);
    }

    // 1. Global locations + their defining blocks (semi-pruned SSA: a location is global
    //    if some block reads it before defining it), restricted to this pass's cover.
    let mut globals: HashSet<Loc> = HashSet::new();
    let mut defblocks: HashMap<Loc, HashSet<usize>> = HashMap::new();
    for b in 0..nb {
        let mut killed: HashSet<Loc> = HashSet::new();
        for i in 0..f.blocks()[b].ops.len() {
            let op = f.blocks()[b].ops[i];
            for slot in 0..f.op(op).num_inputs() {
                if let Some(l) = read_loc(f, op, slot) {
                    if cover.contains(&l) && !killed.contains(&l) {
                        globals.insert(l);
                    }
                }
            }
            if let Some(l) = write_loc(f, op) {
                if cover.contains(&l) {
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
    rename(f, 0, dom, &children, &phis_by_block, &mut stack, &mut inputs, cover);
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

/// Like [`current_def`], but for a phi input flowing out of block `b`: when nothing defines
/// `loc` at its exact width on this path yet a *wider* def at the same offset is current (a
/// sub-register reaching def — e.g. a phi for `EBX` whose initializer wrote the full `RBX`),
/// splice a `SUBPIECE(W, 0)` at the end of block `b` and use it, so the wide initializer is
/// linked (and kept) rather than dropped. Only fires when the exact width is absent, so the
/// in-block def chains (where the exact width is on the stack) are untouched.
fn reaching_phi_input(
    f: &mut Funcdata,
    loc: Loc,
    b: usize,
    stack: &HashMap<Loc, Vec<VarnodeId>>,
    inputs: &mut HashMap<Loc, VarnodeId>,
) -> VarnodeId {
    if stack.get(&loc).and_then(|s| s.last()).is_some() {
        return current_def(f, loc, stack, inputs);
    }
    let (sp, off, sz) = loc;
    let cover = stack
        .iter()
        .filter(|((s, o, w), v)| *s == sp && *o == off && *w > sz && !v.is_empty())
        .min_by_key(|((_, _, w), _)| *w)
        .and_then(|(_, v)| v.last().copied());
    let Some(w) = cover else {
        return current_def(f, loc, stack, inputs);
    };
    let ops = f.blocks()[b].ops.clone();
    let Some(&last) = ops.last() else {
        return current_def(f, loc, stack, inputs);
    };
    let seq = f.op(last).seqnum;
    let zero = f.new_const(4, 0);
    let sub = f.new_op(OpCode::Subpiece, seq, vec![w, zero]);
    let subout = f.new_output_unique(sub, sz);
    f.op_mut(sub).parent = Some(super::block::BlockId(b as u32));
    let pos = if f.op(last).code().terminates_block() { ops.len() - 1 } else { ops.len() };
    let mut new_ops = ops;
    new_ops.insert(pos, sub);
    f.set_block_ops(super::block::BlockId(b as u32), new_ops);
    subout
}

#[allow(clippy::too_many_arguments)]
fn rename(
    f: &mut Funcdata,
    b: usize,
    dom: &Dominators,
    children: &[Vec<usize>],
    phis: &HashMap<usize, Vec<(Loc, OpId)>>,
    stack: &mut HashMap<Loc, Vec<VarnodeId>>,
    inputs: &mut HashMap<Loc, VarnodeId>,
    cover: &HashSet<Loc>,
) {
    let mut pushed: Vec<Loc> = Vec::new();
    let ops = f.blocks()[b].ops.clone();

    for op in ops {
        if f.op(op).code() == OpCode::Multiequal {
            // a phi: its output is the new current def; inputs are filled from preds below.
            // Phis for locations not in this pass's cover (e.g. register phis seen again while the
            // stack pass walks) were already wired by their own pass — leave them be.
            if let Some(l) = write_loc(f, op) {
                if cover.contains(&l) {
                    let out = f.op(op).output.unwrap();
                    stack.entry(l).or_default().push(out);
                    pushed.push(l);
                }
            }
            continue;
        }
        // rename reads in this pass's cover; reads outside it stay free (a later pass links them)
        // or were already linked (an earlier pass).
        for slot in 0..f.op(op).num_inputs() {
            if let Some(l) = read_loc(f, op, slot) {
                if cover.contains(&l) {
                    let def = current_def(f, l, stack, inputs);
                    f.op_set_input(op, slot, def);
                }
            }
        }
        // the output becomes the new current def
        if let Some(l) = write_loc(f, op) {
            if cover.contains(&l) {
                let out = f.op(op).output.unwrap();
                stack.entry(l).or_default().push(out);
                pushed.push(l);
            }
        }
    }

    // fill the phi argument each successor expects from this block
    let succs: Vec<usize> = f.blocks()[b].out_edges.iter().map(|e| e.0 as usize).collect();
    for s in succs {
        let j = f.blocks()[s].in_edges.iter().position(|e| e.0 as usize == b).unwrap();
        let phi_locs: Vec<(Loc, OpId)> = phis.get(&s).cloned().unwrap_or_default();
        for (l, phi) in phi_locs {
            let def = reaching_phi_input(f, l, b, stack, inputs);
            f.op_set_input(phi, j, def);
        }
    }

    for c in &children[b] {
        rename(f, *c, dom, children, phis, stack, inputs, cover);
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
        assert_eq!(m.add(reg, 0x10, 8, 0), 0, "new range");
        assert_eq!(m.find_pass(reg, 0x10), 0);
        assert_eq!(m.find_pass(reg, 0x14), 0, "interior address is covered");
        assert_eq!(m.find_pass(reg, 0x18), -1, "just past the range is uncovered");
        assert_eq!(m.find_pass(ram, 0x10), -1, "other space uncovered");

        // Same offset, a LATER pass, wholly contained ⇒ intersect 2 (already heritaged earlier).
        assert_eq!(m.add(reg, 0x10, 8, 1), 2, "contained in an older-pass range");
        // A sub-range from a later pass is also contained ⇒ 2.
        assert_eq!(m.add(reg, 0x12, 2, 1), 2, "sub-range contained in older range");
        // Same range re-added at the SAME pass ⇒ 0 (only meets same-pass coverage).
        assert_eq!(m.add(reg, 0x10, 8, 0), 0, "same-pass re-add");

        // A later-pass range that extends PAST an older range partially overlaps ⇒ 1.
        assert_eq!(m.add(reg, 0x14, 8, 2), 1, "partial overlap with older range");
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

        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let stack = spaces.by_name("stack").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
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
        assert_eq!(pos(inds[0]), pos(call) + 1, "creation spliced right after the call");

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
        assert_eq!(ipos(gpass), ipos(call) + 1, "ram passthrough spliced right after the call");
    }

    /// A second range disjoint from the first is recorded independently (intersect 0), and a new
    /// range bridging two older ones reports the older overlap.
    #[test]
    fn location_map_disjoint_and_bridge() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let mut m = LocationMap::default();
        assert_eq!(m.add(reg, 0x0, 4, 0), 0);
        assert_eq!(m.add(reg, 0x10, 4, 0), 0, "disjoint new range");
        assert_eq!(m.find_pass(reg, 0x0), 0);
        assert_eq!(m.find_pass(reg, 0x10), 0);
        assert_eq!(m.find_pass(reg, 0x8), -1, "gap between ranges is uncovered");
        // A later-pass range starting inside the first and reaching into the gap ⇒ partial (1).
        assert_eq!(m.add(reg, 0x2, 6, 1), 1, "overlaps the older [0,4) on the left");
    }

    /// `normalize_ranges` (Ghidra `guard()` normalizeReadSize/normalizeWriteSize, heritage.cc:382/416)
    /// on the re-entry mixed-width shape: a RAM range `[0x100074, +4)` a 4-byte write covers, with a
    /// free 2-byte read and a 2-byte write at the base. The narrow read becomes `SUBPIECE(r74:4, #0)`
    /// and the narrow write is widened to a whole-range `PIECE(SUBPIECE(r74:4,#2), <write>)` — exactly
    /// revisit's oracle IR (`r74:2 = SUB42(r74:4,#0)`, `r74:4 = CONCAT22(SUB42(r74:4,#2), AX)`). This
    /// is the width unification the retired pass-0 batch could not reach on a re-heritaged RAM range.
    #[test]
    fn normalize_ranges_reenters_mixed_width_range() {
        use super::super::block::{BlockBasic, BlockId};
        use super::super::op::SeqNum;
        use super::super::space::Address;

        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let base = 0x100074u64;

        // A 4-byte covering write `r74:4 = COPY in` (max_write == range size 4 ⇒ a Normalize range).
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
        f.new_output(op_write, 2, Address::new(ram, base));

        f.set_blocks(vec![BlockBasic { ops: vec![op_cover, op_read, op_write], ..Default::default() }]);
        for &op in &[op_cover, op_read, op_write] {
            f.op_mut(op).parent = Some(BlockId(0));
        }

        // The 2-byte location was heritaged on an earlier pass; pass 1 widens it to 4 bytes — a
        // genuine re-entry, the only case normalize_ranges fires (S8-1 re-entry scope).
        f.globaldisjoint.add(ram, base, 2, 0);
        normalize_ranges(&mut f, 1); // ram is delay-1

        // normalizeReadSize: the 2-byte read became `SUBPIECE(r74:4, #0)` and the reader is rewired.
        let r_in = f.op(op_read).input(0).unwrap();
        let read_sub = f.vn(r_in).def.expect("reader input now has a def");
        assert_eq!(f.op(read_sub).code(), OpCode::Subpiece, "narrow read normalized to SUBPIECE");
        let whole = f.op(read_sub).input(0).unwrap();
        assert_eq!(
            (f.vn(whole).loc.space, f.vn(whole).loc.offset, f.vn(whole).size),
            (ram, base, 4),
            "SUBPIECE reads the whole 4-byte range",
        );
        assert_eq!(f.vn(f.op(read_sub).input(1).unwrap()).loc.offset, 0, "read overlap is 0");

        // normalizeWriteSize: the 2-byte write is widened to a whole-range PIECE ending at r74:4,
        // whose high input is `SUBPIECE(r74:4, #2)` of the previous value (overlap 0, mostsig 2).
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
        // The original write op no longer targets the range loc directly (retargeted to a unique).
        assert_ne!(write_loc(&f, op_write), Some((ram, base, 2)), "narrow write retargeted off the range");
    }

    /// `normalize_ranges` is DORMANT with no re-entry (S8-1 scope): the same mixed-width range, but
    /// with NO prior-pass heritage of the location, is left completely untouched — the pass-0 batch
    /// owns first-pass normalization, so this is byte-identical on the current pipeline. (This is the
    /// property that lets the faithful normalize land as a no-op brick for the S8-2 mainloop.)
    #[test]
    fn normalize_ranges_no_reentry_is_dormant() {
        use super::super::block::{BlockBasic, BlockId};
        use super::super::op::SeqNum;
        use super::super::space::Address;

        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let base = 0x100074u64;

        let cov_in = f.new_input(4, Address::new(reg, 0x40));
        let op_cover = f.new_op(OpCode::Copy, seq, vec![cov_in]);
        f.new_output(op_cover, 4, Address::new(ram, base));
        let narrow_read = f.new_varnode(2, Address::new(ram, base));
        let addc = f.new_const(2, 0x64);
        let op_read = f.new_op(OpCode::IntAdd, seq, vec![narrow_read, addc]);
        let ax = f.new_output(op_read, 2, Address::new(reg, 0x0));
        let op_write = f.new_op(OpCode::Copy, seq, vec![ax]);
        f.new_output(op_write, 2, Address::new(ram, base));

        f.set_blocks(vec![BlockBasic { ops: vec![op_cover, op_read, op_write], ..Default::default() }]);
        for &op in &[op_cover, op_read, op_write] {
            f.op_mut(op).parent = Some(BlockId(0));
        }
        let before = f.blocks()[0].ops.len();
        // NO globaldisjoint pre-seed ⇒ no location was heritaged earlier ⇒ nothing is re-entry.
        normalize_ranges(&mut f, 1);
        assert_eq!(f.blocks()[0].ops.len(), before, "no ops inserted without re-entry");
        assert!(
            !f.blocks()[0].ops.iter().any(|&op| matches!(f.op(op).code(), OpCode::Subpiece | OpCode::Piece)),
            "dormant: no normalization without re-entry",
        );
    }

    /// `normalize_ranges` inserts nothing when a widened range's accesses already fill the new width:
    /// a 4-byte write and 4-byte read fill a range grown to 4, so no SUBPIECE/PIECE is needed (Ghidra's
    /// `guard()` normalizes only `vn < size`). Exercises the widening path with no narrow access.
    #[test]
    fn normalize_ranges_single_width_is_noop() {
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
        f.globaldisjoint.add(ram, base, 2, 0); // prior heritage 2 bytes; this pass widens to 4
        let before = f.blocks()[0].ops.len();
        normalize_ranges(&mut f, 1);
        assert_eq!(f.blocks()[0].ops.len(), before, "no ops inserted");
        assert!(
            !f.blocks()[0].ops.iter().any(|&op| matches!(f.op(op).code(), OpCode::Subpiece | OpCode::Piece)),
            "uniform-width range untouched",
        );
    }

    /// A range no single write covers and wider than 4 bytes is Ghidra's *refinement* (partition)
    /// case (`placeMultiequals`, heritage.cc:2610: `size > 4 && max < size`), NOT whole-range
    /// normalize. For non-laned ranges mosura keeps refinement a deliberate no-op (see
    /// [`refine_overlaps`]), so `normalize_ranges` must skip it — leaving the pieces independent, not
    /// widening the narrow writes into bogus PIECEs (the stackreturn/impliedfield regression cause).
    #[test]
    fn normalize_ranges_skips_wide_uncovered_refinement_range() {
        use super::super::block::{BlockBasic, BlockId};
        use super::super::op::SeqNum;
        use super::super::space::Address;

        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let base = 0x3000u64;

        // Two adjacent 4-byte writes (base, base+4) — no single write covers the union — and a free
        // 8-byte read spanning both, so the merged range is `[base, +8)` with max_write 4 < 8.
        let in0 = f.new_input(4, Address::new(reg, 0x40));
        let w0 = f.new_op(OpCode::Copy, seq, vec![in0]);
        f.new_output(w0, 4, Address::new(ram, base));
        let in1 = f.new_input(4, Address::new(reg, 0x48));
        let w1 = f.new_op(OpCode::Copy, seq, vec![in1]);
        f.new_output(w1, 4, Address::new(ram, base + 4));
        let read8 = f.new_varnode(8, Address::new(ram, base));
        let op_read = f.new_op(OpCode::Copy, seq, vec![read8]);
        f.new_output(op_read, 8, Address::new(reg, 0x0));

        f.set_blocks(vec![BlockBasic { ops: vec![w0, w1, op_read], ..Default::default() }]);
        for &op in &[w0, w1, op_read] {
            f.op_mut(op).parent = Some(BlockId(0));
        }
        // Prior heritage 4 bytes; this pass widens to 8 (a genuine widening re-entry) — but the
        // widened range no single write covers, so the refinement gate must still skip it.
        f.globaldisjoint.add(ram, base, 4, 0);
        normalize_ranges(&mut f, 1);
        assert!(
            !f.blocks()[0].ops.iter().any(|&op| matches!(f.op(op).code(), OpCode::Subpiece | OpCode::Piece)),
            "refinement range left independent (no whole-range normalize)",
        );
        assert_eq!(write_loc(&f, w0), Some((ram, base, 4)), "narrow write NOT widened");
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
        remove_revisited_markers(&mut f, 1);

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
        remove_revisited_markers(&mut f, 1);

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
        remove_revisited_markers(&mut f, 1);

        assert!(!f.blocks()[0].ops.contains(&rcopy), "return-copy removed from the block");
        assert!(f.op(rcopy).is_dead(), "return-copy op destroyed (dead)");
        assert!(
            !f.blocks()[0].ops.iter().any(|&op| f.op(op).code() == OpCode::Subpiece),
            "return-copy unlinked, not rewritten to a SUBPIECE",
        );
    }
}
