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

    /// Ghidra `LocationMap::clear`: reset to empty.
    pub fn clear(&mut self) {
        self.themap.clear();
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

/// Refinement (read side) — Ghidra's `normalizeReadSize`. Where a location is written at
/// a single width `S` but also *read* at a smaller width `s` at the same offset (a
/// sub-register: EAX of a wider RAX def), rewrite each narrow read as `SUBPIECE(W, 0)` of
/// a full-width read `W`, so every access to the location is uniform width and SSA links
/// it cleanly. Conservative: only locations whose writes are all one width are touched;
/// partial writes (the PIECE / write side) and cross-offset overlap (CONCAT) are not yet
/// handled, so those reads remain independent (an under-linking, never a miswiring).
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
    // The vector (XMM/YMM/ZMM) register file begins at register offset 0x1200; everything below it
    // (GP/flags/segment/x87) is scalar. Lane refinement is needed only for these *laned* registers
    // (Ghidra's `LanedRegister`/`ActionLaneDivide` model) — `movaps`/`xorps` write them in 4-byte
    // lanes while floats read 8 bytes. Restricting to them keeps the existing `normalize_read_size`
    // path (and the whole scalar SSA) untouched, so the change is a no-op outside SIMD code.
    const XMM_BASE: u64 = 0x1200;
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
                    if sp == reg && is_laned(off) {
                        acc.push(Acc { is_write: false, off, size: sz, blk: b, pos });
                    }
                }
            }
            if let Some((sp, off, sz)) = write_loc(f, op) {
                if sp == reg && is_laned(off) {
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
    //    `placeMultiequals` guard `size > 4 && max_write < size`), or `Normalize` (a single write
    //    of the whole range exists, so sub-reads at any offset are `SUBPIECE`s of it — Ghidra's
    //    `guard`/`normalizeReadSize` keyed to the *range* base, which links a high-lane read like
    //    `XMM_Qa[4,4]` to the 8-byte write it sub-reads). `mixed_at_base` flags a base offset
    //    written at more than one width, the case the offset-keyed `normalize_read_size` skips.
    enum Mode {
        Refine(Vec<u32>),
        Normalize { size: u32, mixed_at_base: bool },
        Skip,
    }
    let modes: Vec<Mode> = ranges
        .iter()
        .map(|&(base, end)| {
            let size = (end - base) as usize;
            let writes_at_base: std::collections::HashSet<u32> = acc
                .iter()
                .filter(|a| a.is_write && a.off == base)
                .map(|a| a.size)
                .collect();
            let max_write = acc
                .iter()
                .filter(|a| a.is_write && a.off >= base && a.off + a.size as u64 <= end)
                .map(|a| a.size as usize)
                .max()
                .unwrap_or(0);
            if size > 4 && max_write < size {
                // buildRefinement: mark each access's start and end boundary.
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
            // A range a single write fully covers: sub-reads/writes are normalized to the whole
            // (Ghidra's `guard` → normalizeReadSize/normalizeWriteSize). `mixed_at_base` flags a
            // base written at more than one width (the SIMD lane-clear+narrow-write shape), the case
            // the offset-keyed `normalize_read_size` skips.
            if size > 1 && max_write == size {
                return Mode::Normalize { size: size as u32, mixed_at_base: writes_at_base.len() > 1 };
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
                    &Mode::Normalize { size, mixed_at_base } => {
                        // normalizeReadSize: a read narrower than the covering range becomes a
                        // SUBPIECE of the whole. The offset-keyed `normalize_read_size` already
                        // handles a single-width base read; do the cases it can't — a high-lane
                        // read (`off > base`) or a base read whose location is written at mixed
                        // widths. Skip a ZEXT/SEXT whose own output *is* the whole range (its
                        // input read would become a circular SUBPIECE of its own result).
                        if sz >= size || (off == base && !mixed_at_base) {
                            continue;
                        }
                        if matches!(f.op(op).code(), OpCode::IntZext | OpCode::IntSext)
                            && write_loc(f, op) == Some((reg, base, size))
                        {
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
                            &Mode::Normalize { size, mixed_at_base } => {
                                // Faithful `normalizeWriteSize`: widen a write narrower than the
                                // covering range. Still gated to the SIMD partial-overwrite shape (a
                                // base written at mixed widths) and the low write (`off == base`,
                                // overlap 0); Stage 3 relaxes this to guard()'s uniform condition for
                                // GP sub-registers, where the overlap branch comes into play.
                                if mixed_at_base && off == base && size > sz {
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
fn gather_candidates(f: &Funcdata, pass: i32) -> HashMap<Loc, bool> {
    let infos = build_info_list(&f.spaces);
    let eligible = |sp: SpaceId| {
        let info = &infos[sp.0 as usize];
        info.is_heritaged() && info.delay <= pass
    };
    let mut cand: HashMap<Loc, bool> = HashMap::new();
    for b in 0..f.num_blocks() {
        let ops = f.blocks()[b].ops.clone();
        for op in ops {
            for slot in 0..f.op(op).num_inputs() {
                if let Some(l) = read_loc(f, op, slot) {
                    if eligible(l.0) {
                        let free = !f.vn(f.op(op).input(slot).unwrap()).is_heritage_known();
                        *cand.entry(l).or_insert(false) |= free;
                    }
                }
            }
            if let Some(l) = write_loc(f, op) {
                if eligible(l.0) {
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
        // Pass-0 setup, like Ghidra's `splitmanage.split()` / refinement at `pass == 0`: the
        // cross-width refinement that makes overlapping sub-register accesses uniform width.
        refine_overlaps(f, dom);
        normalize_read_size(f);
    }
    // The per-location cover heritaged this pass — Ghidra's `disjoint` task list, built from
    // `globaldisjoint.add`. Process candidates in address order (as Ghidra's `beginLoc` does) so the
    // disjoint cover is deterministic.
    let mut candidates: Vec<(Loc, bool)> = gather_candidates(f, pass).into_iter().collect();
    candidates.sort_by_key(|&((sp, off, sz), _)| (sp.0, off, sz));
    let mut cover: HashSet<Loc> = HashSet::new();
    for (loc, has_free) in candidates {
        let intersect = f.globaldisjoint.add(loc.0, loc.1, loc.2, pass);
        if intersect != 2 || has_free {
            cover.insert(loc);
        }
    }
    f.heritage_pass += 1;
    if cover.is_empty() {
        return 0;
    }
    heritage_spaces(f, dom, &cover);
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
fn heritage_spaces(f: &mut Funcdata, dom: &Dominators, cover: &HashSet<Loc>) {
    let nb = f.num_blocks();

    // 1. Global locations + their defining blocks (semi-pruned SSA: a location is global
    //    if some block reads it before defining it), restricted to this pass's cover.
    let mut globals: HashSet<Loc> = HashSet::new();
    let mut defblocks: HashMap<Loc, HashSet<usize>> = HashMap::new();
    for b in 0..nb {
        let ops = f.blocks()[b].ops.clone();
        let mut killed: HashSet<Loc> = HashSet::new();
        for op in ops {
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

    // 2. Place MULTIEQUALs at iterated dominance frontiers of each global's def-blocks.
    let mut phis: HashMap<(usize, Loc), OpId> = HashMap::new();
    for &l in &globals {
        let Some(defs) = defblocks.get(&l) else { continue };
        let mut worklist: Vec<usize> = defs.iter().copied().collect();
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
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); nb];
    for c in 0..nb {
        if dom.idom[c] != c {
            children[dom.idom[c]].push(c);
        }
    }
    let mut stack: HashMap<Loc, Vec<VarnodeId>> = HashMap::new();
    let mut inputs: HashMap<Loc, VarnodeId> = HashMap::new();
    rename(f, 0, dom, &children, &phis, &mut stack, &mut inputs, cover);
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
    phis: &HashMap<(usize, Loc), OpId>,
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
        let phi_locs: Vec<(Loc, OpId)> = phis
            .iter()
            .filter(|((blk, _), _)| *blk == s)
            .map(|((_, l), &op)| (*l, op))
            .collect();
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
}
