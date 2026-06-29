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

use std::collections::{HashMap, HashSet};

use super::dominator::Dominators;
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::space::SpaceId;
use super::varnode::VarnodeId;

/// An SSA location key: `(space, offset, size)`.
type Loc = (SpaceId, u64, u32);

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
                                // normalizeWriteSize (off == base / overlap 0 case): a partial write
                                // low in a covered range becomes `PIECE(SUB(old_whole, sz), value)`,
                                // pulling the high bytes from the value previously in the range.
                                // Gated on a mixed-width base (the SIMD partial-overwrite shape) so
                                // ordinary sub-register writes are untouched.
                                let mostsig = size - sz;
                                if mixed_at_base && off == base && mostsig > 0 {
                                    let smalltemp = f.new_output_unique(op, sz);
                                    // read the old whole-range value and take its high bytes
                                    let bigread =
                                        f.new_varnode(size, super::space::Address::new(reg, base));
                                    let cst = f.new_const(4, sz as u64);
                                    let subop = f.new_op(OpCode::Subpiece, seq, vec![bigread, cst]);
                                    f.op_mut(subop).parent = Some(bid);
                                    let mostvn = f.new_output_unique(subop, mostsig);
                                    new_ops.push(subop); // before the write
                                    // PIECE(high old bytes, written low bytes) → the new whole write
                                    let pieceop = f.new_op(OpCode::Piece, seq, vec![mostvn, smalltemp]);
                                    f.op_mut(pieceop).parent = Some(bid);
                                    f.new_output(pieceop, size, super::space::Address::new(reg, base));
                                    after.push(pieceop);
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

/// Build the SSA form for `f` using the dominator info `dom`.
///
/// Heritage iterates over address spaces in *delay* order (Ghidra's `Heritage::heritage` pass
/// loop, `heritage.cc:2663`/`2687`): the register space (delay 0) is heritaged before the
/// `ram`/`stack` spaces (delay 1), so that a later pass's reads link to defs (e.g. a recovered
/// stack-pointer offset) discovered in an earlier pass. `globaldisjoint` records which spaces
/// are already in SSA form so each pass only heritages the newly-eligible ones, leaving the
/// rest free (Ghidra's `globaldisjoint` LocationMap).
///
/// This runs the passes back-to-back to completion in a single call, so the result is the same
/// full SSA the single-pass construction produced — spaces are independent in SSA, so splitting
/// the rename walk by space group is output-identical. The *payoff* of iterating (interleaving
/// register heritage with param recovery, then heritaging the stack) belongs to the outer
/// mainloop, which re-invokes heritage between those actions.
pub fn heritage(f: &mut Funcdata, dom: &Dominators) {
    let nb = f.num_blocks();
    if nb == 0 {
        return;
    }
    refine_overlaps(f, dom);
    normalize_read_size(f);

    let infos = build_info_list(&f.spaces);
    let max_delay = infos.iter().filter(|i| i.is_heritaged()).map(|i| i.delay).max().unwrap_or(0);
    let mut globaldisjoint: HashSet<SpaceId> = HashSet::new();
    for pass in 0..=max_delay {
        // Spaces newly eligible this pass: heritaged, delay reached, not yet processed.
        let active: HashSet<SpaceId> = infos
            .iter()
            .filter(|i| i.delay <= pass)
            .filter_map(|i| i.space)
            .filter(|sp| !globaldisjoint.contains(sp))
            .collect();
        if active.is_empty() {
            continue;
        }
        heritage_spaces(f, dom, &active);
        globaldisjoint.extend(active);
    }
}

/// Heritage the locations in `active` (one delay group) into SSA form — the per-pass body of
/// [`heritage`]. Locations in spaces outside `active` are ignored: their reads are left free
/// for a later pass, and their writes/phis don't define anything here. Because SSA locations in
/// different spaces never interact (a read at a slot belongs to exactly one space), running
/// this once per space group reconstructs the same SSA as one combined walk.
fn heritage_spaces(f: &mut Funcdata, dom: &Dominators, active: &HashSet<SpaceId>) {
    let nb = f.num_blocks();

    // 1. Global locations + their defining blocks (semi-pruned SSA: a location is global
    //    if some block reads it before defining it), restricted to the active spaces.
    let mut globals: HashSet<Loc> = HashSet::new();
    let mut defblocks: HashMap<Loc, HashSet<usize>> = HashMap::new();
    for b in 0..nb {
        let ops = f.blocks()[b].ops.clone();
        let mut killed: HashSet<Loc> = HashSet::new();
        for op in ops {
            for slot in 0..f.op(op).num_inputs() {
                if let Some(l) = read_loc(f, op, slot) {
                    if active.contains(&l.0) && !killed.contains(&l) {
                        globals.insert(l);
                    }
                }
            }
            if let Some(l) = write_loc(f, op) {
                if active.contains(&l.0) {
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
    rename(f, 0, dom, &children, &phis, &mut stack, &mut inputs, active);
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
    active: &HashSet<SpaceId>,
) {
    let mut pushed: Vec<Loc> = Vec::new();
    let ops = f.blocks()[b].ops.clone();

    for op in ops {
        if f.op(op).code() == OpCode::Multiequal {
            // a phi: its output is the new current def; inputs are filled from preds below.
            // Phis for spaces not active this pass (e.g. register phis seen again while the
            // stack pass walks) were already wired by their own pass — leave them be.
            if let Some(l) = write_loc(f, op) {
                if active.contains(&l.0) {
                    let out = f.op(op).output.unwrap();
                    stack.entry(l).or_default().push(out);
                    pushed.push(l);
                }
            }
            continue;
        }
        // rename reads in the active spaces; reads in other spaces stay free (a later pass
        // links them) or were already linked (an earlier pass).
        for slot in 0..f.op(op).num_inputs() {
            if let Some(l) = read_loc(f, op, slot) {
                if active.contains(&l.0) {
                    let def = current_def(f, l, stack, inputs);
                    f.op_set_input(op, slot, def);
                }
            }
        }
        // the output becomes the new current def
        if let Some(l) = write_loc(f, op) {
            if active.contains(&l.0) {
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
        rename(f, *c, dom, children, phis, stack, inputs, active);
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
}
