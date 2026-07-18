//! Stack-variable layout recovery — a faithful port of Ghidra's `ScopeLocal`/`MapState`/`RangeHint`
//! (`varmap.cc`), the machinery that reconstructs the function's stack frame as a set of local
//! Symbols with recovered data-types and arrays.
//!
//! Ghidra collects data-type hints (`RangeHint`s) for the stack address space from the Varnodes
//! stored there ([`MapState::gather_varnodes`]) and from pointers into the stack
//! ([`MapState::gather_open`], via [`super::alias`]'s `gatherAdditiveBase`), then merges the
//! overlapping/adjacent hints into a disjoint cover of named Symbols ([`restructure`]). A scalar
//! slot becomes `iStack_NN` (typed by its hint); a uniformly-accessed contiguous region becomes a
//! stack array `aiStack_NN[k]`. This is the `ActionRestructureVarnode` localrecovery pass
//! (`coreaction.cc`), minus the full Symbol-table writeback — the recovered layout is returned as a
//! [`StackSymbol`] list for the printer to render against.
//!
//! Faithfully simplified for mosura's primitive lattice (and noted at each site): the `RangeList`
//! mapped-window / parameter-range exclusion (`resetLocalWindow`/`markNotMapped`), the
//! locked-Symbol and `TypePartialStruct`/`PartialUnion` hint paths (`addFixedType`), the
//! `LoadGuard` array hints (`addGuard`), and the dynamic/name-recommendation bookkeeping — none of
//! which is reached by the stripped x86-64 datatests.

use super::funcdata::Funcdata;
use super::opcode::OpCode;
use super::space::SpaceId;
use super::types::{type_order, Datatype};
use super::varnode::VarnodeId;

/// Ghidra `sign_extend(val, bit)` — sign-extend treating bit index `bit` as the sign.
fn sign_extend(val: u64, bit: u32) -> i64 {
    if bit >= 63 {
        val as i64
    } else {
        let sh = 63 - bit;
        ((val << sh) as i64) >> sh
    }
}

/// Ghidra `RangeHint::RangeType`: the basic categorization of a range.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RangeType {
    Fixed = 0,    // A data-type with a fixed size
    Open = 1,     // An array with a (possibly unknown) number of elements
    Endpoint = 2, // An (artificial) boundary to the range of bytes getting analyzed
}

const FL_TYPELOCK: u32 = 1; // RangeHint::typelock
const FL_COPY_CONSTANT: u32 = 2; // RangeHint::copy_constant

/// Ghidra `RangeHint` (`varmap.hh`): a data-type hint for a sequence of bytes on the stack — where
/// it starts, what one element might be, and how far it extends (possibly as an array).
#[derive(Clone)]
struct RangeHint {
    start: u64,        // starting offset of this range of bytes
    size: i32,         // number of bytes in a single element
    sstart: i64,       // signed version of the starting offset
    ty: Datatype,      // putative data-type for a single element
    flags: u32,        // additional boolean properties
    range_type: RangeType,
    highind: i32,      // minimum upper bound on the array index (if open)
}

impl RangeHint {
    fn is_type_lock(&self) -> bool {
        self.flags & FL_TYPELOCK != 0
    }

    /// Ghidra `RangeHint::isConstAbsorbable`: `self` is assumed open; if it is a primitive and the
    /// other range is just a constant being COPYed, it can be absorbed even if bigger.
    fn is_const_absorbable(&self, b: &RangeHint) -> bool {
        if b.flags & FL_COPY_CONSTANT == 0 {
            return false;
        }
        if b.is_type_lock() {
            return false;
        }
        if b.size < self.size {
            return false;
        }
        if !matches!(self.ty, Datatype::Int(_) | Datatype::Uint(_) | Datatype::Bool | Datatype::Float(_)) {
            return false;
        }
        if !matches!(b.ty, Datatype::Unknown(_) | Datatype::Int(_) | Datatype::Uint(_)) {
            return false;
        }
        let mut end = self.sstart;
        if self.highind > 0 {
            end += self.highind as i64 * self.ty.align_size() as i64;
        } else {
            end += self.size as i64;
        }
        b.sstart <= end
    }

    /// Ghidra `RangeHint::reconcile`: can the intersecting `b` coexist with `self` without
    /// destroying data-type information (do the sub-component sizes line up)?
    fn reconcile(&self, b: &RangeHint) -> bool {
        let (mut a, mut b) = (self, b);
        if a.ty.align_size() < b.ty.align_size() {
            std::mem::swap(&mut a, &mut b); // make sure b is smallest
        }
        let asz = a.ty.align_size() as i64;
        let mut mod_ = (b.sstart - a.sstart) % asz;
        if mod_ < 0 {
            mod_ += asz;
        }
        let mut sub = Some(a.ty.clone());
        while let Some(s) = &sub {
            if s.align_size() <= b.ty.align_size() {
                break;
            }
            match s.get_subtype(mod_) {
                Some((newty, newoff)) => {
                    mod_ = newoff;
                    sub = Some(newty);
                }
                None => sub = None,
            }
        }
        if let Some(s) = &sub {
            if s.align_size() == b.ty.align_size() {
                return true;
            }
            // b overlaps multiple components of a
        }
        // component sizes do not match — check for data-types we want to protect more
        if b.range_type == RangeType::Open && b.is_const_absorbable(a) {
            return true;
        }
        if b.is_type_lock() {
            return false;
        }
        let prot = match &a.ty {
            Datatype::Struct(..) => true,
            Datatype::Array(elem, _) => matches!(**elem, Datatype::Unknown(_)),
            _ => false,
        };
        if !prot {
            return false;
        }
        // For structures and unknown-element arrays, test if b looks like a partial/combined type
        matches!(b.ty, Datatype::Unknown(_) | Datatype::Int(_) | Datatype::Uint(_))
    }

    /// Ghidra `RangeHint::contain`: assuming `self` starts no later than `b` and they intersect,
    /// does one contain the other?
    fn contain(&self, b: &RangeHint) -> bool {
        if self.sstart == b.sstart {
            return true;
        }
        b.sstart + b.size as i64 - 1 < self.sstart + self.size as i64
    }

    /// Ghidra `RangeHint::preferred`: is `self`'s data-type preferred over `b`'s?
    fn preferred(&self, b: &RangeHint, reconcile: bool) -> bool {
        if self.start != b.start {
            return true; // something must occupy self.start to b.start
        }
        if b.is_type_lock() {
            if !self.is_type_lock() {
                return false;
            }
        } else if self.is_type_lock() {
            return true;
        }
        if self.range_type == RangeType::Open && b.range_type != RangeType::Open {
            if !reconcile {
                return false; // throw out open range
            }
            if self.is_const_absorbable(b) {
                return true;
            }
        } else if b.range_type == RangeType::Open && self.range_type != RangeType::Open {
            if !reconcile {
                return true;
            }
            if b.is_const_absorbable(self) {
                return false;
            }
        } else if self.range_type == RangeType::Fixed && b.range_type == RangeType::Fixed
            && self.size != b.size && !reconcile {
                return self.size > b.size;
            }
        type_order(&self.ty, &b.ty) == std::cmp::Ordering::Less // prefer the more specific
    }

    /// Ghidra `RangeHint::absorb`: absorb the indexing/open details of `b` (not its data-type).
    fn absorb(&mut self, b: &RangeHint) {
        if b.range_type == RangeType::Open {
            if self.ty.align_size() == b.ty.align_size() {
                self.range_type = RangeType::Open;
                if 0 <= b.highind {
                    let diffsz = (b.sstart - self.sstart) / self.ty.align_size() as i64;
                    let trialhi = b.highind + diffsz as i32;
                    if self.highind < trialhi {
                        self.highind = trialhi;
                    }
                }
            } else if self.start == b.start && !matches!(self.ty, Datatype::Struct(..)) {
                self.range_type = RangeType::Open;
            }
        } else if b.flags & FL_COPY_CONSTANT != 0 && self.range_type == RangeType::Open {
            let diffsz = b.sstart - self.sstart + b.size as i64;
            if diffsz > self.size as i64 {
                let trialhi = (diffsz / self.ty.align_size() as i64) as i32;
                if self.highind < trialhi {
                    self.highind = trialhi;
                }
            }
        }
        if self.flags & FL_COPY_CONSTANT != 0 && b.flags & FL_COPY_CONSTANT == 0 {
            self.flags ^= FL_COPY_CONSTANT;
        }
    }

    /// Ghidra `RangeHint::attemptJoin`: if `self` is an array and `b` lines up with its step,
    /// absorb `b` and return true.
    fn attempt_join(&mut self, b: &RangeHint) -> bool {
        if self.range_type != RangeType::Open {
            return false;
        }
        if b.range_type == RangeType::Endpoint {
            return false; // don't merge with bounding range
        }
        if self.is_const_absorbable(b) {
            self.absorb(b);
            return true;
        }
        if self.highind < 0 {
            return false;
        }
        let mut settype = self.ty.clone();
        if settype.align_size() != b.ty.align_size() {
            return false;
        }
        if settype != b.ty {
            // Compare through equal pointer nesting; unknown/int/uint are compatible.
            let (mut a_t, mut b_t) = (&self.ty, &b.ty);
            while let Datatype::Pointer(_, ap) = a_t {
                match b_t {
                    Datatype::Pointer(_, bp) => {
                        a_t = ap;
                        b_t = bp;
                    }
                    _ => break,
                }
            }
            let compatible = matches!(a_t, Datatype::Unknown(_))
                || matches!(b_t, Datatype::Unknown(_))
                || matches!((a_t, b_t), (Datatype::Int(_), Datatype::Uint(_)) | (Datatype::Uint(_), Datatype::Int(_)))
                || a_t == b_t;
            if !compatible {
                return false;
            }
            if matches!(a_t, Datatype::Unknown(_)) {
                settype = b.ty.clone();
            }
        }
        if self.is_type_lock() || b.is_type_lock() {
            return false;
        }
        let mut diffsz = b.sstart - self.sstart;
        if diffsz % settype.align_size() as i64 != 0 {
            return false;
        }
        diffsz /= settype.align_size() as i64;
        if diffsz > self.highind as i64 {
            return false;
        }
        self.ty = settype;
        self.absorb(b);
        true
    }

    /// Ghidra `RangeHint::merge`: redefine `self` as the union of the two intersecting ranges,
    /// preserving data-type information where possible. Returns true on an unreconcilable overlap.
    fn merge(&mut self, b: &RangeHint) -> bool {
        let res_type; // 0=self, 1=b, 2=confuse
        let did_reconcile;
        if self.contain(b) {
            did_reconcile = self.reconcile(b);
            if !did_reconcile && self.start != b.start {
                res_type = 2;
            } else {
                res_type = if self.preferred(b, did_reconcile) { 0 } else { 1 };
            }
        } else {
            did_reconcile = false;
            res_type = if self.is_type_lock() { 0 } else { 2 };
        }
        if !did_reconcile && self.is_type_lock() {
            // (mosura models no locked stack types yet — the throw/discard paths are unreachable)
            if b.is_type_lock() {
                return false;
            }
            if self.start != b.start {
                return false; // discard b entirely
            }
        }
        match res_type {
            0 => self.absorb(b),
            1 => {
                let copy = self.clone();
                self.ty = b.ty.clone();
                self.flags = b.flags;
                self.range_type = b.range_type;
                self.highind = b.highind;
                self.size = b.size;
                self.absorb(&copy);
            }
            _ => {
                // Concede confusion: an unknown type spanning the union.
                self.range_type = RangeType::Fixed;
                let diff = (b.sstart - self.sstart) as i32;
                if diff + b.size > self.size {
                    self.size = diff + b.size;
                }
                if !matches!(self.size, 1 | 2 | 4 | 8) {
                    self.size = 1;
                    self.range_type = RangeType::Open;
                }
                self.ty = Datatype::Unknown(self.size as u32);
                self.flags = 0;
                self.highind = -1;
                return false;
            }
        }
        false
    }

    /// Ghidra `RangeHint::compare`: order by signed start, size, range type, flags, high index.
    fn compare(&self, op2: &RangeHint) -> std::cmp::Ordering {
        use std::cmp::Ordering::*;
        if self.sstart != op2.sstart {
            return if self.sstart < op2.sstart { Less } else { Greater };
        }
        if self.size != op2.size {
            return if self.size < op2.size { Less } else { Greater };
        }
        let (rt, ort) = (self.range_type as i32, op2.range_type as i32);
        if rt != ort {
            return rt.cmp(&ort);
        }
        if self.flags != op2.flags {
            return self.flags.cmp(&op2.flags);
        }
        self.highind.cmp(&op2.highind)
    }
}

/// A recovered stack-frame symbol — the disjoint-cover result of [`restructure`].
#[derive(Clone, Debug, PartialEq)]
pub struct StackSymbol {
    /// Signed starting offset from the entry stack pointer (Ghidra `SymbolEntry::getAddr` offset).
    pub start: i64,
    /// Total byte size of the symbol (an array's full extent).
    pub size: u32,
    /// Recovered data-type — a scalar, or an `Array(elem, n)` for a recovered stack array.
    pub ty: Datatype,
}

impl StackSymbol {
    /// The element data-type and index of `off` within this symbol, if it is an array (so the
    /// printer can render `name[index]`). `None` ⇒ render as a scalar / sub-byte access.
    pub fn array_index(&self, off: i64) -> Option<(Datatype, i64)> {
        if let Datatype::Array(elem, _) = &self.ty {
            let es = elem.align_size() as i64;
            if es > 0 {
                return Some(((**elem).clone(), (off - self.start) / es));
            }
        }
        None
    }
}

/// Ghidra `MapState`: the collection of `RangeHint`s gathered for the stack address space.
struct MapState {
    space: SpaceId,
    maplist: Vec<RangeHint>,
    default_type: Datatype,
}

impl MapState {
    fn new(space: SpaceId) -> MapState {
        MapState { space, maplist: Vec::new(), default_type: Datatype::Unknown(1) }
    }

    /// Ghidra `MapState::addRange`: add a hint for `sz` bytes starting at `st`.
    fn add_range(&mut self, st: u64, ct: Option<Datatype>, fl: u32, rt: RangeType, hi: i32) {
        let ct = match ct {
            Some(c) if c.size() != 0 => c,
            _ => self.default_type.clone(),
        };
        let sz = ct.size() as i32;
        // (the RangeList mapped-window `inRange` guard is faithfully omitted — no param range yet)
        let sst = sign_extend(st, 63); // stack addrsize 8, wordsize 1 → identity
        self.maplist.push(RangeHint { start: st, size: sz, sstart: sst, ty: ct, flags: fl, range_type: rt, highind: hi });
    }

    /// Ghidra `MapState::addFixedType`: add a fixed reference (the `TypePartialStruct`/`PartialUnion`
    /// open-array unwrapping is unreached by the primitive lattice and faithfully omitted).
    fn add_fixed_type(&mut self, start: u64, ct: Datatype, flags: u32) {
        self.add_range(start, Some(ct), flags, RangeType::Fixed, -1);
    }

    /// Ghidra `MapState::gatherVarnodes`: a hint per Varnode stored in the stack space, carrying its
    /// current data-type. Marker/`PIECE`/`SUBPIECE` copies between the same location are filtered.
    fn gather_varnodes(&mut self, f: &Funcdata) {
        let space = self.space;
        let stack_vns: Vec<VarnodeId> = (0..f.num_varnodes() as u32)
            .map(VarnodeId)
            .filter(|&v| f.vn(v).loc.space == space && !f.vn(v).is_free())
            .collect();
        for vn in stack_vns {
            let v = f.vn(vn);
            if !v.is_written() {
                if is_read_active(f, vn) {
                    self.add_fixed_type(v.loc.offset, v.get_type(), 0);
                }
                continue;
            }
            let def = v.def.unwrap();
            match f.op(def).code() {
                OpCode::Indirect => {
                    let invn = f.op(def).input(0).unwrap();
                    if f.vn(invn).loc != v.loc || is_read_active(f, vn) {
                        self.add_fixed_type(v.loc.offset, v.get_type(), 0);
                    }
                }
                OpCode::Multiequal => {
                    let differs = (0..f.op(def).num_inputs())
                        .any(|i| f.vn(f.op(def).input(i).unwrap()).loc != v.loc);
                    if differs || is_read_active(f, vn) {
                        self.add_fixed_type(v.loc.offset, v.get_type(), 0);
                    }
                }
                OpCode::Copy => {
                    let in0 = f.op(def).input(0).unwrap();
                    let fl = if f.vn(in0).is_constant() { FL_COPY_CONSTANT } else { 0 };
                    self.add_fixed_type(v.loc.offset, v.get_type(), fl);
                }
                // SUBPIECE/PIECE same-location filtering is faithfully simplified to the default add.
                _ => self.add_fixed_type(v.loc.offset, v.get_type(), 0),
            }
        }
    }

    /// Ghidra `MapState::gatherOpen`: an \e open hint for every pointer into the stack space (its
    /// object size is unknown), so contiguous indexed accesses recover as an array. The
    /// `LoadGuard` array hints are faithfully omitted (mosura records no load guards).
    fn gather_open(&mut self, f: &Funcdata) {
        for ab in super::alias::gather_additive_base(f) {
            let offset = super::alias::gather_offset(f, ab.base);
            // The pointed-at element type (mosura's stack pointers are untyped → unknown array).
            let ct = f.vn(ab.base).get_type();
            let elem = match ct.ptr_to() {
                Some(mut p) => {
                    while let Datatype::Array(inner, _) = p {
                        p = inner;
                    }
                    Some(p.clone())
                }
                None => None,
            };
            let min_items = if ab.index.is_some() { 3 } else { -1 };
            self.add_range(offset, elem, 0, RangeType::Open, min_items);
        }
    }

    /// Ghidra `MapState::reconcileDatatypes`: among hints with the same start/size/flags, pick the
    /// most specific data-type and apply it to all, dropping exact duplicates.
    fn reconcile_datatypes(&mut self) {
        if self.maplist.is_empty() {
            return;
        }
        let mut new_list: Vec<RangeHint> = Vec::with_capacity(self.maplist.len());
        let mut start_pos = 0;
        new_list.push(self.maplist[0].clone());
        let mut start_hint = self.maplist[0].clone();
        let mut start_dt = start_hint.ty.clone();
        for cur_hint in self.maplist.iter().skip(1) {
            if cur_hint.start == start_hint.start
                && cur_hint.size == start_hint.size
                && cur_hint.flags == start_hint.flags
            {
                if type_order(&cur_hint.ty, &start_dt) == std::cmp::Ordering::Less {
                    start_dt = cur_hint.ty.clone();
                }
                if cur_hint.compare(new_list.last().unwrap()) != std::cmp::Ordering::Equal {
                    new_list.push(cur_hint.clone());
                }
            } else {
                while start_pos < new_list.len() {
                    new_list[start_pos].ty = start_dt.clone();
                    start_pos += 1;
                }
                start_hint = cur_hint.clone();
                start_dt = start_hint.ty.clone();
                new_list.push(cur_hint.clone());
            }
        }
        while start_pos < new_list.len() {
            new_list[start_pos].ty = start_dt.clone();
            start_pos += 1;
        }
        self.maplist = new_list;
    }

    /// Ghidra `MapState::initialize`: sort the collection and append the terminating endpoint hint.
    /// Returns false if there is nothing to lay out.
    fn initialize(&mut self) -> bool {
        if self.maplist.is_empty() {
            return false;
        }
        // Bound any final open entry at the locals/parameters boundary (the entry SP, offset 0).
        self.maplist.push(RangeHint {
            start: 0,
            size: 1,
            sstart: 0,
            ty: self.default_type.clone(),
            flags: 0,
            range_type: RangeType::Endpoint,
            highind: -2,
        });
        self.maplist.sort_by(|a, b| a.compare(b));
        self.reconcile_datatypes();
        true
    }
}

/// Ghidra `MapState::isReadActive`: is the Varnode read by something other than a marker/PIECE
/// copying back to its own location?
fn is_read_active(f: &Funcdata, vn: VarnodeId) -> bool {
    let loc = f.vn(vn).loc;
    for &op in &f.vn(vn).descend {
        let o = f.op(op);
        if matches!(o.code(), OpCode::Multiequal | OpCode::Indirect) {
            if f.vn(o.output.unwrap()).loc != loc {
                return true;
            }
        } else if o.code() == OpCode::Subpiece {
            // data-type info comes from the output; ignore the input read
        } else if o.code() == OpCode::Piece {
            return true; // (the same-location PIECE refinement is conservatively treated as active)
        } else {
            return true;
        }
    }
    false
}

/// Ghidra `ScopeLocal::createEntry`: build the final Symbol type for a fitted RangeHint (an array
/// if the range spans multiple elements) and emit it.
fn create_entry(a: &RangeHint, out: &mut Vec<StackSymbol>) {
    let ct = a.ty.clone(); // concretize() is identity for the primitive lattice
    let align = ct.align_size().max(1);
    let num = a.size as u32 / align;
    let ty = if num > 1 { Datatype::Array(Box::new(ct), num as u64) } else { ct };
    out.push(StackSymbol { start: a.sstart, size: a.size as u32, ty });
}

/// Ghidra `ScopeLocal::restructure`: merge the gathered `RangeHint`s into a disjoint cover of
/// Symbols. Overlapping hints are unioned; adjacent compatible hints extend an array.
fn restructure(state: &mut MapState, out: &mut Vec<StackSymbol>) {
    if !state.initialize() {
        return;
    }
    let list = std::mem::take(&mut state.maplist);
    let mut iter = list.into_iter();
    let mut cur = iter.next().unwrap();
    for next in iter {
        if next.sstart < cur.sstart + cur.size as i64 {
            // ranges intersect — union them
            cur.merge(&next);
        } else if !cur.attempt_join(&next) {
            if cur.range_type == RangeType::Open {
                cur.size = (next.sstart - cur.sstart) as i32;
            }
            if cur.size > 0 && !cur.is_type_lock() {
                create_entry(&cur, out);
            }
            cur = next;
        }
    }
    // The last range is the artificial endpoint, so no entry is built for it.
}

/// Recover the stack-frame Symbol layout for the function (Ghidra `ScopeLocal::restructureVarnode`
/// → `restructure`). Returns the disjoint cover of [`StackSymbol`]s; empty if there is no stack.
pub fn recover_scope(f: &Funcdata) -> Vec<StackSymbol> {
    let Some(stack) = f.spaces.by_name("stack") else { return Vec::new() };
    let mut state = MapState::new(stack);
    state.gather_varnodes(f);
    state.gather_open(f);
    let mut out = Vec::new();
    restructure(&mut state, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_scalar_slots_become_typed_symbols() {
        // Two adjacent int4 slots at -0x28 and -0x24 → two scalar symbols (no spurious join).
        let mut state = MapState::new(SpaceId(4));
        state.add_fixed_type(0xffffffffffffffd8, Datatype::Int(4), 0); // -0x28
        state.add_fixed_type(0xffffffffffffffdc, Datatype::Int(4), 0); // -0x24
        let mut out = Vec::new();
        restructure(&mut state, &mut out);
        assert_eq!(out, vec![
            StackSymbol { start: -0x28, size: 4, ty: Datatype::Int(4) },
            StackSymbol { start: -0x24, size: 4, ty: Datatype::Int(4) },
        ]);
    }

    #[test]
    fn open_range_with_index_recovers_an_array() {
        // loopcomment's frame: an indexed pointer + scalar [0] write at -0x1c, bounded above by the
        // next local (iStack_c at -0xc) → the open range covers 16 bytes = an array of 4 int4.
        let mut state = MapState::new(SpaceId(4));
        state.add_fixed_type(0xffffffffffffffe4, Datatype::Int(4), 0); // -0x1c (the [0] element)
        state.add_range(0xffffffffffffffe4, Some(Datatype::Int(4)), 0, RangeType::Open, 3);
        state.add_fixed_type(0xfffffffffffffff4, Datatype::Int(4), 0); // -0xc (bounds the array)
        let mut out = Vec::new();
        restructure(&mut state, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].start, -0x1c);
        assert_eq!(out[0].ty, Datatype::Array(Box::new(Datatype::Int(4)), 4));
        assert_eq!(out[0].array_index(-0x1c), Some((Datatype::Int(4), 0)));
        assert_eq!(out[1], StackSymbol { start: -0xc, size: 4, ty: Datatype::Int(4) });
    }
}
