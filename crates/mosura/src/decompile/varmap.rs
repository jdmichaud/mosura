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
//! locked-Symbol and `TypePartialStruct`/`PartialUnion` hint paths (`addFixedType`), and the
//! dynamic/name-recommendation bookkeeping — none of which is reached by the stripped x86-64
//! datatests. (The `LoadGuard` array hints, `addGuard`, are ported.)

use super::funcdata::Funcdata;
use super::opcode::OpCode;
use super::space::{Address, Range, RangeList, SpaceId, SpaceManager};
use super::types::{type_order, Datatype};
use super::varnode::VarnodeId;

/// Ghidra `sign_extend(val, bit)` — sign-extend treating bit index `bit` as the sign.
/// Sign-extend a 32-bit frame offset for display.
pub fn sx32(v: u64) -> i64 {
    sign_extend(v, 31)
}

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
        // `type->getMetatype()` against TYPE_INT/UINT/BOOL/FLOAT (varmap.cc:39-41) — a METATYPE
        // test, so `char` (TYPE_INT) is included.
        if !(self.ty.is_int_meta()
            || matches!(self.ty, Datatype::Uint(_) | Datatype::Bool | Datatype::Float(_)))
        {
            return false;
        }
        // `b->type->getMetatype()` against TYPE_UNKNOWN/INT/UINT (varmap.cc:42-44).
        if !(b.ty.is_int_meta() || matches!(b.ty, Datatype::Unknown(_) | Datatype::Uint(_))) {
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
        b.ty.is_int_meta() || matches!(b.ty, Datatype::Unknown(_) | Datatype::Uint(_))
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
                || (a_t.is_int_meta() && matches!(b_t, Datatype::Uint(_)))
                || (matches!(a_t, Datatype::Uint(_)) && b_t.is_int_meta())
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
    /// The symbol's name, built ONCE from this symbol's own data-type by [`build_variable_name`].
    /// Ghidra stores the name on the `Symbol` (`Scope::buildDefaultName`, database.cc:1756), so every
    /// reference to the slot renders identically no matter what type the referencing Varnode carries.
    pub name: String,
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

/// Ghidra `ScopeLocal::buildVariableName` (varmap.cc:548) for an address-tied slot in the stack
/// space: the default name of a local, derived from its FRAME offset and its own data-type.
///
/// `raw_off` is the slot's stored (wrapped) stack offset; the frame offset is derived here exactly as
/// Ghidra does (varmap.cc:556-557), then negated for a negative-growing stack (:558) so a local at
/// `-0x24` reads `_24`.
///
/// ⭐ The whole `Stack_` form is gated on `getLocalRange().inRange(addr,1)` (:554). That gate is not a
/// formality: with the default window (`ProtoModel::default_local_range`, fspec.cc:2263) a
/// non-negative frame offset is OUTSIDE the local range, so the caller-allocated `X` marker at :566
/// is unreachable — which is why Ghidra emits `StackX_` zero times over WAR2's 1286 functions.
/// Out-of-range addresses fall through to [`build_internal_variable_name`], Ghidra's `return
/// ScopeInternal::buildVariableName(...)` at :579.
///
/// Two pieces of Ghidra's version are called out rather than approximated: the `Y` marker for an
/// unusual stack region (:571-574) needs `ScopeLocal`'s `minParamOffset`/`maxParamOffset`, set by
/// `restructure` from the symbols it maps, and Ghidra emits zero `StackY_` names over WAR2.
/// `makeNameUnique` (:577) resolves collisions against the scope's name tree; `restructure` produces
/// a DISJOINT cover, so two symbols cannot share a start and no collision arises.
pub fn build_variable_name(
    spaces: &SpaceManager,
    space: SpaceId,
    raw_off: u64,
    ct: &Datatype,
    localrange: &RangeList,
) -> String {
    let spc = spaces.get(space);
    if !localrange.in_range(Address::new(space, raw_off), 1) {
        return build_internal_variable_name(spaces, space, raw_off, ct);
    }
    // `start = byteToAddress(off, wordsize); start = sign_extend(start, addrSize*8-1);` (:556-557).
    // Ghidra reads `stackGrowsNegative` from the prototype (`<stackpointer growth=>`, default
    // "negative"); every target mosura decompiles declares a negative-growing stack.
    let mut start = -sign_extend(raw_off, spc.addr_size.saturating_mul(8).saturating_sub(1));
    let mut s = ct.print_name_base();
    s.push_str(&capitalized(&spc.name));
    if start <= 0 {
        s.push('X'); // local stack space allocated by the caller
        start = -start;
    }
    s.push('_');
    s.push_str(&format!("{start:x}"));
    s
}

/// Ghidra `ScopeInternal::buildVariableName` (database.cc:2434), the `addrtied` branch at :2483: the
/// name of an address-tied value that no `Scope` maps — the type's `printNameBase` stem, the
/// capitalized space name, and the RAW offset in `2*addrSize` hex digits with NO separator
/// (`xStack00000004`, `iRam00089124`). It is what a stack address outside the local range gets, and
/// the shape says exactly that: an unmapped machine address, not a recovered local.
pub fn build_internal_variable_name(
    spaces: &SpaceManager,
    space: SpaceId,
    raw_off: u64,
    ct: &Datatype,
) -> String {
    let spc = spaces.get(space);
    let width = 2 * spc.addr_size as usize;
    // `byteToAddress(off, wordsize)` — the identity on every byte-addressable space mosura loads.
    format!("{}{}{raw_off:0width$x}", ct.print_name_base(), capitalized(&spc.name))
}

/// `spacename[0] = toupper(spacename[0])` (database.cc:2487 / varmap.cc:564).
fn capitalized(name: &str) -> String {
    let mut c = name.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Ghidra `MapState`: the collection of `RangeHint`s gathered for the stack address space.
struct MapState<'a> {
    spaces: &'a SpaceManager,
    space: SpaceId,
    /// The stack space's address size in BITS minus one — Ghidra's `spaceid->getAddrSize()*8-1`, the
    /// sign bit every frame offset is extended from (`MapState::addRange`, varmap.cc:905).
    sign_bit: u32,
    /// Ghidra `MapState::range` (varmap.cc:864-875): the `ScopeLocal`'s mapped window —
    /// `localrange ∪ paramrange` with `paramrange` then REMOVED ("Clear possible input symbols"), so
    /// in practice the local window alone. A hint outside it is dropped, which is why no `ScopeLocal`
    /// symbol ever lands on a stack parameter slot.
    range: RangeList,
    /// The prototype's `<localrange>` alone — what `ScopeLocal::buildVariableName` (varmap.cc:554)
    /// tests, which is NOT the same set as [`Self::range`] whenever a spec's two windows overlap.
    localrange: &'a RangeList,
    maplist: Vec<RangeHint>,
    default_type: Datatype,
}

impl<'a> MapState<'a> {
    fn new(
        spaces: &'a SpaceManager,
        space: SpaceId,
        range: RangeList,
        localrange: &'a RangeList,
    ) -> MapState<'a> {
        MapState {
            spaces,
            space,
            sign_bit: spaces.get(space).addr_size.saturating_mul(8).saturating_sub(1),
            range,
            localrange,
            maplist: Vec::new(),
            default_type: Datatype::Unknown(1),
        }
    }

    /// Ghidra `MapState::addRange`: add a hint for `sz` bytes starting at `st`.
    fn add_range(&mut self, st: u64, ct: Option<Datatype>, fl: u32, rt: RangeType, hi: i32) {
        let ct = match ct {
            Some(c) if c.size() != 0 => c,
            _ => self.default_type.clone(),
        };
        let sz = ct.size() as i32;
        // `if (!range.inRange(Address(spaceid,st),sz)) return;` (varmap.cc:900).
        if !self.range.in_range(Address::new(self.space, st), sz as u32) {
            return;
        }
        // Ghidra `sign_extend(sst, spaceid->getAddrSize()*8-1)` (varmap.cc:905). A 32-bit stack keeps
        // its offsets wrapped (`0xffffffdc`), so without the extension every frame offset compares as
        // a large POSITIVE number: the terminating endpoint hint (sstart 0) then sorts FIRST instead
        // of last, `restructure` emits it as a symbol and never flushes the final real one.
        let sst = sign_extend(st, self.sign_bit); // wordsize 1 → byteToAddress is the identity
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

    /// Ghidra `MapState::addGuard` (varmap.cc:1003): an \e open array hint from a LoadGuard with
    /// a definitive step — the element is the pointer's pointee (or an unknown of the step's
    /// width), the item count the locked range's, else the default 4.
    fn add_guard(&mut self, f: &Funcdata, guard: &super::heritage::LoadGuard, opc: OpCode) {
        if !guard.is_valid(f, opc) {
            return;
        }
        let mut step = guard.step;
        if step == 0 {
            return; // No definitive sign of array access
        }
        let op = guard.op;
        let ptr = f.op(op).input(1).expect("LOAD/STORE pointer");
        let mut ct = f.vn(ptr).get_type();
        if let Some(mut p) = ct.ptr_to().cloned() {
            while let Datatype::Array(inner, _) = p {
                p = *inner;
            }
            ct = p;
        }
        let out_size = if opc == OpCode::Store {
            f.vn(f.op(op).input(2).expect("STORE value")).size as i32 // The Varnode being stored
        } else {
            f.vn(f.op(op).output.expect("LOAD output")).size as i32 // The Varnode being loaded
        };
        if out_size != step {
            // LOAD size doesn't match step: field in array of structures or something more unusual
            if out_size > step || (step % out_size) != 0 {
                return;
            }
            // Since the LOAD size divides the step and we want to preserve the arrayness
            // we pretend we have an array of LOAD's size
            step = out_size;
        }
        if ct.align_size() as i32 != step {
            // Make sure data-type matches our step size
            if step > 8 {
                return; // Don't manufacture primitives bigger than 8-bytes
            }
            ct = Datatype::Unknown(step as u32);
        }
        if guard.is_range_locked() {
            let min_items = ((guard.maximum_offset.wrapping_sub(guard.minimum_offset)).wrapping_add(1) / step as u64) as i32;
            self.add_range(guard.minimum_offset, Some(ct), 0, RangeType::Open, min_items - 1);
        } else {
            self.add_range(guard.minimum_offset, Some(ct), 0, RangeType::Open, 3);
        }
    }

    /// Ghidra `MapState::gatherOpen`: an \e open hint for every pointer into the stack space (its
    /// object size is unknown), so contiguous indexed accesses recover as an array, plus the
    /// `LoadGuard` array hints (`addGuard`, varmap.cc:1242-1248).
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
        for guard in &f.load_guard {
            self.add_guard(f, guard, OpCode::Load);
        }
        for guard in &f.store_guard {
            self.add_guard(f, guard, OpCode::Store);
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
        let highest = self.spaces.get(self.space).highest();
        // Ghidra `MapState::initialize` (varmap.cc) bounds any final open entry ONE PAST THE END
        // OF THE WINDOW — `high = wrapOffset(lastSignedRange->getLast()+1)` — not at a fixed offset
        // 0. The two agree for an untouched frame (the default `<localrange>` ends at -1, so the
        // endpoint is 0), and diverge exactly when `markNotMapped` has carved the callee-save slots
        // off the top: then the window ends at -5 and a trailing open range stops at -4 instead of
        // running into the saved register.
        let Some(term) = last_signed_range(&self.range, self.space, highest) else {
            return false;
        };
        let high = term.last.wrapping_add(1) & highest;
        self.maplist.push(RangeHint {
            start: high,
            size: 1,
            sstart: sign_extend(high, self.sign_bit),
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
fn create_entry(state: &MapState, a: &RangeHint, out: &mut Vec<StackSymbol>) {
    let ct = a.ty.clone(); // concretize() is identity for the primitive lattice
    let align = ct.align_size().max(1);
    let num = a.size as u32 / align;
    let ty = if num > 1 { Datatype::Array(Box::new(ct), num as u64) } else { ct };
    // Ghidra names the Symbol here, from the Symbol's own type (`ScopeLocal::createEntry` →
    // `addSymbol` → `buildDefaultName`), not at each reference.
    let name =
        build_variable_name(state.spaces, state.space, a.start, &ty, state.localrange);
    out.push(StackSymbol { start: a.sstart, size: a.size as u32, ty, name });
}

/// Ghidra `ScopeLocal::adjustFit` (varmap.cc): shrink the hint so it fits the MAPPED region of
/// the scope — `RangeList::longestFit` from its start, i.e. the open range stops at the first
/// ownership hole — and so it does not overlap a Symbol already created; `false` when no valid
/// shrink exists (nothing to fit, already entered, off the map, or shrunk below its own type).
///
/// This is the step that makes a `markNotMapped` carve BOUND an open range: the window's
/// terminator only sits past the LAST range, so without it an open array runs straight through
/// the callee-save hole to the frame top. Measured: sfile_make_name's 12-byte buffer declared
/// `[28]` (frame `SUB ESP,0x1c` for the original's `0xc`), parse_argument's `[24]` for `[4]` —
/// Ghidra's own C for the same fixtures has `[12]` and `[4]` (wc2src-reconciliation-2 A2i).
fn adjust_fit(state: &MapState, a: &mut RangeHint, out: &[StackSymbol]) -> bool {
    if a.size == 0 {
        return false; // nothing to fit
    }
    if a.is_type_lock() {
        return false; // already entered
    }
    let maxsize = state.range.longest_fit(state.space, a.start, a.size as u64);
    if maxsize == 0 {
        return false;
    }
    if maxsize < a.size as u64 {
        // the suggested range doesn't fit
        if maxsize < a.ty.size() as u64 {
            return false; // can't shrink that much
        }
        a.size = maxsize as i32;
    }
    // ANY symbol that might be within this range
    let (s, e) = (a.sstart, a.sstart + a.size as i64);
    if let Some(entry) =
        out.iter().filter(|sym| sym.start < e && sym.start + sym.size as i64 > s).min_by_key(|sym| sym.start)
    {
        if entry.start <= a.sstart {
            return false;
        }
        let maxsize = (entry.start - a.sstart) as u64;
        if maxsize < a.ty.size() as u64 {
            return false; // can't shrink for this type
        }
        a.size = maxsize as i32;
    }
    true
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
            if adjust_fit(state, &mut cur, out) {
                create_entry(state, &cur, out);
            }
            cur = next;
        }
    }
    // The last range is the artificial endpoint, so no entry is built for it.
}

/// Ghidra `RangeList::getLastSignedRange` (space.cc): the last range in SIGNED order — the last
/// one starting at or below the space's midpoint (the "positive" side) if any, otherwise the last
/// range overall (the "negative" side). A stack window is entirely negative, so in practice this is
/// the final range, and its `last` is the byte just below the frame boundary.
fn last_signed_range(rl: &RangeList, spc: SpaceId, highest: u64) -> Option<&Range> {
    let midway = highest / 2;
    rl.iter()
        .rfind(|r| r.spc == spc && r.first <= midway)
        .or_else(|| rl.iter().rfind(|r| r.spc == spc))
}

/// The window `MapState` will accept hints in. Ghidra builds it in two steps: `ScopeLocal`'s own
/// range tree is `localrange ∪ paramrange` (`ScopeLocal::resetLocalWindow`, varmap.cc:441-459), and
/// `MapState`'s constructor then removes `paramrange` from its copy (varmap.cc:870-875, "Clear
/// possible input symbols"). The union-then-subtract is not a no-op: where the two windows overlap
/// (x86-64-gcc's `<localrange>` includes `[8,39]`, inside the default `paramrange` `[0,511]`) the
/// subtraction wins, and a convention with no stack parameter area keeps its whole local window.
fn map_state_range(f: &Funcdata) -> RangeList {
    let mut rl = f.proto_model.localrange.clone();
    for r in f.proto_model.paramrange.iter() {
        rl.insert_range(r.spc, r.first, r.last);
    }
    for r in f.proto_model.paramrange.iter() {
        rl.remove_range(r.spc, r.first, r.last);
    }
    // Ghidra `ScopeLocal::markNotMapped` removes the callee-save slots from the Scope's range tree
    // itself (varmap.cc), so both this window and `initialize`'s endpoint see the hole.
    for r in f.not_mapped.iter().cloned().collect::<Vec<_>>() {
        rl.remove_range(r.spc, r.first, r.last);
    }
    rl
}

/// Recover the stack-frame Symbol layout for the function (Ghidra `ScopeLocal::restructureVarnode`
/// → `restructure`). Returns the disjoint cover of [`StackSymbol`]s; empty if there is no stack.
pub fn recover_scope(f: &Funcdata) -> Vec<StackSymbol> {
    let Some(stack) = f.spaces.by_name("stack") else { return Vec::new() };
    let mut state =
        MapState::new(&f.spaces, stack, map_state_range(f), &f.proto_model.localrange);
    state.gather_varnodes(f);
    state.gather_open(f);
    // `MOSURA_VARMAP=1` dumps the window, the gathered hints and the resulting Symbols, keyed by
    // function — the counterpart to `MOSURA_CFG`. Frame-layout divergences are otherwise only
    // visible as their third-order symptom (a declared array of the wrong length, hence a wrong
    // `sub esp,N`), which is how the FUN_0005118c over-extension went unnoticed.
    if std::env::var_os("MOSURA_VARMAP").is_some() {
        let rl = map_state_range(f);
        for r in rl.iter() {
            eprintln!("VARMAP[{}] range first={} last={}", f.name, r.first as i64, r.last as i64);
        }
        for v in (0..f.num_varnodes() as u32).map(VarnodeId) {
            if f.vn(v).loc.space != stack {
                continue;
            }
            let off = sign_extend(f.vn(v).loc.offset, 31);
            let def = f.vn(v).def.map(|d| format!("{:?}", f.op(d).code()));
            eprintln!(
                "VARMAP[{}] stackvn off={} size={} free={} def={:?} ndescend={}",
                f.name,
                off,
                f.vn(v).size,
                f.vn(v).is_free(),
                def,
                f.vn(v).descend.len()
            );
        }
        for h in &state.maplist {
            eprintln!(
                "VARMAP[{}] hint sstart={} size={} type={:?}",
                f.name, h.sstart, h.size, h.range_type
            );
        }
    }
    let mut out = Vec::new();
    restructure(&mut state, &mut out);
    coalesce_guarded_regions(f, &state, &mut out);
    if std::env::var_os("MOSURA_VARMAP").is_some() {
        for sym in &out {
            eprintln!("VARMAP[{}] sym start={} size={} name={}", f.name, sym.start, sym.size, sym.name);
        }
    }
    out
}

/// EMISSION ARM, beyond Ghidra (recompilation): the frame region an indexed stack LOAD/STORE
/// walks must be ONE C object, or the pointer arithmetic the body performs across it is
/// undefined and the recompiler is free to drop it. Ghidra's `MapState` keeps the per-slot
/// symbols (its `addGuard` hint is `open` and the fixed slot hints win, so it prints
/// `aiStack_30 [2]; xStack_28; xStack_20; …` for a register-save area) — faithful C whose layout
/// only the original compiler guaranteed. Ground truth `vsum`: gcc folded
/// `*(int4 *)((int8)aiStack_30 + uVar3)` to nothing.
///
/// The guard's analysed MAXIMUM is not a usable bound — unlocked guards clip to the frame top and
/// the first cut of this arm swallowed whole frames (zc39: ten COMPILE_FAILs). What characterizes
/// a save area is the SLOTS themselves: starting at the guard's pointer base, a contiguous run of
/// Symbols of the element width (the guard's step, else the access width) that the body only
/// WRITES or takes the address of — never reads by name (a slot read by name is a variable of its
/// own and ends the run). Two or more such slots become one array of the element width.
fn coalesce_guarded_regions(f: &Funcdata, state: &MapState, out: &mut Vec<StackSymbol>) {
    let Some(stack) = f.spaces.by_name("stack") else { return };
    let spc = f.spaces.get(stack);
    let bits = spc.addr_size.saturating_mul(8).saturating_sub(1);
    // Frame offsets read by name: any stack Varnode with a reader.
    let mut read_ranges: Vec<(i64, i64)> = Vec::new();
    for i in 0..f.num_varnodes() as u32 {
        let vn = f.vn(VarnodeId(i));
        if vn.loc.space == stack && !vn.descend.is_empty() {
            let st = sign_extend(vn.loc.offset, bits);
            read_ranges.push((st, st + vn.size as i64));
        }
    }
    let read_by_name = |st: i64, end: i64| read_ranges.iter().any(|&(a, b)| a < end && b > st);
    let guards: Vec<(&super::heritage::LoadGuard, OpCode)> = f
        .load_guard
        .iter()
        .map(|g| (g, OpCode::Load))
        .chain(f.store_guard.iter().map(|g| (g, OpCode::Store)))
        .collect();
    for (g, opc) in guards {
        if !g.is_valid(f, opc) || g.spc != stack {
            continue;
        }
        let op = g.op;
        let width = if opc == OpCode::Store {
            f.op(op).input(2).map_or(0, |v| f.vn(v).size)
        } else {
            f.op(op).output.map_or(0, |v| f.vn(v).size)
        };
        let elem = if g.step > 0 { g.step as u32 } else { width };
        if elem == 0 {
            continue;
        }
        let base = sign_extend(g.pointer_base, bits);
        if base >= 0 {
            continue; // the caller's frame is not ours to lay out
        }
        out.sort_by_key(|s| s.start);
        let Some(first) = out.iter().position(|s| s.start == base) else { continue };
        // The run: contiguous, element-width (or an array of it), never read by name.
        let mut last = first;
        let mut cursor = base;
        for (i, sym) in out.iter().enumerate().skip(first) {
            if sym.start != cursor {
                break;
            }
            let unit = match &sym.ty {
                Datatype::Array(e, _) => e.size(),
                t => t.size(),
            };
            if unit != elem && sym.size != elem {
                break;
            }
            if read_by_name(sym.start, sym.start + sym.size as i64) {
                break;
            }
            last = i;
            cursor = sym.start + sym.size as i64;
        }
        if last == first {
            continue;
        }
        let span = (cursor - base) as u32;
        let count = span.div_ceil(elem);
        let elem_ty = out[first..=last]
            .iter()
            .map(|s| match &s.ty {
                Datatype::Array(e, _) => (**e).clone(),
                t => t.clone(),
            })
            .find(|t| t.size() == elem && !matches!(t, Datatype::Unknown(_)))
            .unwrap_or(Datatype::Unknown(elem));
        let ty = Datatype::Array(Box::new(elem_ty), count as u64);
        let raw = spc.wrap_offset(base as u64);
        let name = build_variable_name(state.spaces, state.space, raw, &ty, state.localrange);
        out.drain(first..=last);
        out.push(StackSymbol { start: base, size: count * elem, ty, name });
        out.sort_by_key(|s| s.start);
    }
}

#[cfg(test)]
mod tests {
    use super::super::fspec::ProtoModel;
    use super::*;

    /// The x86-64 default: an 8-byte `stack` space with the default `<localrange>`/`<paramrange>`.
    fn stack_fixture() -> (SpaceManager, SpaceId, RangeList, RangeList) {
        let spaces = SpaceManager::standard();
        let stack = spaces.by_name("stack").unwrap();
        let local = ProtoModel::default_local_range(&spaces, true);
        let param = ProtoModel::default_param_range(&spaces, true);
        (spaces, stack, local, param)
    }

    fn map_state<'a>(
        spaces: &'a SpaceManager,
        stack: SpaceId,
        local: &'a RangeList,
        param: &RangeList,
    ) -> MapState<'a> {
        let mut range = local.clone();
        for r in param.iter() {
            range.remove_range(r.spc, r.first, r.last);
        }
        MapState::new(spaces, stack, range, local)
    }

    /// A trailing OPEN range is bounded by the artificial endpoint, and the endpoint sits one past
    /// the end of the WINDOW — so once `ActionRestrictLocal` has carved the callee-save slot out,
    /// the array stops there instead of running into it.
    ///
    /// This is FUN_0005118c's defect in miniature: a buffer that Open Watcom allocates 16 bytes for
    /// recovered as 20 because nothing occupied the saved-register slot above it, and the recompile
    /// emitted `sub esp,0x14` against the original's `sub esp,0x10`.
    #[test]
    fn a_saved_register_slot_bounds_a_trailing_open_range() {
        let (spaces, stack, local, param) = stack_fixture();
        // Baseline: with the whole window available the open range runs to the frame base.
        let mut state = map_state(&spaces, stack, &local, &param);
        state.add_range(0xffffffffffffffe8, None, 0, RangeType::Open, -1); // -0x18
        let mut out = Vec::new();
        restructure(&mut state, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].start, -0x18);
        assert_eq!(out[0].size, 0x18, "unbounded, the open range reaches offset 0");

        // Now mark an 8-byte callee-save slot at -8 not-mapped, as ActionRestrictLocal does.
        let mut carved = local.clone();
        carved.remove_range(stack, 0xfffffffffffffff8, 0xffffffffffffffff);
        let mut state = map_state(&spaces, stack, &carved, &param);
        state.add_range(0xffffffffffffffe8, None, 0, RangeType::Open, -1);
        let mut out = Vec::new();
        restructure(&mut state, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].start, -0x18);
        assert_eq!(out[0].size, 0x10, "the open range stops at the saved slot, not the frame base");
    }

    #[test]
    fn fixed_scalar_slots_become_typed_symbols() {
        // Two adjacent int4 slots at -0x28 and -0x24 → two scalar symbols (no spurious join).
        let (spaces, stack, local, param) = stack_fixture();
        let mut state = map_state(&spaces, stack, &local, &param);
        state.add_fixed_type(0xffffffffffffffd8, Datatype::Int(4), 0); // -0x28
        state.add_fixed_type(0xffffffffffffffdc, Datatype::Int(4), 0); // -0x24
        let mut out = Vec::new();
        restructure(&mut state, &mut out);
        assert_eq!(out, vec![
            StackSymbol { start: -0x28, size: 4, ty: Datatype::Int(4), name: "iStack_28".into() },
            StackSymbol { start: -0x24, size: 4, ty: Datatype::Int(4), name: "iStack_24".into() },
        ]);
    }

    /// Ghidra `ScopeLocal::buildVariableName` (varmap.cc:548-577): the frame offset is negated for a
    /// negative-growing stack and the stem is the SYMBOL's own `printNameBase`.
    #[test]
    fn variable_names_match_ghidra_scopelocal() {
        let (spaces, stack, local, _) = stack_fixture();
        let name = |off: i64, ty: &Datatype| {
            build_variable_name(&spaces, stack, off as u64, ty, &local)
        };
        assert_eq!(name(-0x24, &Datatype::Int(4)), "iStack_24");
        assert_eq!(name(-0x16, &Datatype::Int(2)), "iStack_16");
        assert_eq!(name(-0x18, &Datatype::Unknown(4)), "xStack_18");
        assert_eq!(name(-0x10, &Datatype::Uint(1)), "uStack_10");
        // pointer/array stems recurse (type.hh:424/457)
        assert_eq!(name(-0x1c, &Datatype::Array(Box::new(Datatype::Int(4)), 4)), "aiStack_1c");
        assert_eq!(name(-0x8, &Datatype::Pointer(4, Box::new(Datatype::Uint(4)))), "puStack_8");
    }

    /// ⭐ The caller-allocated `X` marker (varmap.cc:566) is behind the `getLocalRange().inRange`
    /// test at varmap.cc:554, and `ProtoModel::defaultLocalRange` (fspec.cc:2263) covers only the top
    /// 999999 bytes — the NEGATIVE offsets. So a non-negative frame offset never reaches the marker;
    /// it takes `ScopeInternal::buildVariableName`'s unmapped-address form instead (database.cc:2483,
    /// `2*addrSize` hex digits, no separator). This is why Ghidra emits `StackX_` and `StackY_` zero
    /// times across WAR2's 1286 functions.
    #[test]
    fn nonnegative_frame_offsets_are_outside_the_local_range() {
        let (spaces, stack, local, param) = stack_fixture();
        assert!(local.in_range(Address::new(stack, (-0x24i64) as u64), 1));
        assert!(!local.in_range(Address::new(stack, 0), 1));
        assert!(!local.in_range(Address::new(stack, 8), 1));
        assert!(param.in_range(Address::new(stack, 8), 1));
        let name = |off: u64, ty: &Datatype| build_variable_name(&spaces, stack, off, ty, &local);
        assert_eq!(name(0, &Datatype::Int(4)), "iStack0000000000000000");
        assert_eq!(name(8, &Datatype::Int(4)), "iStack0000000000000008");
        // and no hint at such an offset is ever mapped (varmap.cc:900)
        let mut state = map_state(&spaces, stack, &local, &param);
        state.add_fixed_type(8, Datatype::Int(4), 0);
        state.add_fixed_type(0xffffffffffffffdc, Datatype::Int(4), 0); // -0x24
        let mut out = Vec::new();
        restructure(&mut state, &mut out);
        assert_eq!(out.iter().map(|s| s.start).collect::<Vec<_>>(), vec![-0x24]);
    }

    #[test]
    fn open_range_with_index_recovers_an_array() {
        // loopcomment's frame: an indexed pointer + scalar [0] write at -0x1c, bounded above by the
        // next local (iStack_c at -0xc) → the open range covers 16 bytes = an array of 4 int4.
        let (spaces, stack, local, param) = stack_fixture();
        let mut state = map_state(&spaces, stack, &local, &param);
        state.add_fixed_type(0xffffffffffffffe4, Datatype::Int(4), 0); // -0x1c (the [0] element)
        state.add_range(0xffffffffffffffe4, Some(Datatype::Int(4)), 0, RangeType::Open, 3);
        state.add_fixed_type(0xfffffffffffffff4, Datatype::Int(4), 0); // -0xc (bounds the array)
        let mut out = Vec::new();
        restructure(&mut state, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].start, -0x1c);
        assert_eq!(out[0].ty, Datatype::Array(Box::new(Datatype::Int(4)), 4));
        assert_eq!(out[0].array_index(-0x1c), Some((Datatype::Int(4), 0)));
        assert_eq!(out[0].name, "aiStack_1c");
        assert_eq!(
            out[1],
            StackSymbol { start: -0xc, size: 4, ty: Datatype::Int(4), name: "iStack_c".into() }
        );
    }
}
