//! Large-scale data-flow transforms — a port of Ghidra's `transform.hh`/`transform.cc`.
//!
//! A [`TransformManager`] builds a *view* of a set of new/modified Varnodes and PcodeOps
//! ([`TransformVar`]/[`TransformOp`] placeholders) describing how a region of the data-flow will
//! be rewritten, then [`apply`](TransformManager::apply)s the whole view to the function at once.
//! Ghidra uses this to split wide values into logical pieces: `LaneDivide` (laned vector split,
//! [`super::subflow`] — task #6), `SplitFlow`/`SubfloatFlow` (double-precision), and `SplitDatatype`
//! all subclass `TransformManager`. This module is the shared base; the split drivers layer on top.
//!
//! Pointer-arithmetic note: Ghidra addresses placeholders with raw `TransformVar*`/`TransformOp*`
//! and indexes split arrays as `rvn + i`. mosura uses arena indices ([`TVarId`]/[`TOpId`]) into the
//! manager's own `Vec`s; a split allocates its lanes contiguously so `rvn + i` becomes
//! `TVarId(base + i)`. Byte-addressable little-endian only (x86-64): Ghidra's big-endian
//! lane-reordering + `Address::renormalize` are identities here and omitted, the same convention as
//! [`super::subvarflow`].

use super::funcdata::Funcdata;
use super::opcode::OpCode;
use super::op::OpId;
use super::space::{Address, SpaceKind};
use super::varnode::VarnodeId;

/// A handle to a [`TransformVar`] placeholder in a [`TransformManager`]'s arena.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TVarId(pub u32);
/// A handle to a [`TransformOp`] placeholder in a [`TransformManager`]'s arena.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TOpId(pub u32);

/// Types of replacement Varnodes (Ghidra `TransformVar` enum, transform.hh:36).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TVarType {
    /// New Varnode is a piece of an original Varnode (overlapping storage preserved).
    Piece = 1,
    /// Varnode preexisted in the original data-flow.
    Preexisting = 2,
    /// A new temporary (`unique` space) Varnode.
    NormalTemp = 3,
    /// A temporary representing a piece of an original Varnode.
    PieceTemp = 4,
    /// A new constant Varnode.
    Constant = 5,
    /// Special iop constant encoding a PcodeOp reference (INDIRECT). Unused in mosura's 1-input
    /// INDIRECT model; see the buildIndirect rebase TODO in [`super::subflow`].
    ConstantIop = 6,
}

/// [`TransformVar`] boolean flags (Ghidra transform.hh:45).
pub mod tvar_flags {
    /// The last (most significant piece) of a split array.
    pub const SPLIT_TERMINATOR: u32 = 1;
    /// This is a piece of an input that has already been visited.
    pub const INPUT_DUPLICATE: u32 = 2;
}

/// [`TransformOp`] special-handling codes (Ghidra transform.hh:71).
pub mod top_flags {
    /// Op replaces an existing op.
    pub const OP_REPLACEMENT: u32 = 1;
    /// Op already exists (but will be transformed).
    pub const OP_PREEXISTING: u32 = 2;
    /// Mark op as indirect creation.
    pub const INDIRECT_CREATION: u32 = 4;
    /// Mark op as indirect creation and possible call output.
    pub const INDIRECT_CREATION_POSSIBLE_OUT: u32 = 8;
}

/// Placeholder node for a Varnode that will exist after a transform is applied (Ghidra
/// `TransformVar`, transform.hh:31).
#[derive(Clone, Debug)]
pub struct TransformVar {
    /// Original \b big Varnode of which this is a component (`None` for temps/constants).
    pub vn: Option<VarnodeId>,
    /// The new explicit lane Varnode, once created.
    pub replacement: Option<VarnodeId>,
    pub ttype: TVarType,
    pub flags: u32,
    /// Size of the lane Varnode in bytes.
    pub byte_size: i32,
    /// Size of the logical value in bits.
    pub bit_size: i32,
    /// Value of constant, or (bit) position within the original big Varnode.
    pub val: u64,
    /// Defining op for the new Varnode.
    pub def: Option<TOpId>,
}

/// Placeholder node for a PcodeOp that will exist after a transform is applied (Ghidra
/// `TransformOp`, transform.hh:66).
#[derive(Clone, Debug)]
pub struct TransformOp {
    /// Original op which this is splitting (or the follow's original op for a new op).
    pub op: Option<OpId>,
    /// The new replacement op, once created.
    pub replacement: Option<OpId>,
    pub opc: OpCode,
    pub special: u32,
    pub output: Option<TVarId>,
    pub input: Vec<Option<TVarId>>,
    /// The op that follows this one (if not `None`), gating insertion order.
    pub follow: Option<TOpId>,
}

// ---------------------------------------------------------------------------------------------
// LanedRegister — a (register) storage location and the ways it can be split into lanes.
// (Ghidra transform.hh:94 / transform.cc:284.)
// ---------------------------------------------------------------------------------------------

/// Describes a (register) storage location and the permissible lane sizes it may be split into
/// (Ghidra `LanedRegister`, transform.hh:94). The record is keyed by the *size* of the whole
/// register (Ghidra `Architecture::getLanedRegister`, architecture.cc:290, matches on size only).
#[derive(Clone, Debug, Default)]
pub struct LanedRegister {
    /// Size of the whole register in bytes.
    whole_size: i32,
    /// A 1-bit for every permissible lane size.
    size_bit_mask: u32,
}

impl LanedRegister {
    pub fn new(sz: i32, mask: u32) -> LanedRegister {
        LanedRegister { whole_size: sz, size_bit_mask: mask }
    }

    /// Parse a `vector_lane_sizes` attribute — a comma-separated list of byte sizes (Ghidra
    /// `LanedRegister::parseSizes`, transform.cc:300). `register_size` is the whole register width.
    pub fn parse_sizes(&mut self, register_size: i32, lane_sizes: &str) {
        self.whole_size = register_size;
        self.size_bit_mask = 0;
        for tok in lane_sizes.split(',') {
            let tok = tok.trim();
            if tok.is_empty() {
                continue;
            }
            // Ghidra accepts hex/dec/oct via istream>>; the pspec uses plain decimal.
            let sz: i32 = tok.parse().unwrap_or(-1);
            if !(0..=16).contains(&sz) {
                continue; // Ghidra throws; the pspec never carries an out-of-range size.
            }
            self.add_lane_size(sz);
        }
    }

    pub fn whole_size(&self) -> i32 {
        self.whole_size
    }
    pub fn size_bit_mask(&self) -> u32 {
        self.size_bit_mask
    }
    /// Add a new lane `size` to the allowed set.
    pub fn add_lane_size(&mut self, size: i32) {
        self.size_bit_mask |= 1u32 << size;
    }
    /// Is `size` among the allowed lane sizes.
    pub fn allowed_lane(&self, size: i32) -> bool {
        ((self.size_bit_mask >> size) & 1) != 0
    }
    /// Iterate the permissible lane sizes, least to greatest (Ghidra `LanedIterator`).
    pub fn lane_sizes(&self) -> impl Iterator<Item = i32> {
        let mask = self.size_bit_mask;
        (0..32).filter(move |&s| (mask >> s) & 1 != 0)
    }
}

// ---------------------------------------------------------------------------------------------
// LaneDescription — logical lanes tiling a big Varnode. (Ghidra transform.hh:132 / transform.cc:24.)
// ---------------------------------------------------------------------------------------------

/// Description of logical lanes within a big Varnode (Ghidra `LaneDescription`, transform.hh:132).
/// A lane is a byte offset and size; lanes are disjoint and tile the whole region.
#[derive(Clone, Debug)]
pub struct LaneDescription {
    whole_size: i32,
    lane_size: Vec<i32>,
    lane_position: Vec<i32>,
}

impl LaneDescription {
    /// Uniform lanes of size `sz` tiling `orig_size` bytes (Ghidra transform.cc:35).
    pub fn uniform(orig_size: i32, sz: i32) -> LaneDescription {
        let num_lanes = orig_size / sz;
        let mut lane_size = vec![0; num_lanes as usize];
        let mut lane_position = vec![0; num_lanes as usize];
        let mut pos = 0;
        for i in 0..num_lanes as usize {
            lane_size[i] = sz;
            lane_position[i] = pos;
            pos += sz;
        }
        LaneDescription { whole_size: orig_size, lane_size, lane_position }
    }

    /// Two lanes of arbitrary size `lo` then `hi` (Ghidra transform.cc:53).
    pub fn two(orig_size: i32, lo: i32, hi: i32) -> LaneDescription {
        LaneDescription {
            whole_size: orig_size,
            lane_size: vec![lo, hi],
            lane_position: vec![0, lo],
        }
    }

    /// Trim to a subset `[lsb_offset, lsb_offset+size)` of the original lanes; `false` if the
    /// subrange splits a lane (Ghidra transform.cc:72).
    pub fn subset(&mut self, lsb_offset: i32, size: i32) -> bool {
        if lsb_offset == 0 && size == self.whole_size {
            return true;
        }
        let first_lane = self.get_boundary(lsb_offset);
        if first_lane < 0 {
            return false;
        }
        let last_lane = self.get_boundary(lsb_offset + size);
        if last_lane < 0 {
            return false;
        }
        let mut new_lane_size = Vec::new();
        self.lane_position.clear();
        let mut new_position = 0;
        for i in first_lane..last_lane {
            let sz = self.lane_size[i as usize];
            self.lane_position.push(new_position);
            new_lane_size.push(sz);
            new_position += sz;
        }
        self.whole_size = size;
        self.lane_size = new_lane_size;
        true
    }

    pub fn num_lanes(&self) -> i32 {
        self.lane_size.len() as i32
    }
    pub fn whole_size(&self) -> i32 {
        self.whole_size
    }
    pub fn size(&self, i: i32) -> i32 {
        self.lane_size[i as usize]
    }
    pub fn position(&self, i: i32) -> i32 {
        self.lane_position[i as usize]
    }

    /// Index of the lane starting at byte position `byte_pos`, or -1 if out of bounds / not on a
    /// lane boundary (Ghidra transform.cc:100). Position == whole size maps to the lane count.
    pub fn get_boundary(&self, byte_pos: i32) -> i32 {
        if byte_pos < 0 || byte_pos > self.whole_size {
            return -1;
        }
        if byte_pos == self.whole_size {
            return self.lane_position.len() as i32;
        }
        let mut min = 0i32;
        let mut max = self.lane_position.len() as i32 - 1;
        while min <= max {
            let index = (min + max) / 2;
            let pos = self.lane_position[index as usize];
            if pos == byte_pos {
                return index;
            }
            if pos < byte_pos {
                min = index + 1;
            } else {
                max = index - 1;
            }
        }
        -1
    }

    /// Is a truncation (`byte_pos`, `size`) of the `skip_lanes..skip_lanes+num_lanes` subset
    /// natural — contains ≥1 lane, splits none (Ghidra transform.cc:133). Passes back the
    /// truncation's lane count and starting lane.
    pub fn restriction(
        &self,
        _num_lanes: i32,
        skip_lanes: i32,
        byte_pos: i32,
        size: i32,
    ) -> Option<(i32, i32)> {
        let res_skip_lanes = self.get_boundary(self.lane_position[skip_lanes as usize] + byte_pos);
        if res_skip_lanes < 0 {
            return None;
        }
        let final_index =
            self.get_boundary(self.lane_position[skip_lanes as usize] + byte_pos + size);
        if final_index < 0 {
            return None;
        }
        let res_num_lanes = final_index - res_skip_lanes;
        if res_num_lanes == 0 {
            None
        } else {
            Some((res_num_lanes, res_skip_lanes))
        }
    }

    /// Is an extension of the `skip_lanes..` subset within a `size`-byte value at `byte_pos`
    /// natural (Ghidra transform.cc:158). Passes back the extension's lane count and starting lane.
    pub fn extension(
        &self,
        _num_lanes: i32,
        skip_lanes: i32,
        byte_pos: i32,
        size: i32,
    ) -> Option<(i32, i32)> {
        let res_skip_lanes = self.get_boundary(self.lane_position[skip_lanes as usize] - byte_pos);
        if res_skip_lanes < 0 {
            return None;
        }
        let final_index =
            self.get_boundary(self.lane_position[skip_lanes as usize] - byte_pos + size);
        if final_index < 0 {
            return None;
        }
        let res_num_lanes = final_index - res_skip_lanes;
        if res_num_lanes == 0 {
            None
        } else {
            Some((res_num_lanes, res_skip_lanes))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// TransformManager — the shared base building + applying the placeholder view.
// (Ghidra transform.hh:156 / transform.cc:329.)
// ---------------------------------------------------------------------------------------------

/// Builds and applies a large-scale data-flow transform (Ghidra `TransformManager`,
/// transform.hh:156). Owns the placeholder arenas and a mutable borrow of the function; the split
/// drivers (`LaneDivide`, `SplitFlow`, …) compose this and call its builder methods.
pub struct TransformManager<'a> {
    pub fd: &'a mut Funcdata,
    /// Map from a big Varnode's `create_index` to the base of its lane/piece placeholder array.
    piece_map: std::collections::BTreeMap<u32, TVarId>,
    /// Standalone placeholder vars (temps/constants/iops), in creation order.
    new_varnodes: Vec<TVarId>,
    /// Placeholder var arena. `piece_map` entries index contiguous runs; `new_varnodes` index
    /// singletons — all share this arena so `TVarId` addresses either.
    vars: Vec<TransformVar>,
    /// Placeholder op arena (Ghidra's `newOps` list), iterated in creation order.
    ops: Vec<TransformOp>,
}

impl<'a> TransformManager<'a> {
    pub fn new(fd: &'a mut Funcdata) -> TransformManager<'a> {
        TransformManager {
            fd,
            piece_map: std::collections::BTreeMap::new(),
            new_varnodes: Vec::new(),
            vars: Vec::new(),
            ops: Vec::new(),
        }
    }

    // -- placeholder-arena accessors (index sugar) --------------------------------------------
    pub fn var(&self, id: TVarId) -> &TransformVar {
        &self.vars[id.0 as usize]
    }
    pub fn top(&self, id: TOpId) -> &TransformOp {
        &self.ops[id.0 as usize]
    }

    fn push_var(&mut self, v: TransformVar) -> TVarId {
        let id = TVarId(self.vars.len() as u32);
        self.vars.push(v);
        id
    }

    fn init_var(
        ttype: TVarType,
        vn: Option<VarnodeId>,
        bits: i32,
        bytes: i32,
        value: u64,
    ) -> TransformVar {
        // Ghidra TransformVar::initialize (transform.hh:203).
        TransformVar {
            vn,
            replacement: None,
            ttype,
            flags: 0,
            byte_size: bytes,
            bit_size: bits,
            val: value,
            def: None,
        }
    }

    /// Should a piece of `vn` reuse overlapping storage (`piece`) rather than a `unique` temp
    /// (`piece_temp`)? (Ghidra `TransformManager::preserveAddress`, transform.cc:348.)
    pub fn preserve_address(&self, vn: VarnodeId, _bit_size: i32, lsb_offset: i32) -> bool {
        if (lsb_offset & 7) != 0 {
            return false; // Logical value not byte-aligned
        }
        let space = self.fd.vn(vn).loc.space;
        if self.fd.spaces.get(space).kind == SpaceKind::Internal {
            return false; // A `unique` value cannot be given overlapping storage
        }
        true
    }

    /// Clear the traversal mark on every big Varnode in the map (Ghidra transform.cc:356).
    pub fn clear_varnode_marks(&mut self) {
        let vns: Vec<VarnodeId> = self
            .piece_map
            .values()
            .filter_map(|&base| self.vars[base.0 as usize].vn)
            .collect();
        for vn in vns {
            self.fd.vn_mut(vn).clear_mark();
        }
    }

    // -- placeholder builders (Ghidra transform.cc:370-575) -----------------------------------

    /// Placeholder for a preexisting Varnode (Ghidra transform.cc:370).
    pub fn new_preexisting_varnode(&mut self, vn: VarnodeId) -> TVarId {
        let size = self.fd.vn(vn).size as i32;
        let mut v = Self::init_var(TVarType::Preexisting, Some(vn), size * 8, size, 0);
        v.flags = tvar_flags::SPLIT_TERMINATOR;
        let id = self.push_var(v);
        let ci = self.fd.vn(vn).create_index;
        self.piece_map.insert(ci, id);
        id
    }

    /// Placeholder for a new `unique`-space temporary (Ghidra transform.cc:384).
    pub fn new_unique(&mut self, size: i32) -> TVarId {
        let v = Self::init_var(TVarType::NormalTemp, None, size * 8, size, 0);
        let id = self.push_var(v);
        self.new_varnodes.push(id);
        id
    }

    /// Placeholder for a new constant, or a piece of an existing constant value (Ghidra
    /// transform.cc:399).
    pub fn new_constant(&mut self, size: i32, lsb_offset: i32, val: u64) -> TVarId {
        let value = (val >> lsb_offset) & super::nzmask::calc_mask(size as u32);
        let v = Self::init_var(TVarType::Constant, None, size * 8, size, value);
        let id = self.push_var(v);
        self.new_varnodes.push(id);
        id
    }

    /// Placeholder for a special iop constant referencing a PcodeOp (Ghidra transform.cc:411).
    /// Only used by INDIRECT splitting; mosura's 1-input INDIRECT uses the guarded-op field instead
    /// (see [`super::subflow`] buildIndirect).
    pub fn new_iop(&mut self, vn: VarnodeId) -> TVarId {
        let (size, off) = { let v = self.fd.vn(vn); (v.size as i32, v.loc.offset) };
        let v = Self::init_var(TVarType::ConstantIop, None, size * 8, size, off);
        let id = self.push_var(v);
        self.new_varnodes.push(id);
        id
    }

    /// Placeholder for a single logical piece of `vn` (Ghidra transform.cc:426).
    pub fn new_piece(&mut self, vn: VarnodeId, bit_size: i32, lsb_offset: i32) -> TVarId {
        let byte_size = (bit_size + 7) / 8;
        let ttype = if self.preserve_address(vn, bit_size, lsb_offset) {
            TVarType::Piece
        } else {
            TVarType::PieceTemp
        };
        let mut v = Self::init_var(ttype, Some(vn), bit_size, byte_size, lsb_offset as u64);
        v.flags = tvar_flags::SPLIT_TERMINATOR;
        let id = self.push_var(v);
        let ci = self.fd.vn(vn).create_index;
        self.piece_map.insert(ci, id);
        id
    }

    /// Create placeholders splitting `vn` into a subset of `description`'s lanes (Ghidra
    /// transform.cc:481; the full-lane overload transform.cc:445 is `start_lane = 0`,
    /// `num_lanes = description.num_lanes()`). Returns the base of the contiguous lane array.
    pub fn new_split(
        &mut self,
        vn: VarnodeId,
        description: &LaneDescription,
        num_lanes: i32,
        start_lane: i32,
    ) -> TVarId {
        let base = TVarId(self.vars.len() as u32);
        let is_const = self.fd.vn(vn).is_constant();
        let vn_off = self.fd.vn(vn).constant_value();
        let base_bit_pos = description.position(start_lane) * 8;
        for i in 0..num_lanes {
            let bitpos = description.position(start_lane + i) * 8 - base_bit_pos;
            let byte_size = description.size(start_lane + i);
            let v = if is_const {
                let val = if (bitpos as usize) < std::mem::size_of::<u64>() * 8 {
                    (vn_off >> bitpos) & super::nzmask::calc_mask(byte_size as u32)
                } else {
                    0 // bits beyond precision assumed 0
                };
                Self::init_var(TVarType::Constant, Some(vn), byte_size * 8, byte_size, val)
            } else {
                let ttype = if self.preserve_address(vn, byte_size * 8, bitpos) {
                    TVarType::Piece
                } else {
                    TVarType::PieceTemp
                };
                Self::init_var(ttype, Some(vn), byte_size * 8, byte_size, bitpos as u64)
            };
            self.vars.push(v);
        }
        self.vars[(base.0 + num_lanes as u32 - 1) as usize].flags |= tvar_flags::SPLIT_TERMINATOR;
        let ci = self.fd.vn(vn).create_index;
        self.piece_map.insert(ci, base);
        base
    }

    fn push_op(&mut self, o: TransformOp) -> TOpId {
        let id = TOpId(self.ops.len() as u32);
        self.ops.push(o);
        id
    }

    /// Placeholder op intended to replace an existing op (Ghidra transform.cc:515).
    pub fn new_op_replace(&mut self, num_params: usize, opc: OpCode, replace: OpId) -> TOpId {
        self.push_op(TransformOp {
            op: Some(replace),
            replacement: None,
            opc,
            special: top_flags::OP_REPLACEMENT,
            output: None,
            input: vec![None; num_params],
            follow: None,
        })
    }

    /// Placeholder op that does not replace an existing op; inserted after `follow` (Ghidra
    /// transform.cc:538).
    pub fn new_op(&mut self, num_params: usize, opc: OpCode, follow: TOpId) -> TOpId {
        let orig = self.ops[follow.0 as usize].op;
        self.push_op(TransformOp {
            op: orig,
            replacement: None,
            opc,
            special: 0,
            output: None,
            input: vec![None; num_params],
            follow: Some(follow),
        })
    }

    /// Placeholder transforming an existing op in place (opcode + inputs change, output kept)
    /// (Ghidra transform.cc:562).
    pub fn new_preexisting_op(&mut self, num_params: usize, opc: OpCode, original: OpId) -> TOpId {
        self.push_op(TransformOp {
            op: Some(original),
            replacement: None,
            opc,
            special: top_flags::OP_PREEXISTING,
            output: None,
            input: vec![None; num_params],
            follow: None,
        })
    }

    /// Get (or create) the placeholder for a preexisting Varnode (Ghidra transform.cc:581).
    pub fn get_preexisting_varnode(&mut self, vn: VarnodeId) -> TVarId {
        if self.fd.vn(vn).is_constant() {
            let (size, off) = { let v = self.fd.vn(vn); (v.size as i32, v.constant_value()) };
            return self.new_constant(size, 0, off);
        }
        let ci = self.fd.vn(vn).create_index;
        if let Some(&id) = self.piece_map.get(&ci) {
            return id;
        }
        self.new_preexisting_varnode(vn)
    }

    /// Get (or create) placeholders splitting `vn` into a subset of `description`'s lanes (Ghidra
    /// transform.cc:640).
    pub fn get_split(
        &mut self,
        vn: VarnodeId,
        description: &LaneDescription,
        num_lanes: i32,
        start_lane: i32,
    ) -> TVarId {
        let ci = self.fd.vn(vn).create_index;
        if let Some(&id) = self.piece_map.get(&ci) {
            return id;
        }
        self.new_split(vn, description, num_lanes, start_lane)
    }

    /// Mark `rvn` as input `slot` of `rop` (Ghidra transform.hh:219).
    pub fn op_set_input(&mut self, rop: TOpId, rvn: TVarId, slot: usize) {
        self.ops[rop.0 as usize].input[slot] = Some(rvn);
    }

    /// Mark `rvn` as the output of `rop`, and `rop` as `rvn`'s def (Ghidra transform.hh:229).
    pub fn op_set_output(&mut self, rop: TOpId, rvn: TVarId) {
        self.ops[rop.0 as usize].output = Some(rvn);
        self.vars[rvn.0 as usize].def = Some(rop);
    }

    /// Should `new_preexisting_op` be called for a binary op visited along `slot` (Ghidra
    /// transform.hh:246) — build it exactly once even though the op is visited per non-constant
    /// input.
    pub fn preexisting_guard(slot: usize, other_ttype: TVarType) -> bool {
        if slot == 0 {
            return true;
        }
        !matches!(other_ttype, TVarType::Piece | TVarType::PieceTemp)
    }

    // -- apply pipeline (Ghidra transform.cc:654-765) -----------------------------------------

    /// Create the actual Varnode for a placeholder (Ghidra `TransformVar::createReplacement`,
    /// transform.cc:175).
    fn create_var_replacement(&mut self, tv: TVarId) {
        if self.vars[tv.0 as usize].replacement.is_some() {
            return;
        }
        match self.vars[tv.0 as usize].ttype {
            TVarType::Preexisting => {
                let vn = self.vars[tv.0 as usize].vn;
                self.vars[tv.0 as usize].replacement = vn;
            }
            TVarType::Constant => {
                let (byte_size, val) =
                    { let v = &self.vars[tv.0 as usize]; (v.byte_size as u32, v.val) };
                let r = self.fd.new_const(byte_size, val);
                self.vars[tv.0 as usize].replacement = Some(r);
            }
            TVarType::NormalTemp | TVarType::PieceTemp => {
                let (byte_size, def) =
                    { let v = &self.vars[tv.0 as usize]; (v.byte_size as u32, v.def) };
                let r = match def {
                    None => self.fd.new_unique(byte_size),
                    Some(d) => {
                        let dop = self.ops[d.0 as usize].replacement.expect("def op created first");
                        self.fd.new_output_unique(dop, byte_size)
                    }
                };
                self.vars[tv.0 as usize].replacement = Some(r);
            }
            TVarType::Piece => {
                let (val, byte_size, vn, def) = {
                    let v = &self.vars[tv.0 as usize];
                    (v.val, v.byte_size as u32, v.vn.expect("piece has original vn"), v.def)
                };
                let bit_pos = val as i32;
                assert_eq!(bit_pos & 7, 0, "Varnode piece is not byte aligned");
                let byte_pos = bit_pos >> 3;
                // x86-64 is little-endian: Ghidra's big-endian `bytePos = size - bytePos - byteSize`
                // and `addr.renormalize` are identities here (see module note).
                let vn_addr = self.fd.vn(vn).loc;
                let addr = Address::new(vn_addr.space, vn_addr.offset + byte_pos as u64);
                let r = match def {
                    None => self.fd.new_varnode(byte_size, addr),
                    Some(d) => {
                        let dop = self.ops[d.0 as usize].replacement.expect("def op created first");
                        self.fd.new_output(dop, byte_size, addr)
                    }
                };
                self.vars[tv.0 as usize].replacement = Some(r);
                self.fd.transfer_varnode_properties(vn, r, byte_pos);
            }
            TVarType::ConstantIop => {
                // mosura's INDIRECT is 1-input (no iop annotation varnode); LaneDivide::buildIndirect
                // uses PcodeOp::guarded_op instead. Unreachable until that path is wired (S2, after
                // rebasing onto sb3's guarded_op field).
                unimplemented!("constant_iop replacement: wired at S2 via PcodeOp::guarded_op");
            }
        }
    }

    /// Create/modify the actual PcodeOp for a placeholder (Ghidra `TransformOp::createReplacement`,
    /// transform.cc:225). Inputs are wired later in [`place_inputs`](Self::place_inputs).
    fn create_op_replacement(&mut self, to: TOpId) {
        let special = self.ops[to.0 as usize].special;
        if special & top_flags::OP_PREEXISTING != 0 {
            // Transform the existing op in place: change opcode; inputs are re-set wholesale in
            // place_inputs (subsumes Ghidra's opUnsetInput/opInsertInput reshaping dance).
            let op = self.ops[to.0 as usize].op.expect("preexisting op");
            let opc = self.ops[to.0 as usize].opc;
            self.ops[to.0 as usize].replacement = Some(op);
            self.fd.op_set_opcode(op, opc);
        } else {
            // A brand-new op. Create it (empty inputs — filled in place_inputs), set opcode, create
            // its output, and insert into control flow if it has no follow gate.
            let (orig, opc, num_in, output, follow) = {
                let r = &self.ops[to.0 as usize];
                (r.op.expect("op has an address source"), r.opc, r.input.len(), r.output, r.follow)
            };
            let pc = self.fd.op(orig).seqnum.pc;
            let uniq = self.fd.num_ops() as u32;
            let newop = self.fd.new_op(opc, super::op::SeqNum { pc, uniq }, Vec::new());
            // Reserve the input slots so place_inputs can address them (mosura has no null inputs;
            // op_set_all_input fills the real vector at place time).
            let _ = num_in;
            self.ops[to.0 as usize].replacement = Some(newop);
            if let Some(out) = output {
                self.create_var_replacement(out);
            }
            if follow.is_none() {
                if opc == OpCode::Multiequal {
                    let parent = self.fd.op(orig).parent.expect("orig op in a block");
                    self.fd.op_insert_begin(newop, parent);
                } else {
                    self.fd.op_insert_before(newop, orig);
                }
            }
        }
    }

    /// Try to place a new op into its block once its follow is placed (Ghidra
    /// `TransformOp::attemptInsertion`, transform.cc:254). Returns `true` if placed (or no gate).
    fn attempt_insertion(&mut self, to: TOpId) -> bool {
        let (follow, opc, repl) = {
            let r = &self.ops[to.0 as usize];
            (r.follow, r.opc, r.replacement.expect("op created"))
        };
        let Some(follow) = follow else {
            return true; // No gate
        };
        if self.ops[follow.0 as usize].follow.is_none() {
            // The follow has been placed; place this op relative to it.
            let follow_repl = self.ops[follow.0 as usize].replacement.expect("follow created");
            if opc == OpCode::Multiequal {
                let parent = self.fd.op(follow_repl).parent.expect("follow in a block");
                self.fd.op_insert_begin(repl, parent);
            } else {
                self.fd.op_insert_before(repl, follow_repl);
            }
            self.ops[to.0 as usize].follow = None; // Mark placed
            return true;
        }
        false
    }

    /// Create every op, then place them respecting follow order (Ghidra transform.cc:665).
    fn create_ops(&mut self) {
        for i in 0..self.ops.len() {
            self.create_op_replacement(TOpId(i as u32));
        }
        loop {
            let mut follow_count = 0;
            for i in 0..self.ops.len() {
                if !self.attempt_insertion(TOpId(i as u32)) {
                    follow_count += 1;
                }
            }
            if follow_count == 0 {
                break;
            }
        }
    }

    /// Create every placeholder Varnode; collect input placeholders (Ghidra transform.cc:684).
    fn create_varnodes(&mut self, input_list: &mut Vec<TVarId>) {
        // pieceMap arrays first (iterated in create_index order), then the standalone new vars.
        let bases: Vec<TVarId> = self.piece_map.values().copied().collect();
        for base in bases {
            let mut i = 0u32;
            loop {
                let rvn = TVarId(base.0 + i);
                let (ttype, vn_opt, terminator) = {
                    let v = &self.vars[rvn.0 as usize];
                    (v.ttype, v.vn, v.flags & tvar_flags::SPLIT_TERMINATOR != 0)
                };
                if ttype == TVarType::Piece {
                    if let Some(vn) = vn_opt {
                        if self.fd.vn(vn).is_input() {
                            input_list.push(rvn);
                            if self.fd.vn(vn).is_mark() {
                                self.vars[rvn.0 as usize].flags |= tvar_flags::INPUT_DUPLICATE;
                            } else {
                                self.fd.vn_mut(vn).set_mark();
                            }
                        }
                    }
                }
                self.create_var_replacement(rvn);
                if terminator {
                    break;
                }
                i += 1;
            }
        }
        let standalone = self.new_varnodes.clone();
        for rvn in standalone {
            self.create_var_replacement(rvn);
        }
    }

    /// Destroy the preexisting ops that a replacement supersedes (Ghidra transform.cc:713).
    fn remove_old(&mut self) {
        for i in 0..self.ops.len() {
            let (special, op) = { let r = &self.ops[i]; (r.special, r.op) };
            if special & top_flags::OP_REPLACEMENT != 0 {
                if let Some(op) = op {
                    if !self.fd.op(op).is_dead() {
                        self.fd.op_destroy(op); // Destroy old op (and its output Varnode)
                        self.fd.op_uninsert(op); // Ghidra's opDestroy also removes it from its block
                    }
                }
            }
        }
    }

    /// Delete old input Varnodes and mark the replacement Varnodes as inputs (Ghidra
    /// transform.cc:729).
    fn transform_input_varnodes(&mut self, input_list: &[TVarId]) {
        for &rvn in input_list {
            let (flags, vn, repl) = {
                let v = &self.vars[rvn.0 as usize];
                (v.flags, v.vn, v.replacement.expect("input replacement created"))
            };
            if flags & tvar_flags::INPUT_DUPLICATE == 0 {
                self.fd.delete_varnode(vn.expect("piece has original vn"));
            }
            let new_repl = self.fd.set_input_varnode(repl);
            self.vars[rvn.0 as usize].replacement = Some(new_repl);
        }
    }

    /// Wire every new op's inputs and run special (INDIRECT) marking (Ghidra transform.cc:740).
    fn place_inputs(&mut self) {
        for i in 0..self.ops.len() {
            let (op, inputs) = {
                let r = &self.ops[i];
                (r.replacement.expect("op created"), r.input.clone())
            };
            let vns: Vec<VarnodeId> = inputs
                .iter()
                .map(|slot| {
                    self.vars[slot.expect("input slot set").0 as usize]
                        .replacement
                        .expect("input var created")
                })
                .collect();
            // mosura sets the whole input vector at once (op_set_all_input), which subsumes Ghidra's
            // per-slot opSetInput on a freshly-null input list.
            self.fd.op_set_all_input(op, &vns);
            self.special_handling(TOpId(i as u32));
        }
    }

    /// INDIRECT-creation marking for a placed op (Ghidra transform.cc:654).
    fn special_handling(&mut self, to: TOpId) {
        let (special, repl) = {
            let r = &self.ops[to.0 as usize];
            (r.special, r.replacement.expect("op created"))
        };
        if special & top_flags::INDIRECT_CREATION != 0 {
            self.fd.mark_indirect_creation(repl, false);
        } else if special & top_flags::INDIRECT_CREATION_POSSIBLE_OUT != 0 {
            self.fd.mark_indirect_creation(repl, true);
        }
    }

    /// Apply the whole placeholder view to the function (Ghidra transform.cc:756).
    pub fn apply(&mut self) {
        let mut input_list = Vec::new();
        self.create_ops();
        self.create_varnodes(&mut input_list);
        self.remove_old();
        self.transform_input_varnodes(&input_list);
        self.place_inputs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::block::{BlockBasic, BlockId};
    use super::super::funcdata::Funcdata;
    use super::super::op::{OpId, SeqNum};
    use super::super::space::{Address, SpaceManager};

    // -- LaneDescription (transform.cc:24-168) ------------------------------------------------

    #[test]
    fn lane_description_uniform_and_boundaries() {
        let d = LaneDescription::uniform(16, 8);
        assert_eq!(d.num_lanes(), 2);
        assert_eq!((d.size(0), d.size(1)), (8, 8));
        assert_eq!((d.position(0), d.position(1)), (0, 8));
        assert_eq!(d.get_boundary(0), 0);
        assert_eq!(d.get_boundary(8), 1);
        assert_eq!(d.get_boundary(16), 2); // whole size maps to lane count
        assert_eq!(d.get_boundary(4), -1); // not on a boundary
        assert_eq!(d.get_boundary(-1), -1);
        assert_eq!(d.get_boundary(20), -1);
    }

    #[test]
    fn lane_description_two_uneven() {
        let d = LaneDescription::two(12, 4, 8);
        assert_eq!(d.num_lanes(), 2);
        assert_eq!((d.size(0), d.size(1)), (4, 8));
        assert_eq!((d.position(0), d.position(1)), (0, 4));
        assert_eq!(d.get_boundary(4), 1);
    }

    #[test]
    fn lane_description_restriction() {
        let d = LaneDescription::uniform(16, 8);
        // Truncate to the low lane and the high lane of the full 2-lane subset.
        assert_eq!(d.restriction(2, 0, 0, 8), Some((1, 0)));
        assert_eq!(d.restriction(2, 0, 8, 8), Some((1, 1)));
        // A truncation that splits a lane is not natural.
        assert_eq!(d.restriction(2, 0, 4, 8), None);
        // The whole 2-lane range.
        assert_eq!(d.restriction(2, 0, 0, 16), Some((2, 0)));
    }

    #[test]
    fn lane_description_extension() {
        let d = LaneDescription::uniform(16, 8);
        // Lane 0 placed at byte 0 within a 16-byte value spans both lanes.
        assert_eq!(d.extension(1, 0, 0, 16), Some((2, 0)));
        // Lane 1 at byte 8 within a 16-byte value.
        assert_eq!(d.extension(1, 1, 8, 16), Some((2, 0)));
        // An extension whose end splits a lane is not natural.
        assert_eq!(d.extension(1, 0, 0, 12), None);
    }

    #[test]
    fn lane_description_subset() {
        let mut d = LaneDescription::uniform(16, 8);
        assert!(d.subset(8, 8)); // keep the high lane only
        assert_eq!(d.num_lanes(), 1);
        assert_eq!(d.whole_size(), 8);
        assert_eq!(d.position(0), 0);
        let mut d2 = LaneDescription::uniform(16, 8);
        assert!(!d2.subset(4, 8)); // splits a lane
    }

    // -- LanedRegister (transform.cc:284-323) -------------------------------------------------

    #[test]
    fn laned_register_parse_and_iterate() {
        let mut lr = LanedRegister::default();
        lr.parse_sizes(16, "1,2,4,8"); // the x86-64 XMM pspec value (x86-64.pspec:143)
        assert_eq!(lr.whole_size(), 16);
        assert!(lr.allowed_lane(1));
        assert!(lr.allowed_lane(8));
        assert!(!lr.allowed_lane(16));
        assert!(!lr.allowed_lane(3));
        assert_eq!(lr.lane_sizes().collect::<Vec<_>>(), vec![1, 2, 4, 8]);
    }

    #[test]
    fn laned_register_add_lane_size() {
        let mut lr = LanedRegister::default();
        lr.add_lane_size(8);
        lr.add_lane_size(16);
        assert!(lr.allowed_lane(8));
        assert!(lr.allowed_lane(16));
        assert!(!lr.allowed_lane(4));
    }

    // -- TransformManager::apply integration (transform.cc:654-765) ---------------------------

    /// Split a 16-byte register COPY into two 8-byte lane COPYs — the shape LaneDivide builds via
    /// `buildUnaryOp` over a COPY def. Exercises the full apply pipeline (createOps → createVarnodes
    /// → removeOld → transformInputVarnodes → placeInputs) without INDIRECT.
    #[test]
    fn apply_splits_a_wide_copy_into_lanes() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        // src:16@reg0x1200 (an XMM-like input) ; dst:16@reg0x1300 = COPY src
        let src = f.new_input(16, Address::new(reg, 0x1200));
        let copyop = f.new_op(OpCode::Copy, seq, vec![src]);
        let dst = f.new_output(copyop, 16, Address::new(reg, 0x1300));
        f.set_blocks(vec![BlockBasic { ops: vec![copyop], ..Default::default() }]);
        f.op_mut(copyop).parent = Some(BlockId(0));

        let desc = LaneDescription::uniform(16, 8);
        {
            let mut tm = TransformManager::new(&mut f);
            let out_split = tm.new_split(dst, &desc, 2, 0);
            let in_split = tm.new_split(src, &desc, 2, 0);
            for i in 0..2u32 {
                let rop = tm.new_op_replace(1, OpCode::Copy, copyop);
                tm.op_set_output(rop, TVarId(out_split.0 + i));
                tm.op_set_input(rop, TVarId(in_split.0 + i), 0);
            }
            tm.apply();
        }

        // The original wide COPY is gone.
        assert!(f.op(copyop).is_dead());
        // Exactly two live COPYs remain, one per 8-byte lane, at the split addresses.
        let copies: Vec<OpId> = (0..f.num_ops() as u32)
            .map(OpId)
            .filter(|&o| !f.op(o).is_dead() && f.op(o).code() == OpCode::Copy)
            .collect();
        assert_eq!(copies.len(), 2, "one COPY per lane");
        let mut outs: Vec<(u64, u64)> = Vec::new();
        for &o in &copies {
            let out = f.op(o).output.unwrap();
            let inp = f.op(o).input(0).unwrap();
            // input lane is a fresh 8-byte input at reg0x1200 / reg0x1208
            assert_eq!(f.vn(inp).size, 8);
            assert!(f.vn(inp).is_input());
            assert_eq!(f.vn(inp).loc.space, reg);
            // output lane is 8 bytes at reg0x1300 / reg0x1308, offset tracking the input lane
            assert_eq!(f.vn(out).size, 8);
            assert_eq!(f.vn(out).loc.space, reg);
            assert_eq!(f.vn(out).loc.offset - 0x1300, f.vn(inp).loc.offset - 0x1200);
            outs.push((f.vn(out).loc.offset, f.vn(inp).loc.offset));
        }
        outs.sort();
        assert_eq!(outs, vec![(0x1300, 0x1200), (0x1308, 0x1208)]);
        // The old wide input varnode was deleted (no longer a live input).
        assert!(!f.vn(src).is_input());
    }
}
