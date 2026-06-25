//! The per-function container — a port of Ghidra's `Funcdata` (`funcdata.hh`/`funcdata.cc`).
//!
//! `Funcdata` owns the arenas (varnodes, ops, blocks) and is the sole place varnodes and
//! ops are created — every `VarnodeId`/`OpId` indexes into here. The graph edges
//! (`def`/`descend`, `output`/`inrefs`) are maintained by the create/wire methods so the
//! Varnode graph and the op list stay consistent, exactly as Ghidra's friend access does.

use std::fmt::Write as _;

use super::block::BlockBasic;
use super::op::{OpId, PcodeOp, SeqNum};
use super::opcode::OpCode;
use super::space::{Address, SpaceKind, SpaceManager};
use super::varnode::{flags, Varnode, VarnodeId};

/// One function being decompiled.
#[derive(Clone)]
pub struct Funcdata {
    pub name: String,
    /// Entry address.
    pub addr: Address,
    /// The architecture's address spaces.
    pub spaces: SpaceManager,
    varnodes: Vec<Varnode>,
    ops: Vec<PcodeOp>,
    blocks: Vec<BlockBasic>,
    create_index: u32,
    unique_offset: u64,
    /// Recovered jump-table case targets, keyed by the BRANCHIND instruction address.
    pub switch_targets: std::collections::HashMap<u64, Vec<u64>>,
    /// The function's loaded memory (address, bytes) chunks — code + data — so jump-table
    /// recovery can read switch tables (Ghidra's LoadImage). Empty for hand-built test functions.
    pub image: Vec<(u64, Vec<u8>)>,
}

impl Funcdata {
    pub fn new(name: impl Into<String>, addr: Address, spaces: SpaceManager) -> Funcdata {
        Funcdata {
            name: name.into(),
            addr,
            spaces,
            varnodes: Vec::new(),
            ops: Vec::new(),
            blocks: Vec::new(),
            create_index: 0,
            unique_offset: 0x10000,
            switch_targets: std::collections::HashMap::new(),
            image: Vec::new(),
        }
    }

    /// Read `size` bytes (little-endian) from the loaded image at `addr`, if present.
    pub fn read_image(&self, addr: u64, size: u32) -> Option<u64> {
        for (base, bytes) in &self.image {
            if addr >= *base && addr + size as u64 <= *base + bytes.len() as u64 {
                let off = (addr - *base) as usize;
                let mut v = 0u64;
                for i in 0..size as usize {
                    v |= (bytes[off + i] as u64) << (8 * i);
                }
                return Some(v);
            }
        }
        None
    }

    // --- accessors ---------------------------------------------------------

    pub fn vn(&self, id: VarnodeId) -> &Varnode {
        &self.varnodes[id.0 as usize]
    }
    pub fn vn_mut(&mut self, id: VarnodeId) -> &mut Varnode {
        &mut self.varnodes[id.0 as usize]
    }
    pub fn op(&self, id: OpId) -> &PcodeOp {
        &self.ops[id.0 as usize]
    }
    pub fn op_mut(&mut self, id: OpId) -> &mut PcodeOp {
        &mut self.ops[id.0 as usize]
    }
    pub fn num_ops(&self) -> usize {
        self.ops.len()
    }
    pub fn num_varnodes(&self) -> usize {
        self.varnodes.len()
    }

    /// The recovered jump tables — each `BRANCHIND`'s table address and ordered case targets
    /// (Ghidra `Funcdata::numJumpTables`/`getJumpTable`). Recovered faithfully from the heritaged
    /// graph ([`super::jumptable`]); call after decompilation. The read-back surface the analysis
    /// track's switch analyzer (A6) consumes.
    pub fn jump_tables(&self) -> Vec<super::jumptable::JumpTable> {
        super::jumptable::recover(self)
    }

    /// The recovered function prototype — the ordered input parameters and the return storage
    /// (Ghidra `Funcdata::getFuncProto`). Recovered from the heritaged graph via the calling
    /// convention's trial machinery ([`super::fspec`]); call after decompilation. This is the
    /// faithful surface the analysis track's parameter-ID (A6) reads back.
    pub fn func_proto(&self) -> super::fspec::FuncProto {
        super::fspec::recover_func_proto(self)
    }
    pub fn blocks(&self) -> &[BlockBasic] {
        &self.blocks
    }
    pub fn block(&self, id: super::block::BlockId) -> &BlockBasic {
        &self.blocks[id.0 as usize]
    }
    pub fn num_blocks(&self) -> usize {
        self.blocks.len()
    }
    /// Install the basic-block list (built by `cfg::build_cfg`).
    pub fn set_blocks(&mut self, blocks: Vec<BlockBasic>) {
        self.blocks = blocks;
    }
    /// The instruction-address range `[first, last]` of a block, from its ops' seqnums.
    pub fn block_range(&self, id: super::block::BlockId) -> Option<(u64, u64)> {
        let b = self.block(id);
        let first = *b.ops.first()?;
        let last = *b.ops.last()?;
        Some((self.op(first).seqnum.pc.offset, self.op(last).seqnum.pc.offset))
    }
    /// All op ids in creation order.
    pub fn op_ids(&self) -> impl Iterator<Item = OpId> {
        (0..self.ops.len() as u32).map(OpId)
    }

    // --- varnode creation --------------------------------------------------

    fn alloc_varnode(&mut self, size: u32, loc: Address, vflags: u32) -> VarnodeId {
        let id = VarnodeId(self.varnodes.len() as u32);
        let create_index = self.create_index;
        self.create_index += 1;
        self.varnodes.push(Varnode {
            loc,
            size,
            flags: vflags,
            create_index,
            def: None,
            descend: Vec::new(),
            ty: None,
        });
        id
    }

    /// A free varnode at a storage location.
    pub fn new_varnode(&mut self, size: u32, loc: Address) -> VarnodeId {
        self.alloc_varnode(size, loc, 0)
    }

    /// A function-input varnode (no ancestor).
    pub fn new_input(&mut self, size: u32, loc: Address) -> VarnodeId {
        self.alloc_varnode(size, loc, flags::INPUT | flags::INSERT)
    }

    /// A constant varnode (`const` space).
    pub fn new_const(&mut self, size: u32, value: u64) -> VarnodeId {
        let loc = Address::new(self.spaces.constant(), value);
        self.alloc_varnode(size, loc, flags::CONSTANT)
    }

    /// A fresh temporary in the `unique` space.
    pub fn new_unique(&mut self, size: u32) -> VarnodeId {
        let space = self.spaces.by_name("unique").expect("unique space");
        let off = self.unique_offset;
        self.unique_offset += size.max(1) as u64;
        self.alloc_varnode(size, Address::new(space, off), 0)
    }

    // --- op creation / wiring ----------------------------------------------

    /// Create an op with the given inputs and no output, appended to the op list. The
    /// inputs' descendant lists are updated.
    pub fn new_op(&mut self, opcode: OpCode, seqnum: SeqNum, inputs: Vec<VarnodeId>) -> OpId {
        let id = OpId(self.ops.len() as u32);
        for &v in &inputs {
            self.varnodes[v.0 as usize].descend.push(id);
        }
        self.ops.push(PcodeOp {
            opcode,
            flags: 0,
            seqnum,
            parent: None,
            output: None,
            inrefs: inputs,
        });
        id
    }

    /// Give `op` a fresh output varnode at `loc` of `size`; returns it. Sets the
    /// varnode's `def` and the `WRITTEN`/`INSERT` flags.
    pub fn new_output(&mut self, op: OpId, size: u32, loc: Address) -> VarnodeId {
        let v = self.alloc_varnode(size, loc, flags::WRITTEN | flags::INSERT);
        self.varnodes[v.0 as usize].def = Some(op);
        self.ops[op.0 as usize].output = Some(v);
        v
    }

    /// Change `op`'s opcode (Ghidra's `opSetOpcode`).
    pub fn op_set_opcode(&mut self, op: OpId, opcode: OpCode) {
        self.ops[op.0 as usize].opcode = opcode;
    }

    /// Swap two input slots of `op` (Ghidra's `opSwapInput`).
    pub fn op_swap_input(&mut self, op: OpId, i: usize, j: usize) {
        self.ops[op.0 as usize].inrefs.swap(i, j);
    }

    /// Append an input to `op` (Ghidra's `opInsertInput` at the end), wiring descendants.
    pub fn op_append_input(&mut self, op: OpId, vid: VarnodeId) {
        self.ops[op.0 as usize].inrefs.push(vid);
        self.varnodes[vid.0 as usize].descend.push(op);
    }

    /// Replace `op`'s entire input list (Ghidra's `opSetAllInput`), fixing descendants.
    pub fn op_set_all_input(&mut self, op: OpId, inputs: &[VarnodeId]) {
        let old = std::mem::take(&mut self.ops[op.0 as usize].inrefs);
        for v in old {
            if let Some(pos) = self.varnodes[v.0 as usize].descend.iter().position(|&o| o == op) {
                self.varnodes[v.0 as usize].descend.remove(pos);
            }
        }
        for &v in inputs {
            self.ops[op.0 as usize].inrefs.push(v);
            self.varnodes[v.0 as usize].descend.push(op);
        }
    }

    /// Remove input `slot` from `op` (Ghidra's `opRemoveInput`), fixing descendant lists.
    pub fn op_remove_input(&mut self, op: OpId, slot: usize) {
        let vid = self.ops[op.0 as usize].inrefs.remove(slot);
        if let Some(pos) = self.varnodes[vid.0 as usize].descend.iter().position(|&o| o == op) {
            self.varnodes[vid.0 as usize].descend.remove(pos);
        }
    }

    /// Replace every use of `old` with `new` across all reading ops (Ghidra's
    /// `totalReplace`), maintaining descendant lists.
    pub fn total_replace(&mut self, old: VarnodeId, new: VarnodeId) {
        let users = std::mem::take(&mut self.varnodes[old.0 as usize].descend);
        for op in users {
            let inrefs = &mut self.ops[op.0 as usize].inrefs;
            for v in inrefs.iter_mut() {
                if *v == old {
                    *v = new;
                    self.varnodes[new.0 as usize].descend.push(op);
                }
            }
        }
    }

    /// Mark `op` dead (pending removal by dead-code elimination).
    pub fn mark_dead(&mut self, op: OpId) {
        self.ops[op.0 as usize].flags |= super::op::flags::DEAD;
    }

    /// Disconnect `op` from the graph (Ghidra's `opDestroy`): drop it from every input's
    /// descendant list, clear its output's def, and mark it dead. The op stays in the
    /// arena but is detached and should be removed from its block's op list separately.
    pub fn op_destroy(&mut self, op: OpId) {
        let inrefs = std::mem::take(&mut self.ops[op.0 as usize].inrefs);
        for v in inrefs {
            if let Some(pos) = self.varnodes[v.0 as usize].descend.iter().position(|&o| o == op) {
                self.varnodes[v.0 as usize].descend.remove(pos);
            }
        }
        if let Some(out) = self.ops[op.0 as usize].output.take() {
            self.varnodes[out.0 as usize].def = None;
            self.varnodes[out.0 as usize].flags &= !flags::WRITTEN;
        }
        self.mark_dead(op);
    }

    /// Give `op` a fresh `unique`-space output of `size`; returns it.
    pub fn new_output_unique(&mut self, op: OpId, size: u32) -> VarnodeId {
        let space = self.spaces.by_name("unique").expect("unique space");
        let off = self.unique_offset;
        self.unique_offset += size.max(1) as u64;
        self.new_output(op, size, Address::new(space, off))
    }

    /// Replace a block's op list (used by heritage refinement to splice in SUBPIECEs).
    pub fn set_block_ops(&mut self, block: super::block::BlockId, ops: Vec<OpId>) {
        self.blocks[block.0 as usize].ops = ops;
    }

    /// Repoint input `slot` of `op` at varnode `vid`, maintaining descendant lists
    /// (Ghidra's `opSetInput`). Used by heritage renaming.
    pub fn op_set_input(&mut self, op: OpId, slot: usize, vid: VarnodeId) {
        let old = self.ops[op.0 as usize].inrefs[slot];
        if old == vid {
            return;
        }
        if let Some(pos) = self.varnodes[old.0 as usize].descend.iter().position(|&o| o == op) {
            self.varnodes[old.0 as usize].descend.remove(pos);
        }
        self.ops[op.0 as usize].inrefs[slot] = vid;
        self.varnodes[vid.0 as usize].descend.push(op);
    }

    /// Create a MULTIEQUAL (phi) for the location `(space, offset, size)` with `npreds`
    /// placeholder inputs (filled during renaming), give it an output at that location,
    /// and prepend it to `block`. Returns the op.
    pub fn new_multiequal(
        &mut self,
        block: super::block::BlockId,
        space: super::space::SpaceId,
        offset: u64,
        size: u32,
        npreds: usize,
    ) -> OpId {
        let loc = Address::new(space, offset);
        let pc = self
            .blocks[block.0 as usize]
            .ops
            .first()
            .map(|&o| self.op(o).seqnum.pc)
            .unwrap_or(self.addr);
        let inputs: Vec<VarnodeId> = (0..npreds).map(|_| self.new_varnode(size, loc)).collect();
        let id = self.new_op(OpCode::Multiequal, SeqNum { pc, uniq: u32::MAX }, inputs);
        self.new_output(id, size, loc);
        self.ops[id.0 as usize].parent = Some(block);
        self.blocks[block.0 as usize].ops.insert(0, id);
        id
    }

    // --- printRaw (the IR dump) --------------------------------------------

    /// Render one varnode as Ghidra's `printRawNoMarkup` does, structurally: `#value` for
    /// a constant, else `<spacechar>0x<offset>`, with a `:size` suffix.
    pub fn vn_str(&self, id: VarnodeId) -> String {
        let vn = self.vn(id);
        if vn.is_constant() {
            return format!("#0x{:x}:{}", vn.constant_value(), vn.size);
        }
        let space = self.spaces.get(vn.loc.space);
        let c = match space.kind {
            SpaceKind::Internal => 'u',
            SpaceKind::Spacebase => 's',
            _ => 'r',
        };
        format!("{c}0x{:x}:{}", vn.loc.offset, vn.size)
    }

    /// Render the function's IR as a raw, block-less op listing (Ghidra's
    /// `Funcdata::printRaw` "Raw operations" mode). Deterministic; the per-phase oracle
    /// format is aligned to Ghidra's exactly in `tests/ir_parity.rs` (P0).
    pub fn print_raw(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "{}() raw operations:", self.name);
        for id in self.op_ids() {
            let op = self.op(id);
            let _ = write!(s, "0x{:x}:{}:\t", op.seqnum.pc.offset, op.seqnum.uniq);
            if let Some(out) = op.output {
                let _ = write!(s, "{} = ", self.vn_str(out));
            }
            let _ = write!(s, "{}", op.opcode.name());
            for &inp in &op.inrefs {
                let _ = write!(s, " {}", self.vn_str(inp));
            }
            s.push('\n');
        }
        s
    }
}
