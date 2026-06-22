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
        }
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
    pub fn blocks(&self) -> &[BlockBasic] {
        &self.blocks
    }
    pub fn num_blocks(&self) -> usize {
        self.blocks.len()
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
