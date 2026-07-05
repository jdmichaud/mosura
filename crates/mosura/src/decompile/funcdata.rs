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
    /// The `default` case address per switch (BRANCHIND instruction address → default target),
    /// recovered by folding the out-of-range guard (Ghidra `JumpTable::defaultBlock`). Only the
    /// switches whose guard was folded in appear here.
    pub switch_defaults: std::collections::HashMap<u64, u64>,
    /// Cached jump-table recovery (Ghidra `Funcdata::jumpvec`): the tables recovered once at build
    /// time, before the guard is folded away. Empty until [`Self::jump_tables`] is populated.
    pub jumptables: Vec<super::jumptable::JumpTable>,
    /// The function's loaded memory (address, bytes) chunks — code + data — so jump-table
    /// recovery can read switch tables (Ghidra's LoadImage). Empty for hand-built test functions.
    pub image: Vec<(u64, Vec<u8>)>,
    /// Ghidra `Funcdata::hasTypeRecoveryStarted`: set once `ActionInferTypes` has committed
    /// data-types onto varnodes, gating the pointer-arithmetic rules.
    typerecovery_started: bool,
    /// Iterating-heritage state (Ghidra's `Heritage` member, `heritage.cc`): the next heritage
    /// pass index. A space enters SSA construction once `pass >= delay`, so registers (delay 0)
    /// heritage before `ram`/`stack` (delay 1). Persists across `ActionHeritage` calls so the
    /// mainloop can interleave param recovery between passes.
    pub heritage_pass: i32,
    /// Ghidra `Heritage::globaldisjoint` (`heritage.cc`): the per-`(addr,size)` record of which
    /// locations have been brought into SSA form and in which pass. A later pass heritages only the
    /// locations not yet covered (or freed since by simplification), leaving the rest of the space
    /// intact — finer-grained than the old per-space "done" set.
    pub globaldisjoint: super::heritage::LocationMap,
    /// Ghidra `Funcdata::activeoutput` (the function's return-value trials): the [`ParamActive`]
    /// recovering which return register actually holds a returned value. Set up + committed by
    /// `recover::resolve_return`; `None` until first invoked and again after it commits
    /// (`clearActiveOutput`). Persisting it lets the trial decision DEFER across heritage passes.
    pub active_output: Option<super::fspec::ParamActive>,
    /// Ghidra `FuncCallSpecs::activeinput`, one per CALL (keyed by the CALL op): the [`ParamActive`]
    /// recovering that sub-function's argument registers. Set up + committed by
    /// `recover::resolve_call_args`; an entry is removed once its trials commit
    /// (`clearActiveInput`). Persisting it lets the prune DEFER instead of committing greedily.
    pub active_inputs: std::collections::HashMap<OpId, super::fspec::ParamActive>,
    /// Master gate for heritage call-effect guarding (Ghidra runs `Heritage::guardCalls` only in the
    /// true heritage). The pipeline sets it before the real heritage; the AliasChecker probe clone
    /// leaves it `false`, so `alias_boundary` is computed on a graph without the call INDIRECTs.
    pub call_guards_active: bool,
    /// Ghidra `AliasChecker` boundary threaded into heritage's call guarding: the shallowest escaped
    /// stack offset — a call with an unknown prototype may modify every stack slot at/above it
    /// (`AliasChecker::hasLocalAlias`, `offset >= aliasBoundary`). `None` ⇒ nothing escapes ⇒ no
    /// stack slot is guarded. Set from the alias probe before the real heritage.
    pub alias_boundary: Option<i64>,
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
            switch_defaults: std::collections::HashMap::new(),
            jumptables: Vec::new(),
            image: Vec::new(),
            typerecovery_started: false,
            heritage_pass: 0,
            globaldisjoint: super::heritage::LocationMap::default(),
            active_output: None,
            active_inputs: std::collections::HashMap::new(),
            call_guards_active: false,
            alias_boundary: None,
        }
    }

    /// Ghidra `Funcdata::hasTypeRecoveryStarted`: whether data-type recovery has committed types.
    pub fn has_type_recovery_started(&self) -> bool {
        self.typerecovery_started
    }
    /// Mark type recovery as begun (Ghidra sets this in `ActionInferTypes`).
    pub fn set_type_recovery_started(&mut self) {
        self.typerecovery_started = true;
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
    ///
    /// Returns the cached `jumptables` if it was populated at build time (Ghidra recovers once into
    /// `jumpvec`), since folding the out-of-range guard into the switch (`cfg::build_cfg`) destroys
    /// the guard the range-recovery would re-derive from. Falls back to on-demand recovery for
    /// funcdata that never cached (e.g. the analysis track's own graphs).
    pub fn jump_tables(&self) -> Vec<super::jumptable::JumpTable> {
        if !self.jumptables.is_empty() {
            return self.jumptables.clone();
        }
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
    /// Mutable access to a basic block (edges / op list), used by CFG-simplification
    /// (`determinedbranch`) when removing branches and unreachable blocks.
    pub fn block_mut(&mut self, id: super::block::BlockId) -> &mut BlockBasic {
        &mut self.blocks[id.0 as usize]
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
        let nzm = if vflags & flags::CONSTANT != 0 {
            loc.offset & super::nzmask::calc_mask(size)
        } else {
            super::nzmask::calc_mask(size)
        };
        self.varnodes.push(Varnode {
            loc,
            size,
            flags: vflags,
            create_index,
            def: None,
            descend: Vec::new(),
            ty: None,
            nzm,
            consume: 0,
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
    /// varnode's `def` and the `WRITTEN`/`INSERT` flags. If `op` already had an output,
    /// that varnode is detached (its `def`/`WRITTEN` cleared) — re-pointing a write, as
    /// Ghidra's `opSetOutput` does, so no varnode is left claiming a stale `def`.
    pub fn new_output(&mut self, op: OpId, size: u32, loc: Address) -> VarnodeId {
        if let Some(old) = self.ops[op.0 as usize].output.take() {
            self.varnodes[old.0 as usize].def = None;
            self.varnodes[old.0 as usize].flags &= !flags::WRITTEN;
        }
        let v = self.alloc_varnode(size, loc, flags::WRITTEN | flags::INSERT);
        self.varnodes[v.0 as usize].def = Some(op);
        self.ops[op.0 as usize].output = Some(v);
        v
    }

    /// Splice `newop` into `follow`'s basic block immediately before it (Ghidra's
    /// `opInsertBefore`): adopt `follow`'s parent block and insert just ahead of it in the
    /// block's op list.
    pub fn op_insert_before(&mut self, newop: OpId, follow: OpId) {
        let parent = self.ops[follow.0 as usize].parent;
        self.ops[newop.0 as usize].parent = parent;
        if let Some(b) = parent {
            let ops = &mut self.blocks[b.0 as usize].ops;
            let pos = ops.iter().position(|&o| o == follow).unwrap_or(ops.len());
            ops.insert(pos, newop);
        }
    }

    /// Splice `newop` into `prev`'s basic block immediately after it (Ghidra's `opInsertAfter`):
    /// adopt `prev`'s parent block and insert just past it in the block's op list.
    pub fn op_insert_after(&mut self, newop: OpId, prev: OpId) {
        let parent = self.ops[prev.0 as usize].parent;
        self.ops[newop.0 as usize].parent = parent;
        if let Some(b) = parent {
            let ops = &mut self.blocks[b.0 as usize].ops;
            let pos = ops.iter().position(|&o| o == prev).map(|p| p + 1).unwrap_or(ops.len());
            ops.insert(pos, newop);
        }
    }

    /// Mark an existing free varnode as a function input (Ghidra's `setInputVarnode`, reduced to
    /// mosura's case): clear any `written`/`def` and set `INPUT | INSERT`. Returns the varnode.
    pub fn set_input_varnode(&mut self, vid: VarnodeId) -> VarnodeId {
        let v = &mut self.varnodes[vid.0 as usize];
        v.def = None;
        v.flags &= !flags::WRITTEN;
        v.flags |= flags::INPUT | flags::INSERT;
        vid
    }

    /// Detach a varnode from the graph (Ghidra's `deleteVarnode`). mosura keeps the arena slot
    /// index-stable, so this orphans the varnode: clear its `def` and `INPUT | INSERT` so nothing
    /// downstream treats it as a live value. The caller must have already moved all of its uses
    /// (via [`total_replace`](Self::total_replace)).
    pub fn delete_varnode(&mut self, vid: VarnodeId) {
        let v = &mut self.varnodes[vid.0 as usize];
        v.def = None;
        v.flags &= !(flags::INPUT | flags::INSERT | flags::WRITTEN);
    }

    /// Create a new op with a fresh `unique`-space output, inserted just before `follow`
    /// (Ghidra's `newOpBefore`). The output is sized like the first input, as Ghidra does.
    /// Used by pointer-arithmetic transforms (`RulePtrArith`) to build PTRADD/PTRSUB trees.
    pub fn new_op_before(&mut self, follow: OpId, opcode: OpCode, inputs: Vec<VarnodeId>) -> OpId {
        let pc = self.ops[follow.0 as usize].seqnum.pc;
        let uniq = self.ops.len() as u32;
        let out_size = self.varnodes[inputs[0].0 as usize].size;
        let id = self.new_op(opcode, SeqNum { pc, uniq }, inputs);
        self.new_output_unique(id, out_size);
        self.op_insert_before(id, follow);
        id
    }

    /// Like [`new_op_before`](Self::new_op_before) but with an explicit output size, for ops whose
    /// output width differs from `inputs[0]` (e.g. an INT_ZEXT that widens its input).
    pub fn new_op_before_sized(
        &mut self,
        follow: OpId,
        opcode: OpCode,
        inputs: Vec<VarnodeId>,
        out_size: u32,
    ) -> OpId {
        let pc = self.ops[follow.0 as usize].seqnum.pc;
        let uniq = self.ops.len() as u32;
        let id = self.new_op(opcode, SeqNum { pc, uniq }, inputs);
        self.new_output_unique(id, out_size);
        self.op_insert_before(id, follow);
        id
    }

    /// Ghidra `Funcdata::newExtendedConstant` (funcdata_varnode.cc:462): materialize a constant of
    /// `size` bytes holding the (up to 128-bit) value `val`, inserted just before `op`. Up to 8
    /// bytes it is a plain constant; wider, it is built as an `INT_ZEXT` of the low 8 bytes (when
    /// the high half is zero) or a `PIECE` of the two 8-byte halves (most significant first). mosura
    /// carries the value in a `u128` (Ghidra's `uint8[2]`: `val[0]` = low, `val[1]` = high).
    pub fn new_extended_constant(&mut self, size: u32, val: u128, op: OpId) -> VarnodeId {
        if size <= 8 {
            return self.new_const(size, val as u64);
        }
        let lo = val as u64;
        let hi = (val >> 64) as u64;
        let newop = if hi == 0 {
            let clo = self.new_const(8, lo);
            self.new_op_before_sized(op, OpCode::IntZext, vec![clo], size)
        } else {
            let chi = self.new_const(8, hi); // Most significant piece
            let clo = self.new_const(8, lo); // Least significant piece
            self.new_op_before_sized(op, OpCode::Piece, vec![chi, clo], size)
        };
        self.ops[newop.0 as usize].output.unwrap()
    }

    /// Ghidra `Funcdata::newIndirectOp` (funcdata_op.cc:683): model that `indeffect` (a CALL/STORE)
    /// may modify the storage range `(loc, size)` — create `out:size@loc = INDIRECT(before:size@loc)`
    /// inserted just before `indeffect`, returning the new op. `before` is a fresh free varnode at
    /// the range (heritage links it to the reaching def); `out` is the post-effect value.
    ///
    /// mosura's INDIRECT is a 1-input model: Ghidra's `input(1) = newVarnodeIop(indeffect)` (the
    /// `iop` annotation referencing the causing op) is omitted here, as mosura omits the `iop`
    /// everywhere (a dead-code-removal detail; see `consume.rs`).
    pub fn new_indirect_op(&mut self, indeffect: OpId, loc: Address, size: u32) -> OpId {
        let before = self.new_varnode(size, loc);
        let pc = self.ops[indeffect.0 as usize].seqnum.pc;
        let uniq = self.ops.len() as u32;
        let op = self.new_op(OpCode::Indirect, SeqNum { pc, uniq }, vec![before]);
        self.new_output(op, size, loc);
        self.op_insert_before(op, indeffect);
        op
    }

    /// Change `op`'s opcode (Ghidra's `opSetOpcode`).
    pub fn op_set_opcode(&mut self, op: OpId, opcode: OpCode) {
        self.ops[op.0 as usize].opcode = opcode;
    }

    /// Remove `op` from its parent block's op list without touching its data-flow connections
    /// (Ghidra's `opUninsert`). Used by `RuleMultiCollapse`'s functional-equality path, which
    /// rewrites a MULTIEQUAL into a plain op and must re-position it (via [`op_insert_begin`])
    /// out of the leading-MULTIEQUAL region.
    pub fn op_uninsert(&mut self, op: OpId) {
        if let Some(b) = self.ops[op.0 as usize].parent {
            let ops = &mut self.blocks[b.0 as usize].ops;
            if let Some(pos) = ops.iter().position(|&o| o == op) {
                ops.remove(pos);
            }
        }
    }

    /// Insert `op` as the first op in `block`, except that all leading MULTIEQUALs stay ahead of
    /// it (Ghidra's `opInsertBegin`). `op` adopts `block` as its parent.
    pub fn op_insert_begin(&mut self, op: OpId, block: super::block::BlockId) {
        self.ops[op.0 as usize].parent = Some(block);
        let is_multi = self.ops[op.0 as usize].opcode == OpCode::Multiequal;
        let mut pos = 0;
        if !is_multi {
            let blk_ops = &self.blocks[block.0 as usize].ops;
            while pos < blk_ops.len()
                && self.ops[blk_ops[pos].0 as usize].opcode == OpCode::Multiequal
            {
                pos += 1;
            }
        }
        self.blocks[block.0 as usize].ops.insert(pos, op);
    }

    /// Re-point `op` to produce the existing varnode `vid` (Ghidra's `opSetOutput`): drop
    /// `op`'s current output, detach `vid` from its old producer, then wire `vid.def = op`.
    /// Used by `RulePtrArith::buildTree` to hand the original ADD's output to the new tail op.
    pub fn op_set_output(&mut self, op: OpId, vid: VarnodeId) {
        if self.ops[op.0 as usize].output == Some(vid) {
            return;
        }
        if let Some(old) = self.ops[op.0 as usize].output.take() {
            self.varnodes[old.0 as usize].def = None;
            self.varnodes[old.0 as usize].flags &= !flags::WRITTEN;
        }
        if let Some(olddef) = self.varnodes[vid.0 as usize].def.take() {
            self.ops[olddef.0 as usize].output = None;
        }
        self.varnodes[vid.0 as usize].def = Some(op);
        self.varnodes[vid.0 as usize].flags |= flags::WRITTEN | flags::INSERT;
        self.ops[op.0 as usize].output = Some(vid);
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

    /// Insert `vid` as a new input of `op` at position `slot` (Ghidra's `opInsertInput`),
    /// shifting later inputs up and adding `op` to `vid`'s descendant list.
    pub fn op_insert_input(&mut self, op: OpId, slot: usize, vid: VarnodeId) {
        self.ops[op.0 as usize].inrefs.insert(slot, vid);
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

    /// Render a single op as one line (`0x<addr>:<uniq>: out = OPCODE inputs`), the per-op form
    /// of [`print_raw`](Self::print_raw). Used by the rule-application trace (`MOSURA_TRACE`) to
    /// capture an op's before/after state; a dead op renders as `**` (Ghidra's `printDebug`).
    pub fn op_str(&self, id: OpId) -> String {
        let op = self.op(id);
        let mut s = String::new();
        let _ = write!(s, "0x{:x}:{}: ", op.seqnum.pc.offset, op.seqnum.uniq);
        if op.is_dead() {
            s.push_str("**");
            return s;
        }
        if let Some(out) = op.output {
            let _ = write!(s, "{} = ", self.vn_str(out));
        }
        let _ = write!(s, "{}", op.opcode.name());
        for &inp in &op.inrefs {
            let _ = write!(s, " {}", self.vn_str(inp));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::{Address, SpaceManager};

    #[test]
    fn new_indirect_op_models_effect_on_range() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0x10), uniq: 0 };
        let target = f.new_const(8, 0x100);
        let call = f.new_op(OpCode::Call, seq, vec![target]);
        // model that the call may modify the 8-byte range at register offset 0 (RAX)
        let loc = Address::new(reg, 0);
        let ind = f.new_indirect_op(call, loc, 8);
        // out:8@loc = INDIRECT(before:8@loc) — 1-input mosura form (no iop)
        assert_eq!(f.op(ind).code(), OpCode::Indirect);
        assert_eq!(f.op(ind).num_inputs(), 1);
        let out = f.op(ind).output.unwrap();
        assert_eq!(f.vn(out).size, 8);
        assert_eq!(f.vn(out).loc, loc);
        assert_eq!(f.vn(out).def, Some(ind));
        let before = f.op(ind).input(0).unwrap();
        assert_eq!(f.vn(before).size, 8);
        assert_eq!(f.vn(before).loc, loc);
        assert!(f.vn(before).is_free()); // heritage links it to the reaching def
    }
}
