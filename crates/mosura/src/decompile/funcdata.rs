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
use super::space::{Address, SpaceId, SpaceKind, SpaceManager};
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
    /// Ghidra `Merge::copyTrims` (merge.hh:90, recorded by `allocateCopyTrim`, merge.cc:432): the
    /// COPY ops inserted by the merge trimming process (`trimOpInput`, the addrtied read snips).
    /// `ActionDominantCopy` (`processCopyTrims`, merge.cc:1415) later collects same-source groups
    /// of these and replaces them with a single dominant COPY; the list is drained there.
    pub copy_trims: Vec<OpId>,
    /// Ghidra's `typerecovery_start` Funcdata flag (funcdata.hh:150): set once `ActionStartTypes`
    /// flips type recovery on (`startTypeRecovery`, funcdata.cc:182), gating `ActionInferTypes`
    /// and the pointer-arithmetic rules — the fullloop's typeless-then-typed two-phase cadence.
    typerecovery_started: bool,
    /// Ghidra `Funcdata::isTypeRecoveryExceeded` (`typerecovery_exceeded` flag, funcdata.hh:152/182):
    /// set once `ActionInferTypes` has made its maximum propagation passes (`localcount == 7`,
    /// coreaction.cc:5390-5394) without the type lattice settling. It is the mainloop's convergence
    /// safety net: propagation then stops re-firing instead of stalling the iterating group.
    typerecovery_exceeded: bool,
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
    /// Set by [`super::directwrite::ActionDirectWrite`], consumed (and reset) by the next
    /// [`super::deadcode::dead_code`]: it does the `addrforce`-clear-for-`!directwrite` step
    /// (Ghidra `ActionDeadCode`, coreaction.cc:3944) only on the deadcode immediately following a
    /// directwrite pass — exactly the two `ActionDirectWrite`→`ActionDeadCode` pairings Ghidra has
    /// (mainloop :5497-5503, fullloop :5680-5682). mosura's rotated pipeline has extra deadcodes
    /// (the mid-mainloop and cleanup sweeps) that Ghidra does not; gating the clear on this flag
    /// keeps those from stripping `addrforce` against a stale/never-computed `directwrite`.
    pub directwrite_pending_clear: bool,
    /// Set on the throwaway `partial` clone that `build` decompiles only to recover jump tables
    /// (build.rs). The late branch-orientation stage (`ActionOrientBranches`) is skipped on it:
    /// materializing a switch guard's negation there perturbs the range analysis
    /// (`JumpBasic::findSmallestNormal`) and under-recovers the table. Orientation is a render-time
    /// concern and only needs to run in the real decompile.
    pub table_recovery_probe: bool,
    /// The architecture's laned-register records (Ghidra `Architecture::lanerecords`, reached via
    /// `Funcdata::getArch`). Consumed by `ActionLaneDivide` to decide which vector registers may be
    /// lane-split. Parsed from the `.pspec` `vector_lane_sizes` by the build caller
    /// ([`crate::lang::pspec_laned_registers`]); empty ⇒ no lane splitting (the default, so a
    /// hand-built or lane-unaware Funcdata is unaffected).
    pub laned: super::transform::LanedRegisterSet,
    /// The function's default calling convention (Ghidra `ProtoModel`, reached via
    /// `Funcdata::getArch()->defaultfp` / `FuncCallSpecs`): the input & output parameter lists and
    /// the call side-effect (`EffectRecord`) list, decoded from the compiler spec's `<default_proto>`
    /// by the build caller ([`crate::analysis::cspec::default_proto_model`], a port of
    /// `ProtoModel::decode`). This replaces the old hardcoded `fspec::sysv_*` literals — prototype
    /// recovery (`recover_input_params`/`resolve_return`), `ActionDirectWrite`, and heritage
    /// `guardCalls` all read it. Empty ([`super::fspec::ProtoModel::empty`]) for a hand-built
    /// `Funcdata`, so a test graph with no compiler spec recovers no convention.
    pub proto_model: super::fspec::ProtoModel,
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
            copy_trims: Vec::new(),
            typerecovery_started: false,
            typerecovery_exceeded: false,
            heritage_pass: 0,
            globaldisjoint: super::heritage::LocationMap::default(),
            active_output: None,
            active_inputs: std::collections::HashMap::new(),
            call_guards_active: false,
            alias_boundary: None,
            directwrite_pending_clear: false,
            table_recovery_probe: false,
            laned: super::transform::LanedRegisterSet::default(),
            proto_model: super::fspec::ProtoModel::empty(),
        }
    }

    /// Ghidra `Funcdata::hasTypeRecoveryStarted`: whether data-type recovery has started
    /// (funcdata.hh:151, the `typerecovery_start` flag). Gates every type-reading site —
    /// `ActionInferTypes` (coreaction.cc:5378), `RulePushPtr` (ruleaction.cc:6851), `RulePtrArith`
    /// (ruleaction.cc:6642) — so the mainloop's first fullloop round runs typeless.
    pub fn has_type_recovery_started(&self) -> bool {
        self.typerecovery_started
    }
    /// Ghidra `Funcdata::startTypeRecovery` (funcdata.cc:182-188): mark that data-type analysis
    /// has started. Returns `true` exactly once — `false` if already started — so
    /// `ActionStartTypes` counts a change (forcing one more fullloop round, the typed phase)
    /// only the first time.
    pub fn start_type_recovery(&mut self) -> bool {
        if self.typerecovery_started {
            return false; // Already started
        }
        self.typerecovery_started = true;
        true
    }

    /// Ghidra `Funcdata::isTypeRecoveryExceeded`: whether type propagation hit its pass cap (7).
    pub fn is_type_recovery_exceeded(&self) -> bool {
        self.typerecovery_exceeded
    }
    /// Ghidra `Funcdata::setTypeRecoveryExceeded`: mark that propagation passes reached the maximum.
    pub fn set_type_recovery_exceeded(&mut self) {
        self.typerecovery_exceeded = true;
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
    ///
    /// GUARD-RAIL: the faithful driver (`jumpbasic::recover_jumpbasic`) bounds the switch variable
    /// by pulling a CircleRange back through the guard comparison (`analyze_guards`). On a
    /// fully-built graph whose out-of-range guard has already been folded into the switch, that
    /// guard is gone, so recovery declines (empty range). Recovery must therefore run on the
    /// build-time multistage partial (guard still intact) and be cached here — never re-run on the
    /// final folded graph.
    pub fn jump_tables(&mut self) -> Vec<super::jumptable::JumpTable> {
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
        // Ghidra sets the storage-derived properties at varnode CREATION: `Funcdata::newVarnode` /
        // `newVarnodeOut` (funcdata_varnode.cc:162-167 / :115-120) call `localmap->queryProperties`
        // → `Scope::queryProperties` (database.cc:1263-1282): an address inside a mapped scope with
        // no explicit symbol gets `mapped | addrtied` (+ `persist` when the scope is global). So a
        // stack or ram varnode is *born* address-tied — including the ones rules create mid-mainloop
        // (`RuleStoreVarnode`'s output, a SubVariableFlow-narrowed global) — and the per-pass symbol
        // sync (`syncVarnodesWithSymbols`, driven by `ActionRestructureVarnode`) can only CLEAR
        // `addrtied` later, for the unaliased stack locals ([`super::varnodeprops::mark_addrtied`]).
        // mosura's scope shape is by space (see `scope::query_properties`): the `stack` (Spacebase)
        // space is the local scope; the delayed Processor space (`ram`) is the global one; the
        // register space (Processor, delay 0), `unique` and `const` are never scope-mapped.
        let sp = self.spaces.get(loc.space);
        let scope_flags = match sp.kind {
            SpaceKind::Spacebase => flags::MAPPED | flags::ADDRTIED,
            SpaceKind::Processor if sp.delay > 0 => flags::MAPPED | flags::ADDRTIED | flags::PERSIST,
            _ => 0,
        };
        self.varnodes.push(Varnode {
            loc,
            size,
            flags: vflags | scope_flags,
            addlflags: 0,
            create_index,
            def: None,
            descend: Vec::new(),
            ty: None,
            nzm,
            // Ghidra Varnode constructor (varnode.cc:586): `consumed = ~((uintb)0)` — a fresh
            // varnode is FULLY consumed (conservative) until the next consume recompute. A 0
            // default is a mis-port: it makes every consume-gated rule (RuleOrConsume, the
            // SubVariableFlow gates, RulePullsubMulti/Indirect) maximally aggressive on varnodes
            // created after the last ActionConsume — e.g. folding a live `x ^ 0x87` to `0x87`.
            consume: !0u64,
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
            guarded_op: None,
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

    /// Ghidra `Funcdata::spacebase` (funcdata.cc:230, the body of `ActionSpacebase`): mark every SSA
    /// version of each space's spacebase (base-pointer) register `is_spacebase()`, and give the input
    /// version a locked pointer type. This activates the pointer-arithmetic (`RulePtrArith`),
    /// nonzero-mask (the stack pointer is treated as aligned) and type-inference (a value copied off
    /// the stack pointer is itself a pointer) rules that key on `is_spacebase()`.
    ///
    /// mosura runs this early once, before the first nonzero-mask / infertypes / pool. Ghidra runs it
    /// every mainloop iteration: pass 1 hits the mark arm (`else`), pass 2+ hits the re-mark arm — when
    /// a register is *already* spacebase with an `INT_ADD` def (the frame base `RSP = RSP+const`) and
    /// still has multiple descendants, `splitUses` clones the def per read into narrow single-use
    /// versions (funcdata.cc:253-259). The re-mark arm is faithfully present here, but inert on the
    /// early once-call (nothing is spacebase-marked yet — `spacebase` is the only setter — so every RSP
    /// version takes the mark arm). It fires only on a *second* late invocation after reheritage, once
    /// the frame base's descendants (loop phi, call arg) exist.
    pub fn spacebase(&mut self) {
        // The (space, register, size) of every spacebase register across all spaces (Ghidra iterates
        // each space's `getSpacebase(i)`); for x86-64 this is the single stack pointer RSP that is the
        // spacebase for the `stack` space. `spc` (the space RSP points into) is the `TypeSpacebase`'s
        // space, distinct from `loc.space` (the `register` space the RSP varnode lives in).
        let regs: Vec<(SpaceId, Address, u32)> = (0..self.spaces.num_spaces() as u32)
            .flat_map(|i| {
                self.spaces.get(SpaceId(i)).spacebase.clone().into_iter().map(move |(loc, sz)| (SpaceId(i), loc, sz))
            })
            .collect();
        for (spc, loc, size) in regs {
            // Every varnode at exactly this register location and size (Ghidra `vbank.beginLoc`).
            let vids: Vec<VarnodeId> = (0..self.varnodes.len() as u32)
                .map(VarnodeId)
                .filter(|&v| self.vn(v).loc == loc && self.vn(v).size == size)
                .collect();
            for v in vids {
                if self.vn(v).is_free() {
                    continue; // give descendants a chance to die naturally (funcdata.cc:252)
                }
                if self.vn(v).is_spacebase() {
                    // Already marked spacebase (funcdata.cc:253-259). Descendants were given a chance
                    // to die naturally; now force a split if it still has multiple descendants — an
                    // `INT_ADD`-defined base register (the frame base `RSP = RSP+const`) gets each read
                    // its own single-use version via `splitUses`. Inert on the early once-call.
                    if let Some(op) = self.vn(v).def {
                        if self.op(op).code() == OpCode::IntAdd {
                            self.split_uses(v);
                        }
                    }
                    continue;
                }
                self.vn_mut(v).set_spacebase(); // mark all base registers, not just the input
                if self.vn(v).is_input() {
                    // Ghidra `updateType(getTypePointer(size, getTypeSpacebase(...)), true, true)`: the
                    // input stack pointer is a locked pointer to a `TypeSpacebase` for this space. The
                    // spacebase pointee (size 0) makes `RulePtrArith` fold every `RSP + const` into a
                    // `PTRSUB` (not the degenerate `PTRADD` a unit `undefined1` pointee produced), which
                    // `printc` names off the recovered `ScopeLocal` symbol table.
                    self.vn_mut(v).ty = Some(super::types::Datatype::Pointer(
                        size,
                        Box::new(super::types::Datatype::Spacebase(spc)),
                    ));
                    self.vn_mut(v).flags |= flags::TYPELOCK;
                }
            }
        }
    }

    /// Ghidra `Funcdata::splitUses` (funcdata_varnode.cc:1540): for the given varnode, duplicate its
    /// defining op at each read so every read becomes its own fresh single-use version. This is what
    /// turns one broad SSA version of a register (e.g. the frame-base `RSP = INT_ADD(RSP,-0x68)` shared
    /// by a loop-phi init and a call argument) into Ghidra's narrow single-use versions (RSP:93 / RSP:94),
    /// so a version's cover ends at its lone use instead of spanning the whole live range. Must NOT be
    /// called on a def with side effects (CALL etc.); the caller (`spacebase`) only invokes it for an
    /// `INT_ADD`-defined spacebase register.
    ///
    /// For each descendant `useop`, clone `op` (same opcode + same inputs, a fresh output varnode at the
    /// same addr/size/type) and repoint that read at the clone. Every read is rewired — including the
    /// last — so the original `op`/`vn` are left with no descendants and dead-code elimination removes
    /// them (Ghidra's "Dead-code actions should remove original op").
    pub fn split_uses(&mut self, vn: VarnodeId) {
        let op = match self.vn(vn).def {
            Some(o) => o,
            None => return, // no def to clone
        };
        // Snapshot the descendant list up front (rewiring below mutates `vn.descend`); Ghidra's live
        // iterator is advanced past each `useop` before the rewire, so a copy is equivalent.
        let descend = self.vn(vn).descend.clone();
        if descend.len() <= 1 {
            return; // no descendants, or only one — nothing to split
        }
        let opcode = self.op(op).opcode;
        let addr = self.op(op).seqnum.pc;
        let inputs = self.op(op).inrefs.clone();
        let size = self.vn(vn).size;
        let loc = self.vn(vn).loc;
        let ty = self.vn(vn).ty.clone();
        for useop in descend {
            // The slot of `useop` still reading `vn` (Ghidra `useop->getSlot(vn)`, the first such slot;
            // a useop that reads `vn` in two slots appears in `descend` twice, so each pass takes the
            // next remaining slot).
            let slot = match self.op(useop).inrefs.iter().position(|&v| v == vn) {
                Some(s) => s,
                None => continue, // already rewired
            };
            let uniq = self.ops.len() as u32;
            let newop = self.new_op(opcode, SeqNum { pc: addr, uniq }, inputs.clone());
            let newvn = self.new_output(newop, size, loc);
            self.vn_mut(newvn).ty = ty.clone();
            self.op_set_input(useop, slot, newvn);
            self.op_insert_before(newop, op);
        }
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

    /// Ghidra `Funcdata::opBoolNegate` (funcdata_op.cc:560): construct a new BOOL_NEGATE of `vn`
    /// inserted before (or after, if `insertafter`) `op`, returning the negated (unique) output.
    pub fn op_bool_negate(&mut self, vn: VarnodeId, op: OpId, insertafter: bool) -> VarnodeId {
        let pc = self.ops[op.0 as usize].seqnum.pc;
        let uniq = self.ops.len() as u32;
        let negateop = self.new_op(OpCode::BoolNegate, SeqNum { pc, uniq }, vec![vn]);
        self.new_output_unique(negateop, 1);
        if insertafter {
            self.op_insert_after(negateop, op);
        } else {
            self.op_insert_before(negateop, op);
        }
        self.ops[negateop.0 as usize].output.unwrap()
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
    /// `iop` annotation referencing the causing op) is carried instead in the op's
    /// [`guarded_op`](super::op::PcodeOp::guarded_op) field (see there for the representation choice).
    /// The consume-side use of the `iop` (`setIndirectSource`) is still omitted (a dead-code-removal
    /// detail; see `consume.rs`).
    pub fn new_indirect_op(&mut self, indeffect: OpId, loc: Address, size: u32) -> OpId {
        let before = self.new_varnode(size, loc);
        let pc = self.ops[indeffect.0 as usize].seqnum.pc;
        let uniq = self.ops.len() as u32;
        let op = self.new_op(OpCode::Indirect, SeqNum { pc, uniq }, vec![before]);
        self.ops[op.0 as usize].guarded_op = Some(indeffect);
        self.new_output(op, size, loc);
        self.op_insert_before(op, indeffect);
        op
    }

    /// Change `op`'s opcode (Ghidra's `opSetOpcode`).
    pub fn op_set_opcode(&mut self, op: OpId, opcode: OpCode) {
        self.ops[op.0 as usize].opcode = opcode;
    }

    /// Ghidra `Funcdata::transferVarnodeProperties` (funcdata_varnode.cc): when a new varnode
    /// `new_vn` is created as a logical piece of `vn` at bit-offset `lsb_offset*8` (i.e. byte
    /// offset `lsb_offset`), carry over the `directwrite`/`addrforce` properties and shift the
    /// consume mask down by that many bytes. Used by the TransformManager when materializing a
    /// `piece` placeholder over overlapping storage.
    pub fn transfer_varnode_properties(&mut self, vn: VarnodeId, new_vn: VarnodeId, lsb_offset: i32) {
        let new_size = self.varnodes[new_vn.0 as usize].size;
        let mut new_consume = !0u64; // bits shifted in above precision are set
        if (lsb_offset as usize) < std::mem::size_of::<u64>() {
            let mut fill_bits = 0u64;
            if lsb_offset != 0 {
                fill_bits = new_consume << (8 * (std::mem::size_of::<u64>() as i32 - lsb_offset));
            }
            new_consume = ((self.varnodes[vn.0 as usize].consume >> (8 * lsb_offset))
                | fill_bits)
                & super::nzmask::calc_mask(new_size);
        }
        let vn_flags = self.varnodes[vn.0 as usize].flags & (flags::DIRECTWRITE | flags::ADDRFORCE);
        let nv = &mut self.varnodes[new_vn.0 as usize];
        nv.flags |= vn_flags; // Preserve addrforce/directwrite setting
        nv.consume = new_consume;
    }

    /// Ghidra `Funcdata::markIndirectCreation` (funcdata_op.cc): mark an INDIRECT op as modeling
    /// a value created out of nothing (a call's `killedbycall` clobber). Ghidra sets
    /// `indirect_creation` on the op, on `in(0)` (the iop-zero, unless the value is a possible
    /// output), and on the output varnode. mosura tracks `indirect_creation` on the output varnode
    /// (`Varnode::INDIRECT_CREATION`, read by `is_indirect_creation`); the op-level flag + the iop
    /// in(0) marking follow the guarded-op INDIRECT model (see the buildIndirect rebase TODO in
    /// `transform.rs`).
    pub fn mark_indirect_creation(&mut self, indop: OpId, possible_output: bool) {
        let out = self.ops[indop.0 as usize].output;
        let in0 = self.ops[indop.0 as usize].input(0);
        if let Some(out) = out {
            self.varnodes[out.0 as usize].set_indirect_creation();
        }
        if !possible_output {
            if let Some(in0) = in0 {
                if self.varnodes[in0.0 as usize].is_constant() {
                    self.varnodes[in0.0 as usize].set_indirect_creation();
                }
            }
        }
    }

    /// Flip the output condition of a CBRANCH (Ghidra's `Funcdata::opFlipCondition`,
    /// funcdata.hh:489 — `op->flipFlag(PcodeOp::boolean_flip)`). Toggles the `BOOLEAN_FLIP` bit so
    /// the branch-sense meaning inverts; used by `RuleCondNegate` after it materializes the
    /// negation in the IR, and by the structurer to record a chosen branch orientation.
    pub fn op_flip_condition(&mut self, op: OpId) {
        self.ops[op.0 as usize].flags ^= super::op::flags::BOOLEAN_FLIP;
    }

    /// Negate the branch sense of a 2-out CBRANCH block (Ghidra's `BlockBasic::negateCondition`,
    /// block.cc:2351): the structurer chose to put this block's body on the false edge, so set
    /// `boolean_flip` (marking the CBRANCH for `RuleCondNegate` to materialize the negation) and
    /// `fallthru_true` on the terminating CBRANCH.
    ///
    /// Ghidra additionally reverses the block's out-edge order (`FlowBlock::negateCondition`).
    /// mosura does NOT: its structurer re-derives the block tree from the CFG at print time, and a
    /// reversed edge order makes the re-collapse diverge for condition blocks entangled with loops
    /// or short-circuits (`rule_short_circuit` re-installs never converge). Instead the orientation
    /// lives in the persistent `fallthru_true` flag — which Ghidra's printc also reads
    /// (printc.cc:542) — and the structurer XORs it into `negated` (`Structured::is_oriented`). The
    /// materialized positive condition is then printed directly, matching Ghidra's rendering without
    /// perturbing the CFG topology.
    pub fn block_negate_condition(&mut self, bid: super::block::BlockId) {
        let Some(&lastop) = self.blocks[bid.0 as usize].ops.last() else {
            return;
        };
        debug_assert_eq!(self.ops[lastop.0 as usize].opcode, OpCode::Cbranch);
        self.ops[lastop.0 as usize].flags |=
            super::op::flags::BOOLEAN_FLIP | super::op::flags::FALLTHRU_TRUE;
    }

    /// The lone op reading `vn`, or `None` if it has zero or several readers (Ghidra
    /// `Varnode::loneDescend`).
    fn lone_descend(&self, vn: VarnodeId) -> Option<OpId> {
        let d = &self.varnodes[vn.0 as usize].descend;
        (d.len() == 1).then(|| d[0])
    }

    /// Trace a boolean value to the set of PcodeOps that would need op-code flipping to negate it,
    /// and report whether that flip *normalizes* (Ghidra's `Funcdata::opFlipInPlaceTest`,
    /// funcdata_op.cc:1221). `op` is a CBRANCH (recurses to its `getIn(1)`'s def) or a
    /// boolean-producing op. Returns `(result, fliplist)`: result 0 if the flip normalizes, 1 if it
    /// is ambivalent, 2 if it does not normalize; `fliplist` holds the ops to hand to
    /// [`op_flip_in_place_execute`](Self::op_flip_in_place_execute). The normal form prefers `==`
    /// over `!=`, a constant on the left of `<`, and a non-constant on the right of `<=`. This is
    /// the decision behind Ghidra's `BlockIf::preferComplement` / `ActionNormalizeBranches`.
    pub fn op_flip_in_place_test(&self, op: OpId) -> (i32, Vec<OpId>) {
        let mut fliplist = Vec::new();
        let r = self.op_flip_in_place_test_rec(op, &mut fliplist);
        (r, fliplist)
    }

    fn op_flip_in_place_test_rec(&self, op: OpId, fliplist: &mut Vec<OpId>) -> i32 {
        match self.op(op).code() {
            OpCode::Cbranch => {
                let Some(vn) = self.op(op).input(1) else { return 2 };
                if self.lone_descend(vn) != Some(op) || !self.vn(vn).is_written() {
                    return 2;
                }
                self.op_flip_in_place_test_rec(self.vn(vn).def.unwrap(), fliplist)
            }
            OpCode::IntEqual | OpCode::FloatEqual => {
                fliplist.push(op);
                1
            }
            OpCode::BoolNegate | OpCode::IntNotequal | OpCode::FloatNotequal => {
                fliplist.push(op);
                0
            }
            OpCode::IntSless | OpCode::IntLess => {
                let in0 = self.op(op).input(0).unwrap();
                fliplist.push(op);
                if !self.vn(in0).is_constant() {
                    1
                } else {
                    0
                }
            }
            OpCode::IntSlessequal | OpCode::IntLessequal => {
                let in1 = self.op(op).input(1).unwrap();
                fliplist.push(op);
                if self.vn(in1).is_constant() {
                    1
                } else {
                    0
                }
            }
            OpCode::BoolOr | OpCode::BoolAnd => {
                let in0 = self.op(op).input(0).unwrap();
                if self.lone_descend(in0) != Some(op) || !self.vn(in0).is_written() {
                    return 2;
                }
                let subtest1 = self.op_flip_in_place_test_rec(self.vn(in0).def.unwrap(), fliplist);
                if subtest1 == 2 {
                    return 2;
                }
                let in1 = self.op(op).input(1).unwrap();
                if self.lone_descend(in1) != Some(op) || !self.vn(in1).is_written() {
                    return 2;
                }
                let subtest2 = self.op_flip_in_place_test_rec(self.vn(in1).def.unwrap(), fliplist);
                if subtest2 == 2 {
                    return 2;
                }
                fliplist.push(op);
                subtest1 // the front of an AND/OR governs whether the whole normalizes
            }
            _ => 2,
        }
    }

    /// Perform the op-code flips computed by [`op_flip_in_place_test`](Self::op_flip_in_place_test)
    /// (Ghidra's `Funcdata::opFlipInPlaceExecute`, funcdata_op.cc:1280): rewrite each fliplist op to
    /// its complement in place. A BOOL_NEGATE (`get_booleanflip` ⇒ COPY) is removed entirely —
    /// its input is propagated into its output's lone descendant. A BOOL_AND/BOOL_OR
    /// (`get_booleanflip` ⇒ CPUI_MAX) is swapped to the other connective. A comparison is set to its
    /// complementary op-code, its inputs swapped when the complement reorders, and a resulting `<=`
    /// is rewritten to `<` via [`replace_lessequal`](super::rules::replace_lessequal).
    pub fn op_flip_in_place_execute(&mut self, fliplist: &[OpId]) {
        for &op in fliplist {
            let code = self.op(op).code();
            match super::opcode::get_booleanflip(code) {
                Some((OpCode::Copy, _)) => {
                    // Remove the BOOL_NEGATE, propagating its input into the lone descendant.
                    let vn = self.op(op).input(0).unwrap();
                    let outvn = self.op(op).output.unwrap();
                    let otherop =
                        self.lone_descend(outvn).expect("flipInPlace BOOL_NEGATE lone descend");
                    let slot = (0..self.op(otherop).num_inputs())
                        .find(|&s| self.op(otherop).input(s) == Some(outvn))
                        .unwrap();
                    self.op_set_input(otherop, slot, vn);
                    self.op_destroy(op);
                }
                None => {
                    // get_booleanflip ⇒ CPUI_MAX: only BOOL_AND/BOOL_OR reach here from a fliplist.
                    match code {
                        OpCode::BoolAnd => self.op_set_opcode(op, OpCode::BoolOr),
                        OpCode::BoolOr => self.op_set_opcode(op, OpCode::BoolAnd),
                        _ => panic!("Bad flipInPlace op"),
                    }
                }
                Some((opc, flipyes)) => {
                    self.op_set_opcode(op, opc);
                    if flipyes {
                        self.op_swap_input(op, 0, 1);
                        if matches!(opc, OpCode::IntLessequal | OpCode::IntSlessequal) {
                            super::rules::replace_lessequal(self, op);
                        }
                    }
                }
            }
        }
    }

    /// Flip which of a 2-out CBRANCH block's edges is the fall-through true branch (Ghidra's
    /// `BlockBasic::flipInPlaceExecute`, block.cc:2378): toggle the terminating CBRANCH's
    /// `fallthru_true` flag. Unlike [`block_negate_condition`](Self::block_negate_condition) it does
    /// **not** touch `boolean_flip` — the condition op-code is being changed explicitly by
    /// [`op_flip_in_place_execute`](Self::op_flip_in_place_execute), so no `RuleCondNegate`
    /// materialization is needed. Per the S1 no-edge-reversal discipline the CFG out-edges are left
    /// intact; the flag alone carries the orientation, which the structurer XORs back in.
    pub fn flip_in_place_execute(&mut self, bid: super::block::BlockId) {
        let Some(&lastop) = self.blocks[bid.0 as usize].ops.last() else {
            return;
        };
        debug_assert_eq!(self.ops[lastop.0 as usize].opcode, OpCode::Cbranch);
        self.ops[lastop.0 as usize].flags ^= super::op::flags::FALLTHRU_TRUE;
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

    /// Insert `op` as the last op in `block`, but *before* a trailing branch/return if the block
    /// ends in one (Ghidra's `opInsertEnd`, funcdata_op.cc): `opInsertEnd` steps back from the block
    /// end and, if the last op is a flow-break (`isFlowBreak`), inserts ahead of it. `op` adopts
    /// `block` as its parent. Used by [`super::merge`]'s marker-trim (`Merge::trimOpInput`) to place a
    /// phi-input snapshot COPY at the predecessor block's end.
    pub fn op_insert_end(&mut self, op: OpId, block: super::block::BlockId) {
        self.ops[op.0 as usize].parent = Some(block);
        let blk_ops = &self.blocks[block.0 as usize].ops;
        let mut pos = blk_ops.len();
        if let Some(&last) = blk_ops.last() {
            if self.ops[last.0 as usize].opcode.terminates_block() {
                pos -= 1; // insert before the terminating branch/return (Ghidra isFlowBreak)
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
            // Ghidra's opDestroy calls destroyVarnode(op->getOut()): the output is removed from the
            // bank. mosura keeps the arena slot index-stable, so free it (clear INPUT|INSERT|WRITTEN
            // + def) as delete_varnode does — otherwise it lingers as a non-free orphan (def=None,
            // INSERT set) that address-tied merge/cover passes wrongly treat as a live same-address
            // value.
            self.varnodes[out.0 as usize].def = None;
            self.varnodes[out.0 as usize].flags &= !(flags::INPUT | flags::INSERT | flags::WRITTEN);
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

    /// `Funcdata::spacebase` (ActionSpacebase) marks every non-free 8-byte SSA version of RSP
    /// `is_spacebase()`, gives only the *input* version a locked pointer type, and leaves free
    /// varnodes, differently-sized varnodes, and other registers untouched.
    #[test]
    fn spacebase_marks_rsp_versions() {
        use crate::decompile::types::Datatype;
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let stack = spaces.by_name("stack").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let rsp = Address::new(reg, 0x20);

        let input = f.new_input(8, rsp); // the entry stack pointer
        // a written version: r0x20:8 = INT_ADD(input, 8)  (a `pop`/frame adjust)
        let eight = f.new_const(8, 8);
        let seq = SeqNum { pc: Address::new(ram, 0x10), uniq: 0 };
        let addop = f.new_op(OpCode::IntAdd, seq, vec![input, eight]);
        let written = f.new_output(addop, 8, rsp);
        let free8 = f.new_varnode(8, rsp); // free (no def, not input) — must be skipped
        let esp4 = f.new_varnode(4, rsp); // 4-byte at RSP location — wrong size, not marked
        let rax = f.new_input(8, Address::new(reg, 0)); // a different register

        f.spacebase();

        // input: marked + locked pointer to the `stack` space's TypeSpacebase (Ghidra
        // `getTypePointer(size, getTypeSpacebase(stack, ...))`).
        assert!(f.vn(input).is_spacebase());
        assert!(f.vn(input).is_typelock());
        assert_eq!(f.vn(input).ty, Some(Datatype::Pointer(8, Box::new(Datatype::Spacebase(stack)))));
        // written version: marked, but NOT typed (only the input gets the pointer type)
        assert!(f.vn(written).is_spacebase());
        assert!(!f.vn(written).is_typelock());
        // free / wrong-size / other-register: untouched
        assert!(!f.vn(free8).is_spacebase());
        assert!(!f.vn(esp4).is_spacebase());
        assert!(!f.vn(rax).is_spacebase());
    }

    /// `Funcdata::split_uses` (funcdata_varnode.cc:1540): given the frame-base spacebase varnode
    /// `RSP = INT_ADD(RSP_input, -0x68)` with two reads (a loop-phi init + a call arg), clone the
    /// INT_ADD def per read so each read becomes its own single-use version at the RSP location —
    /// the narrow SSA versions (Ghidra's RSP:93 / RSP:94) that let each cover end at its lone use.
    #[test]
    fn split_uses_clones_def_per_read() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let rsp = Address::new(reg, 0x20);

        let input = f.new_input(8, rsp); // the entry stack pointer
        // frame base: r0x20:8 = INT_ADD(input, -0x68)
        let neg = f.new_const(8, (-0x68i64) as u64);
        let seq = SeqNum { pc: Address::new(ram, 0x10), uniq: 0 };
        let addop = f.new_op(OpCode::IntAdd, seq, vec![input, neg]);
        let fb = f.new_output(addop, 8, rsp);

        // two reads of the frame base (modelled as two COPY ops to distinct registers)
        let s1 = SeqNum { pc: Address::new(ram, 0x20), uniq: 1 };
        let use1 = f.new_op(OpCode::Copy, s1, vec![fb]);
        f.new_output(use1, 8, Address::new(reg, 0));
        let s2 = SeqNum { pc: Address::new(ram, 0x30), uniq: 2 };
        let use2 = f.new_op(OpCode::Copy, s2, vec![fb]);
        f.new_output(use2, 8, Address::new(reg, 8));

        assert_eq!(f.vn(fb).descend.len(), 2);
        f.split_uses(fb);

        // Original frame base now has NO descendants (both reads rewired to fresh clones); dead-code
        // elimination removes the now-unused original op.
        assert!(f.vn(fb).descend.is_empty());
        let r1 = f.op(use1).input(0).unwrap();
        let r2 = f.op(use2).input(0).unwrap();
        // distinct fresh versions, neither is the original
        assert_ne!(r1, fb);
        assert_ne!(r2, fb);
        assert_ne!(r1, r2);
        for r in [r1, r2] {
            // each clone lives at the RSP location, single-use, with its own INT_ADD def
            assert_eq!(f.vn(r).loc, rsp);
            assert_eq!(f.vn(r).size, 8);
            assert_eq!(f.vn(r).descend.len(), 1);
            let d = f.vn(r).def.expect("clone has a def");
            assert_eq!(f.op(d).code(), OpCode::IntAdd);
            assert_eq!(f.op(d).input(0), Some(input));
            assert_eq!(f.op(d).input(1), Some(neg));
        }
    }

    /// `split_uses` on a varnode with a single read is a no-op (Ghidra's early return).
    #[test]
    fn split_uses_single_read_is_noop() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let rsp = Address::new(reg, 0x20);

        let input = f.new_input(8, rsp);
        let neg = f.new_const(8, (-0x68i64) as u64);
        let seq = SeqNum { pc: Address::new(ram, 0x10), uniq: 0 };
        let addop = f.new_op(OpCode::IntAdd, seq, vec![input, neg]);
        let fb = f.new_output(addop, 8, rsp);
        let use1 = f.new_op(OpCode::Copy, SeqNum { pc: Address::new(ram, 0x20), uniq: 1 }, vec![fb]);
        f.new_output(use1, 8, Address::new(reg, 0));

        f.split_uses(fb);
        // the lone read still points at the original frame base — no clone made
        assert_eq!(f.op(use1).input(0), Some(fb));
        assert_eq!(f.vn(fb).descend.len(), 1);
    }

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
