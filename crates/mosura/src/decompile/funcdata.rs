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
    /// Ghidra `Funcdata::clean_up_index` (funcdata.hh:75): the varnode creation index at the moment
    /// the clean-up phase started, stamped by [`Self::start_clean_up`]. NOTE: in Ghidra 12.0.3 the
    /// companion `getCleanUpIndex()` has no callers anywhere in the decompiler — the watermark is
    /// recorded and never read. Carried for roster fidelity so `ActionStartCleanUp` is a real port
    /// rather than an empty stub; a future consumer finds it already correct.
    clean_up_index: u32,
    /// Ghidra `Funcdata::restart_pending` (funcdata.hh:148, the `restart_pending` flag word bit):
    /// analysis discovered something that invalidates the whole decompile, so the root
    /// `ActionRestartGroup` should clear and re-run it. Set by [`super::heritage::bump_deadcode_delay`].
    pub restart_pending: bool,
    /// Ghidra's per-space `HeritageInfo::deadremoved` (heritage.hh), latched by
    /// `Heritage::deadRemovalAllowedSeen`. mosura derives `HeritageInfo` fresh on every
    /// `build_info_list` call, so the latch needs a persistent home; this is it, indexed by
    /// `SpaceId`.
    pub deadremoved: Vec<i32>,
    /// Ghidra `Override::deadcodedelay` (override.hh), the one piece of state that deliberately
    /// SURVIVES `Funcdata::clear` across a restart ("Do not clear overrides", funcdata.cc:106) —
    /// otherwise the restart would rediscover the same problem and loop forever.
    pub deadcode_delay_override: std::collections::HashMap<SpaceId, i32>,
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
    /// Ghidra `FuncProto::returnBytesConsumed` (fspec.hh:1428): how many BYTES of this function's
    /// return value its callers actually consume — 0 meaning "no information". Written only by
    /// `RulePiecePathology` (ruleaction.cc:10529) and read by the dead-code consume sweep
    /// (`gather_consumed_return`, coreaction.cc:3887) to clamp what the RETURN is considered to
    /// consume.
    ///
    /// It lives on `Funcdata` rather than on [`super::fspec::FuncProto`] because mosura's FuncProto
    /// is a recovered RESULT built at the end, while this is live state the pools mutate.
    /// Ghidra `Funcdata::blocks_unreachable` (funcdata.hh:149, read by `hasUnreachableBlocks`): the
    /// function exhibited unreachable code, which was removed. The double-precision rules refuse to
    /// act while it is set, because a removed block can leave the remaining data-flow looking like a
    /// logical whole when it is not.
    /// Address ranges that are READ-ONLY in the loaded image (`start..=end` offsets in the `ram`
    /// space), from the loader's per-section write flag.
    ///
    /// Ghidra reaches this through `Scope::isReadOnly` → `queryProperties` → the `Varnode::readonly`
    /// property a `MemoryBlock` contributes. mosura has no Scope object for globals, so the ranges
    /// travel directly; the analysis layer fills them in (`analysis::decompiler`), and a hand-built
    /// `Funcdata` has none, which answers "not read-only" — the conservative direction.
    /// Cache for [`super::varmap::recover_scope`] — the recovered stack symbols.
    ///
    /// Ghidra's `TypeSpacebase::getSubType` queries a PERSISTENT `Scope`; mosura's `recover_scope`
    /// REBUILDS the whole table (O(function size)) on every call. That is fine for the callers that
    /// ask once per pass, but `RulePtrsubUndo` asks per PTRSUB evaluation, which measured 23µs a
    /// call and kept WAR2's FUN_00024a88 from finishing. Invalidated wherever the local layout is
    /// recomputed (`ActionRestructureVarnode`), which is exactly when Ghidra's Scope changes.
    pub stack_syms_cache: Option<Vec<super::varmap::StackSymbol>>,
    pub readonly_ranges: Vec<(u64, u64)>,
    /// Which Ghidra GLOBAL-SCOPE behavior this Funcdata models. Ghidra has two: the APPLICATION
    /// resolves a symbol for any address inside a loaded memory block (its program database
    /// auto-answers `queryContainer` — why `&DAT_...` exists for unnamed addresses), while the
    /// STANDALONE decompiler (datatest fixtures, capture_trace) answers only explicitly declared
    /// symbols — its `ActionConstantPtr` is silent on undeclared addresses. mosura's analysis
    /// boundary models the application (`true`); the fixture loader leaves the standalone default
    /// (`false`), matching the oracle each context is validated against. Measured: grounding the
    /// query on the image alone made the fixture corpus emit `&xRam` forms its (silent-action)
    /// oracle lacks — 0.9569 -> 0.9382.
    pub global_scope_all_loaded: bool,
    /// Calls whose committed argument list contained a linked-but-UNWRITTEN varnode, awaiting the
    /// output commit that should give it a definition (see [`Self::reopen_input`]).
    pub calls_awaiting_output: std::collections::BTreeSet<OpId>,
    /// Calls already re-opened once — the bound that keeps the repair from cycling.
    pub reopened_inputs: std::collections::BTreeSet<OpId>,
    pub blocks_unreachable: bool,
    pub return_bytes_consumed: u32,
    /// The structured block hierarchy — Ghidra `Funcdata::sblocks` read via `getStructure()`.
    /// Built by `ActionBlockStructure` (mainloop, coreaction.cc:5659) and `ActionFinalStructure`
    /// (tail, after SetCasts); cleared by [`Self::structure_reset`] whenever the CFG mutates
    /// (Ghidra calls `structureReset()` from every block-editing method, funcdata_block.cc) and
    /// by the orientation-mutating structure actions (whose flag writes mosura's re-deriving
    /// build bakes in, where Ghidra mutates the persistent graph in place). `None` = not built
    /// or invalidated — consumers rebuild, except `ActionReturnSplit`, which SKIPS, exactly as
    /// Ghidra's `getSize() == 0` gate does (blockaction.cc:2276).
    pub structure: Option<super::structure::Structured>,
    pub active_output: Option<super::fspec::ParamActive>,
    /// Width of the return storage the function was found to actually produce, recorded when the
    /// output trials commit.
    ///
    /// It is recorded there because that is the last moment the evidence exists. The recovered
    /// trials say how much of the convention's return register this function really writes — a
    /// comparison result that the original widens to the full register covers four bytes, while a
    /// function returning a byte covers one — and later stages legitimately narrow the Varnode
    /// reaching the RETURN, so by print time the two cases are indistinguishable. They must not
    /// be: the declared return type's width is exactly what makes the compiler emit or omit the
    /// widening instruction, so getting it wrong deletes an instruction in one direction and
    /// invents one in the other.
    pub output_storage_size: Option<u32>,
    /// Ghidra `FuncCallSpecs::activeinput`, one per CALL (keyed by the CALL op): the [`ParamActive`]
    /// recovering that sub-function's argument registers. Set up + committed by
    /// `recover::resolve_call_args`; an entry is removed once its trials commit
    /// (`clearActiveInput`). Persisting it lets the prune DEFER instead of committing greedily.
    pub active_inputs: std::collections::HashMap<OpId, super::fspec::ParamActive>,
    /// The rest of Ghidra's per-CALL `FuncCallSpecs` state (see [`super::fspec::CallSpec`]) — the
    /// stack-pointer offset at the call site and the placeholder's input slot. Separate from
    /// [`active_inputs`](Self::active_inputs) because it must outlive the trial container: the
    /// offset is read by `guardCalls` on every later heritage pass, long after the arguments
    /// commit and the `ParamActive` is dropped.
    pub call_specs: std::collections::HashMap<OpId, super::fspec::CallSpec>,

    /// Register offsets THIS function destroys — written somewhere in its reachable body and not
    /// restored — or `None` when that could not be established
    /// (`analysis::decompiler::callee_writes_cfg`). It is the function's recovered Watcom `modify`
    /// list, and a backend that must reproduce the original's register saves needs it: without a
    /// declaration Watcom preserves registers the original destroys, costing a push/pop pair each.
    pub own_modify: Option<Vec<u64>>,

    /// Register offsets this function SAVES AND RESTORES (a `push`/`pop` pair). They are
    /// callee-saved storage, never parameters — see `recover_input_params`' custom-register branch.
    pub own_saved: Option<Vec<u64>>,

    /// Ghidra `ScopeLocal`'s carved-out ranges (`markNotMapped`, varmap.cc): storage that is NOT a
    /// local variable — today the callee-save slots found by [`super::restrictlocal`]. Ghidra
    /// removes these from the Scope's range tree; mosura has no Scope object, so the removals are
    /// accumulated here and subtracted when the local window is built ([`super::varmap`]).
    /// Cumulative on purpose: the marking happens while the save chain is alive and must outlive
    /// the deadcode pass that deletes it.
    pub not_mapped: super::space::RangeList,
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
    /// How far the explicit/implied classification reached — the Varnode count when
    /// [`super::merge::ActionMarkImplied`] ran (Ghidra `ActionMarkExplicit`/`ActionMarkImplied`,
    /// coreaction.cc:5719-5720). `None` until it does.
    ///
    /// Varnodes created *after* that point — the uniques `ActionSetCasts` (:5735) introduces when it
    /// rewires an op's output through a CAST — were never classified. Ghidra sets their flag once, at
    /// creation, and never re-derives it; so for them the flag is the whole answer, and the
    /// recomputed classification chain must not be consulted at all (see
    /// [`super::printc`]'s `is_explicit`).
    pub classified_upto: Option<usize>,
    /// The function's HighVariables (Ghidra's `Merge`/`Varnode::high`), frozen by
    /// [`super::merge::ActionMergeType`] at Ghidra's merge slot — after the last merge action
    /// (`ActionMergeType`, coreaction.cc:5727) and *before* `ActionSetCasts` (:5735).
    ///
    /// Ghidra's merging is complete before any CAST op exists, and each CAST varnode inserted
    /// afterwards gets its own fresh HighVariable. Recomputing the merge later — over a graph that
    /// now contains those casts — is a different partition. So the printer consumes this frozen
    /// state rather than re-deriving it; see [`super::printc::print_c`].
    pub highs: Option<super::merge::FrozenHighs>,
    /// The ops Ghidra's `ActionCopyMarker` (`Merge::markInternalCopies`, merge.cc:1444) marks
    /// non-printing, frozen by [`super::merge::ActionCopyMarker`] at Ghidra's slot
    /// (coreaction.cc:5729 — after the merges end at :5727, before `ActionSetCasts` at :5735).
    /// `None` until it runs.
    ///
    /// Ghidra decides this before a single CAST exists. `ActionSetCasts::castOutput` does not only
    /// *add* ops, it **rewires** them: the original op is made to write a fresh unique and the CAST
    /// takes over producing the original Varnode. A COPY/PIECE/SUBPIECE whose output was cast
    /// therefore has a different output Varnode — in a different HighVariable, with a different
    /// Cover — after the casts than the one `markInternalCopies` reasons about. Recomputing the
    /// marks at print time asks the question of a graph Ghidra never analyzed; the printer consumes
    /// this instead (see [`super::printc::print_c`]).
    pub nonprinting: Option<std::collections::HashSet<super::op::OpId>>,
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
    /// The stack pointer register, decoded from the compiler spec's `<stackpointer>` (Ghidra
    /// `CompilerSpec::decode`; reached in the decompiler as `glb->translate->getSpacebase`). Stack
    /// recovery, the alias probe and `ActionDirectWrite` all key on it.
    ///
    /// It is spec-sourced rather than a constant because the offset is target-specific and getting
    /// it wrong fails *silently*: x86-64 puts RSP at `0x20`, but `x86:LE:32`'s register file puts
    /// ESP at `0x10` (Ghidra `ia.sinc`, the `@else` branch), and a seed that matches no register
    /// simply never propagates — stack recovery then yields zero stack Varnodes and every frame slot
    /// renders as an offset from an unmodelled register. `None` for a hand-built `Funcdata` with no
    /// compiler spec, which disables the stack-pointer-keyed passes exactly as an empty
    /// `proto_model` disables prototype recovery.
    pub stack_pointer: Option<super::space::Address>,
    /// Ghidra `Architecture::aggressive_ext_trim` (`architecture.hh:176`), decoded from the compiler
    /// spec's `<aggressivetrim signext=>`. `RuleSubvarSext::reset` (`subflow.cc:1745`) reads it and
    /// passes it as `SubvariableFlow`'s `aggressive` argument. `false` is Ghidra's default
    /// (`architecture.cc:156`) and the answer for every x86 spec; see
    /// [`crate::analysis::cspec::aggressive_ext_trim`] for why it is read rather than assumed.
    pub aggressive_ext_trim: bool,
    /// Ghidra `Architecture::funcptr_align` (`architecture.hh:183`), decoded from the compiler
    /// spec's `<funcptr align=>` as a BIT POSITION (see
    /// [`crate::analysis::cspec::funcptr_align`]). 0 — the x86 answer — disables the alignment
    /// analysis entirely, which is what [`RuleFuncPtrEncoding`](super::rules::RuleFuncPtrEncoding)
    /// checks first.
    pub funcptr_align: i32,
    /// User-defined p-code op index → name (Ghidra `Architecture::userops`, reached via
    /// `Funcdata::getArch`). Copied from [`crate::sleigh::engine::Spec::userops`] by the build
    /// caller; consumed by `PrintC::opCallother` to render a `CPUI_CALLOTHER` as `<name>(args)`
    /// rather than leaking a raw `CALLOTHER(...)`. Empty for a hand-built `Funcdata`.
    pub userops: std::collections::HashMap<u64, String>,
    /// Ghidra `Funcdata::opactdbg_active` — record op mutations for the action currently running.
    /// Set by [`debug_activate`](Self::debug_activate) (a no-op unless the facility is on) and
    /// cleared by [`debug_mod_print`](Self::debug_mod_print).
    opactdbg_active: bool,
    /// Ghidra `Funcdata::modify_list` / `modify_before` — the ops mutated during the current action
    /// and their rendered \e before state.
    modify_list: Vec<OpId>,
    modify_before: Vec<String>,
}

impl Funcdata {
    pub fn new(name: impl Into<String>, addr: Address, spaces: SpaceManager) -> Funcdata {
        // Ghidra's `ProtoModel` constructor installs the default `<localrange>`/`<paramrange>`
        // (fspec.cc:2353-2354), so there is no such thing as a model without stack windows. A
        // spec-driven build overwrites this whole field; a hand-built `Funcdata` keeps it, and
        // without it `ScopeLocal` would map no stack local at all.
        let proto_model = super::fspec::ProtoModel::with_default_ranges(&spaces);
        Funcdata {
            name: name.into(),
            addr,
            spaces,
            varnodes: Vec::new(),
            ops: Vec::new(),
            blocks: Vec::new(),
            create_index: 0,
            clean_up_index: 0,
            restart_pending: false,
            deadremoved: Vec::new(),
            deadcode_delay_override: std::collections::HashMap::new(),
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
            return_bytes_consumed: 0,
            structure: None,
            calls_awaiting_output: Default::default(),
            reopened_inputs: Default::default(),
            blocks_unreachable: false,
            readonly_ranges: Vec::new(),
            global_scope_all_loaded: false,
            stack_syms_cache: None,
            output_storage_size: None,
            active_inputs: std::collections::HashMap::new(),
            call_specs: std::collections::HashMap::new(),
            own_modify: None,
            own_saved: None,
            not_mapped: super::space::RangeList::default(),
            call_guards_active: false,
            alias_boundary: None,
            directwrite_pending_clear: false,
            table_recovery_probe: false,
            classified_upto: None,
            highs: None,
            nonprinting: None,
            laned: super::transform::LanedRegisterSet::default(),
            proto_model,
            stack_pointer: None,
            aggressive_ext_trim: false,
            funcptr_align: 0,
            userops: std::collections::HashMap::new(),
            opactdbg_active: false,
            modify_list: Vec::new(),
            modify_before: Vec::new(),
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

    /// Ghidra `Funcdata::combineInputVarnodes` (funcdata_varnode.cc:1620): fuse two CONTIGUOUS
    /// input varnodes into one wider input — the repair for a double-precision value that arrived
    /// as two separate halves.
    ///
    /// Every `PIECE(hi, lo)` that recombined them becomes a COPY of the new whole. Readers that
    /// used a half on its own get a replacement built as a SUBPIECE of the whole, inserted at the
    /// entry block, so no reader is left pointing at a varnode that no longer exists.
    ///
    /// Ghidra throws on non-input or non-contiguous arguments; the callers check first, so this
    /// returns `false` instead (the rule then declines rather than aborting the decompile).
    /// mosura has no varnode bank to `destroy` into, so the old halves are simply left unreferenced.
    pub fn combine_input_varnodes(&mut self, vn_hi: VarnodeId, vn_lo: VarnodeId) -> bool {
        if !self.vn(vn_hi).is_input() || !self.vn(vn_lo).is_input() {
            return false;
        }
        // Little-endian: the low half sits below the high half, and the whole starts at the low.
        let addr = self.vn(vn_lo).loc;
        let other = Address::new(addr.space, addr.offset + self.vn(vn_lo).size as u64);
        if other != self.vn(vn_hi).loc {
            return false;
        }
        let mut piece_list = Vec::new();
        let mut other_ops_hi = false;
        for op in self.vn(vn_hi).descend.clone() {
            if self.op(op).code() == OpCode::Piece
                && self.op(op).input(0) == Some(vn_hi)
                && self.op(op).input(1) == Some(vn_lo)
            {
                piece_list.push(op);
            } else {
                other_ops_hi = true;
            }
        }
        let mut other_ops_lo = false;
        for op in self.vn(vn_lo).descend.clone() {
            if self.op(op).code() != OpCode::Piece
                || self.op(op).input(0) != Some(vn_hi)
                || self.op(op).input(1) != Some(vn_lo)
            {
                other_ops_lo = true;
            }
        }
        for &p in &piece_list {
            self.op_remove_input(p, 1);
            // Ghidra also `opUnsetInput`s slot 0 here, to leave the old half with an empty descend
            // list before destroying it in the varnode bank. mosura has no bank destroy, and slot 0
            // is overwritten with the combined input below, so the unset would be a no-op.
        }
        let entry = super::block::BlockId(0);
        let start = self.block(entry).ops.first().map(|&o| self.op(o).seqnum.pc);
        let mut sub_hi = None;
        let mut sub_lo = None;
        if other_ops_hi {
            let size_lo = self.vn(vn_lo).size;
            let off = self.new_const(4, size_lo as u64);
            let pc = start.unwrap_or(self.vn(vn_hi).loc);
            let uniq = self.num_ops() as u32;
            let op = self.new_op(OpCode::Subpiece, SeqNum { pc, uniq }, vec![vn_hi, off]);
            let (size, loc) = (self.vn(vn_hi).size, self.vn(vn_hi).loc);
            let new_hi = self.new_output(op, size, loc);
            self.op_insert_begin(op, entry);
            self.total_replace(vn_hi, new_hi);
            sub_hi = Some(op);
        }
        if other_ops_lo {
            let off = self.new_const(4, 0);
            let pc = start.unwrap_or(self.vn(vn_lo).loc);
            let uniq = self.num_ops() as u32;
            let op = self.new_op(OpCode::Subpiece, SeqNum { pc, uniq }, vec![vn_lo, off]);
            let (size, loc) = (self.vn(vn_lo).size, self.vn(vn_lo).loc);
            let new_lo = self.new_output(op, size, loc);
            self.op_insert_begin(op, entry);
            self.total_replace(vn_lo, new_lo);
            sub_lo = Some(op);
        }
        let out_size = self.vn(vn_hi).size + self.vn(vn_lo).size;
        let in_vn = self.new_varnode(out_size, addr);
        let in_vn = self.set_input_varnode(in_vn);
        for &p in &piece_list {
            self.op_set_input(p, 0, in_vn);
            self.op_set_opcode(p, OpCode::Copy);
        }
        if let Some(op) = sub_hi {
            self.op_set_input(op, 0, in_vn);
        }
        if let Some(op) = sub_lo {
            self.op_set_input(op, 0, in_vn);
        }
        true
    }

    /// Ghidra `Scope::isReadOnly` (database.cc): is every byte of `[addr, addr+size)` in read-only
    /// storage? Ghidra asks the Scope for the varnode properties covering the range and tests
    /// `Varnode::readonly`; mosura tests the ranges the loader marked non-writable.
    pub fn is_read_only(&self, addr: u64, size: u32) -> bool {
        let end = addr.saturating_add(size.max(1) as u64 - 1);
        self.readonly_ranges.iter().any(|&(s, e)| s <= addr && end <= e)
    }

    /// Is `addr` inside a loaded image chunk? The mosura analog of Ghidra's global-scope
    /// `queryContainer` hit — the application's database resolves a symbol for any address
    /// inside a loaded memory block (which is why `&DAT_...` references exist for addresses no
    /// one named), so `ActionConstantPtr`'s symbol query grounds on the image itself. `image`
    /// is populated by both entry paths (the fixture loader and the analysis boundary).
    pub fn is_loaded(&self, addr: u64) -> bool {
        self.image.iter().any(|(s, b)| *s <= addr && addr < s + b.len() as u64)
    }

    /// The recovered stack symbols, computed once and cached (see [`Self::stack_syms_cache`]).
    pub fn stack_syms(&mut self) -> &[super::varmap::StackSymbol] {
        if self.stack_syms_cache.is_none() {
            self.stack_syms_cache = Some(super::varmap::recover_scope(self));
        }
        self.stack_syms_cache.as_deref().unwrap()
    }

    /// Drop the cached scope — the local layout has changed.
    pub fn invalidate_stack_syms(&mut self) {
        self.stack_syms_cache = None;
    }

    /// Ghidra `FuncCallSpecs::isInputActive` (fspec.hh:1699): is this call still recovering its
    /// input parameters? The container may outlive the recovery — see
    /// [`ParamActive::active`](super::fspec::ParamActive::active).
    pub fn is_input_active(&self, call: OpId) -> bool {
        self.active_inputs.get(&call).is_some_and(|a| a.active)
    }

    /// Re-open a call's input recovery, keeping the trials it already has.
    ///
    /// This is the repair for the call-recovery ORDERING defect (`docs/byte-exact-status.md`, open
    /// thread 1). `ActionResolveCalls` (arguments) is a mainloop member while `ActionActiveReturn`
    /// (call outputs) is in the fullloop tail, so a call's arguments commit while the PRECEDING
    /// call still has no output — and an argument that should be that call's result resolves to a
    /// varnode that is linked but UNWRITTEN, so it prints as a constant and the caller emits an
    /// instruction (`XOR EAX,EAX`) to produce a value the original passed implicitly.
    ///
    /// Ghidra survives this because its fullloop runs another round and the trials are still there.
    /// Re-opening is that same shape, and it is why the trials must not be destroyed on commit.
    /// Bounded to one re-open per call by `reopened_inputs`, so it cannot cycle.
    pub fn reopen_input(&mut self, call: OpId) -> bool {
        if !self.reopened_inputs.insert(call) {
            return false; // already given its second round
        }
        match self.active_inputs.get_mut(&call) {
            Some(a) => {
                a.active = true;
                true
            }
            None => false,
        }
    }

    /// Ghidra `Funcdata::hasUnreachableBlocks` (funcdata.hh:149).
    pub fn has_unreachable_blocks(&self) -> bool {
        self.blocks_unreachable
    }

    /// Ghidra `FuncProto::setReturnBytesConsumed` (fspec.cc:3954): record that callers consume only
    /// `val` bytes of the return value. **Only ever shrinks** — a value of 0, or one no smaller than
    /// what is already recorded, is discarded — and returns whether anything changed, so a rule can
    /// count it as progress.
    pub fn set_return_bytes_consumed(&mut self, val: u32) -> bool {
        if val == 0 {
            return false;
        }
        if self.return_bytes_consumed == 0 || val < self.return_bytes_consumed {
            self.return_bytes_consumed = val;
            return true;
        }
        false
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
    /// Ghidra `Funcdata::structureReset` (funcdata_block.cc:704): any change to the CFG
    /// invalidates the structured hierarchy. (Ghidra also re-derives loop structure and forward
    /// dominators here; mosura derives both inside the next `structure()` build, so clearing the
    /// cache is the whole equivalent.)
    pub fn structure_reset(&mut self) {
        self.structure = None;
    }

    pub fn set_blocks(&mut self, blocks: Vec<BlockBasic>) {
        self.structure_reset();
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
    ///
    /// Ghidra's UNIQUENESS guarantee (`Funcdata::setInputVarnode`, funcdata_varnode.cc): a request
    /// for storage an input already covers returns THAT input rather than making a second one.
    /// Without it one register ends up with two function inputs — FUN_000100b9 had
    /// `register+0x4/4` and `register+0xc/4` twice each. One of a pair becomes a parameter; the
    /// other has no parameter slot, so printc names it `xVar1`, declares it with no assignment (an
    /// input has no defining op) and it is passed as a spurious call argument. 603 emitted TUs
    /// carry such a local and none are byte-clean.
    pub fn new_input(&mut self, size: u32, loc: Address) -> VarnodeId {
        for i in 0..self.varnodes.len() {
            let o = &self.varnodes[i];
            if o.flags & flags::INPUT != 0 && o.loc == loc && o.size == size {
                return VarnodeId(i as u32);
            }
        }
        let vid = self.alloc_varnode(size, loc, flags::INPUT | flags::INSERT);
        self.apply_input_effect(vid);
        vid
    }

    /// A constant varnode (`const` space).
    ///
    /// Like Ghidra's `Funcdata::newConstant` (funcdata_varnode.cc:66) this does NOT mask `value` to
    /// `size` — Ghidra's callers mask, because the fold's own behaviour defines the width
    /// (`OpBehaviorIntMult::evaluateBinary` is `(in1*in2) & calc_mask(sizeout)`, opbehavior.cc:495).
    /// A caller that forgets produces a constant varnode whose value cannot fit its own size, which
    /// is an IR invariant violation and renders as a nonsense literal. `MOSURA_CONSTCHECK=1` reports
    /// every such creation with a backtrace-able message; it is inert otherwise.
    pub fn new_const(&mut self, size: u32, value: u64) -> VarnodeId {
        if size < 8 && value > (1u64 << (size * 8)) - 1 && Self::const_check_enabled() {
            // Name the FUNCTION, not just the value: a bare total cannot say how many functions a
            // class reaches, and per-function reach is the unit every gate here is quoted in.
            eprintln!("CONSTCHECK\t{}\t{value:#x}\t{size}", self.name);
        }
        let loc = Address::new(self.spaces.constant(), value);
        self.alloc_varnode(size, loc, flags::CONSTANT)
    }

    /// Whether `MOSURA_CONSTCHECK` selects the oversized-constant invariant check (cached once).
    fn const_check_enabled() -> bool {
        static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ON.get_or_init(|| std::env::var_os("MOSURA_CONSTCHECK").is_some())
    }

    /// Ghidra `Funcdata::spacebaseConstant` (funcdata.cc:358): rewrite the constant read by
    /// `op` at `slot` into `PTRSUB(<ram-spacebase constant>, #offset)` — the IR form of "the
    /// address of a global" that `ActionConstantPtr` produces, `RulePtrArith` folds, and printc
    /// renders off the global's name.
    ///
    /// Translation notes, each a deliberate reduction of Ghidra's general form:
    /// * `extra` (offset from the symbol entry's start) is always 0 here because the synthesized
    ///   query entry sits exactly at `rampoint` — the INT_ADD arm (funcdata.cc:420) is therefore
    ///   unreachable and not ported until a real global symbol table exists.
    /// * Ghidra's COPY special case REUSES the copy op as the final op of the calculation
    ///   (funcdata.cc:375-388, via `insertInput`); mosura takes the general insert-before path
    ///   for COPY too — the leftover `COPY(ptrsub_out)` collapses to the identical graph via
    ///   `RulePropagateCopy` in the next pool pass.
    /// * `wordsize` is 1 on every mosura target, so the `byteToAddress` conversions are identity.
    pub fn spacebase_constant(
        &mut self,
        op: OpId,
        slot: usize,
        rampoint: u64,
        origval: u64,
        origsize: u32,
        ram: SpaceId,
    ) {
        let sz = self.spaces.get(ram).addr_size;
        let sb_type = super::types::Datatype::Pointer(
            sz,
            Box::new(super::types::Datatype::Spacebase(ram)),
        );
        let sb_vn = self.new_const(sz, 0);
        self.vn_mut(sb_vn).ty = Some(sb_type);
        // Ghidra: `updateType(sb_type, true, true)` — the LOCK is load-bearing, not decoration.
        // Unlocked, the next ActionInferTypes pass rederives the constant's type from its op
        // context, the pointer evaporates, RulePtraddUndo/RulePtrsubUndo see a non-pointer base
        // and dismantle the whole transform back to a (reassociated) INT_ADD — the do/undo cycle
        // recorded in docs/coverage.md's ActionConstantPtr row. Locked, `getLocalType` keeps the
        // Pointer(Spacebase) seed each pass, the PTRSUB output derives Pointer(Unknown(1)) via
        // the spacebase getSubType arm, and both undo guards decline — Ghidra's chain, verified
        // against the app oracle on FUN_00025e90 with a data block (`(&UNK_000804ba)[...]`).
        self.vn_mut(sb_vn).set_typelock();
        self.vn_mut(sb_vn).set_spacebase();
        let newconst = self.new_const(sz, origval);
        self.vn_mut(newconst).set_ptr_check();
        let addop = self.new_op_before_sized(op, super::opcode::OpCode::Ptrsub, vec![sb_vn, newconst], sz);
        let mut outvn = self.op(addop).output.expect("ptrsub output");
        // `getTypePointerStripArray(sz, entrytype, wordsize)` with the synthesized entry's
        // TYPE_UNKNOWN: a pointer to unknown, unlocked.
        self.vn_mut(outvn).ty = Some(super::types::Datatype::Pointer(
            sz,
            Box::new(super::types::Datatype::Unknown(1)),
        ));
        let _ = rampoint; // == origval while `extra` is structurally 0 (see the note above)
        if sz < origsize {
            let z = self.new_op_before_sized(op, super::opcode::OpCode::IntZext, vec![outvn], origsize);
            outvn = self.op(z).output.expect("zext output");
        } else if origsize < sz {
            let c = self.new_const(4, 0);
            let sub = self.new_op_before_sized(op, super::opcode::OpCode::Subpiece, vec![outvn, c], origsize);
            outvn = self.op(sub).output.expect("subpiece output");
        }
        self.op_set_input(op, slot, outvn);
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

    /// Ghidra `Funcdata::adjustInputVarnodes` (funcdata_varnode.cc:494): replace every function
    /// input intersecting `[addr, addr+sz)` with a single new input covering the whole range, each
    /// old input becoming a `SUBPIECE` of it at its justified offset.
    ///
    /// This is what [`super::pipeline::ActionUnjustifiedParams`] uses to widen an input that the
    /// calling convention says is improperly justified inside its parameter container: rather than
    /// leaving a varnode that starts partway into a parameter's storage, the whole container
    /// becomes the input and the original is carved back out of it.
    ///
    /// Panics where Ghidra throws `LowlevelError`: an intersecting input that runs past the end of
    /// the range, or one that is not properly contained, means the caller computed a bad container.
    pub fn adjust_input_varnodes(&mut self, addr: Address, sz: u32) {
        let endoff = addr.offset + (sz as u64 - 1);
        let mut inlist: Vec<VarnodeId> = (0..self.varnodes.len() as u32)
            .map(VarnodeId)
            .filter(|&v| {
                let vn = self.vn(v);
                vn.is_input()
                    && vn.loc.space == addr.space
                    && vn.loc.offset >= addr.offset
                    && vn.loc.offset <= endoff
            })
            .collect();
        // Ghidra walks the def-ordered set, which for one address range is create order.
        inlist.sort_by_key(|&v| (self.vn(v).loc.offset, self.vn(v).create_index));
        for &v in &inlist {
            let vn = self.vn(v);
            assert!(
                vn.loc.offset + (vn.size as u64 - 1) <= endoff,
                "cannot properly adjust input varnodes"
            );
        }
        let entry = self.addr;
        for i in 0..inlist.len() {
            let v = inlist[i];
            let (vloc, vsize) = (self.vn(v).loc, self.vn(v).size);
            // Ghidra: `addr.justifiedContain(sz, vn->getAddr(), vn->getSize(), false)` — the
            // little-endian offset of the old input inside the new container.
            assert!(
                self.vn(v).is_input() && sz > vsize && vloc.offset >= addr.offset,
                "bad adjustment to input varnode"
            );
            let sa = vloc.offset - addr.offset;
            let uniq = self.num_ops() as u32;
            let k = self.new_const(4, sa);
            let subop = self.new_op(
                super::opcode::OpCode::Subpiece,
                super::op::SeqNum { pc: entry, uniq },
                vec![k, k], // input 0 is patched to the new input below
            );
            self.op_set_input(subop, 1, k);
            let newvn = self.new_output(subop, vsize, vloc);
            // `newvn` must not be free, so the block insert happens before the replacement.
            self.op_insert_begin(subop, super::block::BlockId(0));
            self.total_replace(v, newvn);
            self.delete_varnode(v); // get rid of the old input before creating the new one
            inlist[i] = newvn;
        }
        // With every intersecting input pulled out, the new one covering the range can be made.
        let invn = self.new_varnode(sz, addr);
        let invn = self.set_input_varnode(invn);
        // A new input may cause new heritage and "Heritage AFTER dead removal" errors, so heritage
        // is told to ignore it (Ghidra sets the write mask for exactly this reason).
        self.vn_mut(invn).set_write_mask();
        for &v in &inlist {
            let op = self.vn(v).def.expect("just built as a SUBPIECE output");
            self.op_set_input(op, 0, invn);
        }
    }

    /// Ghidra `CloneBlockOps::cloneBlock` (funcdata_block.cc:1004) together with `buildOpClone`
    /// (:951), `buildVarnodeOutput` (:981) and `patchInputs` (:1047): copy every p-code op of `b`
    /// into `bprime`, rewiring the clones to read each other and splitting the MULTIEQUALs.
    ///
    /// The MULTIEQUAL handling is the point of the exercise: `bprime` now takes exactly one of
    /// `b`'s in-edges, so each cloned phi collapses to a COPY of that edge's input, and the
    /// original phi loses that input (itself collapsing to a COPY if only one is left).
    ///
    /// Panics where Ghidra throws: a 2-way/n-way branch, an INDIRECT, a CALL, or a free input
    /// cannot be cloned. `ActionReturnSplit::isSplittable` has already excluded all of them.
    ///
    /// Flag copying is the intersection of Ghidra's lists with what mosura models. Ghidra carries
    /// `nocollapse/startmark/nonprinting/halt/badinstruction/unimplemented/noreturn/missing/
    /// calculated_bool/ptrflow` on ops and `special_prop/special_print/incidental_copy/
    /// is_cpool_transformed/stop_type_propagation/store_unmapped` as op addlflags; mosura has no
    /// counterpart for those, so they are simply absent rather than approximated.
    pub fn clone_block_ops(&mut self, b: super::block::BlockId, bprime: super::block::BlockId, inedge: usize) {
        self.structure_reset();
        use super::op::flags as opf;
        use super::varnode::flags as vnf;
        const OP_KEEP: u32 = opf::STARTBASIC | opf::NO_INDIRECT_COLLAPSE | opf::INDIRECT_STORE;
        const VN_KEEP: u32 = vnf::EXTERNREF
            | vnf::VOLATILE
            | vnf::INCIDENTAL_COPY
            | vnf::READONLY
            | vnf::PERSIST
            | vnf::ADDRTIED
            | vnf::ADDRFORCE
            | vnf::NOLOCALALIAS
            | vnf::SPACEBASE
            | vnf::INDIRECT_CREATION
            | vnf::RETURN_ADDRESS
            | vnf::PRECISLO
            | vnf::PRECISHI;

        let mut clone_list: Vec<(OpId, OpId)> = Vec::new(); // (clone, orig)
        let mut orig_to_clone: std::collections::HashMap<OpId, OpId> = std::collections::HashMap::new();
        for orig in self.blocks[b.0 as usize].ops.clone() {
            if self.op(orig).code().is_branch() {
                assert_eq!(
                    self.op(orig).code(),
                    OpCode::Branch,
                    "cannot duplicate a 2-way or n-way branch in nodesplit"
                );
                continue;
            }
            let (pc, code, nin) =
                (self.op(orig).seqnum.pc, self.op(orig).code(), self.op(orig).num_inputs());
            let uniq = self.num_ops() as u32;
            // Inputs are patched below; seed the clone with the original's so the arity matches.
            let seed: Vec<VarnodeId> =
                (0..nin).map(|i| self.op(orig).input(i).expect("input")).collect();
            let dup = self.new_op(code, super::op::SeqNum { pc, uniq }, seed);
            let fl = self.op(orig).flags & OP_KEEP;
            self.op_mut(dup).flags |= fl;
            if let Some(opvn) = self.op(orig).output {
                let (size, loc, vflags, addl) = (
                    self.vn(opvn).size,
                    self.vn(opvn).loc,
                    self.vn(opvn).flags & VN_KEEP,
                    self.vn(opvn).addlflags & super::varnode::addlflags::WRITEMASK,
                );
                let newvn = self.new_output(dup, size, loc);
                self.vn_mut(newvn).flags |= vflags;
                self.vn_mut(newvn).addlflags |= addl;
            }
            clone_list.push((dup, orig));
            orig_to_clone.insert(orig, dup);
            self.op_insert_end(dup, bprime);
        }
        // patchInputs (funcdata_block.cc:1047)
        for &(clone_op, orig) in &clone_list {
            if self.op(orig).code() == OpCode::Multiequal {
                let pick = self.op(orig).input(inedge).expect("phi input per in-edge");
                // One edge now goes into the new block, so the clone is a COPY of that input.
                while self.op(clone_op).num_inputs() > 1 {
                    self.op_remove_input(clone_op, 1);
                }
                self.op_set_opcode(clone_op, OpCode::Copy);
                self.op_set_input(clone_op, 0, pick);
                // One edge is removed from the original block.
                self.op_remove_input(orig, inedge);
                if self.op(orig).num_inputs() == 1 {
                    self.op_set_opcode(orig, OpCode::Copy);
                }
                continue;
            }
            assert!(self.op(orig).code() != OpCode::Indirect, "can't clone INDIRECTs");
            assert!(!self.op(orig).is_call(), "can't clone CALLs");
            for i in 0..self.op(clone_op).num_inputs() {
                let orig_vn = self.op(orig).input(i).expect("input");
                let clone_vn = if self.vn(orig_vn).is_constant() {
                    orig_vn
                } else if self.vn(orig_vn).is_annotation() {
                    let m = self.vn(orig_vn).loc;
                    self.new_code_ref(m)
                } else {
                    assert!(!self.vn(orig_vn).is_free(), "can't clone a free varnode");
                    match self.vn(orig_vn).def.and_then(|d| orig_to_clone.get(&d).copied()) {
                        Some(c) => self.op(c).output.expect("cloned op has an output"),
                        None => orig_vn,
                    }
                };
                self.op_set_input(clone_op, i, clone_vn);
            }
        }
    }

    /// Ghidra `Funcdata::nodeSplitBlockEdge` (funcdata_block.cc:824) + `nodeSplit` (:845): split
    /// control flow into `b`, duplicating its p-code into a new block that takes over the given
    /// in-edge.
    ///
    /// Panics where Ghidra throws: the block must have no out-flow (Ghidra's own comment notes the
    /// general out-edge case is unimplemented, since it would need MULTIEQUALs in the out-blocks),
    /// must have more than one in-edge, and must have no duplicate in-edges.
    pub fn node_split(&mut self, b: super::block::BlockId, inedge: usize) {
        self.structure_reset();
        assert!(
            self.blocks[b.0 as usize].out_edges.is_empty(),
            "cannot (currently) nodesplit a block with out flow"
        );
        assert!(
            self.blocks[b.0 as usize].in_edges.len() > 1,
            "cannot nodesplit a block with only 1 in edge"
        );
        {
            let ins = &self.blocks[b.0 as usize].in_edges;
            let mut seen = std::collections::HashSet::new();
            assert!(
                ins.iter().all(|e| seen.insert(*e)),
                "cannot nodesplit a block with redundant in edges"
            );
        }
        // nodeSplitBlockEdge: a duplicate block takes over the one in-edge, inheriting b's outs
        // (of which there are none here).
        let a = self.blocks[b.0 as usize].in_edges[inedge];
        let bprime = self.new_block_basic();
        let a_out = self.blocks[a.0 as usize]
            .out_edges
            .iter()
            .position(|&x| x == b)
            .expect("edge is reciprocal");
        self.blocks[a.0 as usize].out_edges[a_out] = bprime;
        self.blocks[b.0 as usize].in_edges.remove(inedge);
        self.blocks[bprime.0 as usize].in_edges.push(a);
        self.clone_block_ops(b, bprime, inedge);
    }

    /// Ghidra `BlockGraph::removeEdge` (block.cc): drop the edge `from` -> `to` from both sides.
    pub fn remove_edge(&mut self, from: super::block::BlockId, to: super::block::BlockId) {
        self.structure_reset();
        let oi = self.blocks[from.0 as usize]
            .out_edges
            .iter()
            .position(|&b| b == to)
            .expect("edge exists");
        let ii = self.blocks[to.0 as usize]
            .in_edges
            .iter()
            .position(|&b| b == from)
            .expect("edge is reciprocal");
        self.blocks[from.0 as usize].out_edges.remove(oi);
        self.blocks[to.0 as usize].in_edges.remove(ii);
    }

    /// Ghidra `BlockGraph::moveOutEdge` (block.cc:1502) via `FlowBlock::replaceInEdge`
    /// (block.cc:160): re-source `blold`'s out-edge at `slot` so it leaves `blnew` instead.
    ///
    /// The target's IN-edge index is preserved and the edge is appended to `blnew`'s out list.
    /// Preserving the in-index is the load-bearing part: it keeps the target's MULTIEQUAL input
    /// slots lined up with their incoming edges across the surgery.
    pub fn move_out_edge(&mut self, blold: super::block::BlockId, slot: usize, blnew: super::block::BlockId) {
        self.structure_reset();
        let outbl = self.blocks[blold.0 as usize].out_edges[slot];
        let i = self.blocks[outbl.0 as usize]
            .in_edges
            .iter()
            .position(|&b| b == blold)
            .expect("edge is reciprocal");
        self.blocks[blold.0 as usize].out_edges.remove(slot);
        self.blocks[outbl.0 as usize].in_edges[i] = blnew;
        self.blocks[blnew.0 as usize].out_edges.push(outbl);
    }

    /// Ghidra `BlockGraph::addEdge` (block.cc): append a new edge `from` -> `to`.
    pub fn add_edge(&mut self, from: super::block::BlockId, to: super::block::BlockId) {
        self.structure_reset();
        self.blocks[from.0 as usize].out_edges.push(to);
        self.blocks[to.0 as usize].in_edges.push(from);
    }

    /// Ghidra `BlockGraph::newBlockBasic` (block.cc): append an empty basic block.
    pub fn new_block_basic(&mut self) -> super::block::BlockId {
        self.structure_reset();
        self.blocks.push(super::block::BlockBasic::default());
        super::block::BlockId(self.blocks.len() as u32 - 1)
    }

    /// Ghidra `Funcdata::nodeJoinCreateBlock` (funcdata_block.cc:779): build the new joined
    /// condition block for [`super::blockjoin::ConditionalJoin`].
    ///
    /// Two of the four original edges into `exita`/`exitb` are deleted — for each exit, the one
    /// from whichever side holds the HIGHER in-index, so the surviving edge keeps the lower index
    /// and the caller's recorded slots stay valid. The two survivors are re-sourced onto the new
    /// block, and `block1`/`block2` both gain an edge into it.
    pub fn node_join_create_block(
        &mut self,
        block1: super::block::BlockId,
        block2: super::block::BlockId,
        exita: super::block::BlockId,
        exitb: super::block::BlockId,
        fora_block1ishigh: bool,
        forb_block1ishigh: bool,
    ) -> super::block::BlockId {
        self.structure_reset();
        let newblock = self.new_block_basic();
        let swapa = if fora_block1ishigh {
            self.remove_edge(block1, exita);
            block2
        } else {
            self.remove_edge(block2, exita);
            block1
        };
        let swapb = if forb_block1ishigh {
            self.remove_edge(block1, exitb);
            block2
        } else {
            self.remove_edge(block2, exitb);
            block1
        };
        let sa = self.blocks[swapa.0 as usize]
            .out_edges
            .iter()
            .position(|&b| b == exita)
            .expect("surviving edge to exita");
        self.move_out_edge(swapa, sa, newblock);
        let sb = self.blocks[swapb.0 as usize]
            .out_edges
            .iter()
            .position(|&b| b == exitb)
            .expect("surviving edge to exitb");
        self.move_out_edge(swapb, sb, newblock);
        self.add_edge(block1, newblock);
        self.add_edge(block2, newblock);
        newblock
    }

    /// Ghidra `FlowBlock::replaceEdgesThru` (block.cc:198): splice in-edge `in` of `bl` directly
    /// onto out-edge `out`, then drop both from `bl`.
    ///
    /// The neighbours keep their edge SLOT positions — the predecessor's out-slot that pointed at
    /// `bl` now points at the successor, and the successor's in-slot that pointed at `bl` now
    /// points at the predecessor. That matters: an out-slot's index is what distinguishes a
    /// CBRANCH's false branch (0) from its true branch (1).
    ///
    /// Ghidra stores each edge's `reverse_index` explicitly; mosura derives it by searching the
    /// neighbour's list, the same way `block_remove_internal_preserving` and `branch_remove_internal`
    /// already do.
    pub fn replace_edges_thru(&mut self, bl: super::block::BlockId, inslot: usize, outslot: usize) {
        self.structure_reset();
        let inb = self.blocks[bl.0 as usize].in_edges[inslot];
        let outb = self.blocks[bl.0 as usize].out_edges[outslot];
        let inblock_outslot = self.blocks[inb.0 as usize]
            .out_edges
            .iter()
            .position(|&b| b == bl)
            .expect("predecessor lists bl as an out-edge");
        let outblock_inslot = self.blocks[outb.0 as usize]
            .in_edges
            .iter()
            .position(|&b| b == bl)
            .expect("successor lists bl as an in-edge");
        self.blocks[inb.0 as usize].out_edges[inblock_outslot] = outb;
        self.blocks[outb.0 as usize].in_edges[outblock_inslot] = inb;
        self.blocks[bl.0 as usize].in_edges.remove(inslot);
        self.blocks[bl.0 as usize].out_edges.remove(outslot);
    }

    /// Ghidra `BlockGraph::removeFromFlowSplit` (block.cc:1575) as reached through
    /// `Funcdata::removeFromFlowSplit` (funcdata_block.cc:882): remove a 2-in/2-out block, routing
    /// each input directly to one output. With `flipflow`, In(0) goes to Out(1) and In(1) to Out(0);
    /// otherwise In(0)→Out(0) and In(1)→Out(1).
    ///
    /// This is what [`super::condexe::ActionConditionalExe`] uses to delete the unnecessary
    /// control-flow join once the data flow through it has been reproduced. Ghidra follows it with
    /// `structureReset()`; mosura rebuilds the structured graph from scratch in `structure.rs`
    /// rather than caching it, so there is nothing to invalidate.
    pub fn remove_from_flow_split(&mut self, bl: super::block::BlockId, flipflow: bool) {
        self.structure_reset();
        // The order matters: each call deletes one in-edge and one out-edge, so the second call's
        // (0,0) names whichever pair is left.
        if flipflow {
            self.replace_edges_thru(bl, 0, 1);
        } else {
            self.replace_edges_thru(bl, 1, 1);
        }
        self.replace_edges_thru(bl, 0, 0);
    }

    /// Ghidra `Funcdata::totalReplaceConstant` (funcdata_varnode.cc:1496): make every read of
    /// `vn` read the constant `val` instead.
    ///
    /// A marker op (MULTIEQUAL/INDIRECT) must not take a constant directly, so those reads go
    /// through a single shared COPY of the constant — placed after `vn`'s defining op, or at the
    /// start of the entry block when `vn` is not written.
    pub fn total_replace_constant(&mut self, vn: VarnodeId, val: u64) {
        let size = self.vn(vn).size;
        let mut copyout: Option<VarnodeId> = None;
        for op in self.vn(vn).descend.clone() {
            let Some(slot) = self.op(op).inrefs.iter().position(|&v| v == vn) else { continue };
            let newrep = if self.op(op).is_marker() {
                match copyout {
                    Some(v) => v,
                    None => {
                        let k = self.new_const(size, val);
                        let v = match self.vn(vn).def {
                            Some(def) => {
                                let pc = self.op(def).seqnum.pc;
                                let uniq = self.num_ops() as u32;
                                let cop = self.new_op(OpCode::Copy, SeqNum { pc, uniq }, vec![k]);
                                let out = self.new_output_unique(cop, size);
                                self.op_insert_after(cop, def);
                                out
                            }
                            None => {
                                let bb = super::block::BlockId(0);
                                let pc = self.addr;
                                let uniq = self.num_ops() as u32;
                                let cop = self.new_op(OpCode::Copy, SeqNum { pc, uniq }, vec![k]);
                                let out = self.new_output_unique(cop, size);
                                self.op_insert_begin(cop, bb);
                                out
                            }
                        };
                        copyout = Some(v);
                        v
                    }
                }
            } else {
                self.new_const(size, val)
            };
            self.op_set_input(op, slot, newrep);
        }
    }

    /// Write the deadcode-delay override into the space table, so `dead_removal_allowed` sees the
    /// delayed value after a restart. Ghidra reads the Override through
    /// `Heritage::getInfo`/`spc->getDeadcodeDelay()` rather than copying it, but the effect is the
    /// same and mosura's `HeritageInfo` is derived from the spaces.
    pub fn apply_deadcode_delay_override(&mut self) {
        for (&spc, &delay) in &self.deadcode_delay_override.clone() {
            self.spaces.set_deadcode_delay(spc, delay);
        }
    }

    /// Ghidra `Funcdata::startCleanUp` (funcdata.hh:186): stamp the varnode creation index at the
    /// start of the clean-up phase.
    pub fn start_clean_up(&mut self) {
        self.clean_up_index = self.create_index;
    }

    /// Ghidra `Funcdata::getCleanUpIndex` (funcdata.hh:187).
    pub fn clean_up_index(&self) -> u32 {
        self.clean_up_index
    }

    /// Ghidra `VarnodeBank::findCoveredInput` (varnode.cc:1485): the function input varnode that
    /// lies completely inside `[loc, loc+s)`. Ghidra range-queries the def-ordered set from `loc`
    /// to `loc+s` and returns the first input fully contained; if it exists it is unique.
    pub fn find_covered_input(&self, s: u32, loc: Address) -> Option<VarnodeId> {
        let end = loc.offset + s as u64 - 1;
        let mut hits: Vec<VarnodeId> = (0..self.varnodes.len() as u32)
            .map(VarnodeId)
            .filter(|&v| {
                let vn = self.vn(v);
                vn.is_input()
                    && vn.loc.space == loc.space
                    && vn.loc.offset >= loc.offset
                    && vn.loc.offset <= end
                    && vn.loc.offset + (vn.size as u64 - 1) <= end
            })
            .collect();
        hits.sort_by_key(|&v| (self.vn(v).loc.offset, self.vn(v).create_index));
        hits.first().copied()
    }

    /// Mark an existing free varnode as a function input (Ghidra's `setInputVarnode`, reduced to
    /// mosura's case): clear any `written`/`def` and set `INPUT | INSERT`. Returns the varnode.
    pub fn set_input_varnode(&mut self, vid: VarnodeId) -> VarnodeId {
        // Ghidra's UNIQUENESS guarantee (funcdata_varnode.cc): an input already marked is returned
        // unchanged, and a request for storage some other input already covers returns THAT input
        // rather than marking a second one —
        //     if (vn->isInput()) return vn;
        //     if (vn->getSize()==invn->getSize() && vn->getAddr()==invn->getAddr()) return invn;
        // mosura marked unconditionally, so one register could end up with TWO function inputs.
        // FUN_000100b9 has `register+0x4/4` and `register+0xc/4` twice each: one of each pair
        // becomes a parameter, and the OTHER has no parameter slot, so printc names it `xVar1`,
        // declares it with no assignment (an input has no defining op) and it is passed as a
        // spurious call argument. 603 emitted TUs carry such a local and none are byte-clean.
        {
            let v = &self.varnodes[vid.0 as usize];
            if v.flags & flags::INPUT != 0 {
                return vid;
            }
            let (loc, size) = (v.loc, v.size);
            for i in 0..self.varnodes.len() {
                let o = &self.varnodes[i];
                if i != vid.0 as usize
                    && o.flags & flags::INPUT != 0
                    && o.loc == loc
                    && o.size == size
                {
                    return VarnodeId(i as u32);
                }
            }
        }
        let v = &mut self.varnodes[vid.0 as usize];
        v.def = None;
        v.flags &= !flags::WRITTEN;
        v.flags |= flags::INPUT | flags::INSERT;
        self.apply_input_effect(vid);
        vid
    }

    /// Ghidra `Funcdata::setInputVarnode` (funcdata_varnode.cc:365-371): the convention's effect on
    /// an input's storage decides whether it is `unaffected` — a callee-saved register whose value
    /// flows through the function untouched — and whether it is the return address.
    ///     uint4 effecttype = funcp.hasEffect(vn->getAddr(),vn->getSize());
    ///     if (effecttype == EffectRecord::unaffected) vn->setUnaffected();
    ///     if (effecttype == EffectRecord::return_address) { setUnaffected(); setReturnAddress(); }
    /// mosura had the flag and its readers but NO setter anywhere, so `is_unaffected()` was false
    /// for every varnode in every function and `ActionRestrictLocal` could not recognise a single
    /// callee-save slot. Applied at BOTH input-creation entry points, since Ghidra funnels all of
    /// them through `setInputVarnode`.
    fn apply_input_effect(&mut self, vid: VarnodeId) {
        let (loc, size) = (self.varnodes[vid.0 as usize].loc, self.varnodes[vid.0 as usize].size);
        let effecttype = self.proto_model.has_effect(loc, size);
        if effecttype == super::fspec::effect::UNAFFECTED {
            self.varnodes[vid.0 as usize].flags |= flags::UNAFFECTED;
        }
        if effecttype == super::fspec::effect::RETURN_ADDRESS {
            self.varnodes[vid.0 as usize].flags |= flags::UNAFFECTED | flags::RETURN_ADDRESS;
        }
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

    /// Ghidra `Funcdata::opUndoPtradd` (funcdata_op.cc:579): convert a `CPUI_PTRADD` back into the
    /// equivalent `CPUI_INT_ADD`, inserting a `CPUI_INT_MULT` when the element size is not 1.
    ///
    /// A PTRADD is `base + index * elemsize` with the element size a constant in slot 2; an INT_ADD
    /// is plain `base + offset`. So undoing one must fold the scale back into the offset: a constant
    /// index multiplies out in place, a non-constant one gains a real INT_MULT op.
    ///
    /// `finalize` mirrors Ghidra's parameter — set by the `ActionSetCasts` refit (coreaction.cc:2745)
    /// because that action runs dead-last, after `ActionMarkImplied`, so any op created there must
    /// arrive already typed and already marked implied or it would render as a bare statement that
    /// nothing marked up. The rule call sites (ruleaction.cc:6925/7115) pass false and let the
    /// mainloop retype what they build; those two are not ported.
    pub fn op_undo_ptradd(&mut self, op: OpId, finalize: bool) {
        let mult_vn = self.op(op).input(2).expect("PTRADD has 3 inputs");
        let mult_size = self.vn(mult_vn).constant_value();
        self.op_remove_input(op, 2);
        self.op_set_opcode(op, OpCode::IntAdd);
        if mult_size == 1 {
            return; // no multiplier, we are done
        }
        let off_vn = self.op(op).input(1).expect("INT_ADD has 2 inputs");
        let off_size = self.vn(off_vn).size;
        if self.vn(off_vn).is_constant() {
            // Ghidra masks with `calc_mask(offVn->getSize())`: the fold's width is the offset's own
            // width, and an unmasked product is an oversized constant — the IR invariant
            // `new_const`'s `MOSURA_CONSTCHECK` exists to catch.
            let new_val = mult_size
                .wrapping_mul(self.vn(off_vn).constant_value())
                & super::nzmask::calc_mask(off_size);
            let new_off = self.new_const(off_size, new_val);
            if finalize {
                let ct = super::merge::high_type_read_facing(self, off_vn);
                self.vn_mut(new_off).update_type(ct);
            }
            self.op_set_input(op, 1, new_off);
            return;
        }
        let mult_op = self.new_op_before(op, OpCode::IntMult, vec![off_vn, mult_vn]);
        let add_vn = self.op(mult_op).output.expect("new_op_before gives an output");
        if finalize {
            let ct = self.vn(mult_vn).get_type();
            self.vn_mut(add_vn).update_type(ct);
            self.vn_mut(add_vn).flags |= flags::IMPLIED;
        }
        self.op_set_input(op, 1, add_vn);
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
        self.debug_mod_check(op); // Ghidra OPACTION_DEBUG site (funcdata_op.cc)
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
    pub(crate) fn lone_descend(&self, vn: VarnodeId) -> Option<OpId> {
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
        self.debug_mod_check(op); // Ghidra OPACTION_DEBUG site (funcdata_op.cc)
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
        self.debug_mod_check(op); // Ghidra OPACTION_DEBUG site (funcdata_op.cc)
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
        self.debug_mod_check(op); // Ghidra OPACTION_DEBUG site (funcdata_op.cc)
        self.ops[op.0 as usize].inrefs.swap(i, j);
    }

    /// Append an input to `op` (Ghidra's `opInsertInput` at the end), wiring descendants.
    pub fn op_append_input(&mut self, op: OpId, vid: VarnodeId) {
        self.ops[op.0 as usize].inrefs.push(vid);
        self.varnodes[vid.0 as usize].descend.push(op);
    }

    /// Replace `op`'s entire input list (Ghidra's `opSetAllInput`), fixing descendants.
    pub fn op_set_all_input(&mut self, op: OpId, inputs: &[VarnodeId]) {
        self.debug_mod_check(op); // Ghidra OPACTION_DEBUG site (funcdata_op.cc)
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
        self.debug_mod_check(op); // Ghidra OPACTION_DEBUG site (funcdata_op.cc)
        let vid = self.ops[op.0 as usize].inrefs.remove(slot);
        if let Some(pos) = self.varnodes[vid.0 as usize].descend.iter().position(|&o| o == op) {
            self.varnodes[vid.0 as usize].descend.remove(pos);
        }
    }

    /// Replace every use of `old` with `new` across all reading ops (Ghidra's
    /// `totalReplace`), maintaining descendant lists.
    /// Ghidra `ScopeLocal::markNotMapped` (varmap.cc): record that `[first, first+sz)` is not
    /// local-variable storage. Ghidra also removes any Symbol already built over the range; mosura
    /// builds Symbols fresh from the window on every `restructure`, so recording the hole is
    /// sufficient.
    pub fn mark_not_mapped(&mut self, spc: super::space::SpaceId, first: u64, sz: u32) {
        let highest = self.spaces.get(spc).highest();
        let last = first.wrapping_add(sz as u64).wrapping_sub(1);
        // "Do not allow the range to cover the split point between negative and positive stack
        // offsets" — a wrap, or running past the space, clamps to the top.
        let last = if last < first || last > highest { highest } else { last };
        self.not_mapped.insert_range(spc, first, last);
    }

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
    /// Ghidra `Funcdata::opDestroyRecursive` (funcdata_op.cc:398): destroy an op and, transitively,
    /// the ops defining inputs that only it read. An input's definition follows it down only when
    /// the input is written, is not `autolive` (address-tied storage that must survive), had this
    /// op as its LONE reader, and is not produced by a call or an INDIRECT source — those have
    /// effects beyond the value.
    ///
    /// Ghidra threads a caller-owned `scratch` vector purely to reuse the allocation; the worklist
    /// is local here.
    /// Ghidra `Funcdata::newCodeRef` (funcdata_varnode.cc:129): a size-1 annotation varnode holding
    /// a code address, typed `code`. It is the operand form a BRANCH/CBRANCH takes for a static
    /// target — mosura's CFG builder reads such an operand's `loc.offset` as the target address
    /// (`cfg::branch_target`), exactly as the SLEIGH lift produces it.
    pub fn new_code_ref(&mut self, m: Address) -> VarnodeId {
        let vn = self.alloc_varnode(1, m, super::varnode::flags::ANNOTATION);
        self.vn_mut(vn).ty = Some(super::types::Datatype::Code);
        vn
    }

    /// Ghidra `Funcdata::findJumpTable` (funcdata.cc:1024): the recovered jump table for this
    /// BRANCHIND, matched on the op's address as Ghidra matches on the op's address.
    pub fn find_jump_table(&self, op: OpId) -> Option<usize> {
        let addr = self.op(op).seqnum.pc.offset;
        self.jumptables.iter().position(|jt| jt.op_addr == addr)
    }

    /// Ghidra `Funcdata::removeJumpTable` (funcdata.cc:1053): forget a recovered jump table, so the
    /// BRANCHIND it described no longer structures as a switch.
    pub fn remove_jump_table(&mut self, idx: usize) {
        self.jumptables.remove(idx);
    }

    pub fn op_destroy_recursive(&mut self, op: OpId) {
        let mut worklist = vec![op];
        let mut pos = 0;
        while pos < worklist.len() {
            let cur = worklist[pos];
            pos += 1;
            for i in 0..self.op(cur).num_inputs() {
                let Some(vn) = self.op(cur).input(i) else { continue };
                if !self.vn(vn).is_written() || self.vn(vn).is_auto_live() {
                    continue;
                }
                if self.lone_descend(vn).is_none() {
                    continue;
                }
                let def_op = self.vn(vn).def.unwrap();
                if self.op(def_op).is_call() || self.op(def_op).is_indirect_source() {
                    continue;
                }
                worklist.push(def_op);
            }
            self.op_destroy(cur);
        }
    }

    pub fn op_destroy(&mut self, op: OpId) {
        self.debug_mod_check(op); // Ghidra OPACTION_DEBUG site (funcdata_op.cc)
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

    /// Ghidra `Funcdata::newSpacebasePtr` (funcdata.cc:275): a fresh (free) Varnode naming the
    /// register that points into the given spacebase space — RSP for the x86-64 `stack` space.
    /// Free, not the input version: the rules resolve it to whatever SSA value reaches this point,
    /// which is exactly how the placeholder measures the stack-pointer delta at a call site.
    pub fn new_spacebase_ptr(&mut self, space: super::space::SpaceId) -> Option<VarnodeId> {
        let &(reg, size) = self.spaces.get(space).spacebase.first()?;
        Some(self.new_varnode(size, reg))
    }

    /// Ghidra `Funcdata::createStackRef` (funcdata_op.cc:459): build `spacebase_ptr + off` as the
    /// address expression for a stack access, inserted before/after `op`. Ghidra's `SegmentOp`
    /// wrapping is omitted for the same reason `RuleLoadVarnode` omits its unwrapping — mosura's
    /// x86-64 lift emits no `CPUI_SEGMENTOP`; it re-enables faithfully with a segmented target.
    pub fn create_stack_ref(
        &mut self,
        space: super::space::SpaceId,
        off: u64,
        op: OpId,
        stackptr: Option<VarnodeId>,
        insertafter: bool,
    ) -> Option<VarnodeId> {
        let stackptr = match stackptr {
            Some(v) => v,
            None => self.new_spacebase_ptr(space)?,
        };
        let addrsize = self.vn(stackptr).size;
        let seq = self.op(op).seqnum;
        // Ghidra `AddrSpace::byteToAddress` (space.hh:169): the caller passes a BYTE offset, the
        // constant added to the spacebase register is in the space's addressable units. Identity on
        // every space mosura currently registers (all wordSize 1), but ported rather than assumed —
        // a word-addressed target would otherwise silently scale wrong.
        let ws = self.spaces.get(space).wordsize as u64;
        let off = if ws == 1 { off } else { off / ws };
        let cst = self.new_const(addrsize, off);
        let addop = self.new_op(OpCode::IntAdd, seq, vec![stackptr, cst]);
        let addout = self.new_output_unique(addop, addrsize);
        if insertafter {
            self.op_insert_after(addop, op);
        } else {
            self.op_insert_before(addop, op);
        }
        Some(addout)
    }

    /// Ghidra `Funcdata::opStackLoad` (funcdata_op.cc:541): a LOAD of `sz` bytes from `space + off`,
    /// expressed the way the lifter would (a LOAD off the spacebase's CONTAINER space), returning
    /// the loaded value. The LOAD goes immediately after the address computation regardless of
    /// `insertafter`, which Ghidra spells out.
    pub fn op_stack_load(
        &mut self,
        space: super::space::SpaceId,
        off: u64,
        sz: u32,
        op: OpId,
        stackref: Option<VarnodeId>,
        insertafter: bool,
    ) -> Option<VarnodeId> {
        let container = self.spaces.get(space).contain?;
        let addout = self.create_stack_ref(space, off, op, stackref, insertafter)?;
        let seq = self.op(op).seqnum;
        // Ghidra `newVarnodeSpace` (funcdata_varnode.cc:190): the LOAD's slot-0 annotation is the
        // data space's INDEX as a constant — the same encoding `check_spacebase` reads back out of
        // input(0). Width 8 is Ghidra's own `sizeof(spc)` (a host pointer), and it is what mosura's
        // lifter already emits for every LOAD/STORE space annotation (`build.rs:124`); matching it
        // keeps a manufactured LOAD indistinguishable from a lifted one.
        let spacevn = self.new_const(8, container.0 as u64);
        let loadop = self.new_op(OpCode::Load, seq, vec![spacevn, addout]);
        let res = self.new_output_unique(loadop, sz);
        let addop = self.vn(addout).def.expect("createStackRef defines addout");
        self.op_insert_after(loadop, addop);
        Some(res)
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
        self.debug_mod_check(op); // Ghidra OPACTION_DEBUG site (funcdata_op.cc)
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
        self.debug_mod_check(op); // Ghidra OPACTION_DEBUG site (funcdata_op.cc)
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
        let mut s = format!("{c}0x{:x}:{}", vn.loc.offset, vn.size);
        // Ghidra `Varnode::printRaw` (varnode.cc): after the storage, mark the varnode's role —
        // `(i)` for a function input, `(<seqnum>)` for a written value naming its DEFINING OP, and
        // `(free)` for one that is neither inserted in the SSA tree nor constant.
        //
        // The seqnum is the SSA VERSION and it is load-bearing for reading a dump: without it two
        // different definitions of the same storage render identically (two LOADs both printing
        // `u0x17200:4`), so "which definition feeds this op" is unreadable and a dump can be
        // misread into the opposite of the truth. That cost a real detour this campaign.
        if vn.is_input() {
            s.push_str("(i)");
        }
        if vn.is_written() {
            if let Some(def) = vn.def {
                let sq = self.ops[def.0 as usize].seqnum;
                let _ = write!(s, "(0x{:x}:{})", sq.pc.offset, sq.uniq);
            }
        }
        if vn.is_free() {
            s.push_str("(free)"); // Ghidra: `(flags & (insert|constant)) == 0`
        }
        s
    }

    /// Render the function's IR as a raw, block-less op listing (Ghidra's
    /// `Funcdata::printRaw` "Raw operations" mode). Deterministic; the per-phase oracle
    /// format is aligned to Ghidra's exactly in `tests/ir_parity.rs` (P0).
    pub fn print_raw(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "{}() raw operations:", self.name);
        // Render every op through [`op_str`] — Ghidra `PcodeOp::printDebug` (op.cc), which prints
        // `**` for an op that is dead or unparented.
        //
        // This dump lists the WHOLE ARENA, destroyed ops included. `op_destroy` clears an op's
        // inputs and output, so a destroyed op previously rendered as a BARE OPCODE — visually
        // identical to a live op that legitimately has no output (a STORE, a BRANCH). Counting
        // bare opcodes as survivors reads corpses as live values, which is exactly how an
        // investigation this campaign concluded the opposite of the truth about who was deleting
        // real calls. The `**` marker makes the distinction impossible to miss.
        for id in self.op_ids() {
            let _ = writeln!(s, "{}", self.op_str(id));
        }
        s
    }

    /// Render a single op as one line (`0x<addr>:<uniq>: out = OPCODE inputs`), the per-op form
    /// of [`print_raw`](Self::print_raw). Used by the rule-application trace (`MOSURA_TRACE`) to
    /// capture an op's before/after state; a dead op renders as `**` (Ghidra's `printDebug`).
    /// Ghidra's `OPACTION_DEBUG` selector (`Action::turnOnDebug`, action.hh:98). `MOSURA_OPACTION`
    /// unset ⇒ the whole facility is off and every hook below early-outs on a single bool.
    /// `MOSURA_OPACTION=1` (or empty) traces every action; any other value names the one action to
    /// trace, matched against [`Action::name`](super::action::Action::name).
    fn opaction_filter() -> Option<&'static str> {
        static F: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
        F.get_or_init(|| {
            // `MOSURA_TRACE=1` is the older spelling and selects everything — there is only one
            // facility now, so it is an alias for `MOSURA_OPACTION=1` rather than a second switch
            // covering rules only. scripts/trace-diff.sh sets both.
            std::env::var("MOSURA_OPACTION")
                .ok()
                .or_else(|| std::env::var("MOSURA_TRACE").ok().map(|_| "1".to_string()))
        })
        .as_deref()
    }

    /// Ghidra `Funcdata::debugActivate` (funcdata.hh:596) — begin recording op mutations, if this
    /// action is selected. Called by the action driver before `apply`.
    pub fn debug_activate(&mut self, actionname: &str) {
        // The alias probe runs a rule pool on a THROWAWAY CLONE of the function; its firings are not
        // pipeline history and must not appear in the trace (`with_suppressed_trace`).
        if super::action::trace_suppressed() {
            self.opactdbg_active = false;
            return;
        }
        self.opactdbg_active = match Self::opaction_filter() {
            None => false,
            Some("") | Some("1") => true,
            Some(sel) => sel == actionname,
        };
    }

    /// Ghidra `Funcdata::debugModCheck` (funcdata.cc) — cache the \e before state of `op` the FIRST
    /// time the running action touches it. Called from every op-mutation primitive, which is what
    /// makes this facility answer "who modified/destroyed this op?" for **actions**, not just rules:
    /// the rule-level trace ([`super::action`]) only sees the op a rule was applied to, so an action
    /// that destroys some *other* op — the case that cost this campaign a hand-rolled backtrace
    /// probe — is invisible to it and visible here.
    pub fn debug_mod_check(&mut self, op: OpId) {
        if !self.opactdbg_active {
            return; // the facility is off: one predictable branch, nothing else
        }
        if self.ops[op.0 as usize].flags & super::op::flags::MODIFIED != 0 {
            return; // already captured for this action
        }
        self.ops[op.0 as usize].flags |= super::op::flags::MODIFIED;
        let before = self.op_str(op);
        self.modify_list.push(op);
        self.modify_before.push(before);
    }

    /// Ghidra `Funcdata::debugModPrint` (funcdata.cc) — print the before/after pair for every op the
    /// named action modified, then stop recording. Format mirrors Ghidra's exactly, and the
    /// rule-level trace's, so one differ can read both.
    pub fn debug_mod_print(&mut self, actionname: &str) {
        if !self.opactdbg_active {
            return;
        }
        self.opactdbg_active = false;
        if self.modify_list.is_empty() {
            return;
        }
        let n = super::action::next_debug_seq();
        let mut s = format!("DEBUG {n}: {actionname}\n");
        for (i, &op) in self.modify_list.iter().enumerate() {
            let _ = writeln!(s, "{}", self.modify_before[i]);
            let _ = writeln!(s, "   {}", self.op_str(op));
        }
        for &op in &self.modify_list {
            self.ops[op.0 as usize].flags &= !super::op::flags::MODIFIED;
        }
        self.modify_list.clear();
        self.modify_before.clear();
        print!("{s}");
    }

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
