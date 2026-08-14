//! The p-code operation — a port of Ghidra's `PcodeOp` (`op.hh`/`op.cc`).
//!
//! A `PcodeOp` has an opcode, an ordered input list, at most one output, a parent block,
//! and a [`SeqNum`] identity (the instruction it came from). Inputs/output are
//! [`VarnodeId`]s into the `Funcdata` arena; the parent is a [`BlockId`].

use super::block::BlockId;
use super::opcode::OpCode;
use super::space::Address;
use super::varnode::VarnodeId;

/// A handle to a [`PcodeOp`] — an index into the `Funcdata` op arena.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct OpId(pub u32);

/// An op's identity (Ghidra's `SeqNum`): the instruction address it was lifted from plus
/// a one-up uniqueness/order counter. Prints as `pc:uniq`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SeqNum {
    pub pc: Address,
    pub uniq: u32,
}

/// Ghidra's `PcodeOp::pcode_flags` — the subset used so far. mosura assigns its own compact bit
/// values (they are internal, never serialized against Ghidra's), so these do not match Ghidra's
/// literal flag constants; the doc comment names the Ghidra flag each mirrors.
pub mod flags {
    pub const STARTBASIC: u32 = 0x1; // op starts a basic block
    pub const BRANCH: u32 = 0x2; // op is a branch
    pub const CALL: u32 = 0x4; // op is a call
    pub const RETURN: u32 = 0x8; // op is a return
    pub const DEAD: u32 = 0x10; // op is marked dead (pending removal)
    pub const MARKER: u32 = 0x20; // MULTIEQUAL/INDIRECT — a heritage marker, not real flow
    pub const MARK: u32 = 0x40; // transient traversal bit (Ghidra `PcodeOp::mark`)
    /// Ghidra `PcodeOp::boolean_flip` (op.hh:83): on a CBRANCH, the condition must be \e false to
    /// take the branch — the branch sense is inverted relative to the condition varnode.
    pub const BOOLEAN_FLIP: u32 = 0x80;
    /// Ghidra `PcodeOp::fallthru_true` (op.hh:84): on a CBRANCH, fall-through happens on the \e true
    /// condition (paired with `BOOLEAN_FLIP` to record how the structurer oriented the branch).
    pub const FALLTHRU_TRUE: u32 = 0x100;
    /// Ghidra `PcodeOp::return_copy` (op.hh:94): a "return form" COPY that holds a global (persistent)
    /// value to the end of the function — the COPY `Heritage::guardReturns` inserts before each RETURN
    /// for a persistent range (heritage.cc:1686, `markReturnCopy`). Its presence blocks
    /// `RulePropagateCopy` (ruleaction.cc:3933) so the COPY keeps reading the store version directly.
    pub const RETURN_COPY: u32 = 0x200;
    /// Ghidra `PcodeOp::indirect_source` (op.hh:85): this op is the *source* of one or more
    /// CPUI_INDIRECTs — some INDIRECT guards against its side effect, so removing it would strand
    /// that INDIRECT.
    ///
    /// The flag is **transient, recomputed from scratch on every dead-code pass**: Ghidra clears it
    /// on every alive op at the top of `ActionDeadCode::apply` (coreaction.cc:3965) and re-derives
    /// it while the consume sweep walks each INDIRECT's `iop` back to the causing op
    /// (coreaction.cc:3656/3661, mosura [`super::consume::indirect_source`]). It is never set by the
    /// code that *creates* an INDIRECT, and never carried forward across a pass — so it cannot go
    /// stale and wrongly keep a dead op alive. Read by `RuleEarlyRemoval` (ruleaction.cc:31) and by
    /// `Funcdata::opDestroyRecursive` (funcdata_op.cc:242, ported as
    /// [`Funcdata::op_destroy_recursive`](super::funcdata::Funcdata::op_destroy_recursive)).
    pub const INDIRECT_SOURCE: u32 = 0x400;
    /// Ghidra `PcodeOp::partialroot` (op.hh:99): this PIECE is the root of a CONCAT tree that
    /// `RulePieceStructure` has already visited, so it is not re-visited.
    pub const PARTIALROOT: u32 = 0x100000;

    /// Ghidra `PcodeOp::spacebase_ptr` (op.hh:101) — a LOAD/STORE through a *dynamic* pointer into a
    /// spacebase, marked by `Funcdata::opMarkSpacebasePtr` (funcdata.hh:487) from the
    /// `discoverIndexedStackPointers`/`LoadGuard` subsystem. mosura records no load guards (an
    /// already-documented omission, `heritage.rs:1392`/`varmap.rs:447`), so nothing sets this and
    /// `uses_spacebase_ptr` reads `false` — the same branch Ghidra takes with the flag unset.
    pub const SPACEBASE_PTR: u32 = 0x800;
    /// Ghidra `PcodeOp::no_indirect_collapse` (op.hh:224) — an INDIRECT on the data-flow path from a
    /// constant to a switch variable, protected from collapse by
    /// `ActionRestructureVarnode::protectSwitchPaths` (coreaction.cc:2245/2257). That protection is
    /// jumptable-recovery-time only and is not modelled (`pipeline.rs:342`), so nothing sets this.
    pub const NO_INDIRECT_COLLAPSE: u32 = 0x1000;
    /// Ghidra `PcodeOp::modified` (op.hh, an `additional_flags` bit) — transient bookkeeping for the
    /// `OPACTION_DEBUG` facility: this op's \e before state has already been captured for the action
    /// currently running, so the next mutation must not overwrite it. Set by
    /// `Funcdata::debug_mod_check`, cleared by `debug_mod_print`/`debug_mod_clear`. Never read by
    /// the pipeline.
    pub const MODIFIED: u32 = 0x2000;
    /// Ghidra `PcodeOp::indirect_store` (op.hh:106): this INDIRECT is caused by a STORE rather than
    /// by a call. Set by `Heritage::guardStores` (heritage.cc:1553) and read by
    /// `ActionLikelyTrash::traceTrash`, which follows such an INDIRECT's output instead of treating
    /// it as a trash sink.
    pub const INDIRECT_STORE: u32 = 0x4000;
}

/// A p-code operation. Created via [`Funcdata`](super::funcdata::Funcdata).
#[derive(Clone, Debug)]
pub struct PcodeOp {
    pub opcode: OpCode,
    pub flags: u32,
    /// Identity / source instruction.
    pub seqnum: SeqNum,
    /// Containing basic block, once the CFG is built.
    pub parent: Option<BlockId>,
    /// The output varnode, if any.
    pub output: Option<VarnodeId>,
    /// The ordered input varnodes.
    pub inrefs: Vec<VarnodeId>,
    /// For an INDIRECT, the op whose side effect caused it (a CALL/STORE) — Ghidra's `iop`
    /// annotation. Ghidra stores it as the INDIRECT's `input(1) = newVarnodeIop(indeffect)`
    /// (`funcdata_op.cc:newIndirectOp`), an annotation *varnode* whose value encodes the causing
    /// op; the varnode form exists for graph uniformity/serialization. mosura's arena carries the
    /// op reference directly in this field — the same representation-choice pattern as the
    /// branch-orientation flag (Ghidra edge-reversal → a persistent op flag). The semantic content
    /// is identical: "which op caused this INDIRECT". Read by the cover machinery, where an
    /// INDIRECT is positioned at its causing op (Ghidra `CoverBlock::getUIndex`, `cover.cc`).
    pub guarded_op: Option<OpId>,
}

impl PcodeOp {
    pub fn code(&self) -> OpCode {
        self.opcode
    }
    pub fn num_inputs(&self) -> usize {
        self.inrefs.len()
    }
    pub fn input(&self, slot: usize) -> Option<VarnodeId> {
        self.inrefs.get(slot).copied()
    }
    pub fn is_dead(&self) -> bool {
        self.flags & flags::DEAD != 0
    }
    /// The op whose side effect caused this INDIRECT (Ghidra's `iop`), if recorded. See
    /// [`guarded_op`](Self::guarded_op).
    pub fn guarded_op(&self) -> Option<OpId> {
        self.guarded_op
    }
    /// A heritage marker (MULTIEQUAL/INDIRECT) — placed by heritage, not real control flow.
    /// Ghidra `TypeOp::isArithmeticOp` (`addlflags & arithmetic_op`, typeop.cc): the op computes an
    /// arithmetic value, as opposed to a logical/bitwise one. The set is exactly the TypeOps whose
    /// constructor sets `arithmetic_op`.
    ///
    /// Read by the double-precision `attemptMarking` routines (double.cc), which use "is this value
    /// read arithmetically?" as the evidence that a concatenation is a genuine logical whole rather
    /// than two unrelated halves that happen to be adjacent.
    pub fn is_arithmetic_op(&self) -> bool {
        use OpCode::*;
        matches!(
            self.opcode,
            IntAdd
                | IntSub
                | IntCarry
                | IntScarry
                | IntSborrow
                | Int2comp
                | IntMult
                | IntDiv
                | IntSdiv
                | IntRem
                | IntSrem
                | Ptradd
                | Ptrsub
        )
    }

    /// Ghidra `TypeOp::isFloatingPointOp` (`addlflags & floatingpoint_op`, typeop.cc).
    pub fn is_floatingpoint_op(&self) -> bool {
        use OpCode::*;
        matches!(
            self.opcode,
            FloatEqual
                | FloatNotequal
                | FloatLess
                | FloatLessequal
                | FloatNan
                | FloatAdd
                | FloatDiv
                | FloatMult
                | FloatSub
                | FloatNeg
                | FloatAbs
                | FloatSqrt
                | FloatInt2float
                | FloatFloat2float
                | FloatTrunc
                | FloatCeil
                | FloatFloor
                | FloatRound
        )
    }

    /// Ghidra `(PcodeOp::getEvalType() & (PcodeOp::unary | PcodeOp::binary)) != 0` — the op is a
    /// plain unary or binary computation. The set is exactly the opcodes whose `TypeOp` constructor
    /// sets `PcodeOp::unary` or `PcodeOp::binary` (typeop.cc): note CAST is `unary|special` so it
    /// IS here, while PTRADD is `ternary` and MULTIEQUAL/INDIRECT/LOAD/STORE/CALL* are `special`
    /// only, so they are not.
    ///
    /// Read by `RulePiecePathology` (ruleaction.cc:10507), which requires the low half of a
    /// pathological concatenation to come from a real computation (or a call with a locked output).
    pub fn is_unary_or_binary(&self) -> bool {
        use OpCode::*;
        matches!(
            self.opcode,
            Copy | Cast
                | Ptrsub
                | IntEqual
                | IntNotequal
                | IntSless
                | IntSlessequal
                | IntLess
                | IntLessequal
                | IntZext
                | IntSext
                | IntAdd
                | IntSub
                | IntCarry
                | IntScarry
                | IntSborrow
                | Int2comp
                | IntNegate
                | IntXor
                | IntAnd
                | IntOr
                | IntLeft
                | IntRight
                | IntSright
                | IntMult
                | IntDiv
                | IntSdiv
                | IntRem
                | IntSrem
                | BoolNegate
                | BoolXor
                | BoolAnd
                | BoolOr
                | FloatEqual
                | FloatNotequal
                | FloatLess
                | FloatLessequal
                | FloatNan
                | FloatAdd
                | FloatDiv
                | FloatMult
                | FloatSub
                | FloatNeg
                | FloatAbs
                | FloatSqrt
                | FloatInt2float
                | FloatFloat2float
                | FloatTrunc
                | FloatCeil
                | FloatFloor
                | FloatRound
                | Piece
                | Subpiece
                | Popcount
                | Lzcount
        )
    }

    /// Ghidra `PcodeOp::getEvalType() == PcodeOp::special` (op.hh:379): the op is neither unary,
    /// binary nor ternary — it is one of the structural/special forms. The opcode set is exactly
    /// those whose `TypeOp` constructor sets `PcodeOp::special` WITHOUT also setting unary/binary
    /// (typeop.cc): note CAST is `unary|special`, so its eval type is not `special` and it is not
    /// in this set — Ghidra's test is an equality on the masked flags, not a bit test.
    ///
    /// Read by `RuleConditionalMove::gatherExpression` (ruleaction.cc:9307) to refuse to pull such
    /// an op out of a conditional branch.
    pub fn is_special_eval(&self) -> bool {
        use OpCode::*;
        matches!(
            self.opcode,
            Load | Store
                | Branch
                | Cbranch
                | Branchind
                | Call
                | Callind
                | Callother
                | Return
                | Multiequal
                | Indirect
                | Segmentop
                | Cpoolref
                | New
        )
    }
    /// Ghidra `PcodeOp::isPartialRoot` (op.hh:99).
    pub fn is_partial_root(&self) -> bool {
        self.flags & flags::PARTIALROOT != 0
    }
    /// Ghidra `PcodeOp::setPartialRoot`.
    pub fn set_partial_root(&mut self) {
        self.flags |= flags::PARTIALROOT;
    }
    pub fn is_marker(&self) -> bool {
        matches!(self.opcode, OpCode::Multiequal | OpCode::Indirect)
    }
    /// Ghidra `PcodeOp::isIndirectStore` (op.hh:180): is this INDIRECT caused by a STORE?
    pub fn is_indirect_store(&self) -> bool {
        self.flags & flags::INDIRECT_STORE != 0
    }
    /// Ghidra's `PcodeOp::indirect_store` set at `newIndirectOp` (heritage.cc:1553).
    pub fn set_indirect_store(&mut self) {
        self.flags |= flags::INDIRECT_STORE;
    }
    /// Ghidra `PcodeOp::isMark` — the transient traversal bit (see [`flags::MARK`]).
    pub fn is_mark(&self) -> bool {
        self.flags & flags::MARK != 0
    }
    /// Ghidra `PcodeOp::setMark`.
    pub fn set_mark(&mut self) {
        self.flags |= flags::MARK;
    }
    /// Ghidra `PcodeOp::clearMark`.
    pub fn clear_mark(&mut self) {
        self.flags &= !flags::MARK;
    }
    /// Ghidra `PcodeOp::isCall` — a CALL/CALLIND/CALLOTHER.
    pub fn is_call(&self) -> bool {
        matches!(self.opcode, OpCode::Call | OpCode::Callind | OpCode::Callother)
    }
    /// Ghidra `PcodeOp::isReturnCopy` (op.hh:222) — a global-holding return-form COPY (see
    /// [`flags::RETURN_COPY`]). Set on the `guardReturns` COPY via [`Self::mark_return_copy`].
    pub fn is_return_copy(&self) -> bool {
        self.flags & flags::RETURN_COPY != 0
    }
    /// Ghidra `Funcdata::markReturnCopy` (funcdata.hh:452) — mark a COPY as holding a global value
    /// to (past) the end of the function.
    pub fn mark_return_copy(&mut self) {
        self.flags |= flags::RETURN_COPY;
    }
    /// Ghidra `PcodeOp::isIndirectSource` (op.hh:202) — this op causes an INDIRECT (see
    /// [`flags::INDIRECT_SOURCE`]).
    pub fn is_indirect_source(&self) -> bool {
        self.flags & flags::INDIRECT_SOURCE != 0
    }
    /// Ghidra `PcodeOp::setIndirectSource` (op.hh:203).
    pub fn set_indirect_source(&mut self) {
        self.flags |= flags::INDIRECT_SOURCE;
    }
    /// Ghidra `PcodeOp::clearIndirectSource` (op.hh:204).
    pub fn clear_indirect_source(&mut self) {
        self.flags &= !flags::INDIRECT_SOURCE;
    }
    /// Ghidra `PcodeOp::usesSpacebasePtr` (op.hh:228) — see [`flags::SPACEBASE_PTR`].
    pub fn uses_spacebase_ptr(&self) -> bool {
        self.flags & flags::SPACEBASE_PTR != 0
    }
    /// Ghidra `PcodeOp::noIndirectCollapse` (op.hh:224) — see [`flags::NO_INDIRECT_COLLAPSE`].
    pub fn no_indirect_collapse(&self) -> bool {
        self.flags & flags::NO_INDIRECT_COLLAPSE != 0
    }
    /// Ghidra `PcodeOp::isBooleanFlip` (op.hh:191) — on a CBRANCH, the branch is taken when the
    /// condition is \e false (see [`flags::BOOLEAN_FLIP`]).
    pub fn is_boolean_flip(&self) -> bool {
        self.flags & flags::BOOLEAN_FLIP != 0
    }
    /// Ghidra `PcodeOp::isFallthruTrue` (op.hh:193) — on a CBRANCH, fall-through is taken when the
    /// condition is \e true (see [`flags::FALLTHRU_TRUE`]).
    pub fn is_fallthru_true(&self) -> bool {
        self.flags & flags::FALLTHRU_TRUE != 0
    }
    /// Ghidra `PcodeOp::isBoolOutput` — the op's output is a 1-bit boolean (the `booloutput`
    /// opflag). This is the same opcode set nzmask treats as boolean-result (`op_nzmask_local`).
    pub fn is_bool_output(&self) -> bool {
        use OpCode::*;
        matches!(
            self.opcode,
            IntEqual
                | IntNotequal
                | IntSless
                | IntSlessequal
                | IntLess
                | IntLessequal
                | IntCarry
                | IntScarry
                | IntSborrow
                | BoolNegate
                | BoolXor
                | BoolAnd
                | BoolOr
                | FloatEqual
                | FloatNotequal
                | FloatLess
                | FloatLessequal
                | FloatNan
        )
    }
}
