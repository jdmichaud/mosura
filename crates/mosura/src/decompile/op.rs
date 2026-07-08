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
    /// A heritage marker (MULTIEQUAL/INDIRECT) — placed by heritage, not real control flow.
    pub fn is_marker(&self) -> bool {
        matches!(self.opcode, OpCode::Multiequal | OpCode::Indirect)
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
