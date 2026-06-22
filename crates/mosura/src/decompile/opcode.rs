//! The p-code operation set — a faithful port of Ghidra's `OpCode` enum (`opcodes.hh`).
//! Discriminants are Ghidra's `CPUI_*` numbers (so `as u32` / [`from_u32`] round-trip
//! the lifter's raw opcodes). `45` is unused in Ghidra and absent here.

/// A p-code opcode (`CPUI_*`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u32)]
pub enum OpCode {
    Copy = 1,
    Load = 2,
    Store = 3,
    Branch = 4,
    Cbranch = 5,
    Branchind = 6,
    Call = 7,
    Callind = 8,
    Callother = 9,
    Return = 10,
    IntEqual = 11,
    IntNotequal = 12,
    IntSless = 13,
    IntSlessequal = 14,
    IntLess = 15,
    IntLessequal = 16,
    IntZext = 17,
    IntSext = 18,
    IntAdd = 19,
    IntSub = 20,
    IntCarry = 21,
    IntScarry = 22,
    IntSborrow = 23,
    Int2comp = 24,
    IntNegate = 25,
    IntXor = 26,
    IntAnd = 27,
    IntOr = 28,
    IntLeft = 29,
    IntRight = 30,
    IntSright = 31,
    IntMult = 32,
    IntDiv = 33,
    IntSdiv = 34,
    IntRem = 35,
    IntSrem = 36,
    BoolNegate = 37,
    BoolXor = 38,
    BoolAnd = 39,
    BoolOr = 40,
    FloatEqual = 41,
    FloatNotequal = 42,
    FloatLess = 43,
    FloatLessequal = 44,
    FloatNan = 46,
    FloatAdd = 47,
    FloatDiv = 48,
    FloatMult = 49,
    FloatSub = 50,
    FloatNeg = 51,
    FloatAbs = 52,
    FloatSqrt = 53,
    FloatInt2float = 54,
    FloatFloat2float = 55,
    FloatTrunc = 56,
    FloatCeil = 57,
    FloatFloor = 58,
    FloatRound = 59,
    Multiequal = 60,
    Indirect = 61,
    Piece = 62,
    Subpiece = 63,
    Cast = 64,
    Ptradd = 65,
    Ptrsub = 66,
    Segmentop = 67,
    Cpoolref = 68,
    New = 69,
    Insert = 70,
    Extract = 71,
    Popcount = 72,
    Lzcount = 73,
}

impl OpCode {
    /// The opcode for a raw lifter number, or `None` if unrecognized.
    pub fn from_u32(n: u32) -> Option<OpCode> {
        use OpCode::*;
        Some(match n {
            1 => Copy, 2 => Load, 3 => Store, 4 => Branch, 5 => Cbranch, 6 => Branchind,
            7 => Call, 8 => Callind, 9 => Callother, 10 => Return,
            11 => IntEqual, 12 => IntNotequal, 13 => IntSless, 14 => IntSlessequal,
            15 => IntLess, 16 => IntLessequal, 17 => IntZext, 18 => IntSext,
            19 => IntAdd, 20 => IntSub, 21 => IntCarry, 22 => IntScarry, 23 => IntSborrow,
            24 => Int2comp, 25 => IntNegate, 26 => IntXor, 27 => IntAnd, 28 => IntOr,
            29 => IntLeft, 30 => IntRight, 31 => IntSright, 32 => IntMult, 33 => IntDiv,
            34 => IntSdiv, 35 => IntRem, 36 => IntSrem,
            37 => BoolNegate, 38 => BoolXor, 39 => BoolAnd, 40 => BoolOr,
            41 => FloatEqual, 42 => FloatNotequal, 43 => FloatLess, 44 => FloatLessequal,
            46 => FloatNan, 47 => FloatAdd, 48 => FloatDiv, 49 => FloatMult, 50 => FloatSub,
            51 => FloatNeg, 52 => FloatAbs, 53 => FloatSqrt, 54 => FloatInt2float,
            55 => FloatFloat2float, 56 => FloatTrunc, 57 => FloatCeil, 58 => FloatFloor,
            59 => FloatRound, 60 => Multiequal, 61 => Indirect, 62 => Piece, 63 => Subpiece,
            64 => Cast, 65 => Ptradd, 66 => Ptrsub, 67 => Segmentop, 68 => Cpoolref,
            69 => New, 70 => Insert, 71 => Extract, 72 => Popcount, 73 => Lzcount,
            _ => return None,
        })
    }

    /// The canonical name as Ghidra prints it (e.g. `INT_ADD`).
    pub fn name(self) -> &'static str {
        use OpCode::*;
        match self {
            Copy => "COPY", Load => "LOAD", Store => "STORE", Branch => "BRANCH",
            Cbranch => "CBRANCH", Branchind => "BRANCHIND", Call => "CALL",
            Callind => "CALLIND", Callother => "CALLOTHER", Return => "RETURN",
            IntEqual => "INT_EQUAL", IntNotequal => "INT_NOTEQUAL", IntSless => "INT_SLESS",
            IntSlessequal => "INT_SLESSEQUAL", IntLess => "INT_LESS",
            IntLessequal => "INT_LESSEQUAL", IntZext => "INT_ZEXT", IntSext => "INT_SEXT",
            IntAdd => "INT_ADD", IntSub => "INT_SUB", IntCarry => "INT_CARRY",
            IntScarry => "INT_SCARRY", IntSborrow => "INT_SBORROW", Int2comp => "INT_2COMP",
            IntNegate => "INT_NEGATE", IntXor => "INT_XOR", IntAnd => "INT_AND",
            IntOr => "INT_OR", IntLeft => "INT_LEFT", IntRight => "INT_RIGHT",
            IntSright => "INT_SRIGHT", IntMult => "INT_MULT", IntDiv => "INT_DIV",
            IntSdiv => "INT_SDIV", IntRem => "INT_REM", IntSrem => "INT_SREM",
            BoolNegate => "BOOL_NEGATE", BoolXor => "BOOL_XOR", BoolAnd => "BOOL_AND",
            BoolOr => "BOOL_OR", FloatEqual => "FLOAT_EQUAL", FloatNotequal => "FLOAT_NOTEQUAL",
            FloatLess => "FLOAT_LESS", FloatLessequal => "FLOAT_LESSEQUAL", FloatNan => "FLOAT_NAN",
            FloatAdd => "FLOAT_ADD", FloatDiv => "FLOAT_DIV", FloatMult => "FLOAT_MULT",
            FloatSub => "FLOAT_SUB", FloatNeg => "FLOAT_NEG", FloatAbs => "FLOAT_ABS",
            FloatSqrt => "FLOAT_SQRT", FloatInt2float => "FLOAT_INT2FLOAT",
            FloatFloat2float => "FLOAT_FLOAT2FLOAT", FloatTrunc => "FLOAT_TRUNC",
            FloatCeil => "FLOAT_CEIL", FloatFloor => "FLOAT_FLOOR", FloatRound => "FLOAT_ROUND",
            Multiequal => "MULTIEQUAL", Indirect => "INDIRECT", Piece => "PIECE",
            Subpiece => "SUBPIECE", Cast => "CAST", Ptradd => "PTRADD", Ptrsub => "PTRSUB",
            Segmentop => "SEGMENTOP", Cpoolref => "CPOOLREF", New => "NEW", Insert => "INSERT",
            Extract => "EXTRACT", Popcount => "POPCOUNT", Lzcount => "LZCOUNT",
        }
    }

    /// A branch op (has an explicit target). Calls are *not* branches — they fall through.
    pub fn is_branch(self) -> bool {
        use OpCode::*;
        matches!(self, Branch | Cbranch | Branchind)
    }

    /// Ends a basic block. Per Ghidra: branches and returns end a block; **calls do
    /// not** (a call falls through to the next op in the same block).
    pub fn terminates_block(self) -> bool {
        use OpCode::*;
        matches!(self, Branch | Cbranch | Branchind | Return)
    }
}
