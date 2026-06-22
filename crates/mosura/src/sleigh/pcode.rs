//! Structured p-code — the IR shared by the lifter (stage 1b), the interpreter
//! ([`super::emu`]), and the decompiler ([`crate::decomp`]).
//!
//! A [`PcodeOp`] is `out = OPCODE in0 in1 …`. Each operand is a [`Varnode`]
//! `(space, offset, size)`, except a LOAD/STORE address-space input, which is a
//! [`PArg::Space`] rendered `(space,NAME)`. [`PcodeOp::render`] reproduces the
//! exact normalized text used by the disasm/p-code goldens, so the structured form
//! is the single source of truth and the text is just a view of it.

/// A p-code varnode: a slice of an address space.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Varnode {
    pub space: String,
    pub offset: u64,
    pub size: u32,
}

impl Varnode {
    pub fn render(&self) -> String {
        format!("({},{:#x},{})", self.space, self.offset, self.size)
    }
    /// True for the constant space (immediate values).
    pub fn is_const(&self) -> bool {
        self.space == "const"
    }
}

/// A p-code op argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PArg {
    Var(Varnode),
    /// A target address space — the first input of LOAD/STORE; renders `(space,NAME)`.
    Space(String),
}

impl PArg {
    pub fn render(&self) -> String {
        match self {
            PArg::Var(v) => v.render(),
            PArg::Space(name) => format!("(space,{name})"),
        }
    }
    pub fn as_var(&self) -> Option<&Varnode> {
        match self {
            PArg::Var(v) => Some(v),
            PArg::Space(_) => None,
        }
    }
}

/// One p-code operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcodeOp {
    pub opcode: u32,
    pub out: Option<Varnode>,
    pub ins: Vec<PArg>,
}

impl PcodeOp {
    pub fn name(&self) -> &'static str {
        opcode_name(self.opcode)
    }
    pub fn render(&self) -> String {
        let mut s = String::new();
        if let Some(out) = &self.out {
            s.push_str(&out.render());
            s.push_str(" = ");
        }
        s.push_str(self.name());
        for a in &self.ins {
            s.push(' ');
            s.push_str(&a.render());
        }
        s
    }
}

/// CPUI opcode → mnemonic (`opcodes.hh`). Pseudo-ops 60/61 (BUILD/DELAY_SLOT) are
/// consumed during lifting and never appear in emitted p-code.
pub fn opcode_name(op: u32) -> &'static str {
    match op {
        1 => "COPY",
        2 => "LOAD",
        3 => "STORE",
        4 => "BRANCH",
        5 => "CBRANCH",
        6 => "BRANCHIND",
        7 => "CALL",
        8 => "CALLIND",
        9 => "CALLOTHER",
        10 => "RETURN",
        11 => "INT_EQUAL",
        12 => "INT_NOTEQUAL",
        13 => "INT_SLESS",
        14 => "INT_SLESSEQUAL",
        15 => "INT_LESS",
        16 => "INT_LESSEQUAL",
        17 => "INT_ZEXT",
        18 => "INT_SEXT",
        19 => "INT_ADD",
        20 => "INT_SUB",
        21 => "INT_CARRY",
        22 => "INT_SCARRY",
        23 => "INT_SBORROW",
        24 => "INT_2COMP",
        25 => "INT_NEGATE",
        26 => "INT_XOR",
        27 => "INT_AND",
        28 => "INT_OR",
        29 => "INT_LEFT",
        30 => "INT_RIGHT",
        31 => "INT_SRIGHT",
        32 => "INT_MULT",
        33 => "INT_DIV",
        34 => "INT_SDIV",
        35 => "INT_REM",
        36 => "INT_SREM",
        37 => "BOOL_NEGATE",
        38 => "BOOL_XOR",
        39 => "BOOL_AND",
        40 => "BOOL_OR",
        41 => "FLOAT_EQUAL",
        42 => "FLOAT_NOTEQUAL",
        43 => "FLOAT_LESS",
        44 => "FLOAT_LESSEQUAL",
        46 => "FLOAT_NAN",
        47 => "FLOAT_ADD",
        48 => "FLOAT_DIV",
        49 => "FLOAT_MULT",
        50 => "FLOAT_SUB",
        51 => "FLOAT_NEG",
        52 => "FLOAT_ABS",
        53 => "FLOAT_SQRT",
        54 => "FLOAT_INT2FLOAT",
        55 => "FLOAT_FLOAT2FLOAT",
        56 => "FLOAT_TRUNC",
        57 => "FLOAT_CEIL",
        58 => "FLOAT_FLOOR",
        59 => "FLOAT_ROUND",
        62 => "PIECE",
        63 => "SUBPIECE",
        64 => "CAST",
        65 => "PTRADD",
        66 => "PTRSUB",
        67 => "SEGMENTOP",
        68 => "CPOOLREF",
        69 => "NEW",
        70 => "INSERT",
        71 => "EXTRACT",
        72 => "POPCOUNT",
        73 => "LZCOUNT",
        _ => "PCODE_OP",
    }
}
