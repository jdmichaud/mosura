//! SLEIGH runtime engine (stage 1b): interpret a decoded `.sla` element tree
//! into a working disassembler + p-code lifter.
//!
//! Pipeline: [`Spec::from_sla`] builds typed tables from the [`super::sla`]
//! element tree; [`Spec::disassemble`] walks the root subtable's decision tree to
//! match a constructor for each instruction, renders its display pieces, and
//! expands its p-code template.
//!
//! This is an early slice — enough to decode simple fixed-length, operand-free
//! constructors (verified on 6502 NOP/CLC/SEC/RTS). Operand resolution and
//! context handling are stubbed where not yet needed.

use super::pcode::{PArg, PcodeOp, Varnode};
use super::sla::{self, Element};
use super::Instruction;
use std::cell::{Cell, RefCell};

// ---- sla element ids (slaformat.cc, namespace sla) ----
#[allow(dead_code)] // complete id table kept as reference; not all are used yet
mod eid {
    pub const SYMBOL_TABLE: u32 = 38;
    pub const SCOPE: u32 = 22;
    pub const SPACES: u32 = 34;
    pub const NAMETAB: u32 = 66;
    pub const VALUETAB: u32 = 75;
    // symbol header / body element ids, paired
    pub const OPERAND_SYM_HEAD: u32 = 14;
    pub const VARNODE_SYM_HEAD: u32 = 24;
    pub const SUBTABLE_SYM_HEAD: u32 = 72;
    pub const VALUE_SYM_HEAD: u32 = 40;
    pub const CONTEXT_SYM_HEAD: u32 = 42;
    // bodies
    pub const USEROP: u32 = 25;
    pub const EPSILON_SYM: u32 = 62;
    pub const VALUE_SYM: u32 = 39;
    pub const VALUEMAP_SYM: u32 = 73;
    pub const NAME_SYM: u32 = 64;
    pub const VARNODE_SYM: u32 = 23;
    pub const CONTEXT_SYM: u32 = 41;
    pub const VARLIST_SYM: u32 = 76;
    pub const OPERAND_SYM: u32 = 13;
    pub const START_SYM: u32 = 69;
    pub const END_SYM: u32 = 43;
    pub const NEXT2_SYM: u32 = 67;
    pub const SUBTABLE_SYM: u32 = 71;
    // constructor + decision
    pub const CONSTRUCTOR: u32 = 20;
    pub const OPER: u32 = 15;
    pub const PRINT: u32 = 8;
    pub const OPPRINT: u32 = 17;
    pub const DECISION: u32 = 16;
    pub const PAIR: u32 = 9;
    pub const CONTEXT_OP: u32 = 32;
    // patterns
    pub const MASK_WORD: u32 = 6;
    pub const INSTRUCT_PAT: u32 = 18;
    pub const CONTEXT_PAT: u32 = 10;
    pub const COMBINE_PAT: u32 = 19;
    // pattern expressions
    pub const OPERAND_EXP: u32 = 12;
    pub const TOKENFIELD: u32 = 27;
    pub const VAR: u32 = 28;
    pub const CONTEXTFIELD: u32 = 29;
    pub const AND_EXP: u32 = 47;
    pub const DIV_EXP: u32 = 48;
    pub const LSHIFT_EXP: u32 = 49;
    pub const MINUS_EXP: u32 = 50;
    pub const MULT_EXP: u32 = 51;
    pub const NOT_EXP: u32 = 52;
    pub const OR_EXP: u32 = 53;
    pub const PLUS_EXP: u32 = 54;
    pub const RSHIFT_EXP: u32 = 55;
    pub const SUB_EXP: u32 = 56;
    pub const XOR_EXP: u32 = 57;
    pub const INTB: u32 = 58;
    pub const END_EXP: u32 = 59;
    pub const NEXT2_EXP: u32 = 60;
    pub const START_EXP: u32 = 61;
    // templates
    pub const CONSTRUCT_TPL: u32 = 21;
    pub const OP_TPL: u32 = 5;
    pub const VARNODE_TPL: u32 = 2;
    pub const HANDLE_TPL: u32 = 30;
    pub const NULL: u32 = 11;
    // const-tpl variants
    pub const CONST_REAL: u32 = 1;
    pub const CONST_SPACEID: u32 = 3;
    pub const CONST_HANDLE: u32 = 4;
    pub const CONST_RELATIVE: u32 = 31;
    pub const CONST_START: u32 = 80;
    pub const CONST_NEXT: u32 = 81;
    pub const CONST_NEXT2: u32 = 82;
    pub const CONST_CURSPACE: u32 = 83;
    pub const CONST_CURSPACE_SIZE: u32 = 84;
}

// ---- sla attribute ids ----
#[allow(dead_code)] // complete id table kept as reference; not all are used yet
mod aid {
    pub const VAL: u32 = 2;
    pub const ID: u32 = 3;
    pub const SPACE: u32 = 4;
    pub const S: u32 = 5;
    pub const OFF: u32 = 6;
    pub const CODE: u32 = 7;
    pub const MASK: u32 = 8;
    pub const INDEX: u32 = 9;
    pub const NONZERO: u32 = 10;
    pub const PIECE: u32 = 11;
    pub const NAME: u32 = 12;
    pub const STARTBIT: u32 = 14;
    pub const SIZE: u32 = 15;
    pub const MINLEN: u32 = 18;
    pub const BASE: u32 = 19;
    pub const NUMBER: u32 = 20;
    pub const CONTEXT: u32 = 21;
    pub const PARENT: u32 = 22;
    pub const I: u32 = 52;
    pub const SUBSYM: u32 = 23;
    pub const LENGTH: u32 = 26;
    pub const FIRST: u32 = 27;
    pub const PLUS: u32 = 28;
    pub const SHIFT: u32 = 29;
    pub const ENDBIT: u32 = 30;
    pub const SIGNBIT: u32 = 31;
    pub const ENDBYTE: u32 = 32;
    pub const STARTBYTE: u32 = 33;
    pub const BIGENDIAN: u32 = 35;
    pub const ALIGN: u32 = 36;
    pub const DEFAULTSPACE: u32 = 41;
    pub const SCOPESIZE: u32 = 45;
    pub const SYMBOLSIZE: u32 = 46;
    pub const LOW: u32 = 48;
    pub const HIGH: u32 = 49;
    pub const NUMCT: u32 = 53;
}

#[derive(Debug)]
pub enum Error {
    Sla(sla::Error),
    Schema(String),
    Decode(String),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Sla(e) => write!(f, "sla: {e}"),
            Error::Schema(s) => write!(f, "schema: {s}"),
            Error::Decode(s) => write!(f, "decode: {s}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<sla::Error> for Error {
    fn from(e: sla::Error) -> Self {
        Error::Sla(e)
    }
}

fn schema<T>(msg: impl Into<String>) -> Result<T, Error> {
    Err(Error::Schema(msg.into()))
}

// ---- typed tables ----

#[derive(Debug, Clone)]
pub struct Space {
    pub name: String,
    pub index: u64,
    pub size: u64,
    pub big_endian: bool,
}

#[derive(Debug, Clone)]
pub struct Constructor {
    pub min_length: i64,
    pub first_whitespace: i64,
    pub operand_ids: Vec<u32>,
    pub print: Vec<Piece>,
    pub tmpl: Option<ConstructTpl>,
    pub context_ops: Vec<ContextOp>,
}

/// A context-register mutation applied when a constructor matches (e.g. a REX
/// prefix setting `rexWprefix`), affecting how following operands decode.
#[derive(Debug, Clone)]
pub struct ContextOp {
    pub word: usize,
    pub shift: i64,
    pub mask: u32,
    pub value: PatternExpr,
}

#[derive(Debug, Clone)]
pub enum Piece {
    Literal(String),
    Operand(usize),
}

#[derive(Debug, Clone, Default)]
pub struct Subtable {
    pub constructors: Vec<Constructor>,
    pub decision: Option<Decision>,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub context_decision: bool,
    pub startbit: i64,
    pub bitsize: i64,
    pub pairs: Vec<(Pattern, usize)>, // (pattern, constructor index)
    pub children: Vec<Decision>,
}

#[derive(Debug, Clone)]
pub enum Pattern {
    Instruction(PatternBlock),
    Context(PatternBlock),
    Combine { context: PatternBlock, instr: PatternBlock },
}

#[derive(Debug, Clone)]
pub struct PatternBlock {
    pub offset: i64,
    pub nonzero: i64,
    pub mask: Vec<u32>,
    pub val: Vec<u32>,
}

// p-code templates
#[derive(Debug, Clone)]
pub struct ConstructTpl {
    pub ops: Vec<OpTpl>,
    /// The constructor's exported handle (what an operand referencing it resolves
    /// to), if any.
    pub result: Option<HandleTpl>,
}

/// A constructor's exported handle template (7 `ConstTpl` fields).
#[derive(Debug, Clone)]
pub struct HandleTpl {
    pub space: ConstTpl,
    pub size: ConstTpl,
    pub ptrspace: ConstTpl,
    pub ptroffset: ConstTpl,
    pub ptrsize: ConstTpl,
    pub tempspace: ConstTpl,
    pub tempoffset: ConstTpl,
}

/// A resolved operand handle. For a static operand, `(space, offset, size)` is the
/// varnode. For a **dynamic** operand (memory: `[RDI]`), `(space, offset, size)` is
/// the *temp* the value is loaded into, and `ptr` is the address to LOAD/STORE
/// through.
#[derive(Debug, Clone, Copy, Default)]
struct Handle {
    space: u64,
    offset: u64,
    size: u64,
    ptr: Option<Ptr>,
}

/// A dynamic operand's pointer: the space pointed into, and the pointer varnode.
#[derive(Debug, Clone, Copy)]
struct Ptr {
    value_space: u64,
    space: u64,
    offset: u64,
    size: u64,
}

#[derive(Debug, Clone)]
pub struct OpTpl {
    pub opcode: u32,
    pub output: Option<VarnodeTpl>,
    pub inputs: Vec<VarnodeTpl>,
}

#[derive(Debug, Clone)]
pub struct VarnodeTpl {
    pub space: ConstTpl,
    pub offset: ConstTpl,
    pub size: ConstTpl,
}

#[derive(Debug, Clone)]
pub enum ConstTpl {
    Real(u64),
    SpaceId(u64), // space index
    Handle { index: i64, sel: u32, plus: u64 },
    Relative(u64),
    Start,
    Next,
    Next2,
    CurSpace,
    CurSpaceSize,
}

/// A symbol slot; only the variants the engine currently uses are typed.
#[derive(Debug, Clone)]
pub enum Symbol {
    Subtable(Subtable),
    /// A named varnode (register): space index, offset, size.
    Varnode { space: u64, offset: u64, size: u64 },
    Operand(OperandSym),
    /// A register selected from a list by a pattern value (`attach variables`).
    VarnodeList(VarnodeListSym),
    /// A value computed from a pattern expression (immediate, etc.).
    Value(PatternExpr),
    /// A value selected from a table by a pattern index (e.g. SIB scale 1/2/4/8).
    ValueMap { patval: PatternExpr, table: Vec<i64> },
    /// A name selected from a table by a pattern index.
    Name { patval: PatternExpr, table: Vec<String> },
    Other,
}

#[derive(Debug, Clone)]
pub struct OperandSym {
    pub reloffset: i64,
    pub offsetbase: i64, // -1 = relative to the constructor's own offset
    pub minlen: i64,
    pub subsym: Option<u32>, // defining triple symbol id
    pub defexp: Option<PatternExpr>,
}

#[derive(Debug, Clone)]
pub struct VarnodeListSym {
    pub patval: PatternExpr,
    pub varnodes: Vec<Option<u32>>, // varnode symbol ids (None = invalid slot)
}

/// A SLEIGH pattern expression — evaluates to an integer against an instruction.
#[derive(Debug, Clone)]
pub enum PatternExpr {
    Token { bigendian: bool, signbit: bool, bitstart: i64, bitend: i64, bytestart: i64, byteend: i64, shift: i64 },
    Context { signbit: bool, startbit: i64, endbit: i64, startbyte: i64, endbyte: i64, shift: i64 },
    Constant(i64),
    Operand(usize),
    Start,
    End,
    Next2,
    Bin(BinOp, Box<PatternExpr>, Box<PatternExpr>),
    Un(UnOp, Box<PatternExpr>),
}

#[derive(Debug, Clone, Copy)]
pub enum BinOp {
    Add, Sub, Mul, Div, LShift, RShift, And, Or, Xor,
}

#[derive(Debug, Clone, Copy)]
pub enum UnOp {
    Minus, Not,
}

pub struct Spec {
    pub spaces: Vec<Space>,
    pub default_space: usize,
    pub unique_space: usize,
    pub big_endian: bool,
    pub align: i64,
    symbols: Vec<Option<Symbol>>,
    symbol_names: Vec<String>,
    root_subtable: usize, // symbol id of the "instruction" subtable
    /// Context variable name -> (low, high) bit range (MSB-numbered) in contextreg.
    context_vars: std::collections::HashMap<String, (u32, u32)>,
    /// Number of 32-bit words in the context register.
    context_words: usize,
    /// Laned-register metadata from the processor spec's `vector_lane_sizes` (Ghidra
    /// `Architecture::lanerecords`, architecture.hh:211), as `(whole_register_size, lane_size_mask)`
    /// pairs merged by size. Filled by the loader ([`crate::speccache::get`] / [`crate::lang::load`])
    /// from the `.pspec`, not from the `.sla`; empty for a bare [`Spec::from_sla`]. The decompiler's
    /// `build` wraps these in a `LanedRegisterSet` for `ActionLaneDivide`. Kept as primitives here so
    /// the `sleigh` layer needs no dependency on the `decompile` types.
    pub laned: Vec<(i32, u32)>,
}

impl Spec {
    pub fn from_sla(bytes: &[u8]) -> Result<Spec, Error> {
        let root = sla::decode(bytes)?;
        Self::from_element(&root)
    }

    pub fn from_element(root: &Element) -> Result<Spec, Error> {
        let big_endian = root.attr_bool(aid::BIGENDIAN).unwrap_or(false);
        let align = root.attr_int(aid::ALIGN).unwrap_or(1);

        // spaces
        let spaces_el = root.child(eid::SPACES).ok_or_else(|| Error::Schema("no <spaces>".into()))?;
        let default_name = spaces_el.attr_str(aid::DEFAULTSPACE).unwrap_or("").to_string();
        let mut spaces = Vec::new();
        // index 0 is the constant space (implicit in Ghidra); space elements carry their own index.
        for sp in &spaces_el.children {
            let name = sp.attr_str(aid::NAME).unwrap_or("").to_string();
            spaces.push(Space {
                index: sp.attr_int(aid::INDEX).unwrap_or(0) as u64,
                size: sp.attr_int(aid::SIZE).unwrap_or(0) as u64,
                big_endian: sp.attr_bool(aid::BIGENDIAN).unwrap_or(big_endian),
                name,
            });
        }
        let default_space = spaces
            .iter()
            .position(|s| s.name == default_name)
            .ok_or_else(|| Error::Schema(format!("default space {default_name:?} not found")))?;
        let unique_space = spaces.iter().position(|s| s.name == "unique").unwrap_or(0);

        // symbol table
        let st = root
            .child(eid::SYMBOL_TABLE)
            .ok_or_else(|| Error::Schema("no <symbol_table>".into()))?;
        let scopesize = st.attr_int(aid::SCOPESIZE).unwrap_or(0) as usize;
        let symbolsize = st.attr_int(aid::SYMBOLSIZE).unwrap_or(0) as usize;
        let mut symbols: Vec<Option<Symbol>> = vec![None; symbolsize];
        let mut names: Vec<String> = vec![String::new(); symbolsize];

        // children: [scopes..][headers..][bodies..]
        let kids = &st.children;
        if kids.len() < scopesize + symbolsize {
            return schema("symbol_table too short");
        }
        // headers: capture id->name for locating the root "instruction" subtable
        for h in &kids[scopesize..scopesize + symbolsize] {
            let id = h.attr_int(aid::ID).unwrap_or(-1);
            if let (Ok(i), Some(n)) = (usize::try_from(id), h.attr_str(aid::NAME)) {
                if i < names.len() {
                    names[i] = n.to_string();
                }
            }
        }
        // bodies
        let mut context_vars = std::collections::HashMap::new();
        let mut context_words = 0usize;
        for body in &kids[scopesize + symbolsize..] {
            let id = body.attr_int(aid::ID);
            let Some(i) = id.and_then(|v| usize::try_from(v).ok()) else { continue };
            if i >= symbols.len() {
                continue;
            }
            if body.id == eid::CONTEXT_SYM {
                if let (Some(low), Some(high)) = (body.attr_int(aid::LOW), body.attr_int(aid::HIGH)) {
                    context_vars.insert(names[i].clone(), (low as u32, high as u32));
                }
            } else if body.id == eid::VARNODE_SYM && names[i] == "contextreg" {
                context_words = (body.attr_int(aid::SIZE).unwrap_or(0) as usize).div_ceil(4);
            }
            symbols[i] = Some(decode_symbol(body)?);
        }

        let root_subtable = names
            .iter()
            .position(|n| n == "instruction")
            .ok_or_else(|| Error::Schema("no 'instruction' subtable".into()))?;
        if !matches!(symbols.get(root_subtable), Some(Some(Symbol::Subtable(_)))) {
            return schema("'instruction' symbol is not a subtable");
        }

        Ok(Spec {
            spaces,
            default_space,
            unique_space,
            big_endian,
            align,
            symbols,
            symbol_names: names,
            root_subtable,
            context_vars,
            context_words,
            laned: Vec::new(),
        })
    }

    fn symbol(&self, id: u32) -> Option<&Symbol> {
        self.symbols.get(id as usize).and_then(|o| o.as_ref())
    }
    fn symbol_name(&self, id: u32) -> &str {
        self.symbol_names.get(id as usize).map(String::as_str).unwrap_or("?")
    }
    fn operand(&self, id: u32) -> Option<&OperandSym> {
        match self.symbol(id) {
            Some(Symbol::Operand(o)) => Some(o),
            _ => None,
        }
    }

    /// The byte size of the named register (a `Varnode` symbol), or `None` if there is no such
    /// register. Used to resolve a `.pspec` `<register name=…>` to the storage size Ghidra reads
    /// from the sleigh register table (the `vector_lane_sizes` laned-register lookup).
    pub fn register_size(&self, name: &str) -> Option<u32> {
        for (i, sym) in self.symbols.iter().enumerate() {
            if let Some(Symbol::Varnode { size, .. }) = sym {
                if self.symbol_names.get(i).map(String::as_str) == Some(name) {
                    return Some(*size as u32);
                }
            }
        }
        None
    }

    /// Build a context-register word array from named context-variable settings
    /// (e.g. the `.pspec` `<context_set>` defaults: `longMode=1`, `addrsize=2`…).
    pub fn context_from_sets(&self, sets: &[(&str, u64)]) -> Vec<u32> {
        let mut ctx = vec![0u32; self.context_words.max(1)];
        for (name, val) in sets {
            let Some(&(low, high)) = self.context_vars.get(*name) else { continue };
            let word = (low / 32) as usize;
            if word >= ctx.len() || low / 32 != high / 32 {
                continue; // single-word fields only (all x86 context vars qualify)
            }
            let width = high - low + 1;
            let shift = 32 - (high % 32) - 1; // field LSB position within the word
            let mask = if width >= 32 { u32::MAX } else { ((1u32 << width) - 1) << shift };
            ctx[word] = (ctx[word] & !mask) | (((*val as u32) << shift) & mask);
        }
        ctx
    }

    fn subtable(&self, id: usize) -> Option<&Subtable> {
        match self.symbols.get(id) {
            Some(Some(Symbol::Subtable(s))) => Some(s),
            _ => None,
        }
    }

    fn space_name(&self, index: u64) -> &str {
        // const space (index 0) is implicit; address spaces carry their own index.
        if index == 0 {
            return "const";
        }
        self.spaces
            .iter()
            .find(|s| s.index == index)
            .map(|s| s.name.as_str())
            .unwrap_or("?")
    }

    /// Disassemble `bytes` starting at `base` with no context (fine for arches
    /// without a context register, e.g. 6502).
    pub fn disassemble(&self, bytes: &[u8], base: u64) -> Vec<Instruction> {
        self.disassemble_ctx(bytes, base, &[])
    }

    /// Disassemble `bytes` starting at `base` with an explicit context register
    /// value (see [`Spec::context_from_sets`]).
    pub fn disassemble_ctx(&self, bytes: &[u8], base: u64, context: &[u32]) -> Vec<Instruction> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos < bytes.len() {
            let walker = Walker {
                buf: &bytes[pos..],
                addr: base + pos as u64,
                context: RefCell::new(context.to_vec()),
                next: Cell::new(0),
            };
            let Some(node) = self.resolve(&walker, self.root_subtable, 0) else { break };
            let mut ilen = node.length.max(1);
            // A branch whose template emits a DELAY_SLOT directive consumes its
            // following instruction too (MIPS/SPARC); extend the length so bytes and
            // fall-through match Ghidra's `oneInstruction`.
            if self.has_delay_slot(&node) && ilen < walker.buf.len() {
                let dw = Walker {
                    buf: &walker.buf[ilen..],
                    addr: walker.addr + ilen as u64,
                    context: RefCell::new(walker.context.borrow().clone()),
                    next: Cell::new(0),
                };
                if let Some(dn) = self.resolve(&dw, self.root_subtable, 0) {
                    ilen += dn.length.max(1);
                }
            }
            walker.next.set(walker.addr + ilen as u64); // for relative branch targets
            let nb = ilen.min(bytes.len() - pos);

            let (mnemonic, body) = self.render_node(&node, &walker);
            let ops = self.build_pcode_node(&node, &walker);
            let pcode = ops.iter().map(PcodeOp::render).collect();

            // Zero-pad when a chunk ends mid-instruction — the SLEIGH decoder reads
            // a fixed window and the loader supplies zeros past the chunk.
            let mut insn_bytes = bytes[pos..pos + nb].to_vec();
            insn_bytes.resize(ilen, 0);

            out.push(Instruction {
                address: walker.addr,
                bytes: insn_bytes,
                mnemonic,
                body,
                pcode,
                ops,
            });
            pos += ilen;
        }
        out
    }

    /// Expand a constructor's p-code template into normalized op lines, recursing
    /// into operand sub-constructors at `BUILD` ops.
    fn build_into(&self, node: &Node, walker: &Walker, ops: &mut Vec<PcodeOp>) {
        const BUILD: u32 = 60; // CPUI_MULTIEQUAL, aliased as BUILD in templates
        const DELAY_SLOT: u32 = 61;
        const LABELBUILD: u32 = 65;
        const CROSSBUILD: u32 = 66;
        let Some(tmpl) = self.ctor_of(node).tmpl.as_ref() else { return };
        for op in &tmpl.ops {
            match op.opcode {
                BUILD => {
                    let idx = op
                        .inputs
                        .first()
                        .and_then(|v| self.resolve_const_h(&v.offset, node, walker))
                        .unwrap_or(0) as usize;
                    if let Some(OpNode::Sub(sub)) = node.operands.get(idx) {
                        self.build_into(sub, walker, ops);
                    }
                }
                DELAY_SLOT => {
                    // Inline the p-code of the instruction in the branch's delay
                    // slot (MIPS/SPARC) — `SleighBuilder::delaySlot`.
                    let len = node.length.max(1) as usize;
                    if len < walker.buf.len() {
                        let dwalker = Walker {
                            buf: &walker.buf[len..],
                            addr: walker.addr + len as u64,
                            context: RefCell::new(walker.context.borrow().clone()),
                            next: Cell::new(0),
                        };
                        if let Some(dnode) = self.resolve(&dwalker, self.root_subtable, 0) {
                            dwalker.next.set(dwalker.addr + dnode.length.max(1) as u64);
                            self.build_into(&dnode, &dwalker, ops);
                        }
                    }
                }
                LABELBUILD | CROSSBUILD => {} // not modeled yet
                _ => match self.op_pcode(op, node, walker) {
                    Some(mut v) => ops.append(&mut v),
                    None => ops.push(PcodeOp { opcode: op.opcode, out: None, ins: Vec::new() }),
                },
            }
        }
    }

    /// Build the structured p-code op(s) for one template op, generating `LOAD`/
    /// `STORE` around any dynamic (memory) operands (`SleighBuilder::dump`).
    fn op_pcode(&self, op: &OpTpl, node: &Node, walker: &Walker) -> Option<Vec<PcodeOp>> {
        const LOAD: u32 = 2;
        const STORE: u32 = 3;
        let mut ops = Vec::new();
        let mut ins: Vec<PArg> = Vec::new();
        for (i, inp) in op.inputs.iter().enumerate() {
            if (op.opcode == LOAD || op.opcode == STORE) && i == 0 {
                // explicit space-id input of an actual LOAD/STORE op
                let space = self.resolve_const_h(&inp.offset, node, walker)?;
                ins.push(PArg::Space(self.space_name(space).to_string()));
            } else if let Some(ptr) = self.dynamic_ptr(inp, node, walker) {
                // dynamic input: LOAD through the pointer into a temp, use the temp
                let temp = self.varnode_h(inp, node, walker)?;
                ops.push(PcodeOp {
                    opcode: LOAD,
                    out: Some(temp.clone()),
                    ins: vec![PArg::Space(self.space_name(ptr.value_space).to_string()), PArg::Var(self.ptr_varnode(ptr))],
                });
                ins.push(PArg::Var(temp));
            } else {
                ins.push(PArg::Var(self.varnode_h(inp, node, walker)?));
            }
        }
        match &op.output {
            Some(out) if self.dynamic_ptr(out, node, walker).is_some() => {
                let ptr = self.dynamic_ptr(out, node, walker)?;
                let temp = self.varnode_h(out, node, walker)?;
                ops.push(PcodeOp { opcode: op.opcode, out: Some(temp.clone()), ins });
                ops.push(PcodeOp {
                    opcode: STORE,
                    out: None,
                    ins: vec![PArg::Space(self.space_name(ptr.value_space).to_string()), PArg::Var(self.ptr_varnode(ptr)), PArg::Var(temp)],
                });
            }
            Some(out) => {
                let o = self.varnode_h(out, node, walker)?;
                ops.push(PcodeOp { opcode: op.opcode, out: Some(o), ins });
            }
            None => ops.push(PcodeOp { opcode: op.opcode, out: None, ins }),
        }
        Some(ops)
    }

    /// If varnode `v`'s offset is a dynamic operand handle, return its pointer.
    fn dynamic_ptr(&self, v: &VarnodeTpl, node: &Node, walker: &Walker) -> Option<Ptr> {
        if let ConstTpl::Handle { index, .. } = v.offset {
            return self.operand_handle(node, index as usize, walker)?.ptr;
        }
        None
    }

    fn ptr_varnode(&self, ptr: Ptr) -> Varnode {
        Varnode { space: self.space_name(ptr.space).to_string(), offset: ptr.offset, size: ptr.size as u32 }
    }

    fn varnode_h(&self, v: &VarnodeTpl, node: &Node, walker: &Walker) -> Option<Varnode> {
        let space = self.resolve_const_h(&v.space, node, walker)?;
        let mut offset = self.resolve_const_h(&v.offset, node, walker)?;
        let size = self.resolve_const_h(&v.size, node, walker)?;
        // const-space varnodes carry their value masked to their size (Ghidra
        // `generateLocation`); a sign-extended negative immediate prints truncated.
        if space == 0 && (1..8).contains(&size) {
            offset &= (1u64 << (size * 8)) - 1;
        }
        Some(Varnode { space: self.space_name(space).to_string(), offset, size: size as u32 })
    }

    /// Resolve a `ConstTpl` to a value, following operand-handle references.
    fn resolve_const_h(&self, c: &ConstTpl, node: &Node, walker: &Walker) -> Option<u64> {
        match c {
            ConstTpl::Real(v) | ConstTpl::SpaceId(v) => Some(*v),
            ConstTpl::CurSpace => Some(self.spaces[self.default_space].index),
            ConstTpl::CurSpaceSize => Some(self.spaces[self.default_space].size),
            ConstTpl::Start => Some(walker.addr),
            ConstTpl::Next => Some(walker.next.get()),
            ConstTpl::Next2 | ConstTpl::Relative(_) => None,
            ConstTpl::Handle { index, sel, plus } => {
                let h = self.operand_handle(node, *index as usize, walker)?;
                Some(match *sel {
                    0 => h.space,
                    1 => h.offset,
                    2 => h.size,
                    // v_offset_plus: a varnode truncation `vn[lo,sz]` (e.g. SLEIGH
                    // `XmmReg[32,32]`). `plus` is the packed truncation Ghidra builds in
                    // `VarnodeTpl::adjustTruncation` — low 16 bits = byte offset (endian
                    // adjusted), high bits = the original byte offset for the constant case.
                    // `ConstTpl::fix` (semantics.cc): a non-constant handle bumps the offset
                    // by the low 16 bits; a constant is right-shifted by 8*(plus>>16) bytes.
                    3 if h.space != 0 => h.offset.wrapping_add(*plus & 0xffff),
                    3 => h.offset >> (8 * (*plus >> 16)),
                    _ => return None,
                })
            }
        }
    }

    fn operand_handle(&self, node: &Node, i: usize, walker: &Walker) -> Option<Handle> {
        match node.operands.get(i)? {
            OpNode::Sub(sub) => self.exported_handle(sub, walker),
            OpNode::Leaf { sym, offset, .. } => self.leaf_handle(*sym, *offset, node, walker),
            OpNode::Expr { op_id, offset, .. } => {
                let v = self
                    .operand(*op_id)
                    .and_then(|o| o.defexp.as_ref())
                    .map_or(0, |e| self.eval(e, walker, Operands::Node(node), *offset));
                Some(Handle { space: 0, offset: v as u64, size: 0, ptr: None })
            }
        }
    }

    /// A constructor's exported handle (static, or dynamic/pointer for memory).
    fn exported_handle(&self, node: &Node, walker: &Walker) -> Option<Handle> {
        let htpl = self.ctor_of(node).tmpl.as_ref()?.result.as_ref()?;
        let size = self.resolve_const_h(&htpl.size, node, walker)?;
        // Dynamic iff the pointer lives in a real (non-constant) space; if `ptrspace`
        // is a real const or resolves to the const space (index 0), it's static.
        let ptr_space = match &htpl.ptrspace {
            ConstTpl::Real(_) => 0,
            other => self.resolve_const_h(other, node, walker)?,
        };
        if ptr_space == 0 {
            Some(Handle {
                space: self.resolve_const_h(&htpl.space, node, walker)?,
                offset: self.resolve_const_h(&htpl.ptroffset, node, walker)?,
                size,
                ptr: None,
            })
        } else {
            // dynamic: `space`/`offset` are the temp; `ptr` is the address to deref.
            Some(Handle {
                space: self.resolve_const_h(&htpl.tempspace, node, walker)?,
                offset: self.resolve_const_h(&htpl.tempoffset, node, walker)?,
                size,
                ptr: Some(Ptr {
                    value_space: self.resolve_const_h(&htpl.space, node, walker)?,
                    space: ptr_space,
                    offset: self.resolve_const_h(&htpl.ptroffset, node, walker)?,
                    size: self.resolve_const_h(&htpl.ptrsize, node, walker)?,
                }),
            })
        }
    }

    fn leaf_handle(&self, sym: u32, offset: usize, node: &Node, walker: &Walker) -> Option<Handle> {
        match self.symbol(sym) {
            Some(Symbol::Varnode { space, offset: off, size }) => {
                Some(Handle { space: *space, offset: *off, size: *size, ptr: None })
            }
            Some(Symbol::VarnodeList(vl)) => {
                let idx = self.eval(&vl.patval, walker, Operands::Node(node), offset) as usize;
                let vn = vl.varnodes.get(idx).copied().flatten()?;
                match self.symbol(vn) {
                    Some(Symbol::Varnode { space, offset: off, size }) => {
                        Some(Handle { space: *space, offset: *off, size: *size, ptr: None })
                    }
                    _ => None,
                }
            }
            Some(Symbol::Value(e)) => {
                let v = self.eval(e, walker, Operands::Node(node), offset);
                Some(Handle { space: 0, offset: v as u64, size: 0, ptr: None })
            }
            Some(Symbol::ValueMap { patval, table }) => {
                let idx = self.eval(patval, walker, Operands::Node(node), offset) as usize;
                Some(Handle { space: 0, offset: table.get(idx).copied().unwrap_or(0) as u64, size: 0, ptr: None })
            }
            _ => None,
        }
    }
}

// ---- decode helpers ----

fn decode_symbol(body: &Element) -> Result<Symbol, Error> {
    Ok(match body.id {
        eid::SUBTABLE_SYM => Symbol::Subtable(decode_subtable(body)?),
        eid::VARNODE_SYM => Symbol::Varnode {
            space: body.attr_int(aid::SPACE).unwrap_or(0) as u64,
            offset: body.attr_int(aid::OFF).unwrap_or(0) as u64,
            size: body.attr_int(aid::SIZE).unwrap_or(0) as u64,
        },
        eid::OPERAND_SYM => Symbol::Operand(decode_operand(body)),
        eid::VARLIST_SYM => Symbol::VarnodeList(decode_varnodelist(body)),
        eid::VALUE_SYM => Symbol::Value(
            body.children.iter().find_map(decode_pattern_expr).unwrap_or(PatternExpr::Constant(0)),
        ),
        eid::VALUEMAP_SYM => Symbol::ValueMap {
            patval: body.children.iter().find_map(decode_pattern_expr).unwrap_or(PatternExpr::Constant(0)),
            table: body.children.iter().filter(|c| c.id == eid::VALUETAB).map(|c| c.attr_int(aid::VAL).unwrap_or(0)).collect(),
        },
        eid::NAME_SYM => Symbol::Name {
            patval: body.children.iter().find_map(decode_pattern_expr).unwrap_or(PatternExpr::Constant(0)),
            table: body.children.iter().filter(|c| c.id == eid::NAMETAB).map(|c| c.attr_str(aid::NAME).unwrap_or("").to_string()).collect(),
        },
        eid::USEROP
        | eid::EPSILON_SYM
        | eid::CONTEXT_SYM
        | eid::START_SYM
        | eid::END_SYM
        | eid::NEXT2_SYM => Symbol::Other,
        other => return Err(Error::Schema(format!("unknown symbol body element {other}"))),
    })
}

fn decode_operand(el: &Element) -> OperandSym {
    // children are [localexp, defexp?]; localexp is the operand's own value, we keep defexp.
    let exprs: Vec<PatternExpr> = el.children.iter().filter_map(decode_pattern_expr).collect();
    OperandSym {
        reloffset: el.attr_int(aid::OFF).unwrap_or(0),
        offsetbase: el.attr_int(aid::BASE).unwrap_or(-1),
        minlen: el.attr_int(aid::MINLEN).unwrap_or(0),
        subsym: el.attr_int(aid::SUBSYM).and_then(|v| u32::try_from(v).ok()),
        defexp: exprs.into_iter().nth(1),
    }
}

fn decode_varnodelist(el: &Element) -> VarnodeListSym {
    let patval = el.children.iter().find_map(decode_pattern_expr).unwrap_or(PatternExpr::Constant(0));
    let varnodes = el
        .children
        .iter()
        .filter(|c| c.id == eid::VAR || c.id == eid::NULL)
        .map(|c| (c.id == eid::VAR).then(|| c.attr_int(aid::ID).and_then(|v| u32::try_from(v).ok())).flatten())
        .collect();
    VarnodeListSym { patval, varnodes }
}

fn decode_pattern_expr(el: &Element) -> Option<PatternExpr> {
    let kids: Vec<PatternExpr> = el.children.iter().filter_map(decode_pattern_expr).collect();
    let bin = |op: BinOp| PatternExpr::Bin(op, Box::new(kids[0].clone()), Box::new(kids[1].clone()));
    Some(match el.id {
        eid::TOKENFIELD => PatternExpr::Token {
            bigendian: el.attr_bool(aid::BIGENDIAN).unwrap_or(false),
            signbit: el.attr_bool(aid::SIGNBIT).unwrap_or(false),
            bitstart: el.attr_int(aid::STARTBIT).unwrap_or(0),
            bitend: el.attr_int(aid::ENDBIT).unwrap_or(0),
            bytestart: el.attr_int(aid::STARTBYTE).unwrap_or(0),
            byteend: el.attr_int(aid::ENDBYTE).unwrap_or(0),
            shift: el.attr_int(aid::SHIFT).unwrap_or(0),
        },
        eid::CONTEXTFIELD => PatternExpr::Context {
            signbit: el.attr_bool(aid::SIGNBIT).unwrap_or(false),
            startbit: el.attr_int(aid::STARTBIT).unwrap_or(0),
            endbit: el.attr_int(aid::ENDBIT).unwrap_or(0),
            startbyte: el.attr_int(aid::STARTBYTE).unwrap_or(0),
            endbyte: el.attr_int(aid::ENDBYTE).unwrap_or(0),
            shift: el.attr_int(aid::SHIFT).unwrap_or(0),
        },
        eid::INTB => PatternExpr::Constant(el.attr_int(aid::VAL).unwrap_or(0)),
        eid::OPERAND_EXP => PatternExpr::Operand(el.attr_int(aid::INDEX).unwrap_or(0) as usize),
        eid::START_EXP => PatternExpr::Start,
        eid::END_EXP => PatternExpr::End,
        eid::NEXT2_EXP => PatternExpr::Next2,
        eid::PLUS_EXP => bin(BinOp::Add),
        eid::SUB_EXP => bin(BinOp::Sub),
        eid::MULT_EXP => bin(BinOp::Mul),
        eid::DIV_EXP => bin(BinOp::Div),
        eid::LSHIFT_EXP => bin(BinOp::LShift),
        eid::RSHIFT_EXP => bin(BinOp::RShift),
        eid::AND_EXP => bin(BinOp::And),
        eid::OR_EXP => bin(BinOp::Or),
        eid::XOR_EXP => bin(BinOp::Xor),
        eid::MINUS_EXP => PatternExpr::Un(UnOp::Minus, Box::new(kids[0].clone())),
        eid::NOT_EXP => PatternExpr::Un(UnOp::Not, Box::new(kids[0].clone())),
        _ => return None,
    })
}

fn decode_subtable(el: &Element) -> Result<Subtable, Error> {
    let numct = el.attr_int(aid::NUMCT).unwrap_or(0) as usize;
    let mut constructors = Vec::with_capacity(numct);
    let mut decision = None;
    for child in &el.children {
        match child.id {
            eid::CONSTRUCTOR => constructors.push(decode_constructor(child)?),
            eid::DECISION => decision = Some(decode_decision(child)?),
            _ => {}
        }
    }
    Ok(Subtable { constructors, decision })
}

fn decode_constructor(el: &Element) -> Result<Constructor, Error> {
    let mut operand_ids = Vec::new();
    let mut print = Vec::new();
    let mut tmpl = None;
    let mut context_ops = Vec::new();
    for child in &el.children {
        match child.id {
            eid::OPER => operand_ids.push(child.attr_int(aid::ID).unwrap_or(0) as u32),
            eid::PRINT => print.push(Piece::Literal(
                child.attr_str(aid::PIECE).unwrap_or("").to_string(),
            )),
            eid::OPPRINT => print.push(Piece::Operand(child.attr_int(aid::ID).unwrap_or(0) as usize)),
            eid::CONSTRUCT_TPL => tmpl = Some(decode_construct_tpl(child)?),
            eid::CONTEXT_OP => context_ops.push(ContextOp {
                word: child.attr_int(aid::I).unwrap_or(0) as usize,
                shift: child.attr_int(aid::SHIFT).unwrap_or(0),
                mask: child.attr_int(aid::MASK).unwrap_or(0) as u32,
                value: child.children.iter().find_map(decode_pattern_expr).unwrap_or(PatternExpr::Constant(0)),
            }),
            _ => {}
        }
    }
    Ok(Constructor {
        min_length: el.attr_int(aid::LENGTH).unwrap_or(0),
        first_whitespace: el.attr_int(aid::FIRST).unwrap_or(-1),
        operand_ids,
        print,
        tmpl,
        context_ops,
    })
}

fn decode_decision(el: &Element) -> Result<Decision, Error> {
    let mut pairs = Vec::new();
    let mut children = Vec::new();
    for child in &el.children {
        match child.id {
            eid::PAIR => {
                let idx = child.attr_int(aid::ID).unwrap_or(0) as usize;
                let pat = child
                    .children
                    .iter()
                    .find_map(|c| decode_pattern(c))
                    .ok_or_else(|| Error::Schema("PAIR without pattern".into()))?;
                pairs.push((pat, idx));
            }
            eid::DECISION => children.push(decode_decision(child)?),
            _ => {}
        }
    }
    Ok(Decision {
        context_decision: el.attr_bool(aid::CONTEXT).unwrap_or(false),
        startbit: el.attr_int(aid::STARTBIT).unwrap_or(0),
        bitsize: el.attr_int(aid::SIZE).unwrap_or(0),
        pairs,
        children,
    })
}

fn decode_pattern(el: &Element) -> Option<Pattern> {
    match el.id {
        eid::INSTRUCT_PAT => Some(Pattern::Instruction(decode_pattern_block(el.children.first()?))),
        eid::CONTEXT_PAT => Some(Pattern::Context(decode_pattern_block(el.children.first()?))),
        eid::COMBINE_PAT => {
            // children: ContextPattern then InstructionPattern
            let context = decode_pattern_block(el.children.first()?.children.first()?);
            let instr = decode_pattern_block(el.children.get(1)?.children.first()?);
            Some(Pattern::Combine { context, instr })
        }
        _ => None,
    }
}

fn decode_pattern_block(el: &Element) -> PatternBlock {
    let mut mask = Vec::new();
    let mut val = Vec::new();
    for w in &el.children {
        if w.id == eid::MASK_WORD {
            mask.push(w.attr_int(aid::MASK).unwrap_or(0) as u32);
            val.push(w.attr_int(aid::VAL).unwrap_or(0) as u32);
        }
    }
    PatternBlock {
        offset: el.attr_int(aid::OFF).unwrap_or(0),
        nonzero: el.attr_int(aid::NONZERO).unwrap_or(0),
        mask,
        val,
    }
}

fn decode_construct_tpl(el: &Element) -> Result<ConstructTpl, Error> {
    let mut ops = Vec::new();
    let mut result = None;
    for child in &el.children {
        match child.id {
            eid::HANDLE_TPL => result = Some(decode_handle_tpl(child)?),
            eid::OP_TPL => ops.push(decode_op_tpl(child)?),
            _ => {}
        }
    }
    Ok(ConstructTpl { ops, result })
}

fn decode_handle_tpl(el: &Element) -> Result<HandleTpl, Error> {
    let cs: Vec<ConstTpl> = el
        .children
        .iter()
        .filter(|c| is_const_tpl(c.id))
        .map(decode_const_tpl)
        .collect::<Result<_, _>>()?;
    let g = |i: usize| cs.get(i).cloned().unwrap_or(ConstTpl::Real(0));
    Ok(HandleTpl {
        space: g(0),
        size: g(1),
        ptrspace: g(2),
        ptroffset: g(3),
        ptrsize: g(4),
        tempspace: g(5),
        tempoffset: g(6),
    })
}

fn decode_op_tpl(el: &Element) -> Result<OpTpl, Error> {
    let opcode = el.attr_int(aid::CODE).unwrap_or(0) as u32;
    let mut varnodes = el.children.iter().filter(|c| c.id == eid::VARNODE_TPL || c.id == eid::NULL);
    let output = match varnodes.next() {
        Some(v) if v.id == eid::VARNODE_TPL => Some(decode_varnode_tpl(v)?),
        _ => None,
    };
    let inputs = varnodes
        .filter(|v| v.id == eid::VARNODE_TPL)
        .map(decode_varnode_tpl)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(OpTpl { opcode, output, inputs })
}

fn decode_varnode_tpl(el: &Element) -> Result<VarnodeTpl, Error> {
    let mut it = el.children.iter().filter(|c| is_const_tpl(c.id));
    let space = decode_const_tpl(it.next().ok_or_else(|| Error::Schema("varnode_tpl missing space".into()))?)?;
    let offset = decode_const_tpl(it.next().ok_or_else(|| Error::Schema("varnode_tpl missing offset".into()))?)?;
    let size = decode_const_tpl(it.next().ok_or_else(|| Error::Schema("varnode_tpl missing size".into()))?)?;
    Ok(VarnodeTpl { space, offset, size })
}

fn is_const_tpl(id: u32) -> bool {
    matches!(
        id,
        eid::CONST_REAL
            | eid::CONST_SPACEID
            | eid::CONST_HANDLE
            | eid::CONST_RELATIVE
            | eid::CONST_START
            | eid::CONST_NEXT
            | eid::CONST_NEXT2
            | eid::CONST_CURSPACE
            | eid::CONST_CURSPACE_SIZE
    )
}

fn decode_const_tpl(el: &Element) -> Result<ConstTpl, Error> {
    Ok(match el.id {
        eid::CONST_REAL => ConstTpl::Real(el.attr_int(aid::VAL).unwrap_or(0) as u64),
        eid::CONST_SPACEID => ConstTpl::SpaceId(el.attr_int(aid::SPACE).unwrap_or(0) as u64),
        eid::CONST_HANDLE => ConstTpl::Handle {
            index: el.attr_int(aid::VAL).unwrap_or(0),
            sel: el.attr_int(aid::S).unwrap_or(0) as u32,
            plus: el.attr_int(aid::PLUS).unwrap_or(0) as u64,
        },
        eid::CONST_RELATIVE => ConstTpl::Relative(el.attr_int(aid::VAL).unwrap_or(0) as u64),
        eid::CONST_START => ConstTpl::Start,
        eid::CONST_NEXT => ConstTpl::Next,
        eid::CONST_NEXT2 => ConstTpl::Next2,
        eid::CONST_CURSPACE => ConstTpl::CurSpace,
        eid::CONST_CURSPACE_SIZE => ConstTpl::CurSpaceSize,
        other => return Err(Error::Schema(format!("unknown const_tpl element {other}"))),
    })
}

// ---- runtime walker ----

struct Walker<'a> {
    buf: &'a [u8],
    addr: u64,
    /// Mutable during a single instruction: context-changing constructors (e.g.
    /// REX prefixes) update it, affecting how following operands decode.
    context: RefCell<Vec<u32>>,
    /// Address of the next instruction (for relative branch targets). Set after
    /// the instruction length is known.
    next: Cell<u64>,
}

impl<'a> Walker<'a> {
    fn byte(&self, i: usize) -> u32 {
        self.buf.get(i).copied().unwrap_or(0) as u32
    }

    /// 4 context bytes assembled big-endian starting at byte offset `off`
    /// (matches `getContextBytes`; `off` need not be word-aligned).
    fn context_bytes(&self, off: usize) -> u32 {
        (self.context_byte(off) << 24)
            | (self.context_byte(off + 1) << 16)
            | (self.context_byte(off + 2) << 8)
            | self.context_byte(off + 3)
    }

    /// A single context byte at index `b` (words are big-endian).
    fn context_byte(&self, b: usize) -> u32 {
        (self.context.borrow().get(b / 4).copied().unwrap_or(0) >> (8 * (3 - (b % 4)))) & 0xff
    }

    /// `size` bits starting at context bit `startbit` (matches `getContextBits`).
    fn context_bits(&self, startbit: i64, size: i64) -> u32 {
        let ctx = self.context.borrow();
        let mut intstart = (startbit / 32) as usize;
        let bit_offset = (startbit % 32) as u32;
        let size = size as u32;
        let mut res = ctx.get(intstart).copied().unwrap_or(0);
        res = res.wrapping_shl(bit_offset);
        res >>= 32 - size;
        let remaining = size as i64 - 32 + bit_offset as i64;
        if remaining > 0 {
            intstart += 1;
            if let Some(&w) = ctx.get(intstart) {
                res |= w >> (32 - remaining as u32);
            }
        }
        res
    }

    /// Apply a context mutation (a `ContextOp`).
    fn apply_context(&self, word: usize, shift: u32, mask: u32, val: u64) {
        let mut ctx = self.context.borrow_mut();
        if let Some(w) = ctx.get_mut(word) {
            *w = (*w & !mask) | (((val << shift) as u32) & mask);
        }
    }
    /// Big-endian assemble `size` bytes at `base+off` into a 32-bit word.
    fn instruction_bytes(&self, base: usize, off: usize, size: usize) -> u32 {
        let mut res = 0u32;
        for i in 0..size {
            res = (res << 8) | self.byte(base + off + i);
        }
        res
    }
    /// `size` bits starting at bit `startbit` from byte `base` (big-endian bits).
    fn instruction_bits(&self, base: usize, startbit: i64, size: i64) -> u32 {
        let off = (startbit / 8) as usize;
        let startbit = (startbit % 8) as u32;
        let bytesize = ((startbit as i64 + size - 1) / 8 + 1) as usize;
        let mut res = 0u32;
        for i in 0..bytesize {
            res = (res << 8) | self.byte(base + off + i);
        }
        // move starting bit to highest position, then shift to the bottom
        res = res.wrapping_shl(8 * (4 - bytesize as u32) + startbit);
        res >> (32 - size as u32)
    }
}

impl Decision {
    fn resolve(&self, walker: &Walker, base: usize) -> Option<usize> {
        if self.bitsize == 0 {
            for (pat, idx) in &self.pairs {
                if pat.is_match(walker, base) {
                    return Some(*idx);
                }
            }
            return None;
        }
        let val = if self.context_decision {
            walker.context_bits(self.startbit, self.bitsize)
        } else {
            walker.instruction_bits(base, self.startbit, self.bitsize)
        };
        self.children.get(val as usize)?.resolve(walker, base)
    }
}

impl Pattern {
    fn is_match(&self, walker: &Walker, base: usize) -> bool {
        match self {
            Pattern::Instruction(b) => b.is_instruction_match(walker, base),
            Pattern::Context(b) => b.is_context_match(walker),
            Pattern::Combine { instr, context } => {
                instr.is_instruction_match(walker, base) && context.is_context_match(walker)
            }
        }
    }
}

impl PatternBlock {
    fn is_instruction_match(&self, walker: &Walker, base: usize) -> bool {
        if self.nonzero <= 0 {
            return self.nonzero == 0;
        }
        let mut off = self.offset as usize;
        for i in 0..self.mask.len() {
            let data = walker.instruction_bytes(base, off, 4);
            if self.mask[i] & data != self.val[i] {
                return false;
            }
            off += 4;
        }
        true
    }

    fn is_context_match(&self, walker: &Walker) -> bool {
        if self.nonzero <= 0 {
            return self.nonzero == 0;
        }
        let mut off = self.offset as usize;
        for i in 0..self.mask.len() {
            if self.mask[i] & walker.context_bytes(off) != self.val[i] {
                return false;
            }
            off += 4;
        }
        true
    }
}

// ---- parse tree (operand resolution) ----

/// A resolved constructor instance in the parse tree.
struct Node {
    subtable: usize,
    ctor_idx: usize,
    offset: usize, // absolute, from instruction start
    length: usize, // relative to `offset`
    operands: Vec<OpNode>,
}

enum OpNode {
    Sub(Box<Node>),
    Leaf { sym: u32, offset: usize, length: usize },
    Expr { op_id: u32, offset: usize, length: usize },
}

impl OpNode {
    fn end(&self) -> usize {
        match self {
            OpNode::Sub(n) => n.offset + n.length,
            OpNode::Leaf { offset, length, .. } | OpNode::Expr { offset, length, .. } => offset + length,
        }
    }
}

impl Spec {
    fn ctor_of(&self, node: &Node) -> &Constructor {
        &self.subtable(node.subtable).unwrap().constructors[node.ctor_idx]
    }

    /// True if the node's constructor emits a delay-slot directive (a
    /// DELAY_SLOT/`CPUI_INDIRECT` op in its p-code template).
    fn has_delay_slot(&self, node: &Node) -> bool {
        self.ctor_of(node)
            .tmpl
            .as_ref()
            .is_some_and(|t| t.ops.iter().any(|o| o.opcode == 61))
    }

    /// Build the parse tree for `subtable_id` at byte `offset` (Ghidra `Sleigh::resolve`).
    fn resolve(&self, walker: &Walker, subtable_id: usize, offset: usize) -> Option<Node> {
        let st = self.subtable(subtable_id)?;
        let ctor_idx = st.decision.as_ref()?.resolve(walker, offset)?;
        let ctor = st.constructors.get(ctor_idx)?;
        // Apply this constructor's context changes (e.g. REX prefix) before its
        // operands resolve, so they decode with the updated context.
        for cop in &ctor.context_ops {
            // Context-op values may reference operand values (e.g. `rexRprefix=rexr`)
            // before operands are resolved → evaluate them out-of-band.
            let val = self.eval(&cop.value, walker, Operands::Ctor(ctor, offset), offset) as u64;
            walker.apply_context(cop.word, cop.shift as u32, cop.mask, val);
        }
        let mut operands: Vec<OpNode> = Vec::with_capacity(ctor.operand_ids.len());
        for &op_id in &ctor.operand_ids {
            let op = self.operand(op_id)?;
            let base = if op.offsetbase < 0 {
                offset
            } else {
                operands.get(op.offsetbase as usize)?.end()
            };
            let op_offset = (base as i64 + op.reloffset) as usize;
            let len = op.minlen.max(0) as usize;
            match op.subsym {
                Some(sub) if matches!(self.symbol(sub), Some(Symbol::Subtable(_))) => {
                    operands.push(OpNode::Sub(Box::new(self.resolve(walker, sub as usize, op_offset)?)));
                }
                Some(sub) => operands.push(OpNode::Leaf { sym: sub, offset: op_offset, length: len }),
                None => operands.push(OpNode::Expr { op_id, offset: op_offset, length: len }),
            }
        }
        // calcCurrentLength: max(min_length, operand extents), back to relative.
        let mut length = ctor.min_length.max(0) as usize + offset;
        for o in &operands {
            length = length.max(o.end());
        }
        Some(Node { subtable: subtable_id, ctor_idx, offset, length: length - offset, operands })
    }

    fn render_node(&self, node: &Node, walker: &Walker) -> (String, String) {
        let ctor = self.ctor_of(node);
        // flowthru: a lone operand piece that refers to a sub-constructor
        if let [Piece::Operand(idx)] = ctor.print.as_slice() {
            if let Some(OpNode::Sub(sub)) = node.operands.get(*idx) {
                return self.render_node(sub, walker);
            }
        }
        let n = ctor.print.len();
        let split = if ctor.first_whitespace < 0 { n } else { (ctor.first_whitespace as usize).min(n) };
        let mnem = self.print_range(node, walker, 0, split);
        let body = self.print_range(node, walker, (split + 1).min(n), n);
        (mnem, body)
    }

    fn print_all(&self, node: &Node, walker: &Walker) -> String {
        let n = self.ctor_of(node).print.len();
        self.print_range(node, walker, 0, n)
    }

    fn print_range(&self, node: &Node, walker: &Walker, start: usize, end: usize) -> String {
        let ctor = self.ctor_of(node);
        let mut s = String::new();
        for piece in &ctor.print[start..end] {
            match piece {
                Piece::Literal(t) => s.push_str(t),
                Piece::Operand(idx) => {
                    if let Some(op) = node.operands.get(*idx) {
                        s.push_str(&self.print_operand(op, node, walker));
                    }
                }
            }
        }
        s
    }

    fn print_operand(&self, op: &OpNode, node: &Node, walker: &Walker) -> String {
        match op {
            OpNode::Sub(n) => self.print_all(n, walker),
            OpNode::Leaf { sym, offset, .. } => self.print_leaf(*sym, *offset, node, walker),
            OpNode::Expr { op_id, offset, .. } => match self.operand(*op_id).and_then(|o| o.defexp.as_ref()) {
                Some(e) => fmt_hex(self.eval(e, walker, Operands::Node(node), *offset)),
                None => "?".to_string(),
            },
        }
    }

    fn print_leaf(&self, sym: u32, offset: usize, node: &Node, walker: &Walker) -> String {
        match self.symbol(sym) {
            Some(Symbol::Varnode { .. }) => self.symbol_name(sym).to_string(),
            Some(Symbol::VarnodeList(vl)) => {
                let idx = self.eval(&vl.patval, walker, Operands::Node(node), offset) as usize;
                match vl.varnodes.get(idx).copied().flatten() {
                    Some(vn) => self.symbol_name(vn).to_string(),
                    None => "?".to_string(),
                }
            }
            Some(Symbol::Value(e)) => fmt_hex(self.eval(e, walker, Operands::Node(node), offset)),
            Some(Symbol::ValueMap { patval, table }) => {
                let idx = self.eval(patval, walker, Operands::Node(node), offset) as usize;
                table.get(idx).map_or_else(|| "?".to_string(), |v| fmt_hex(*v))
            }
            Some(Symbol::Name { patval, table }) => {
                let idx = self.eval(patval, walker, Operands::Node(node), offset) as usize;
                table.get(idx).cloned().unwrap_or_else(|| "?".to_string())
            }
            _ => "?".to_string(),
        }
    }

    fn build_pcode_node(&self, node: &Node, walker: &Walker) -> Vec<PcodeOp> {
        let mut ops = Vec::new();
        self.build_into(node, walker, &mut ops);
        ops
    }
}

fn fmt_hex(v: i64) -> String {
    if v >= 0 {
        format!("0x{v:x}")
    } else {
        // `-v` overflows for i64::MIN; take the magnitude as unsigned.
        format!("-0x{:x}", v.unsigned_abs())
    }
}

/// Operand context for expression evaluation (`OperandValue` resolution).
#[derive(Clone, Copy)]
enum Operands<'a> {
    None,
    /// Resolved parse-tree node (during rendering).
    Node(&'a Node),
    /// A constructor being resolved, out-of-band (during context-op application,
    /// before the parse tree exists).
    Ctor(&'a Constructor, usize),
}

impl Spec {
    fn eval(&self, e: &PatternExpr, walker: &Walker, ops: Operands, offset: usize) -> i64 {
        match e {
            PatternExpr::Token { bigendian, signbit, bitstart, bitend, bytestart, byteend, shift } => {
                let size = (byteend - bytestart + 1).max(1) as usize;
                let mut res = 0u64;
                for i in 0..size {
                    res = (res << 8) | walker.byte(offset + *bytestart as usize + i) as u64;
                }
                if !bigendian {
                    res = byte_swap(res, size);
                }
                extend(res >> shift, (bitend - bitstart).max(0) as u32, *signbit)
            }
            PatternExpr::Context { signbit, startbit, endbit, startbyte, endbyte, shift } => {
                let mut res = 0u64;
                for b in *startbyte as usize..=*endbyte as usize {
                    res = (res << 8) | walker.context_byte(b) as u64;
                }
                extend(res >> shift, (endbit - startbit).max(0) as u32, *signbit)
            }
            PatternExpr::Constant(v) => *v,
            PatternExpr::Start => walker.addr as i64,
            PatternExpr::End => walker.next.get() as i64,
            PatternExpr::Next2 => 0,
            PatternExpr::Operand(i) => match ops {
                Operands::Node(n) => self.operand_value(n, *i, walker),
                Operands::Ctor(c, coff) => self.operand_value_oob(c, *i, walker, coff),
                Operands::None => 0,
            },
            PatternExpr::Bin(op, a, b) => {
                let (x, y) = (self.eval(a, walker, ops, offset), self.eval(b, walker, ops, offset));
                match op {
                    BinOp::Add => x.wrapping_add(y),
                    BinOp::Sub => x.wrapping_sub(y),
                    BinOp::Mul => x.wrapping_mul(y),
                    BinOp::Div => if y != 0 { x / y } else { 0 },
                    BinOp::LShift => x.wrapping_shl(y as u32),
                    BinOp::RShift => x.wrapping_shr(y as u32),
                    BinOp::And => x & y,
                    BinOp::Or => x | y,
                    BinOp::Xor => x ^ y,
                }
            }
            PatternExpr::Un(op, a) => {
                let x = self.eval(a, walker, ops, offset);
                match op {
                    UnOp::Minus => x.wrapping_neg(),
                    UnOp::Not => !x,
                }
            }
        }
    }

    /// Value of a resolved sibling operand `i` (`OperandValue` during render).
    fn operand_value(&self, node: &Node, i: usize, walker: &Walker) -> i64 {
        let Some(op) = node.operands.get(i) else { return 0 };
        match op {
            OpNode::Leaf { sym, offset, .. } => self.leaf_value(*sym, *offset, Operands::Node(node), walker),
            OpNode::Expr { op_id, offset, .. } => match self.operand(*op_id).and_then(|o| o.defexp.as_ref()) {
                Some(e) => self.eval(e, walker, Operands::Node(node), *offset),
                None => 0,
            },
            OpNode::Sub(_) => 0,
        }
    }

    /// Value of operand `i` of a constructor being resolved, before the parse tree
    /// exists (for context ops like `rexRprefix=rexr`).
    fn operand_value_oob(&self, ctor: &Constructor, i: usize, walker: &Walker, ctor_offset: usize) -> i64 {
        let Some(op) = ctor.operand_ids.get(i).and_then(|id| self.operand(*id)) else { return 0 };
        let off = (ctor_offset as i64 + op.reloffset) as usize;
        let ops = Operands::Ctor(ctor, ctor_offset);
        match op.subsym {
            Some(sub) => self.leaf_value(sub, off, ops, walker),
            None => op.defexp.as_ref().map_or(0, |e| self.eval(e, walker, ops, off)),
        }
    }

    /// Evaluate a leaf symbol's value (Value / ValueMap / VarnodeList index).
    fn leaf_value(&self, sym: u32, offset: usize, ops: Operands, walker: &Walker) -> i64 {
        match self.symbol(sym) {
            Some(Symbol::Value(e)) => self.eval(e, walker, ops, offset),
            Some(Symbol::ValueMap { patval, table }) => {
                let idx = self.eval(patval, walker, ops, offset) as usize;
                table.get(idx).copied().unwrap_or(0)
            }
            Some(Symbol::VarnodeList(vl)) => self.eval(&vl.patval, walker, ops, offset),
            _ => 0,
        }
    }
}

fn byte_swap(val: u64, size: usize) -> u64 {
    let mut res = 0u64;
    let mut v = val;
    for _ in 0..size {
        res = (res << 8) | (v & 0xff);
        v >>= 8;
    }
    res
}

/// Extend the low `hi+1` bits of `val`, signed or zero.
fn extend(val: u64, hi: u32, signed: bool) -> i64 {
    if hi >= 63 {
        return val as i64;
    }
    let masked = val & ((1u64 << (hi + 1)) - 1);
    if signed {
        let sign = 1u64 << hi;
        (masked ^ sign).wrapping_sub(sign) as i64
    } else {
        masked as i64
    }
}
