//! C emission — Ghidra's `PrintC` (`printc.cc`). Walks the structured-block tree
//! ([`structure`](super::structure)), renders each op as a C expression (inlining
//! single-use values, naming the [`merge`](super::merge) HighVariables), and emits
//! statements + control flow.
//!
//! This increment handles expressions, variable naming, the function signature, and the
//! linear case (basic blocks / lists). Structured control flow (`if`/`while`) emission,
//! casts, and faithful types are the next increments. The return value is located
//! heuristically (the last write to a return register) until P6 ActionReturnRecovery wires
//! it to RETURN.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use super::block::BlockId;
use super::funcdata::Funcdata;
use super::infertypes::infer;
use super::merge::{merge, HighVariables};
use super::op::OpId;
use super::opcode::OpCode;
use super::structure::{structure, FlowKind, Structured};
use super::types::Datatype;
use super::varnode::VarnodeId;

/// Collect the basic blocks under a structured block (its loop body, etc.).
fn basic_blocks_of(s: &Structured, idx: usize, acc: &mut Vec<BlockId>) {
    match &s.blocks[idx].kind {
        FlowKind::Basic(b) => acc.push(*b),
        _ => {
            for &c in &s.blocks[idx].components {
                basic_blocks_of(s, c, acc);
            }
        }
    }
}

/// The exit basic block of a structured block (where its terminating CBRANCH lives).
fn exit_basic(s: &Structured, idx: usize) -> Option<BlockId> {
    match &s.blocks[idx].kind {
        FlowKind::Basic(b) => Some(*b),
        _ => exit_basic(s, *s.blocks[idx].components.last()?),
    }
}

/// The entry basic block of a structured block (where a case/label starts).
fn entry_basic(s: &Structured, idx: usize) -> Option<BlockId> {
    match &s.blocks[idx].kind {
        FlowKind::Basic(b) => Some(*b),
        _ => entry_basic(s, *s.blocks[idx].components.first()?),
    }
}

/// Ghidra's C name for an N-byte IEEE float.
fn float_name(size: u32) -> String {
    match size {
        4 => "float".to_string(),
        8 => "double".to_string(),
        10 | 16 => "longdouble".to_string(),
        n => format!("float{n}"),
    }
}

/// Ghidra's one-letter type prefix for a variable/global name.
fn type_prefix(t: &Datatype) -> &'static str {
    match t {
        Datatype::Int(_) => "i",
        Datatype::Uint(_) => "u",
        Datatype::Bool => "b",
        Datatype::Float(_) => "f",
        Datatype::Pointer(..) => "p",
        _ => "x",
    }
}

/// The 64-bit name of an x86-64 integer register by offset (for `extraout_*` etc.).
fn reg64_name(offset: u64) -> Option<&'static str> {
    Some(match offset {
        0x0 => "RAX",
        0x38 => "RDI",
        0x30 => "RSI",
        0x10 => "RDX",
        0x08 => "RCX",
        0x80 => "R8",
        0x88 => "R9",
        _ => return None,
    })
}

/// SysV integer parameter registers → `param_N`.
fn param_name(space_is_reg: bool, offset: u64) -> Option<&'static str> {
    if !space_is_reg {
        return None;
    }
    Some(match offset {
        0x38 => "param_1", // RDI
        0x30 => "param_2", // RSI
        0x10 => "param_3", // RDX
        0x08 => "param_4", // RCX
        0x80 => "param_5", // R8
        0x88 => "param_6", // R9
        _ => return None,
    })
}

struct PrintC<'a> {
    f: &'a Funcdata,
    h: HighVariables,
    names: HashMap<u32, String>,
    reg_space: Option<super::space::SpaceId>,
    ram_space: Option<super::space::SpaceId>,
    var_counter: u32,
    ret_val: Option<VarnodeId>,
    types: HashMap<VarnodeId, Datatype>,
    /// WhileDo block index → (initializer value, iterator op, loop variable) for `for`-loops.
    for_loops: HashMap<usize, (Option<VarnodeId>, OpId, VarnodeId)>,
    /// Ops emitted in a `for` header (initializer/iterator) — suppressed in their block.
    suppressed: HashSet<OpId>,
    /// Pointer base → element size, for bases accessed uniformly as an array (so the access
    /// renders `base[i]`). Non-uniform bases (struct-like) are absent and stay `*(base+k)`.
    array_elem: HashMap<VarnodeId, u32>,
    /// Goto edges cut for irreducible regions: source block → (target, negated condition).
    gotos: HashMap<BlockId, (BlockId, bool)>,
    /// Basic blocks that are goto targets (emitted with a label).
    labels: HashSet<BlockId>,
}

impl PrintC<'_> {
    fn type_of(&self, v: VarnodeId) -> Datatype {
        self.types.get(&v).cloned().unwrap_or_else(|| Datatype::default_for(self.f.vn(v).size))
    }
}

impl<'a> PrintC<'a> {
    /// Whether a varnode is printed as its own named variable (vs inlined into its use).
    fn is_explicit(&self, v: VarnodeId) -> bool {
        let vn = self.f.vn(v);
        if vn.is_constant() {
            return false;
        }
        if vn.is_input() {
            return true;
        }
        if !vn.is_written() {
            return true;
        }
        if let Some(def) = vn.def {
            // a phi is a merged variable, and an INDIRECT (a value clobbered by a call) is an
            // opaque `extraout_*` — both are always named, never inlined raw
            if matches!(self.f.op(def).code(), OpCode::Multiequal | OpCode::Indirect) {
                return true;
            }
        }
        if vn.descend.len() != 1 {
            return true; // 0 or >1 uses: named
        }
        // single use: inline, unless it feeds a phi — then it must be materialized as an
        // assignment to the merged variable (the loop increment `i = i + 1`, the init `i = 0`)
        self.f.op(vn.descend[0]).code() == OpCode::Multiequal
    }

    /// The name of `v`'s variable, assigning one on first use.
    fn name_of(&mut self, v: VarnodeId) -> String {
        let vn = self.f.vn(v);
        let is_reg = Some(vn.loc.space) == self.reg_space;
        if vn.is_input() {
            if let Some(p) = param_name(is_reg, vn.loc.offset) {
                return p.to_string();
            }
        }
        // a direct global — a constant-address access in `ram` — is named by its address,
        // like Ghidra's `<typeprefix>Ram<addr>` (e.g. `iRam0000000000101000`)
        if Some(vn.loc.space) == self.ram_space {
            let (off, prefix) = (vn.loc.offset, type_prefix(&self.type_of(v)));
            return format!("{prefix}Ram{off:016x}");
        }
        // a value left in a caller-saved register by a call (an INDIRECT def) is Ghidra's
        // `extraout_<reg>`
        if is_reg {
            if let Some(def) = vn.def {
                if self.f.op(def).code() == OpCode::Indirect {
                    if let Some(r) = reg64_name(vn.loc.offset) {
                        return format!("extraout_{r}");
                    }
                }
            }
        }
        let id = self.h.high(v);
        if let Some(n) = self.names.get(&id) {
            return n.clone();
        }
        self.var_counter += 1;
        let n = format!("uVar{}", self.var_counter);
        self.names.insert(id, n.clone());
        n
    }

    /// Render a varnode as a C expression with its operator precedence (16 = atomic).
    fn render_var(&mut self, v: VarnodeId) -> (String, u8) {
        let vn = self.f.vn(v);
        if vn.is_constant() {
            return (render_const(vn.constant_value(), vn.size), 16);
        }
        if self.is_explicit(v) {
            return (self.name_of(v), 16);
        }
        match vn.def {
            Some(def) => self.render_op(def),
            None => (self.name_of(v), 16),
        }
    }

    /// Render `v` as an operand of an operator of precedence `parent`, parenthesizing when
    /// the sub-expression binds looser (`right` operands also parenthesize at equal
    /// precedence, for left-associativity).
    fn operand(&mut self, v: VarnodeId, parent: u8, right: bool) -> String {
        let (s, p) = self.render_var(v);
        if p < parent || (right && p == parent) {
            format!("({s})")
        } else {
            s
        }
    }

    /// If `base` is the stack/frame pointer (RSP 0x20 / RBP 0x28) and `off` a constant, this
    /// is the address of a stack local taken as a value — render `&Stack_<offset>`.
    fn stack_addr(&self, base: VarnodeId, off: VarnodeId) -> Option<String> {
        let bvn = self.f.vn(base);
        let is_fp = Some(bvn.loc.space) == self.reg_space && matches!(bvn.loc.offset, 0x20 | 0x28);
        if !is_fp || !self.f.vn(off).is_constant() {
            return None;
        }
        let c = self.f.vn(off).constant_value() as i64;
        Some(format!("&Stack_{:x}", c.unsigned_abs()))
    }

    /// If `off` is `idx * size` (a scaled array index), return `idx`.
    fn scaled_index(&self, off: VarnodeId, size: u32) -> Option<VarnodeId> {
        let def = self.f.vn(off).def?;
        let o = self.f.op(def);
        if o.code() == OpCode::IntMult && o.num_inputs() == 2 {
            let c = o.input(1)?;
            if self.f.vn(c).is_constant() && self.f.vn(c).constant_value() == size as u64 {
                return o.input(0);
            }
        }
        None
    }

    /// Decompose a load/store address into `(base, index-fits-an-array-of `size`)`. The base
    /// is the pointer; the bool is whether the offset is a clean array index (a constant
    /// multiple of `size`, or a variable scaled by `size`, or zero).
    fn addr_base(&self, addr: VarnodeId, size: u32) -> (VarnodeId, bool) {
        if let Some(def) = self.f.vn(addr).def {
            let o = self.f.op(def);
            if o.code() == OpCode::IntAdd && o.num_inputs() == 2 {
                let (base, off) = (o.input(0).unwrap(), o.input(1).unwrap());
                let ok = (self.f.vn(off).is_constant()
                    && size > 0
                    && self.f.vn(off).constant_value() % size as u64 == 0)
                    || self.scaled_index(off, size).is_some();
                return (base, ok);
            }
        }
        (addr, true) // direct deref — element 0
    }

    /// Infer which pointer bases are accessed uniformly as an array (Ghidra's pointee
    /// inference, from the access pattern): a base qualifies only if every access through it
    /// uses the same element size and lands on a clean array index. Struct-like bases (mixed
    /// sizes/offsets) are excluded and keep `*(base + k)`.
    fn detect_arrays(&self) -> HashMap<VarnodeId, u32> {
        let mut info: HashMap<VarnodeId, Option<u32>> = HashMap::new();
        for op in self.f.op_ids() {
            let o = self.f.op(op);
            let (addr, size) = match o.code() {
                OpCode::Load => (o.input(1), o.output.map(|v| self.f.vn(v).size)),
                OpCode::Store => (o.input(1), o.input(2).map(|v| self.f.vn(v).size)),
                _ => continue,
            };
            let (Some(addr), Some(size)) = (addr, size) else { continue };
            if size == 0 {
                continue;
            }
            let (base, ok) = self.addr_base(addr, size);
            if !matches!(self.type_of(base), Datatype::Pointer(..)) {
                continue;
            }
            let e = info.entry(base).or_insert(Some(size));
            if !(ok && *e == Some(size)) {
                *e = None; // mixed element size or non-array offset — disqualify
            }
        }
        info.into_iter().filter_map(|(b, s)| s.map(|sz| (b, sz))).collect()
    }

    /// Render a memory access `*addr` of `size` bytes — `base[i]` for a detected array base
    /// (non-zero index), else `*addr`.
    fn render_mem(&mut self, addr: VarnodeId, _size: u32) -> (String, u8) {
        if let Some(def) = self.f.vn(addr).def {
            let o = self.f.op(def).clone();
            if o.code() == OpCode::IntAdd && o.num_inputs() == 2 {
                let (base, off) = (o.input(0).unwrap(), o.input(1).unwrap());
                if let Some(&elem) = self.array_elem.get(&base) {
                    if self.f.vn(off).is_constant() && elem > 0 {
                        let c = self.f.vn(off).constant_value();
                        if c != 0 && c % elem as u64 == 0 {
                            let b = self.operand(base, 16, false);
                            return (format!("{b}[{}]", c / elem as u64), 16);
                        }
                    } else if let Some(idx) = self.scaled_index(off, elem) {
                        let b = self.operand(base, 16, false);
                        let i = self.render_var(idx).0;
                        return (format!("{b}[{i}]"), 16);
                    }
                }
            }
        }
        (format!("*{}", self.operand(addr, 15, false)), 15)
    }

    /// Render an op as a C expression with its precedence.
    fn render_op(&mut self, op: super::op::OpId) -> (String, u8) {
        let o = self.f.op(op);
        let a = |i: usize| o.input(i).unwrap();
        let bin = |s: &mut Self, sym: &str, prec: u8| {
            let l = s.operand(a(0), prec, false);
            let r = s.operand(a(1), prec, true);
            (format!("{l} {sym} {r}"), prec)
        };
        match o.code() {
            // ZEXT (the implicit x86 32→64 zero-extension) and SUBPIECE stay transparent;
            // SEXT is an explicit signed widening that Ghidra prints as a cast
            OpCode::Copy | OpCode::IntZext | OpCode::Subpiece => self.render_var(a(0)),
            OpCode::IntSext => {
                let n = self.f.vn(o.output.unwrap()).size;
                let in0 = a(0);
                (format!("(int{n}){}", self.operand(in0, 14, false)), 14)
            }
            OpCode::IntMult => bin(self, "*", 13),
            OpCode::IntDiv | OpCode::IntSdiv => bin(self, "/", 13),
            OpCode::IntRem | OpCode::IntSrem => bin(self, "%", 13),
            OpCode::IntAdd => {
                // a frame-pointer-relative address taken as a value is `&Stack_<offset>`
                let (i0, i1) = (a(0), a(1));
                match self.stack_addr(i0, i1) {
                    Some(s) => (s, 15),
                    None => bin(self, "+", 12),
                }
            }
            OpCode::IntSub => bin(self, "-", 12),
            OpCode::IntLeft => bin(self, "<<", 11),
            OpCode::IntRight | OpCode::IntSright => bin(self, ">>", 11),
            OpCode::IntLess | OpCode::IntSless => bin(self, "<", 10),
            OpCode::IntLessequal | OpCode::IntSlessequal => bin(self, "<=", 10),
            OpCode::IntEqual => bin(self, "==", 9),
            OpCode::IntNotequal => bin(self, "!=", 9),
            OpCode::IntAnd => bin(self, "&", 8),
            OpCode::IntXor | OpCode::BoolXor => bin(self, "^", 7),
            OpCode::IntOr => bin(self, "|", 6),
            OpCode::BoolAnd => bin(self, "&&", 5),
            OpCode::BoolOr => bin(self, "||", 4),
            OpCode::IntNegate => (format!("~{}", self.operand(a(0), 15, false)), 15),
            OpCode::Int2comp => (format!("-{}", self.operand(a(0), 15, false)), 15),
            OpCode::BoolNegate => (format!("!{}", self.operand(a(0), 15, false)), 15),
            // floating point: arithmetic and comparisons as operators
            OpCode::FloatAdd => bin(self, "+", 12),
            OpCode::FloatSub => bin(self, "-", 12),
            OpCode::FloatMult => bin(self, "*", 13),
            OpCode::FloatDiv => bin(self, "/", 13),
            OpCode::FloatLess => bin(self, "<", 10),
            OpCode::FloatLessequal => bin(self, "<=", 10),
            OpCode::FloatEqual => bin(self, "==", 9),
            OpCode::FloatNotequal => bin(self, "!=", 9),
            OpCode::FloatNeg => (format!("-{}", self.operand(a(0), 15, false)), 15),
            // float intrinsics Ghidra prints as named calls
            OpCode::FloatNan => (format!("NAN({})", self.render_var(a(0)).0), 16),
            OpCode::FloatAbs => (format!("ABS({})", self.render_var(a(0)).0), 16),
            OpCode::FloatSqrt => (format!("SQRT({})", self.render_var(a(0)).0), 16),
            OpCode::FloatCeil => (format!("ceil({})", self.render_var(a(0)).0), 16),
            OpCode::FloatFloor => (format!("floor({})", self.render_var(a(0)).0), 16),
            OpCode::FloatRound => (format!("round({})", self.render_var(a(0)).0), 16),
            // conversions render as casts (to the output float/int width)
            OpCode::FloatInt2float | OpCode::FloatFloat2float => {
                let ty = float_name(self.f.vn(o.output.unwrap()).size);
                let in0 = a(0);
                (format!("({ty}){}", self.operand(in0, 14, false)), 14)
            }
            OpCode::FloatTrunc => {
                let n = self.f.vn(o.output.unwrap()).size;
                let in0 = a(0);
                (format!("(int{n}){}", self.operand(in0, 14, false)), 14)
            }
            OpCode::Load => {
                let (addr, sz) = (a(1), self.f.vn(o.output.unwrap()).size);
                self.render_mem(addr, sz)
            }
            OpCode::Call => {
                // input 0 is the (constant) call target — name it func_0x<addr>, like Ghidra
                let name = match o.input(0) {
                    Some(t) => format!("func_0x{:08x}", self.f.vn(t).loc.offset),
                    None => "func".to_string(),
                };
                let args: Vec<String> = (1..o.num_inputs()).map(|i| self.render_var(a(i)).0).collect();
                (format!("{name}({})", args.join(", ")), 16)
            }
            OpCode::Callind => {
                // indirect call through a computed target — Ghidra casts it to a code pointer
                let tgt = self.operand(a(0), 16, false);
                let args: Vec<String> = (1..o.num_inputs()).map(|i| self.render_var(a(i)).0).collect();
                (format!("(*(code *){tgt})({})", args.join(", ")), 16)
            }
            other => (format!("{}(...)", other.name()), 16),
        }
    }

    /// The function's return value: the value wired into a RETURN by return recovery (its
    /// second input), or `None` for a void function.
    fn return_value(&self) -> Option<VarnodeId> {
        self.f
            .op_ids()
            .find(|&op| self.f.op(op).code() == OpCode::Return && self.f.op(op).num_inputs() > 1)
            .and_then(|op| self.f.op(op).input(1))
    }

    /// Render an assignment statement body (`lhs = rhs`, no terminator) for an op.
    fn render_assign(&mut self, op: OpId) -> String {
        let outv = self.f.op(op).output.unwrap();
        let lhs = self.name_of(outv);
        let rhs = self.render_op(op).0;
        format!("{lhs} = {rhs}")
    }

    /// Walk back (≤4 levels, Ghidra's `findLoopVariable`) from the condition variable to a
    /// MULTIEQUAL defined in the loop header `head`.
    fn find_loop_phi(&self, cond_var: VarnodeId, head: BlockId) -> Option<OpId> {
        let mut stack = vec![(cond_var, 0u32)];
        let mut seen: HashSet<OpId> = HashSet::new();
        while let Some((v, depth)) = stack.pop() {
            let Some(def) = self.f.vn(v).def else { continue };
            if !seen.insert(def) {
                continue;
            }
            let o = self.f.op(def);
            if o.code() == OpCode::Multiequal {
                if o.parent == Some(head) {
                    return Some(def);
                }
                continue; // don't trace through a phi
            }
            if depth >= 4 || matches!(o.code(), OpCode::Call | OpCode::Callind) {
                continue;
            }
            for &inp in &o.inrefs.clone() {
                stack.push((inp, depth + 1));
            }
        }
        None
    }

    /// If the WhileDo with header `cond_idx` and body `body_idx` is a `for`-loop, return its
    /// `(initializer, iterator)` ops (Ghidra `findLoopVariable`/`findInitializer`): the
    /// condition variable's loop-header phi has one input defined in the body (the iterator)
    /// and one defined before the loop (the initializer).
    fn for_parts(
        &self,
        s: &Structured,
        cond_idx: usize,
        body_idx: usize,
    ) -> Option<(Option<VarnodeId>, OpId, VarnodeId)> {
        let head = exit_basic(s, cond_idx)?;
        let cbranch = self
            .f
            .block(head)
            .ops
            .iter()
            .rev()
            .copied()
            .find(|&op| self.f.op(op).code() == OpCode::Cbranch)?;
        let cond_var = self.f.op(cbranch).input(1)?;
        let phi = self.find_loop_phi(cond_var, head)?;
        let phi_out = self.f.op(phi).output?;

        let mut body_blocks = Vec::new();
        basic_blocks_of(s, body_idx, &mut body_blocks);

        // the phi's body-defined input is the iterator; its other input is the initializer
        // value (often a folded constant, so carry the varnode rather than a defining op)
        let (mut iterate, mut init_var) = (None, None);
        for &inp in &self.f.op(phi).inrefs {
            let in_body = match self.f.vn(inp).def {
                Some(d) => {
                    self.f.op(d).parent.is_some_and(|pb| body_blocks.contains(&pb))
                        && !self.f.op(d).is_marker()
                }
                None => false,
            };
            if in_body {
                iterate = self.f.vn(inp).def;
            } else {
                init_var = Some(inp);
            }
        }
        iterate.map(|it| (init_var, it, phi_out))
    }

    /// Find all `for`-loops in the structure tree and record their parts.
    fn detect_for_loops(&mut self, s: &Structured, idx: usize) {
        if let FlowKind::WhileDo = s.blocks[idx].kind {
            let comps = s.blocks[idx].components.clone();
            if let Some((init_var, iterate, phi_out)) = self.for_parts(s, comps[0], comps[1]) {
                self.for_loops.insert(idx, (init_var, iterate, phi_out));
                self.suppressed.insert(iterate);
                // a non-constant initializer is a real op in the pre-loop block — suppress it
                if let Some(d) = init_var.and_then(|iv| self.f.vn(iv).def) {
                    self.suppressed.insert(d);
                }
            }
        }
        for &c in &s.blocks[idx].components.clone() {
            self.detect_for_loops(s, c);
        }
    }

    /// The boolean tested by a condition block — the CBRANCH operand for a basic block, or
    /// the joined operands of a short-circuit `&&`/`||`.
    fn render_cond_expr(&mut self, s: &Structured, idx: usize) -> String {
        let comps = s.blocks[idx].components.clone();
        match s.blocks[idx].kind {
            FlowKind::CondAnd => {
                let (a, b) = (self.render_cond_operand(s, comps[0]), self.render_cond_operand(s, comps[1]));
                format!("{a} && {b}")
            }
            FlowKind::CondOr => {
                let (a, b) = (self.render_cond_operand(s, comps[0]), self.render_cond_operand(s, comps[1]));
                format!("{a} || {b}")
            }
            _ => exit_basic(s, idx)
                .and_then(|bid| {
                    self.f.block(bid).ops.iter().rev().copied().find(|&op| self.f.op(op).code() == OpCode::Cbranch)
                })
                .and_then(|cbr| self.f.op(cbr).input(1))
                .map(|v| self.render_var(v).0)
                .unwrap_or_else(|| "1".into()),
        }
    }

    /// A short-circuit operand, parenthesized (Ghidra's `(a) && (b)` style).
    fn render_cond_operand(&mut self, s: &Structured, idx: usize) -> String {
        format!("({})", self.render_cond_expr(s, idx))
    }

    /// The condition of an `if`/`while`, negated when the body is on the false edge. The
    /// negation is pushed into the expression (Ghidra's print-time boolean negation) rather
    /// than wrapped in `!(...)`: `!(!x)` cancels, `==`/`!=` flip.
    fn render_condition(&mut self, s: &Structured, cond_idx: usize, negated: bool) -> String {
        // short-circuit conditions: render the join, negate with !(...) (no De Morgan)
        if matches!(s.blocks[cond_idx].kind, FlowKind::CondAnd | FlowKind::CondOr) {
            let cond = self.render_cond_expr(s, cond_idx);
            return if negated { format!("!({cond})") } else { cond };
        }
        let cvar = exit_basic(s, cond_idx)
            .and_then(|bid| {
                self.f.block(bid).ops.iter().rev().copied().find(|&op| self.f.op(op).code() == OpCode::Cbranch)
            })
            .and_then(|cbr| self.f.op(cbr).input(1));
        match cvar {
            Some(v) if negated => self.render_negated(v),
            Some(v) => self.render_var(v).0,
            None => if negated { "!(1)".to_string() } else { "1".to_string() },
        }
    }

    /// Render the logical negation of boolean `v`, folding double negation and flipping
    /// equality (Ghidra's print-time negation); falls back to `!(...)`.
    fn render_negated(&mut self, v: VarnodeId) -> String {
        if let Some(def) = self.f.vn(v).def {
            let code = self.f.op(def).code();
            match code {
                OpCode::BoolNegate => {
                    let inner = self.f.op(def).input(0).unwrap();
                    return self.render_var(inner).0; // !(!x) => x
                }
                OpCode::IntEqual | OpCode::IntNotequal => {
                    let (i0, i1) = (self.f.op(def).input(0).unwrap(), self.f.op(def).input(1).unwrap());
                    let sym = if code == OpCode::IntEqual { "!=" } else { "==" };
                    let l = self.operand(i0, 9, false);
                    let r = self.operand(i1, 9, true);
                    return format!("{l} {sym} {r}");
                }
                // !(a < b) => b <= a ; !(a <= b) => b < a (swap operands, flip strictness)
                OpCode::IntLess | OpCode::IntSless | OpCode::IntLessequal | OpCode::IntSlessequal => {
                    let (i0, i1) = (self.f.op(def).input(0).unwrap(), self.f.op(def).input(1).unwrap());
                    let sym = if matches!(code, OpCode::IntLess | OpCode::IntSless) { "<=" } else { "<" };
                    let l = self.operand(i1, 9, false);
                    let r = self.operand(i0, 9, true);
                    return format!("{l} {sym} {r}");
                }
                _ => {}
            }
        }
        format!("!{}", self.operand(v, 15, false))
    }

    /// Emit a structured block (and its children) as C.
    fn emit_structured(&mut self, s: &Structured, idx: usize, indent: usize, out: &mut String) {
        let pad = "  ".repeat(indent);
        let fb = &s.blocks[idx];
        let (kind, comps, negated) = (fb.kind.clone(), fb.components.clone(), fb.negated);
        match kind {
            FlowKind::Basic(bid) => self.emit_basic(bid, indent, out),
            // a short-circuit condition: its operands are inlined by render_condition; emit
            // only any side-effecting statements they carry (rare)
            FlowKind::CondAnd | FlowKind::CondOr => {
                for c in comps {
                    self.emit_structured(s, c, indent, out);
                }
            }
            FlowKind::Switch => {
                let head = exit_basic(s, comps[0]);
                let head_pc = head.and_then(|b| {
                    self.f.block(b).ops.iter().rev().copied().find(|&op| self.f.op(op).code() == OpCode::Branchind).map(|op| self.f.op(op).seqnum.pc.offset)
                });
                let idx = head
                    .and_then(|b| self.switch_index(b))
                    .map(|v| self.render_var(v).0)
                    .unwrap_or_else(|| "switchD".to_string());
                let _ = writeln!(out, "{pad}switch ({idx}) {{");
                for &case in &comps[1..] {
                    if let (Some(pc), Some(cb)) = (head_pc, entry_basic(s, case)) {
                        let addr = self.f.block_range(cb).map(|(a, _)| a).unwrap_or(0);
                        for v in self.case_labels(pc, addr) {
                            let _ = writeln!(out, "{pad}case {v}:");
                        }
                    }
                    self.emit_structured(s, case, indent + 1, out);
                }
                let _ = writeln!(out, "{pad}}}");
            }
            FlowKind::List => {
                for c in comps {
                    self.emit_structured(s, c, indent, out);
                }
            }
            FlowKind::If => {
                self.emit_structured(s, comps[0], indent, out);
                let cond = self.render_condition(s, comps[0], negated);
                let _ = writeln!(out, "{pad}if ({cond}) {{");
                self.emit_structured(s, comps[1], indent + 1, out);
                let _ = writeln!(out, "{pad}}}");
            }
            FlowKind::IfElse => {
                self.emit_structured(s, comps[0], indent, out);
                let cond = self.render_condition(s, comps[0], negated);
                let _ = writeln!(out, "{pad}if ({cond}) {{");
                self.emit_structured(s, comps[1], indent + 1, out);
                let _ = writeln!(out, "{pad}}}");
                let _ = writeln!(out, "{pad}else {{");
                self.emit_structured(s, comps[2], indent + 1, out);
                let _ = writeln!(out, "{pad}}}");
            }
            FlowKind::WhileDo => {
                self.emit_structured(s, comps[0], indent, out);
                if let Some((init_var, iterate, phi_out)) = self.for_loops.get(&idx).copied() {
                    let init_s = match init_var {
                        Some(iv) => {
                            let lhs = self.name_of(phi_out);
                            let rhs = match self.f.vn(iv).def {
                                Some(d) => self.render_op(d).0, // the initializer's expression
                                None => self.render_var(iv).0,  // a folded constant / input
                            };
                            format!("{lhs} = {rhs}")
                        }
                        None => String::new(),
                    };
                    let cond = self.render_condition(s, comps[0], negated);
                    let iter_s = self.render_assign(iterate);
                    let _ = writeln!(out, "{pad}for ({init_s}; {cond}; {iter_s}) {{");
                    self.emit_structured(s, comps[1], indent + 1, out);
                    let _ = writeln!(out, "{pad}}}");
                } else {
                    let cond = self.render_condition(s, comps[0], negated);
                    let _ = writeln!(out, "{pad}while ({cond}) {{");
                    self.emit_structured(s, comps[1], indent + 1, out);
                    let _ = writeln!(out, "{pad}}}");
                }
            }
            FlowKind::DoWhile => {
                let _ = writeln!(out, "{pad}do {{");
                self.emit_structured(s, comps[0], indent + 1, out);
                let cond = self.render_condition(s, comps[0], negated);
                let _ = writeln!(out, "{pad}}} while ({cond});");
            }
        }
    }

    /// Emit one basic block's statements (skipping control-flow and inlined ops).
    fn emit_basic(&mut self, b: super::block::BlockId, indent: usize, out: &mut String) {
        let pad = "  ".repeat(indent);
        if self.labels.contains(&b) {
            let _ = writeln!(out, "{}{}:", "  ".repeat(indent.saturating_sub(1)), self.lab_name(b));
        }
        for op in self.f.block(b).ops.clone() {
            if self.suppressed.contains(&op) {
                continue; // emitted in a for-loop header (initializer / iterator)
            }
            let o = self.f.op(op);
            match o.code() {
                OpCode::Cbranch | OpCode::Branch | OpCode::Branchind | OpCode::Multiequal | OpCode::Indirect => {}
                OpCode::Return => match o.input(1) {
                    Some(v) => {
                        let e = self.render_var(v).0; // wired return value (inlined when single-use)
                        let _ = writeln!(out, "{pad}return {e};");
                    }
                    None => {
                        let _ = writeln!(out, "{pad}return;");
                    }
                },
                OpCode::Store => {
                    let (addr, vv) = (o.input(1).unwrap(), o.input(2).unwrap());
                    let sz = self.f.vn(vv).size;
                    let lhs = self.render_mem(addr, sz).0;
                    let val = self.render_var(vv).0;
                    let _ = writeln!(out, "{pad}{lhs} = {val};");
                }
                OpCode::Call | OpCode::Callind => {
                    // a call is a statement (it has a side effect); its result inlines at the
                    // single consumer, is named when used more than once, and is dropped when
                    // unused — but a void call must still be emitted.
                    let out_vn = o.output;
                    let uses = out_vn.map(|v| self.f.vn(v).descend.len());
                    match (out_vn, uses) {
                        (Some(_), Some(1)) => {} // single-use result: inlined into its consumer
                        (Some(outv), Some(n)) if n > 1 => {
                            let lhs = self.name_of(outv);
                            let rhs = self.render_op(op).0;
                            let _ = writeln!(out, "{pad}{lhs} = {rhs};");
                        }
                        _ => {
                            let e = self.render_op(op).0;
                            let _ = writeln!(out, "{pad}{e};");
                        }
                    }
                }
                _ => {
                    if let Some(outv) = o.output {
                        if self.is_explicit(outv) {
                            let lhs = self.name_of(outv);
                            let rhs = self.render_op(op).0;
                            let _ = writeln!(out, "{pad}{lhs} = {rhs};");
                        }
                    }
                }
            }
        }
        // a goto edge cut from this block for an irreducible region
        if let Some(&(target, negated)) = self.gotos.get(&b) {
            let lab = self.lab_name(target);
            let cbr = self
                .f
                .block(b)
                .ops
                .iter()
                .rev()
                .copied()
                .find(|&op| self.f.op(op).code() == OpCode::Cbranch);
            match cbr.and_then(|op| self.f.op(op).input(1)) {
                Some(cond) => {
                    let c = if negated { self.render_negated(cond) } else { self.render_var(cond).0 };
                    let _ = writeln!(out, "{pad}if ({c}) goto {lab};");
                }
                None => {
                    let _ = writeln!(out, "{pad}goto {lab};");
                }
            }
        }
    }

    /// The index variable of a switch head: trace the BRANCHIND through the table lookup if
    /// the lookup survived, else fall back to the dominating bound check `index <(=) count`.
    fn switch_index(&self, head: BlockId) -> Option<VarnodeId> {
        let bi = self.f.block(head).ops.iter().rev().copied().find(|&op| self.f.op(op).code() == OpCode::Branchind)?;
        if let Some(v) = self.trace_table_index(self.f.op(bi).input(0)?) {
            return Some(v);
        }
        // fallback: the range check guarding the switch — `index <= count-1` / `index < count`
        let pc = self.f.op(bi).seqnum.pc.offset;
        let num_cases = self.f.switch_targets.get(&pc).map(|t| t.len())?;
        for i in 0..self.f.num_ops() as u32 {
            let o = self.f.op(OpId(i));
            let c = match o.input(1) {
                Some(b) if self.f.vn(b).is_constant() => self.f.vn(b).constant_value() as usize,
                _ => continue,
            };
            let hit = (o.code() == OpCode::IntLessequal && c + 1 == num_cases) || (o.code() == OpCode::IntLess && c == num_cases);
            if hit {
                return o.input(0);
            }
        }
        None
    }

    /// Trace `RAX = base + ext(load(base + index*scale))` ⇒ `index`, when the lookup survives.
    fn trace_table_index(&self, mut v: VarnodeId) -> Option<VarnodeId> {
        for _ in 0..10 {
            let def = self.f.vn(v).def?;
            let o = self.f.op(def);
            match o.code() {
                OpCode::Load => {
                    let addr = o.input(1)?;
                    if let Some(ad) = self.f.vn(addr).def {
                        if self.f.op(ad).code() == OpCode::IntAdd {
                            for k in 0..self.f.op(ad).num_inputs() {
                                if let Some(pd) = self.f.op(ad).input(k).and_then(|p| self.f.vn(p).def) {
                                    if self.f.op(pd).code() == OpCode::IntMult {
                                        return self.f.op(pd).input(0);
                                    }
                                }
                            }
                        }
                    }
                    return Some(addr);
                }
                OpCode::IntAdd => {
                    v = (0..o.num_inputs()).filter_map(|k| o.input(k)).find(|&iv| self.f.vn(iv).def.is_some())?;
                }
                OpCode::IntSext | OpCode::IntZext | OpCode::Subpiece | OpCode::Copy => v = o.input(0)?,
                _ => return None,
            }
        }
        None
    }

    /// The case values that dispatch to `case_addr`, from the recovered jump table.
    fn case_labels(&self, head_pc: u64, case_addr: u64) -> Vec<usize> {
        self.f
            .switch_targets
            .get(&head_pc)
            .map(|ts| ts.iter().enumerate().filter(|(_, &t)| t == case_addr).map(|(i, _)| i).collect())
            .unwrap_or_default()
    }

    /// A label name for a goto target basic block, by its entry address.
    fn lab_name(&self, b: BlockId) -> String {
        let addr = self.f.block_range(b).map(|(a, _)| a).unwrap_or(0);
        format!("LAB_{addr:08x}")
    }
}

/// Render a constant: small negatives as signed decimal (Ghidra prints `0xff..fb` as `-5`),
/// otherwise decimal for small values and hex for the rest.
fn render_const(val: u64, size: u32) -> String {
    let signed = if size == 0 || size >= 8 {
        val as i64
    } else {
        let sh = 64 - 8 * size;
        ((val << sh) as i64) >> sh
    };
    if signed < 0 && signed > -0x10000 {
        return format!("{signed}");
    }
    if val < 10 {
        format!("{val}")
    } else {
        format!("0x{val:x}")
    }
}

/// Decompile `f` to C text.
pub fn print_c(f: &Funcdata) -> String {
    let reg_space = f.spaces.by_name("register");
    let mut p = PrintC {
        f,
        h: merge(f),
        names: HashMap::new(),
        reg_space,
        ram_space: f.spaces.by_name("ram"),
        var_counter: 0,
        ret_val: None,
        types: infer(f),
        for_loops: HashMap::new(),
        suppressed: HashSet::new(),
        array_elem: HashMap::new(),
        gotos: HashMap::new(),
        labels: HashSet::new(),
    };
    p.array_elem = p.detect_arrays();
    p.ret_val = p.return_value();

    // parameters: input varnodes sitting in a parameter register that are actually used.
    // (Unused param-register inputs are scratch — e.g. the call-argument candidates that
    // return/arg recovery left unconsumed — not real parameters.)
    let mut params: Vec<(u64, VarnodeId)> = Vec::new();
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        let vn = f.vn(v);
        if vn.is_input()
            && !vn.descend.is_empty()
            && param_name(Some(vn.loc.space) == reg_space, vn.loc.offset).is_some()
        {
            params.push((vn.loc.offset, v));
        }
    }
    params.sort_by_key(|&(off, _)| param_order(off));
    params.dedup_by_key(|&mut (off, _)| off);

    let ret = p.return_value();
    let ret_ty = ret.map_or("void".to_string(), |v| p.type_of(v).name());
    let plist: Vec<String> =
        params.iter().map(|&(_, v)| format!("{} {}", p.type_of(v).name(), p.name_of(v))).collect();

    let s = structure(f);
    p.gotos = s.gotos.clone();
    p.labels = s.labels.clone();
    p.detect_for_loops(&s, s.root);
    let mut out = String::new();
    let _ = writeln!(out, "{ret_ty} {}({})", f.name, plist.join(", "));
    out.push_str("{\n");
    p.emit_structured(&s, s.root, 1, &mut out);
    out.push_str("}\n");
    out
}

fn param_order(offset: u64) -> u32 {
    match offset {
        0x38 => 1, 0x30 => 2, 0x10 => 3, 0x08 => 4, 0x80 => 5, 0x88 => 6,
        _ => 99,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::build::raw_funcdata_flow;
    use crate::decompile::pipeline;
    use crate::sleigh::engine::Spec;
    use crate::{datatest, paths};

    #[test]
    fn emits_c_for_a_straight_line_function() {
        let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
        if !sla.exists() {
            return;
        }
        let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
        let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
        let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_sem.xml")).unwrap();
        let mut f = raw_funcdata_flow(&spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);
        pipeline::decompile(&mut f);

        let c = print_c(&f);
        // well-formed: a signature line, balanced braces, and a return statement
        assert!(c.contains("func("), "has a signature:\n{c}");
        assert_eq!(c.matches('{').count(), c.matches('}').count(), "balanced braces:\n{c}");
        assert!(c.contains("return"), "has a return:\n{c}");
        // the body exactly matches Ghidra (modulo type names)
        assert!(c.contains("return param_1 * 3 + -5 + (param_2 >> 2);"), "body:\n{c}");
    }

    #[test]
    fn emits_structured_control_flow() {
        let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
        if !sla.exists() {
            return;
        }
        let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
        let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
        let dt = datatest::parse_file(&paths::datatests_dir().join("threedim.xml")).unwrap();
        let mut f = raw_funcdata_flow(&spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);
        pipeline::decompile(&mut f);
        let c = print_c(&f);
        // threedim has a loop — the structurer recovers a for/while, well-nested
        assert!(c.contains("while (") || c.contains("for ("), "structured loop expected:\n{c}");
        assert_eq!(c.matches('{').count(), c.matches('}').count(), "balanced braces:\n{c}");
    }
}
