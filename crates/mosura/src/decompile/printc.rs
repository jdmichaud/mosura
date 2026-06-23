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
            if self.f.op(def).code() == OpCode::Multiequal {
                return true; // a phi is a merged variable — always named, never inlined raw
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
            OpCode::Copy | OpCode::IntZext | OpCode::IntSext | OpCode::Subpiece => self.render_var(a(0)),
            OpCode::IntMult => bin(self, "*", 13),
            OpCode::IntDiv | OpCode::IntSdiv => bin(self, "/", 13),
            OpCode::IntRem | OpCode::IntSrem => bin(self, "%", 13),
            OpCode::IntAdd => bin(self, "+", 12),
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
            OpCode::Load => (format!("*{}", self.operand(a(1), 15, false)), 15),
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
                // indirect call through a computed target
                let tgt = self.operand(a(0), 16, false);
                let args: Vec<String> = (1..o.num_inputs()).map(|i| self.render_var(a(i)).0).collect();
                (format!("(*{tgt})({})", args.join(", ")), 16)
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
                    let ptr = self.operand(o.input(1).unwrap(), 15, false);
                    let val = self.render_var(o.input(2).unwrap()).0;
                    let _ = writeln!(out, "{pad}*{ptr} = {val};");
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
    };
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
