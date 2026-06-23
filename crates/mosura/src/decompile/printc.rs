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

use std::collections::HashMap;
use std::fmt::Write as _;

use super::block::BlockId;
use super::funcdata::Funcdata;
use super::infertypes::infer;
use super::merge::{merge, HighVariables};
use super::opcode::OpCode;
use super::structure::{structure, FlowKind, Structured};
use super::types::Datatype;
use super::varnode::VarnodeId;

/// The exit basic block of a structured block (where its terminating CBRANCH lives).
fn exit_basic(s: &Structured, idx: usize) -> Option<BlockId> {
    match &s.blocks[idx].kind {
        FlowKind::Basic(b) => Some(*b),
        _ => exit_basic(s, *s.blocks[idx].components.last()?),
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
    var_counter: u32,
    ret_val: Option<VarnodeId>,
    types: HashMap<VarnodeId, Datatype>,
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
        vn.descend.len() != 1 // single-use values inline; everything else is named
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
            OpCode::Call | OpCode::Callind => {
                let args: Vec<String> = (1..o.num_inputs()).map(|i| self.render_var(a(i)).0).collect();
                (format!("func({})", args.join(", ")), 16)
            }
            other => (format!("{}(...)", other.name()), 16),
        }
    }

    /// The varnode returned by the function: the last write to a return register
    /// (RAX 0x0 / XMM0 0x1200). Heuristic until P6.
    fn return_value(&self) -> Option<VarnodeId> {
        let reg = self.reg_space?;
        let mut best: Option<(u32, VarnodeId)> = None;
        for i in 0..self.f.num_varnodes() as u32 {
            let v = VarnodeId(i);
            let vn = self.f.vn(v);
            if vn.is_written() && vn.loc.space == reg && matches!(vn.loc.offset, 0x0 | 0x1200) {
                if best.map_or(true, |(ci, _)| vn.create_index > ci) {
                    best = Some((vn.create_index, v));
                }
            }
        }
        best.map(|(_, v)| v)
    }

    /// Is the return value purely the function result (no other use)? Then it inlines into
    /// `return` and its assignment statement is suppressed.
    fn ret_inlined(&self) -> Option<VarnodeId> {
        let v = self.ret_val?;
        let vn = self.f.vn(v);
        (vn.is_written() && vn.descend.is_empty()).then_some(v)
    }

    /// The condition of an `if`/`while`: the boolean tested by the CBRANCH at the exit of
    /// the condition block, negated when the body is on the false edge.
    fn render_condition(&mut self, s: &Structured, cond_idx: usize, negated: bool) -> String {
        let cond = exit_basic(s, cond_idx)
            .and_then(|bid| {
                self.f.block(bid).ops.iter().rev().copied().find(|&op| self.f.op(op).code() == OpCode::Cbranch)
            })
            .and_then(|cbr| self.f.op(cbr).input(1))
            .map(|v| self.render_var(v).0)
            .unwrap_or_else(|| "1".into());
        if negated {
            format!("!({cond})")
        } else {
            cond
        }
    }

    /// Emit a structured block (and its children) as C.
    fn emit_structured(&mut self, s: &Structured, idx: usize, indent: usize, out: &mut String) {
        let pad = "  ".repeat(indent);
        let fb = &s.blocks[idx];
        let (kind, comps, negated) = (fb.kind.clone(), fb.components.clone(), fb.negated);
        match kind {
            FlowKind::Basic(bid) => self.emit_basic(bid, indent, out),
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
                let cond = self.render_condition(s, comps[0], negated);
                let _ = writeln!(out, "{pad}while ({cond}) {{");
                self.emit_structured(s, comps[1], indent + 1, out);
                let _ = writeln!(out, "{pad}}}");
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
        let ret_inl = self.ret_inlined();
        for op in self.f.block(b).ops.clone() {
            let o = self.f.op(op);
            match o.code() {
                OpCode::Cbranch | OpCode::Branch | OpCode::Branchind | OpCode::Multiequal | OpCode::Indirect => {}
                OpCode::Return => match (ret_inl, self.ret_val) {
                    (Some(v), _) => {
                        let e = self.render_op(self.f.vn(v).def.unwrap()).0;
                        let _ = writeln!(out, "{pad}return {e};");
                    }
                    (None, Some(v)) => {
                        let e = self.render_var(v).0;
                        let _ = writeln!(out, "{pad}return {e};");
                    }
                    (None, None) => {
                        let _ = writeln!(out, "{pad}return;");
                    }
                },
                OpCode::Store => {
                    let ptr = self.operand(o.input(1).unwrap(), 15, false);
                    let val = self.render_var(o.input(2).unwrap()).0;
                    let _ = writeln!(out, "{pad}*{ptr} = {val};");
                }
                _ => {
                    if let Some(outv) = o.output {
                        if Some(outv) == ret_inl {
                            continue; // inlined into the return
                        }
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
        var_counter: 0,
        ret_val: None,
        types: infer(f),
    };
    p.ret_val = p.return_value();

    // parameters: input varnodes sitting in a parameter register, in order
    let mut params: Vec<(u64, VarnodeId)> = Vec::new();
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        let vn = f.vn(v);
        if vn.is_input() && param_name(Some(vn.loc.space) == reg_space, vn.loc.offset).is_some() {
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
        // threedim has a loop — the structurer recovers a while, well-nested
        assert!(c.contains("while ("), "structured loop expected:\n{c}");
        assert_eq!(c.matches('{').count(), c.matches('}').count(), "balanced braces:\n{c}");
    }
}
