//! Decompiler D5 (thin slice): fold a function's SSA into C expressions and emit C
//! (Ghidra `PrintC`). Handles a single-`RETURN`, loop-free function: straight-line
//! code folds to one expression, and a `MULTIEQUAL` (phi) at a 2-way merge is
//! recovered as a `?:` ternary — which is exactly how optimized conditionals
//! (`CMOV`/select) lift. Real loops/statements (D4) and the structural comparator
//! are layered on after.

use super::cfg::Funcdata;
use super::ssa::{heritaged, Def, Loc, Ssa};
use crate::sleigh::pcode::{opcode_name, PArg};
use std::collections::HashMap;

/// Loop-variable names: phi id → C variable name. Empty for non-loop expressions.
type LoopVars = HashMap<usize, String>;

/// A recovered C expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Const(u64, u32),
    Var(String),
    Call(&'static str, Vec<Expr>),
    FnCall(String, Vec<Expr>),
    Unary(&'static str, Box<Expr>),
    Binary(&'static str, Box<Expr>, Box<Expr>),
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),
    Deref(Box<Expr>),
}

impl Expr {
    /// Render with enough parentheses to be unambiguous.
    pub fn render(&self) -> String {
        match self {
            Expr::Const(v, size) => {
                // mask to the operand width, then pick base the way Ghidra does:
                // values <= 10 are always decimal, otherwise the "most natural" base
                let masked = if *size >= 8 || *size == 0 { *v } else { v & ((1u64 << (size * 8)) - 1) };
                if masked > 10 && most_natural_base(masked) == 16 {
                    format!("0x{masked:x}")
                } else {
                    masked.to_string()
                }
            }
            Expr::Var(n) => n.clone(),
            Expr::Call(n, args) => format!("{n}({})", args.iter().map(Expr::render).collect::<Vec<_>>().join(", ")),
            Expr::FnCall(n, args) => format!("{n}({})", args.iter().map(Expr::render).collect::<Vec<_>>().join(", ")),
            Expr::Unary(op, a) => format!("{op}({})", a.render()),
            Expr::Binary(op, a, b) => format!("({} {op} {})", a.render(), b.render()),
            Expr::Ternary(c, t, e) => format!("({} ? {} : {})", c.render(), t.render(), e.render()),
            Expr::Deref(p) => match &**p {
                Expr::Var(_) => format!("*{}", p.render()),
                _ => format!("*({})", p.render()),
            },
        }
    }

    /// Render in a statement/condition context — without the outermost redundant
    /// parentheses.
    pub fn render_top(&self) -> String {
        match self {
            Expr::Binary(op, a, b) => format!("{} {op} {}", a.render(), b.render()),
            Expr::Ternary(c, t, e) => format!("{} ? {} : {}", c.render(), t.render(), e.render()),
            other => other.render(),
        }
    }
}

/// x86-64 SysV integer argument registers → parameter name (offset-keyed).
fn x86_param(space: &str, offset: u64) -> Option<String> {
    if space != "register" {
        return None;
    }
    let n = match offset {
        0x38 => 1, // RDI
        0x30 => 2, // RSI
        0x10 => 3, // RDX
        0x08 => 4, // RCX
        0x80 => 5, // R8
        0x88 => 6, // R9
        _ => return None,
    };
    Some(format!("param_{n}"))
}

/// A recovered C statement (D4 structuring).
#[derive(Debug, Clone)]
pub enum Stmt {
    Return(Expr),
    If(Expr, Box<Stmt>, Option<Box<Stmt>>),
    Seq(Vec<Stmt>),
    Decl(String, Expr),
    Assign(String, Expr),
    Expr(Expr),
    Store(Expr, Expr),
    DoWhile(Box<Stmt>, Expr),
    While(Expr, Box<Stmt>),
    For(Box<Stmt>, Expr, Box<Stmt>, Box<Stmt>),
}

/// Render a statement inline (for a `for`-loop init/increment), without indent,
/// trailing semicolon, or newline.
fn one_line(s: &Stmt) -> String {
    match s {
        Stmt::Seq(v) if v.is_empty() => String::new(),
        Stmt::Assign(n, e) => format!("{n} = {}", e.render_top()),
        _ => emit_stmt(s, 0).trim().trim_end_matches(';').to_string(),
    }
}

fn emit_stmt(s: &Stmt, indent: usize) -> String {
    let pad = "  ".repeat(indent);
    match s {
        Stmt::Return(e) => match e {
            Expr::Var(n) if n == "undefined" => format!("{pad}return;\n"),
            _ => format!("{pad}return {};\n", e.render_top()),
        },
        Stmt::Decl(n, e) => format!("{pad}int {n} = {};\n", e.render_top()),
        Stmt::Assign(n, e) => format!("{pad}{n} = {};\n", e.render_top()),
        Stmt::Expr(e) => format!("{pad}{};\n", e.render_top()),
        Stmt::Store(p, v) => format!("{pad}{} = {};\n", deref(p), v.render_top()),
        Stmt::Seq(ss) => ss.iter().map(|s| emit_stmt(s, indent)).collect(),
        Stmt::DoWhile(body, c) => format!("{pad}do {{\n{}{pad}}} while ({});\n", emit_stmt(body, indent + 1), c.render_top()),
        Stmt::While(c, body) => format!("{pad}while ({}) {{\n{}{pad}}}\n", c.render_top(), emit_stmt(body, indent + 1)),
        Stmt::For(init, c, incr, body) => format!(
            "{pad}for ({}; {}; {}) {{\n{}{pad}}}\n",
            one_line(init),
            c.render_top(),
            one_line(incr),
            emit_stmt(body, indent + 1)
        ),
        Stmt::If(c, t, None) => format!("{pad}if ({}) {{\n{}{pad}}}\n", c.render_top(), emit_stmt(t, indent + 1)),
        Stmt::If(c, t, Some(e)) => format!(
            "{pad}if ({}) {{\n{}{pad}}} else {{\n{}{pad}}}\n",
            c.render_top(),
            emit_stmt(t, indent + 1),
            emit_stmt(e, indent + 1)
        ),
    }
}

/// The recovered pieces of a loop, ready to emit.
struct LoopParts {
    decls: Vec<(String, Expr)>,
    body: Vec<Stmt>,
    cond: Expr,
    ret: Expr,
    /// `true` → `while (cond) { body }` (condition at the top); `false` → do-while.
    while_form: bool,
}

const MAX_DEPTH: u32 = 128;

impl Funcdata {
    fn build_expr(&self, d: Def, ssa: &Ssa, lv: &LoopVars, depth: u32) -> Expr {
        if depth > MAX_DEPTH {
            return Expr::Var("...".into());
        }
        match d {
            Def::Live => Expr::Var("undefined".into()),
            Def::Phi(p) => match lv.get(&p) {
                Some(name) => Expr::Var(name.clone()), // a loop variable — stop here
                None => self.phi_expr(p, ssa, lv, depth),
            },
            Def::Op(i) => {
                let op = &self.ops[i].op;
                let a = |pos: usize| self.input_expr(i, pos, ssa, lv, depth + 1);
                match opcode_name(op.opcode) {
                    "COPY" | "INT_ZEXT" | "INT_SEXT" | "SUBPIECE" => a(0),
                    "INT_ADD" => bin("+", a(0), a(1)),
                    "INT_SUB" => bin("-", a(0), a(1)),
                    "INT_MULT" => bin("*", a(0), a(1)),
                    "INT_DIV" | "INT_SDIV" => bin("/", a(0), a(1)),
                    "INT_REM" | "INT_SREM" => bin("%", a(0), a(1)),
                    "INT_AND" => bin("&", a(0), a(1)),
                    "INT_OR" => bin("|", a(0), a(1)),
                    "INT_XOR" => bin("^", a(0), a(1)),
                    "INT_LEFT" => bin("<<", a(0), a(1)),
                    "INT_RIGHT" | "INT_SRIGHT" => bin(">>", a(0), a(1)),
                    "INT_EQUAL" => bin("==", a(0), a(1)),
                    "INT_NOTEQUAL" => bin("!=", a(0), a(1)),
                    "INT_LESS" | "INT_SLESS" => bin("<", a(0), a(1)),
                    "INT_LESSEQUAL" | "INT_SLESSEQUAL" => bin("<=", a(0), a(1)),
                    "INT_NEGATE" => Expr::Unary("~", Box::new(a(0))),
                    "INT_2COMP" => Expr::Unary("-", Box::new(a(0))),
                    "BOOL_NEGATE" => Expr::Unary("!", Box::new(a(0))),
                    "LOAD" => Expr::Deref(Box::new(a(1))), // ins[1] is the pointer
                    "CALL" | "CALLIND" => {
                        // ins[0] = target address; ins[1..] = argument registers.
                        // Recover the contiguous arg registers set up before the call.
                        let target = match op.ins.first() {
                            Some(PArg::Var(v)) if v.space == "ram" => format!("FUN_{:08x}", v.offset),
                            _ => "func".into(),
                        };
                        let mut args = Vec::new();
                        for pos in 1..op.ins.len() {
                            let off = match op.ins.get(pos) {
                                Some(PArg::Var(v)) => v.offset,
                                _ => break,
                            };
                            match ssa.uses.get(&(i, pos)) {
                                // set up before the call (a computed argument)
                                Some(d) if !matches!(d, Def::Live) => args.push(a(pos)),
                                // a parameter passed straight through (live at the call,
                                // but read live-in elsewhere) — still an argument
                                _ if self.is_param_reg(off, ssa) => args.push(a(pos)),
                                _ => break,
                            }
                        }
                        Expr::FnCall(target, args)
                    }
                    other => {
                        let args = (0..op.ins.len()).filter(|&p| op.ins[p].as_var().is_some()).map(a).collect();
                        Expr::Call(other, args)
                    }
                }
            }
        }
    }

    fn input_expr(&self, i: usize, pos: usize, ssa: &Ssa, lv: &LoopVars, depth: u32) -> Expr {
        match self.ops[i].op.ins.get(pos) {
            Some(PArg::Var(v)) if v.is_const() => Expr::Const(v.offset, v.size),
            Some(PArg::Var(v)) if heritaged(&v.space) => match ssa.uses.get(&(i, pos)).copied() {
                Some(Def::Live) | None => {
                    Expr::Var(x86_param(&v.space, v.offset).unwrap_or_else(|| format!("in_{}_{:x}", v.space, v.offset)))
                }
                Some(d) => self.build_expr(d, ssa, lv, depth),
            },
            Some(PArg::Var(v)) => Expr::Var(format!("{}_{:x}", v.space, v.offset)),
            _ => Expr::Var("?".into()),
        }
    }

    /// Recover a 2-way phi as a `?:` ternary, gated by the `CBRANCH` of the merge's
    /// immediate dominator. Falls back to a named value if the shape isn't a clean
    /// diamond.
    fn phi_expr(&self, p: usize, ssa: &Ssa, lv: &LoopVars, depth: u32) -> Expr {
        let ph = &ssa.phis[p];
        let m = ph.block;
        let fallback = || Expr::Var(format!("phi_{p}"));
        if ph.args.len() != 2 {
            return fallback();
        }
        let s = ssa.dom.idom[m];
        if s == usize::MAX || s == m || self.blocks[s].end == self.blocks[s].start {
            return fallback();
        }
        let last = self.blocks[s].end - 1;
        if self.ops[last].op.opcode != 5 {
            return fallback(); // not a CBRANCH split
        }
        let taken = self.blocks[s].succ.first().copied(); // CBRANCH true target
        let cond = self.input_expr(last, 1, ssa, lv, depth + 1);

        // assign each phi argument to the true/false side of the branch
        let (mut t_arg, mut f_arg) = (None, None);
        for (k, &pred) in self.blocks[m].pred.iter().enumerate() {
            let on_true = if pred == s { Some(m) == taken } else { Some(pred) == taken };
            if on_true {
                t_arg = Some(ph.args[k]);
            } else {
                f_arg = Some(ph.args[k]);
            }
        }
        match (t_arg, f_arg) {
            (Some(t), Some(e)) => Expr::Ternary(
                Box::new(cond),
                Box::new(self.build_expr(t, ssa, lv, depth + 1)),
                Box::new(self.build_expr(e, ssa, lv, depth + 1)),
            ),
            _ => fallback(),
        }
    }

    /// Build the statement structure of block `b` (no-loop, reducible CFG): a
    /// `RETURN` ends a path; a `CBRANCH` becomes `if`/`else` over its two
    /// successors. Assumes the arms terminate (early-return style) — the
    /// reconverging case is handled by the single-return phi→ternary path.
    fn structure(&self, b: usize, ssa: &Ssa, lv: &LoopVars, loops: &HashMap<usize, LoopParts>, depth: u32) -> Stmt {
        if depth > MAX_DEPTH {
            return Stmt::Seq(Vec::new());
        }
        // a loop header: emit declarations + do-while, then continue at the exit
        if let Some(lp) = loops.get(&b) {
            let mut seq: Vec<Stmt> = lp.decls.iter().map(|(n, e)| Stmt::Decl(n.clone(), e.clone())).collect();
            if lp.while_form {
                // recover a for-loop when a condition variable is incremented at the
                // end of the body (its update becomes the for-increment)
                let cond_vars = expr_vars(&lp.cond);
                let incr = lp.body.iter().rposition(|s| matches!(s, Stmt::Assign(n, _) if cond_vars.contains(n)));
                match incr {
                    Some(ip) => {
                        let rest: Vec<Stmt> = lp.body.iter().enumerate().filter(|(k, _)| *k != ip).map(|(_, s)| s.clone()).collect();
                        seq.push(Stmt::For(
                            Box::new(Stmt::Seq(Vec::new())),
                            lp.cond.clone(),
                            Box::new(lp.body[ip].clone()),
                            Box::new(Stmt::Seq(rest)),
                        ));
                    }
                    None => seq.push(Stmt::While(lp.cond.clone(), Box::new(Stmt::Seq(lp.body.clone())))),
                }
            } else {
                seq.push(Stmt::DoWhile(Box::new(Stmt::Seq(lp.body.clone())), lp.cond.clone()));
            }
            seq.push(Stmt::Return(lp.ret.clone()));
            return Stmt::Seq(seq);
        }
        if self.blocks[b].end == self.blocks[b].start {
            return Stmt::Seq(Vec::new());
        }
        let blk = &self.blocks[b];
        let last = blk.end - 1;
        match self.ops[last].op.opcode {
            10 => {
                let d = self.ret_def(last, ssa);
                Stmt::Return(simplify(self.build_expr(d, ssa, lv, 0)))
            }
            5 => {
                let cond = simplify(self.input_expr(last, 1, ssa, lv, 0)); // succ[0] taken when true
                let then_s = blk.succ.first().map_or(Stmt::Seq(Vec::new()), |&t| self.structure(t, ssa, lv, loops, depth + 1));
                let else_s = blk.succ.get(1).map(|&e| Box::new(self.structure(e, ssa, lv, loops, depth + 1)));
                Stmt::If(cond, Box::new(then_s), else_s)
            }
            _ => blk.succ.first().map_or(Stmt::Seq(Vec::new()), |&t| self.structure(t, ssa, lv, loops, depth + 1)),
        }
    }

    /// Decompile a function to C. `live_out[0]` is the return register.
    pub fn decompile(&self, live_out: &[Loc]) -> Option<String> {
        // Determine whether the function actually produces a return value. If the
        // return register only ever holds a callee's leftover result (or is unset),
        // the function is void — and then there is no live return register at all.
        let probe = self.ssa(live_out);
        let rets: Vec<usize> = self.ops.iter().enumerate().filter(|(_, fo)| fo.op.opcode == 10).map(|(i, _)| i).collect();
        let void_ret = !rets.is_empty() && rets.iter().all(|&r| self.void_def(self.ret_def(r, &probe), &probe, 0));
        let eff_live_out: Vec<Loc> = if void_ret { Vec::new() } else { live_out.to_vec() };

        let ssa = self.ssa(&eff_live_out);
        let no_lv = LoopVars::new();
        let no_loops = HashMap::new();

        // Find the single back-edge (latch L → header H, H dominates L) among the
        // blocks reachable from the entry. A chunk can hold several functions; the
        // others are unreachable here and must not pull us onto the loop path.
        let mut edge: Option<(usize, usize)> = None;
        for (l, blk) in self.blocks.iter().enumerate() {
            if ssa.dom.post[l] == usize::MAX {
                continue;
            }
            for &h in &blk.succ {
                if ssa.dom.post[h] != usize::MAX && dominates(&ssa, h, l) {
                    if edge.is_some() && edge != Some((h, l)) {
                        return None; // more than one loop
                    }
                    edge = Some((h, l));
                }
            }
        }
        let body = if let Some((h, latch)) = edge {
            // a self-loop is the do-while case (H == L), otherwise a while
            let live = self.dead_code(&ssa);
            let mut lv = LoopVars::new();
            let lp = self.loop_parts(h, latch, &ssa, &live, &mut lv)?;
            let mut loops = HashMap::new();
            loops.insert(h, lp);
            self.structure(0, &ssa, &lv, &loops, 0) // wraps the loop in any guard/if
        } else {
            let reach = self.reachable_op_mask(&ssa);
            let rets: Vec<usize> = self.ops.iter().enumerate().filter(|(i, fo)| fo.op.opcode == 10 && reach[*i]).map(|(i, _)| i).collect();
            if rets.is_empty() {
                return None;
            }
            if rets.len() == 1 {
                // single return → side-effecting statements then one return expression
                // (diamond phis fold to a ?: ternary)
                let ret = rets[0];
                let d = self.ret_def(ret, &ssa);
                let live = self.dead_code(&ssa);
                let mut seq: Vec<Stmt> =
                    (0..self.blocks.len()).filter(|&b| reach.get(self.blocks[b].start).copied().unwrap_or(false)).flat_map(|b| self.block_stmts(b, &ssa, &no_lv, &live)).collect();
                seq.push(Stmt::Return(simplify(self.build_expr(d, &ssa, &no_lv, 0))));
                if seq.len() == 1 {
                    seq.pop().unwrap()
                } else {
                    Stmt::Seq(seq)
                }
            } else {
                // multiple returns → structure into if/else
                self.structure(0, &ssa, &no_lv, &no_loops, 0)
            }
        };
        let rty = if void_ret { "void" } else { "int" };
        Some(format!("{rty} func({})\n{{\n{}}}", self.params_sig(&ssa), emit_stmt(&body, 1)))
    }

    /// Is `d` a value not actually *produced* by this function — undefined, a phi of
    /// such, or (transitively) a callee's return value? Such a value in the return
    /// register means the function is void (Ghidra's output recovery).
    fn void_def(&self, d: Def, ssa: &Ssa, depth: u32) -> bool {
        if depth > MAX_DEPTH {
            return false;
        }
        match d {
            Def::Live => true,
            Def::Phi(p) => ssa.phis[p].args.iter().all(|&a| self.void_def(a, ssa, depth + 1)),
            Def::Op(i) => match opcode_name(self.ops[i].op.opcode) {
                "CALL" | "CALLIND" => true, // a callee's leftover, not produced here
                "COPY" | "INT_ZEXT" | "INT_SEXT" | "SUBPIECE" => {
                    // returning a parameter (live-in param register) is a real return
                    if let Some(PArg::Var(v)) = self.ops[i].op.ins.first() {
                        let src_live = matches!(ssa.uses.get(&(i, 0)), Some(Def::Live) | None);
                        if v.space == "register" && src_live && self.is_param_reg(v.offset, ssa) {
                            return false;
                        }
                    }
                    match ssa.uses.get(&(i, 0)) {
                        Some(&d2) => self.void_def(d2, ssa, depth + 1),
                        None => false,
                    }
                }
                _ => false,
            },
        }
    }

    /// The reaching definition of a return value, trying each live-out slot in turn
    /// (e.g. `EAX` then `RAX`) and taking the first that is actually defined — a
    /// small overlap workaround for sub-register vs full-register writes.
    fn ret_def(&self, ret_op: usize, ssa: &Ssa) -> Def {
        let base = self.ops[ret_op].op.ins.len();
        for k in 0..4 {
            if let Some(d) = ssa.uses.get(&(ret_op, base + k)) {
                if !matches!(d, Def::Live) {
                    return *d;
                }
            }
        }
        Def::Live
    }

    /// Side-effecting statements of a block, in program order: unused-result calls
    /// (`printf(...)`) and real memory stores (`*p = x`). The call's own
    /// return-address push (a `STORE` through `RSP`) is skipped.
    fn block_stmts(&self, b: usize, ssa: &Ssa, lv: &LoopVars, live: &super::simplify::Liveness) -> Vec<Stmt> {
        // a call's result counts as used only if a *live* op or *live* phi consumes it
        let used = |d: Def| {
            ssa.uses.iter().any(|(&(op, _), u)| *u == d && live.live_ops[op])
                || ssa.phis.iter().enumerate().any(|(p, ph)| live.live_phis[p] && ph.args.contains(&d))
        };
        let mut stmts = Vec::new();
        for i in self.blocks[b].start..self.blocks[b].end {
            match self.ops[i].op.opcode {
                7 | 8 if !used(Def::Op(i)) => {
                    stmts.push(Stmt::Expr(simplify(self.build_expr(Def::Op(i), ssa, lv, 0))));
                }
                3 => {
                    let rsp_push = matches!(self.ops[i].op.ins.get(1), Some(PArg::Var(v)) if v.space == "register" && v.offset == 0x20);
                    if !rsp_push {
                        let ptr = simplify(self.input_expr(i, 1, ssa, lv, 0));
                        let val = simplify(self.input_expr(i, 2, ssa, lv, 0));
                        stmts.push(Stmt::Store(ptr, val));
                    }
                }
                _ => {}
            }
        }
        stmts
    }

    /// Parameters used as a pointer — the base address of a (live) `LOAD`/`STORE`.
    fn pointer_params(&self, ssa: &Ssa, live: &super::simplify::Liveness) -> std::collections::HashSet<usize> {
        let mut ptrs = std::collections::HashSet::new();
        let no_lv = LoopVars::new();
        for (i, fo) in self.ops.iter().enumerate() {
            if live.live_ops[i] && matches!(fo.op.opcode, 2 | 3) {
                if let Some(n) = ptr_base(&self.input_expr(i, 1, ssa, &no_lv, 0)) {
                    ptrs.insert(n);
                }
            }
        }
        ptrs
    }

    /// Parameters used as operands of a *live* unsigned-specific op — `INT_LESS(13)`,
    /// `INT_LESSEQUAL(15)`, `INT_RIGHT(30)` (logical shift), `INT_DIV(33)`,
    /// `INT_REM(35)` — so they are unsigned (`uint`). Dead flag-computation ops (which
    /// use `INT_LESS` for carry/borrow) are skipped.
    fn uint_params(&self, ssa: &Ssa, live: &super::simplify::Liveness) -> std::collections::HashSet<usize> {
        let mut u = std::collections::HashSet::new();
        let no_lv = LoopVars::new();
        for (i, fo) in self.ops.iter().enumerate() {
            if live.live_ops[i] && matches!(fo.op.opcode, 13 | 15 | 30 | 33 | 35) {
                for pos in 0..fo.op.ins.len() {
                    if let Some(n) = ptr_base(&self.input_expr(i, pos, ssa, &no_lv, 0)) {
                        u.insert(n);
                    }
                }
            }
        }
        u
    }

    /// Is the register at `off` a function parameter — i.e. read live-in by some
    /// non-call op (so a `Live` use of it at a call is a passthrough argument)?
    fn is_param_reg(&self, off: u64, ssa: &Ssa) -> bool {
        if x86_param("register", off).is_none() {
            return false;
        }
        let reach = self.reachable_op_mask(ssa);
        self.ops.iter().enumerate().any(|(j, fo)| {
            reach[j]
                && !matches!(fo.op.opcode, 7 | 8)
                && fo.op.ins.iter().enumerate().any(|(p, arg)| {
                    matches!(arg.as_var(), Some(v) if v.space == "register" && v.offset == off)
                        && matches!(ssa.uses.get(&(j, p)), Some(Def::Live) | None)
                })
        })
    }

    /// Per-op mask of whether the op lies in a block reachable from the entry. A
    /// datatest chunk can hold several functions back-to-back; only the first (the
    /// reachable subgraph from block 0) is the function we are decompiling.
    fn reachable_op_mask(&self, ssa: &Ssa) -> Vec<bool> {
        let mut mask = vec![false; self.ops.len()];
        for (b, blk) in self.blocks.iter().enumerate() {
            if ssa.dom.post.get(b).copied().unwrap_or(usize::MAX) != usize::MAX {
                for i in blk.start..blk.end {
                    mask[i] = true;
                }
            }
        }
        mask
    }

    /// Parameter signature from the registers read live-in (op uses or live-in phi
    /// arguments — the latter carries loop variables initialized from a parameter).
    fn params_sig(&self, ssa: &Ssa) -> String {
        let mut params: Vec<usize> = Vec::new();
        let mut note = |space: &str, off: u64, params: &mut Vec<usize>| {
            if let Some(name) = x86_param(space, off) {
                if let Ok(n) = name[6..].parse::<usize>() {
                    if !params.contains(&n) {
                        params.push(n);
                    }
                }
            }
        };
        let reach = self.reachable_op_mask(ssa);
        for (idx, fo) in self.ops.iter().enumerate() {
            if !reach[idx] || matches!(fo.op.opcode, 7 | 8) {
                continue; // unreachable (another function), or a CALL's arg registers
            }
            for (pos, arg) in fo.op.ins.iter().enumerate() {
                if let Some(v) = arg.as_var() {
                    if matches!(ssa.uses.get(&(idx, pos)), Some(Def::Live) | None) {
                        note(&v.space, v.offset, &mut params);
                    }
                }
            }
        }
        for ph in &ssa.phis {
            if reach.get(self.blocks[ph.block].start).copied().unwrap_or(false) && ph.args.iter().any(|a| matches!(a, Def::Live)) {
                note(&ph.loc.0, ph.loc.1, &mut params);
            }
        }
        params.sort_unstable();
        let live = self.dead_code(ssa);
        let ptrs = self.pointer_params(ssa, &live);
        let uints = self.uint_params(ssa, &live);
        let sig = params
            .iter()
            .map(|n| {
                if ptrs.contains(n) {
                    format!("int *param_{n}")
                } else if uints.contains(n) {
                    format!("uint param_{n}")
                } else {
                    format!("int param_{n}")
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        if sig.is_empty() { "void".into() } else { sig }
    }

    /// Recover the pieces of a single self-loop (do-while) at header `h`. D3-lite:
    /// group the header phis by `(space, offset)` so overlapping sub-registers
    /// (`EAX`/`RAX`) collapse to one variable — the casts are transparent for integer
    /// code. Populates `lv` (phi id → variable name) for the caller's structuring.
    fn loop_parts(&self, h: usize, latch: usize, ssa: &Ssa, live: &super::simplify::Liveness, lv: &mut LoopVars) -> Option<LoopParts> {
        let preds = self.blocks[h].pred.clone();
        let back = preds.iter().position(|&p| p == latch)?;
        let pre = preds.iter().position(|&p| p != latch)?;
        let while_form = h != latch; // condition at the top vs do-while (self-loop)

        // group ALL header phis by (space, offset) so overlapping sub-registers land
        // together even when DCE keeps only one of them live
        let mut order: Vec<(String, u64)> = Vec::new();
        let mut groups: HashMap<(String, u64), Vec<usize>> = HashMap::new();
        for (pi, ph) in ssa.phis.iter().enumerate() {
            if ph.block != h {
                continue;
            }
            if ph.loc.0 == "register" && ph.loc.1 == 0x20 {
                continue; // RSP — a call's push makes it look like an induction variable
            }
            let key = (ph.loc.0.clone(), ph.loc.1);
            groups.entry(key.clone()).or_insert_with(|| { order.push(key.clone()); Vec::new() }).push(pi);
        }
        let mut vars = Vec::new();
        for key in &order {
            let phis = &groups[key];
            if !phis.iter().any(|&pi| live.live_phis[pi]) {
                continue; // whole group dead (e.g. flags)
            }
            let canon = *phis.iter().max_by_key(|&&pi| {
                let real = !matches!(ssa.phis[pi].args.get(pre), Some(Def::Live)) as i32;
                (real, ssa.phis[pi].loc.2 as i32)
            })?;
            let name = format!("var_{}", vars.len());
            for &pi in phis {
                lv.insert(pi, name.clone());
            }
            vars.push((name, ssa.phis[canon].loc.clone(), canon));
        }
        if vars.is_empty() {
            return None;
        }
        let none = LoopVars::new();
        let mut decls = Vec::new();
        let mut updates: Vec<(String, Expr, std::collections::HashSet<String>)> = Vec::new();
        for (name, loc, canon) in &vars {
            let init = match ssa.phis[*canon].args[pre] {
                Def::Live => Expr::Var(x86_param(&loc.0, loc.1).unwrap_or_else(|| format!("in_{}_{:x}", loc.0, loc.1))),
                d => simplify(self.build_expr(d, ssa, &none, 0)),
            };
            let upd = simplify(self.build_expr(ssa.phis[*canon].args[back], ssa, lv, 0));
            decls.push((name.clone(), init));
            updates.push((name.clone(), upd.clone(), expr_vars(&upd)));
        }

        let last = self.blocks[h].end - 1;
        if self.ops[last].op.opcode != 5 {
            return None;
        }
        let (cond, exit) = if while_form {
            // condition at the top, over pre-update values; continue toward the latch
            let cont = self.blocks[h].succ.iter().copied().find(|&s| self.reaches(s, latch, h))?;
            let exit = self.blocks[h].succ.iter().copied().find(|&s| s != cont)?;
            let mut c = self.input_expr(last, 1, ssa, lv, 0);
            if self.blocks[h].succ.first() != Some(&cont) {
                c = Expr::Unary("!", Box::new(c));
            }
            (simplify(c), exit)
        } else {
            // do-while: condition at the bottom, over post-update values (subst)
            let exit = *self.blocks[h].succ.iter().find(|&&s| s != h)?;
            let mut c = self.input_expr(last, 1, ssa, lv, 0);
            for (name, upd, _) in &updates {
                c = subst(&c, upd, name);
            }
            let mut c = simplify(c);
            if self.blocks[h].succ.first() != Some(&h) {
                c = simplify(Expr::Unary("!", Box::new(c)));
            }
            (c, exit)
        };

        // exit return: a do-while exit reads post-update values; a while exit reads
        // the header phi directly
        let ret_op = (self.blocks[exit].start..self.blocks[exit].end).find(|&i| self.ops[i].op.opcode == 10)?;
        let rv = self.ret_def(ret_op, ssa);
        let mut ret_e = self.build_expr(rv, ssa, lv, 0);
        if !while_form {
            for (name, upd, _) in &updates {
                ret_e = subst(&ret_e, upd, name);
            }
        }
        let ret = simplify(ret_e);

        // body statements. In a `while`, the loop blocks may contain side-effecting
        // calls whose result is unused (e.g. `printf`) — emit those as statements,
        // ahead of the variable updates. A call whose result is used folds into an
        // update instead; non-stack stores and branchy bodies aren't handled yet.
        let mut body: Vec<Stmt> = Vec::new();
        if while_form {
            for (b, blk) in self.blocks.iter().enumerate() {
                if b == h || b == exit || !dominates(ssa, h, b) {
                    continue;
                }
                if self.ops[blk.end - 1].op.opcode == 5 {
                    return None; // branchy loop body — not handled
                }
                body.extend(self.block_stmts(b, ssa, lv, live));
            }
        }
        for (n, e, _) in order_updates(&updates) {
            body.push(Stmt::Assign(n.clone(), e.clone()));
        }
        Some(LoopParts { decls, body, cond, ret, while_form })
    }

    /// Can block `from` reach `target` without passing through `avoid`?
    fn reaches(&self, from: usize, target: usize, avoid: usize) -> bool {
        let mut stack = vec![from];
        let mut seen = std::collections::HashSet::new();
        while let Some(b) = stack.pop() {
            if b == target {
                return true;
            }
            if b == avoid || !seen.insert(b) {
                continue;
            }
            stack.extend(self.blocks[b].succ.iter().copied());
        }
        false
    }
}

/// Does block `a` dominate block `b`?
fn dominates(ssa: &Ssa, a: usize, b: usize) -> bool {
    let mut x = b;
    loop {
        if x == a {
            return true;
        }
        let idom = ssa.dom.idom[x];
        if idom == x || idom == usize::MAX {
            return false;
        }
        x = idom;
    }
}

/// Preferred print base for an integer (Ghidra `PrintLanguage::mostNaturalBase`):
/// count runs of trailing `0`/`9` digits (decimal) vs `0`/`f` nibbles (hex); the
/// "rounder" representation wins. Returns 10 or 16.
fn most_natural_base(val: u64) -> u32 {
    let mut countdec = 0u32;
    let mut tmp = val;
    if tmp == 0 {
        return 10;
    }
    let setdig = tmp % 10;
    if setdig == 0 || setdig == 9 {
        countdec += 1;
        tmp /= 10;
        while tmp != 0 {
            if tmp % 10 == setdig {
                countdec += 1;
            } else {
                break;
            }
            tmp /= 10;
        }
    }
    match countdec {
        0 => return 16,
        1 if tmp > 1 || setdig == 9 => return 16,
        2 if tmp > 10 => return 16,
        3 | 4 if tmp > 100 => return 16,
        n if n >= 5 && tmp > 1000 => return 16,
        _ => {}
    }
    let mut counthex = 0u32;
    tmp = val;
    let setdig = tmp & 0xf;
    if setdig == 0 || setdig == 0xf {
        counthex += 1;
        tmp >>= 4;
        while tmp != 0 {
            if tmp & 0xf == setdig {
                counthex += 1;
            } else {
                break;
            }
            tmp >>= 4;
        }
    }
    if countdec > counthex {
        10
    } else {
        16
    }
}

/// Render a pointer dereference as an lvalue: `*p` for a bare pointer, else `*(expr)`.
fn deref(p: &Expr) -> String {
    match p {
        Expr::Var(_) => format!("*{}", p.render()),
        _ => format!("*({})", p.render()),
    }
}

/// The parameter a pointer expression is based on — `param_N` or `param_N + idx`.
fn ptr_base(e: &Expr) -> Option<usize> {
    match e {
        Expr::Var(n) if n.starts_with("param_") => n[6..].parse().ok(),
        Expr::Binary("+", a, b) => ptr_base(a).or_else(|| ptr_base(b)),
        _ => None,
    }
}

/// Variable names referenced by an expression.
fn expr_vars(e: &Expr) -> std::collections::HashSet<String> {
    fn go(e: &Expr, s: &mut std::collections::HashSet<String>) {
        match e {
            Expr::Var(n) => {
                s.insert(n.clone());
            }
            Expr::Unary(_, a) => go(a, s),
            Expr::Binary(_, a, b) => {
                go(a, s);
                go(b, s);
            }
            Expr::Ternary(c, t, el) => {
                go(c, s);
                go(t, s);
                go(el, s);
            }
            Expr::Call(_, args) | Expr::FnCall(_, args) => args.iter().for_each(|a| go(a, s)),
            Expr::Deref(p) => go(p, s),
            Expr::Const(..) => {}
        }
    }
    let mut s = std::collections::HashSet::new();
    go(e, &mut s);
    s
}

/// Order the update assignments so a variable is reassigned only after every other
/// update that reads its old value has run (parallel-copy sequentialization). Falls
/// back to original order on a cycle (would need a temp — rare).
fn order_updates(updates: &[(String, Expr, std::collections::HashSet<String>)]) -> Vec<&(String, Expr, std::collections::HashSet<String>)> {
    let mut remaining: Vec<usize> = (0..updates.len()).collect();
    let mut result = Vec::new();
    while !remaining.is_empty() {
        let pick = remaining.iter().position(|&vi| {
            let vname = &updates[vi].0;
            !remaining.iter().any(|&wi| wi != vi && updates[wi].2.contains(vname))
        });
        match pick {
            Some(idx) => result.push(&updates[remaining.remove(idx)]),
            None => {
                remaining.iter().for_each(|&vi| result.push(&updates[vi]));
                break;
            }
        }
    }
    result
}

/// Replace every occurrence of `target` in `e` with `Var(name)`.
fn subst(e: &Expr, target: &Expr, name: &str) -> Expr {
    if e == target {
        return Expr::Var(name.to_string());
    }
    match e {
        Expr::Unary(op, a) => Expr::Unary(op, Box::new(subst(a, target, name))),
        Expr::Deref(p) => Expr::Deref(Box::new(subst(p, target, name))),
        Expr::Binary(op, a, b) => Expr::Binary(op, Box::new(subst(a, target, name)), Box::new(subst(b, target, name))),
        Expr::Ternary(c, t, el) => Expr::Ternary(Box::new(subst(c, target, name)), Box::new(subst(t, target, name)), Box::new(subst(el, target, name))),
        Expr::Call(n, args) => Expr::Call(n, args.iter().map(|a| subst(a, target, name)).collect()),
        Expr::FnCall(n, args) => Expr::FnCall(n.clone(), args.iter().map(|a| subst(a, target, name)).collect()),
        other => other.clone(),
    }
}

fn bin(op: &'static str, a: Expr, b: Expr) -> Expr {
    if let (Expr::Const(x, s), Expr::Const(y, _)) = (&a, &b) {
        if let Some(v) = fold(op, *x, *y, *s) {
            return Expr::Const(v, *s);
        }
    }
    let zero = |e: &Expr| matches!(e, Expr::Const(0, _));
    let one = |e: &Expr| matches!(e, Expr::Const(1, _));
    match op {
        "*" if one(&b) => return a,
        "*" if one(&a) => return b,
        "+" | "-" | "<<" | ">>" | "|" | "^" if zero(&b) => return a,
        "+" | "|" | "^" if zero(&a) => return b,
        "&" | "|" if a == b => return a, // idempotent (x & x → x, e.g. TEST x,x)
        _ => {}
    }
    Expr::Binary(op, Box::new(a), Box::new(b))
}

/// The C comparison that is the logical negation of `op`.
fn neg_cmp(op: &str) -> Option<&'static str> {
    Some(match op {
        "==" => "!=",
        "!=" => "==",
        "<" => ">=",
        ">=" => "<",
        "<=" => ">",
        ">" => "<=",
        _ => return None,
    })
}

/// Peephole rewrites that normalize flag idioms toward source-level conditions
/// (a small subset of Ghidra's condition `Rule`s). Applied bottom-up.
fn simplify(e: Expr) -> Expr {
    let e = match e {
        Expr::Call(n, args) => Expr::Call(n, args.into_iter().map(simplify).collect()),
        Expr::FnCall(n, args) => Expr::FnCall(n, args.into_iter().map(simplify).collect()),
        Expr::Unary(op, a) => Expr::Unary(op, Box::new(simplify(*a))),
        Expr::Deref(p) => Expr::Deref(Box::new(simplify(*p))),
        Expr::Binary(op, a, b) => Expr::Binary(op, Box::new(simplify(*a)), Box::new(simplify(*b))),
        Expr::Ternary(c, t, el) => Expr::Ternary(Box::new(simplify(*c)), Box::new(simplify(*t)), Box::new(simplify(*el))),
        other => other,
    };
    // arithmetic: strength reduction + additive-constant normalization
    if let Expr::Binary("+", a, b) = &e {
        if a == b {
            return simplify(Expr::Binary("*", a.clone(), Box::new(Expr::Const(2, 4))));
        }
        if let Some(r) = add_mul(a, b).or_else(|| add_mul(b, a)) {
            return simplify(r);
        }
        // c + x  =>  x + c   (move constant right)
        if matches!(&**a, Expr::Const(..)) && !matches!(&**b, Expr::Const(..)) {
            return simplify(Expr::Binary("+", b.clone(), a.clone()));
        }
        // x + (negative c)  =>  x - |c|
        if let Expr::Const(v, sz) = &**b {
            let neg = if *sz >= 8 { (*v as i64) < 0 } else { (v >> (sz * 8 - 1)) & 1 == 1 };
            if neg {
                let mask = if *sz >= 8 { u64::MAX } else { (1u64 << (sz * 8)) - 1 };
                return Expr::Binary("-", a.clone(), Box::new(Expr::Const(v.wrapping_neg() & mask, *sz)));
            }
        }
    }
    // !(a OP b)  =>  a (negated OP) b
    if let Expr::Unary("!", inner) = &e {
        if let Expr::Binary(op, a, b) = &**inner {
            if let Some(no) = neg_cmp(op) {
                return simplify(Expr::Binary(no, a.clone(), b.clone()));
            }
        }
    }
    // (a - b) {==,!=} 0  =>  a {==,!=} b   (equality is overflow-safe)
    if let Expr::Binary(op @ ("==" | "!="), sub, z) = &e {
        if matches!(&**z, Expr::Const(0, _)) {
            if let Expr::Binary("-", a, b) = &**sub {
                return Expr::Binary(op, a.clone(), b.clone());
            }
        }
    }
    // signed-comparison flag idiom: SBORROW(a,b) {!=,==} ((a-b) < 0)  =>  a {<,>=} b
    if let Expr::Binary(op @ ("==" | "!="), x, y) = &e {
        if let Some(r) = sborrow_cmp(op, x, y).or_else(|| sborrow_cmp(op, y, x)) {
            return r;
        }
    }
    // 0 != cmp  =>  cmp  (a boolean compared to 0 is itself)
    if let Expr::Binary("!=", a, b) = &e {
        let is_cmp = |x: &Expr| matches!(x, Expr::Binary(op, ..) if matches!(*op, "==" | "!=" | "<" | "<=" | ">" | ">="));
        if matches!(&**a, Expr::Const(0, _)) && is_cmp(b) {
            return (**b).clone();
        }
        if matches!(&**b, Expr::Const(0, _)) && is_cmp(a) {
            return (**a).clone();
        }
    }
    // BOOL_AND(a != b, a >= b)  =>  a > b ;  BOOL_OR(a == b, a < b)  =>  a <= b
    if let Expr::Call("BOOL_AND", args) = &e {
        if args.len() == 2 {
            if let Some(r) = and_gt(&args[0], &args[1]).or_else(|| and_gt(&args[1], &args[0])) {
                return r;
            }
        }
    }
    if let Expr::Call("BOOL_OR", args) = &e {
        if args.len() == 2 {
            if let Some(r) = or_le(&args[0], &args[1]).or_else(|| or_le(&args[1], &args[0])) {
                return r;
            }
        }
    }
    // canonicalize a ternary's condition to a positive comparison (<, <=, ==) by
    // swapping the branches: (a >= b) ? t : e  =>  (a < b) ? e : t
    if let Expr::Ternary(c, t, el) = &e {
        let flipped = match &**c {
            Expr::Unary("!", inner) => Some((**inner).clone()),
            Expr::Binary(op @ (">=" | ">" | "!="), a, b) => Some(Expr::Binary(neg_cmp(op).unwrap(), a.clone(), b.clone())),
            _ => None,
        };
        if let Some(nc) = flipped {
            return Expr::Ternary(Box::new(nc), el.clone(), t.clone());
        }
    }
    e
}

fn sborrow_cmp(op: &str, p: &Expr, q: &Expr) -> Option<Expr> {
    if let (Expr::Call("INT_SBORROW", args), Expr::Binary("<", sub, z)) = (p, q) {
        if args.len() == 2 && matches!(&**z, Expr::Const(0, _)) {
            if let Expr::Binary("-", a, b) = &**sub {
                if **a == args[0] && **b == args[1] {
                    let cmp = if op == "!=" { "<" } else { ">=" };
                    return Some(Expr::Binary(cmp, a.clone(), b.clone()));
                }
            }
        }
    }
    None
}

/// `x + (x * k)`  =>  `x * (k+1)` — strength reduction (e.g. `a + a*2` → `a*3`).
fn add_mul(x: &Expr, m: &Expr) -> Option<Expr> {
    if let Expr::Binary("*", y, k) = m {
        if let (Expr::Const(kv, sz), true) = (&**k, **y == *x) {
            return Some(Expr::Binary("*", Box::new(x.clone()), Box::new(Expr::Const(kv.wrapping_add(1), *sz))));
        }
        if let (Expr::Const(kv, sz), true) = (&**y, **k == *x) {
            return Some(Expr::Binary("*", Box::new(x.clone()), Box::new(Expr::Const(kv.wrapping_add(1), *sz))));
        }
    }
    None
}

fn and_gt(p: &Expr, q: &Expr) -> Option<Expr> {
    if let (Expr::Binary("!=", a1, b1), Expr::Binary(">=", a2, b2)) = (p, q) {
        if a1 == a2 && b1 == b2 {
            return Some(Expr::Binary(">", a1.clone(), b1.clone()));
        }
    }
    None
}

fn or_le(p: &Expr, q: &Expr) -> Option<Expr> {
    if let (Expr::Binary("==", a1, b1), Expr::Binary("<", a2, b2)) = (p, q) {
        if a1 == a2 && b1 == b2 {
            return Some(Expr::Binary("<=", a1.clone(), b1.clone()));
        }
    }
    None
}

fn fold(op: &str, x: u64, y: u64, _size: u32) -> Option<u64> {
    Some(match op {
        "+" => x.wrapping_add(y),
        "-" => x.wrapping_sub(y),
        "*" => x.wrapping_mul(y),
        "&" => x & y,
        "|" => x | y,
        "^" => x ^ y,
        "<<" => x.wrapping_shl(y as u32),
        ">>" => x.wrapping_shr(y as u32),
        _ => return None,
    })
}
