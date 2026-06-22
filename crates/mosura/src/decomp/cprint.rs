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

/// Explicit-temp names: op index → C variable name. A value Ghidra marks
/// \e explicit (multiply-used, per `ActionMarkExplicit`) is emitted once as a named
/// temporary and referenced, rather than re-inlined at each use. Empty disables it.
type Explicit = HashMap<usize, String>;

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

/// x86-64 SysV argument registers → parameter name (offset-keyed): the six integer
/// registers, then the eight XMM float registers (`XMM0 = 0x1200`, stride `0x40`). The
/// exact number/order is cosmetic — the comparator erases identifiers — what matters is
/// recognizing each as a distinct parameter so the count and the float values are right.
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
        // XMM0..XMM7 (float/SSE args) → params 7..14
        o if o >= 0x1200 && o < 0x1200 + 8 * 0x40 && (o - 0x1200) % 0x40 == 0 => 7 + (o - 0x1200) / 0x40,
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
    /// `switch (expr) { case v…: body … default: … }` — the index, the cases (each a
    /// set of case values + a body), and an optional default body.
    Switch(Expr, Vec<(Vec<u64>, Stmt)>, Option<Box<Stmt>>),
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
        Stmt::Switch(idx, cases, default) => {
            let mut s = format!("{pad}switch ({}) {{\n", idx.render_top());
            for (values, body) in cases {
                for v in values {
                    s += &format!("{pad}case {}:\n", Expr::Const(*v, 4).render());
                }
                s += &emit_stmt(body, indent + 1);
            }
            if let Some(d) = default {
                s += &format!("{pad}default:\n{}", emit_stmt(d, indent + 1));
            }
            s += &format!("{pad}}}\n");
            s
        }
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

/// Read-only context threaded through [`Funcdata::structure_region`].
struct Region<'a> {
    ssa: &'a Ssa,
    lv: &'a LoopVars,
    loops: &'a HashMap<usize, LoopParts>,
    live: &'a super::simplify::Liveness,
    ex: &'a Explicit,
    pidom: &'a [usize],
}

/// Is `s` an empty (no-op) statement — an empty `Seq`?
fn is_empty_stmt(s: &Stmt) -> bool {
    matches!(s, Stmt::Seq(v) if v.is_empty())
}

/// Logically negate a branch condition, flipping the relational operator where possible
/// (so `if (!cond)` reads as `a >= b` rather than `!(a < b)`).
fn negate_cond(e: Expr) -> Expr {
    match e {
        Expr::Binary("==", a, b) => Expr::Binary("!=", a, b),
        Expr::Binary("!=", a, b) => Expr::Binary("==", a, b),
        Expr::Binary("<", a, b) => Expr::Binary(">=", a, b),
        Expr::Binary(">=", a, b) => Expr::Binary("<", a, b),
        Expr::Binary(">", a, b) => Expr::Binary("<=", a, b),
        Expr::Binary("<=", a, b) => Expr::Binary(">", a, b),
        Expr::Unary("!", a) => *a,
        other => Expr::Unary("!", Box::new(other)),
    }
}

const MAX_DEPTH: u32 = 128;

impl Funcdata {
    fn build_expr(&self, d: Def, ssa: &Ssa, lv: &LoopVars, ex: &Explicit, depth: u32) -> Expr {
        if depth > MAX_DEPTH {
            return Expr::Var("...".into());
        }
        match d {
            Def::Live => Expr::Var("undefined".into()),
            Def::Phi(p) => match lv.get(&p) {
                Some(name) => Expr::Var(name.clone()), // a loop variable — stop here
                None => self.phi_expr(p, ssa, lv, ex, depth),
            },
            // a value marked explicit is referenced by its temp name, not re-inlined
            Def::Op(i) if ex.contains_key(&i) => Expr::Var(ex[&i].clone()),
            Def::Op(i) => self.build_op(i, ssa, lv, ex, depth),
        }
    }

    /// Build the C expression *defining* op `i` (the explicit-temp check is bypassed
    /// for this root op, so its own definition expands rather than self-referencing).
    fn build_op(&self, i: usize, ssa: &Ssa, lv: &LoopVars, ex: &Explicit, depth: u32) -> Expr {
        {
            let op = &self.ops[i].op;
            // division / remainder by a constant, recovered from the compiler's
            // magic-number multiply (Ghidra RuleDivOpt family) → x / C, x % C
            let sz = op.out.as_ref().map_or(8, |o| o.size);
            let div = |fd: &Self, df: super::divrecover::DivForm, opc: &'static str| {
                bin(opc, fd.build_expr(df.x, ssa, lv, ex, depth + 1), Expr::Const(df.divisor, sz))
            };
            match opcode_name(op.opcode) {
                "INT_RIGHT" | "INT_SRIGHT" => {
                    if let Some(df) = super::divrecover::recover_div(self, ssa, i) {
                        return div(self, df, "/");
                    }
                }
                "INT_SUB" => {
                    if let Some(df) = super::divrecover::recover_signed_div(self, ssa, i) {
                        return div(self, df, "/");
                    }
                }
                _ => {}
            }
            let a = |pos: usize| self.input_expr(i, pos, ssa, lv, ex, depth + 1);
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
                    // floating-point ops render with the same C operators; the special
                    // functions (abs/sqrt/nan) are Ghidra's PrintC intrinsic macros
                    "FLOAT_ADD" => bin("+", a(0), a(1)),
                    "FLOAT_SUB" => bin("-", a(0), a(1)),
                    "FLOAT_MULT" => bin("*", a(0), a(1)),
                    "FLOAT_DIV" => bin("/", a(0), a(1)),
                    "FLOAT_EQUAL" => bin("==", a(0), a(1)),
                    "FLOAT_NOTEQUAL" => bin("!=", a(0), a(1)),
                    "FLOAT_LESS" => bin("<", a(0), a(1)),
                    "FLOAT_LESSEQUAL" => bin("<=", a(0), a(1)),
                    "FLOAT_NEG" => Expr::Unary("-", Box::new(a(0))),
                    "FLOAT_ABS" => Expr::Call("ABS", vec![a(0)]),
                    "FLOAT_SQRT" => Expr::Call("SQRT", vec![a(0)]),
                    "FLOAT_NAN" => Expr::Call("NAN", vec![a(0)]),
                    // conversions: int→float / float→float widen-narrow are casts that
                    // Ghidra prints, but the cast type is erased by the comparator — keep
                    // the value transparent for now (the float-width cast comes with XMM).
                    "FLOAT_INT2FLOAT" | "FLOAT_FLOAT2FLOAT" => a(0),
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

    /// Does `build_op` render op `i` by passing input 0 straight through? Such ops
    /// (`COPY`/`ZEXT`/`SEXT`/`SUBPIECE`) are transparent: two uses reaching the same
    /// producer through them are the *same* value.
    fn is_transparent_op(&self, i: usize) -> bool {
        matches!(opcode_name(self.ops[i].op.opcode), "COPY" | "INT_ZEXT" | "INT_SEXT" | "SUBPIECE")
    }

    /// Follow transparent ops (input 0) from `d` to the real op producing its value,
    /// or `None` if it folds to a terminal (parameter / live-in / constant / phi).
    fn value_op(&self, d: Def, ssa: &Ssa) -> Option<usize> {
        let mut cur = d;
        for _ in 0..MAX_DEPTH {
            match cur {
                Def::Op(i) if self.is_transparent_op(i) => cur = *ssa.uses.get(&(i, 0))?,
                Def::Op(i) => return Some(i),
                _ => return None,
            }
        }
        None
    }

    /// Is op `i` a value worth naming — a real op with a usable output whose
    /// expression is more than a bare terminal (a parameter/constant is already named)?
    /// Stack/frame-pointer (\e spacebase) values are never named: Ghidra keeps them
    /// implicit (`ActionMarkExplicit` skips spacebase varnodes) and usually discards
    /// the raw pointer arithmetic entirely.
    fn nameable(&self, i: usize, ssa: &Ssa) -> bool {
        if self.is_transparent_op(i) || self.ops[i].op.out.is_none() {
            return false;
        }
        let e = self.build_op(i, ssa, &LoopVars::new(), &Explicit::new(), 0);
        if matches!(e, Expr::Var(_) | Expr::Const(..)) || expr_refs_spacebase(&e) {
            return false;
        }
        true
    }

    /// Mark values explicit the way Ghidra's `ActionMarkExplicit` does: a value with
    /// more than `MAX_IMPLIED_REF` descendants, or exactly two whose expression
    /// duplicates more than `MAX_TERM_DUPLICATION` terminal leaves, is emitted once as
    /// a named temporary and referenced — instead of being re-inlined at each use.
    /// Returns op index → temp name. (Ghidra's `Architecture` defaults, `architecture.cc`.)
    fn mark_explicit(&self, ssa: &Ssa, live: &super::simplify::Liveness) -> Explicit {
        const MAX_IMPLIED_REF: usize = 2;
        const MAX_TERM_DUPLICATION: usize = 2;

        // Count folded descendants as *distinct consumers*: attribute each live use
        // (op input, live phi arg, or return live-out — all in `ssa.uses`) to its real
        // producer, but count each consuming op/phi once per producer. (A `RETURN`
        // reads its value through two overlapping live-out slots, `EAX` and `RAX`,
        // which fold to the same producer — that is one descendant, not two.) Skip
        // transparent consumers, whose uses are credited to the op they fold into.
        let mut edges: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
        for (&(op, _pos), &d) in &ssa.uses {
            if !live.live_ops[op] || self.is_transparent_op(op) {
                continue;
            }
            if let Some(r) = self.value_op(d, ssa) {
                edges.insert((op, r));
            }
        }
        for (p, ph) in ssa.phis.iter().enumerate() {
            if live.live_phis[p] {
                for &a in &ph.args {
                    if let Some(r) = self.value_op(a, ssa) {
                        edges.insert((self.ops.len() + p, r)); // phi consumer key, disjoint from op indices
                    }
                }
            }
        }
        let mut desc: HashMap<usize, usize> = HashMap::new();
        for &(_consumer, r) in &edges {
            *desc.entry(r).or_default() += 1;
        }

        // ops consumed by a recovered division render as `x / C`, not as themselves —
        // never name them (the multiply etc. would otherwise leak out as dead temps)
        let consumed = super::divrecover::consumed_ops(self, ssa);
        let mut cand: Vec<usize> = desc.iter().filter(|(&i, &c)| c >= 2 && !consumed.contains(&i)).map(|(&i, _)| i).collect();
        cand.sort_unstable();
        let mut marked: std::collections::HashSet<usize> = std::collections::HashSet::new();
        // pass 1 — too many descendants (baseExplicit, maxref): always explicit
        for &i in &cand {
            if desc[&i] > MAX_IMPLIED_REF && self.nameable(i, ssa) {
                marked.insert(i);
            }
        }
        // pass 2 — exactly-two descendants: explicit only if expanding duplicates too
        // many terminals (processMultiplier, maxdup), counting pass-1 temps as terminals
        for &i in &cand {
            if marked.contains(&i) || desc[&i] != 2 || !self.nameable(i, ssa) {
                continue;
            }
            let prov: Explicit = marked.iter().map(|&j| (j, String::new())).collect();
            let e = self.build_op(i, ssa, &LoopVars::new(), &prov, 0);
            if leaf_count(&e) > MAX_TERM_DUPLICATION {
                marked.insert(i);
            }
        }

        // name in program order so temps read top-to-bottom
        let mut set: Vec<usize> = marked.into_iter().collect();
        set.sort_unstable();
        set.iter().enumerate().map(|(k, &i)| (i, format!("var_{k}"))).collect()
    }

    /// The frame offset of the value defined by `d`, as a constant displacement from the
    /// spacebase — Ghidra `AliasChecker::gatherOffset` (follow COPY/ADD/SUB/PTRSUB,
    /// summing constants; a non-constant index contributes 0).
    fn gather_offset(&self, d: Def, ssa: &Ssa, depth: u32) -> i64 {
        if depth > 64 {
            return 0;
        }
        let Def::Op(i) = d else { return 0 }; // the spacebase live-in is offset 0
        let op = &self.ops[i].op;
        // a definition of the frame pointer (RBP, set by the prologue) is the base, offset 0
        if matches!(&op.out, Some(v) if v.space == "register" && v.offset == 0x28) {
            return 0;
        }
        let g = |pos: usize| -> i64 {
            if let Some(PArg::Var(v)) = op.ins.get(pos) {
                if v.is_const() {
                    return v.offset as i64;
                }
            }
            ssa.uses.get(&(i, pos)).map_or(0, |&dd| self.gather_offset(dd, ssa, depth + 1))
        };
        match opcode_name(op.opcode) {
            "COPY" | "INT_ZEXT" | "INT_SEXT" => g(0),
            "INT_ADD" | "PTRSUB" => g(0).wrapping_add(g(1)),
            "INT_SUB" => g(0).wrapping_sub(g(1)),
            _ => 0,
        }
    }

    /// The stack alias boundary: the lowest (deepest) local frame offset whose address
    /// is taken — a port of Ghidra `AliasChecker::gatherAdditiveBase`. Walk forward from
    /// the RBP spacebase through ADD/SUB/COPY chains; any derived value with a
    /// *non-additive* use (a real pointer use: call arg, store, load, compare) is an
    /// address taken at its offset. Stack slots at or above the boundary are aliased and
    /// kept symbolic. `None` if no local address is ever taken.
    fn stack_alias_boundary(&self, ssa: &Ssa) -> Option<i64> {
        // reverse use map: each def → the ops (with input position) that read it
        let mut uses_of: HashMap<Def, Vec<(usize, usize)>> = HashMap::new();
        for (&(op, pos), &d) in &ssa.uses {
            uses_of.entry(d).or_default().push((op, pos));
        }
        let mut visited: std::collections::HashSet<i64> = std::collections::HashSet::new();
        let mut work: Vec<i64> = vec![-1]; // -1 = the RBP spacebase (offset 0)
        let mut bases: Vec<Def> = Vec::new(); // additive bases that have a non-additive use
        while let Some(b) = work.pop() {
            if !visited.insert(b) {
                continue;
            }
            let descs: Vec<(usize, usize)> = if b < 0 {
                // spacebase descendants: every op reading the frame pointer RBP (set by
                // the prologue, so its reads are the frame base — recover_stack treats it
                // as offset 0); the defining COPY/ADD chain is followed via gather_offset.
                let mut v = Vec::new();
                for (i, fo) in self.ops.iter().enumerate() {
                    for (pos, a) in fo.op.ins.iter().enumerate() {
                        if matches!(a, PArg::Var(vn) if vn.space == "register" && vn.offset == 0x28) {
                            v.push((i, pos));
                        }
                    }
                }
                v
            } else {
                uses_of.get(&Def::Op(b as usize)).cloned().unwrap_or_default()
            };
            let mut nonadduse = false;
            for (o, pos) in descs {
                match opcode_name(self.ops[o].op.opcode) {
                    "COPY" => {
                        nonadduse = true; // a COPY is both a non-additive use and part of the chain
                        work.push(o as i64);
                    }
                    "INT_SUB" if pos == 1 => nonadduse = true, // subtracting the pointer
                    "INT_ADD" | "INT_SUB" | "PTRADD" | "PTRSUB" | "SEGMENTOP" => work.push(o as i64),
                    _ => nonadduse = true, // used in a non-additive expression — the address escapes
                }
            }
            if nonadduse && b >= 0 {
                bases.push(Def::Op(b as usize));
            }
        }
        let mut boundary: Option<i64> = None;
        for d in bases {
            let off = self.gather_offset(d, ssa, 0);
            if off < 0 {
                // a local (below the frame); params are at positive offsets — skip them
                boundary = Some(boundary.map_or(off, |b| b.min(off)));
            }
        }
        boundary
    }

    fn input_expr(&self, i: usize, pos: usize, ssa: &Ssa, lv: &LoopVars, ex: &Explicit, depth: u32) -> Expr {
        match self.ops[i].op.ins.get(pos) {
            Some(PArg::Var(v)) if v.is_const() => Expr::Const(v.offset, v.size),
            // an aliased stack slot reads as its named local (Ghidra keeps it symbolic);
            // an unaliased slot is inlined — its stored value propagated, below.
            Some(PArg::Var(v)) if v.space == "stack" && self.stack_alias_boundary(ssa).is_some_and(|b| v.offset as i64 >= b) => {
                Expr::Var(stack_name(v.offset as i64))
            }
            Some(PArg::Var(v)) if heritaged(&v.space) => match ssa.uses.get(&(i, pos)).copied() {
                Some(Def::Live) | None => {
                    Expr::Var(x86_param(&v.space, v.offset).unwrap_or_else(|| format!("in_{}_{:x}", v.space, v.offset)))
                }
                Some(d) => self.build_expr(d, ssa, lv, ex, depth),
            },
            Some(PArg::Var(v)) => Expr::Var(format!("{}_{:x}", v.space, v.offset)),
            _ => Expr::Var("?".into()),
        }
    }

    /// Recover a 2-way phi as a `?:` ternary, gated by the `CBRANCH` of the merge's
    /// immediate dominator. Falls back to a named value if the shape isn't a clean
    /// diamond.
    fn phi_expr(&self, p: usize, ssa: &Ssa, lv: &LoopVars, ex: &Explicit, depth: u32) -> Expr {
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
        let cond = self.input_expr(last, 1, ssa, lv, ex, depth + 1);

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
                Box::new(self.build_expr(t, ssa, lv, ex, depth + 1)),
                Box::new(self.build_expr(e, ssa, lv, ex, depth + 1)),
            ),
            _ => fallback(),
        }
    }

    /// Structure the region of blocks from `b` up to (but excluding) the follow node
    /// `stop`, into nested statements — post-dominator-based structuring (Ghidra's
    /// `BlockGraph`): each block's side effects are emitted, a `CBRANCH` becomes an
    /// `if`/`else` whose arms are bounded by the branch's post-dominator (so reconverging
    /// paths are structured once, not duplicated), and control then continues at that
    /// merge point. `stop == usize::MAX` means "until a function exit".
    fn structure_region(&self, b: usize, stop: usize, r: &Region, depth: u32) -> Stmt {
        if depth > MAX_DEPTH || b == stop || b >= self.blocks.len() {
            return Stmt::Seq(Vec::new());
        }
        // a loop header: emit the loop (terminal — loop then return)
        if let Some(lp) = r.loops.get(&b) {
            return self.emit_loop(lp);
        }
        if self.blocks[b].end == self.blocks[b].start {
            let next = self.blocks[b].succ.first().copied().unwrap_or(stop);
            return self.structure_region(next, stop, r, depth + 1);
        }
        let blk = &self.blocks[b];
        let last = blk.end - 1;
        let mut seq: Vec<Stmt> = self.block_stmts(b, r.ssa, r.lv, r.ex, r.live);
        match self.ops[last].op.opcode {
            10 => {
                let d = self.ret_def(last, r.ssa);
                seq.push(Stmt::Return(simplify(self.build_expr(d, r.ssa, r.lv, r.ex, 0))));
            }
            5 => {
                let cond = simplify(self.input_expr(last, 1, r.ssa, r.lv, r.ex, 0)); // succ[0] taken when true
                let follow = r.pidom.get(b).copied().unwrap_or(usize::MAX);
                let fstop = if follow == usize::MAX { stop } else { follow };
                let then_s = blk.succ.first().map_or(Stmt::Seq(Vec::new()), |&t| self.structure_region(t, fstop, r, depth + 1));
                let else_s = blk.succ.get(1).map_or(Stmt::Seq(Vec::new()), |&e| self.structure_region(e, fstop, r, depth + 1));
                let (te, ee) = (is_empty_stmt(&then_s), is_empty_stmt(&else_s));
                if te && !ee {
                    seq.push(Stmt::If(negate_cond(cond), Box::new(else_s), None)); // `if (!cond)` reads better than an empty then
                } else if ee {
                    seq.push(Stmt::If(cond, Box::new(then_s), None));
                } else {
                    seq.push(Stmt::If(cond, Box::new(then_s), Some(Box::new(else_s))));
                }
                if follow != usize::MAX && follow != stop {
                    let cont = self.structure_region(follow, stop, r, depth + 1);
                    if !is_empty_stmt(&cont) {
                        seq.push(cont);
                    }
                }
            }
            _ => {
                let next = blk.succ.first().copied().unwrap_or(stop);
                let cont = self.structure_region(next, stop, r, depth + 1);
                if !is_empty_stmt(&cont) {
                    seq.push(cont);
                }
            }
        }
        if seq.len() == 1 {
            seq.pop().unwrap()
        } else {
            Stmt::Seq(seq)
        }
    }

    /// Emit a recovered loop (`LoopParts`) as a `for`/`while`/`do-while` plus the
    /// post-loop return — shared by the old and post-dominator structurers.
    fn emit_loop(&self, lp: &LoopParts) -> Stmt {
        let mut seq: Vec<Stmt> = lp.decls.iter().map(|(n, e)| Stmt::Decl(n.clone(), e.clone())).collect();
        if lp.while_form {
            let cond_vars = expr_vars(&lp.cond);
            let incr = lp.body.iter().rposition(|s| matches!(s, Stmt::Assign(n, _) if cond_vars.contains(n)));
            match incr {
                Some(ip) => {
                    let rest: Vec<Stmt> = lp.body.iter().enumerate().filter(|(k, _)| *k != ip).map(|(_, s)| s.clone()).collect();
                    seq.push(Stmt::For(Box::new(Stmt::Seq(Vec::new())), lp.cond.clone(), Box::new(lp.body[ip].clone()), Box::new(Stmt::Seq(rest))));
                }
                None => seq.push(Stmt::While(lp.cond.clone(), Box::new(Stmt::Seq(lp.body.clone())))),
            }
        } else {
            seq.push(Stmt::DoWhile(Box::new(Stmt::Seq(lp.body.clone())), lp.cond.clone()));
        }
        seq.push(Stmt::Return(lp.ret.clone()));
        Stmt::Seq(seq)
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
            return self.emit_loop(lp);
        }
        if self.blocks[b].end == self.blocks[b].start {
            return Stmt::Seq(Vec::new());
        }
        let blk = &self.blocks[b];
        let last = blk.end - 1;
        let no_ex = Explicit::new();
        match self.ops[last].op.opcode {
            10 => {
                let d = self.ret_def(last, ssa);
                Stmt::Return(simplify(self.build_expr(d, ssa, lv, &no_ex, 0)))
            }
            5 => {
                let cond = simplify(self.input_expr(last, 1, ssa, lv, &no_ex, 0)); // succ[0] taken when true
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
        // a recovered jump table → emit `switch (index) { case … }` (S3). Only when the
        // function is loop-free: a switch inside a loop has cyclic case bodies that the
        // (acyclic) structurer would expand exponentially.
        let sw = match edge {
            None => self.switches.iter().find(|s| ssa.dom.post.get(s.block).copied().unwrap_or(usize::MAX) != usize::MAX),
            Some(_) => None,
        };
        let body = if let Some(sw) = sw {
            self.decompile_switch(sw, &ssa)
        } else if let Some((h, latch)) = edge {
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
                // mark multiply-used values explicit (Ghidra ActionMarkExplicit): they
                // are emitted once as named temporaries by block_stmts and referenced.
                let ex = self.mark_explicit(&ssa, &live);
                let mut seq: Vec<Stmt> =
                    (0..self.blocks.len()).filter(|&b| reach.get(self.blocks[b].start).copied().unwrap_or(false)).flat_map(|b| self.block_stmts(b, &ssa, &no_lv, &ex, &live)).collect();
                seq.push(Stmt::Return(simplify(self.build_expr(d, &ssa, &no_lv, &ex, 0))));
                if seq.len() == 1 {
                    seq.pop().unwrap()
                } else {
                    Stmt::Seq(seq)
                }
            } else {
                // multiple returns → post-dominator structuring into if/else
                let live = self.dead_code(&ssa);
                let ex = self.mark_explicit(&ssa, &live);
                let pidom = self.post_idom();
                let r = Region { ssa: &ssa, lv: &no_lv, loops: &no_loops, live: &live, ex: &ex, pidom: &pidom };
                self.structure_region(0, usize::MAX, &r, 0)
            }
        };
        let body = name_stack_stmt(body); // raw RSP/RBP arithmetic → named stack locals
        // declare the stack locals at the top of the body, as Ghidra does
        let mut stack_vars = std::collections::BTreeSet::new();
        collect_stack_vars(&body, &mut stack_vars);
        let decls: String = stack_vars.iter().map(|n| format!("  undefined8 {n};\n")).collect();
        let rty = if void_ret { "void" } else { "int" };
        Some(format!("{rty} func({})\n{{\n{decls}{}}}", self.params_sig(&ssa), emit_stmt(&body, 1)))
    }

    /// Structure a recovered jump table into `switch (index) { case … }` (S3): emit the
    /// prologue (side effects of the blocks before the switch), then a case per distinct
    /// target block, grouping the case values that share it. The target with the most
    /// case values is taken as the `default`.
    fn decompile_switch(&self, sw: &super::cfg::SwitchInfo, ssa: &Ssa) -> Stmt {
        let no_lv = LoopVars::new();
        let no_ex = Explicit::new();
        let no_loops = HashMap::new();
        let live = self.dead_code(ssa);

        // prologue: side-effecting statements of the blocks dominating the switch
        let mut seq: Vec<Stmt> = (0..self.blocks.len())
            .filter(|&b| b != sw.block && dominates(ssa, b, sw.block))
            .flat_map(|b| self.block_stmts(b, ssa, &no_lv, &no_ex, &live))
            .collect();

        // group case values by their target block; the most-shared target is the default
        let mut by_target: HashMap<usize, Vec<u64>> = HashMap::new();
        for &(cv, tb) in &sw.cases {
            by_target.entry(tb).or_default().push(cv);
        }
        let default_block = by_target.iter().max_by_key(|(_, v)| v.len()).map(|(&b, _)| b);
        // a case body = the target block's side effects and control flow, structured
        let pidom = self.post_idom();
        let r = Region { ssa, lv: &no_lv, loops: &no_loops, live: &live, ex: &no_ex, pidom: &pidom };
        let case_body = |b: usize| -> Stmt { self.structure_region(b, usize::MAX, &r, 0) };
        let mut cases: Vec<(Vec<u64>, Stmt)> = by_target
            .iter()
            .filter(|(&b, _)| Some(b) != default_block)
            .map(|(&b, vals)| {
                let mut v = vals.clone();
                v.sort_unstable();
                (v, case_body(b))
            })
            .collect();
        cases.sort_by_key(|(vals, _)| vals[0]);
        let default = default_block.map(|b| Box::new(case_body(b)));

        let index = simplify(self.build_expr(sw.index, ssa, &no_lv, &no_ex, 0));
        seq.push(Stmt::Switch(index, cases, default));
        if seq.len() == 1 {
            seq.pop().unwrap()
        } else {
            Stmt::Seq(seq)
        }
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

    /// Side-effecting statements of a block, in program order: explicit-temp
    /// definitions (`var = <expr>` for a multiply-used value), unused-result calls
    /// (`printf(...)`) and real memory stores (`*p = x`). The call's own
    /// return-address push (a `STORE` through `RSP`) is skipped.
    fn block_stmts(&self, b: usize, ssa: &Ssa, lv: &LoopVars, ex: &Explicit, live: &super::simplify::Liveness) -> Vec<Stmt> {
        // a call's result counts as used only if a *live* op or *live* phi consumes it
        let used = |d: Def| {
            ssa.uses.iter().any(|(&(op, _), u)| *u == d && live.live_ops[op])
                || ssa.phis.iter().enumerate().any(|(p, ph)| live.live_phis[p] && ph.args.contains(&d))
        };
        let mut stmts = Vec::new();
        for i in self.blocks[b].start..self.blocks[b].end {
            // an explicit (multiply-used) value is defined here once, then referenced
            if let Some(name) = ex.get(&i) {
                stmts.push(Stmt::Decl(name.clone(), simplify(self.build_op(i, ssa, lv, ex, 0))));
                continue;
            }
            // a write to a global — an op whose output is an absolute `ram` address
            // (e.g. `glob = value`) — is a side effect; emit it (F4).
            if let Some(out) = self.ops[i].op.out.clone() {
                if out.space == "ram" && live.live_ops[i] {
                    stmts.push(Stmt::Assign(format!("ram_{:x}", out.offset), simplify(self.build_op(i, ssa, lv, ex, 0))));
                    continue;
                }
                // a store to an *aliased* stack slot is a named-variable assignment —
                // `aStack_C = value` (an unaliased slot is inlined instead, not emitted).
                if out.space == "stack" && self.ops[i].op.opcode == 1 && live.live_ops[i] && self.stack_alias_boundary(ssa).is_some_and(|b| out.offset as i64 >= b) {
                    stmts.push(Stmt::Assign(stack_name(out.offset as i64), simplify(self.input_expr(i, 0, ssa, lv, ex, 0))));
                    continue;
                }
            }
            match self.ops[i].op.opcode {
                7 | 8 if !used(Def::Op(i)) => {
                    stmts.push(Stmt::Expr(simplify(self.build_expr(Def::Op(i), ssa, lv, ex, 0))));
                }
                3 => {
                    let rsp_push = matches!(self.ops[i].op.ins.get(1), Some(PArg::Var(v)) if v.space == "register" && v.offset == 0x20);
                    if !rsp_push {
                        let ptr = simplify(self.input_expr(i, 1, ssa, lv, ex, 0));
                        let val = simplify(self.input_expr(i, 2, ssa, lv, ex, 0));
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
        let no_ex = Explicit::new();
        for (i, fo) in self.ops.iter().enumerate() {
            if live.live_ops[i] && matches!(fo.op.opcode, 2 | 3) {
                if let Some(n) = ptr_base(&self.input_expr(i, 1, ssa, &no_lv, &no_ex, 0)) {
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
        let no_ex = Explicit::new();
        for (i, fo) in self.ops.iter().enumerate() {
            if live.live_ops[i] && matches!(fo.op.opcode, 13 | 15 | 30 | 33 | 35) {
                for pos in 0..fo.op.ins.len() {
                    if let Some(n) = ptr_base(&self.input_expr(i, pos, ssa, &no_lv, &no_ex, 0)) {
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
        let note = |space: &str, off: u64, params: &mut Vec<usize>| {
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
        let no_ex = Explicit::new();
        let mut decls = Vec::new();
        let mut updates: Vec<(String, Expr, std::collections::HashSet<String>)> = Vec::new();
        for (name, loc, canon) in &vars {
            let init = match ssa.phis[*canon].args[pre] {
                Def::Live => Expr::Var(x86_param(&loc.0, loc.1).unwrap_or_else(|| format!("in_{}_{:x}", loc.0, loc.1))),
                d => simplify(self.build_expr(d, ssa, &none, &no_ex, 0)),
            };
            let upd = simplify(self.build_expr(ssa.phis[*canon].args[back], ssa, lv, &no_ex, 0));
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
            let mut c = self.input_expr(last, 1, ssa, lv, &no_ex, 0);
            if self.blocks[h].succ.first() != Some(&cont) {
                c = Expr::Unary("!", Box::new(c));
            }
            (simplify(c), exit)
        } else {
            // do-while: condition at the bottom, over post-update values (subst)
            let exit = *self.blocks[h].succ.iter().find(|&&s| s != h)?;
            let mut c = self.input_expr(last, 1, ssa, lv, &no_ex, 0);
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
        let mut ret_e = self.build_expr(rv, ssa, lv, &no_ex, 0);
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
        let mut stmts: Vec<Stmt> = Vec::new();
        if while_form {
            for (b, blk) in self.blocks.iter().enumerate() {
                if b == h || b == exit || !dominates(ssa, h, b) {
                    continue;
                }
                if self.ops[blk.end - 1].op.opcode == 5 {
                    return None; // branchy loop body — not handled
                }
                stmts.extend(self.block_stmts(b, ssa, lv, &no_ex, live));
            }
        }
        // loop-body CSE: a loop variable whose new value also appears verbatim in a body
        // statement (a value that is used *and* carried — e.g. a load that is stored and
        // returned) is emitted once at the top of the body and referenced, instead of
        // being re-inlined at each use.
        let mut hoisted: Vec<Stmt> = Vec::new();
        let mut tail: Vec<Stmt> = Vec::new();
        for (n, e, _) in order_updates(&updates) {
            let used = !matches!(e, Expr::Var(_) | Expr::Const(..)) && stmts.iter().any(|s| stmt_contains_expr(s, e));
            if used {
                stmts = stmts.iter().map(|s| subst_in_stmt(s, e, n)).collect();
                hoisted.push(Stmt::Assign(n.clone(), e.clone()));
            } else {
                tail.push(Stmt::Assign(n.clone(), e.clone()));
            }
        }
        let mut body = hoisted;
        body.extend(stmts);
        body.extend(tail);
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

/// Does an expression read the raw stack/frame pointer (`RSP`=reg 0x20, `RBP`=reg
/// 0x28) live-in — i.e. is it spacebase-relative? Ghidra never makes such a value an
/// explicit variable.
fn expr_refs_spacebase(e: &Expr) -> bool {
    expr_vars(e).iter().any(|n| n == "in_register_20" || n == "in_register_28")
}

/// Does the expression contain a function call (`FnCall`) — a side-effecting term that
/// must not be cancelled (`f() - f()` is not `0`).
fn expr_has_call(e: &Expr) -> bool {
    match e {
        Expr::FnCall(..) => true,
        Expr::Const(..) | Expr::Var(_) => false,
        Expr::Unary(_, a) | Expr::Deref(a) => expr_has_call(a),
        Expr::Binary(_, a, b) => expr_has_call(a) || expr_has_call(b),
        Expr::Ternary(c, t, el) => expr_has_call(c) || expr_has_call(t) || expr_has_call(el),
        Expr::Call(_, args) => args.iter().any(expr_has_call),
    }
}

/// Number of terminal leaves (variables + constants) in an expression — Ghidra's
/// "term duplication" count for the explicit/implicit decision. A nested explicit
/// value (rendered as a bare `Var`) counts as a single terminal.
fn leaf_count(e: &Expr) -> usize {
    match e {
        Expr::Const(..) | Expr::Var(_) => 1,
        Expr::Unary(_, a) | Expr::Deref(a) => leaf_count(a),
        Expr::Binary(_, a, b) => leaf_count(a) + leaf_count(b),
        Expr::Ternary(c, t, el) => leaf_count(c) + leaf_count(t) + leaf_count(el),
        Expr::Call(_, args) | Expr::FnCall(_, args) => args.iter().map(leaf_count).sum::<usize>().max(1),
    }
}

/// If `e` is a stack-pointer-relative *address* with a constant displacement
/// (`in_register_20`/`in_register_28` ± constants), the displacement; else `None`.
/// `in_register_20` is RSP, `in_register_28` RBP — the live-in stack-pointer values
/// from which frame-pointer-omitted code addresses its locals.
fn stack_offset(e: &Expr) -> Option<i64> {
    let sext = |c: u64, sz: u32| -> i64 {
        if sz == 0 || sz >= 8 {
            c as i64
        } else {
            let b = sz * 8;
            ((c << (64 - b)) as i64) >> (64 - b)
        }
    };
    match e {
        Expr::Var(n) if n == "in_register_20" || n == "in_register_28" => Some(0),
        Expr::Binary("+", a, b) => match (&**a, &**b) {
            (_, Expr::Const(c, sz)) => stack_offset(a).map(|k| k + sext(*c, *sz)),
            (Expr::Const(c, sz), _) => stack_offset(b).map(|k| k + sext(*c, *sz)),
            _ => None,
        },
        Expr::Binary("-", a, b) => match &**b {
            Expr::Const(c, sz) => stack_offset(a).map(|k| k - sext(*c, *sz)),
            _ => None,
        },
        _ => None,
    }
}

/// A C name for the stack slot at displacement `k` (the comparator erases the name to
/// an identifier, so only the form — a name, not a pointer dereference — matters).
fn stack_name(k: i64) -> String {
    if k < 0 {
        format!("aStack_{:x}", -k)
    } else {
        format!("aStack_p{k:x}")
    }
}

/// Render stack-pointer arithmetic as named locals (Ghidra's stack variables): a scalar
/// load `*(rsp + C)` becomes a bare `aStack_C`, an address `rsp + C` becomes `aStack_C`,
/// and an indexed `*(rsp + C + i)` keeps the deref over a named base — collapsing the
/// raw `in_register_20` arithmetic mosura would otherwise emit.
fn name_stack(e: Expr) -> Expr {
    if let Expr::Deref(inner) = &e {
        if let Some(k) = stack_offset(inner) {
            return Expr::Var(stack_name(k)); // scalar stack var — drop the dereference
        }
    }
    if let Some(k) = stack_offset(&e) {
        return Expr::Var(stack_name(k)); // a stack address used as a value (e.g. an arg)
    }
    match e {
        Expr::Call(n, a) => Expr::Call(n, a.into_iter().map(name_stack).collect()),
        Expr::FnCall(n, a) => Expr::FnCall(n, a.into_iter().map(name_stack).collect()),
        Expr::Unary(op, a) => Expr::Unary(op, Box::new(name_stack(*a))),
        Expr::Binary(op, a, b) => Expr::Binary(op, Box::new(name_stack(*a)), Box::new(name_stack(*b))),
        Expr::Ternary(c, t, el) => Expr::Ternary(Box::new(name_stack(*c)), Box::new(name_stack(*t)), Box::new(name_stack(*el))),
        Expr::Deref(p) => Expr::Deref(Box::new(name_stack(*p))),
        other => other,
    }
}

/// Apply [`name_stack`] across a statement tree. A store to a scalar stack slot becomes
/// a named assignment (`aStack_C = v`) rather than `*(addr) = v`.
fn name_stack_stmt(s: Stmt) -> Stmt {
    match s {
        Stmt::Return(e) => Stmt::Return(name_stack(e)),
        Stmt::If(c, t, el) => Stmt::If(name_stack(c), Box::new(name_stack_stmt(*t)), el.map(|e| Box::new(name_stack_stmt(*e)))),
        Stmt::Seq(v) => Stmt::Seq(v.into_iter().map(name_stack_stmt).collect()),
        Stmt::Decl(n, e) => Stmt::Decl(n, name_stack(e)),
        Stmt::Assign(n, e) => Stmt::Assign(n, name_stack(e)),
        Stmt::Expr(e) => Stmt::Expr(name_stack(e)),
        Stmt::Store(a, v) => match stack_offset(&a) {
            Some(k) => Stmt::Assign(stack_name(k), name_stack(v)),
            None => Stmt::Store(name_stack(a), name_stack(v)),
        },
        Stmt::DoWhile(b, c) => Stmt::DoWhile(Box::new(name_stack_stmt(*b)), name_stack(c)),
        Stmt::While(c, b) => Stmt::While(name_stack(c), Box::new(name_stack_stmt(*b))),
        Stmt::For(i, c, u, b) => Stmt::For(Box::new(name_stack_stmt(*i)), name_stack(c), Box::new(name_stack_stmt(*u)), Box::new(name_stack_stmt(*b))),
        Stmt::Switch(e, cases, def) => {
            Stmt::Switch(name_stack(e), cases.into_iter().map(|(vals, body)| (vals, name_stack_stmt(body))).collect(), def.map(|d| Box::new(name_stack_stmt(*d))))
        }
    }
}

/// The distinct named stack locals (`aStack_*`) referenced anywhere in a statement —
/// both in expressions and as assignment targets — so they can be declared.
fn collect_stack_vars(s: &Stmt, out: &mut std::collections::BTreeSet<String>) {
    let add_expr = |e: &Expr, out: &mut std::collections::BTreeSet<String>| {
        out.extend(expr_vars(e).into_iter().filter(|v| v.starts_with("aStack_")));
    };
    let add_name = |n: &str, out: &mut std::collections::BTreeSet<String>| {
        if n.starts_with("aStack_") {
            out.insert(n.to_string());
        }
    };
    match s {
        Stmt::Return(e) | Stmt::Expr(e) => add_expr(e, out),
        Stmt::Decl(n, e) | Stmt::Assign(n, e) => {
            add_name(n, out);
            add_expr(e, out);
        }
        Stmt::If(c, t, el) => {
            add_expr(c, out);
            collect_stack_vars(t, out);
            if let Some(e) = el {
                collect_stack_vars(e, out);
            }
        }
        Stmt::Seq(v) => v.iter().for_each(|s| collect_stack_vars(s, out)),
        Stmt::Store(a, b) => {
            add_expr(a, out);
            add_expr(b, out);
        }
        Stmt::DoWhile(b, c) => {
            collect_stack_vars(b, out);
            add_expr(c, out);
        }
        Stmt::While(c, b) => {
            add_expr(c, out);
            collect_stack_vars(b, out);
        }
        Stmt::For(i, c, u, b) => {
            collect_stack_vars(i, out);
            add_expr(c, out);
            collect_stack_vars(u, out);
            collect_stack_vars(b, out);
        }
        Stmt::Switch(e, cases, def) => {
            add_expr(e, out);
            cases.iter().for_each(|(_, b)| collect_stack_vars(b, out));
            if let Some(d) = def {
                collect_stack_vars(d, out);
            }
        }
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

/// Does `target` occur as a sub-expression of `e`?
fn contains_expr(e: &Expr, target: &Expr) -> bool {
    if e == target {
        return true;
    }
    match e {
        Expr::Unary(_, a) | Expr::Deref(a) => contains_expr(a, target),
        Expr::Binary(_, a, b) => contains_expr(a, target) || contains_expr(b, target),
        Expr::Ternary(c, t, el) => contains_expr(c, target) || contains_expr(t, target) || contains_expr(el, target),
        Expr::Call(_, args) | Expr::FnCall(_, args) => args.iter().any(|a| contains_expr(a, target)),
        _ => false,
    }
}

/// Does `target` occur in any expression of statement `s`? (Loop-body CSE.)
fn stmt_contains_expr(s: &Stmt, target: &Expr) -> bool {
    match s {
        Stmt::Expr(e) | Stmt::Assign(_, e) | Stmt::Decl(_, e) | Stmt::Return(e) => contains_expr(e, target),
        Stmt::Store(p, v) => contains_expr(p, target) || contains_expr(v, target),
        _ => false,
    }
}

/// Replace every occurrence of `target` with `Var(name)` in statement `s`.
fn subst_in_stmt(s: &Stmt, target: &Expr, name: &str) -> Stmt {
    let su = |e: &Expr| subst(e, target, name);
    match s {
        Stmt::Expr(e) => Stmt::Expr(su(e)),
        Stmt::Assign(n, e) => Stmt::Assign(n.clone(), su(e)),
        Stmt::Decl(n, e) => Stmt::Decl(n.clone(), su(e)),
        Stmt::Return(e) => Stmt::Return(su(e)),
        Stmt::Store(p, v) => Stmt::Store(su(p), su(v)),
        other => other.clone(),
    }
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
    // fold nested constant multiplies: (x * c1) * c2  =>  x * (c1*c2) — so a
    // strength-reduced `q * 6` (emitted as `(q*3)*2`) collapses for the modulo idiom
    if let Expr::Binary("*", a, b) = &e {
        let assoc = |inner: &Expr, c2: u64, sz: u32| -> Option<Expr> {
            if let Expr::Binary("*", p, q) = inner {
                let (x, c1) = match (&**p, &**q) {
                    (Expr::Const(v, _), _) => (q, *v),
                    (_, Expr::Const(v, _)) => (p, *v),
                    _ => return None,
                };
                return Some(Expr::Binary("*", x.clone(), Box::new(Expr::Const(c1.wrapping_mul(c2), sz))));
            }
            None
        };
        if let Expr::Const(v2, sz) = &**b {
            if let Some(r) = assoc(a, *v2, *sz) {
                return simplify(r);
            }
        }
        if let Expr::Const(v2, sz) = &**a {
            if let Some(r) = assoc(b, *v2, *sz) {
                return simplify(r);
            }
        }
    }
    // self-cancelling: x ^ x => 0 and x - x => 0 (Ghidra RuleXorCollapse / identity).
    // The `xorps reg,reg` float-zero idiom decompiles to `x ^ x`; folding it to 0 turns
    // `a / (x ^ x)` into `a / 0` — matching Ghidra's `a / 0.0`.
    if let Expr::Binary("^" | "-", a, b) = &e {
        if a == b && !expr_has_call(a) {
            return Expr::Const(0, 4);
        }
    }
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
    // remainder idiom: a - (a / c) * c  =>  a % c  (Ghidra RuleModOpt; the division is
    // recovered by divrecover, the `* c` strength reduction folded by add_mul above)
    if let Expr::Binary("-", a, m) = &e {
        if let Expr::Binary("*", p, q) = &**m {
            // dv is `a / C`, c is the constant `C` (compared by value — widths may differ)
            let amod = |dv: &Expr, c: &Expr| -> Option<Expr> {
                if let (Expr::Binary("/", num, den), Expr::Const(cv, _)) = (dv, c) {
                    if let Expr::Const(dvv, _) = &**den {
                        if num.as_ref() == &**a && dvv == cv {
                            return Some(Expr::Binary("%", a.clone(), den.clone()));
                        }
                    }
                }
                None
            };
            if let Some(r) = amod(p, q).or_else(|| amod(q, p)) {
                return r;
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
