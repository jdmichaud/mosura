//! Control-flow structuring — Ghidra's `CollapseStructure` (`blockaction.cc`) over a
//! `BlockGraph` (`block.cc`). Repeatedly collapses CFG patterns into structured blocks
//! (list/if/if-else/while/do-while) until one block remains, recovering `if`/`while`/`for`
//! from the goto-level CFG.
//!
//! The graph is a vector of [`FlowBlock`]s; each structured block lists its sub-blocks and
//! presents the same successor interface, so the rules compose. Out-edges are the source of
//! truth; in-edges are recomputed each pass. CBRANCH order is `[false, true]` (as built by
//! `cfg`). This increment ports the reducible patterns; gotos for irreducible regions,
//! switches, and short-circuit conditions are later additions.

use std::collections::{HashMap, HashSet};

use super::block::BlockId;
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::varnode::VarnodeId;

/// The lone op that reads `vn`, or `None` if it has zero or multiple readers (Ghidra's
/// `Varnode::loneDescend`).
fn lone_descend(f: &Funcdata, vn: VarnodeId) -> Option<OpId> {
    let d = &f.vn(vn).descend;
    (d.len() == 1).then(|| d[0])
}

/// Faithful port of `Funcdata::opFlipInPlaceTest` (funcdata_op.cc:1221): trace a boolean
/// value to decide whether flipping it (negating the predicate + swapping the branch arms)
/// puts the condition in Ghidra's normal form. Returns 0 if the flip normalizes, 1 if it is
/// ambivalent, 2 if it cannot. `op` is the CBRANCH (Ghidra recurses to its `getIn(1)`'s def);
/// the normal form prefers `==` over `!=`, a constant on the left of `<`, and a non-constant
/// on the right of `<=`. This is the decision behind `ActionNormalizeBranches`
/// (blockaction.cc:2117); mosura applies it at the structurer + print-time negation
/// (`printc::render_negated`, the `get_booleanflip`/`replaceLessequal` port) rather than as
/// an IR rewrite — a justified architectural subset, result-verified against `oracle --c`.
fn op_flip_in_place_test(f: &Funcdata, op: OpId) -> i32 {
    match f.op(op).code() {
        OpCode::Cbranch => {
            let Some(vn) = f.op(op).input(1) else { return 2 };
            if lone_descend(f, vn) != Some(op) || !f.vn(vn).is_written() {
                return 2;
            }
            op_flip_in_place_test(f, f.vn(vn).def.unwrap())
        }
        OpCode::IntEqual | OpCode::FloatEqual => 1,
        OpCode::BoolNegate | OpCode::IntNotequal | OpCode::FloatNotequal => 0,
        OpCode::IntSless | OpCode::IntLess => {
            let in0 = f.op(op).input(0).unwrap();
            if f.vn(in0).is_constant() { 0 } else { 1 }
        }
        OpCode::IntSlessequal | OpCode::IntLessequal => {
            let in1 = f.op(op).input(1).unwrap();
            if f.vn(in1).is_constant() { 1 } else { 0 }
        }
        OpCode::BoolOr | OpCode::BoolAnd => {
            let in0 = f.op(op).input(0).unwrap();
            if lone_descend(f, in0) != Some(op) || !f.vn(in0).is_written() {
                return 2;
            }
            let subtest1 = op_flip_in_place_test(f, f.vn(in0).def.unwrap());
            if subtest1 == 2 {
                return 2;
            }
            let in1 = f.op(op).input(1).unwrap();
            if lone_descend(f, in1) != Some(op) || !f.vn(in1).is_written() {
                return 2;
            }
            let subtest2 = op_flip_in_place_test(f, f.vn(in1).def.unwrap());
            if subtest2 == 2 {
                return 2;
            }
            subtest1 // the front of an AND/OR governs whether the whole normalizes
        }
        _ => 2,
    }
}

/// A node in the structuring graph: a leaf basic block or a structured composite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlowKind {
    Basic(BlockId),
    /// Sequence; components run in order.
    List,
    /// `if (cond) then` — components `[cond, then]`.
    If,
    /// `if (cond) tc else fc` — components `[cond, tc, fc]`.
    IfElse,
    /// `while (cond) body` — components `[cond, body]`.
    WhileDo,
    /// `do body while (cond)` — components `[body]`.
    DoWhile,
    /// Short-circuit `a && b` — components `[a, b]`; still a two-out condition block.
    CondAnd,
    /// Short-circuit `a || b` — components `[a, b]`; still a two-out condition block.
    CondOr,
    /// `switch` — components `[head, case0, case1, …]`; head ends in BRANCHIND.
    Switch,
}

#[derive(Clone, Debug)]
pub struct FlowBlock {
    pub kind: FlowKind,
    pub components: Vec<usize>,
    pub out_edges: Vec<usize>,
    pub active: bool,
    /// For `If`/`IfElse`/`WhileDo`/`DoWhile`: the body/then is reached on the condition's
    /// *false* edge, so the printed condition must be negated.
    pub negated: bool,
}

/// The structured-block forest; `root` is the single block the CFG collapsed to (or the
/// entry, if the CFG was irreducible and could not fully collapse).
pub struct Structured {
    pub blocks: Vec<FlowBlock>,
    pub root: usize,
    /// Edges cut to gotos for an irreducible region: source exit basic block → (target
    /// entry basic block, negated condition). An unconditional source has no CBRANCH.
    pub gotos: HashMap<BlockId, (BlockId, bool)>,
    /// Basic blocks that are goto targets (get a label).
    pub labels: HashSet<BlockId>,
    /// Per basic block (indexed by `BlockId`): whether its terminating CBRANCH condition is in
    /// non-normal form so an `if`/`else` over it should flip to the positive form (Ghidra's
    /// `opFlipInPlaceTest == 0`). Precomputed from `Funcdata` since the structurer holds no `f`.
    flip: Vec<bool>,
}

impl Structured {
    /// The entry basic block of a structured block (where a goto label would go).
    fn entry_basic(&self, idx: usize) -> Option<BlockId> {
        match &self.blocks[idx].kind {
            FlowKind::Basic(b) => Some(*b),
            _ => self.entry_basic(*self.blocks[idx].components.first()?),
        }
    }
    /// The exit basic block of a structured block (where its terminating branch lives).
    fn exit_basic(&self, idx: usize) -> Option<BlockId> {
        match &self.blocks[idx].kind {
            FlowKind::Basic(b) => Some(*b),
            _ => self.exit_basic(*self.blocks[idx].components.last()?),
        }
    }

    /// Predecessor lists for the currently-active blocks, from their out-edges.
    fn in_edges(&self) -> Vec<Vec<usize>> {
        let mut ins = vec![Vec::new(); self.blocks.len()];
        for b in 0..self.blocks.len() {
            if self.blocks[b].active {
                for &o in &self.blocks[b].out_edges {
                    ins[o].push(b);
                }
            }
        }
        ins
    }

    /// Replace `components` (entry = `components[0]`) with one structured block of `kind`
    /// and the given external `out_edges`. Predecessors of the entry are redirected to the
    /// new block; components are deactivated.
    fn install(&mut self, components: Vec<usize>, kind: FlowKind, out_edges: Vec<usize>, ins: &[Vec<usize>]) -> usize {
        let entry = components[0];
        let compset: HashSet<usize> = components.iter().copied().collect();
        let n = self.blocks.len();
        let preds: Vec<usize> = ins[entry].iter().copied().filter(|p| !compset.contains(p)).collect();
        self.blocks.push(FlowBlock { kind, components, out_edges, active: true, negated: false });
        for p in preds {
            for e in self.blocks[p].out_edges.iter_mut() {
                if compset.contains(e) {
                    *e = n;
                }
            }
        }
        for &c in &self.blocks[n].components.clone() {
            self.blocks[c].active = false;
        }
        n
    }

    /// `ruleBlockSwitch`: a block with ≥3 out-edges is a switch head (a BRANCHIND). Collapse
    /// it with its single-entry case successors into a `Switch`; the remaining edges (shared
    /// / default cases, or break targets) are the switch's exits.
    fn rule_switch(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        if self.out(b).len() < 3 {
            return false;
        }
        // Defer until each single-entry case has fully collapsed: a case with internal control
        // flow (an `if` in its body, >1 exit) must structure first, and a case whose single
        // exit is its own continuation block (a single-entry "break" tail) must `cat` that tail
        // in first — otherwise those tails leak as extra switch exits and the dispatch nests
        // into gotos (the switch-in-loop case).
        for c in self.blocks[b].out_edges.clone() {
            if c == b || ins[c].len() != 1 {
                continue;
            }
            let outc: Vec<usize> = self.out(c).to_vec();
            if outc.len() > 1 || (outc.len() == 1 && outc[0] != b && ins[outc[0]].len() == 1) {
                return false;
            }
        }
        let mut comps = vec![b];
        let mut exits: Vec<usize> = Vec::new();
        for c in self.blocks[b].out_edges.clone() {
            if c == b {
                return false;
            }
            if ins[c].len() == 1 && self.out(c).len() <= 1 {
                comps.push(c);
                exits.extend(self.out(c).iter().copied());
            } else {
                exits.push(c);
            }
        }
        if comps.len() < 2 {
            return false;
        }
        exits.retain(|e| !comps.contains(e));
        exits.sort_unstable();
        exits.dedup();
        self.install(comps, FlowKind::Switch, exits, ins);
        true
    }

    /// Try every rule on `b`; return whether one fired (and changed the graph).
    fn try_rules(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        self.rule_switch(b, ins)
            || self.rule_cat(b, ins)
            || self.rule_short_circuit(b, ins)
            || self.rule_proper_if(b, ins)
            || self.rule_if_else(b, ins)
            || self.rule_while_do(b, ins)
            || self.rule_do_while(b, ins)
            // after the loop rules: a loop exit is terminal too, so loops must match first
            || self.rule_if_no_exit(b, ins)
    }

    /// `ruleBlockIfNoExit`: `if (cond) clause` where the clause is a single-entry block with
    /// no exit (it returns/halts), so control continues to the other arm afterwards.
    fn rule_if_no_exit(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        if self.out(b).len() != 2 || self.out(b)[0] == b || self.out(b)[1] == b {
            return false;
        }
        for i in 0..2 {
            let (clause, other) = (self.out(b)[i], self.out(b)[1 - i]);
            if clause != other && ins[clause].len() == 1 && self.out(clause).is_empty() {
                // don't dissolve a loop header: if the other arm flows back to `b`, this is the
                // exit test of a loop — leave it for the loop rules (after the body collapses).
                if self.reaches(other, b) {
                    continue;
                }
                let n = self.install(vec![b, clause], FlowKind::If, vec![other], ins);
                self.blocks[n].negated = i == 0;
                return true;
            }
        }
        false
    }

    /// Whether `from` can reach `target` over the current (active) structure graph.
    fn reaches(&self, from: usize, target: usize) -> bool {
        let mut seen = vec![false; self.blocks.len()];
        let mut stack = vec![from];
        while let Some(x) = stack.pop() {
            if x == target {
                return true;
            }
            if std::mem::replace(&mut seen[x], true) {
                continue;
            }
            stack.extend_from_slice(self.out(x));
        }
        false
    }

    /// `ruleBlockCondition`: two chained condition blocks collapse to a short-circuit
    /// condition. For `a && b`, `a`'s *true* edge enters `b` and both *false* edges share an
    /// exit; for `a || b`, `a`'s *false* edge enters `b` and both *true* edges share. The
    /// result is itself a two-out condition block (structured later by the `if` rules).
    fn rule_short_circuit(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        if self.out(b).len() != 2 {
            return false;
        }
        for and in [true, false] {
            let (cont, shared) = if and { (1, 0) } else { (0, 1) };
            let bb = self.out(b)[cont]; // the second condition
            if bb == b || ins[bb].len() != 1 || self.out(bb).len() != 2 {
                continue;
            }
            if self.out(b)[shared] == bb || self.out(b)[shared] != self.out(bb)[shared] {
                continue;
            }
            let out = self.blocks[bb].out_edges.clone();
            let kind = if and { FlowKind::CondAnd } else { FlowKind::CondOr };
            self.install(vec![b, bb], kind, out, ins);
            return true;
        }
        false
    }

    fn out(&self, b: usize) -> &[usize] {
        &self.blocks[b].out_edges
    }

    /// `ruleBlockGoto`: last resort for an irreducible region — when no structural rule
    /// fires, cut one in-edge of a merge block to a goto so structuring can proceed. The cut
    /// edge `b → t` is recorded (`b`'s exit emits `goto L_t`, `t`'s entry gets a label) and
    /// removed; `b` (now with one fewer out-edge) and `t` (one fewer in-edge) become
    /// reducible. Repeated until the graph collapses.
    fn rule_goto(&mut self) -> bool {
        let ins = self.in_edges();
        let active: Vec<usize> = (0..self.blocks.len()).filter(|&b| self.blocks[b].active).collect();
        for &t in &active {
            if ins[t].len() < 2 {
                continue;
            }
            for &b in &ins[t] {
                if b == t {
                    continue; // a self-loop is a do-while, not a goto
                }
                let Some(idx) = self.blocks[b].out_edges.iter().position(|&o| o == t) else {
                    continue;
                };
                let (Some(eb), Some(et)) = (self.exit_basic(b), self.entry_basic(t)) else {
                    continue;
                };
                self.gotos.insert(eb, (et, idx == 0)); // out[0] is the false edge
                self.labels.insert(et);
                self.blocks[b].out_edges.remove(idx);
                return true;
            }
        }
        false
    }

    /// `ruleBlockCat`: a chain of single-out → single-in blocks becomes a list.
    fn rule_cat(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        if self.out(b).len() != 1 {
            return false;
        }
        // if b's only predecessor has a single out, let that predecessor start the list
        if ins[b].len() == 1 && self.out(ins[b][0]).len() == 1 {
            return false;
        }
        let mut nodes = vec![b];
        let mut cur = b;
        loop {
            let nxt = self.out(cur)[0];
            if nxt == b || ins[nxt].len() != 1 {
                break;
            }
            nodes.push(nxt);
            cur = nxt;
            if self.out(cur).len() != 1 {
                break;
            }
        }
        if nodes.len() < 2 {
            return false;
        }
        let out = self.blocks[*nodes.last().unwrap()].out_edges.clone();
        self.install(nodes, FlowKind::List, out, ins);
        true
    }

    /// `ruleBlockProperIf`: `if (cond) clause` where `clause` reconverges to the other arm.
    fn rule_proper_if(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        if self.out(b).len() != 2 || self.out(b)[0] == b || self.out(b)[1] == b {
            return false;
        }
        for i in 0..2 {
            let clause = self.out(b)[i];
            if ins[clause].len() == 1 && self.out(clause).len() == 1 && self.out(clause)[0] == self.out(b)[1 - i] {
                let merge = self.out(b)[1 - i];
                let n = self.install(vec![b, clause], FlowKind::If, vec![merge], ins);
                self.blocks[n].negated = i == 0;
                return true;
            }
        }
        false
    }

    /// Whether the `if`/`else` over condition block `b` should be rendered in Ghidra's positive
    /// normal form (`opFlipInPlaceTest == 0`): swap the then/else arms and negate the printed
    /// condition. A compound (short-circuit) condition is left as-is — its normal form needs the
    /// `BOOL_AND`/`BOOL_OR` recursion over the structural operands (a faithful subset, the simple
    /// CBRANCH case covers the corpus's if/else conditions).
    fn if_else_flip(&self, b: usize) -> bool {
        if matches!(self.blocks[b].kind, FlowKind::CondAnd | FlowKind::CondOr) {
            return false;
        }
        self.exit_basic(b).is_some_and(|bid| self.flip.get(bid.0 as usize).copied().unwrap_or(false))
    }

    /// `ruleBlockIfElse`: both arms reconverge to one block.
    fn rule_if_else(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        if self.out(b).len() != 2 {
            return false;
        }
        let (fc, tc) = (self.out(b)[0], self.out(b)[1]);
        if ins[tc].len() != 1 || ins[fc].len() != 1 || self.out(tc).len() != 1 || self.out(fc).len() != 1 {
            return false;
        }
        let merge = self.out(tc)[0];
        if merge == b || merge != self.out(fc)[0] {
            return false;
        }
        // Ghidra `ActionNormalizeBranches`: render the positive form when the condition is
        // non-normal — swap the then/else arms and negate (printc::render_negated). The taken
        // edge `tc` is the un-negated then; flipping makes the fall-through `fc` the then.
        let flip = self.if_else_flip(b);
        let (then_c, else_c) = if flip { (fc, tc) } else { (tc, fc) };
        let n = self.install(vec![b, then_c, else_c], FlowKind::IfElse, vec![merge], ins);
        self.blocks[n].negated = flip;
        true
    }

    /// `ruleBlockWhileDo`: one arm is a single-in/single-out block that loops back to `b`.
    fn rule_while_do(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        if self.out(b).len() != 2 || self.out(b)[0] == b || self.out(b)[1] == b {
            return false;
        }
        for i in 0..2 {
            let body = self.out(b)[i];
            if ins[body].len() == 1 && self.out(body).len() == 1 && self.out(body)[0] == b {
                let exit = self.out(b)[1 - i];
                let n = self.install(vec![b, body], FlowKind::WhileDo, vec![exit], ins);
                self.blocks[n].negated = i == 0;
                return true;
            }
        }
        false
    }

    /// `ruleBlockDoWhile`: a block with a self-edge.
    fn rule_do_while(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        if self.out(b).len() != 2 {
            return false;
        }
        for i in 0..2 {
            if self.out(b)[i] == b {
                let exit = self.out(b)[1 - i];
                let n = self.install(vec![b], FlowKind::DoWhile, vec![exit], ins);
                self.blocks[n].negated = i == 0;
                return true;
            }
        }
        false
    }
}

/// Structure the CFG of `f`.
pub fn structure(f: &Funcdata) -> Structured {
    let blocks: Vec<FlowBlock> = (0..f.num_blocks())
        .map(|b| FlowBlock {
            kind: FlowKind::Basic(BlockId(b as u32)),
            components: Vec::new(),
            out_edges: f.blocks()[b].out_edges.iter().map(|e| e.0 as usize).collect(),
            active: true,
            negated: false,
        })
        .collect();
    // Precompute the normal-form flip decision per basic block from its terminating CBRANCH
    // (Ghidra's `opFlipInPlaceTest`); `rule_if_else` consults it to choose the positive form.
    let flip: Vec<bool> = (0..f.num_blocks())
        .map(|b| {
            let bid = BlockId(b as u32);
            f.block(bid)
                .ops
                .last()
                .copied()
                .is_some_and(|op| f.op(op).code() == OpCode::Cbranch && op_flip_in_place_test(f, op) == 0)
        })
        .collect();
    let mut s = Structured { blocks, root: 0, gotos: HashMap::new(), labels: HashSet::new(), flip };

    loop {
        let active: Vec<usize> = (0..s.blocks.len()).filter(|&b| s.blocks[b].active).collect();
        if active.len() <= 1 {
            break;
        }
        let ins = s.in_edges();
        let mut fired = false;
        for &b in &active {
            if s.try_rules(b, &ins) {
                fired = true;
                break;
            }
        }
        if !fired && !s.rule_goto() {
            break; // truly stuck (no structural rule and no goto edge to cut)
        }
    }
    s.root = (0..s.blocks.len()).find(|&b| s.blocks[b].active).unwrap_or(0);
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::block::{BlockBasic, BlockId};
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::Funcdata;

    fn cfg(nb: usize, edges: &[(usize, usize)]) -> Funcdata {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let mut blocks: Vec<BlockBasic> = vec![BlockBasic::default(); nb];
        for &(a, b) in edges {
            blocks[a].out_edges.push(BlockId(b as u32));
            blocks[b].in_edges.push(BlockId(a as u32));
        }
        f.set_blocks(blocks);
        f
    }

    fn active(s: &Structured) -> usize {
        (0..s.blocks.len()).filter(|&b| s.blocks[b].active).count()
    }
    fn kinds(s: &Structured) -> Vec<FlowKind> {
        let mut k = Vec::new();
        fn walk(s: &Structured, b: usize, k: &mut Vec<FlowKind>) {
            k.push(s.blocks[b].kind.clone());
            for &c in &s.blocks[b].components {
                walk(s, c, k);
            }
        }
        walk(s, s.root, &mut k);
        k
    }

    #[test]
    fn sequence_becomes_a_list() {
        let s = structure(&cfg(3, &[(0, 1), (1, 2)]));
        assert_eq!(active(&s), 1);
        assert_eq!(s.blocks[s.root].kind, FlowKind::List);
    }

    #[test]
    fn diamond_becomes_if_else() {
        // 0 -> {1(false), 2(true)} -> 3
        let s = structure(&cfg(4, &[(0, 1), (0, 2), (1, 3), (2, 3)]));
        assert_eq!(active(&s), 1);
        assert!(kinds(&s).contains(&FlowKind::IfElse));
    }

    #[test]
    fn triangle_becomes_proper_if() {
        // 0 -> {1, 2}; 1 -> 2  (then=1, merge=2)
        let s = structure(&cfg(3, &[(0, 1), (0, 2), (1, 2)]));
        assert_eq!(active(&s), 1);
        assert!(kinds(&s).contains(&FlowKind::If));
    }

    #[test]
    fn loop_becomes_while_do() {
        // 0 -> 1; 1 -> {2(body), 3(exit)}; 2 -> 1
        let s = structure(&cfg(4, &[(0, 1), (1, 2), (1, 3), (2, 1)]));
        assert_eq!(active(&s), 1);
        assert!(kinds(&s).contains(&FlowKind::WhileDo));
    }

    #[test]
    fn short_circuit_and_merges() {
        // A=0 out [merge=3(false), B=1(true)]; B=1 out [merge=3(false), then=2(true)]; 2 -> 3
        //   i.e. if (a && b) then(2); merge=3
        let s = structure(&cfg(4, &[(0, 3), (0, 1), (1, 3), (1, 2), (2, 3)]));
        assert_eq!(active(&s), 1);
        assert!(kinds(&s).contains(&FlowKind::CondAnd), "kinds: {:?}", kinds(&s));
    }

    #[test]
    fn short_circuit_or_merges() {
        // A=0 out [B=1(false), then=2(true)]; B=1 out [merge=3(false), then=2(true)]; 2 -> 3
        //   i.e. if (a || b) then(2); merge=3
        let s = structure(&cfg(4, &[(0, 1), (0, 2), (1, 3), (1, 2), (2, 3)]));
        assert_eq!(active(&s), 1);
        assert!(kinds(&s).contains(&FlowKind::CondOr), "kinds: {:?}", kinds(&s));
    }

    #[test]
    fn irreducible_collapses_with_goto() {
        // 0 -> {1, 2}; 1 -> 2; 2 -> 1  (1 and 2 form an irreducible two-cycle)
        let s = structure(&cfg(3, &[(0, 1), (0, 2), (1, 2), (2, 1)]));
        assert_eq!(active(&s), 1, "collapses fully via gotos");
        assert!(!s.gotos.is_empty(), "recorded a goto edge");
    }

    #[test]
    fn self_loop_becomes_do_while() {
        // 0 -> 1; 1 -> {1(self), 2(exit)}
        let s = structure(&cfg(3, &[(0, 1), (1, 1), (1, 2)]));
        assert_eq!(active(&s), 1);
        assert!(kinds(&s).contains(&FlowKind::DoWhile));
    }
}
