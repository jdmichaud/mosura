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

use std::collections::HashSet;

use super::block::BlockId;
use super::funcdata::Funcdata;

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
}

impl Structured {
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

    /// Try every rule on `b`; return whether one fired (and changed the graph).
    fn try_rules(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        self.rule_cat(b, ins)
            || self.rule_short_circuit(b, ins)
            || self.rule_proper_if(b, ins)
            || self.rule_if_else(b, ins)
            || self.rule_while_do(b, ins)
            || self.rule_do_while(b, ins)
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
        self.install(vec![b, tc, fc], FlowKind::IfElse, vec![merge], ins);
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
    let mut s = Structured { blocks, root: 0 };

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
        if !fired {
            break; // irreducible region — gotos are a later increment
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
    fn self_loop_becomes_do_while() {
        // 0 -> 1; 1 -> {1(self), 2(exit)}
        let s = structure(&cfg(3, &[(0, 1), (1, 1), (1, 2)]));
        assert_eq!(active(&s), 1);
        assert!(kinds(&s).contains(&FlowKind::DoWhile));
    }
}
