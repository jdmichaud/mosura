//! Decompiler D1: SSA scaffolding — dominator tree, dominance frontiers, and phi
//! (MULTIEQUAL) placement (Cytron et al.; Ghidra `Heritage`).
//!
//! SSA is built over *heritaged* spaces (register/unique); const and ram are not
//! versioned (memory flows through LOAD/STORE). NOTE: overlapping varnodes (e.g.
//! `EAX`=(register,0x0,4) vs `RAX`=(register,0x0,8)) are treated as distinct
//! locations — a correct SSA of the p-code-as-written when each location is used at
//! a consistent size (true for the target functions); general aliasing/coverage is
//! a later refinement (it matters for D3 variable recovery, not SSA form).

use super::cfg::Funcdata;
use std::collections::{HashMap, HashSet};

/// A heritaged storage location: `(space, offset, size)`.
pub type Loc = (String, u64, u32);

pub fn heritaged(space: &str) -> bool {
    space == "register" || space == "unique" || space == "stack"
}

/// Dominator-tree result.
pub struct Dominators {
    /// Immediate dominator per block; `idom[entry] == entry`, `usize::MAX` if the
    /// block is unreachable from the entry.
    pub idom: Vec<usize>,
    /// Postorder index per block (entry has the highest); `usize::MAX` if unreachable.
    pub post: Vec<usize>,
}

impl Funcdata {
    /// Map each op index to the id of the block containing it.
    fn op_blocks(&self) -> Vec<usize> {
        let mut v = vec![0usize; self.ops.len()];
        for (b, blk) in self.blocks.iter().enumerate() {
            for i in blk.start..blk.end {
                v[i] = b;
            }
        }
        v
    }

    /// Immediate-dominator tree via Cooper–Harvey–Kennedy.
    pub fn dominators(&self) -> Dominators {
        let n = self.blocks.len();
        // Iterative postorder DFS from the entry (block 0).
        let mut post = vec![usize::MAX; n];
        let mut order: Vec<usize> = Vec::new();
        let mut visited = vec![false; n];
        if n > 0 {
            visited[0] = true;
            let mut stack = vec![(0usize, 0usize)];
            while let Some(&(b, ci)) = stack.last() {
                if ci < self.blocks[b].succ.len() {
                    stack.last_mut().unwrap().1 += 1;
                    let s = self.blocks[b].succ[ci];
                    if !visited[s] {
                        visited[s] = true;
                        stack.push((s, 0));
                    }
                } else {
                    post[b] = order.len();
                    order.push(b);
                    stack.pop();
                }
            }
        }
        let rpo: Vec<usize> = order.iter().rev().copied().collect();

        let intersect = |mut a: usize, mut b: usize, idom: &[usize], post: &[usize]| {
            while a != b {
                while post[a] < post[b] {
                    a = idom[a];
                }
                while post[b] < post[a] {
                    b = idom[b];
                }
            }
            a
        };

        let mut idom = vec![usize::MAX; n];
        if n > 0 {
            idom[0] = 0;
        }
        let mut changed = true;
        while changed {
            changed = false;
            for &b in &rpo {
                if b == 0 {
                    continue;
                }
                let mut new_idom = usize::MAX;
                for &p in &self.blocks[b].pred {
                    if idom[p] != usize::MAX {
                        new_idom = if new_idom == usize::MAX { p } else { intersect(p, new_idom, &idom, &post) };
                    }
                }
                if new_idom != usize::MAX && idom[b] != new_idom {
                    idom[b] = new_idom;
                    changed = true;
                }
            }
        }
        Dominators { idom, post }
    }

    /// Dominance frontier of every block.
    pub fn dominance_frontier(&self, dom: &Dominators) -> Vec<Vec<usize>> {
        let n = self.blocks.len();
        let mut df = vec![Vec::new(); n];
        for b in 0..n {
            if self.blocks[b].pred.len() < 2 || dom.idom[b] == usize::MAX {
                continue;
            }
            for &p in &self.blocks[b].pred {
                let mut runner = p;
                while runner != usize::MAX && runner != dom.idom[b] {
                    if !df[runner].contains(&b) {
                        df[runner].push(b);
                    }
                    if runner == dom.idom[runner] {
                        break; // entry self-loop
                    }
                    runner = dom.idom[runner];
                }
            }
        }
        df
    }

    /// Blocks needing a phi (MULTIEQUAL) node, as `(block, location)` — the iterated
    /// dominance frontier of each location's definition sites.
    pub fn phi_sites(&self, dom: &Dominators) -> Vec<(usize, Loc)> {
        let df = self.dominance_frontier(dom);
        let opb = self.op_blocks();

        let mut defsites: HashMap<Loc, Vec<usize>> = HashMap::new();
        for (i, fo) in self.ops.iter().enumerate() {
            if let Some(out) = &fo.op.out {
                if heritaged(&out.space) {
                    let blocks = defsites.entry((out.space.clone(), out.offset, out.size)).or_default();
                    if !blocks.contains(&opb[i]) {
                        blocks.push(opb[i]);
                    }
                }
            }
        }

        let mut result = Vec::new();
        for (loc, sites) in &defsites {
            let mut worklist = sites.clone();
            let mut ever: HashSet<usize> = sites.iter().copied().collect();
            let mut has_phi: HashSet<usize> = HashSet::new();
            while let Some(b) = worklist.pop() {
                if b >= df.len() {
                    continue;
                }
                for &d in &df[b] {
                    if has_phi.insert(d) {
                        result.push((d, loc.clone()));
                    }
                    if ever.insert(d) {
                        worklist.push(d);
                    }
                }
            }
        }
        result
    }

    /// Full SSA: dominators, placed phi nodes, and the reaching definition of every
    /// heritaged use (Cytron renaming over the dominator tree).
    ///
    /// `live_out` names locations whose value is live at function exit (e.g. the
    /// calling-convention return register) — minimal return recovery, so dead-code
    /// elimination doesn't delete the result. Each is recorded as a synthetic use
    /// at every `RETURN`.
    pub fn ssa(&self, live_out: &[Loc]) -> Ssa {
        let dom = self.dominators();
        let n = self.blocks.len();
        let mut phis: Vec<Phi> = self
            .phi_sites(&dom)
            .into_iter()
            .map(|(b, loc)| Phi { block: b, loc, args: vec![Def::Live; self.blocks[b].pred.len()] })
            .collect();

        let mut block_phis = vec![Vec::new(); n];
        for (pi, ph) in phis.iter().enumerate() {
            block_phis[ph.block].push(pi);
        }
        // dominator-tree children
        let mut children = vec![Vec::new(); n];
        for c in 0..n {
            if c != 0 && dom.idom[c] != usize::MAX {
                children[dom.idom[c]].push(c);
            }
        }

        let mut uses: HashMap<(usize, usize), Def> = HashMap::new();
        let mut stack: HashMap<Loc, Vec<Def>> = HashMap::new();
        if n > 0 {
            rename(0, self, &children, &block_phis, live_out, &mut phis, &mut uses, &mut stack);
        }
        Ssa { dom, phis, uses }
    }
}

/// An SSA definition site.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Def {
    /// Defined by `ops[i]`'s output.
    Op(usize),
    /// Defined by `phis[i]`.
    Phi(usize),
    /// Live-in (function input / undefined on entry).
    Live,
}

/// A phi (MULTIEQUAL) node: one incoming definition per predecessor block.
#[derive(Clone, Debug)]
pub struct Phi {
    pub block: usize,
    pub loc: Loc,
    pub args: Vec<Def>,
}

/// SSA form of a function.
pub struct Ssa {
    pub dom: Dominators,
    pub phis: Vec<Phi>,
    /// Reaching definition for each heritaged use, keyed `(op_index, input_index)`.
    pub uses: HashMap<(usize, usize), Def>,
}

#[allow(clippy::too_many_arguments)]
fn rename(
    block: usize,
    f: &Funcdata,
    children: &[Vec<usize>],
    block_phis: &[Vec<usize>],
    live_out: &[Loc],
    phis: &mut [Phi],
    uses: &mut HashMap<(usize, usize), Def>,
    stack: &mut HashMap<Loc, Vec<Def>>,
) {
    let top = |stack: &HashMap<Loc, Vec<Def>>, loc: &Loc| stack.get(loc).and_then(|s| s.last().copied()).unwrap_or(Def::Live);
    let mut pushed: Vec<Loc> = Vec::new();

    // phis define their location
    for &pi in &block_phis[block] {
        let loc = phis[pi].loc.clone();
        stack.entry(loc.clone()).or_default().push(Def::Phi(pi));
        pushed.push(loc);
    }
    // ops: resolve heritaged uses, then define the output
    for i in f.blocks[block].start..f.blocks[block].end {
        let op = &f.ops[i].op;
        for (pos, arg) in op.ins.iter().enumerate() {
            if let Some(v) = arg.as_var() {
                if heritaged(&v.space) {
                    let d = top(stack, &(v.space.clone(), v.offset, v.size));
                    uses.insert((i, pos), d);
                }
            }
        }
        if let Some(out) = &op.out {
            if heritaged(&out.space) {
                let loc = (out.space.clone(), out.offset, out.size);
                stack.entry(loc.clone()).or_default().push(Def::Op(i));
                pushed.push(loc);
            }
        }
        if op.opcode == 10 {
            // RETURN: the live-out locations read their reaching definition here.
            for (k, loc) in live_out.iter().enumerate() {
                let d = top(stack, loc);
                uses.insert((i, op.ins.len() + k), d);
            }
        }
    }
    // fill in this block's slot of each successor's phis
    for &s in &f.blocks[block].succ {
        let j = f.blocks[s].pred.iter().position(|&p| p == block).unwrap_or(0);
        for &pi in &block_phis[s] {
            let d = top(stack, &phis[pi].loc);
            if j < phis[pi].args.len() {
                phis[pi].args[j] = d;
            }
        }
    }
    // recurse over dominator-tree children
    for &c in &children[block] {
        rename(c, f, children, block_phis, live_out, phis, uses, stack);
    }
    // pop everything defined here
    for loc in pushed {
        if let Some(st) = stack.get_mut(&loc) {
            st.pop();
        }
    }
}
