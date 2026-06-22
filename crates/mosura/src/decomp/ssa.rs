//! Decompiler D1: SSA scaffolding — dominator tree, dominance frontiers, and phi
//! (MULTIEQUAL) placement (Cytron et al.; Ghidra `Heritage`).
//!
//! SSA is built over *heritaged* spaces (register/unique/stack); const and ram are not
//! versioned (memory flows through LOAD/STORE). Locations are keyed by [`loc_key`]:
//! XMM/SSE registers merge across access width (a 4-byte zero-extending write and an
//! 8-byte read at the same offset are one SSA location — the float-overlap the SSE code
//! relies on, e.g. `xorps`/`movss`/`addsd`), while GP registers, unique temps, and stack
//! slots stay exact-size (the p-code-as-written SSA). Full byte-level coverage/aliasing
//! (Ghidra `Heritage`) is still a later refinement.

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

    /// Immediate post-dominator of each block: the nearest block through which every
    /// path from `b` to a function exit passes (`usize::MAX` if none / unreachable).
    /// Computed as the dominator tree of the reverse CFG joined at a virtual exit — the
    /// follow node of an `if` is the post-dominator of its branch block.
    pub fn post_idom(&self) -> Vec<usize> {
        let n = self.blocks.len();
        if n == 0 {
            return Vec::new();
        }
        let exit = n; // virtual exit node
        let fdom = self.dominators();
        let reach: Vec<bool> = (0..n).map(|b| fdom.post[b] != usize::MAX).collect();
        let succ_r = |b: usize| -> Vec<usize> {
            // forward successors of b that are reachable (b's predecessors in the reverse CFG)
            self.blocks[b].succ.iter().copied().filter(|&s| reach[s]).collect()
        };
        let is_sink = |b: usize| reach[b] && !self.blocks[b].succ.iter().any(|&s| reach[s]);

        // reverse-CFG adjacency for the postorder walk: exit -> every sink, b -> forward preds
        let mut radj = vec![Vec::new(); n + 1];
        for b in 0..n {
            if !reach[b] {
                continue;
            }
            if is_sink(b) {
                radj[exit].push(b);
            }
            for &p in &self.blocks[b].pred {
                if reach[p] {
                    radj[b].push(p);
                }
            }
        }

        // postorder of the reverse CFG from the virtual exit
        let mut post = vec![usize::MAX; n + 1];
        let mut order = Vec::new();
        let mut visited = vec![false; n + 1];
        visited[exit] = true;
        let mut stack = vec![(exit, 0usize)];
        while let Some(&(b, ci)) = stack.last() {
            if ci < radj[b].len() {
                stack.last_mut().unwrap().1 += 1;
                let s = radj[b][ci];
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
        let mut idom = vec![usize::MAX; n + 1];
        idom[exit] = exit;
        let mut changed = true;
        while changed {
            changed = false;
            for &b in &rpo {
                if b == exit {
                    continue;
                }
                // reverse-CFG predecessors of b = forward successors (+ exit if b is a sink)
                let mut preds = succ_r(b);
                if is_sink(b) {
                    preds.push(exit);
                }
                let mut new_idom = usize::MAX;
                for p in preds {
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
        (0..n).map(|b| if idom[b] == exit { usize::MAX } else { idom[b] }).collect()
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

        // Defs are grouped by `loc_key`, so overlapping XMM sub-registers (4-vs-8-byte)
        // share a phi location; the phi's nominal size is the widest def seen there.
        let mut defsites: HashMap<Loc, (Vec<usize>, u32)> = HashMap::new();
        for (i, fo) in self.ops.iter().enumerate() {
            if let Some(out) = &fo.op.out {
                if heritaged(&out.space) {
                    let e = defsites.entry(loc_key(&out.space, out.offset, out.size)).or_insert((Vec::new(), 0));
                    if !e.0.contains(&opb[i]) {
                        e.0.push(opb[i]);
                    }
                    e.1 = e.1.max(out.size);
                }
            }
        }

        let mut result = Vec::new();
        for (key, (sites, size)) in &defsites {
            let loc: Loc = (key.0.clone(), key.1, *size);
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
        let mut stack: RenameStack = HashMap::new();
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

type RenameStack = HashMap<Loc, Vec<(Def, u32)>>;

/// The SSA key for a storage location. XMM/SSE registers (x86-64 register offset
/// ≥ 0x1200) are merged across access width — same key regardless of size — so an
/// 8-byte read sees a 4-byte (zero-extending) write and a 4-byte read sees the low half
/// of an 8-byte write (the float overlap the SSE code relies on). Every other location
/// stays exact-size: the p-code-as-written SSA, which leaves ordinary GP-register
/// def-use untouched (a wider rule there perturbs call-argument recovery).
pub fn loc_key(space: &str, offset: u64, size: u32) -> Loc {
    if space == "register" && offset >= 0x1200 {
        (space.to_string(), offset, 0)
    } else {
        (space.to_string(), offset, size)
    }
}

/// The reaching definition of a read of `size` bytes at `(space, offset)`: the most
/// recent def at that location wide enough to cover it. On x86-64 a write of ≥4 bytes
/// zero-extends to fill the whole register, so it covers any read; otherwise the def
/// must be at least as wide as the read (a 1/2-byte partial write doesn't cover more).
fn resolve(stack: &RenameStack, space: &str, offset: u64, size: u32) -> Def {
    if let Some(st) = stack.get(&loc_key(space, offset, size)) {
        for &(d, dsize) in st.iter().rev() {
            if dsize >= 4 || dsize >= size {
                return d;
            }
        }
    }
    Def::Live
}

#[cfg(test)]
mod tests {
    use super::loc_key;
    use crate::decomp::cfg::{Block, Funcdata};

    #[test]
    fn xmm_registers_merge_across_width_but_gp_stays_exact() {
        // XMM (offset >= 0x1200) collapses 4- and 8-byte accesses to one key, so a
        // 4-byte XOR-zero and an 8-byte FLOAT_ADD at the same offset share an SSA stack.
        assert_eq!(loc_key("register", 0x1200, 4), loc_key("register", 0x1200, 8));
        // GP registers keep size in the key (EAX and RAX are distinct SSA locations).
        assert_ne!(loc_key("register", 0x0, 4), loc_key("register", 0x0, 8));
        // stack/unique stay exact-size too.
        assert_ne!(loc_key("stack", 0x10, 4), loc_key("stack", 0x10, 8));
    }

    fn cfg(succ: &[&[usize]]) -> Funcdata {
        let mut blocks: Vec<Block> = succ.iter().map(|s| Block { start: 0, end: 0, succ: s.to_vec(), pred: Vec::new() }).collect();
        for b in 0..blocks.len() {
            for s in blocks[b].succ.clone() {
                blocks[s].pred.push(b);
            }
        }
        Funcdata { entry: 0, ops: Vec::new(), blocks, switches: Vec::new() }
    }

    #[test]
    fn post_idom_of_a_diamond_is_the_merge() {
        // 0 -> {1,2}; 1,2 -> 3 (exit). The follow node of the branch at 0 is 3.
        let f = cfg(&[&[1, 2], &[3], &[3], &[]]);
        let p = f.post_idom();
        assert_eq!(p[0], 3, "branch block post-dominated by the merge");
        assert_eq!(p[1], 3);
        assert_eq!(p[2], 3);
        assert_eq!(p[3], usize::MAX, "the exit has no post-dominator");
    }

    #[test]
    fn post_idom_of_an_if_then_is_the_fallthrough() {
        // 0 -> {1,2}; 1 -> 2; 2 -> exit. The then-block 1 reconverges at 2.
        let f = cfg(&[&[1, 2], &[2], &[]]);
        let p = f.post_idom();
        assert_eq!(p[0], 2);
        assert_eq!(p[1], 2);
        assert_eq!(p[2], usize::MAX);
    }
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
    stack: &mut RenameStack,
) {
    let mut pushed: Vec<Loc> = Vec::new();

    // phis define their location
    for &pi in &block_phis[block] {
        let loc = phis[pi].loc.clone();
        let key = loc_key(&loc.0, loc.1, loc.2);
        stack.entry(key.clone()).or_default().push((Def::Phi(pi), loc.2));
        pushed.push(key);
    }
    // ops: resolve heritaged uses, then define the output
    for i in f.blocks[block].start..f.blocks[block].end {
        let op = &f.ops[i].op;
        for (pos, arg) in op.ins.iter().enumerate() {
            if let Some(v) = arg.as_var() {
                if heritaged(&v.space) {
                    let d = resolve(stack, &v.space, v.offset, v.size);
                    uses.insert((i, pos), d);
                }
            }
        }
        if let Some(out) = &op.out {
            if heritaged(&out.space) {
                let key = loc_key(&out.space, out.offset, out.size);
                stack.entry(key.clone()).or_default().push((Def::Op(i), out.size));
                pushed.push(key);
            }
        }
        if op.opcode == 10 {
            // RETURN: the live-out locations read their reaching definition here.
            for (k, loc) in live_out.iter().enumerate() {
                let d = resolve(stack, &loc.0, loc.1, loc.2);
                uses.insert((i, op.ins.len() + k), d);
            }
        }
    }
    // fill in this block's slot of each successor's phis
    for &s in &f.blocks[block].succ {
        let j = f.blocks[s].pred.iter().position(|&p| p == block).unwrap_or(0);
        for &pi in &block_phis[s] {
            let loc = &phis[pi].loc;
            let d = resolve(stack, &loc.0, loc.1, loc.2);
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
    for key in pushed {
        if let Some(st) = stack.get_mut(&key) {
            st.pop();
        }
    }
}
