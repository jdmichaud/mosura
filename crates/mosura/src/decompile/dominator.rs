//! Dominator tree and dominance frontiers over the CFG — the substrate heritage uses to
//! place MULTIEQUALs (Ghidra computes these in `block.cc`; the dominator tree is a unique
//! object, so the Cooper–Harvey–Kennedy iterative algorithm yields the same result).
//!
//! Assumes the CFG is entry-reachable (block 0 is the entry), which `cfg::build_cfg`
//! guarantees via its reachability prune.

use super::funcdata::Funcdata;

/// Per-block immediate dominators and dominance frontiers (indexed by block number).
pub struct Dominators {
    /// Immediate dominator of each block. The entry's idom is itself.
    pub idom: Vec<usize>,
    /// Dominance frontier of each block.
    pub frontier: Vec<Vec<usize>>,
}

impl Dominators {
    /// Does block `a` dominate block `b` (walking the idom chain)?
    pub fn dominates(&self, a: usize, b: usize) -> bool {
        let mut n = b;
        loop {
            if n == a {
                return true;
            }
            if n == self.idom[n] {
                return false; // reached entry
            }
            n = self.idom[n];
        }
    }
}

/// Postorder of the CFG from the entry (block 0), over out-edges.
fn postorder(f: &Funcdata) -> Vec<usize> {
    let nb = f.num_blocks();
    let mut order = Vec::with_capacity(nb);
    let mut visited = vec![false; nb];
    // iterative DFS; push children, emit on the way back up
    let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
    visited[0] = true;
    while let Some(&mut (node, ref mut ci)) = stack.last_mut() {
        let outs = &f.blocks()[node].out_edges;
        if *ci < outs.len() {
            let succ = outs[*ci].0 as usize;
            *ci += 1;
            if !visited[succ] {
                visited[succ] = true;
                stack.push((succ, 0));
            }
        } else {
            order.push(node);
            stack.pop();
        }
    }
    order
}

/// Compute the dominator tree and dominance frontiers.
pub fn compute(f: &Funcdata) -> Dominators {
    let nb = f.num_blocks();
    let mut idom = vec![usize::MAX; nb];
    let mut frontier = vec![Vec::new(); nb];
    let mut rpo_num = vec![0usize; nb];
    if nb == 0 {
        return Dominators { idom, frontier };
    }

    let po = postorder(f);
    // reverse postorder, with each node's position
    let rpo: Vec<usize> = po.iter().rev().copied().collect();
    for (i, &b) in rpo.iter().enumerate() {
        rpo_num[b] = i;
    }

    // Cooper-Harvey-Kennedy iterative idom
    idom[0] = 0; // entry dominates itself
    let intersect = |mut a: usize, mut b: usize, idom: &[usize], rpo_num: &[usize]| -> usize {
        while a != b {
            while rpo_num[a] > rpo_num[b] {
                a = idom[a];
            }
            while rpo_num[b] > rpo_num[a] {
                b = idom[b];
            }
        }
        a
    };
    let mut changed = true;
    while changed {
        changed = false;
        for &b in rpo.iter() {
            if b == 0 {
                continue;
            }
            let mut new_idom = usize::MAX;
            for &p in &f.blocks()[b].in_edges {
                let p = p.0 as usize;
                if idom[p] == usize::MAX {
                    continue; // predecessor not yet processed
                }
                new_idom = if new_idom == usize::MAX {
                    p
                } else {
                    intersect(p, new_idom, &idom, &rpo_num)
                };
            }
            if new_idom != usize::MAX && idom[b] != new_idom {
                idom[b] = new_idom;
                changed = true;
            }
        }
    }

    // Dominance frontiers (Cooper): for each join, walk preds up to its idom.
    for b in 0..nb {
        let preds = &f.blocks()[b].in_edges;
        if preds.len() < 2 {
            continue;
        }
        for p in preds {
            let mut runner = p.0 as usize;
            while runner != idom[b] && runner != usize::MAX {
                if !frontier[runner].contains(&b) {
                    frontier[runner].push(b);
                }
                if runner == idom[runner] {
                    break; // entry
                }
                runner = idom[runner];
            }
        }
    }
    for df in &mut frontier {
        df.sort_unstable();
    }

    Dominators { idom, frontier }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::block::{BlockBasic, BlockId};
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::Funcdata;

    /// Build a Funcdata with `nb` empty blocks and the given edge list (no ops).
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

    #[test]
    fn diamond_dominators_and_frontiers() {
        // 0 -> {1,2} -> 3
        let f = cfg(4, &[(0, 1), (0, 2), (1, 3), (2, 3)]);
        let d = compute(&f);
        assert_eq!(d.idom, vec![0, 0, 0, 0]); // all dominated by entry
        // the merge (3) is in the frontier of both arms
        assert_eq!(d.frontier[1], vec![3]);
        assert_eq!(d.frontier[2], vec![3]);
        assert!(d.frontier[0].is_empty());
        assert!(d.dominates(0, 3));
        assert!(!d.dominates(1, 3));
    }

    #[test]
    fn loop_dominators_and_frontiers() {
        // 0 -> 1 -> 2 -> 1 (back edge), 2 -> 3
        let f = cfg(4, &[(0, 1), (1, 2), (2, 1), (2, 3)]);
        let d = compute(&f);
        assert_eq!(d.idom, vec![0, 0, 1, 2]);
        // the loop header (1) is its own back-edge frontier
        assert_eq!(d.frontier[2], vec![1]);
        assert_eq!(d.frontier[1], vec![1]);
        assert!(d.dominates(1, 3));
    }
}
