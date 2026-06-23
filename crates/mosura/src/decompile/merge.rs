//! Variable merging — Ghidra's `Merge`/`HighVariable` (`merge.cc`, `variable.cc`). Groups
//! the SSA Varnodes that represent one C variable into a [`HighVariable`], so the printer
//! emits one named variable instead of many SSA versions.
//!
//! P5 increment 1: the [`HighVariables`] union-find and the *required* marker merges
//! (`mergeMarker`) — a MULTIEQUAL/INDIRECT output is the same variable as its inputs, which
//! threads a value's SSA versions across control flow into one variable (loop counters,
//! merged conditionals). Cover-based merging of non-interfering same-storage varnodes, and
//! naming, are the next increments.

use std::collections::HashMap;

use super::cover::{all_covers, Cover};
use super::funcdata::Funcdata;
use super::opcode::OpCode;
use super::space::SpaceId;
use super::varnode::VarnodeId;

/// A union-find over Varnodes: each class is one HighVariable (one C variable).
pub struct HighVariables {
    parent: Vec<u32>,
}

impl HighVariables {
    fn new(n: usize) -> HighVariables {
        HighVariables { parent: (0..n as u32).collect() }
    }

    fn find(&mut self, mut x: u32) -> u32 {
        while self.parent[x as usize] != x {
            self.parent[x as usize] = self.parent[self.parent[x as usize] as usize]; // halving
            x = self.parent[x as usize];
        }
        x
    }

    fn union(&mut self, a: u32, b: u32) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.parent[ra as usize] = rb;
        }
    }

    /// The HighVariable id of a varnode (its union-find representative).
    pub fn high(&mut self, v: VarnodeId) -> u32 {
        self.find(v.0)
    }

    /// Whether two varnodes belong to the same HighVariable.
    pub fn same(&mut self, a: VarnodeId, b: VarnodeId) -> bool {
        self.find(a.0) == self.find(b.0)
    }

    /// The number of distinct HighVariables among the given varnodes.
    pub fn count(&mut self, vns: impl IntoIterator<Item = VarnodeId>) -> usize {
        let mut reps: Vec<u32> = vns.into_iter().map(|v| self.find(v.0)).collect();
        reps.sort_unstable();
        reps.dedup();
        reps.len()
    }
}

/// A varnode that can belong to a HighVariable — not a constant (constants are values, not
/// variables) and not an annotation.
fn mergeable(f: &Funcdata, v: VarnodeId) -> bool {
    let vn = f.vn(v);
    !vn.is_constant() && vn.flags & super::varnode::flags::ANNOTATION == 0
}

/// Build the HighVariables for `f`: the required marker merges (`Merge::mergeMarker`)
/// followed by cover-based merging of non-interfering same-storage varnodes.
pub fn merge(f: &Funcdata) -> HighVariables {
    let mut h = HighVariables::new(f.num_varnodes());
    merge_markers(f, &mut h);
    merge_same_storage(f, &mut h);
    h
}

/// `Merge::mergeMarker`: a MULTIEQUAL/INDIRECT output is one variable with its inputs.
fn merge_markers(f: &Funcdata, h: &mut HighVariables) {
    for op in f.op_ids() {
        let o = f.op(op);
        if o.is_dead() || !o.is_marker() {
            continue;
        }
        let Some(out) = o.output else { continue };
        if !mergeable(f, out) {
            continue;
        }
        // INDIRECT merges only its data input (slot 0); MULTIEQUAL merges all inputs.
        let max = if o.code() == OpCode::Indirect { 1 } else { o.num_inputs() };
        for j in 0..max {
            if let Some(inv) = o.input(j) {
                if mergeable(f, inv) {
                    h.union(out.0, inv.0);
                }
            }
        }
    }
}

/// Do any member of class `a` and member of class `b` have overlapping liveness?
fn classes_interfere(a: &[VarnodeId], b: &[VarnodeId], covers: &HashMap<VarnodeId, Cover>) -> bool {
    a.iter().any(|x| {
        b.iter().any(|y| match (covers.get(x), covers.get(y)) {
            (Some(cx), Some(cy)) => cx.intersects(cy),
            _ => false,
        })
    })
}

/// `Merge::mergeAddrTied`/`mergeOpcode`: greedily merge HighVariables that share storage
/// and never live simultaneously, so reused registers/slots become one variable.
fn merge_same_storage(f: &Funcdata, h: &mut HighVariables) {
    let covers = all_covers(f);
    let mut by_storage: HashMap<(SpaceId, u64), Vec<VarnodeId>> = HashMap::new();
    for &v in covers.keys() {
        let vn = f.vn(v);
        by_storage.entry((vn.loc.space, vn.loc.offset)).or_default().push(v);
    }

    for members in by_storage.into_values() {
        if members.len() < 2 {
            continue;
        }
        loop {
            // partition this storage group into current HighVariable classes
            let mut classes: HashMap<u32, Vec<VarnodeId>> = HashMap::new();
            for &v in &members {
                classes.entry(h.high(v)).or_default().push(v);
            }
            let reps: Vec<u32> = classes.keys().copied().collect();
            let mut merged = false;
            'pair: for i in 0..reps.len() {
                for j in (i + 1)..reps.len() {
                    if !classes_interfere(&classes[&reps[i]], &classes[&reps[j]], &covers) {
                        h.union(classes[&reps[i]][0].0, classes[&reps[j]][0].0);
                        merged = true;
                        break 'pair;
                    }
                }
            }
            if !merged {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::{BlockBasic, Funcdata, OpCode, SeqNum};

    #[test]
    fn multiequal_merges_its_versions() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        // x1, x2 are two SSA versions; phi = MULTIEQUAL(x1, x2, #0)
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let one = f.new_const(8, 1);
        let c1 = f.new_op(OpCode::Copy, seq, vec![one]);
        let x1 = f.new_output(c1, 8, Address::new(reg, 0));
        let two = f.new_const(8, 2);
        let c2 = f.new_op(OpCode::Copy, seq, vec![two]);
        let x2 = f.new_output(c2, 8, Address::new(reg, 0));
        let zero = f.new_const(8, 0);
        let phi = f.new_op(OpCode::Multiequal, seq, vec![x1, x2, zero]);
        let xp = f.new_output(phi, 8, Address::new(reg, 0));
        f.set_blocks(vec![BlockBasic { ops: vec![c1, c2, phi], ..Default::default() }]);

        let mut h = merge(&f);
        // the phi output and both written versions are one HighVariable…
        assert!(h.same(xp, x1) && h.same(xp, x2));
        // …but the constant is its own thing.
        assert!(!h.same(xp, zero));
        assert_eq!(h.count([xp, x1, x2]), 1);
    }
}
