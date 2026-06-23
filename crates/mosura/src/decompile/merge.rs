//! Variable merging — Ghidra's `Merge`/`HighVariable` (`merge.cc`, `variable.cc`). Groups
//! the SSA Varnodes that represent one C variable into a [`HighVariable`], so the printer
//! emits one named variable instead of many SSA versions.
//!
//! P5 increment 1: the [`HighVariables`] union-find and the *required* marker merges
//! (`mergeMarker`) — a MULTIEQUAL/INDIRECT output is the same variable as its inputs, which
//! threads a value's SSA versions across control flow into one variable (loop counters,
//! merged conditionals). Cover-based merging of non-interfering same-storage varnodes, and
//! naming, are the next increments.

use super::funcdata::Funcdata;
use super::opcode::OpCode;
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

/// Build the HighVariables for `f`: the required marker merges (`Merge::mergeMarker`).
pub fn merge(f: &Funcdata) -> HighVariables {
    let mut h = HighVariables::new(f.num_varnodes());
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
    h
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
