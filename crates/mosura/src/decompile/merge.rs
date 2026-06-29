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
    // Group by storage *and size* with members in varnode (create_index) order — Ghidra processes
    // varnodes in a deterministic order, so this drives a deterministic merge (a HashMap's
    // iteration order must never reach the output). A Ghidra HighVariable has a single size: a
    // differently-sized varnode sharing an address (e.g. scratch reuse of a parameter register as a
    // 4-byte temporary) is a *distinct* variable, accessed via SUBPIECE — never merged in. Keying
    // on size keeps an 8-byte pointer parameter from being dragged to a 4-byte scratch's `int4`.
    let mut by_storage: HashMap<(SpaceId, u64, u32), Vec<VarnodeId>> = HashMap::new();
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        if covers.contains_key(&v) {
            let vn = f.vn(v);
            by_storage.entry((vn.loc.space, vn.loc.offset, vn.size)).or_default().push(v);
        }
    }
    // Process the (independent) storage groups in a deterministic order too.
    let mut groups: Vec<Vec<VarnodeId>> = by_storage.into_values().filter(|m| m.len() >= 2).collect();
    groups.sort_by_key(|m| m[0]);

    for members in groups {
        loop {
            // partition this storage group into current HighVariable classes, ordered by their
            // lowest member so the pairwise merge below is deterministic
            let mut classes: HashMap<u32, Vec<VarnodeId>> = HashMap::new();
            for &v in &members {
                classes.entry(h.high(v)).or_default().push(v);
            }
            let mut class_list: Vec<Vec<VarnodeId>> = classes.into_values().collect();
            class_list.sort_by_key(|c| c[0]);
            // The interference test must compare the WHOLE HighVariable each storage member belongs
            // to, not just the same-storage members — Ghidra's `HighVariable::updateInternalCover`
            // (variable.cc) unions the covers of *all* member Varnodes, so merging two same-storage
            // values transitively merges their whole HighVariables and interferes if any pair of
            // members does. (pointercmp: the bound `param_1+0x18` shares RAX with the iterator's
            // init value, whose HighVariable also holds the stack-slot phi that is live across the
            // compare — checking only the RAX members missed that overlap and unified them into the
            // bogus `pStack_10 < pStack_10`.)
            let full = full_members_by_rep(f, h, &covers);
            let empty: Vec<VarnodeId> = Vec::new();
            let mut merged = false;
            'pair: for i in 0..class_list.len() {
                for j in (i + 1)..class_list.len() {
                    let rep_i = h.high(class_list[i][0]);
                    let rep_j = h.high(class_list[j][0]);
                    let fi = full.get(&rep_i).unwrap_or(&empty);
                    let fj = full.get(&rep_j).unwrap_or(&empty);
                    if !classes_interfere(fi, fj, &covers) {
                        h.union(class_list[i][0].0, class_list[j][0].0);
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

/// Map each current HighVariable representative to *all* its member Varnodes that have a cover —
/// the membership over which interference is tested (Ghidra's `HighVariable::inst`).
fn full_members_by_rep(
    f: &Funcdata,
    h: &mut HighVariables,
    covers: &HashMap<VarnodeId, Cover>,
) -> HashMap<u32, Vec<VarnodeId>> {
    let mut full: HashMap<u32, Vec<VarnodeId>> = HashMap::new();
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        if covers.contains_key(&v) {
            let rep = h.high(v);
            full.entry(rep).or_default().push(v);
        }
    }
    full
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::{BlockBasic, BlockId, Funcdata, OpCode, SeqNum};

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

    /// Regression for the cover/interference bug (pointercmp): a register value (the loop bound)
    /// that shares storage with the iterator's *init* value must not be merged into the iterator
    /// when the iterator's whole HighVariable — which includes the loop-carried phi that is live
    /// across the compare — interferes with the bound, even though the bound and the init value
    /// alone never overlap. Same-storage interference must be tested over the full HighVariable.
    #[test]
    fn same_storage_merge_respects_full_highvariable_cover() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let uniq = spaces.by_name("unique").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let s = |u: u32| SeqNum { pc: Address::new(ram, u as u64), uniq: u };
        let param = f.new_input(8, Address::new(reg, 0x38));

        // block 0 (entry): vinit = param + 8  -> RAX(reg 0); then branch to the loop header.
        let c8 = f.new_const(8, 8);
        let o_init = f.new_op(OpCode::IntAdd, s(0), vec![param, c8]);
        let vinit = f.new_output(o_init, 8, Address::new(reg, 0));
        let br0 = f.new_op(OpCode::Branch, s(1), vec![]);

        // The loop-carried phi lives at a *stack-like* slot (distinct storage from RAX).
        let phi = f.new_op(OpCode::Multiequal, SeqNum { pc: Address::new(ram, 2), uniq: u32::MAX }, vec![vinit, vinit]);
        let vphi = f.new_output(phi, 8, Address::new(reg, 0x100));

        // block 1 (loop body): vinc = PTRADD(vphi, 1, 1) -> unique; back-edge to the header.
        let c1a = f.new_const(8, 1);
        let c1b = f.new_const(8, 1);
        let o_inc = f.new_op(OpCode::Ptradd, s(3), vec![vphi, c1a, c1b]);
        let vinc = f.new_output(o_inc, 8, Address::new(uniq, 0x500));
        f.op_set_input(phi, 1, vinc); // phi = MULTIEQUAL(vinit, vinc)

        // block 2 (header): vbound = param + 0x18 -> RAX(reg 0); cmp = vphi < vbound; cbranch.
        let c18 = f.new_const(8, 0x18);
        let o_bound = f.new_op(OpCode::IntAdd, s(4), vec![param, c18]);
        let vbound = f.new_output(o_bound, 8, Address::new(reg, 0));
        let cmp = f.new_op(OpCode::IntLess, s(5), vec![vphi, vbound]);
        let _b = f.new_output(cmp, 1, Address::new(reg, 0x200));
        let cbr = f.new_op(OpCode::Cbranch, s(6), vec![]);

        // block 3 (exit): return, carrying vbound (so it stays live past the compare).
        let ret = f.new_op(OpCode::Return, s(7), vec![vbound]);

        f.set_blocks(vec![
            BlockBasic { ops: vec![o_init, br0], in_edges: vec![], out_edges: vec![BlockId(2)] },
            BlockBasic { ops: vec![o_inc], in_edges: vec![BlockId(2)], out_edges: vec![BlockId(2)] },
            BlockBasic {
                ops: vec![phi, o_bound, cmp, cbr],
                in_edges: vec![BlockId(0), BlockId(1)],
                out_edges: vec![BlockId(1), BlockId(3)],
            },
            BlockBasic { ops: vec![ret], in_edges: vec![BlockId(2)], out_edges: vec![] },
        ]);

        let mut h = merge(&f);
        // the iterator's versions are one HighVariable (the phi merge)…
        assert!(h.same(vphi, vinit) && h.same(vphi, vinc));
        // …and the bound, though it reuses RAX like vinit, is a DISTINCT variable: vphi is live at
        // the compare where vbound is also live, so the whole HighVariables interfere.
        assert!(!h.same(vinit, vbound), "bound must not merge into the iterator (full-cover interference)");
        assert!(!h.same(vphi, vbound));
    }
}
