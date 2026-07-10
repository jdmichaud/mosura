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

use super::block::BlockId;
use super::cover::{all_covers, Cover};
use super::funcdata::Funcdata;
use super::opcode::OpCode;
use super::space::{Address, SpaceId};
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

/// Build the HighVariables for `f`, in Ghidra's merge-phase order (coreaction.cc:5719-5735):
/// the required marker merges (`Merge::mergeMarker`) and address-tied unification
/// (`Merge::mergeAddrTied`), then the COPY input/output merges (`Merge::mergeOpcode(COPY)`), then
/// the speculative cover-based merging of non-interfering same-storage varnodes.
pub fn merge(f: &Funcdata) -> HighVariables {
    let mut h = HighVariables::new(f.num_varnodes());
    let covers = all_covers(f);
    merge_markers(f, &mut h);
    merge_addrtied(f, &mut h, &covers);
    merge_copy(f, &mut h, &covers);
    merge_same_storage(f, &mut h, &covers);
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

/// The speculative same-storage merges (Ghidra `Merge::mergeByDatatype` / `ActionMergeType`):
/// greedily merge HighVariables that share storage and never live simultaneously, so reused
/// registers/slots become one variable.
fn merge_same_storage(f: &Funcdata, h: &mut HighVariables, covers: &HashMap<VarnodeId, Cover>) {
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

    // The interference test must compare the WHOLE HighVariable each storage member belongs
    // to, not just the same-storage members — Ghidra's `HighVariable::updateInternalCover`
    // (variable.cc) unions the covers of *all* member Varnodes, so merging two same-storage
    // values transitively merges their whole HighVariables and interferes if any pair of
    // members does. (pointercmp: the bound `param_1+0x18` shares RAX with the iterator's
    // init value, whose HighVariable also holds the stack-slot phi that is live across the
    // compare — checking only the RAX members missed that overlap and unified them into the
    // bogus `pStack_10 < pStack_10`.)
    //
    // `full` (rep → all cover-bearing members) is maintained incrementally across unions —
    // only the two unioned classes change, and `classes_interfere` is an order-insensitive
    // any-pair test, so splicing their member lists is decision-identical to the full rescan.
    let mut full = full_members_by_rep(f, h, covers);
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
            let empty: Vec<VarnodeId> = Vec::new();
            let mut merged = false;
            'pair: for i in 0..class_list.len() {
                for j in (i + 1)..class_list.len() {
                    let rep_i = h.high(class_list[i][0]);
                    let rep_j = h.high(class_list[j][0]);
                    let fi = full.get(&rep_i).unwrap_or(&empty);
                    let fj = full.get(&rep_j).unwrap_or(&empty);
                    if !classes_interfere(fi, fj, covers) {
                        h.union(class_list[i][0].0, class_list[j][0].0);
                        let mut m = full.remove(&rep_i).unwrap_or_default();
                        m.extend(full.remove(&rep_j).unwrap_or_default());
                        full.insert(h.high(class_list[i][0]), m);
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

/// All cover-bearing Varnodes currently merged into the HighVariable `rep` — the membership over
/// which Cover interference is tested (Ghidra's `HighVariable::inst`).
fn members_of(
    f: &Funcdata,
    h: &mut HighVariables,
    covers: &HashMap<VarnodeId, Cover>,
    rep: u32,
) -> Vec<VarnodeId> {
    (0..f.num_varnodes() as u32)
        .map(VarnodeId)
        .filter(|&v| covers.contains_key(&v) && h.high(v) == rep)
        .collect()
}

/// `Merge::mergeAddrTied` (merge.cc:609) — force-merge address-tied Varnodes sharing a storage
/// address into one HighVariable. Ghidra force-merges the same-size versions (`mergeRangeMust`,
/// the [`super::mergesnip`] snip having already resolved any Cover intersection) and links
/// different-size versions into a VariableGroup (`groupWith`/VariablePiece). mosura has no
/// VariablePiece (the P4/P8 debt), so it approximates the group by unioning *every* address-tied
/// cover-bearing version at an address, any size — giving the storage one HighVariable whose Cover
/// spans all its versions. That spanning Cover is what lets [`merge_copy`] tell a pre-store
/// snapshot (which stays live across the overwriting store) apart from the stored value.
fn merge_addrtied(f: &Funcdata, h: &mut HighVariables, _covers: &HashMap<VarnodeId, Cover>) {
    let mut by_addr: HashMap<(SpaceId, u64), Vec<VarnodeId>> = HashMap::new();
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        let vn = f.vn(v);
        // Ghidra `unifyAddress` gates on `!isFree` (heritaged), NOT on having a Cover: an
        // address-forced write held to the end of the function has no explicit reader (so mosura's
        // Cover is empty) but is still an instance of the storage's variable and must be unified,
        // else the `guardReturns` terminal COPY stays cross-high and prints a spurious `g = g`.
        if vn.is_free() || !vn.is_addrtied() {
            continue;
        }
        by_addr.entry((vn.loc.space, vn.loc.offset)).or_default().push(v);
    }
    // Deterministic order (the union representative is the lowest-index member of each group).
    let mut groups: Vec<Vec<VarnodeId>> = by_addr.into_values().filter(|g| g.len() >= 2).collect();
    groups.sort_by_key(|g| g[0]);
    for g in groups {
        for &w in &g[1..] {
            h.union(g[0].0, w.0);
        }
    }
}

/// `Merge::mergeOpcode(CPUI_COPY)` (merge.cc:326) — in linear block order, try to merge each
/// COPY's input HighVariable with its output HighVariable. The merge is skipped if `mergeTestBasic`
/// or `mergeTestRequired` forbids it, or if it would introduce a Cover intersection (Ghidra ignores
/// `merge()`'s return, merge.cc:346). This collapses redundant register/return COPYs into one
/// variable and — crucially — LEAVES a COPY whose input and output Covers interfere (a snapshot of
/// an address-tied value taken before that address is overwritten) as two distinct HighVariables,
/// so the printer renders it as an explicit `iVar = <snapshot>` assignment (see printc's
/// cross-high COPY arm, Ghidra `Merge::markInternalCopies`).
fn merge_copy(f: &Funcdata, h: &mut HighVariables, covers: &HashMap<VarnodeId, Cover>) {
    for b in 0..f.num_blocks() as u32 {
        let ops = f.block(BlockId(b)).ops.clone();
        for op in ops {
            let o = f.op(op);
            if o.is_dead() || o.code() != OpCode::Copy {
                continue;
            }
            let Some(out) = o.output else { continue };
            if !merge_test_basic(f, covers, out) {
                continue;
            }
            for j in 0..o.num_inputs() {
                let Some(inv) = o.input(j) else { continue };
                if !merge_test_basic(f, covers, inv) {
                    continue;
                }
                let rep_out = h.high(out);
                let rep_in = h.high(inv);
                if rep_out == rep_in {
                    continue;
                }
                if !merge_test_required(f, h, rep_out, rep_in) {
                    continue;
                }
                let mo = members_of(f, h, covers, rep_out);
                let mi = members_of(f, h, covers, rep_in);
                if classes_interfere(&mo, &mi, covers) {
                    continue; // would introduce a Cover intersection — skip
                }
                h.union(out.0, inv.0);
            }
        }
    }
}

/// `Merge::mergeTestBasic` (merge.cc:255) — a Varnode may take part in a merge only if it has a
/// Cover and is neither implied nor a spacebase. (Ghidra also excludes `isProtoPartial`; mosura
/// has no VariablePiece so that case is inapplicable.)
fn merge_test_basic(f: &Funcdata, covers: &HashMap<VarnodeId, Cover>, v: VarnodeId) -> bool {
    if !covers.contains_key(&v) {
        return false;
    }
    let vn = f.vn(v);
    !vn.is_implied() && !vn.is_spacebase()
}

/// The aggregate `(address-tied storage address, is-input, is-persist)` over every Varnode merged
/// into HighVariable `rep` — Ghidra's HighVariable flag aggregation across its instances. A `stack`
/// member counts as tied-to-its-address even without the `addrtied` flag: Ghidra maps every stack
/// local (so it is addrtied), while mosura marks only *escaped* slots ([`super::varnodeprops`]), so
/// the merge guard would otherwise let a stack local merge with a differently-addressed global.
fn high_props(f: &Funcdata, h: &mut HighVariables, rep: u32) -> (Option<Address>, bool, bool) {
    let stack = f.spaces.by_name("stack");
    let mut tied: Option<Address> = None;
    let (mut input, mut persist) = (false, false);
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        if h.high(v) != rep {
            continue;
        }
        let vn = f.vn(v);
        if vn.is_addrtied() || Some(vn.loc.space) == stack {
            tied = Some(vn.loc);
        }
        input |= vn.is_input();
        persist |= vn.is_persist();
    }
    (tied, input, persist)
}

/// `Merge::mergeTestRequired` (merge.cc:102), the subset mosura models: keep an address-tied output
/// from swallowing an address-tied input of a *different* address, and keep function inputs
/// distinct from persistent / address-tied storage (an input must not be dragged into the internal
/// parts of a stack structure). The typelock / extraout / protopartial / VariablePiece / symbol
/// guards are not modeled — mosura has no type-locks, VariablePieces or symbol tables at merge time.
fn merge_test_required(f: &Funcdata, h: &mut HighVariables, rep_out: u32, rep_in: u32) -> bool {
    if rep_out == rep_in {
        return true; // already merged
    }
    let (out_tied, out_input, out_persist) = high_props(f, h, rep_out);
    let (in_tied, in_input, in_persist) = high_props(f, h, rep_in);
    if let (Some(oa), Some(ia)) = (out_tied, in_tied) {
        if oa != ia {
            return false; // address-tied output vs address-tied input of a different address
        }
    }
    if in_input {
        if out_persist {
            return false; // inputs and persists are inherently different variables
        }
        if out_tied.is_some() && in_tied.is_none() {
            return false; // don't drag an input into address-tied storage
        }
    }
    if out_input {
        if in_persist {
            return false;
        }
        if in_tied.is_some() && out_tied.is_none() {
            return false;
        }
    }
    true
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

    /// `merge_addrtied` unifies every address-tied version at one storage address, ANY size (the
    /// VariablePiece approximation) — a 4-byte and an 8-byte write to the same global become one
    /// HighVariable, while a write to a different address stays distinct.
    #[test]
    fn merge_addrtied_unifies_all_sizes_at_one_address() {
        use crate::decompile::varnode::flags as vflags;
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let (c1, c2, c3) = (f.new_const(8, 1), f.new_const(4, 2), f.new_const(8, 3));
        let o1 = f.new_op(OpCode::Copy, seq, vec![c1]);
        let g8 = f.new_output(o1, 8, Address::new(ram, 0x1000));
        let o2 = f.new_op(OpCode::Copy, seq, vec![c2]);
        let g4 = f.new_output(o2, 4, Address::new(ram, 0x1000)); // same address, smaller size
        let o3 = f.new_op(OpCode::Copy, seq, vec![c3]);
        let other = f.new_output(o3, 8, Address::new(ram, 0x2000)); // different address
        for v in [g8, g4, other] {
            f.vn_mut(v).flags |= vflags::ADDRTIED | vflags::PERSIST;
        }
        f.set_blocks(vec![BlockBasic { ops: vec![o1, o2, o3], ..Default::default() }]);

        let covers = all_covers(&f);
        let mut h = HighVariables::new(f.num_varnodes());
        merge_addrtied(&f, &mut h, &covers);
        assert!(h.same(g8, g4), "same-address addrtied versions unify regardless of size");
        assert!(!h.same(g8, other), "a different address stays a distinct variable");
    }

    /// `merge_copy` (mergeOpcode COPY) merges a COPY's input and output when their Covers don't
    /// interfere, but LEAVES them distinct when they do — a snapshot read that stays live across a
    /// later write to the same variable must remain its own explicit temporary.
    #[test]
    fn merge_copy_merges_noninterfering_but_not_interfering() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let s = |u: u32| SeqNum { pc: Address::new(ram, u as u64), uniq: u };
        let c = f.new_const(8, 5);

        // Non-interfering chain: a = c + c; b = COPY(a); rb = b + c. `a` is dead after the COPY.
        let o1 = f.new_op(OpCode::IntAdd, s(0), vec![c, c]);
        let a = f.new_output(o1, 8, Address::new(reg, 0));
        let o2 = f.new_op(OpCode::Copy, s(1), vec![a]);
        let b = f.new_output(o2, 8, Address::new(reg, 0x8));
        let o3 = f.new_op(OpCode::IntAdd, s(2), vec![b, c]);
        let _rb = f.new_output(o3, 8, Address::new(reg, 0x10));

        // Interfering chain: e = c + c; d = COPY(e); rd = e + d. `e` is read again alongside `d`,
        // so `e` and `d` are both live at the last op and must NOT merge.
        let o4 = f.new_op(OpCode::IntAdd, s(3), vec![c, c]);
        let e = f.new_output(o4, 8, Address::new(reg, 0x18));
        let o5 = f.new_op(OpCode::Copy, s(4), vec![e]);
        let d = f.new_output(o5, 8, Address::new(reg, 0x20));
        let o6 = f.new_op(OpCode::IntAdd, s(5), vec![e, d]);
        let _rd = f.new_output(o6, 8, Address::new(reg, 0x28));
        f.set_blocks(vec![BlockBasic { ops: vec![o1, o2, o3, o4, o5, o6], ..Default::default() }]);

        let mut h = merge(&f);
        assert!(h.same(a, b), "a non-interfering COPY merges its input and output");
        assert!(!h.same(e, d), "an interfering COPY (input still live) is left as a distinct variable");
    }

    /// `merge_test_required` (the modeled subset of `mergeTestRequired`): an address-tied output
    /// never swallows a differently-addressed address-tied input — including a `stack` local, which
    /// mosura does not flag `addrtied` but Ghidra maps — nor a function input into persistent
    /// storage; a plain register temporary CAN become a global's value.
    #[test]
    fn merge_test_required_guards() {
        use crate::decompile::varnode::flags as vflags;
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let stack = spaces.by_name("stack").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let glob = f.new_varnode(8, Address::new(ram, 0x1000));
        let glob2 = f.new_varnode(8, Address::new(ram, 0x2000));
        for v in [glob, glob2] {
            f.vn_mut(v).flags |= vflags::ADDRTIED | vflags::PERSIST | vflags::INSERT;
        }
        let slot = f.new_varnode(4, Address::new(stack, 0xffff_ffff_ffff_fff0));
        f.vn_mut(slot).flags |= vflags::INSERT; // stack local, NOT addrtied in mosura
        let inp = f.new_input(8, Address::new(reg, 0x38));
        let tmp = f.new_varnode(8, Address::new(reg, 0));
        f.vn_mut(tmp).flags |= vflags::INSERT;

        // No unions performed, so each Varnode is its own HighVariable (rep == id).
        let mut h = HighVariables::new(f.num_varnodes());
        assert!(!merge_test_required(&f, &mut h, glob.0, glob2.0), "two globals at different addresses");
        assert!(!merge_test_required(&f, &mut h, glob.0, slot.0), "a global and a stack local");
        assert!(!merge_test_required(&f, &mut h, glob.0, inp.0), "a persistent global and a function input");
        assert!(merge_test_required(&f, &mut h, glob.0, tmp.0), "a register temp CAN become the global's value");
    }
}
