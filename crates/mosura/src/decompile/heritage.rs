//! Heritage — building SSA form over the Varnode graph (Ghidra's `Heritage`, `heritage.cc`).
//!
//! Links every free read to its reaching definition and inserts MULTIEQUAL (phi) ops at
//! control-flow joins, via Cytron's algorithm using the dominance frontiers. Phi placement
//! is semi-pruned: only *global* locations (read in some block before being written there)
//! get phis, which keeps block-local temporaries (the `unique` space) phi-free, as Ghidra's
//! result is.
//!
//! This first pass treats each distinct `(space, offset, size)` as one SSA variable. Size
//! *overlap* (a location read at a different width than written — sub-registers, CONCAT)
//! is Ghidra's heritage *refinement* and is a later P1 sub-task; until then overlapping
//! accesses are independent variables (an under-linking, not a miswiring).

use std::collections::{HashMap, HashSet};

use super::dominator::Dominators;
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::space::SpaceId;
use super::varnode::VarnodeId;

/// An SSA location key: `(space, offset, size)`.
type Loc = (SpaceId, u64, u32);

/// The location an input slot reads, or `None` if it is not heritaged (a constant, a
/// branch/call destination address, or a space annotation).
fn read_loc(f: &Funcdata, op: OpId, slot: usize) -> Option<Loc> {
    let o = f.op(op);
    if slot == 0
        && matches!(
            o.code(),
            OpCode::Branch
                | OpCode::Cbranch
                | OpCode::Branchind
                | OpCode::Call
                | OpCode::Callind
                | OpCode::Callother
                | OpCode::Return
        )
    {
        return None; // destination/return-target annotation, not dataflow
    }
    let vn = f.vn(o.input(slot)?);
    if vn.is_constant() {
        return None;
    }
    Some((vn.loc.space, vn.loc.offset, vn.size))
}

/// The location an op writes, or `None` if it has no (non-constant) output.
fn write_loc(f: &Funcdata, op: OpId) -> Option<Loc> {
    let vn = f.vn(f.op(op).output?);
    if vn.is_constant() {
        return None;
    }
    Some((vn.loc.space, vn.loc.offset, vn.size))
}

/// Refinement (read side) — Ghidra's `normalizeReadSize`. Where a location is written at
/// a single width `S` but also *read* at a smaller width `s` at the same offset (a
/// sub-register: EAX of a wider RAX def), rewrite each narrow read as `SUBPIECE(W, 0)` of
/// a full-width read `W`, so every access to the location is uniform width and SSA links
/// it cleanly. Conservative: only locations whose writes are all one width are touched;
/// partial writes (the PIECE / write side) and cross-offset overlap (CONCAT) are not yet
/// handled, so those reads remain independent (an under-linking, never a miswiring).
fn normalize_read_size(f: &mut Funcdata) {
    let nb = f.num_blocks();
    let mut write_sizes: HashMap<(SpaceId, u64), HashSet<u32>> = HashMap::new();
    let mut read_sizes: HashMap<(SpaceId, u64), HashSet<u32>> = HashMap::new();
    for b in 0..nb {
        for op in f.blocks()[b].ops.clone() {
            for slot in 0..f.op(op).num_inputs() {
                if let Some((sp, off, sz)) = read_loc(f, op, slot) {
                    read_sizes.entry((sp, off)).or_default().insert(sz);
                }
            }
            if let Some((sp, off, sz)) = write_loc(f, op) {
                write_sizes.entry((sp, off)).or_default().insert(sz);
            }
        }
    }
    // canonical width per location: a single write width that is also read narrower
    let mut canonical: HashMap<(SpaceId, u64), u32> = HashMap::new();
    for (k, ws) in &write_sizes {
        if ws.len() == 1 {
            let s = *ws.iter().next().unwrap();
            if read_sizes.get(k).is_some_and(|rs| rs.iter().any(|&r| r < s)) {
                canonical.insert(*k, s);
            }
        }
    }
    if canonical.is_empty() {
        return;
    }
    for b in 0..nb {
        let ops = f.blocks()[b].ops.clone();
        let mut new_ops: Vec<OpId> = Vec::with_capacity(ops.len());
        for op in ops {
            for slot in 0..f.op(op).num_inputs() {
                let Some((sp, off, sz)) = read_loc(f, op, slot) else { continue };
                let Some(&s) = canonical.get(&(sp, off)) else { continue };
                if sz >= s {
                    continue;
                }
                let seq = f.op(op).seqnum;
                let w = f.new_varnode(s, super::space::Address::new(sp, off));
                let zero = f.new_const(4, 0);
                let sub = f.new_op(OpCode::Subpiece, seq, vec![w, zero]);
                let subout = f.new_output_unique(sub, sz);
                f.op_mut(sub).parent = Some(super::block::BlockId(b as u32));
                f.op_set_input(op, slot, subout);
                new_ops.push(sub); // splice the SUBPIECE in just before its reader
            }
            new_ops.push(op);
        }
        f.set_block_ops(super::block::BlockId(b as u32), new_ops);
    }
}

/// Build the SSA form for `f` using the dominator info `dom`.
pub fn heritage(f: &mut Funcdata, dom: &Dominators) {
    let nb = f.num_blocks();
    if nb == 0 {
        return;
    }
    normalize_read_size(f);

    // 1. Global locations + their defining blocks (semi-pruned SSA: a location is global
    //    if some block reads it before defining it).
    let mut globals: HashSet<Loc> = HashSet::new();
    let mut defblocks: HashMap<Loc, HashSet<usize>> = HashMap::new();
    for b in 0..nb {
        let ops = f.blocks()[b].ops.clone();
        let mut killed: HashSet<Loc> = HashSet::new();
        for op in ops {
            for slot in 0..f.op(op).num_inputs() {
                if let Some(l) = read_loc(f, op, slot) {
                    if !killed.contains(&l) {
                        globals.insert(l);
                    }
                }
            }
            if let Some(l) = write_loc(f, op) {
                killed.insert(l);
                defblocks.entry(l).or_default().insert(b);
            }
        }
    }

    // 2. Place MULTIEQUALs at iterated dominance frontiers of each global's def-blocks.
    let mut phis: HashMap<(usize, Loc), OpId> = HashMap::new();
    for &l in &globals {
        let Some(defs) = defblocks.get(&l) else { continue };
        let mut worklist: Vec<usize> = defs.iter().copied().collect();
        let mut placed: HashSet<usize> = HashSet::new();
        while let Some(x) = worklist.pop() {
            for &d in &dom.frontier[x] {
                if placed.insert(d) {
                    let npreds = f.blocks()[d].in_edges.len();
                    let phi = f.new_multiequal(super::block::BlockId(d as u32), l.0, l.1, l.2, npreds);
                    phis.insert((d, l), phi);
                    if !defs.contains(&d) {
                        worklist.push(d);
                    }
                }
            }
        }
    }

    // 3. Rename: dominator-tree walk maintaining a per-location stack of current defs.
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); nb];
    for c in 0..nb {
        if dom.idom[c] != c {
            children[dom.idom[c]].push(c);
        }
    }
    let mut stack: HashMap<Loc, Vec<VarnodeId>> = HashMap::new();
    let mut inputs: HashMap<Loc, VarnodeId> = HashMap::new();
    rename(f, 0, dom, &children, &phis, &mut stack, &mut inputs);
}

/// The reaching definition for `loc`: the top of its rename stack, or a (cached) function
/// input varnode if nothing defines it on this path.
fn current_def(
    f: &mut Funcdata,
    loc: Loc,
    stack: &HashMap<Loc, Vec<VarnodeId>>,
    inputs: &mut HashMap<Loc, VarnodeId>,
) -> VarnodeId {
    if let Some(top) = stack.get(&loc).and_then(|s| s.last()) {
        return *top;
    }
    *inputs
        .entry(loc)
        .or_insert_with(|| f.new_input(loc.2, super::space::Address::new(loc.0, loc.1)))
}

#[allow(clippy::too_many_arguments)]
fn rename(
    f: &mut Funcdata,
    b: usize,
    dom: &Dominators,
    children: &[Vec<usize>],
    phis: &HashMap<(usize, Loc), OpId>,
    stack: &mut HashMap<Loc, Vec<VarnodeId>>,
    inputs: &mut HashMap<Loc, VarnodeId>,
) {
    let mut pushed: Vec<Loc> = Vec::new();
    let ops = f.blocks()[b].ops.clone();

    for op in ops {
        if f.op(op).code() == OpCode::Multiequal {
            // a phi: its output is the new current def; inputs are filled from preds below
            if let Some(l) = write_loc(f, op) {
                let out = f.op(op).output.unwrap();
                stack.entry(l).or_default().push(out);
                pushed.push(l);
            }
            continue;
        }
        // rename reads
        for slot in 0..f.op(op).num_inputs() {
            if let Some(l) = read_loc(f, op, slot) {
                let def = current_def(f, l, stack, inputs);
                f.op_set_input(op, slot, def);
            }
        }
        // the output becomes the new current def
        if let Some(l) = write_loc(f, op) {
            let out = f.op(op).output.unwrap();
            stack.entry(l).or_default().push(out);
            pushed.push(l);
        }
    }

    // fill the phi argument each successor expects from this block
    let succs: Vec<usize> = f.blocks()[b].out_edges.iter().map(|e| e.0 as usize).collect();
    for s in succs {
        let j = f.blocks()[s].in_edges.iter().position(|e| e.0 as usize == b).unwrap();
        let phi_locs: Vec<(Loc, OpId)> = phis
            .iter()
            .filter(|((blk, _), _)| *blk == s)
            .map(|((_, l), &op)| (*l, op))
            .collect();
        for (l, phi) in phi_locs {
            let def = current_def(f, l, stack, inputs);
            f.op_set_input(phi, j, def);
        }
    }

    for c in &children[b] {
        rename(f, *c, dom, children, phis, stack, inputs);
    }

    for l in pushed {
        stack.get_mut(&l).unwrap().pop();
    }
}
