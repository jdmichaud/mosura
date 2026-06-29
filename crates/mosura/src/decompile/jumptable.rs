//! Jump-table (switch) recovery — a port of Ghidra's `JumpTable`/`JumpBasic` (`jumptable.{cc,hh}`).
//!
//! For each indirect `BRANCHIND`, recover the ordered list of case-target addresses the way Ghidra
//! does: backtrace the branch target to the switch variable (`JumpBasic::findDeterminingVarnodes`),
//! bound that variable's range from the guard comparison (`analyzeGuards`/`CircleRange`), then for
//! each value in range emulate the address calculation through to the branch target
//! (`EmulateFunction::emulatePath`), reading the table out of the function's loaded image. This
//! runs on the heritaged graph — the most-simplified form, matching Ghidra's `stageJumpTable`,
//! where the guard variable and the table index are the same SSA value.
//!
//! This is the faithful read-back the analysis track's `DecompilerSwitchAnalyzer` (A6) consumes via
//! [`super::funcdata::Funcdata::jump_tables`]; it replaces the table-base heuristic in `build.rs`.

use std::collections::HashSet;

use super::block::BlockId;
use super::funcdata::Funcdata;
use super::opcode::OpCode;
use super::op::OpId;
use super::varnode::VarnodeId;

/// One recovered jump table — Ghidra `JumpTable`'s result surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JumpTable {
    /// Address of the `BRANCHIND` instruction.
    pub op_addr: u64,
    /// The ordered case-target addresses (index → target), as produced by emulating each switch
    /// value through the address calculation.
    pub targets: Vec<u64>,
    /// The address of the `default` case, if the out-of-range guard's target was folded into the
    /// switch (Ghidra `JumpTable::defaultBlock`, set by `JumpBasic::foldInOneGuard`). `None` when
    /// no guard branches directly into the switch.
    pub default: Option<u64>,
}

/// Recover every jump table in `f` (Ghidra `Funcdata::recoverJumpTables` over each BRANCHIND).
pub fn recover(f: &Funcdata) -> Vec<JumpTable> {
    let mut out = Vec::new();
    for op in f.op_ids() {
        if !f.op(op).is_dead() && f.op(op).code() == OpCode::Branchind {
            if let Some(jt) = recover_one(f, op) {
                out.push(jt);
            }
        }
    }
    out
}

fn recover_one(f: &Funcdata, indop: OpId) -> Option<JumpTable> {
    let target_vn = f.op(indop).input(0)?;
    // findDeterminingVarnodes: the varnodes the branch target is computed from.
    let path = backtrace_set(f, target_vn);
    // analyzeGuards + CircleRange: bound the switch variable's value range from the guards.
    let (switch_var, low, high) = guard_range(f, &path, indop)?;
    let count = high.checked_sub(low)?.checked_add(1)?;
    if count == 0 || count > 4096 {
        return None; // implausible range — Ghidra rejects ranges over maxtablesize
    }
    // buildAddresses: emulate each switch value through to the branch target. The switch variable
    // takes its actual values [low,high] (an offset switch reads table[val-base] for each), so the
    // targets come out in table-index order.
    let mut targets = Vec::with_capacity(count as usize);
    for val in low..=high {
        let t = emulate(f, target_vn, switch_var, val, 0)?;
        if !in_image(f, t) {
            return None; // sanityCheck: every case target must be a real address in the image
        }
        targets.push(t);
    }
    let default = find_default(f, indop, &path);
    Some(JumpTable { op_addr: f.op(indop).seqnum.pc.offset, targets, default })
}

/// Ghidra `JumpBasic::foldInOneGuard` geometry: a bounds guard whose in-range edge branches
/// directly into the switch block has its *other* (out-of-range) edge target as the `default`
/// case. Find that guard among the switch block's predecessors and return the default address.
fn find_default(f: &Funcdata, indop: OpId, path: &HashSet<VarnodeId>) -> Option<u64> {
    let ind_block = f.op(indop).parent?;
    for &pred in &f.block(ind_block).in_edges {
        let blk = f.block(pred);
        if blk.out_edges.len() != 2 {
            continue; // guard must be a 2-way CBRANCH (`cbranchblock->sizeOut() != 2`)
        }
        let Some(&last) = blk.ops.last() else { continue };
        if f.op(last).code() != OpCode::Cbranch {
            continue;
        }
        // Require a real bounds guard: the compared value (after value-movement) is the switch
        // path variable. An equality test or unrelated CBRANCH preceding the switch is not folded.
        let Some(cond) = f.op(last).input(1) else { continue };
        let Some(cdef) = f.vn(cond).def else { continue };
        if !matches!(
            f.op(cdef).code(),
            OpCode::IntLess | OpCode::IntLessequal | OpCode::IntSless | OpCode::IntSlessequal
        ) {
            continue;
        }
        let (Some(a), Some(b)) = (f.op(cdef).input(0), f.op(cdef).input(1)) else { continue };
        let raw = if f.vn(b).is_constant() {
            a
        } else if f.vn(a).is_constant() {
            b
        } else {
            continue;
        };
        if !path.contains(&normalize(f, raw)) {
            continue;
        }
        // `guardtarget = cbranchblock->getOut(1-indpath)`: the edge that does not enter the switch.
        let other = blk.out_edges.iter().copied().find(|&o| o != ind_block)?;
        return f.block(other).ops.first().map(|&op| f.op(op).seqnum.pc.offset);
    }
    None
}

/// Whether `addr` lies within some loaded chunk (a backstop sanity check on recovered targets).
fn in_image(f: &Funcdata, addr: u64) -> bool {
    f.image.iter().any(|(base, bytes)| addr >= *base && addr < base + bytes.len() as u64)
}

/// Whether `start` can reach `target` without passing through `avoid` (used to decide which side
/// of a guard's branch is in-range — `avoid` is the guard block itself, so a loop's back-edge to
/// the switch, which must pass through the guard, doesn't make the out-of-range side look in-range).
fn reaches(f: &Funcdata, start: BlockId, target: BlockId, avoid: BlockId) -> bool {
    if start == target {
        return true;
    }
    let mut seen = HashSet::new();
    let mut stack = vec![start];
    while let Some(b) = stack.pop() {
        if b == target {
            return true;
        }
        if b == avoid || !seen.insert(b) {
            continue;
        }
        for &nx in &f.block(b).out_edges {
            stack.push(nx);
        }
    }
    false
}

/// Strip value-movement (COPY / sign- or zero-extension / low SUBPIECE) to the underlying value,
/// so a guard's compared variable can be matched to the switch value on the table path.
fn normalize(f: &Funcdata, mut v: VarnodeId) -> VarnodeId {
    loop {
        let Some(def) = f.vn(v).def else { return v };
        let op = f.op(def);
        v = match op.code() {
            OpCode::Copy | OpCode::IntSext | OpCode::IntZext => match op.input(0) {
                Some(x) => x,
                None => return v,
            },
            OpCode::Subpiece => match (op.input(0), op.input(1)) {
                (Some(x), Some(s)) if f.vn(s).is_constant() && f.vn(s).loc.offset == 0 => x,
                _ => return v,
            },
            _ => return v,
        };
    }
}

/// The set of varnodes the value `vn` is computed from (Ghidra's `PathMeld` reach): a backward
/// walk through defining ops, collecting every varnode on the way.
fn backtrace_set(f: &Funcdata, vn: VarnodeId) -> HashSet<VarnodeId> {
    let mut set = HashSet::new();
    let mut stack = vec![vn];
    while let Some(v) = stack.pop() {
        if !set.insert(v) {
            continue;
        }
        if f.vn(v).is_constant() {
            continue;
        }
        if let Some(def) = f.vn(v).def {
            for i in 0..f.op(def).num_inputs() {
                if let Some(inv) = f.op(def).input(i) {
                    stack.push(inv);
                }
            }
        }
    }
    set
}

/// A one-sided inequality constraint on the switch variable (the in-range condition of a guard).
#[derive(Clone, Copy)]
enum Kind {
    Lt,
    Le,
    Gt,
    Ge,
}

impl Kind {
    /// The constraint that holds when the comparison is *false* (the other side of the branch).
    fn negate(self) -> Kind {
        match self {
            Kind::Lt => Kind::Ge,
            Kind::Le => Kind::Gt,
            Kind::Gt => Kind::Le,
            Kind::Ge => Kind::Lt,
        }
    }
}

/// Ghidra `analyzeGuards` + `CircleRange`: bound the switch variable's value range `[low,high]`
/// from the guard comparisons, using the CFG to decide which side of each guard is in-range (the
/// side that reaches the BRANCHIND). Returns the most tightly-bounded path variable and its range.
fn guard_range(f: &Funcdata, path: &HashSet<VarnodeId>, indop: OpId) -> Option<(VarnodeId, u64, u64)> {
    let ind_block = f.op(indop).parent?;
    let mut bounds: std::collections::HashMap<VarnodeId, (i128, Option<i128>)> = std::collections::HashMap::new();
    for op in f.op_ids() {
        if f.op(op).is_dead() || f.op(op).code() != OpCode::Cbranch {
            continue;
        }
        let Some(cb) = f.op(op).parent else { continue };
        if f.block(cb).out_edges.len() < 2 {
            continue;
        }
        let Some(cond) = f.op(op).input(1) else { continue };
        let Some(cdef) = f.vn(cond).def else { continue };
        let code = f.op(cdef).code();
        let is_le = matches!(code, OpCode::IntLessequal | OpCode::IntSlessequal);
        if !is_le && !matches!(code, OpCode::IntLess | OpCode::IntSless) {
            continue;
        }
        let (Some(a), Some(b)) = (f.op(cdef).input(0), f.op(cdef).input(1)) else { continue };
        // Identify (var, const). The compared variable may be a sign/zero-extended or copied form
        // of the switch value (Ghidra's `valueMatch`/`pullBack`): normalize it through value-
        // movement to its root, and require that root to be on the branch-target path.
        let (raw_var, c, var_on_left) = if f.vn(b).is_constant() {
            (a, f.vn(b).loc.offset as i128, true)
        } else if f.vn(a).is_constant() {
            (b, f.vn(a).loc.offset as i128, false)
        } else {
            continue;
        };
        let var = normalize(f, raw_var);
        if !path.contains(&var) {
            continue;
        }
        // Which branch is in-range? The successor that can reach the BRANCHIND (out_edges =
        // [fallthrough, taken]; the comparison is true on the taken edge).
        let taken = f.block(cb).out_edges[1];
        let fall = f.block(cb).out_edges[0];
        let in_range_when_true = match (reaches(f, taken, ind_block, cb), reaches(f, fall, ind_block, cb)) {
            (true, false) => true,
            (false, true) => false,
            _ => continue, // ambiguous — skip this guard
        };
        // The in-range constraint on `var`: the true-branch condition, negated if in-range is the
        // false branch.  true-branch condition by (is_le, var side): `<`/`<=` for var-on-left,
        // `>`/`>=` for var-on-right (since `C < var` ⇒ `var > C`).
        let true_kind = match (is_le, var_on_left) {
            (false, true) => Kind::Lt,
            (false, false) => Kind::Gt,
            (true, true) => Kind::Le,
            (true, false) => Kind::Ge,
        };
        let kind = if in_range_when_true { true_kind } else { true_kind.negate() };
        let e = bounds.entry(var).or_insert((0, None));
        match kind {
            Kind::Lt => e.1 = Some(e.1.map_or(c - 1, |h| h.min(c - 1))),
            Kind::Le => e.1 = Some(e.1.map_or(c, |h| h.min(c))),
            Kind::Gt => e.0 = e.0.max(c + 1),
            Kind::Ge => e.0 = e.0.max(c),
        }
    }
    // Pick the bounded variable with the smallest range (Ghidra `findSmallestNormal`), breaking
    // ties by varnode id for determinism.
    let mut cand: Vec<(VarnodeId, i128, i128)> =
        bounds.into_iter().filter_map(|(v, (lo, hi))| hi.filter(|&h| h >= lo && lo >= 0).map(|h| (v, lo, h))).collect();
    cand.sort_by_key(|&(v, lo, hi)| (hi - lo, v.0));
    let (var, low, high) = cand.into_iter().next()?;
    Some((var, low as u64, high as u64))
}

/// Emulate the address calculation `vn` with the switch variable pinned to `idx`
/// (Ghidra `EmulateFunction::emulatePath`): a forward evaluation of the defining-op chain, with
/// LOADs served from the function's image (the switch table).
fn emulate(f: &Funcdata, vn: VarnodeId, sw: VarnodeId, idx: u64, depth: u32) -> Option<u64> {
    if depth > 100 {
        return None;
    }
    if vn == sw {
        return Some(idx);
    }
    let v = f.vn(vn);
    if v.is_constant() {
        return Some(v.loc.offset);
    }
    let def = v.def?;
    let op = f.op(def);
    let osz = op.output.map(|o| f.vn(o).size as u32).unwrap_or(8);
    let e = |i: usize| op.input(i).and_then(|x| emulate(f, x, sw, idx, depth + 1));
    let in_size = |i: usize| op.input(i).map(|x| f.vn(x).size as u32);
    let r = match op.code() {
        OpCode::IntAdd => e(0)?.wrapping_add(e(1)?),
        OpCode::IntSub => e(0)?.wrapping_sub(e(1)?),
        OpCode::IntMult => e(0)?.wrapping_mul(e(1)?),
        OpCode::IntLeft => e(0)?.wrapping_shl(e(1)? as u32),
        OpCode::IntRight => e(0)? >> e(1)?,
        OpCode::IntAnd => e(0)? & e(1)?,
        OpCode::IntOr => e(0)? | e(1)?,
        OpCode::Copy | OpCode::IntZext => e(0)?,
        OpCode::IntSext => sign_extend(e(0)?, in_size(0)?),
        OpCode::Subpiece => {
            let s = op.input(1)?;
            if !f.vn(s).is_constant() {
                return None;
            }
            e(0)? >> (f.vn(s).loc.offset * 8)
        }
        OpCode::Load => f.read_image(e(1)?, osz)?,
        _ => return None,
    };
    Some(mask(r, osz))
}

fn mask(x: u64, size: u32) -> u64 {
    if size >= 8 {
        x
    } else {
        x & ((1u64 << (size * 8)) - 1)
    }
}

fn sign_extend(x: u64, size: u32) -> u64 {
    if size >= 8 {
        return x;
    }
    let bits = size * 8;
    let signbit = 1u64 << (bits - 1);
    if x & signbit != 0 {
        x | !((1u64 << bits) - 1)
    } else {
        x & ((1u64 << bits) - 1)
    }
}
