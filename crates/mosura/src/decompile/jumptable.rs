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
    /// The case label (switch-variable value) for each target — Ghidra `JumpTable::label`, computed
    /// by `JumpBasic::buildLabels` at recovery time (where the switch variable's bounded range is
    /// known). Parallel to `targets`: a switch on `iVar` with cases `1..9`, not `0..8`.
    pub labels: Vec<i64>,
    /// Storage location and size of the *unnormalized* switch variable found during recovery
    /// (`JumpBasic::findUnnormalized` on the recovery partial; kept as Ghidra keeps the saved model
    /// `origmodel`). `ActionSwitchNorm` re-instantiates the variable on the final graph at this
    /// address (`matchModel`) to fold the `BRANCHIND` onto it.
    pub switchvn_loc: Option<(super::space::Address, u32)>,
    /// Set once `ActionSwitchNorm`'s `foldInNormalization` has repointed the `BRANCHIND` at the
    /// switch variable, so the printer reads that variable directly and uses `labels`.
    pub normalized: bool,
}

/// Recover every jump table in `f` (Ghidra `Funcdata::recoverJumpTables` over each BRANCHIND).
pub fn recover(f: &mut Funcdata) -> Vec<JumpTable> {
    let mut out = Vec::new();
    // Collect the BRANCHIND ops first: recover_jumpbasic takes `&mut Funcdata` (its PathMeld walk
    // transiently marks Varnodes), so we can't hold an immutable op iterator across the calls.
    let branchinds: Vec<OpId> = f
        .op_ids()
        .filter(|&op| !f.op(op).is_dead() && f.op(op).code() == OpCode::Branchind)
        .collect();
    for op in branchinds {
        if let Some(jt) = super::jumpbasic::recover_jumpbasic(f, op) {
            out.push(jt);
        }
    }
    out
}

/// Ghidra `JumpBasic::foldInOneGuard` geometry: a bounds guard whose in-range edge branches
/// directly into the switch block has its *other* (out-of-range) edge target as the `default`
/// case. Find that guard among the switch block's predecessors and return the default address.
pub(crate) fn find_default(f: &Funcdata, indop: OpId, path: &HashSet<VarnodeId>) -> Option<u64> {
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
pub(crate) fn in_image(f: &Funcdata, addr: u64) -> bool {
    f.image.iter().any(|(base, bytes)| addr >= *base && addr < base + bytes.len() as u64)
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
pub(crate) fn backtrace_set(f: &Funcdata, vn: VarnodeId) -> HashSet<VarnodeId> {
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

/// Emulate the address calculation `vn` with the switch variable pinned to `idx`
/// (Ghidra `EmulateFunction::emulatePath`): a forward evaluation of the defining-op chain, with
/// LOADs served from the function's image (the switch table).
pub(crate) fn emulate(f: &Funcdata, vn: VarnodeId, sw: VarnodeId, idx: u64, depth: u32) -> Option<u64> {
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
