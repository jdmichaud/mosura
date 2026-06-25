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
    // analyzeGuards + CircleRange: bound the switch variable's range from the guard comparison.
    let (switch_var, n) = find_guard(f, &path)?;
    if n == 0 || n > 4096 {
        return None; // implausible range — Ghidra rejects ranges over maxtablesize
    }
    // buildAddresses: emulate each value through to the branch target.
    let mut targets = Vec::with_capacity(n as usize);
    for idx in 0..n {
        targets.push(emulate(f, target_vn, switch_var, idx as u64, 0)?);
    }
    Some(JumpTable { op_addr: f.op(indop).seqnum.pc.offset, targets })
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

/// Find the guard bounding the switch variable (Ghidra `analyzeGuards` reduced to the single
/// range-check shape): a CBRANCH whose condition compares a path varnode against a constant.
/// Returns `(switch_var, case_count)` — the variable to vary and the number of cases.
fn find_guard(f: &Funcdata, path: &HashSet<VarnodeId>) -> Option<(VarnodeId, u64)> {
    for op in f.op_ids() {
        if f.op(op).is_dead() || f.op(op).code() != OpCode::Cbranch {
            continue;
        }
        let Some(cond) = f.op(op).input(1) else { continue };
        let Some(cdef) = f.vn(cond).def else { continue };
        let cop = f.op(cdef);
        let (Some(a), Some(b)) = (cop.input(0), cop.input(1)) else { continue };
        let (ca, cb) = (f.vn(a).is_constant(), f.vn(b).is_constant());
        // `var < C` / `var <= C` bound the variable above; `C < var` / `C <= var` express the
        // out-of-range condition (the branch goes to the default), so the in-range count is C(+1).
        let bound = match cop.code() {
            OpCode::IntLess | OpCode::IntSless => {
                if cb && path.contains(&a) {
                    Some((a, f.vn(b).loc.offset)) // var < C → C cases
                } else if ca && path.contains(&b) {
                    Some((b, f.vn(a).loc.offset + 1)) // C < var → var in [0,C] → C+1 cases
                } else {
                    None
                }
            }
            OpCode::IntLessequal | OpCode::IntSlessequal => {
                if cb && path.contains(&a) {
                    Some((a, f.vn(b).loc.offset + 1)) // var <= C → C+1 cases
                } else if ca && path.contains(&b) {
                    Some((b, f.vn(a).loc.offset)) // C <= var → var in [0,C) → C cases
                } else {
                    None
                }
            }
            _ => None,
        };
        if bound.is_some() {
            return bound;
        }
    }
    None
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
