//! `join-width=consumer` — a local whose value is the JOIN of narrow constants the ORIGINAL
//! materialized into an 8-bit sub-register (`MOV DL,k`, not `MOV EDX,k`) declares at that narrow
//! width, so the recompile reuses the sub-register; per witnessed site set
//! (`recovered.join_narrow_sites`, from `buildconfig::join_narrow_sites_from_evidence`, over this
//! arm's `join_narrow_candidates` report). A target-informed emit choice, NOT Ghidra: the
//! reference decompiler declares the local at the value's width.
//!
//! Moved verbatim out of printc.rs (review R2b, commit 5): the width reader
//! (`narrowed_join_width`, one caller) and the consult that sat inline in `name_of`'s
//! declaration-type decision; the only textual changes are `self.` → `pr.`, the sibling call,
//! the flag's path (the arm's State from the `join-width` axis) and the answer form (the
//! narrowed type → `return Some(..)`). The port keeps `storage_widened_local(..).unwrap_or(ty)`
//! as the None path (it was the same expression on both of the old branches).
//!
//! The arm answers ONE seam, `arms::local_decl_type` — the declared type of a genuine local
//! `name_of` is about to declare.
use crate::decompile::emit::{EmitChoices, JoinWidth};
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;
use crate::decompile::types::Datatype;
use crate::decompile::varnode::VarnodeId;

/// The arm's state: its configuration (the witness set is the port's).
#[derive(Debug, Default)]
pub(crate) struct State {
    /// `join-width=consumer` is on for the whole function.
    pub(crate) consumer: bool,
}

impl State {
    pub(crate) fn new(choices: &EmitChoices) -> Self {
        State { consumer: choices.join_width == JoinWidth::Consumer }
    }
}

/// The arm's answer for the local `v` (value type `ty`) `name_of` is declaring: the narrowed
/// declared type, or `None` for the port's own declaration width.
pub(crate) fn local_decl_type(pr: &mut PrintC<'_>, v: VarnodeId, ty: &Datatype) -> Option<Datatype> {
    if let Some((w, pcs)) = narrowed_join_width(pr, v) {
        // N1 (witnessed): record the constant-materialization pcs; narrow the declaration only
        // where EVERY join constant is loaded into an 8-bit sub-register in the original
        // (`MOV DL,k` not `MOV EDX,k` — do_unit_comp_defend 0x2c9a8 uses the full register and
        // must stay wide). The recovered set is empty on the report pass (records only) and
        // populated on the final pass.
        for pc in &pcs {
            pr.report.join_narrow_candidates.push(*pc);
        }
        if pr.arms.join_narrow.consumer && pcs.iter().all(|pc| pr.recovered.join_narrow_sites.contains(pc)) {
            return Some(match ty {
                Datatype::Int(_) => Datatype::Int(w),
                Datatype::Uint(_) => Datatype::Uint(w),
                _ => Datatype::Unknown(w),
            });
        }
    }
    None
}

/// N1 (wc2src-reconciliation-3): the narrower declaration width for a CONSTANT-JOIN local
/// `v` — a HighVariable every member of which is a constant, a COPY of a constant, or a
/// MULTIEQUAL of such — that is passed as an argument to a call whose RECOVERED prototype
/// (`CallSpec::reads`) declares a narrower parameter at that slot. `None` when the local is
/// not an all-constant join, no consuming call has a narrower recovered param, or a constant
/// does not fit the narrow width. Value-identical: the constants fit, so a byte declaration
/// truncates nothing and C's promotion restores the value at any wider use.
fn narrowed_join_width(pr: &PrintC<'_>, v: VarnodeId) -> Option<(u32, Vec<u64>)> {
    let cur = pr.type_of(v).size();
    let mut pcs: Vec<u64> = Vec::new();
    let members = pr.high_members.get(&pr.high_of[v.0 as usize])?;
    // Gate 1: every member is constant-fed.
    let mut consts: Vec<u64> = Vec::new();
    for &m in members {
        let mv = pr.f.vn(m);
        if mv.is_constant() {
            consts.push(mv.loc.offset);
            continue;
        }
        let Some(d) = mv.def else { return None };
        match pr.f.op(d).code() {
            OpCode::Copy => {
                let in0 = pr.f.op(d).input(0)?;
                if pr.f.vn(in0).is_constant() {
                    consts.push(pr.f.vn(in0).loc.offset);
                    pcs.push(pr.f.op(d).seqnum.pc.offset);
                } else {
                    return None;
                }
            }
            OpCode::Multiequal => {} // its inputs are other members of the same join
            _ => return None,
        }
    }
    if consts.is_empty() {
        return None;
    }
    // Gate 2: a consuming call whose recovered param at this arg slot is narrower.
    let mut target: Option<u32> = None;
    for &m in members {
        for &op in &pr.f.vn(m).descend {
            let o = pr.f.op(op);
            if !matches!(o.code(), OpCode::Call | OpCode::Callind) {
                continue;
            }
            let Some(slot) = (0..o.num_inputs()).find(|&i| o.input(i) == Some(m)) else { continue };
            if slot == 0 {
                continue; // the call target, not an argument
            }
            // The callee's ACTUAL read width (un-widened), not `reads`' register-entry width.
            let w = pr.f.call_specs.get(&op).and_then(|cs| cs.param_widths.as_ref()).and_then(|pw| pw.get(slot - 1)).copied();
            let Some(w) = w else { continue };
            if w == 0 || w >= cur {
                continue;
            }
            // every joined constant must fit the narrow width
            let mask = if w >= 8 { u64::MAX } else { (1u64 << (w * 8)) - 1 };
            if consts.iter().any(|&c| c & !mask != 0) {
                continue;
            }
            target = Some(target.map_or(w, |t| t.min(w)));
        }
    }
    target.map(|w| (w, pcs))
}
