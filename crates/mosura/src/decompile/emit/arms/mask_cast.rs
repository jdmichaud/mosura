//! `mask-cast` — a call argument the ORIGINAL masks to a narrow width before the call prints as
//! the narrow cast of its expression: `f((uint2)(x + 0xbc1), ..)`. Ghidra's `RuleAndMask` proves
//! such a mask redundant (a byte plus a small constant never reaches bit 16) and removes it from
//! the IR, so the port has nothing to print — but this compiler emits the mask only from a
//! source that truncates (a `WORD` temporary, a cast), and without it the argument's `AND
//! EAX,0xffff` is missing from the recompile (WAR2 FUN_000121ac and the `+ 0xbbb` message-id
//! family, FUN_0004a194's `(cond) + 0xbf8`: 23 near-miss functions on round e6). The witness is
//! the original's own `AND r,0xff|0xffff` on the argument's register between the argument's
//! definition and the call (`recovered.mask_cast.sites`, from `buildconfig::masked_args_from_evidence`
//! over this arm's `mask_candidates` report). Value-preserving: the mask the original applied is
//! the one Ghidra proved redundant. A target-informed emit choice, NOT Ghidra.
//!
//! The arm answers ONE seam, `ValueSite::CallArg`: it reports every register-resident, non-constant
//! argument (the survey's evidence) and renders the witnessed ones cast; `None` = the port's own
//! rendering of the argument.
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;
use crate::decompile::types::Datatype;

/// The arm's answer at `ValueSite::CallArg`: `op` the call, `slot` the argument's input slot.
pub(crate) fn render(pr: &mut PrintC<'_>, op: OpId, slot: usize) -> Option<(String, u8)> {
    let o = pr.f.op(op);
    let v = o.input(slot)?;
    let vn = pr.f.vn(v);
    if vn.is_constant() || pr.f.spaces.by_name("register") != Some(vn.loc.space) {
        return None;
    }
    // a pointer is never masked, and an argument the IR still masks (`x & 0xff` kept, the mask
    // not provably redundant) already prints its mask
    if matches!(pr.type_of(v), Datatype::Pointer(..)) {
        return None;
    }
    if vn.def.is_some_and(|d| {
        let dop = pr.f.op(d);
        dop.code() == OpCode::IntAnd && dop.input(1).is_some_and(|c| pr.f.vn(c).is_constant())
    }) {
        return None;
    }
    // the argument's definition, for the witness's window; an input (no def) starts at entry
    let def_pc = vn.def.map(|d| pr.f.op(d).seqnum.pc.offset).unwrap_or(0);
    let call_pc = o.seqnum.pc.offset;
    pr.report.mask_cast.candidates.push((call_pc, slot as u32, def_pc, (vn.loc.offset, vn.size)));
    let &width = pr.recovered.mask_cast.sites.get(&(call_pc, slot as u32))?;
    let inner = pr.operand(v, 14, false);
    Some((format!("({})({inner})", Datatype::Uint(width).name()), 14))
}

/// The mask-cast's candidates the report pass collects (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Every register-resident, non-constant CALL argument, as `(call address, argument slot,
    /// definition address, register (offset, size))` — the `mask-cast` candidates. Ghidra's
    /// `RuleAndMask` removes a mask it proves redundant, so an argument the original masks to a
    /// narrow width before the call (`ADD EAX,0xbc1 ; AND EAX,0xffff ; CALL`) has no mask left
    /// in the IR; a target rule reads the original's `AND` on the argument's register between
    /// its definition and the call (`buildconfig::masked_args_from_evidence`).
    pub candidates: Vec<(u64, u32, u64, (u64, u32))>,
}

/// The mask-cast's witnessed decisions the recovered pass renders (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Sites {
    /// `mask-cast`: call arguments to print as `(uintN)(expr)` — `(call address, slot)` to the
    /// witnessed mask width (`mask_candidates` evidence, `buildconfig::masked_args_from_evidence`).
    pub sites: std::collections::HashMap<(u64, u32), u32>,
}
