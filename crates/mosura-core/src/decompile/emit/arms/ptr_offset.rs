//! `ptr-offset` — a dereference at a constant offset from a pointer prints as byte-pointer
//! arithmetic, `*(T *)((char *)p + k)`, where the port prints `*(T *)((int4)p + k)` (Ghidra's
//! `arithmeticOutputStandard`: the sum of a pointer and an int is int-natured and casts). Both
//! name the same address, but this compiler treats the int-cast sum as integer arithmetic and
//! materializes it (`LEA EAX,[EDX + 0x1a]` then `CMP word ptr [EAX],0`, the subject's FUN_0003ca54;
//! `ADD EAX,0x1f` in FUN_0001c918) where it folds pointer arithmetic into the addressing mode
//! (`CMP word ptr [EDX + 0x1a],0`) — 118 emitted TUs carry the form, 87 of them with an extra
//! `LEA` (round e12). The witness (`recovered.ptr_offset.sites`, from
//! `buildconfig::ptr_offsets_from_evidence` over this arm's `ptr_offset_candidates`): the
//! original's instruction at the sum's address carries the offset as a displacement
//! (`[.. + 0x1a]`) and is not an `LEA`. A target-informed emit choice, NOT Ghidra.
//!
//! The arm answers LAST at `ValueSite::Deref` (after struct-return and array-index); `None` =
//! the port's own rendering.
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;
use crate::decompile::types::Datatype;
use crate::decompile::varnode::VarnodeId;

/// The varnode under any chain of implied CASTs.
fn strip_casts(pr: &PrintC<'_>, mut v: VarnodeId) -> VarnodeId {
    while !pr.is_explicit(v) {
        let Some(d) = pr.f.vn(v).def else { break };
        let o = pr.f.op(d);
        if o.code() != OpCode::Cast {
            break;
        }
        let Some(x) = o.input(0) else { break };
        v = x;
    }
    v
}

/// The arm's answer at `ValueSite::Deref`: `addr` the dereferenced address, `vty` the access type.
pub(crate) fn render(pr: &mut PrintC<'_>, addr: VarnodeId, vty: &Datatype) -> Option<(String, u8)> {
    if pr.is_explicit(addr) {
        return None;
    }
    // through the CASTs the port's cast strategy wraps the sum and its pointer operand in
    let sum = strip_casts(pr, addr);
    let def = pr.f.vn(sum).def?;
    let o = pr.f.op(def);
    if o.code() != OpCode::IntAdd || o.num_inputs() != 2 {
        return None;
    }
    let (base, off) = (strip_casts(pr, o.input(0)?), o.input(1)?);
    if !pr.f.vn(off).is_constant() || pr.f.vn(base).is_constant() {
        return None;
    }
    let k = pr.f.vn(off).constant_value();
    // the port's own subscript form takes a whole-element offset into a known array
    if k == 0 || pr.array_elem.get(&base).is_some_and(|&e| e > 0 && k.is_multiple_of(u64::from(e))) {
        return None;
    }
    // only the sum the port casts to int: a pointer-typed base
    if !matches!(pr.type_of(base), Datatype::Pointer(..)) {
        return None;
    }
    let pc = o.seqnum.pc.offset;
    crate::debug!(crate::debug::Topic::Recover, "ptr-offset candidate @{pc:x} + 0x{k:x}");
    pr.report.ptr_offset.candidates.push((pc, k));
    if !pr.recovered.ptr_offset.sites.contains(&pc) {
        return None;
    }
    let b = pr.operand(base, 14, false);
    Some((format!("*({} *)((char *){b} + 0x{k:x})", vty.name()), 15))
}

/// The ptr-offset's candidates the report pass collects (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Every dereference at a constant offset from a pointer-typed base (`ptr-offset`), as
    /// `(the sum's address, offset)`: the original folds the offset into the addressing mode
    /// or materializes the sum.
    pub candidates: Vec<(u64, u64)>,
}

/// The ptr-offset's witnessed decisions the recovered pass renders (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Sites {
    /// Sum addresses whose offset the original folds into the addressing mode (`ptr-offset`,
    /// `ptr_offset_candidates` evidence, `buildconfig::ptr_offsets_from_evidence`).
    pub sites: std::collections::HashSet<u64>,
}
