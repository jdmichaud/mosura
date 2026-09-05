//! `narrow-cmp` — a compare between a value narrower than int and a constant prints the constant
//! cast to the value's own type, `param_1 <= (uint1)0x8`, `(uint2)1 < *p`, where the ORIGINAL
//! compares at the narrow width (`CMP AL,0x8 ; JA`, `CMP BX,0x1 ; JBE`). C promotes both operands
//! to int and this compiler then widens the value first (`XOR EDX,EDX ; MOV DL,AL ; CMP EDX,0x8 ;
//! JG` — a signed compare of the promoted value); a constant of the operand's own type keeps the
//! compare narrow and unsigned (the subject's FUN_00020220 EXACT, FUN_00049b84's compare rows; 65 non-exact
//! functions carry a narrow-vs-wide compare row on round f0). Value-identical: the constant is
//! representable at the operand's width (checked), so the cast changes nothing but the width the
//! compiler compares at. The witness (`recovered.narrow_cmp.sites`, from
//! `buildconfig::narrow_cmps_from_evidence` over this arm's candidates): the original's
//! flag-setting `CMP` in the few instructions before the compare's branch names a register or
//! memory operand of the operand's width. A target-informed emit choice, NOT Ghidra.
//!
//! The arm answers LAST at `ValueSite::Compare` and `ValueSite::Equality` (after the sign and
//! order arms — a witnessed cast there already re-spells the compare); `None` = the port's own
//! rendering.
use crate::decompile::op::OpId;
use crate::decompile::printc::PrintC;
use crate::decompile::types::Datatype;
use crate::decompile::varnode::VarnodeId;

/// The candidate's shape and its witnessed answer: `(the value's slot, the constant's type to
/// cast to)` — `None` when the compare is not a sub-int value against a constant of its width,
/// or is not witnessed. Records the candidate on every print. Shared with the complement arm,
/// which answers the `Compare` seam first and applies this cast to its own adjusted constant.
pub(crate) fn cast_for(pr: &mut PrintC<'_>, op: OpId) -> Option<(usize, Datatype)> {
    let o = pr.f.op(op);
    let (a, b) = (o.input(0)?, o.input(1)?);
    let (ka, kb) = (pr.f.vn(a).is_constant(), pr.f.vn(b).is_constant());
    if ka == kb {
        return None; // two values, or two constants
    }
    let (v, k, vslot) = if kb { (a, b, 0) } else { (b, a, 1) };
    let size = pr.f.vn(v).size;
    if size == 0 || size >= pr.f.size_of_int() || pr.f.vn(k).size != size {
        return None;
    }
    let ty = match pr.type_of(v) {
        Datatype::Uint(n) | Datatype::Int(n) if n == size => pr.type_of(v),
        Datatype::Bool | Datatype::Char if size == 1 => Datatype::Uint(1),
        _ => return None,
    };
    let pc = o.seqnum.pc.offset;
    crate::debug!(crate::debug::Topic::Recover, "narrow-cmp candidate @{pc:x} size {size} witnessed {}", pr.recovered.narrow_cmp.sites.contains(&pc));
    pr.report.narrow_cmp.candidates.push((pc, size));
    if !pr.recovered.narrow_cmp.sites.contains(&pc) {
        return None;
    }
    Some((vslot, ty))
}

/// The arm's answer: `op` the compare, `sym` its C spelling, `prec` the port's precedence.
pub(crate) fn render(pr: &mut PrintC<'_>, op: OpId, sym: &str, prec: u8) -> Option<(String, u8)> {
    let (vslot, ty) = cast_for(pr, op)?;
    let o = pr.f.op(op);
    let kslot = 1 - vslot;
    let k = o.input(kslot)?;
    let konst = render_narrow_const(pr, k, &ty);
    let val = pr.cast_operand(op, 1 - kslot, prec, kslot == 0);
    let konst = format!("({}){konst}", ty.name());
    Some((if kslot == 1 { format!("{val} {sym} {konst}") } else { format!("{konst} {sym} {val}") }, prec))
}

/// The constant at the operand's width: unsigned as the masked hex value, signed as the
/// sign-extended decimal, so the cast never changes the value.
fn render_narrow_const(pr: &PrintC<'_>, k: VarnodeId, ty: &Datatype) -> String {
    let w = pr.f.vn(k).size;
    let mask = (1u64 << (8 * w)) - 1;
    let raw = pr.f.vn(k).constant_value() & mask;
    match ty {
        Datatype::Int(_) if raw & (1u64 << (8 * w - 1)) != 0 => format!("{}", (raw | !mask) as i64),
        _ => format!("0x{raw:x}"),
    }
}

/// The narrow-cmp's candidates the report pass collects (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Every compare of a sub-int value against a constant of its width (`narrow-cmp`), as
    /// `(compare address, operand size)`: the original compares at that width or widens first.
    pub candidates: Vec<(u64, u32)>,
}

/// The narrow-cmp's witnessed decisions the recovered pass renders (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Sites {
    /// Compare addresses whose constant prints cast to the operand's type (`narrow-cmp`,
    /// `narrow_cmp` candidates evidence, `buildconfig::narrow_cmps_from_evidence`).
    pub sites: std::collections::HashSet<u64>,
}
