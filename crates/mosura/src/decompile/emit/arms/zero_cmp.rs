//! `zero-cmp` — an equality of an UNSIGNED value against zero prints as the order compare the
//! source wrote, `x <= 0` for `x == 0` and `0 < x` for `x != 0`, where the ORIGINAL branches on
//! the unsigned order flags (`TEST AX,AX ; JBE`, `CMP byte ptr [..],0 ; JA`) — Ghidra's
//! `RuleLessEqual`/`RuleLess2Zero` fold an unsigned `x <= 0` to `x == 0` in the IR and this
//! compiler then branches `JZ`/`JNZ` (the subject's FUN_0003dd60's four `JBE`, FUN_000487cc; 14 functions
//! carry the `JBE`→`JZ` / `JA`→`JNZ` row on round f1). Value-identical for an unsigned operand
//! (`x <= 0` ⇔ `x == 0`). The witness (`recovered.zero_cmp.sites`, from
//! `buildconfig::zero_cmps_from_evidence` over this arm's candidates): the original's branch at
//! the compare's address is `JBE`/`JA`. A target-informed emit choice, NOT Ghidra.
//!
//! The arm answers LAST at `ValueSite::Equality` and `ValueSite::NegatedEquality` (after the
//! sign, all-ones and narrow arms; the negated seam hands it the flipped token);
//! `None` = the port's own rendering.
use crate::decompile::op::OpId;
use crate::decompile::printc::PrintC;
use crate::decompile::types::Datatype;

/// The arm's answer: `op` the equality, `sym` its C spelling, `prec` the port's precedence.
pub(crate) fn render(pr: &mut PrintC<'_>, op: OpId, sym: &str, prec: u8) -> Option<(String, u8)> {
    let o = pr.f.op(op);
    let (a, b) = (o.input(0)?, o.input(1)?);
    if !pr.f.vn(b).is_constant() || pr.f.vn(b).constant_value() != 0 || pr.f.vn(a).is_constant() {
        return None;
    }
    // an operand C promotes without a sign: the port's unsigned types, its unknowns (typedef'd
    // unsigned by the prelude) and Ghidra's `char` (unsigned under this compiler's default)
    if !matches!(pr.type_of(a), Datatype::Uint(_) | Datatype::Bool | Datatype::Char | Datatype::Unknown(_)) {
        return None;
    }
    let pc = o.seqnum.pc.offset;
    pr.report.zero_cmp.candidates.push(pc);
    if !pr.recovered.zero_cmp.sites.contains(&pc) {
        return None;
    }
    // the order compare prints at the port's order precedence (10), below the equality's
    let x = pr.cast_operand(op, 0, 10, false);
    Some(match sym {
        "==" => (format!("{x} <= 0"), 10),
        "!=" => (format!("0 < {x}"), 10),
        _ => return None,
    })
}

/// The zero-cmp's candidates the report pass collects (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Every equality of an unsigned value against zero (`zero-cmp`), by compare address: the
    /// original branches on the zero flag or on the unsigned order flags.
    pub candidates: Vec<u64>,
}

/// The zero-cmp's witnessed decisions the recovered pass renders (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Sites {
    /// Compare addresses whose zero test prints as the unsigned order compare (`zero-cmp`,
    /// `zero_cmp` candidates evidence, `buildconfig::zero_cmps_from_evidence`).
    pub sites: std::collections::HashSet<u64>,
}
