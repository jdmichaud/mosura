//! `unsigned-cmp` — an equality against an all-ones narrow constant whose ORIGINAL compare
//! immediate is the zero-extended spelling prints as `(uintN)x == 0xffN` instead of the signed
//! `x == -1`: the source compared an unsigned narrow value (the `allones_cmp_candidates` doc on
//! `EmitReport`; witness `recovered.unsigned_cmp_sites`, from
//! `buildconfig::unsigned_cmps_from_evidence` — one of the text-parsing witnesses, R3b). A
//! target-informed emit choice, NOT Ghidra: the reference decompiler prints the signed `-1`.
//!
//! Moved verbatim out of printc.rs (review R2b, commit 1): the site analysis (the constant slot,
//! the narrow width, the mask), the candidate report and the witnessed rendering that sat inline in
//! `eq_bin`; the only textual change is `self.` → `pr.` and the answer form (`return` →
//! `return Some`).
//!
//! The arm answers ONE seam, `ValueSite::Equality` — an `==`/`!=` the port is about to render:
//! it reports every all-ones site as a candidate (the survey's evidence) and renders the witnessed
//! ones; `None` = the port's own equality rendering.
use crate::decompile::op::OpId;
use crate::decompile::printc::PrintC;
use crate::decompile::types::Datatype;

/// The arm's answer at `ValueSite::Equality`: `op` is the equality, `sym` its spelling, `prec`
/// the port's precedence for it.
pub(crate) fn render(pr: &mut PrintC<'_>, op: OpId, sym: &'static str, prec: u8) -> Option<(String, u8)> {
    let o = pr.f.op(op);
    let pc = o.seqnum.pc.offset;
    let site = o.input(0).zip(o.input(1)).and_then(|(x, y)| {
        let cslot = if pr.f.vn(y).is_constant() {
            1usize
        } else if pr.f.vn(x).is_constant() {
            0usize
        } else {
            return None;
        };
        let cvn = if cslot == 0 { x } else { y };
        let size = pr.f.vn(cvn).size;
        if !(size == 1 || size == 2) {
            return None;
        }
        let mask = (1u64 << (u64::from(size) * 8)) - 1;
        (pr.f.vn(cvn).constant_value() & mask == mask).then_some((cslot, size, mask))
    });
    if let Some((cslot, size, mask)) = site {
        pr.report.allones_cmp_candidates.push((pc, size));
        if pr.recovered.unsigned_cmp_sites.contains(&pc) {
            let other = pr.cast_operand(op, 1 - cslot, 13, false);
            return Some((
                format!("({}){other} {sym} 0x{mask:x}", Datatype::Uint(size).name()),
                prec,
            ));
        }
    }
    None
}
