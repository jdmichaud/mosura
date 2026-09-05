//! `return-widen` — the SIGN of a widened return. The `return-width` witness
//! (`buildconfig::narrow_return_from_evidence`) declares the return at int width when a
//! narrow write completes a widening (`XOR EAX,EAX ; MOV AX,[g]`, the carve-out); the value
//! the IR returns is still the narrow one, and a SIGNED narrow value (`short g`) then
//! sign-extends in C — this compiler's `MOV EAX,[g-2] ; SAR EAX,0x10` where the original
//! zero-extended (the subject's FUN_000243bc, FUN_00029b50: `return iRam00090160;` under a `short`
//! declaration). The `XOR` IS the extension the original performed: the value prints
//! `(uintN)` cast (`recovered.return_widen.zero_widened`, from the same witness). Value-faithful to
//! the original's bytes, and to the IR's narrow value; only the C promotion changes.
//! A target-informed emit choice, NOT Ghidra.
//!
//! The arm answers ONE seam, `ValueSite::ReturnValue`; `None` = the port's own rendering.
use crate::decompile::printc::PrintC;
use crate::decompile::types::Datatype;
use crate::decompile::varnode::VarnodeId;

/// The arm's answer at `ValueSite::ReturnValue`: `v` the returned value (after the narrowed
/// return's low-part selection).
pub(crate) fn render(pr: &mut PrintC<'_>, v: VarnodeId) -> Option<(String, u8)> {
    if !pr.recovered.return_widen.zero_widened {
        return None;
    }
    let vn = pr.f.vn(v);
    if vn.is_constant() || vn.size >= pr.f.size_of_int() {
        return None;
    }
    // an unsigned narrow value already zero-extends under C's promotion (Watcom's plain
    // `char` is unsigned); only a signed-typed one needs the re-sign
    if !matches!(pr.type_of(v), Datatype::Int(_)) {
        return None;
    }
    let inner = pr.operand(v, 14, false);
    Some((format!("({}){inner}", Datatype::Uint(vn.size).name()), 14))
}

/// The return-widen's witnessed decisions the recovered pass renders (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Sites {
    /// The `return-width` witness saw the widening carve-out (`XOR EAX,EAX` completing a narrow
    /// write): the widened return zero-extends its narrow value (`return-widen`).
    pub zero_widened: bool,
}
