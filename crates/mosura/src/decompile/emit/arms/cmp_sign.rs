//! `cmp-sign` — the extension a narrow compare operand takes. A 16-bit value compared against
//! an int-width constant is promoted by C; a SIGNED narrow type (`*(int2 *)(p + 0x1c) == 1`,
//! the decompiler's type from a signed use elsewhere) promotes by sign-extension — this
//! compiler's `MOV EAX,[p+0x1a] ; SAR EAX,0x10` — where the original zero-extended
//! (`MOV AX,[p+0x1c] ; AND EAX,0xffff`, WAR2 FUN_00059784). Ghidra's `RuleZextEliminate`
//! removed the IR's ZEXT (`ZEXT(x) == 1` is `x == 1:2`), so the port has nothing to print; the
//! original's own extension idiom before the compare is the witness (`recovered.cmp_unsigned_sites`
//! from `buildconfig::cmp_signs_from_evidence` over this arm's `cmp_sign_candidates`): an
//! `AND r,0xffff|0xff` or `XOR r,r ; MOV r16/r8` says zero-extend, a `SAR r,0x10` / `CWDE` /
//! `MOVSX` says sign. A witnessed site prints its narrow signed MEMORY operands `(uintN)` cast
//! (a global or an inline load; a register-resident local is loaded at its definition).
//! Value-identical at the compare for every value the original could hold (the original
//! compared the zero-extended value). A target-informed emit choice, NOT Ghidra.
//!
//! The arm answers LAST at `ValueSite::Equality` and `ValueSite::Compare`.
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;
use crate::decompile::types::Datatype;
use crate::decompile::varnode::VarnodeId;

/// The arm's answer: `op` the compare, `sym` its C spelling, `prec` the port's precedence.
pub(crate) fn render(pr: &mut PrintC<'_>, op: OpId, sym: &str, prec: u8) -> Option<(String, u8)> {
    let o = pr.f.op(op);
    let pc = o.seqnum.pc.offset;
    let (a, b) = (o.input(0)?, o.input(1)?);
    let (na, nb) = (narrow_signed(pr, a), narrow_signed(pr, b));
    if !na && !nb {
        return None;
    }
    let v = if na { a } else { b };
    let size = pr.f.vn(v).size;
    let global = global_address(pr, v);
    crate::debug!(crate::debug::Topic::Recover, "cmp-sign candidate @{pc:x} size {size} global {global:x?}");
    pr.report.cmp_sign_candidates.push((pc, size, global));
    // a witnessed site, or another witnessed compare of the SAME global in this function: the
    // original loads a global once and compares it twice (FUN_00029b50's `== 0x3c` then
    // `== 0x32`, the second on the register), and a cast on one read alone splits the load
    let witnessed = pr.recovered.cmp_unsigned_sites.contains(&pc)
        || global.is_some_and(|g| pr.recovered.cmp_unsigned_globals.contains(&g));
    if !witnessed {
        return None;
    }
    let cast = |pr: &mut PrintC<'_>, slot: usize, v: VarnodeId, narrow: bool, right: bool| -> String {
        if narrow {
            let inner = pr.cast_operand(op, slot, 14, right);
            format!("({}){inner}", Datatype::Uint(pr.f.vn(v).size).name())
        } else {
            pr.cast_operand(op, slot, prec, right)
        }
    };
    let l = cast(pr, 0, a, na, false);
    let r = cast(pr, 1, b, nb, true);
    Some((format!("{l} {sym} {r}"), prec))
}

/// The ram address of a global operand, `None` for a load through a pointer.
fn global_address(pr: &PrintC<'_>, v: VarnodeId) -> Option<u64> {
    let vn = pr.f.vn(v);
    (Some(vn.loc.space) == pr.f.spaces.by_name("ram")).then_some(vn.loc.offset)
}

/// A non-constant operand narrower than int whose C type is a signed integer and which the
/// compare reads FROM MEMORY — a global, or a load rendered at the compare. A register-resident
/// local (`iVar1 == 9`) is loaded at its own definition, and the original's zero-extending load
/// pair there is the local's load whatever the type (measured: FUN_0001562c, FUN_00059730,
/// FUN_00059ff8 lost EXACT to the cast, round e13).
fn narrow_signed(pr: &PrintC<'_>, v: VarnodeId) -> bool {
    let vn = pr.f.vn(v);
    if vn.is_constant() || vn.size >= pr.f.size_of_int() || !matches!(pr.type_of(v), Datatype::Int(_)) {
        return false;
    }
    let ram = pr.f.spaces.by_name("ram");
    let global = Some(vn.loc.space) == ram;
    let inline_load = !pr.is_explicit(v) && vn.def.is_some_and(|d| pr.f.op(d).code() == OpCode::Load);
    global || inline_load
}
