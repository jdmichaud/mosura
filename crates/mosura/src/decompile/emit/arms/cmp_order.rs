//! `cmp-order` — an order comparison whose ORIGINAL `CMP` names the port's RIGHT operand first
//! prints mirrored: `b > a` for the port's `a < b`, `b >= a` for its `a <= b`. Ghidra
//! canonicalizes every `>` / `>=` to `<` / `<=` (the flag-collapse rules build one
//! INT_LESS-family op per branch, operands in the order the rule chose), so the IR no longer
//! carries which operand the source wrote first — but this compiler emits the `CMP` in SOURCE
//! order (`CMP a,b` for `a < b`, `CMP b,a` for `b > a`), so the original bytes still do. The
//! witness is `recovered.cmp_order_sites`, from `buildconfig::cmp_orders_from_evidence`
//! (measured on WAR2 FUN_0002530c: the original `CMP EDX,EAX ; SETGE` where the port's
//! `x <= y` compiled to `CMP EAX,EDX ; SETLE`; EXACT once mirrored). Constant operands are never
//! candidates: x86 always encodes the constant second, so their order carries no information —
//! the off-by-one immediate flavour of the same canonicalization is `complement_cmp`'s. A
//! target-informed emit choice, NOT Ghidra: the reference decompiler prints the canonical form.
//!
//! The arm answers ONE seam, `ValueSite::Compare`, after `complement_cmp` declined: it reports
//! every two-operand order comparison (the survey's evidence) and renders the witnessed ones
//! mirrored; `None` = the port's own compare rendering.
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;
use crate::decompile::varnode::VarnodeId;

/// The arm's answer at `ValueSite::Compare`: `op` the compare, `strict` its kind, `prec` the
/// port's precedence for it.
pub(crate) fn render(pr: &mut PrintC<'_>, op: OpId, strict: bool, prec: u8) -> Option<(String, u8)> {
    let o = pr.f.op(op);
    let pc = o.seqnum.pc.offset;
    let (a, b) = (o.input(0)?, o.input(1)?);
    if pr.f.vn(a).is_constant() || pr.f.vn(b).is_constant() {
        return None;
    }
    // LEAF operands only: a value the compare reads as it stands (an input, a load, a named
    // variable, an extension or piece of one). An ARITHMETIC operand is evaluated into a register
    // by the compare's own code, and mirroring the compare re-orders that evaluation and with it
    // the allocation (WAR2 FUN_0004bdb0: `field >> 16 > a + b` lost SAME_SHAPE, round e2).
    if !leaf(pr, a) || !leaf(pr, b) {
        return None;
    }
    let (ra, rb) = (operand_of(pr, a), operand_of(pr, b));
    pr.report.cmp_order_candidates.push((pc, ra, rb));
    if !pr.recovered.cmp_order_sites.contains(&pc) {
        return None;
    }
    let sym = if strict { ">" } else { ">=" };
    // the mirrored form: the port's right operand is the left one here, so slot 1 renders on
    // the left side and slot 0 on the right
    let l = pr.cast_operand(op, 1, prec, false);
    let r = pr.cast_operand(op, 0, prec, true);
    Some((format!("{l} {sym} {r}"), prec))
}

/// A value the compare reads as it stands: an input, an explicit variable, or a load / copy /
/// extension / piece chain ending in one — not the result of arithmetic.
fn leaf(pr: &PrintC<'_>, v: VarnodeId) -> bool {
    if pr.is_explicit(v) {
        return true;
    }
    let Some(d) = pr.f.vn(v).def else { return true };
    match pr.f.op(d).code() {
        OpCode::Load | OpCode::Multiequal | OpCode::Indirect => true,
        OpCode::Copy | OpCode::IntZext | OpCode::IntSext | OpCode::Subpiece | OpCode::Cast => {
            pr.f.op(d).input(0).is_none_or(|x| leaf(pr, x))
        }
        _ => false,
    }
}

/// `(offset, size)` of `v` in the register space — `None` for anything else (memory, a
/// temporary, a stack slot): only a register the disassembly can name is matched by the witness.
/// A compare operand the original's `CMP` can name: a general register (by register-space
/// offset and size) or a GLOBAL by its address (`CMP DL,byte ptr [0x8f042]`, WAR2 FUN_00014990:
/// two byte globals compared, the memory operand names the source's right-hand side).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpOperand {
    Reg(u64, u32),
    Mem(u64),
}

fn operand_of(pr: &PrintC<'_>, v: VarnodeId) -> Option<CmpOperand> {
    let vn = pr.f.vn(v);
    if pr.f.spaces.by_name("register") == Some(vn.loc.space) {
        Some(CmpOperand::Reg(vn.loc.offset, vn.size))
    } else if pr.f.spaces.by_name("ram") == Some(vn.loc.space) {
        Some(CmpOperand::Mem(vn.loc.offset))
    } else {
        None
    }
}
