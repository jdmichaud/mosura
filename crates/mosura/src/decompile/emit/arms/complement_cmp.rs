//! `compare-form=complement` — a strict/non-strict compare whose ORIGINAL the compiler spelled
//! through the complemented condition prints complemented (the `!(a < b)` forms), so the
//! recompile reproduces the original's jump sense; per function under the `compare-form` choice,
//! or per site by witness (`recovered.complement_sites`, from
//! `buildconfig::complement_compares_from_evidence` — one of the text-parsing witnesses, R3b). A
//! target-informed emit choice, NOT Ghidra: the reference decompiler prints the direct compare.
//!
//! Moved verbatim out of printc.rs (review R2b, commit 2): the site reader (`compare_site`, whose
//! `compare_sites` report is the survey's evidence and travels with it), the complemented
//! rendering (`complemented_cmp`) and the consult that sat inline at the head of `cmp_bin`; the
//! only textual changes are `self.` → `pr.`, the sibling calls, the answer form (`return` →
//! `return Some`) and the function-wide flag's path (the arm's own State).
//!
//! The arm answers ONE seam, `ValueSite::Compare` — a `<`/`<=` the port is about to render: it
//! reports every compare site (evidence) and renders the gated or witnessed ones complemented;
//! `None` = the port's own compare rendering.
use crate::decompile::emit::{CompareForm, EmitChoices};
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::{render_const, PrintC};
use crate::decompile::types::Datatype;
use crate::decompile::varnode::VarnodeId;

/// The arm's state: its configuration (the witness, `recovered.complement_sites`, is the port's).
#[derive(Debug, Default)]
pub(crate) struct State {
    /// `compare-form=complement` is on for the whole function.
    pub(crate) complement: bool,
}

impl State {
    pub(crate) fn new(choices: &EmitChoices) -> Self {
        State { complement: choices.compare_form == CompareForm::Complement }
    }
}

/// The arm's answer at `ValueSite::Compare`: `op` the compare, `strict` its kind, `prec` the
/// port's precedence for it.
pub(crate) fn render(pr: &mut PrintC<'_>, op: OpId, strict: bool, prec: u8) -> Option<(String, u8)> {
    let site = compare_site(pr, op, strict);
    if let Some(site) = site {
        pr.report.compare_sites.push(site);
    }
    let recovered_here =
        site.is_some_and(|(pc, _, _)| pr.recovered.complement_sites.contains(&pc));
    if pr.arms.complement_cmp.complement || recovered_here {
        if let Some(r) = complemented_cmp(pr, op, strict) {
            return Some((r, prec));
        }
    }
    None
}

/// `(instruction address, our constant, complemented constant)` for a comparison the
/// `compare-form` axis could rewrite — the same gate as [`Self::complemented_cmp`],
/// reporting the two spellings instead of rendering one. See [`EmitReport::compare_sites`].
fn compare_site(pr: &mut PrintC<'_>, op: crate::decompile::op::OpId, strict: bool) -> Option<(u64, u64, u64)> {
    let o = pr.f.op(op);
    let pc = o.seqnum.pc.offset;
    let signed = matches!(o.code(), OpCode::IntSless | OpCode::IntSlessequal);
    let cslot = if pr.f.vn(o.input(1)?).is_constant() {
        1usize
    } else if pr.f.vn(o.input(0)?).is_constant() {
        0usize
    } else {
        return None;
    };
    let cvn = o.input(cslot)?;
    if pr.get_input_cast(op, cslot).is_some() {
        return None;
    }
    let size = pr.f.vn(cvn).size;
    let bits = u64::from(size) * 8;
    let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
    let c = pr.f.vn(cvn).constant_value() & mask;
    let dec = (cslot == 1) == strict;
    let adj = if dec { c.wrapping_sub(1) } else { c.wrapping_add(1) } & mask;
    let valid = if signed {
        let smin = 1u64 << (bits - 1);
        if dec { c != smin } else { c != smin - 1 }
    } else if dec {
        c != 0
    } else {
        c != mask
    };
    valid.then_some((pc, c, adj))
}

fn complemented_cmp(pr: &mut PrintC<'_>, op: crate::decompile::op::OpId, strict: bool) -> Option<String> {
    let prec = 10u8;
    let o = pr.f.op(op);
    let signed = matches!(o.code(), OpCode::IntSless | OpCode::IntSlessequal);
    let (cslot, vslot) = if pr.f.vn(o.input(1)?).is_constant() {
        (1usize, 0usize)
    } else if pr.f.vn(o.input(0)?).is_constant() {
        (0usize, 1usize)
    } else {
        return None;
    };
    let cvn = o.input(cslot)?;
    if pr.get_input_cast(op, cslot).is_some() {
        return None; // a required cast on the constant is not reproducible on the adjusted literal
    }
    if !matches!(pr.type_of(cvn), Datatype::Int(_) | Datatype::Uint(_) | Datatype::Unknown(_) | Datatype::Bool)
    {
        return None;
    }
    let size = pr.f.vn(cvn).size;
    let bits = u64::from(size) * 8;
    let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
    let c = pr.f.vn(cvn).constant_value() & mask;
    // `x < c` -> `x <= c-1` and `c <= x` -> `c-1 < x` decrement; the other two increment.
    let dec = (cslot == 1) == strict;
    let adj = if dec { c.wrapping_sub(1) } else { c.wrapping_add(1) } & mask;
    // no wrap at the bound, at the constant's own width and signedness
    let valid = if signed {
        let smin = 1u64 << (bits - 1);
        let smax = smin - 1;
        if dec { c != smin } else { c != smax }
    } else if dec {
        c != 0
    } else {
        c != mask
    };
    if !valid {
        return None;
    }
    // the adjusted literal at the compare's OWN signedness: an unsigned compare's bound is a
    // non-negative value whatever its top bit (`0x7f < x` on a byte complements to `0x80 <= x`,
    // never `-0x80 <= x` — which this compiler encodes as the sign-extended imm8 and so compares
    // a different value: WAR2 FUN_00041a6c's `CMP EAX,0x80`)
    let lit = if signed { render_const(adj, size) } else { format!("0x{adj:x}") };
    let other = pr.cast_operand(op, vslot, prec, cslot == 0);
    let sym = if strict { "<=" } else { "<" };
    Some(if cslot == 1 { format!("{other} {sym} {lit}") } else { format!("{lit} {sym} {other}") })
}
