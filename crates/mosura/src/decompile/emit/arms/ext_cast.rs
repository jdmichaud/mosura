//! `ext-cast=promotion` — the Watcom-32 emitter's rendering of an integer extension: C's own
//! integer promotion widens a narrow-typed operand, so the extension prints BARE where that
//! promotion is the extension and as a CAST where it is not. Moved out of printc.rs (2026-09-03,
//! the EXACT push — docs/exact-arms.md): the `promotion` value of the `ext-cast` axis sat inline
//! in the port's IntZext/IntSext branches, self-labelled an emission arm; this is the seam it
//! belongs behind. The reference renderings (`ext-cast=ghidra`, `hide-wide`) stay the port's —
//! `PrintC::opIntZext`/`opIntSext` with `isExtensionCastImplied` (printc.cc:786, cast.cc:249).
//!
//! The rules, each measured on the WAR2 corpus:
//! - a zero-extension TO int width prints bare for a NARROW-TYPED operand (a declared variable or
//!   parameter, a load, a cast, a boolean, a mask, a right shift, a call result under its
//!   `extern int`), which C's promotion widens faithfully; it keeps a `(uintN)` cast over
//!   OVERFLOWING arithmetic (add, subtract, multiply, shift left, negate, divide), whose narrow IR
//!   width is Ghidra's subvariable narrowing of a 32-bit computation the original truncates
//!   (`(cond) + 0xbf8` masked with `AND EAX,0xffff`, FUN_0004a194); casting a call result
//!   measured −0.23 on one function, so it is bare;
//! - a zero-extension BELOW int width (`(uint2)byte`, the IR's 16-bit arithmetic) prints bare —
//!   this compiler widens into the full register and computes at 32 bits — unless the original's
//!   own widening at the site is the 16-bit idiom (`XOR AH,AH`), when the port's cast stands:
//!   the witness is `recovered.ext_cast.sites` (`buildconfig::narrow_zexts_from_evidence`
//!   over this arm's `narrow_zext_candidates` report); the cast everywhere measured −3/+1 EXACT;
//! - a sign-extension prints `(intN)` over its operand re-signed at the operand's own width
//!   (`(int4)(int2)x`) unless the operand's C type is already that signed type: an unsigned,
//!   unknown, bool or `char` operand (Watcom's plain `char` is unsigned), an arithmetic or call
//!   operand (an `int` expression in C whatever the IR width), or a partial-symbol accessor (the
//!   emitter makes `x._2_2_` compilable as an unsigned deref) would ZERO-extend in C where the
//!   IR and the original's `MOVSX` sign-extend — wrong code in the split-point family.
//!
//! The arm answers ONE seam, `ValueSite::Extension`, only under `ext-cast=promotion`; `None` =
//! the port's own rendering. An extension PAST int width is the port's target rule for
//! undeclarable wide integers (it answers first) and never reaches here.
use crate::decompile::emit::{EmitChoices, ExtCast};
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;
use crate::decompile::types::Datatype;
use crate::decompile::varnode::VarnodeId;

/// The arm's state: its configuration.
#[derive(Debug, Default)]
pub(crate) struct State {
    /// `ext-cast=promotion` is on for this function.
    pub(crate) promotion: bool,
}

impl State {
    pub(crate) fn new(choices: &EmitChoices) -> Self {
        State { promotion: choices.ext_cast == ExtCast::Promotion }
    }
}

/// The arm's answer at `ValueSite::Extension`: `op` the INT_ZEXT (`signed` false) or INT_SEXT.
pub(crate) fn render(pr: &mut PrintC<'_>, op: OpId, signed: bool) -> Option<(String, u8)> {
    if !pr.arms.ext_cast.promotion {
        return None;
    }
    let o = pr.f.op(op);
    let (in0, out) = (o.input(0)?, o.output?);
    let (insize, outsize) = (pr.f.vn(in0).size, pr.f.vn(out).size);
    let int = pr.f.size_of_int();
    if outsize > int {
        return None;
    }
    if !signed {
        if outsize >= int {
            if narrow_typed_operand(pr, in0) {
                // the 16-BIT widening of a byte: `XOR AH,AH ; MOV AL,..` paired in the original
                // (this compiler zero-extends a byte to 16 bits when the value is consumed
                // at 16 bits — a short global's store, WAR2 FUN_000207b8 EXACT with `(uint2)x`;
                // 21 functions carry the pair against the recompile's `XOR EAX,EAX` on round
                // f4). The cast is the identity on a zero-extended byte. Witnessed by the
                // PAIR (`buildconfig::narrow_zexts_from_evidence`, the int-width arm), never
                // by a lone high-byte zero — round e24's lone-zero spelling reached 131 TUs.
                if insize == 1 {
                    let pc = o.seqnum.pc.offset;
                    pr.report.ext_cast.candidates.push((pc, insize, outsize));
                    if pr.recovered.ext_cast.sites.contains(&pc) {
                        let operand = pr.operand(in0, 14, false);
                        return Some((format!("({}){operand}", Datatype::Uint(2).name()), 14));
                    }
                }
                return Some(pr.render_var(in0));
            }
            let operand = pr.operand(in0, 14, false);
            return Some((format!("({}){operand}", Datatype::Uint(insize).name()), 14));
        }
        let pc = o.seqnum.pc.offset;
        pr.report.ext_cast.candidates.push((pc, insize, outsize));
        if !pr.recovered.ext_cast.sites.contains(&pc) {
            return Some(pr.render_var(in0));
        }
        return None; // witnessed: the port's own `(uint2)x` cast
    }
    let inty = pr.type_of(in0);
    let operand = pr.cast_operand(op, 0, 14, false);
    let accessor = pr.is_partial_symbol(in0);
    let inner = if matches!(inty, Datatype::Int(sz) if sz == insize) && narrow_typed_operand(pr, in0) && !accessor {
        String::new()
    } else {
        format!("(int{insize})")
    };
    Some((format!("(int{outsize}){inner}{operand}"), 14))
}

/// Does `v` render as an expression C's own promotion widens faithfully — a declared variable or
/// parameter, a load, a cast, a boolean, a mask or right shift (nothing above the narrow width
/// can appear), a call result (`int` under its `extern int`)? The exceptions are the OVERFLOWING
/// arithmetic ops, whose narrow IR width is Ghidra's subvariable narrowing of a 32-bit
/// computation the original truncates: printed bare they compute at int width and skip the
/// truncation.
fn narrow_typed_operand(pr: &PrintC<'_>, v: VarnodeId) -> bool {
    if pr.f.vn(v).is_constant() {
        return false;
    }
    if pr.is_explicit(v) {
        return true;
    }
    let Some(d) = pr.f.vn(v).def else { return true };
    match pr.f.op(d).code() {
        OpCode::IntAdd
        | OpCode::IntSub
        | OpCode::IntMult
        | OpCode::IntLeft
        | OpCode::IntNegate
        | OpCode::Int2comp
        | OpCode::IntDiv
        | OpCode::IntSdiv
        | OpCode::IntRem
        | OpCode::IntSrem => false,
        OpCode::Copy => pr.f.op(d).input(0).is_none_or(|x| narrow_typed_operand(pr, x)),
        _ => true,
    }
}

/// The ext-cast's candidates the report pass collects (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Every zero-extension NARROWER than int (`(uint2)byte`, the IR's 16-bit arithmetic) the
    /// `ext-cast=promotion` arm would print bare, as `(instruction address, in size, out size)`.
    /// The IR's 2-byte ZEXT does not say how the compiler widened: this one zero-extends into
    /// the full register (`XOR EDX,EDX ; MOV DL,..`, and computes at 32 bits) unless the source
    /// pinned the 16-bit width, when it zeroes only the high byte (`XOR AH,AH ; MOV AL,..`,
    /// WAR2 FUN_00019344's `(ushort)byte * 2`). A target rule reads which idiom the original used
    /// at the site and keeps the cast only for the 16-bit one (`narrow_zexts_from_evidence`);
    /// printing it everywhere measured −3 EXACT / +1 (round e1, 2026-09-03).
    pub candidates: Vec<(u64, u32, u32)>,
}

/// The ext-cast's witnessed decisions the recovered pass renders (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Sites {
    /// Sub-int zero-extension sites (`narrow_zext_candidates`) whose original widens with the
    /// 16-bit idiom (`XOR xH,xH`): the `ext-cast=promotion` arm keeps the `(uint2)` cast there.
    pub sites: std::collections::HashSet<u64>,
}
