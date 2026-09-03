//! `struct-return=witness` — a function whose slot-0 parameter is a HIDDEN RETURN POINTER (only
//! stored through inside `[0, N)`, returned unchanged: `analysis::sret::sret_shape`) prints as the
//! struct-returning C function the source wrote, and a call to such a callee prints
//! `local = f(..)` (docs/struct-return-arm.md). A target-informed emit choice, NOT Ghidra: the
//! reference decompiler recovers `void f(undefined4 *param_1, ..)` from these bytes, and with the
//! return type locked it prints the pointer as an explicit parameter and returns it
//! (`pt * mk(pt *rethidden, int4 a, int4 b) { ..; return rethidden; }`, the oracle traces in
//! docs/ground-truth-findings.md) — neither compiles to the callee-pop `ret $4` a cdecl caller
//! expects. The witness is `recompile::recovery::struct_return`: the callee's own `ret $4`, or
//! every known call site dropping the returned pointer and passing a local's address.
//!
//! The DEFINITION half: `struct sN f(args minus slot 0) { struct sN __ret; __ret.f<off> = ..;
//! return __ret; }` — the signature through the declarations family's fourth seam
//! ([`signature`]: the preamble `struct sN { .. };`, the return type, the dropped parameter),
//! `__ret` through the port's `decls` service, every store through the hidden pointer at
//! `ValueSite::Deref` (a field write), the returned pointer at `ValueSite::Var`.
//!
//! The CALLER half: a call whose callee is witnessed (`CallSpec::sret`, copied by the prototype
//! pass), whose returned pointer is dead and whose slot-0 argument is the address of a stack
//! local prints `local = f(args minus slot 0)` at `ValueSite::OpRoot`; the local is declared ONCE
//! as the struct (`declare_slot`, ahead of frame-fill) and every slot inside it renders as its
//! field (`SlotName`/`SlotOffset`/`SlotAddress`, ahead of frame-fill). THE DECLINE RULE: when
//! frame-fill's aggregate (its SETUP state, `arms.frame_fill.agg`) covers the local, this arm
//! declares nothing and answers no slot inside it — the call then renders
//! `*(struct sN *)<the port's address text> = f(..)`, a write within the one aggregate object.
//!
//! Field naming: `f<off>` with the STORED type, gaps `uint1 pad<off>[n]` (`analysis::sret::
//! struct_declaration`); the layout is the witness's; one `struct sN` declaration per layout per
//! function text, and the gt TU builder copies a callee's declaration into its callers' TUs.
//! A false positive of the caller-side witness (a pointer-filling `int *fill(int *p, ..) { ..;
//! return p; }` whose callers all drop the result) changes FORM, never values ONLY on an ABI that
//! returns the struct through the CALLER'S MEMORY — gcc's i386 memory return, the case this arm is
//! enabled for, where `local = fill(..)` performs the same stores into the same bytes. On a
//! register-return convention it is a behaviour change: measured on WAR2/Watcom, where small
//! structs come back in EAX, 9 functions carry the shape, NONE carries the callee-pop witness
//! (slot 0 is a register, so `on_stack` is never true) and the one callers-witness firing is an
//! out-parameter rewritten into a register return. Four of those nine are EXACT today, so widening
//! this witness aims at EXACT rows; and the survey's TU assembly declares every callee
//! `extern int func_0x...();`, so a struct-returning callee cannot even be called from another TU
//! there. The axis is off for Watcom (docs/struct-return-arm.md, "Measured on WAR2").
use crate::analysis::sret::{self, SretShape};
use crate::decompile::emit::arms::{Answer, Arm, Signature, Site, SiteKind, ValueSite};
use crate::decompile::emit::{EmitChoices, StructReturn};
use crate::decompile::funcdata::Funcdata;
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;
use crate::decompile::varnode::VarnodeId;
use std::collections::{HashMap, HashSet};

/// The precedence a slot rendering reports: nominal (the slot callers take the text).
const NOMINAL: u8 = 14;
/// The local the definition half returns.
const RET_NAME: &str = "__ret";

/// The arm's state (the state rule, R2 commit 7): the choice flag, the definition fact, the
/// witnessed calls, the typed locals the caller half declares.
#[derive(Debug, Default)]
pub(crate) struct State {
    pub(crate) witness: bool,
    pub(crate) def: Option<Def>,
    pub(crate) calls: HashMap<OpId, CallSite>,
    pub(crate) locals: Vec<Local>,
}

/// This function returns a struct through `hidden` (its slot-0 input varnode).
#[derive(Clone, Debug)]
pub(crate) struct Def {
    pub(crate) hidden: VarnodeId,
    pub(crate) shape: SretShape,
}

/// A call to a witnessed callee: the frame offset of the local whose address is slot 0, the
/// callee's shape, and whether this arm declares that local as the struct (else the cast form).
#[derive(Clone, Debug)]
pub(crate) struct CallSite {
    pub(crate) off: i64,
    pub(crate) shape: SretShape,
    pub(crate) typed_local: bool,
}

/// A stack local this arm declares as `struct sN <name>` at frame offset `off`.
#[derive(Clone, Debug)]
pub(crate) struct Local {
    pub(crate) off: i64,
    pub(crate) shape: SretShape,
    pub(crate) name: String,
}

impl Local {
    fn covers(&self, off: i64) -> bool {
        off >= self.off && off < self.off + self.shape.size as i64
    }
}

impl State {
    pub(crate) fn new(choices: &EmitChoices) -> Self {
        State { witness: choices.struct_return == StructReturn::Witness, ..Default::default() }
    }
}

/// The arm, as the [`super::ARMS`] table holds it: the RETURN statement site — a definition whose
/// RETURN carries no value (slot 0 is the untouched return register, the void form of "returned
/// unchanged") prints `return __ret`; a RETURN with a value renders it through the value seam.
pub const ARM: Arm = Arm {
    name: "struct-return: a hidden-return-pointer function as the struct-returning function (docs/struct-return-arm.md)",
    kinds: &[SiteKind::Return],
    try_emit,
};

fn try_emit(p: &mut PrintC<'_>, site: Site<'_>, _out: &mut String) -> Option<Answer> {
    let Site::Return { op } = site else { return None };
    if !p.arms.struct_return.witness || p.arms.struct_return.def.is_none() || p.f.op(op).num_inputs() > 1 {
        return None;
    }
    Some(Answer::Fused { stmt: format!("return {RET_NAME}"), members: vec![op] })
}

/// The decline rule, as a function of frame-fill's SETUP state: a local at `off` of `size` bytes
/// inside the frame aggregate is frame-fill's, not this arm's.
pub(crate) fn declined_by_frame_fill(agg: Option<&super::frame_fill::FrameAgg>, off: i64, size: u32) -> bool {
    agg.is_some_and(|a| a.covers(off) || a.covers(off + size as i64 - 1))
}

/// Arm setup (called after frame-fill's, whose aggregate the decline rule reads): the definition
/// fact and `__ret`'s declaration; the witnessed calls and their typed locals.
pub(crate) fn recognize(p: &mut PrintC<'_>, f: &Funcdata) {
    debug!(crate::debug::Topic::Args, "{:#x}: struct-return arm witness={} ret_pop={:?} callers={:?}", f.addr.offset, p.arms.struct_return.witness, f.ret_pop, f.sret_callers);
    if !p.arms.struct_return.witness {
        return;
    }
    if let Some(fact) = crate::recompile::recovery::struct_return(f) {
        if let Some(hidden) = crate::decompile::printc::rendered_param_slots(f).first().and_then(|s| s.vn) {
            p.decls.push((RET_NAME.to_string(), sret::struct_datatype(&fact.shape), None));
            p.arms.struct_return.def = Some(Def { hidden, shape: fact.shape });
        }
    }
    let mut calls: Vec<OpId> = f.call_specs.iter().filter(|(_, cs)| cs.sret.is_some()).map(|(&op, _)| op).collect();
    calls.sort();
    for call in calls {
        let o = f.op(call);
        if o.is_dead() || o.code() != OpCode::Call {
            continue;
        }
        let Some(shape) = f.call_specs[&call].sret.clone() else { continue };
        if !sret::call_evidence(f, call).supports_sret() {
            continue;
        }
        let Some(arg0) = o.input(1) else { continue };
        let Some(off) = sret::local_address_off(f, arg0) else { continue };
        let agg = p.arms.frame_fill.agg.clone();
        let mut typed_local = !declined_by_frame_fill(agg.as_ref(), off, shape.size);
        if typed_local {
            match p.arms.struct_return.locals.iter().find(|l| l.off == off) {
                Some(l) if l.shape.size != shape.size => typed_local = false, // two shapes on one local
                Some(_) => {}
                None => {
                    // the local's name: the recovered symbol starting there, else the port's stack form
                    let name = p
                        .spacebase_sym_at(off)
                        .filter(|s| s.start == off)
                        .map(|s| s.name)
                        .unwrap_or_else(|| if off < 0 { format!("sStack_{:x}", -off) } else { format!("sStack{:08x}", off) });
                    p.arms.struct_return.locals.push(Local { off, shape: shape.clone(), name });
                }
            }
        }
        debug!(crate::debug::Topic::Args, "{:#x}: struct-return call op={} local off={off:#x} typed_local={typed_local}", f.addr.offset, call.0);
        p.arms.struct_return.calls.insert(call, CallSite { off, shape, typed_local });
    }
}

/// The fourth declarations-family seam: the preamble (one `struct sN { .. };` per layout this
/// function text names), the return type of a definition, the hidden parameter to drop.
pub(crate) fn signature(p: &mut PrintC<'_>) -> Option<Signature> {
    let st = &p.arms.struct_return;
    if !st.witness {
        return None;
    }
    let mut preamble: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut add = |shape: &SretShape| {
        let d = sret::struct_declaration(shape);
        if seen.insert(d.clone()) {
            preamble.push(d);
        }
    };
    if let Some(def) = &st.def {
        add(&def.shape);
    }
    for l in &st.locals {
        add(&l.shape);
    }
    for c in st.calls.values() {
        add(&c.shape);
    }
    if preamble.is_empty() {
        return None;
    }
    Some(Signature {
        preamble,
        ret_ty: st.def.as_ref().map(|d| sret::struct_datatype(&d.shape).name()),
        drop: st.def.as_ref().map(|d| d.hidden),
    })
}

/// The declarations seam, ahead of frame-fill: a slot inside a typed local declares the ONE
/// struct local (once) instead of itself.
pub(crate) fn declare_slot(pr: &mut PrintC<'_>, start: i64) -> bool {
    let Some(l) = pr.arms.struct_return.locals.iter().find(|l| l.covers(start)).cloned() else { return false };
    if pr.stack_declared.insert(l.off) {
        pr.decls.push((l.name.clone(), sret::struct_datatype(&l.shape), Some(l.off)));
    }
    true
}

/// The value seam: the definition's pointer and field writes, the witnessed calls, the slots of
/// a typed local.
pub(crate) fn render_value(p: &mut PrintC<'_>, site: &ValueSite<'_>) -> Option<(String, u8)> {
    if !p.arms.struct_return.witness {
        return None;
    }
    match *site {
        ValueSite::Var { v } => {
            let def = p.arms.struct_return.def.as_ref()?;
            (v == def.hidden).then(|| (RET_NAME.to_string(), 16))
        }
        ValueSite::Deref { addr, .. } => {
            let def = p.arms.struct_return.def.clone()?;
            let disp = displacement(p.f, def.hidden, addr)?;
            let off = field_at(&def.shape, disp)?;
            Some((format!("{RET_NAME}.f{off}"), NOMINAL))
        }
        ValueSite::OpRoot { op } => render_call(p, op),
        ValueSite::SlotName { foff, .. } => slot_field(p, foff),
        ValueSite::SlotOffset { off, .. } => slot_field(p, off),
        ValueSite::SlotAddress { off, deref } => {
            let l = local_at(p, off)?;
            let k = field_at(&l.shape, (off - l.off) as u32)?;
            declare(p, &l);
            Some(if deref {
                (format!("{}.f{k}", l.name), NOMINAL)
            } else if off == l.off {
                (format!("&{}", l.name), NOMINAL)
            } else {
                (format!("&{}.f{k}", l.name), NOMINAL)
            })
        }
        _ => None,
    }
}

/// `local = func_0x<addr>(args minus slot 0)` for a witnessed call; the cast form when the local
/// is frame-fill's.
fn render_call(p: &mut PrintC<'_>, op: OpId) -> Option<(String, u8)> {
    let site = p.arms.struct_return.calls.get(&op)?.clone();
    let o = p.f.op(op).clone();
    let name = p.callee_name(op);
    let args: Vec<String> = (2..o.num_inputs()).map(|i| p.render_var(o.input(i).unwrap()).0).collect();
    let lhs = if site.typed_local {
        let l = local_at(p, site.off)?;
        declare(p, &l);
        l.name
    } else {
        let a = p.render_var(o.input(1)?).0;
        format!("*(struct {} *)({a})", sret::struct_tag(&site.shape))
    };
    Some((format!("{lhs} = {name}({})", args.join(", ")), 2))
}

fn slot_field(p: &mut PrintC<'_>, off: i64) -> Option<(String, u8)> {
    let l = local_at(p, off)?;
    let k = field_at(&l.shape, (off - l.off) as u32)?;
    declare(p, &l);
    Some((format!("{}.f{k}", l.name), NOMINAL))
}

fn local_at(p: &PrintC<'_>, off: i64) -> Option<Local> {
    p.arms.struct_return.locals.iter().find(|l| l.covers(off)).cloned()
}

fn declare(p: &mut PrintC<'_>, l: &Local) {
    // through the port's `declare_stack`, which asks the declarations seam first — `declare_slot`
    // above answers, so the struct local is declared exactly once
    p.declare_stack(l.off, &l.name, sret::struct_datatype(&l.shape));
}

/// The field starting exactly at `disp`, if any.
fn field_at(shape: &SretShape, disp: u32) -> Option<u32> {
    shape.fields.iter().find(|&&(off, _, _)| off == disp).map(|&(off, _, _)| off)
}

/// The constant displacement of `addr` from `hidden` through COPY/CAST, INT_ADD by a constant,
/// PTRADD by a constant index and PTRSUB by a constant — the walk `sret_shape` admitted, inverted.
fn displacement(f: &Funcdata, hidden: VarnodeId, addr: VarnodeId) -> Option<u32> {
    let mut v = addr;
    let mut disp: i64 = 0;
    for _ in 0..16 {
        if v == hidden {
            return (disp >= 0).then_some(disp as u32);
        }
        let def = f.vn(v).def?;
        let o = f.op(def);
        let c = |x: VarnodeId| -> Option<i64> {
            let vn = f.vn(x);
            vn.is_constant().then(|| {
                let bits = (vn.size * 8).min(64);
                let raw = vn.constant_value();
                if bits == 64 { raw as i64 } else { let m = 1u64 << (bits - 1); ((raw & ((1u64 << bits) - 1)) ^ m).wrapping_sub(m) as i64 }
            })
        };
        match o.code() {
            OpCode::Copy | OpCode::Cast => v = o.input(0)?,
            OpCode::IntAdd => {
                let (a, b) = (o.input(0)?, o.input(1)?);
                if let Some(k) = c(b) { disp += k; v = a; } else { disp += c(a)?; v = b; }
            }
            OpCode::Ptrsub => { disp += c(o.input(1)?)?; v = o.input(0)?; }
            OpCode::Ptradd => { disp += c(o.input(1)?)? * c(o.input(2)?)?; v = o.input(0)?; }
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The decline rule reads frame-fill's SETUP state: a local inside the aggregate is declined,
    /// one outside it (or with no aggregate) is this arm's.
    #[test]
    fn frame_fill_aggregate_declines_the_typed_local() {
        let agg = super::super::frame_fill::FrameAgg { bottom: -0x40, top: -0x10, size: 0x30, name: "auStack_40".into() };
        assert!(declined_by_frame_fill(Some(&agg), -0x14, 8), "inside the aggregate");
        assert!(declined_by_frame_fill(Some(&agg), -0x14, 4), "ends at the top");
        assert!(!declined_by_frame_fill(Some(&agg), -0x8, 8), "above the aggregate");
        assert!(!declined_by_frame_fill(None, -0x14, 8), "no aggregate");
    }
}
