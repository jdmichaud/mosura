//! `frame-fill=aggregate` — a frame the original opens with `SUB ESP,n` but whose recovered
//! locals total a few bytes declares as ONE byte aggregate at the frame bottom, every slot a field
//! at its byte offset (docs/frame-fill-arm.md, W4 frame half; fable-b's srcform12 form). A
//! target-informed emit choice, NOT Ghidra: the reference decompiler declares the recovered
//! scalars, and the recompile loses the frame.
//!
//! Moved verbatim out of printc.rs (review R2, commit 4): the aggregate ([`FrameAgg`]), the gate
//! that ran inline in print_c_inner ([`recognize`], arm setup: a witnessed prologue frame, an
//! escaping local inside it, >= 32 bytes of slack), the field renderer ([`frame_field`]) and the
//! six inline consults of `frame_agg` — five value renderings and one declaration — which are now
//! the arm's answers at the value-render chokepoint ([`render_value`]) and at the declarations
//! seam ([`declare_slot`]). The only textual change in the moved code is `self.` → `pr.`.
//!
//! The arm answers TWO seams. `ValueSite`: `SlotPiece` (a piece of a covered slot is its field,
//! never `<field expr>._off_size_` — 0x66100, seam 6), `SlotName` (an element or split-pair piece
//! of a swallowed symbol is the field at its slot — 0x4e06e's `aiStack_2c[0]`, seam 4),
//! `SlotOffset` (a slot by frame offset), `SlotAddress` (an address inside the frame is
//! `(T *)(base + delta)`, a value `*(T *)(base + delta)`), `FusedStore` (the coalesced whole-symbol
//! store writes the field). And the DECLARATIONS seam: a slot inside the frame declares the ONE
//! aggregate instead of itself — it cannot be pre-computed at setup (any offset of the frame may be
//! declared, on first use), so it is an explicit seam, never an inline consult.
use crate::decompile::emit::arms::ValueSite;
use crate::decompile::emit::EmitChoices;
use crate::decompile::funcdata::Funcdata;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::{render_const_typed, PrintC};
use crate::decompile::types::Datatype;
use crate::decompile::varnode::VarnodeId;

/// The precedence a slot rendering reports: nominal — the port's slot callers take the text (a
/// name, a field, a statement), only the `OpRoot` answerers' precedence is read.
const NOMINAL: u8 = 14;

#[derive(Clone, Debug)]
pub(crate) struct FrameAgg {
    pub(crate) bottom: i64,
    pub(crate) top: i64,
    pub(crate) size: u32,
    pub(crate) name: String,
}

impl FrameAgg {
    pub(crate) fn covers(&self, off: i64) -> bool {
        off >= self.bottom && off < self.top
    }
}

/// The gate, run once when the printer is built (arm setup): witnessed prologue frame, an escaping
/// local (the alias boundary exists) and >= 32 bytes of slack between the frame and the recovered
/// locals inside it → the one aggregate the frame's stack symbols render through.
pub(crate) fn recognize(p: &mut PrintC<'_>, f: &Funcdata, choices: &EmitChoices) {
// frame-fill=aggregate: witnessed prologue frame, an escaping local (the alias boundary exists),
// and >= 32 bytes of slack between the frame and the recovered locals inside it.
if choices.frame_fill == crate::decompile::emit::FrameFill::Aggregate {
    if std::env::var_os("MOSURA_FRAME_DEBUG").is_some() {
        let declared: i64 = p.stack_syms.iter().map(|s| s.size as i64).sum();
        eprintln!("[frame-fill] {:#x}: witness={:?} alias_boundary={:?} stack_syms={} declared={} syms={:?}",
            f.addr.offset, p.recovered.frame_fill, f.alias_boundary, p.stack_syms.len(), declared,
            p.stack_syms.iter().map(|s| (s.start, s.size)).collect::<Vec<_>>());
    }
    if let (Some((frame, pushes)), Some(ab)) = (p.recovered.frame_fill, f.alias_boundary) {
        let top = -(4 * pushes as i64);
        let bottom = top - frame as i64;
        // the escaping local must lie INSIDE the frame: an alias boundary below it is the
        // pushed-argument slots of a stack-convention call (0x45ba0: `aiStack_54` under a 0x50
        // frame), whose five scalars then lost their registers to a needless aggregate
        let boundary = p.frame_off(ab as u64);
        if boundary < bottom {
            if std::env::var_os("MOSURA_FRAME_DEBUG").is_some() {
                eprintln!("[frame-fill] {:#x}: alias boundary {boundary:#x} below the frame bottom {bottom:#x} — declined", f.addr.offset);
            }
        } else {
        // the slack is against the symbols the C will DECLARE — those some live stack varnode or
        // PTRSUB offset references — not the recovered scope's full extent: the lookup that sizes
        // an indexed array to the frame leaves an unreferenced frame-sized symbol behind
        // (0x2dc74: 207 of 208 bytes "declared" by a symbol no statement ever touches).
        let referenced: std::collections::HashSet<i64> = {
            let mut set = std::collections::HashSet::new();
            let stk = p.stack_space;
            for i in 0..f.num_varnodes() as u32 {
                let vn = f.vn(VarnodeId(i));
                if Some(vn.loc.space) == stk && (vn.is_written() || vn.is_input() || !vn.descend.is_empty()) {
                    set.insert(p.frame_off(vn.loc.offset));
                }
            }
            for op in f.op_ids() {
                let o = f.op(op);
                if !o.is_dead() && o.code() == OpCode::Ptrsub {
                    if let (Some(b), Some(k)) = (o.input(0), o.input(1)) {
                        if f.vn(b).is_spacebase() && !f.vn(b).is_constant() && f.vn(k).is_constant() {
                            set.insert(p.frame_off(f.vn(k).constant_value()));
                        }
                    }
                }
            }
            set
        };
        let declared: i64 = p
            .stack_syms
            .iter()
            .filter(|s| s.start >= bottom && s.start < top && referenced.iter().any(|&r| r >= s.start && r < s.start + s.size as i64))
            .map(|s| s.size as i64)
            .sum();
        if std::env::var_os("MOSURA_FRAME_DEBUG").is_some() {
            eprintln!("[frame-fill] {:#x}: referenced-declared={declared} slack={}", f.addr.offset, frame as i64 - declared);
        }
        if frame > 0 && frame as i64 - declared >= 32 {
            let ty = Datatype::Array(Box::new(Datatype::Unknown(1)), frame as u64);
            let name = p.stack_slot_name(bottom, &ty);
            p.frame_agg = Some(FrameAgg { bottom, top, size: frame, name });
        }
        }
    }
}
}

/// frame-fill=aggregate: the field expression for the frame slot at `off` holding a `ty` value —
/// `base[delta]` for a byte, `*(T *)(base + delta)` otherwise (fable-b's srcform12 form).
fn frame_field(pr: &mut PrintC<'_>, agg: &FrameAgg, off: i64, ty: &Datatype) -> String {
    pr.declare_stack(off, "", Datatype::Unknown(1));
    let delta = off - agg.bottom;
    let base = if delta == 0 { agg.name.clone() } else { format!("{} + {}", agg.name, render_const_typed(delta as u64, 4, false)) };
    if ty.size() == 1 {
        if delta == 0 { format!("{}[0]", agg.name) } else { format!("{}[{}]", agg.name, render_const_typed(delta as u64, 4, false)) }
    } else if delta == 0 {
        format!("*({} *){}", ty.name(), agg.name)
    } else {
        format!("*({} *)({base})", ty.name())
    }
}

/// The value-render answers (see the module doc): `None` = not a covered slot, the port renders it.
pub(crate) fn render_value(pr: &mut PrintC<'_>, site: &ValueSite<'_>) -> Option<(String, u8)> {
    match *site {
        ValueSite::SlotPiece { base, off, v } => {
// frame-fill=aggregate (seam 6): a piece of a slot the aggregate covers is the field at
// `base offset + off` with the piece's own type — never `<field expr>._off_size_`
// (0x66100: `*(uint4 *)(axStack_534 + 0x510)._1_1_`, COMPILE_FAIL E1032)
if let Some(agg) = pr.frame_agg.clone() {
    let bvn = pr.f.vn(base);
    let boff = if Some(bvn.loc.space) == pr.stack_space {
        Some(pr.frame_off(bvn.loc.offset))
    } else {
        pr.high_stack_off.get(&pr.high_of[base.0 as usize]).map(|&o| pr.frame_off(o))
    };
    if let Some(bo) = boff {
        if agg.covers(bo) {
            let pty = pr.type_of(v);
            return Some((frame_field(pr, &agg, bo + off as i64, &pty), NOMINAL));
        }
    }
}
            None
        }
        ValueSite::SlotName { id, foff, sym, ty } => {
// frame-fill=aggregate: an element or a split-pair piece of a swallowed symbol is
// the field at its slot (0x4e06e's `aiStack_2c[0]` read the symbol by name after
// the aggregate had taken its declaration — COMPILE_FAIL E1011 in probe w4bp)
if let Some(agg) = pr.frame_agg.clone() {
    if agg.covers(foff) {
        let fty = sym.array_index(foff).map(|(e, _)| e).unwrap_or_else(|| ty.clone());
        let field = frame_field(pr, &agg, foff, &fty);
        pr.names.insert(id, field.clone());
        return Some((field, NOMINAL));
    }
}
            None
        }
        ValueSite::SlotOffset { off, ty } => {
if let Some(agg) = pr.frame_agg.clone() {
    if agg.covers(off) {
        return Some((frame_field(pr, &agg, off, ty), NOMINAL));
    }
}
            None
        }
        ValueSite::SlotAddress { off, deref } => {
// frame-fill=aggregate: an address inside the frame is `(T *)(base + delta)` (`base` itself for
// the byte aggregate's own bottom), an element/value `*(T *)(base + delta)` — T from the
// recovered symbol (its element type for an array), the W1 cast rule on the pointer.
if let Some(agg) = pr.frame_agg.clone() {
    if agg.covers(off) {
        let ty = match pr.spacebase_sym_at(off) {
            Some(sym) => sym.array_index(off).map(|(e, _)| e).unwrap_or(sym.ty.clone()),
            None => Datatype::Unknown(1),
        };
        if deref {
            return Some((frame_field(pr, &agg, off, &ty), NOMINAL));
        }
        pr.declare_stack(off, "", Datatype::Unknown(1));
        let delta = off - agg.bottom;
        let addr = if delta == 0 { agg.name.clone() } else { format!("{} + {}", agg.name, render_const_typed(delta as u64, 4, false)) };
        return Some((if ty.size() == 1 { addr } else if delta == 0 { format!("({} *){}", ty.name(), agg.name) } else { format!("({} *)({addr})", ty.name()) }, NOMINAL));
    }
}
            None
        }
        ValueSite::FusedStore { sym, src } => {
// frame-fill=aggregate: the fused whole-symbol store writes the field at its slot
if let Some(agg) = pr.frame_agg.clone() {
    if agg.covers(sym.start) {
        let sty = pr.type_of(src);
        let lhs = frame_field(pr, &agg, sym.start, &sty);
        let rhs = pr.render_var(src).0;
        return Some((format!("{lhs} = {rhs}"), NOMINAL));
    }
}
            None
        }
        ValueSite::OpRoot { .. } => None,
    }
}

/// The declarations seam: a slot inside the frame declares the ONE aggregate (once) instead of
/// itself; `true` = declared here, the port declares nothing.
pub(crate) fn declare_slot(pr: &mut PrintC<'_>, start: i64) -> bool {
// frame-fill=aggregate: a slot inside the frame declares the ONE aggregate instead
if let Some(agg) = pr.frame_agg.clone() {
    if agg.covers(start) {
        if pr.stack_declared.insert(agg.bottom) {
            pr.decls.push((agg.name, Datatype::Array(Box::new(Datatype::Unknown(1)), agg.size as u64), Some(agg.bottom)));
        }
        return true;
    }
}
    false
}
