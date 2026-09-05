//! `array-index=spelled` — a scaled-index pointer temp `piVar = (T *)(idx*sizeof(T) + base)`
//! (base a constant/global) whose only uses are derefs is inlined, each deref rendering
//! `((T *)base)[idx]`, so Watcom addresses the access with a scaled-index operand; per witnessed
//! access set (`recovered.array_index.sites`, from `buildconfig::array_index_sites_from_evidence`,
//! over this arm's `array_index_candidates` report — the original either uses `[reg*sz + base]`
//! or keeps the address in a register, a codegen lottery the witness settles per site). A
//! target-informed emit choice, NOT Ghidra: the reference decompiler prints the temp and `*piVar`.
//!
//! Moved verbatim out of printc.rs (review R2b, commit 6): the census that sat in
//! `print_c_inner`'s arm setup (`recognize`: the temps and the suppression of their assignments)
//! and the subscript consult at the head of `render_mem` (`render`); the only textual changes are
//! `p.`/`self.` → `pr.`, the temps' path (the arm's own State — `array_index_temps` was a PrintC
//! field only this rule read) and the answer form (`return (..)` → `return Some((..))`). The
//! unread `array_index_spelled` flag (initialized, never consulted) is dropped.
//!
//! The arm answers ONE seam, `ValueSite::Deref` — the address `render_mem` is about to
//! dereference: `Some` renders the subscript, `None` = the port's own deref rendering.
use crate::decompile::emit::{ArrayIndex, EmitChoices};
use crate::decompile::op::OpId;
use crate::decompile::funcdata::Funcdata;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;
use crate::decompile::types::Datatype;
use crate::decompile::varnode::VarnodeId;
use std::collections::HashMap;

/// The arm's state: the inlined temps (`temp varnode → (base, index, pointee type)`), recorded
/// by `recognize` and read at every deref.
#[derive(Debug, Default)]
pub(crate) struct State {
    pub(crate) temps: HashMap<VarnodeId, (VarnodeId, VarnodeId, Datatype)>,
}

impl State {
    pub(crate) fn new(_choices: &EmitChoices) -> Self {
        State::default()
    }
}

/// The census (arm setup, called from `print_c_inner` where it sat): record every candidate
/// access (survey evidence), inline the witnessed temps.
pub(crate) fn recognize(pr: &mut PrintC<'_>, f: &Funcdata, choices: &EmitChoices) {
    if choices.array_index == ArrayIndex::Spelled {
        for op in f.op_ids() {
            let o = f.op(op);
            if o.is_dead() || !matches!(o.code(), OpCode::Cast | OpCode::Copy) {
                continue;
            }
            let (Some(out), Some(inp)) = (o.output, o.input(0)) else { continue };
            // the pointee type of the temp (the `(int2 *)` cast) and its size = the scale
            let Datatype::Pointer(_, pointee) = f.vn(out).get_type() else { continue };
            let elem = pointee.size();
            if elem == 0 {
                continue;
            }
            // input must be INT_ADD(scaled_index(elem), const/global base), either order
            let Some(d) = f.vn(inp).def else { continue };
            let add = f.op(d);
            if add.code() != OpCode::IntAdd || add.num_inputs() != 2 {
                continue;
            }
            let (a, b) = (add.input(0).unwrap(), add.input(1).unwrap());
            let pick = |base: VarnodeId, off: VarnodeId| -> Option<(VarnodeId, VarnodeId)> {
                let base_ok = f.vn(base).is_constant()
                    || Some(f.vn(base).loc.space) == f.spaces.by_name("ram");
                if !base_ok {
                    return None;
                }
                let od = f.vn(off).def?;
                let oo = f.op(od);
                if oo.code() == OpCode::IntMult
                    && oo.input(1).is_some_and(|c| f.vn(c).is_constant() && f.vn(c).constant_value() == elem as u64)
                {
                    return Some((base, oo.input(0)?));
                }
                None
            };
            let Some((base, idx)) = pick(a, b).or_else(|| pick(b, a)) else { continue };
            let _ = idx;
            // Every use must be a LOAD/STORE deref at width == elem, collecting the access pcs.
            let uses: Vec<OpId> = f.vn(out).descend.iter().copied().filter(|&u| !f.op(u).is_dead()).collect();
            if uses.is_empty() {
                continue;
            }
            let mut pcs: Vec<u64> = Vec::new();
            let all_deref = uses.iter().all(|&u| {
                let uo = f.op(u);
                let ok = match uo.code() {
                    OpCode::Load => uo.input(1) == Some(out) && uo.output.is_some_and(|v| f.vn(v).size == elem),
                    OpCode::Store => uo.input(1) == Some(out) && uo.input(2).is_some_and(|v| f.vn(v).size == elem),
                    _ => false,
                };
                if ok {
                    pcs.push(uo.seqnum.pc.offset);
                }
                ok
            });
            if !all_deref {
                continue;
            }
            // N3 WITNESS (wc2src-reconciliation-3, reviewer's steer — witnessed from the first
            // round, not blanket-then-gate): the subscript form is value-identical to the pointer
            // arithmetic but is a Watcom-codegen LOTTERY — the original either addresses the access
            // with a scaled-index operand (`[reg*sz + base]` → spell the subscript) or keeps the
            // address in a register (`SHL`/`ADD` then `[reg]` → keep the arithmetic). Record each
            // access pc as a candidate; inline only when EVERY deref is witnessed (the recovered
            // set is empty on the report pass, so this records there and applies on the final one).
            for &pc in &pcs {
                pr.report.array_index.candidates.push((pc, elem));
            }
            if !pcs.iter().all(|pc| pr.recovered.array_index.sites.contains(pc)) {
                continue;
            }
            pr.arms.array_index.temps.insert(out, (base, idx, (*pointee).clone()));
            pr.suppressed.insert(op); // the `piVar = (T *)(...)` assignment is inlined
        }
    }
}

/// The arm's answer at `ValueSite::Deref`: `addr` the address `render_mem` dereferences.
pub(crate) fn render(pr: &mut PrintC<'_>, addr: VarnodeId) -> Option<(String, u8)> {
    if let Some((base, idx, pointee)) = pr.arms.array_index.temps.get(&addr).cloned() {
        let bs = pr.operand(base, 14, false);
        let i = pr.render_var(idx).0;
        return Some((format!("(({} *){bs})[{i}]", pointee.name()), 16));
    }
    None
}

/// The array-index's candidates the report pass collects (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// N3 (array-index): scaled-index accesses through a constant/global base — `(deref pc,
    /// element size)` per access. The witness (`buildconfig::array_index_sites_from_evidence`)
    /// keeps only pcs where the ORIGINAL uses a scaled-index operand `[reg*sz + base]`.
    pub candidates: Vec<(u64, u32)>,
}

/// The array-index's witnessed decisions the recovered pass renders (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Sites {
    /// N3 access pcs to spell as subscripts — witnessed by the original's scaled-index operand.
    pub sites: std::collections::HashSet<u64>,
}
