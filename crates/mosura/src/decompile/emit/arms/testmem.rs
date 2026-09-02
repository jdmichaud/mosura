//! `testmem` — a masked narrow load feeding a zero-equality whose ORIGINAL tests memory directly at
//! int width (`TEST dword [..], imm`) prints its deref at int width: the mask keeps the value
//! identical and this compiler shrinks the wide masked test back to the original's byte TEST. A
//! target-informed emit choice, NOT Ghidra: the reference decompiler prints the load at the
//! varnode's size. Witness: `recovered.testmem_sites`, from `buildconfig::testmem_from_evidence`
//! (one of the text-parsing witnesses, R3b) over this arm's candidate report.
//!
//! Moved verbatim out of printc.rs (review R2b, commit 3): the candidate census that sat in
//! `print_c_inner`'s evidence section (`recognize`) and the width consult that sat inline in
//! `render_op_inner`'s `Load` arm (`render`); the only textual changes are `p.`/`self.` → `pr.`
//! and the answer form (the if-branch's value → `return Some`); the port keeps its own else
//! branch as the `None` path.
use crate::decompile::funcdata::Funcdata;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;
use crate::decompile::types::Datatype;
use crate::decompile::varnode::VarnodeId;

/// The census (survey evidence, `EmitReport::testmem_candidates`), called from `print_c_inner`'s
/// evidence section where it sat.
pub(crate) fn recognize(pr: &mut PrintC<'_>, f: &Funcdata) {
    // testmem candidates (see EmitReport::testmem_candidates): masked narrow loads feeding a
    // zero-equality — the shape whose original-instruction readout distinguishes an int-wide
    // source access from a narrow one.
    for opid in f.op_ids() {
        let o = f.op(opid);
        if o.is_dead() || o.code() != OpCode::Load {
            continue;
        }
        let Some(out) = o.output else { continue };
        if f.vn(out).size == 0 || f.vn(out).size >= f.size_of_int() {
            continue;
        }
        // the value, looked through a single ZEXT if present
        let mut val = out;
        let uses: Vec<_> = f.vn(val).descend.iter().copied().filter(|&u| !f.op(u).is_dead()).collect();
        if uses.len() == 1 && f.op(uses[0]).code() == OpCode::IntZext {
            if let Some(z) = f.op(uses[0]).output {
                val = z;
            }
        }
        let anduse: Vec<_> = f.vn(val).descend.iter().copied().filter(|&u| !f.op(u).is_dead()).collect();
        if anduse.len() != 1 || f.op(anduse[0]).code() != OpCode::IntAnd {
            continue;
        }
        let ao = f.op(anduse[0]);
        let narrow_bits = u64::from(f.vn(out).size) * 8;
        let narrow_mask = if narrow_bits >= 64 { u64::MAX } else { (1u64 << narrow_bits) - 1 };
        let const_fits = ao.input(1).is_some_and(|k| {
            f.vn(k).is_constant() && f.vn(k).constant_value() & !narrow_mask == 0
        });
        if !const_fits {
            continue;
        }
        let cmp0 = ao.output.is_some_and(|av| {
            f.vn(av).descend.iter().all(|&u| {
                let uo = f.op(u);
                matches!(uo.code(), OpCode::IntEqual | OpCode::IntNotequal)
                    && uo.input(1).is_some_and(|k| f.vn(k).is_constant() && f.vn(k).constant_value() == 0)
                    || uo.code() == OpCode::BoolNegate
            })
        });
        if !cmp0 {
            continue;
        }
        pr.report.testmem_candidates.push((out, o.seqnum.pc.offset));
    }
}

/// The arm's answer at `ValueSite::Load`: `out` the loaded value, `addr` its address — the deref
/// at int width for a witnessed site.
pub(crate) fn render(pr: &mut PrintC<'_>, out: VarnodeId, addr: VarnodeId) -> Option<(String, u8)> {
    // ON THE AXIS since Order Q (`testmem=witness|off`). It was gated on the witness set ALONE,
    // which is not a switch: the witness says the original read int width, it does not say we
    // should print it that way, and with no axis the arm fired under every choice vector -- 196
    // TUs / 320 int-width deref tokens of the canonical tree that could be neither turned off nor
    // priced (measured by the axis itself: emit both values and diff. The first census said 183,
    // a regex for `(uint4 *)(uint1 *)` that could not see the 13 TUs spelling the same construct
    // `*(uint4 *)puVar1` -- an axis is the census, a regex over rendered text is a proxy). The
    // reference path is unaffected either way: `print_c` carries no recovered evidence, so the
    // witness set is empty and this returns `None` before the axis is even consulted.
    if pr.arms.testmem.witness && pr.recovered.testmem_sites.contains(&out) {
        let w = pr.f.size_of_int();
        let vty = Datatype::Uint(w);
        return Some(pr.render_mem(addr, w, &vty));
    }
    None
}

/// The arm's own state: its choice flag, per THE STATE RULE (arms/mod.rs) — an arm's reading of
/// the axis lives here, not as a field on the printer.
#[derive(Debug)]
pub(crate) struct State {
    /// `testmem=witness` is on for this function.
    pub(crate) witness: bool,
}

impl State {
    pub(crate) fn new(choices: &crate::decompile::emit::EmitChoices) -> Self {
        State { witness: choices.testmem == crate::decompile::emit::TestMem::Witness }
    }
}
