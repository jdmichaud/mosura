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
    // (`ram` was a local of print_c_inner the census read; bound here the same way)
    let ram = f.spaces.by_name("ram");
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
    if pr.recovered.testmem_sites.contains(&out) {
        let w = pr.f.size_of_int();
        let vty = Datatype::Uint(w);
        return Some(pr.render_mem(addr, w, &vty));
    }
    None
}
