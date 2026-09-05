//! `signed-load` — a load narrower than int, masked into a zero-equality, prints its deref at the
//! SIGNED type of its width, `(*(int2 *)(p + 0x10) & 1) != 0`, where the ORIGINAL sign-extends
//! the masked value before testing it (`MOV AX,[..] ; XOR AH,AH ; AND AL,1 ; CWDE ; TEST EAX,EAX`
//! — the source read a `short`). The port types the load unsigned (nothing in the IR distinguishes
//! the signs of a masked zero test) and this compiler zero-extends (`AND EAX,0xffff`): the subject
//! FUN_0002ebd0 (EXACT with the signed derefs), FUN_00043514, FUN_0002ea18 (four sites). The
//! candidates are the `testmem` shape's LOAD half (a sub-int LOAD whose zext-linked single use is
//! an INT_AND with a constant that fits the width, feeding equalities against zero); the mask and
//! the zero test read the same under either sign, so the rendering is value-identical. The
//! witness (`recovered.signed_load.sites`, from `buildconfig::signed_loads_from_evidence` over
//! this arm's candidates): a `CWDE`/`CBW`/`MOVSX` within the five instructions after the load's
//! address. A target-informed emit choice, NOT Ghidra.
//!
//! The arm answers at `ValueSite::Load` after `testmem` (a witnessed int-wide deref wins).
use crate::decompile::funcdata::Funcdata;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;
use crate::decompile::types::Datatype;
use crate::decompile::varnode::VarnodeId;

/// The census, called from `print_c_inner`'s evidence section: every masked narrow load feeding a
/// zero-equality, as `(load output, load address)`.
pub(crate) fn recognize(pr: &mut PrintC<'_>, f: &Funcdata) {
    for opid in f.op_ids() {
        let o = f.op(opid);
        if o.is_dead() || o.code() != OpCode::Load {
            continue;
        }
        let Some(out) = o.output else { continue };
        if f.vn(out).size == 0 || f.vn(out).size >= f.size_of_int() {
            continue;
        }
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
        let narrow_mask = (1u64 << narrow_bits) - 1;
        let const_fits = ao.input(1).is_some_and(|k| f.vn(k).is_constant() && f.vn(k).constant_value() & !narrow_mask == 0);
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
        if cmp0 {
            crate::debug!(crate::debug::Topic::Recover, "signed-load candidate @{:x} witnessed {}", o.seqnum.pc.offset, pr.recovered.signed_load.sites.contains(&out));
            pr.report.signed_load.candidates.push((out, o.seqnum.pc.offset));
        }
    }
}

/// The arm's answer at `ValueSite::Load`: `out` the loaded value, `addr` its address — the deref
/// at the signed type of the load's width for a witnessed site.
pub(crate) fn render(pr: &mut PrintC<'_>, out: VarnodeId, addr: VarnodeId) -> Option<(String, u8)> {
    if !pr.recovered.signed_load.sites.contains(&out) {
        return None;
    }
    let w = pr.f.vn(out).size;
    // the address carries the port's own pointer cast (`(uint2 *)(p + 0x10)`, an implied CAST
    // the deref would print bare): strip it, the signed pointer cast replaces it
    let mut inner = addr;
    while !pr.is_explicit(inner) {
        let Some(d) = pr.f.vn(inner).def else { break };
        let o = pr.f.op(d);
        if o.code() != OpCode::Cast {
            break;
        }
        let Some(x) = o.input(0) else { break };
        inner = x;
    }
    let a = pr.operand(inner, 14, false);
    Some((format!("*({} *){a}", Datatype::Int(w).name()), 15))
}

/// The signed-load's candidates the report pass collects (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Every masked narrow load feeding a zero-equality (`signed-load`), as `(load output,
    /// load address)`: the original sign-extends the masked value or zero-extends it.
    pub candidates: Vec<(VarnodeId, u64)>,
}

/// The signed-load's witnessed decisions the recovered pass renders (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Sites {
    /// Masked narrow loads whose deref renders at the SIGNED type of their width
    /// (`signed-load`, `signed_load` candidates evidence, `buildconfig::signed_loads_from_evidence`).
    pub sites: std::collections::HashSet<VarnodeId>,
}
