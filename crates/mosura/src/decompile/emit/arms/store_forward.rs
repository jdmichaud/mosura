//! `store-forward` — a call argument that is the value just stored to a global prints the
//! GLOBAL where the original reloads it. Ghidra's data-flow names the stored VALUE at every
//! later use (`xRam00080004 = xRam0008f046; f(xRam0008f046);`): the same value, but this
//! compiler then keeps the source global's load for the argument where the original reloaded
//! the stored one (`MOV [0x80004],AX .. MOV AX,[0x80004]`, WAR2 FUN_00014214 and FUN_00014240:
//! the source wrote `g = h; f(g);`). The witness (`recovered.store_forward.sites`, from
//! `buildconfig::store_forwards_from_evidence` over this arm's `store_forward_candidates`):
//! between the store and the call, the original loads the stored global. Value-identical: no
//! write to the global and no call intervenes between the store and the use. A
//! target-informed emit choice, NOT Ghidra.
//!
//! The arm answers `ValueSite::CallArg` after mask-cast; `None` = the port's own rendering.
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;

/// The arm's answer at `ValueSite::CallArg`: `op` the call, `slot` the argument's input slot.
pub(crate) fn render(pr: &mut PrintC<'_>, op: OpId, slot: usize) -> Option<(String, u8)> {
    let o = pr.f.op(op);
    let v = o.input(slot)?;
    let ram = pr.f.spaces.by_name("ram")?;
    let vn = pr.f.vn(v);
    if vn.is_constant() || vn.loc.space != ram {
        return None;
    }
    // walk the call's block backwards: the first COPY of this value into another global,
    // with no call or store in between (a write to any global between would be another
    // statement the reload could read instead)
    let bid = o.parent?;
    let ops = &pr.f.block(bid).ops;
    let at = ops.iter().position(|&x| x == op)?;
    let mut stored = None;
    for &x in ops[..at].iter().rev() {
        let xo = pr.f.op(x);
        if xo.is_dead() || xo.is_marker() || xo.is_return_copy() {
            continue;
        }
        match xo.code() {
            OpCode::Call | OpCode::Callind | OpCode::Callother | OpCode::Store => break,
            OpCode::Copy => {
                let (Some(src), Some(out)) = (xo.input(0), xo.output) else { continue };
                // the written global: the ram location itself, or the unique the pipeline
                // restructured the store into and the naming renders AS the global
                let gaddr = if pr.f.vn(out).loc.space == ram {
                    Some(pr.f.vn(out).loc.offset)
                } else {
                    pr.high_ram_off.get(&pr.high_of[out.0 as usize]).copied()
                };
                let Some(gaddr) = gaddr else { continue };
                if src == v && gaddr != vn.loc.offset && pr.is_explicit(out) {
                    stored = Some((x, out, gaddr));
                }
                break; // the nearest global write decides either way
            }
            _ => {}
        }
    }
    let (copy, out, g) = stored?;
    let (store_pc, call_pc) = (pr.f.op(copy).seqnum.pc.offset, o.seqnum.pc.offset);
    crate::debug!(crate::debug::Topic::Recover, "store-forward: candidate call @{call_pc:x} slot {slot} store @{store_pc:x} g {g:x} witnessed {}", pr.recovered.store_forward.sites.contains(&(call_pc, slot as u32)));
    pr.report.store_forward.candidates.push((call_pc, slot as u32, store_pc, g));
    if !pr.recovered.store_forward.sites.contains(&(call_pc, slot as u32)) {
        return None;
    }
    Some(pr.render_var(out))
}

/// The store-forward's candidates the report pass collects (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Every call argument that is the value just stored to another global (`store-forward`),
    /// as `(call address, slot, store address, the stored global's address)`.
    pub candidates: Vec<(u64, u32, u64, u64)>,
}

/// The store-forward's witnessed decisions the recovered pass renders (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Sites {
    /// `(call address, slot)` pairs whose argument the original reloads from the stored global
    /// (`store-forward`, `store_forward_candidates` evidence).
    pub sites: std::collections::HashSet<(u64, u32)>,
}
