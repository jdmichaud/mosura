//! `struct-copy=assign` — a run of k plain `MOVSD` (no REP, no ECX) after an ESI/EDI setup is
//! Watcom's struct assignment at or below its unroll threshold and prints as
//! `*(struct pN *)dst = *(struct pN *)src` (docs/struct-copy-arm.md, W6). A target-informed emit
//! choice, NOT Ghidra: the reference decompiler prints k dword copies.
//!
//! Moved verbatim out of printc.rs (review R2, commit 2): the run printers (`movsd_run_stmt` for a
//! pc-keyed load/store run, `movsd_global_run` for the global-to-global runs heritage re-homes at
//! the block's exit, matched by SHAPE against a witnessed run length, `movsd_copy_shape`), the
//! block-op answer (`movsd_run_at`) and the arm's debug dumps. The only textual change in the
//! moved code is `self.` → `p.` in the former methods.
//!
//! The arm answers ONE seam, `Site::BlockOp`: for an op of a block's statement list it tries, IN
//! THIS ORDER, the global-to-global run shape and then the pc-keyed run — the order the port had
//! inline, and a necessary one: heritage re-homes the global-to-global copies at the block's exit
//! (0x20258's `xRam0008faf0 = xRam000a7fe0;` prints at the JMP's pc), so such a run's members do
//! not sit at the run's own pc and the shape match must come first, or the pc lookup would miss
//! them. It returns the fused statement with the ops it covers; the `struct-copy` choice gate lives
//! here. `reordered` (the ops the port has already emitted or re-ordered) rides on the site as data
//! the PORT owns: the arm reads it to avoid a consumed op and writes to it only through the
//! `Answer`'s members, which the port inserts. The port keeps its own precondition at the site (a
//! dead or already-suppressed op is not a statement) and writes the fused statement in its
//! statement form.
use crate::decompile::emit::arms::{Answer, Arm, Site, SiteKind};
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;
use crate::decompile::varnode::VarnodeId;

/// The arm, as the [`super::ARMS`] table holds it.
pub const ARM: Arm = Arm {
    name: "struct-copy: a plain MOVSD run as the struct assignment (docs/struct-copy-arm.md)",
    kinds: &[SiteKind::BlockOp],
    try_emit,
};

fn try_emit(p: &mut PrintC<'_>, site: Site<'_>, _out: &mut String) -> Option<Answer> {
    let Site::BlockOp { block_ops, op, pc, reordered } = site else { return None };
    if !p.arms.struct_copy.assign {
        return None;
    }
    debug_dump_block(p, block_ops, op);
    // a global-to-global run: heritage re-homes those copies at the block's exit (0x20258's
    // `xRam0008faf0 = xRam000a7fe0;` prints at the JMP's pc), so the witness matches the SHAPE —
    // k consecutive `ram[A+4i] = ram[B+4i]` copies whose k is a witnessed run length
    if let Some((stmt, members)) = movsd_global_run(p, block_ops, op, reordered) {
        return Some(Answer::Fused { stmt, members });
    }
    movsd_run_at(p, block_ops, op, pc).map(|(stmt, members)| Answer::Fused { stmt, members })
}

/// The arm's setup-time dump (`MOSURA_STRUCTCOPY_DEBUG`): the witness runs.
/// The arm's setup hook (review R6): nothing to recognize — the witnesses are the port's
/// `movsd_runs` — only the diagnostic dump of the setup under its topic. Called from
/// print_c_inner's arm-setup block, where every arm's recognizer is called, instead of from the
/// port's printing code.
pub(crate) fn recognize(p: &PrintC<'_>) {
    debug_dump_setup(p);
}

pub(crate) fn debug_dump_setup(p: &PrintC<'_>) {
if p.arms.struct_copy.assign {
    debug!(crate::debug::Topic::StructCopy, "{:#x} witness runs {:?}", p.f.addr.offset, p.recovered.movsd_runs);
}
}

/// The arm's per-block dump (`MOSURA_STRUCTCOPY_DEBUG`): the ops of each witnessed run in this
/// block, printed once per block at its first op (the port printed it before the block's op loop;
/// the one difference is a block whose first op is dead or suppressed, which no longer dumps —
/// debug output only, never on the print path).
fn debug_dump_block(p: &PrintC<'_>, block_ops: &[OpId], op: OpId) {
    if block_ops.first() != Some(&op) {
        return;
    }
    let Some(b) = p.f.op(op).parent else { return };
    if p.arms.struct_copy.assign && crate::debug::on(crate::debug::Topic::StructCopy) && !p.recovered.movsd_runs.is_empty() {
    for (&rp, &rk) in &p.recovered.movsd_runs {
        let here: Vec<String> = block_ops.iter().filter(|&&o| { let pc = p.f.op(o).seqnum.pc.offset; pc >= rp && pc < rp + rk as u64 }).map(|&o| { let x = p.f.op(o); format!("{:#x}:{:?}{}", x.seqnum.pc.offset, x.code(), if x.is_dead() { "(dead)" } else { "" }) }).collect();
        if !here.is_empty() { debug!(crate::debug::Topic::StructCopy, "{:#x} blk{} run @{rp:#x} k {rk}: ops {:?}", p.f.addr.offset, b.0, here); }
    }
}
}

/// `struct-copy=assign`: the k dword copies a plain-`MOVSD` run lifted to, one per pc
/// `pc..pc+k` (a MOVSD is one byte), fused into `*(struct pN *)dst = *(struct pN *)src`
/// with the run's first destination and source addresses (the later ones are base + 4i by
/// the instruction's own semantics). Each copy is a STORE fed by a LOAD, or the explicit
/// assignment the load/store rules made of a global (`xRam.. = xRam..`).
/// `struct-copy` at a block op: the fused statement when `op` is the first member of a witnessed
/// run at `pc` (the other ops of that pc are its load and the folded pointer steps). The arm's
/// answer at `Site::BlockOp`; its debug print lives here, with the arm.
pub(crate) fn movsd_run_at(p: &mut PrintC<'_>, block_ops: &[OpId], op: OpId, pc: u64) -> Option<(String, Vec<OpId>)> {
    let k = *p.recovered.movsd_runs.get(&pc)?;
    let fused = movsd_run_stmt(p, block_ops, pc, k);
    debug!(crate::debug::Topic::StructCopy, 
            "{:#x} run @{pc:#x} k {k} at op {:?} {:?}: {}",
            p.f.addr.offset,
            op,
            p.f.op(op).code(),
            fused.as_ref().map(|f| f.0.clone()).unwrap_or_else(|| "-".to_string())
        );
    // fires once, at the run's first member
    fused.filter(|(_, m)| m.first() == Some(&op))
}

fn movsd_run_stmt(p: &mut PrintC<'_>, block_ops: &[OpId], pc: u64, k: u32) -> Option<(String, Vec<OpId>)> {
    let mut members = Vec::new();
    let mut first: Option<(String, String)> = None;
    let dbg = crate::debug::on(crate::debug::Topic::StructCopy);
    for i in 0..k as u64 {
        let op = block_ops.iter().copied().find(|&o| {
            let x = p.f.op(o);
            !x.is_dead() && !p.suppressed.contains(&o) && x.seqnum.pc.offset == pc + i
                && (x.code() == OpCode::Store || (x.code() == OpCode::Copy && x.output.is_some_and(|v| p.is_explicit(v))))
        });
        let Some(op) = op else {
            if dbg {
                let at: Vec<String> = block_ops.iter().filter(|&&o| p.f.op(o).seqnum.pc.offset == pc + i).map(|&o| { let x = p.f.op(o); format!("{:?}{}{}{}", x.code(), if x.is_dead() { "(dead)" } else { "" }, if p.suppressed.contains(&o) { "(supp)" } else { "" }, x.output.map(|v| if p.is_explicit(v) { "(explicit)" } else { "(implied)" }).unwrap_or("")) }).collect();
                debug!(crate::debug::Topic::StructCopy, "element {i} @{:#x}: no printable copy; ops there: {:?}", pc + i, at);
            }
            return None;
        };
        let shape = movsd_copy_shape(p, op, pc + i)?;
        if i == 0 {
            first = Some(shape);
        }
        members.push(op);
    }
    let (dst, src) = first?;
    let n = 4 * k;
    Some((format!("*(struct p{n} *){dst} = *(struct p{n} *){src}"), members))
}

/// A run of consecutive global-to-global dword copies `ram[A+4i] = ram[B+4i]` starting at
/// `first`, k >= 2, k a witnessed MOVSD run length: the struct assignment between the two
/// addresses.
fn movsd_global_run(p: &mut PrintC<'_>, block_ops: &[OpId], first: OpId, reordered: &std::collections::HashSet<OpId>) -> Option<(String, Vec<OpId>)> {
    // the global's address: the varnode's own when it lives in ram, else the ram member of the
    // HighVariable it was merged into (heritage writes the re-homed copies to uniques)
    let ram4 = |me: &PrintC<'_>, v: VarnodeId| -> Option<u64> {
        let vn = me.f.vn(v);
        if vn.size != 4 {
            return None;
        }
        if me.f.spaces.get(vn.loc.space).name == "ram" {
            return Some(vn.loc.offset);
        }
        let h = *me.high_of.get(v.0 as usize)?;
        me.high_members.get(&h)?.iter().copied().find_map(|m| {
            let mv = me.f.vn(m);
            (me.f.spaces.get(mv.loc.space).name == "ram" && mv.size == 4).then_some(mv.loc.offset)
        })
    };
    // a printable copy between two DIFFERENT globals (the block-exit `ram[A] = ram[A]` phi
    // carries are implied and never print)
    let copy = |me: &PrintC<'_>, o: OpId| -> Option<(u64, u64)> {
        let x = me.f.op(o);
        if x.is_dead() || x.code() != OpCode::Copy || me.suppressed.contains(&o) || me.nonprinting.contains(&o) {
            return None;
        }
        let out = x.output?;
        if !me.is_explicit(out) {
            return None;
        }
        let a = ram4(me, out)?;
        let b = ram4(me, x.input(0)?)?;
        (a != b).then_some((a, b))
    };
    let (a0, b0) = copy(p, first)?;
    let start = block_ops.iter().position(|&o| o == first)?;
    let mut members = vec![first];
    let mut i = 1u64;
    for &o in &block_ops[start + 1..] {
        if reordered.contains(&o) || p.suppressed.contains(&o) {
            continue;
        }
        let x = p.f.op(o);
        if x.is_dead() || x.is_marker() || x.output.is_some_and(|v| !p.is_explicit(v)) && x.code() != OpCode::Copy {
            continue; // an implied value in between does not break the run
        }
        match copy(p, o) {
            Some((a, b)) if a == a0 + 4 * i && b == b0 + 4 * i => {
                members.push(o);
                i += 1;
            }
            _ => break,
        }
    }
    let k = members.len();
    if k < 2 || !p.recovered.movsd_runs.values().any(|&rk| rk as usize == k) {
        return None;
    }
    let n = 4 * k;
    Some((format!("*(struct p{n} *){a0:#x} = *(struct p{n} *){b0:#x}"), members))
}

/// One dword copy of a MOVSD run: (destination address, source address) as C expressions,
/// parenthesized for the cast. A RAM varnode names its own address.
fn movsd_copy_shape(p: &mut PrintC<'_>, op: OpId, pc: u64) -> Option<(String, String)> {
    let o = p.f.op(op);
    let dbg = crate::debug::on(crate::debug::Topic::StructCopy);
    let ram = |me: &PrintC<'_>, v: VarnodeId| -> Option<String> {
        let vn = me.f.vn(v);
        let name = &me.f.spaces.get(vn.loc.space).name;
        if dbg && name != "ram" { debug!(crate::debug::Topic::StructCopy, "varnode {v:?} in space {name:?} size {} — not ram", vn.size); }
        (name == "ram" && vn.size == 4).then(|| format!("{:#x}", vn.loc.offset))
    };
    let (dst, value) = match o.code() {
        OpCode::Store => {
            let (addr, vv) = (o.input(1)?, o.input(2)?);
            if p.f.vn(vv).size != 4 {
                debug!(crate::debug::Topic::StructCopy, "copy @{pc:#x}: store of size {} — declined", p.f.vn(vv).size);
                return None;
            }
            let a = p.render_var(addr).0;
            let a = match a.find(" *)(") {
                Some(i) if a.starts_with('(') && a.ends_with(')') && !a[1..i].contains(['(', ' ']) => a[i + 3..].to_string(),
                _ => format!("({a})"),
            };
            (a, vv)
        }
        _ => {
            let out = o.output?;
            if p.f.vn(out).size != 4 {
                debug!(crate::debug::Topic::StructCopy, "copy @{pc:#x}: assign of size {} — declined", p.f.vn(out).size);
                return None;
            }
            let vv = match o.code() {
                OpCode::Copy => o.input(0)?,
                other => {
                    debug!(crate::debug::Topic::StructCopy, "copy @{pc:#x}: printable {other:?} is not a copy — declined");
                    return None;
                }
            };
            (ram(p, out)?, vv)
        }
    };
    // the value must be THIS MOVSD's own load (same pc): a load from an earlier run that
    // copy-propagation carried here (0x38158's swap through a stack temp) would re-read a
    // location the run in between overwrote
    let src = match p.f.vn(value).def {
        Some(d) if p.f.op(d).code() == OpCode::Load => {
            if p.f.op(d).seqnum.pc.offset != pc {
                debug!(crate::debug::Topic::StructCopy, "copy @{pc:#x}: load from another pc {:#x} — declined", p.f.op(d).seqnum.pc.offset);
                return None;
            }
            let a = p.render_var(p.f.op(d).input(1)?).0;
            match a.find(" *)(") {
                Some(i) if a.starts_with('(') && a.ends_with(')') && !a[1..i].contains(['(', ' ']) => a[i + 3..].to_string(),
                _ => format!("({a})"),
            }
        }
        Some(d) if p.f.op(d).code() == OpCode::Copy && ram(p, p.f.op(d).input(0)?).is_some() => ram(p, p.f.op(d).input(0)?)?,
        _ => match ram(p, value) {
            Some(a) => a,
            None => {
                debug!(crate::debug::Topic::StructCopy, "copy @{pc:#x}: value {:?} def {:?} is not a load/global — declined", value, p.f.vn(value).def.map(|d| p.f.op(d).code()));
                return None;
            }
        },
    };
    Some((dst, src))
}

/// The arm's state: its configuration (the witness, `recovered.movsd_runs`, is the port's).
#[derive(Debug, Default)]
pub(crate) struct State {
    /// `struct-copy=assign` is on for this function.
    pub(crate) assign: bool,
}

impl State {
    pub(crate) fn new(choices: &crate::decompile::emit::EmitChoices) -> Self {
        State { assign: choices.struct_copy == crate::decompile::emit::StructCopy::Assign }
    }
}
