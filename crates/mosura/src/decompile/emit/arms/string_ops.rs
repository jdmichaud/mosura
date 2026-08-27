//! `string-ops=intrinsic` — a lifted `REP MOVS`/`STOS`/`CMPS`/`SCAS` loop prints as the
//! `memcpy`/`memset`/`memcmp`/`strlen` call Watcom 10.0a's intrinsic template compiled it from
//! (docs/rep-string-intrinsic-arm.md; W1/W2/V2/V3). A target-informed emit choice, NOT Ghidra: the
//! reference decompiler prints the loop.
//!
//! Moved verbatim out of printc.rs (review R2, commit 1): the recognizer that runs at print setup
//! ([`recognize`] — fills the witness map `rep_movs`, the skip set `rep_skip`, the `strlen_alias`
//! table and the port's `suppressed` set), the loop-node printer ([`try_emit_rep_movs`]), the
//! node suppression ([`covered_by_collapsed`]) and the value answerer ([`strlen_fold`]). The only
//! textual change is `self.` → `p.` in the three former methods.
//!
//! The arm answers THREE seams: `Site::LoopNode` — the collapsed loop prints as the call;
//! `Site::Node` — a node whose every live op belongs to a collapsed string-op's skip set (the
//! pair's byte loop, memcmp's `if (!zf) r = …` result block) emits nothing, the call covers it.
//! That suppression is its own site because it applies to EVERY structured node kind, not only
//! to the loop the call replaced; and `ValueSite::OpRoot` — an add/sub/compare between a
//! `len + 1` alias and a constant prints with the constant re-adjusted (V3 `strlen`).
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use crate::decompile::emit::arms::{Answer, Arm, Site, SiteKind};
use crate::decompile::emit::{EmitChoices, StringOps};
use crate::decompile::funcdata::Funcdata;
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::{collect_basics, render_const_typed, strip_copies, PrintC};
use crate::decompile::structure::Structured;
use crate::decompile::varnode::VarnodeId;

/// The arm, as the [`crate::decompile::ARMS`] table holds it.
pub const ARM: Arm = Arm {
    name: "string-ops: a lifted REP MOVS/STOS/CMPS/SCAS as memcpy/memset/memcmp/strlen (docs/rep-string-intrinsic-arm.md)",
    kinds: &[SiteKind::LoopNode, SiteKind::Node],
    try_emit,
};

fn try_emit(p: &mut PrintC<'_>, site: Site<'_>, out: &mut String) -> Option<Answer> {
    match site {
        Site::LoopNode { s, idx, indent } => try_emit_rep_movs(p, s, idx, indent, out).then_some(Answer::Emitted),
        Site::Node { s, idx } => covered_by_collapsed(p, s, idx).then_some(Answer::Emitted),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum RepSize {
    /// A compile-time constant (a struct copy / `UNMAP_SIZE`): `c1*4 + c2` folded.
    Const(u64),
    /// The runtime length varnode `n` that fed both `n>>2` and `n&3`.
    Var(VarnodeId),
    /// Unrecovered runtime split: rendered `count1 * 4 + count2` (value-identical).
    Split(VarnodeId, VarnodeId),
}

/// A recognized lifted `REP MOVS`/`REP STOS` (single, or a MOVSD+MOVSB / STOSD+STOSB PAIR — Watcom
/// 10.0a's intrinsic template always emits the pair, even for a constant length), keyed by the
/// FIRST loop's instruction pc — the operands to render as `memcpy(dst, src, size)` /
/// `memset(dst, val, size)`. `src`/`set_val` are exclusive (copy vs set); values are loop-entry.
/// `frame-fill=aggregate` (docs/compilable-c-remediation.md Phase 10b): the ONE byte aggregate the
/// frame's stack symbols render through — `[bottom, top)` is the original `SUB ESP` frame below the
/// pushed registers, `size = top - bottom`.

#[derive(Debug, Clone, Copy)]
pub(crate) struct RepMovs {
    pub(crate) dst: VarnodeId,
    pub(crate) src: Option<VarnodeId>,
    pub(crate) set_val: Option<VarnodeId>,
    pub(crate) size: RepSize,
    /// `memcmp` (a lifted `REPE CMPS`): the -1/0/1 result varnode the call assigns.
    pub(crate) cmp_result: Option<VarnodeId>,
    /// V3 `strlen`: the value Watcom's `NOT ECX; DEC ECX` template materializes (`~cnt - 1`, addend
    /// 0) or a bare `~cnt` reader (addend 1, the user's `+ 1` folded into the template's `- 1`).
    pub(crate) strlen_result: Option<(VarnodeId, i64)>,
}

/// One lifted rep-string loop, as the recognizer sees it (all ops at one pc).
#[derive(Debug, Clone, Copy)]
struct RepLoop {
    pc: u64,
    elem: u32,
    dst_phi: VarnodeId,
    src_phi: Option<VarnodeId>,
    dst_entry: VarnodeId,
    src_entry: Option<VarnodeId>,
    set_val: Option<VarnodeId>,
    count_phi: VarnodeId,
    count_entry: VarnodeId,
}

/// From a phi's entry input, cross the materialization chain — COPYs/CASTs whose output feeds
/// nothing live but the next link (or the phi) — to the value the printer names. A COPY whose
/// output has other uses is a real local's assignment (`pTemp = malloc(n)` — also read later):
/// crossing it rendered the call inline in the memcpy, a second call (measured, 0x33efc).
fn phi_entry_source(f: &Funcdata, raw: VarnodeId, consumer: OpId) -> VarnodeId {
    let mut v = raw;
    let mut consumer = consumer;
    for _ in 0..8 {
        let Some(d) = f.vn(v).def else { break };
        if !matches!(f.op(d).code(), OpCode::Copy | OpCode::Cast) {
            break;
        }
        let only = f.vn(v).descend.iter().all(|&u| u == consumer || f.op(u).is_dead());
        if !only {
            break;
        }
        consumer = d;
        v = f.op(d).input(0).unwrap_or(v);
    }
    v
}

/// The COPY/CAST ops between a phi's raw input and its named source (see [`phi_entry_source`]),
/// for suppression once a collapsed call reads the source directly. Each op is listed only if its
/// output feeds nothing live but the next op in the chain (or the phi).
fn phi_entry_chain(f: &Funcdata, raw: VarnodeId, phi_op: OpId) -> Vec<OpId> {
    let mut out = Vec::new();
    let mut v = raw;
    let mut consumer = phi_op;
    let mut copies = 0;
    for _ in 0..8 {
        let Some(d) = f.vn(v).def else { break };
        let code = f.op(d).code();
        if !(code == OpCode::Cast || (code == OpCode::Copy && copies == 0)) {
            break;
        }
        let only = f.vn(v).descend.iter().all(|&u| u == consumer || f.op(u).is_dead());
        if !only {
            break;
        }
        out.push(d);
        if code == OpCode::Copy {
            copies += 1;
        }
        consumer = d;
        v = f.op(d).input(0).unwrap_or(v);
    }
    out
}

/// A value LOADed at `pc`: `v = LOAD ptr` at the pc, or — after Ghidra's cleanup `RuleExpandLoad`
/// widened the load to the pointer's pointee — `v = SUBPIECE(LOAD ptr, 0)` at the pc. Returns the
/// (COPY/CAST-stripped) pointer and the loaded value's size (the STORE's element size, not the
/// widened load's).
fn rep_load_at(f: &Funcdata, v: VarnodeId, pc: u64) -> Option<(VarnodeId, u32)> {
    let d = f.vn(v).def?;
    let o = f.op(d);
    if o.seqnum.pc.offset != pc {
        return None;
    }
    match o.code() {
        OpCode::Load => Some((strip_copies(f, o.input(1)?), f.vn(v).size)),
        OpCode::Subpiece if o.input(1).is_some_and(|k| f.vn(k).is_constant() && f.vn(k).constant_value() == 0) => {
            let inner = o.input(0)?;
            let ld = f.vn(inner).def?;
            let lo = f.op(ld);
            (lo.code() == OpCode::Load && lo.seqnum.pc.offset == pc)
                .then(|| Some((strip_copies(f, lo.input(1)?), f.vn(v).size)))
                .flatten()
        }
        _ => None,
    }
}

/// Follow `COPY`/`CAST` chains to the source varnode (`ActionSetCasts` inserts a `CAST` between a
/// typed pointer phi and the LOAD/STORE that reads it; a rep-string loop's shape is the same).

/// The loop-entry (pre-loop) value of a rep-string induction varnode: if `v` is a `MULTIEQUAL`
/// whose one input is defined at the loop pc (the back-edge, a `PTRADD`/`INT_ADD`) and the other is
/// not, return the other (following a `COPY` to its source so it renders as the original operand).
fn rep_loop_entry(f: &Funcdata, v: VarnodeId, pc: u64) -> Option<VarnodeId> {
    let d = f.vn(v).def?;
    let o = f.op(d);
    if o.code() != OpCode::Multiequal || o.num_inputs() != 2 {
        return None;
    }
    let (a, b) = (o.input(0)?, o.input(1)?);
    let at = f.vn(a).def.map(|x| f.op(x).seqnum.pc.offset);
    let bt = f.vn(b).def.map(|x| f.op(x).seqnum.pc.offset);
    let entry = match (at == Some(pc), bt == Some(pc)) {
        (true, false) => b,
        (false, true) => a,
        _ => return None,
    };
    // Follow the phi-materialization COPY (exactly one) and any CASTs to the value the printer names
    // (a parameter, a stack slot, a local). Never cross a SECOND COPY: that is the local's own
    // assignment (`pTemp = malloc(n)`), and crossing it rendered the call inline in the memcpy —
    // a second call, with the local left unassigned (measured: 0x33efc).
    Some(phi_entry_source(f, entry, d))
}

/// The count phi of the rep-string loop at `pc` (a `MULTIEQUAL` at `pc` whose back-edge input is
/// `INT_ADD(self, const)` — the `ECX--`) and its loop-entry value (the initial `ECX`).
fn rep_count(f: &Funcdata, pc: u64) -> Option<(VarnodeId, VarnodeId)> {
    for op in f.op_ids() {
        let o = f.op(op);
        if o.is_dead() || o.code() != OpCode::Multiequal || o.seqnum.pc.offset != pc || o.num_inputs() != 2 {
            continue;
        }
        let out = o.output?;
        // `ECX--`: INT_ADD(self, -1) for a signed count, INT_SUB(self, 1) once typed unsigned.
        let back = [o.input(0)?, o.input(1)?].into_iter().find(|&iv| {
            f.vn(iv).def.is_some_and(|dd| {
                let do_ = f.op(dd);
                matches!(do_.code(), OpCode::IntAdd | OpCode::IntSub) && do_.input(0) == Some(out)
            })
        });
        if back.is_some() {
            return rep_loop_entry(f, out, pc).map(|e| (out, e));
        }
    }
    None
}

/// Safety: `memcpy`/`memset` does not leave the advanced pointers/count behind, so the loop's
/// induction phis must have NO use outside the loop's own pc. Returns false if any live use of a
/// listed varnode's phi output is at a different pc (then the loop is kept, not collapsed).
fn rep_post_loop_dead(f: &Funcdata, phis: &[VarnodeId], pc: u64) -> bool {
    for &v in phis {
        for &u in &f.vn(v).descend {
            if !f.op(u).is_dead() && f.op(u).seqnum.pc.offset != pc {
                return false;
            }
        }
    }
    true
}

/// Whether a varnode derives from `root` through only `INT_ZEXT` / `INT_NOTEQUAL(x, 0)` — the shape
/// of Watcom's memcmp result `1 - zext(CF) - zext(CF != 0)` (the two `SBB`s), with `CF` = `root`.
fn derives_via_zext_ne(f: &Funcdata, v: VarnodeId, root: VarnodeId, depth: u32) -> bool {
    if v == root {
        return true;
    }
    if depth == 0 {
        return false;
    }
    let Some(d) = f.vn(v).def else { return false };
    let o = f.op(d);
    match o.code() {
        OpCode::IntZext | OpCode::Copy => o.input(0).is_some_and(|x| derives_via_zext_ne(f, x, root, depth - 1)),
        OpCode::IntNotequal => {
            o.input(1).is_some_and(|k| f.vn(k).is_constant() && f.vn(k).constant_value() == 0)
                && o.input(0).is_some_and(|x| derives_via_zext_ne(f, x, root, depth - 1))
        }
        _ => false,
    }
}

/// The ops of the memcmp result chain rooted at `r1 = INT_SUB(INT_SUB(#1, zext(cf)), zext(cf != 0))`,
/// collected for suppression (returns None if `r1` is not that shape over `cf_exit`).
fn rep_cmp_chain(f: &Funcdata, r1: VarnodeId, cf_exit: VarnodeId) -> Option<Vec<OpId>> {
    let d = f.vn(r1).def?;
    let o = f.op(d);
    if o.code() != OpCode::IntSub {
        return None;
    }
    let (s1, y) = (o.input(0)?, o.input(1)?);
    let sd = f.vn(s1).def?;
    let so = f.op(sd);
    if so.code() != OpCode::IntSub
        || !so.input(0).is_some_and(|k| f.vn(k).is_constant() && f.vn(k).constant_value() == 1)
    {
        return None;
    }
    let x = so.input(1)?;
    if !derives_via_zext_ne(f, x, cf_exit, 4) || !derives_via_zext_ne(f, y, cf_exit, 4) {
        return None;
    }
    // collect every op between cf_exit and r1
    let mut ops = vec![d, sd];
    let mut stack = vec![x, y];
    while let Some(v) = stack.pop() {
        if v == cf_exit {
            continue;
        }
        if let Some(vd) = f.vn(v).def {
            if !ops.contains(&vd) {
                ops.push(vd);
                for i in 0..f.op(vd).num_inputs() {
                    if let Some(iv) = f.op(vd).input(i) {
                        if !f.vn(iv).is_constant() {
                            stack.push(iv);
                        }
                    }
                }
            }
        }
    }
    Some(ops)
}

/// V3 `strlen`: an add/sub/compare between a `len + 1` alias and a constant prints with the
/// constant re-adjusted (`~cnt != 1` → `len != 0`, `~cnt - 2` → `len - 1`, `~cnt + k` →
/// `len + (k + 1)`) — undoing the fold Ghidra applied to the template's `DEC`.
pub(crate) fn strlen_fold(p: &mut PrintC<'_>, op: OpId) -> Option<(String, u8)> {
    if p.strlen_alias.is_empty() {
        return None;
    }
    let o = p.f.op(op);
    let (i0, i1) = (o.input(0)?, o.input(1)?);
    let (av, kv, alias_left) = match (p.strlen_alias.get(&i0), p.strlen_alias.get(&i1)) {
        (Some(&(r, add)), None) if p.f.vn(i1).is_constant() => ((r, add, i0), i1, true),
        (None, Some(&(r, add))) if p.f.vn(i0).is_constant() => ((r, add, i1), i0, false),
        _ => return None,
    };
    let (r, add, v) = av;
    if add == 0 {
        return None;
    }
    let size = p.f.vn(kv).size;
    let mask = if size >= 8 { u64::MAX } else { (1u64 << (8 * size)) - 1 };
    let k = p.f.vn(kv).constant_value() & mask;
    let k = if size < 8 && k & (1u64 << (8 * size - 1)) != 0 { (k | !mask) as i64 } else { k as i64 };
    let (sym, prec, k2) = match o.code() {
        OpCode::IntAdd => ("+", 12, k + add),
        OpCode::IntSub if alias_left => ("-", 12, k - add),
        OpCode::IntEqual => ("==", 9, k - add),
        OpCode::IntNotequal => ("!=", 9, k - add),
        OpCode::IntLess | OpCode::IntSless => ("<", 10, k - add),
        OpCode::IntLessequal | OpCode::IntSlessequal => ("<=", 10, k - add),
        _ => return None,
    };
    let rn = if r == v { p.name_of(v) } else { p.render_var(r).0 };
    if k2 == 0 && matches!(o.code(), OpCode::IntAdd | OpCode::IntSub) {
        return Some((rn, 16));
    }
    let kt = render_const_typed((k2 as u64) & mask, size, k2 < 0);
    Some(if alias_left || matches!(o.code(), OpCode::IntAdd) { (format!("{rn} {sym} {kt}"), prec) } else { (format!("{kt} {sym} {rn}"), prec) })
}

/// `string-ops=intrinsic`: if this loop node is a recognized single-instruction `REP MOVS`/
/// `REP STOS` (all its ops share one recovered pc in `p.arms.string_ops.rep_movs`), emit the `memcpy`/`memset`
/// call in place of the whole loop and return true (so the caller skips the loop emit).
fn try_emit_rep_movs(p: &mut PrintC<'_>, s: &Structured, idx: usize, indent: usize, out: &mut String) -> bool {
    if p.arms.string_ops.rep_movs.is_empty() {
        return false;
    }
    let mut basics = Vec::new();
    collect_basics(s, idx, &mut basics);
    let mut pc: Option<u64> = None;
    for b in basics {
        for op in p.f.block(b).ops.clone() {
            if p.f.op(op).is_dead() {
                continue;
            }
            let p = p.f.op(op).seqnum.pc.offset;
            match pc {
                None => pc = Some(p),
                Some(x) if x == p => {}
                _ => return false, // more than one instruction's ops → not a single REP MOVS
            }
        }
    }
    let Some(pc) = pc else { return false };
    if p.arms.string_ops.rep_skip.contains(&pc) {
        return true; // the pair's byte loop: covered by the first loop's call
    }
    let Some(info) = p.arms.string_ops.rep_movs.get(&pc).copied() else { return false };
    let dst = p.render_var(info.dst).0;
    let size = match info.size {
        RepSize::Const(c) => if c < 10 { format!("{c}") } else { format!("{c:#x}") },
        RepSize::Var(v) => p.render_var(v).0,
        RepSize::Split(a, b) if a == b => format!("{} * 4", p.render_var(a).0),
        RepSize::Split(a, b) => format!("{} * 4 + {}", p.render_var(a).0, p.render_var(b).0),
    };
    let stmt = match (info.src, info.set_val) {
        (Some(src), _) if info.cmp_result.is_some() => {
            let src = p.render_var(src).0;
            let r = p.lvalue_of(info.cmp_result.unwrap());
            format!("{r} = memcmp({dst}, {src}, {size})")
        }
        (Some(src), _) => {
            let src = p.render_var(src).0;
            format!("memcpy({dst}, {src}, {size})")
        }
        (None, Some(v)) => {
            let v = p.render_var(v).0;
            format!("memset({dst}, {v}, {size})")
        }
        (None, None) => {
            let Some((r, add)) = info.strlen_result else { return false };
            if p.strlen_exprs.contains_key(&r) {
                return true; // implied: rendered at its use, the loop prints nothing
            }
            let r = p.lvalue_of(r);
            let sv = p.strlen_arg(info.dst);
            if add == 0 { format!("{r} = strlen({sv})") } else { format!("{r} = strlen({sv}) + {add}") }
        }
    };
    let _ = writeln!(out, "{}{stmt};", "  ".repeat(indent));
    true
}

/// A node whose every live op belongs to a collapsed string-op's skip set (the pair's byte loop,
/// memcmp's `if (!zf) r = …` result block) emits nothing: the call covers it.
fn covered_by_collapsed(p: &mut PrintC<'_>, s: &Structured, idx: usize) -> bool {
if p.arms.string_ops.rep_skip.is_empty() {
    return false;
}
{
    let mut basics = Vec::new();
    collect_basics(s, idx, &mut basics);
    let mut any = false;
    let all_skip = basics.iter().all(|&b| {
        p.f.block(b).ops.iter().all(|&op| {
            let o = p.f.op(op);
            if o.is_dead() { return true; }
            any = true;
            p.arms.string_ops.rep_skip.contains(&o.seqnum.pc.offset)
        })
    });
    if any && all_skip {
        return true;
    }
}
    false
}

/// The recognizer, run once when the printer is built (arm setup): lifted REP loops → the
/// witness map `rep_movs`, the skip set `rep_skip`, the `strlen_alias` table and the port's
/// `suppressed` set, reported through `report.rep_movs_candidates`.
pub(crate) fn recognize(p: &mut PrintC<'_>) {
    let f: &Funcdata = p.f;
// string-ops=intrinsic (docs/rep-string-intrinsic-arm.md): lifted REP MOVS/STOS loops →
// memcpy/memset. Watcom 10.0a's intrinsic template is a MOVSD+MOVSB (STOSD+STOSB) PAIR sharing
// the advanced pointers — `n>>2` dwords then `n&3` bytes — emitted even for a constant length
// (a struct copy / sizeof), so the pair is the unit. All of one loop's ops share one pc.
// Witnessed on the original bytes (buildconfig::string_ops_from_evidence: F2|F3 MOVS/STOS).
if p.arms.string_ops.intrinsic {
    let mut loops: Vec<RepLoop> = Vec::new();
    for op in f.op_ids() {
        let o = f.op(op);
        if o.is_dead() || o.code() != OpCode::Store {
            continue;
        }
        let pc = o.seqnum.pc.offset;
        let (Some(dst_ptr), Some(val)) = (o.input(1), o.input(2)) else { continue };
        let dst_phi = strip_copies(f, dst_ptr);
        let elem = f.vn(val).size;
        if elem == 0 || loops.iter().any(|l| l.pc == pc) {
            continue;
        }
        let (src_phi, set_val) = match rep_load_at(f, val, pc) {
            Some((ptr, _)) => (Some(ptr), None),
            None => (None, Some(val)),
        };
        let Some(dst_entry) = rep_loop_entry(f, dst_phi, pc) else { continue };
        let src_entry = match src_phi {
            Some(sp) => match rep_loop_entry(f, sp, pc) {
                Some(e) => Some(e),
                None => continue,
            },
            None => None,
        };
        let Some((count_phi, count_entry)) = rep_count(f, pc) else { continue };
        loops.push(RepLoop { pc, elem, dst_phi, src_phi, dst_entry, src_entry, set_val, count_phi, count_entry });
    }
    // Pair up: a dword loop whose advanced pointers are the entry of a byte loop.
    let mut used: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut recognized: Vec<(RepLoop, Option<RepLoop>)> = Vec::new();
    for l1 in &loops {
        if l1.elem != 4 || used.contains(&l1.pc) {
            continue;
        }
        let pair = loops.iter().find(|l2| {
            l2.elem == 1
                && !used.contains(&l2.pc)
                && strip_copies(f, l2.dst_entry) == l1.dst_phi
                && match (l2.src_entry, l1.src_phi) {
                    (Some(e), Some(p)) => strip_copies(f, e) == p,
                    (None, None) => true,
                    _ => false,
                }
        });
        if let Some(l2) = pair {
            used.insert(l1.pc);
            used.insert(l2.pc);
            recognized.push((*l1, Some(*l2)));
        }
    }
    for l in &loops {
        if !used.contains(&l.pc) {
            recognized.push((*l, None));
        }
    }
    for (l1, l2) in recognized {
        // memcpy/memset leaves no advanced pointer behind: the LAST loop's pointers must be dead
        // after it (a pair's first-loop pointers legitimately flow into the second).
        let last = l2.unwrap_or(l1);
        let mut phis = vec![last.dst_phi];
        if let Some(sp) = last.src_phi {
            phis.push(sp);
        }
        if !rep_post_loop_dead(f, &phis, last.pc) {
            continue;
        }
        // Size in bytes.
        let c = |v: VarnodeId| -> Option<u64> {
            let v = strip_copies(f, v);
            f.vn(v).is_constant().then(|| f.vn(v).constant_value())
        };
        let size = match l2 {
            Some(l2) => match (c(l1.count_entry), c(l2.count_entry)) {
                (Some(c1), Some(c2)) => RepSize::Const(c1 * 4 + c2),
                _ => {
                    // runtime n: count1 = n >> 2, count2 = n & 3 from one varnode
                    let n1 = f.vn(strip_copies(f, l1.count_entry)).def.and_then(|d| {
                        let o = f.op(d);
                        (o.code() == OpCode::IntRight
                            && o.input(1).is_some_and(|k| f.vn(k).is_constant() && f.vn(k).constant_value() == 2))
                        .then(|| strip_copies(f, o.input(0).unwrap()))
                    });
                    let n2 = f.vn(strip_copies(f, l2.count_entry)).def.and_then(|d| {
                        let o = f.op(d);
                        (o.code() == OpCode::IntAnd
                            && o.input(1).is_some_and(|k| f.vn(k).is_constant() && f.vn(k).constant_value() == 3))
                        .then(|| strip_copies(f, o.input(0).unwrap()))
                    });
                    match (n1, n2) {
                        (Some(a), Some(b)) if a == b => RepSize::Var(a),
                        _ => RepSize::Split(l1.count_entry, l2.count_entry),
                    }
                }
            },
            None => match c(l1.count_entry) {
                Some(c1) => RepSize::Const(c1 * l1.elem as u64),
                None if l1.elem == 1 => RepSize::Var(l1.count_entry),
                None => RepSize::Split(l1.count_entry, l1.count_entry), // rendered below as count*elem
            },
        };
        // memset value: a pair's byte loop carries the byte; a lone STOSD needs a broadcast const.
        if l2.is_none() && matches!(size, RepSize::Const(0)) {
            continue; // a zero-count lone loop is a no-op; never `memset(p, v, 0)`
        }
        let set_val = match (l1.set_val, l2) {
            (Some(_), Some(l2)) => l2.set_val,
            (Some(v), None) => Some(v),
            _ => None,
        };
        let single_dword_set_ok = match (l1.set_val, l2) {
            (Some(v), None) if l1.elem == 4 => {
                let v = strip_copies(f, v);
                f.vn(v).is_constant() && {
                    let k = f.vn(v).constant_value();
                    (k & 0xff) * 0x0101_0101 == k
                }
            }
            _ => true,
        };
        if !single_dword_set_ok {
            continue;
        }
        p.report.rep_movs_candidates.push((l1.pc, l1.elem));
        if let Some(l2) = l2 {
            p.report.rep_movs_candidates.push((l2.pc, l2.elem));
        }
        let witnessed = p.recovered.string_op_sites.contains(&l1.pc)
            && l2.map_or(true, |l2| p.recovered.string_op_sites.contains(&l2.pc));
        if !witnessed {
            continue;
        }
        p.arms.string_ops.rep_movs.insert(l1.pc, RepMovs { dst: l1.dst_entry, src: l1.src_entry, set_val, size, cmp_result: None, strlen_result: None });
        if let Some(l2) = l2 {
            p.arms.string_ops.rep_skip.insert(l2.pc);
        }
        // The phi-entry COPYs (`pxVar6 = pTemp; iVar4 = 0x4000; ...`) become dead assignments once
        // the call reads the entry values directly; suppress those used only by their phi, so the
        // recompile sees exactly the source's `memcpy(dst, src, n)` and allocates like the original.
        let mut entries = vec![(l1.dst_phi, l1.dst_entry), (l1.count_phi, l1.count_entry)];
        if let (Some(sp), Some(se)) = (l1.src_phi, l1.src_entry) {
            entries.push((sp, se));
        }
        if let Some(l2) = l2 {
            entries.push((l2.count_phi, l2.count_entry));
        }
        for (phi, entry) in entries {
            let Some(pd) = f.vn(phi).def else { continue };
            let raw = f.op(pd).inrefs.iter().copied().find(|&i| phi_entry_source(f, i, pd) == entry || i == entry);
            let Some(raw) = raw else { continue };
            for cd in phi_entry_chain(f, raw, pd) {
                p.suppressed.insert(cd);
            }
        }
    }
    // memcmp: a lifted `REPE CMPS` — at one pc, LOAD a / LOAD b, `INT_LESS(a,b)` (CF) and
    // `INT_EQUAL(a,b)` (ZF, the loop condition); after the loop Watcom's intrinsic materializes
    // `r = ZF ? 0 : (CF ? -1 : 1)` as `XOR EAX,EAX; …; JZ; SBB EAX,EAX; SBB EAX,-1`, which
    // Ghidra prints `r = 0; … if (!zf) r = 1 - cf - (cf != 0);`. Render `r = memcmp(a, b, n);`
    // at the loop and skip the if-node (docs/rep-string-intrinsic-arm.md V2).
    for op in f.op_ids() {
        let o = f.op(op);
        if o.is_dead() || o.code() != OpCode::IntEqual {
            continue;
        }
        let pc = o.seqnum.pc.offset;
        let (Some(la), Some(lb), Some(zf)) = (o.input(0), o.input(1), o.output) else { continue };
        let load_of = |v: VarnodeId| -> Option<(VarnodeId, u32)> { rep_load_at(f, v, pc) };
        let (Some((a_phi, elem)), Some((b_phi, _))) = (load_of(la), load_of(lb)) else { continue };
        // the CF compare on the same two loads at this pc
        let cf = f.op_ids().find_map(|c| {
            let co = f.op(c);
            (!co.is_dead() && co.code() == OpCode::IntLess && co.seqnum.pc.offset == pc
                && co.input(0) == Some(la) && co.input(1) == Some(lb)).then(|| co.output).flatten()
        });
        let Some(cf) = cf else { continue };
        let (Some(a_entry), Some(b_entry)) = (rep_loop_entry(f, a_phi, pc), rep_loop_entry(f, b_phi, pc)) else { continue };
        let Some((count_phi, count_entry)) = rep_count(f, pc) else { continue };
        // exit phis (not at the loop pc) merging the loop's flag phi with the compare result
        let exit_phi = |flag: VarnodeId| -> Option<VarnodeId> {
            f.op_ids().find_map(|m| {
                let mo = f.op(m);
                (!mo.is_dead() && mo.code() == OpCode::Multiequal && mo.seqnum.pc.offset != pc
                    && mo.inrefs.contains(&flag)).then(|| mo.output).flatten()
            })
        };
        let (Some(cf_exit), Some(zf_exit)) = (exit_phi(cf), exit_phi(zf)) else { continue };
        // the result phi: MULTIEQUAL(0, r1) with r1 the SBB chain over cf_exit
        let mut found: Option<(VarnodeId, Vec<OpId>, OpId)> = None;
        for m in f.op_ids() {
            let mo = f.op(m);
            if mo.is_dead() || mo.code() != OpCode::Multiequal || mo.num_inputs() != 2 {
                continue;
            }
            let (Some(i0), Some(i1), Some(out)) = (mo.input(0), mo.input(1), mo.output) else { continue };
            for (zero, r1) in [(i0, i1), (i1, i0)] {
                let z = strip_copies(f, zero);
                if !(f.vn(z).is_constant() && f.vn(z).constant_value() == 0) {
                    continue;
                }
                if let Some(chain) = rep_cmp_chain(f, r1, cf_exit) {
                    // the zero COPY feeding the phi (to suppress)
                    if let Some(zd) = f.vn(zero).def {
                        found = Some((out, chain, zd));
                    }
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }
        let Some((result, chain, zero_copy)) = found else { continue };
        // the `if (!zf)` branch on the exit flag
        let Some(cbr) = f.vn(zf_exit).descend.iter().copied().find(|&u| !f.op(u).is_dead() && f.op(u).code() == OpCode::Cbranch) else { continue };
        // safety: the flags feed only this structure; the pointers are dead after the loop
        let uses_ok = f.vn(zf_exit).descend.iter().all(|&u| f.op(u).is_dead() || u == cbr)
            && f.vn(cf_exit).descend.iter().all(|&u| f.op(u).is_dead() || chain.contains(&u));
        if !uses_ok {
            continue;
        }
        let ptr_dead = [a_phi, b_phi].iter().all(|&ph| {
            f.vn(ph).descend.iter().all(|&u| {
                let uo = f.op(u);
                uo.is_dead() || uo.seqnum.pc.offset == pc
                    || (uo.code() == OpCode::Multiequal && uo.output.is_some_and(|x| f.vn(x).descend.iter().all(|&w| f.op(w).is_dead())))
            })
        });
        if !ptr_dead {
            continue;
        }
        p.report.rep_movs_candidates.push((pc, elem));
        if !p.recovered.string_op_sites.contains(&pc) {
            continue;
        }
        let size = match strip_copies(f, count_entry) {
            c if f.vn(c).is_constant() => RepSize::Const(f.vn(c).constant_value() * elem as u64),
            c if elem == 1 => RepSize::Var(c),
            c => RepSize::Split(c, c),
        };
        p.arms.string_ops.rep_movs.insert(pc, RepMovs { dst: a_entry, src: Some(b_entry), set_val: None, size, cmp_result: Some(result), strlen_result: None });
        p.arms.string_ops.rep_skip.insert(f.op(cbr).seqnum.pc.offset);
        for &c in &chain {
            p.arms.string_ops.rep_skip.insert(f.op(c).seqnum.pc.offset);
            p.suppressed.insert(c);
        }
        // pre-loop inits: the result's zero, the flag phis' entries, the pointer/count entries
        if f.op(zero_copy).code() == OpCode::Copy {
            p.suppressed.insert(zero_copy);
        }
        let mut entries = vec![(a_phi, a_entry), (b_phi, b_entry), (count_phi, count_entry)];
        for flag in [cf, zf] {
            // the loop flag phi is the MULTIEQUAL at pc whose inrefs contain the compare result
            if let Some(fp) = f.op_ids().find(|&m| { let mo = f.op(m); !mo.is_dead() && mo.code() == OpCode::Multiequal && mo.seqnum.pc.offset == pc && mo.inrefs.contains(&flag) }) {
                if let Some(fo) = f.op(fp).output {
                    let other = f.op(fp).inrefs.iter().copied().find(|&i| i != flag);
                    if let Some(e) = other {
                        entries.push((fo, e));
                    }
                }
            }
        }
        for (phi, entry) in entries {
            let Some(pd) = f.vn(phi).def else { continue };
            let raw = f.op(pd).inrefs.iter().copied().find(|&i| phi_entry_source(f, i, pd) == entry || i == entry);
            let Some(raw) = raw else { continue };
            for cd in phi_entry_chain(f, raw, pd) {
                p.suppressed.insert(cd);
            }
        }
    }
    // strlen: a lifted `REPNE SCASB` seeded with `ECX = -1`, `AL = 0` — at one pc, a 1-byte
    // `LOAD p`, `INT_NOTEQUAL(byte, 0)` as the loop-continue CBRANCH and the count's
    // `INT_EQUAL(cnt, 0)` exit; after the loop Watcom's `strlen` template materializes the
    // length as `NOT ECX; DEC ECX` = `~cnt - 1` over the exit count (a MULTIEQUAL of the count
    // phi and its decrement). Render `r = strlen(s);` at the loop — where the original computed
    // it — and suppress the chain; a bare `~cnt` reader is `r = strlen(s) + 1;`. An implied
    // (single-use) result renders `strlen(s)` at its use instead. Value guard: the chain sits in
    // the loop's exit block with no CALL/STORE before it and nothing between reading the
    // result's variable (docs/rep-string-intrinsic-arm.md V3).
    for op in f.op_ids() {
        let o = f.op(op);
        if o.is_dead() || o.code() != OpCode::IntNotequal {
            continue;
        }
        let pc = o.seqnum.pc.offset;
        let (Some(lv), Some(k), Some(cond)) = (o.input(0), o.input(1), o.output) else { continue };
        if !(f.vn(k).is_constant() && f.vn(k).constant_value() == 0) {
            continue;
        }
        let Some((ptr_phi, elem)) = rep_load_at(f, lv, pc) else { continue };
        if elem != 1 {
            continue;
        }
        if !f.vn(cond).descend.iter().any(|&u| !f.op(u).is_dead() && f.op(u).code() == OpCode::Cbranch && f.op(u).seqnum.pc.offset == pc) {
            continue;
        }
        let Some(ptr_entry) = rep_loop_entry(f, ptr_phi, pc) else { continue };
        let Some((count_phi, count_entry)) = rep_count(f, pc) else { continue };
        let ce = strip_copies(f, count_entry);
        if !(f.vn(ce).is_constant() && f.vn(ce).constant_value() == 0xffff_ffff) {
            continue;
        }
        // the exit count: a MULTIEQUAL outside the loop merging the count phi with its decrement
        let Some(cnt_exit) = f.op_ids().find_map(|m| {
            let mo = f.op(m);
            (!mo.is_dead() && mo.code() == OpCode::Multiequal && mo.seqnum.pc.offset != pc && mo.inrefs.contains(&count_phi)).then(|| mo.output).flatten()
        }) else { continue };
        let readers: Vec<OpId> = f.vn(cnt_exit).descend.iter().copied().filter(|&u| !f.op(u).is_dead()).collect();
        if readers.len() != 1 || f.op(readers[0]).code() != OpCode::IntNegate {
            continue;
        }
        let neg = readers[0];
        let Some(neg_out) = f.op(neg).output else { continue };
        let neg_uses: Vec<OpId> = f.vn(neg_out).descend.iter().copied().filter(|&u| !f.op(u).is_dead()).collect();
        let is_dec1 = |u: OpId| -> bool {
            let uo = f.op(u);
            uo.code() == OpCode::IntSub && uo.input(0) == Some(neg_out)
                && uo.input(1).is_some_and(|c| f.vn(c).is_constant() && f.vn(c).constant_value() == 1)
                && uo.output.is_some()
        };
        // the length is the `- 1` chain's value when one exists; readers of the bare negate
        // beside it print `r + 1`, duplicate `- 1` chains print `r` (one evaluation)
        let subs: Vec<OpId> = neg_uses.iter().copied().filter(|&u| is_dec1(u)).collect();
        let others = neg_uses.len() - subs.len();
        // The value the arm names is always the LENGTH (what `NOT; DEC` leaves in ECX). Ghidra
        // folded the source's constants into the template's `DEC` (`if (len != 0)` became
        // `~cnt != 1`, `p + len - 1` became `p + ~cnt - 2`), so every reader of the bare negate
        // is `len + 1` with its constant re-adjusted (`strlen_fold`) — the inverse of that fold.
        let (result, addend, chain): (VarnodeId, i64, Vec<OpId>) = match subs.first() {
            Some(&u) => (f.op(u).output.unwrap(), 0, std::iter::once(neg).chain(subs.iter().copied()).collect()),
            None if neg_uses.is_empty() => continue,
            None => (neg_out, 0, vec![neg]),
        };
        let mut aliases: Vec<(VarnodeId, i64)> = Vec::new();
        if subs.is_empty() || others > 0 {
            aliases.push((neg_out, 1));
        }
        for &u in subs.iter().skip(1) {
            if let Some(o) = f.op(u).output {
                aliases.push((o, 0));
            }
        }
        // value guard
        let Some(exit_def) = f.vn(cnt_exit).def else { continue };
        let last = *chain.last().unwrap();
        let Some(bid) = f.op(last).parent else { continue };
        if f.op(exit_def).parent != Some(bid) {
            continue;
        }
        let ops = f.block(bid).ops.clone();
        let Some(end) = ops.iter().position(|&x| x == last) else { continue };
        let result_high = p.h.high(result);
        let mut ok = true;
        for &x in &ops[..end] {
            let xo = f.op(x);
            // phis are not statements: the exit MULTIEQUAL's inputs share the result's
            // variable when the negate assigns into the count itself (`cnt = ~cnt`, 0x4a330)
            if xo.is_dead() || chain.contains(&x) || matches!(xo.code(), OpCode::Multiequal | OpCode::Indirect) {
                continue;
            }
            if matches!(xo.code(), OpCode::Call | OpCode::Callind | OpCode::Callother | OpCode::Store) {
                ok = false;
                break;
            }
            if (0..xo.num_inputs()).any(|i| xo.input(i).is_some_and(|iv| !f.vn(iv).is_constant() && p.h.high(iv) == result_high)) {
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }
        // the scanned pointer is dead after the loop
        let ptr_dead = f.vn(ptr_phi).descend.iter().all(|&u| {
            let uo = f.op(u);
            uo.is_dead() || uo.seqnum.pc.offset == pc
                || (uo.code() == OpCode::Multiequal && uo.output.is_some_and(|x| f.vn(x).descend.iter().all(|&w| f.op(w).is_dead())))
        });
        if !ptr_dead {
            continue;
        }
        p.report.rep_movs_candidates.push((pc, 1));
        if !p.recovered.string_op_sites.contains(&pc) {
            continue;
        }
        // one evaluation: a result read more than once is named and assigned at the loop
        // (`force_explicit`, the printer's own naming decision); a single implied use inlines
        // a result with no printable reader (0x2bb10: the length is a hidden third call
        // argument the recovered prototype lacks) stays an explicit statement, as the loop was
        let uses = f.vn(result).descend.iter().filter(|&&u| !f.op(u).is_dead()).count();
        if uses != 1 || !aliases.is_empty() {
            p.force_explicit.insert(result);
        } else if !p.is_explicit(result) {
            p.strlen_exprs.insert(result, (ptr_entry, addend));
        }
        for (v, add) in aliases {
            p.strlen_alias.insert(v, (result, add));
        }
        p.arms.string_ops.rep_movs.insert(pc, RepMovs { dst: ptr_entry, src: None, set_val: None, size: RepSize::Const(0), cmp_result: None, strlen_result: Some((result, addend)) });
        for &c in &chain {
            p.suppressed.insert(c);
        }
        for (phi, entry) in [(ptr_phi, ptr_entry), (count_phi, count_entry)] {
            let Some(pd) = f.vn(phi).def else { continue };
            let raw = f.op(pd).inrefs.iter().copied().find(|&i| phi_entry_source(f, i, pd) == entry || i == entry);
            let Some(raw) = raw else { continue };
            for cd in phi_entry_chain(f, raw, pd) {
                p.suppressed.insert(cd);
            }
        }
    }
}
}

/// The arm's state: its configuration and its witness maps, one place (review R2, commit 7).
#[derive(Debug, Default)]
pub(crate) struct State {
    /// `string-ops=intrinsic` is on for this function.
    pub(crate) intrinsic: bool,
    /// The recognized loops, keyed by the FIRST loop's instruction pc — what to render as
    /// `memcpy`/`memset`/`memcmp`/`strlen`.
    pub(crate) rep_movs: HashMap<u64, RepMovs>,
    /// The pcs of every op a collapsed string op covers (the pair's byte loop, memcmp's result
    /// block): a node made only of these emits nothing.
    pub(crate) rep_skip: HashSet<u64>,
}

impl State {
    pub(crate) fn new(choices: &EmitChoices) -> Self {
        State { intrinsic: choices.string_ops == StringOps::Intrinsic, ..Default::default() }
    }
}
