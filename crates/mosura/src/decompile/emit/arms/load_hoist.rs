//! `load-hoist` — an explicitness swap. When a load's address is a pointer temp into an array
//! (`puVar4 = auStack_28 + iVar3`) and the loaded value is consumed only AFTER the index has
//! been redefined (`iVar3 = iVar3 + 1; *(..) = *puVar4;`), Ghidra keeps the POINTER explicit
//! and inlines the load at its consumer; this compiler then hoists the array's address into a
//! register (`LEA EBX,[EBP - 0x20]`) and indexes through it (`[EBX + EAX*2]`) where the
//! original loaded the element straight from the frame (`MOV DX,[EBP + EAX*2 - 0x20]`, the subject
//! FUN_0002a75c and its two siblings). The other legal choice makes the VALUE explicit and the
//! pointer implied — `uVar5 = auStack_28[iVar3]; iVar3 = iVar3 + 1; *(..) = uVar5;` — the load
//! at its own position, the subscript folded into the access. Value-identical: the same load
//! at the same point of the same trace. The witness (`recovered.load_hoist.sites`, from
//! `buildconfig::load_hoists_from_evidence` over this arm's `load_hoist_candidates`): the
//! original's instruction at the load's address reads the frame through a scaled index
//! (`[EBP + EAX*0x2 + -0x20]`) and the pointer's own address holds no `LEA` — the element
//! addressed directly, no pointer temp. The recognizer also sees a stepped base pointer
//! (FUN_00022638: `piVar1 = param_1 + 1; param_1 = param_1 + 2; .. - *piVar1`), but the
//! witness declines it: swapped, the value takes a scratch register where the original held it
//! in a callee-saved one (3 downs, no flip, round e21). A target-informed emit choice, NOT
//! Ghidra.
//!
//! The arm is a SETUP pass: it fills the printer's `force_explicit` (the value) and
//! `force_implied` (the pointer) sets, both consulted by `is_explicit`.
use crate::decompile::funcdata::Funcdata;
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;
use crate::decompile::varnode::VarnodeId;

/// The census: every load through an explicit pointer temp whose value is consumed after the
/// pointer's index is redefined — reported, and swapped where witnessed.
pub(crate) fn recognize(pr: &mut PrintC<'_>, f: &Funcdata) {
    let mut swaps: Vec<(VarnodeId, VarnodeId)> = Vec::new();
    for b in f.blocks() {
        let ops: Vec<OpId> = b.ops.clone();
        for (i, &op) in ops.iter().enumerate() {
            let o = f.op(op);
            if o.code() != OpCode::Load || o.is_dead() {
                continue;
            }
            let (Some(p), Some(out)) = (o.input(1), o.output) else { continue };
            // the pointer: an explicit temp defined by PTRADD/INT_ADD of a base and a non-constant index
            if !pr.is_explicit(p) {
                continue;
            }
            let Some(pd) = f.vn(p).def else { continue };
            let po = f.op(pd);
            if !matches!(po.code(), OpCode::Ptradd | OpCode::IntAdd) || po.num_inputs() < 2 {
                continue;
            }
            let (Some(base), Some(idx)) = (po.input(0), po.input(1)) else { continue };
            if f.vn(p).descend.iter().filter(|&&u| !f.op(u).is_dead()).count() != 1 {
                continue;
            }
            // the value chain: implied single-use unary steps up to the consumer
            let mut cur = out;
            let consumer;
            loop {
                if pr.is_explicit(cur) {
                    consumer = None;
                    break;
                }
                let uses: Vec<OpId> = f.vn(cur).descend.iter().copied().filter(|&u| !f.op(u).is_dead()).collect();
                if uses.len() != 1 {
                    consumer = None;
                    break;
                }
                let u = uses[0];
                let uo = f.op(u);
                if matches!(uo.code(), OpCode::IntZext | OpCode::IntSext | OpCode::Cast | OpCode::Copy | OpCode::Subpiece)
                    && uo.output.is_some()
                {
                    cur = uo.output.unwrap();
                    continue;
                }
                consumer = Some(u);
                break;
            }
            let Some(consumer) = consumer else { continue };
            let Some(j) = ops.iter().position(|&x| x == consumer) else { continue };
            if j <= i {
                continue;
            }
            // the base or the index redefined between the load and the consumer (the index
            // advanced under a scaled access, FUN_0002a75c; the base pointer stepped,
            // FUN_00022638's `piVar1 = param_1 + 1; param_1 = param_1 + 2; .. *piVar1`)
            let highs: Vec<u32> = [base, idx]
                .into_iter()
                .filter(|&v| !f.vn(v).is_constant())
                .map(|v| pr.high_of[v.0 as usize])
                .collect();
            let redefined = ops[i + 1..j].iter().any(|&x| {
                !f.op(x).is_dead() && f.op(x).output.is_some_and(|w| highs.contains(&pr.high_of[w.0 as usize]))
            });
            if !redefined {
                continue;
            }
            let pc = o.seqnum.pc.offset;
            pr.report.load_hoist.candidates.push((pc, po.seqnum.pc.offset));
            if pr.recovered.load_hoist.sites.contains(&pc) {
                swaps.push((cur, p));
            }
        }
    }
    for (value, pointer) in swaps {
        pr.force_explicit.insert(value);
        pr.force_implied.insert(pointer);
    }
}

/// The load-hoist's candidates the report pass collects (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Every load through an explicit pointer temp whose value is consumed after the pointer's
    /// base or index is redefined (`load-hoist`), as `(load address, pointer's address)`.
    pub candidates: Vec<(u64, u64)>,
}

/// The load-hoist's witnessed decisions the recovered pass renders (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Sites {
    /// Load addresses whose original reads the element through a scaled index (`load-hoist`,
    /// `load_hoist_candidates` evidence, `buildconfig::load_hoists_from_evidence`).
    pub sites: std::collections::HashSet<u64>,
}
