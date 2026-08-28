//! Whole-program interface recovery: what each function's prototype actually is.
//!
//! Decompiling a function recovers its parameter list and its return storage — and then that
//! answer is thrown away. Every caller re-derives the same callee's interface from trials taken
//! at one call site, with no access to the body that would settle it. When the two disagree the
//! callee is right, because it is the one whose body shows what it reads.
//!
//! The measured cost of not propagating it is arguments that vanish from the emitted C. A caller
//! declares `extern int func_0x0004245c();` — no prototype at all — guesses four arguments from
//! its call site, and drops the fifth, which the callee's own recovery had already found sitting
//! on the stack. The push disappears and the recompiled function is a different program.
//!
//! So: recover every prototype first, then decompile again with the answers available. The pass
//! reads a frozen snapshot rather than iterating to a fixpoint, which keeps it terminating and
//! explainable; whether a further round moves anything is a measurement, not an assumption.
//!
//! See `docs/interface-recovery-plan.md`.

use crate::decompile::fspec::{FuncProto, ProtoSlot, recover_input_params};
use crate::decompile::funcdata::Funcdata;
use std::collections::HashMap;

use super::program::Program;

/// Recover the prototype of every function in the program.
///
/// Costs one decompile per function. A function whose decompile fails contributes nothing rather
/// than an empty prototype — absence must read as "no evidence", since an empty parameter list is
/// itself a claim, and the wrong one.
pub fn recover_prototypes(program: &Program) -> HashMap<u64, FuncProto> {
    let entries: Vec<u64> = program.function_manager.functions().map(|f| f.entry.offset).collect();
    recover_prototypes_of(program, entries)
}

/// [`recover_prototypes`] restricted to `scope` — the probe path (`war2_survey --only`): a
/// probed function's decompile consults `recovered_protos` only at its OWN call sites (lookup
/// by direct static callee VA; an indirect call has no static target to look up), and every
/// other upgrade-gate input comes from the landed world or per-callee lazy caches. So a probe
/// needs exactly the probed functions' direct callees recovered, not the whole program — the
/// whole-program pass was the probe's second ~100s of fixed cost.
pub fn recover_prototypes_for(program: &Program, scope: &std::collections::HashSet<u64>) -> HashMap<u64, FuncProto> {
    let entries: Vec<u64> = program
        .function_manager
        .functions()
        .map(|f| f.entry.offset)
        .filter(|o| scope.contains(o))
        .collect();
    recover_prototypes_of(program, entries)
}

/// The pass to a FIXPOINT, callee-first by construction (Ghidra's Decompiler-Parameter-ID analyzer
/// walks the call graph callee-first; a fixpoint over rounds reaches the same state and needs no
/// cycle breaking): each round decompiles every entry with the previous round's prototypes in
/// `program.recovered_protos`, so a caller's call copies its callee's prototype
/// (`record_callee_effects`) and a PASS-THROUGH function — `l5: call l6; add eax,5; ret`, whose
/// EAX exists only to be handed on — sees its register read as used and resolves its own model.
/// Stops when a round changes nothing (`max_rounds` bounds a pathological program).
pub fn recover_prototypes_fixpoint(program: &mut Program, entries: Vec<u64>, max_rounds: usize) -> usize {
    let key = |m: &HashMap<u64, FuncProto>| -> Vec<(u64, Vec<(u64, u32)>, Option<(u64, u32)>, String)> {
        let mut v: Vec<_> = m
            .iter()
            .map(|(e, p)| {
                (
                    *e,
                    p.params.iter().map(|s| (s.addr.offset, s.size)).collect(),
                    p.output.as_ref().map(|o| (o.addr.offset, o.size)),
                    p.model.as_ref().map(|m| m.name.clone()).unwrap_or_default(),
                )
            })
            .collect();
        v.sort();
        v
    };
    // the struct-return facts and evidence are part of the state the rounds converge on
    let sret_key = |m: &HashMap<u64, super::sret::SretFact>| -> Vec<(u64, Option<(u32, Vec<(u32, u32)>)>, Option<u32>)> {
        let mut v: Vec<_> = m
            .iter()
            .map(|(e, s)| {
                (
                    *e,
                    s.shape.as_ref().map(|sh| (sh.size, sh.fields.iter().map(|&(o, z, _)| (o, z)).collect())),
                    s.ret_pop,
                )
            })
            .collect();
        v.sort();
        v
    };
    let callers_key = |m: &HashMap<u64, Vec<super::sret::CallEvidence>>| -> Vec<(u64, Vec<(bool, bool)>)> {
        let mut v: Vec<_> = m.iter().map(|(e, c)| (*e, c.iter().map(|x| (x.output_dead, x.arg0_local_addr)).collect())).collect();
        v.sort();
        v
    };
    let mut rounds = 0;
    loop {
        let next = recover_pass(program, entries.clone());
        rounds += 1;
        let same = key(&next.protos) == key(&program.recovered_protos)
            && sret_key(&next.sret) == sret_key(&program.recovered_sret)
            && callers_key(&next.callers) == callers_key(&program.sret_callers);
        program.recovered_protos = next.protos;
        program.recovered_sret = next.sret;
        program.sret_callers = next.callers;
        if same || rounds >= max_rounds {
            return rounds;
        }
    }
}

/// The same pass over an explicit list of function entries — for a program whose functions come
/// from elsewhere than the analysis' function manager (the gt oracle's ELF symbol table).
pub fn recover_prototypes_of(program: &Program, entries: Vec<u64>) -> HashMap<u64, FuncProto> {
    recover_pass(program, entries).protos
}

/// One round of the pass: the prototypes, and the hidden struct-return facts and call-site
/// evidence (`analysis::sret`) the same decompilations show.
pub struct ProtoPass {
    pub protos: HashMap<u64, FuncProto>,
    pub sret: HashMap<u64, super::sret::SretFact>,
    pub callers: HashMap<u64, Vec<super::sret::CallEvidence>>,
}

/// The pass over `entries`, recording per function its prototype and its struct-return fact, and
/// per CALLEE what each analyzed call says about it — the two facts the `struct-return` arm's
/// witness needs, carried by the same fixpoint as the prototypes.
pub fn recover_pass(program: &Program, entries: Vec<u64>) -> ProtoPass {
    let ram = program.default_space;
    let mut protos = HashMap::with_capacity(entries.len());
    let mut sret = HashMap::with_capacity(entries.len());
    let mut callers: HashMap<u64, Vec<super::sret::CallEvidence>> = HashMap::new();
    for entry in entries {
        let Some(f) = super::decompiler::decompile_function(program, crate::decompile::space::Address::new(ram, entry))
        else {
            continue;
        };
        protos.insert(entry, prototype_of(&f));
        sret.insert(entry, super::sret::SretFact { shape: super::sret::sret_shape(&f), ret_pop: f.ret_pop });
        let mut calls: Vec<_> = f.call_specs.keys().copied().collect();
        calls.sort();
        for call in calls {
            let Some(t) = f.op(call).input(0) else { continue };
            let target = f.vn(t).loc.offset;
            if target == 0 {
                continue;
            }
            callers.entry(target).or_default().push(super::sret::call_evidence(&f, call));
        }
    }
    ProtoPass { protos, sret, callers }
}

/// The prototype a decompiled function presents: its recovered inputs, and the storage it returns
/// in.
///
/// The return storage width comes from [`Funcdata::output_storage_size`] — recorded when the
/// output trials commit, which is the last point at which the evidence exists, since later stages
/// narrow the Varnode reaching the RETURN.
pub fn prototype_of(f: &Funcdata) -> FuncProto {
    let params = recover_input_params(f);
    let output = return_storage(f);
    FuncProto { params, output, model: crate::decompile::fspec::non_default_model(f) }
}

fn return_storage(f: &Funcdata) -> Option<ProtoSlot> {
    use crate::decompile::opcode::OpCode;
    let ret = f
        .op_ids()
        .find(|&op| !f.op(op).is_dead() && f.op(op).code() == OpCode::Return && f.op(op).num_inputs() > 1)
        .and_then(|op| f.op(op).input(1))?;
    let vn = f.vn(ret);
    Some(ProtoSlot { addr: vn.loc, size: f.output_storage_size.unwrap_or(vn.size).max(vn.size) })
}
