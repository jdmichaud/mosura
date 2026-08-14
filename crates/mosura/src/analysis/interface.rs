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
/// Recover every prototype repeatedly, until a round changes nothing or `max_rounds` is spent.
///
/// One round is not enough, and the single-round version's own note said so — "whether a further
/// round moves anything is a measurement, not an assumption". It moves things, and the direction is
/// the damaging one: a callee's parameter recovery IMPROVES once its own callees' prototypes are
/// known, so a snapshot taken before any prototypes exist is systematically too narrow. Propagating
/// that snapshot then DELETES real arguments at every call site, because a propagated list replaces
/// the call-site scan rather than merging with it.
///
/// Measured on WAR2's `FUN_0004c978`: round one recovers `[register+0x0/2]` — one two-byte
/// parameter — while the same function decompiled with prototypes available recovers
/// `register+0x0/4, register+0x8/4`. Its caller `FUN_00049284` is byte-exact without the pass and
/// loses its second argument (`MOV EDX,0x4921c`) with it, purely because the stale narrow list was
/// propagated.
///
/// Termination is by fixpoint with a hard bound, not by hope: each round is compared to the last
/// and the loop stops when they agree. A bound is still required because nothing guarantees the
/// sequence is monotone — mutually recursive functions can oscillate — and a decompiler that
/// sometimes does not terminate is worse than one that is occasionally one round short.
pub fn recover_prototypes_iterated(program: &mut Program, max_rounds: usize) -> usize {
    for round in 1..=max_rounds {
        let next = recover_prototypes(program);
        let same = next.len() == program.recovered_protos.len()
            && next.iter().all(|(k, v)| {
                program.recovered_protos.get(k).is_some_and(|p| p.params == v.params && p.output == v.output)
            });
        program.recovered_protos = next;
        if same {
            return round;
        }
    }
    max_rounds
}

pub fn recover_prototypes(program: &Program) -> HashMap<u64, FuncProto> {
    let entries: Vec<u64> = program.function_manager.functions().map(|f| f.entry.offset).collect();
    let ram = program.default_space;
    let mut out = HashMap::with_capacity(entries.len());
    for entry in entries {
        let Some(f) = super::decompiler::decompile_function(program, crate::decompile::space::Address::new(ram, entry))
        else {
            continue;
        };
        out.insert(entry, prototype_of(&f));
    }
    out
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
    FuncProto { params, output }
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
