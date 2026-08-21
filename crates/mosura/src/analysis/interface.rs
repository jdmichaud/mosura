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

fn recover_prototypes_of(program: &Program, entries: Vec<u64>) -> HashMap<u64, FuncProto> {
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
