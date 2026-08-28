//! Ghidra `ActionSetCasts` (coreaction.cc:2722): insert real `CPUI_CAST` ops so the C printer
//! renders `(type)expr` wherever a value's committed type and the type an operation naturally
//! produces (or requires) diverge. This is the IR-CAST-op model — casts are ops in the graph (they
//! block type propagation through the no-op [`super::infertypes`] `propagate_type(Cast)`), not a
//! print-time decision.
//!
//! Ghidra runs this action DEAD-LAST (coreaction.cc:5735), after `ActionMarkImplied`
//! (coreaction.cc:5720) has settled `Varnode::isImplied`. mosura runs it as the final pipeline
//! action (after the Stage-0c final `ActionInferTypes`), reading the `ActionMarkImplied`
//! classification via [`super::merge::implied_classification`].
//!
//! Ported: [`cast_input`] — Ghidra `castInput` (coreaction.cc:2655), the operand-side cast (moved
//! out of printc's render-time `cast_operand`); and [`cast_output`] — Ghidra `castOutput`
//! (coreaction.cc:2532), the def-side cast. castOutput renders the pointercmp
//! `(xunknown1 *)(param_1 + 8)`: a loop phi back-relayed a pointer type onto an `INT_ADD` whose
//! natural (input-derived) token type is `int8`, so a `CPUI_CAST` splits the int arithmetic result
//! from the pointer value it is assigned to. Input casts run first (coreaction.cc:2757, "output may
//! depend on input").
//!
//! ⚠️ THE REMAINDER IS FOUR SEPARATE ITEMS WITH FOUR DIFFERENT ANSWERS, and they were previously
//! recorded as one line ("deferred with the composite/union lattice they concern"). That single
//! sentence was doing what an inherited gate always does — making an unexamined claim look settled.
//! Grounded read-only at `13bd6e1`:
//!
//! · `resolveUnion` (coreaction.cc:2755) — **GENUINELY GATED.** It resolves a `TypeUnion` field
//!   against the accessing op; mosura's lattice has no union type at all, so there is nothing to
//!   resolve and no way to write the port. This one really does land with the union lattice.
//!
//! · `checkPointerIssues` (LOAD/STORE, coreaction.cc:2765) — **NOT GATED, AND MEASURED INERT.** It is
//!   NOT a lattice consumer: it mutates no IR and inserts no cast, it only calls `data.warning()` for
//!   a LOAD/STORE whose pointer type disagrees with the accessed size or address space. Everything it
//!   needs (`Pointer`, `getPtrTo()->getSize()`) mosura already has. But over all 1286 WAR2 functions,
//!   Ghidra's own output contains **zero** of either warning it can emit — no "Load/Store size is
//!   inaccurate", no "refers to '<space>' but pointer attribute is '<space>'". Porting it would add
//!   code that provably does nothing on our target. Recorded as a certificate rather than built.
//!   REVIVAL CONDITION: a target where those warnings appear in Ghidra's output.
//!
//! · PTRADD refit (`opUndoPtradd`, coreaction.cc:2740) — ⭐ **MEASURED: NOT GATED, AND NOT INERT.
//!   THIS IS A LIVE UNPORTED GAP.** `MOSURA_PTRFIT=1` over all 1303 WAR2 functions: **3371
//!   PTRADD/PTRSUB ops reach this action (2835 + 536), and 59 PTRADDs meet Ghidra's refit guard** —
//!   its pointee size differs from the element-size constant, so Ghidra undoes the PTRADD back to
//!   plain arithmetic while mosura keeps it and renders pointer arithmetic instead.
//!   **AND NOT ONE OF THE 59 NEEDS THE COMPOSITE LATTICE.** Every one is a pointer to a PRIMITIVE or
//!   not a pointer at all: `Pointer(4,Int..)` x34, `Pointer(4,Uint..)` x18, `Pointer(4,Unknown..)`
//!   x4, bare `Unknown(4)` x3. The recorded reason for deferring it was wrong on both counts.
//!
//! · PTRSUB refit (:2748) — reach is 536 ops, but the VERDICT still needs `isPtrsubMatching`, whose
//!   sub-field walk is a genuine composite-lattice consumer. Reach measured; gating not settled.
//!   Do not assume it follows the PTRADD answer.

use super::action::Action;
use super::block::BlockId;
use super::cast::{cast_standard, input_cast, output_token};
use super::funcdata::Funcdata;
use super::merge::high_type_read_facing;
use super::op::{OpId, SeqNum};
use super::opcode::OpCode;
use super::types::Datatype;
use super::varnode::VarnodeId;

/// Ghidra `ActionSetCasts`.
#[derive(Default)]
pub struct ActionSetCasts;

impl Action for ActionSetCasts {
    fn name(&self) -> &str {
        "setcasts"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        // Skip during the jump-table recovery probe (build.rs `partial.table_recovery_probe`): the
        // inserted casts are a render-only transform, and casting the switch-index def perturbs the
        // dataflow `recover_staged` reads to extract the table — under-recovering the switch, exactly
        // as the late branch-orientation is skipped here (see `table_recovery_probe`, structure.rs).
        if data.table_recovery_probe {
            return 0;
        }
        apply(data);
        // Ghidra `ActionSetCasts::apply` returns 0 ("Indicate full completion"): the inserted casts
        // are render-only and must not drive any mainloop fixpoint (this action is dead-last anyway).
        0
    }
}

/// `MOSURA_PTRFIT=1` — count the PTRADD/PTRSUB ops reaching `ActionSetCasts` and how many meet
/// Ghidra's refit guard. READ-ONLY: it evaluates the condition and prints, it never refits.
///
/// This exists because the refits were filed as "gated on the composite lattice" and that was an
/// unmeasured claim. The cheapest discriminator is not the guard's semantics at all — it is whether
/// any PTRADD/PTRSUB even SURVIVES to this action, which runs dead-last. A zero count settles the
/// question without modelling `getAlignSize`/`isPtrsubMatching` at all.
///
/// Every row carries the FUNCTION NAME. A bare count cannot answer the only question a gate asks —
/// *which* functions does this reach — and AGENT.md's standing rule is that a per-specimen
/// instrument must filter by function or the operator must. Without the name the 59 misfitting
/// PTRADDs could not be intersected with the byte-clean set, which is the pre-check that decides
/// whether the refit can regress a byte-exact function.
fn ptrfit_probe(data: &Funcdata, op: OpId) {
    let o = data.op(op);
    match o.code() {
        OpCode::Ptradd => {
            // Ghidra coreaction.cc:2740 — refit unless in0 is a pointer whose pointee size equals
            // the element-size constant in slot 2 (wordSize is 1 on every space mosura loads, so
            // `addressToByteInt` is the identity, and `getAlignSize() == getSize()` for every type
            // mosura models: the base `Datatype` constructor sets `alignSize = s`, type.hh:215, and
            // only composites — which mosura has no metatype for — can round it up).
            let ct = high_type_read_facing(data, o.input(0).unwrap());
            let sz = data.vn(o.input(2).unwrap()).constant_value();
            let fits = matches!(&ct, Datatype::Pointer(_, pt) if pt.size() as u64 == sz);
            // Both CHANNELS, because they answer different questions and the difference is the
            // whole reason `RulePtraddUndo` reaches sites this refit does not. Ghidra reads
            // `getTypeReadFacing` (the VARNODE's type) in the mainloop rule and
            // `getHighTypeReadFacing` (the merged HIGHVARIABLE's) here — not as a choice, but
            // because HighVariables DO NOT EXIST during the mainloop (`Funcdata::highs` is None
            // until `ActionMergeType`, and reading it earlier panics by construction). So a row
            // where the two disagree is a site where MERGING changed the verdict.
            let vt = data.vn(o.input(0).unwrap()).get_type();
            let vt_fits = matches!(&vt, Datatype::Pointer(_, pt) if pt.size() as u64 == sz);
            let chan = if vt_fits == fits { "same" } else { "CHANNELS_DISAGREE" };
            debug!(crate::debug::Topic::Pointers,
                "ptrfit\t{}\tptradd\tfits={fits}\tvn_fits={vt_fits}\t{chan}\telem_sz={sz}\tptr={ct:?}\tvn_ty={vt:?}",
                data.name
            );
        }
        OpCode::Ptrsub => {
            // coreaction.cc:2748 — refit unless in0's type accepts the slot-1 offset as a sub-field.
            // Only the pointer-metatype half is evaluated here; `isPtrsubMatching`'s sub-field walk
            // needs the composite lattice, so a `ptr_off0=false` row is REACH, not a verdict.
            let ct = high_type_read_facing(data, o.input(0).unwrap());
            let off = data.vn(o.input(1).unwrap()).constant_value();
            debug!(crate::debug::Topic::Pointers, "ptrfit\t{}\tptrsub\tis_ptr={}\toff={off}\tty={ct:?}", data.name, ct.is_pointer());
        }
        _ => {}
    }
}

fn ptrfit_probe_on() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| crate::debug::on(crate::debug::Topic::Pointers))
}

fn apply(data: &mut Funcdata) {
    // Ghidra reads `Varnode::isImplied`, set by `ActionMarkImplied` just before this action.
    let implied = super::merge::implied_classification(data);
    // "We follow data flow, doing basic blocks in dominance order, operations in basic block order"
    // (coreaction.cc:2730). A per-block op snapshot: casts inserted before/after the current op are
    // skipped by Ghidra anyway (`opc == CPUI_CAST` continue), so not revisiting them is equivalent.
    for b in 0..data.num_blocks() {
        let ops: Vec<OpId> = data.block(BlockId(b as u32)).ops.clone();
        for op in ops {
            let o = data.op(op);
            // `if (op->notPrinted()) continue;` — markers (MULTIEQUAL/INDIRECT) and dead ops don't
            // print, so they take no casts; and skip an existing CAST (`opc == CPUI_CAST`).
            if o.is_marker() || o.is_dead() || o.code() == OpCode::Cast {
                continue;
            }
            // `MOSURA_PTRFIT=1` still measures the guard for BOTH ops (the PTRSUB refit is not
            // ported), and it runs BEFORE the refit below so its rows describe the input IR.
            if ptrfit_probe_on() {
                ptrfit_probe(data, op);
            }
            // "Check for PTRADD that no longer fits its pointer" (coreaction.cc:2740). A PTRADD
            // carries the element size it was built with in slot 2; if the base's type has since
            // become something else — not a pointer at all, or a pointer to a differently-sized
            // type — the op is scaling by a stride its own operand no longer has, so Ghidra undoes
            // it to plain integer arithmetic rather than render a lie.
            //
            // `getAlignSize()` is `getSize()` for every type mosura models (the base `Datatype`
            // constructor sets `alignSize = s`, type.hh:215; only composites round it up, and there
            // is no composite metatype here), and `addressToByteInt(sz, wordSize)` is the identity
            // because `wordSize` is 1 on every space mosura loads. So the guard below is Ghidra's,
            // not a simplification of it.
            if data.op(op).code() == OpCode::Ptradd {
                let ct = high_type_read_facing(data, data.op(op).input(0).unwrap());
                let sz = data.vn(data.op(op).input(2).unwrap()).constant_value();
                let fits = matches!(&ct, Datatype::Pointer(_, pt) if pt.size() as u64 == sz);
                if !fits {
                    data.op_undo_ptradd(op, true);
                }
            }
            // "Do input casts first, as output may depend on input" (coreaction.cc:2757): a castInput
            // that casts an operand changes the type castOutput's `getOutputToken` then reads.
            for slot in 0..data.op(op).num_inputs() {
                cast_input(data, op, slot, &implied);
            }
            if data.op(op).output.is_some() {
                cast_output(data, op, &implied);
            }
        }
    }
}

/// Ghidra `ActionSetCasts::castInput` (coreaction.cc:2655): if op input `slot` requires a type its
/// value does not already satisfy ([`input_cast`], = Ghidra `getInputCast`), insert a `CPUI_CAST`
/// before the op so the operand renders `(type)expr`. This is the operand-side cast mosura used to
/// apply at render time (printc `cast_operand`); moved here it becomes a real IR op, and printc
/// renders the CAST instead of wrapping. The `markExplicitUnsigned`/`markExplicitLongSize` print
/// concerns (Ghidra's `ct == null` branch) stay in printc — they are not CAST insertions.
fn cast_input(f: &mut Funcdata, op: OpId, slot: usize, implied: &[bool]) {
    let Some(ct) = input_cast(f, op, slot) else {
        return; // no cast required (markExplicitUnsigned/LongSize handled at print time)
    };
    let vn = f.op(op).input(slot).unwrap();
    // Guard against chains of casts (coreaction.cc:2672): if the operand is already an implied CAST
    // feeding only this op, retype it or read directly from the earlier cast's input.
    if f.vn(vn).is_written() && f.op(f.vn(vn).def.unwrap()).code() == OpCode::Cast {
        if is_implied(implied, vn) {
            let def = f.vn(vn).def.unwrap();
            if lone_descend(f, vn) == Some(op) {
                f.vn_mut(vn).update_type(ct.clone());
                if f.vn(vn).get_type() == ct {
                    return;
                }
            }
            let vnin = f.op(def).input(0).unwrap();
            if f.vn(vnin).get_type() == ct {
                f.op_set_input(op, slot, vnin); // reuse the earlier Varnode
                return;
            }
        }
    } else if f.vn(vn).is_constant() {
        // A constant literal simply adopts the required type (no CAST op) — Ghidra coreaction.cc:2687,
        // and mosura's existing "constants aren't wrapped" print rule.
        f.vn_mut(vn).update_type(ct.clone());
        if f.vn(vn).get_type() == ct {
            return;
        }
    }
    // (testStructOffset0 → insertPtrsubZero and tryResolutionAdjustment deferred — no composites/unions.)
    // Insert: `vnout(ct) = CAST(vn)`; op reads vnout at `slot` (coreaction.cc:2702).
    let sz = f.vn(vn).size;
    let seq = SeqNum { pc: f.op(op).seqnum.pc, uniq: 0 };
    let newop = f.new_op(OpCode::Cast, seq, vec![vn]);
    let vnout = f.new_output_unique(newop, sz);
    f.vn_mut(vnout).update_type(ct);
    f.vn_mut(vnout).set_implied();
    f.op_set_input(op, slot, vnout);
    f.op_insert_before(newop, op); // the cast comes before the operation
}

/// Ghidra `ActionSetCasts::castOutput` (coreaction.cc:2532): if the op's natural output token type
/// ([`output_token`]) differs from the committed type of its output value, insert a `CPUI_CAST` on
/// the def side — the arithmetic result keeps the token type, and a CAST produces the committed
/// (assigned) type. Returns nothing; mutates the graph in place.
fn cast_output(f: &mut Funcdata, op: OpId, implied: &[bool]) {
    let tokenct = output_token(f, op);
    let outvn = f.op(op).output.unwrap();
    let out_high = high_type_read_facing(f, outvn);
    if tokenct == out_high {
        // Short-circuit: same type, no cast (union `needsResolution` handling deferred — no unions).
        return;
    }
    let mut out_resolve = out_high;
    let mut force = false;
    if is_implied(implied, outvn) {
        // Ghidra `outvn->isImplied()`: an implied varnode has no declaration, so it can adopt the
        // token type inline instead of taking a cast.
        if f.vn(outvn).is_typelock() {
            // A type-locked implied varnode: force a cast unless it is the input to a RETURN (which
            // casts as if explicit). `isOpIdentical` reduces to type-equality in the primitive
            // lattice (no typedef/union chains).
            let lone = lone_descend(f, outvn);
            let feeds_return = lone.map(|d| f.op(d).code() == OpCode::Return).unwrap_or(false);
            if !feeds_return {
                force = out_resolve != tokenct;
            }
        } else if !matches!(out_resolve, Datatype::Pointer(..)) {
            // Implied atomic (non-pointer): ignore the committed type in favor of the token.
            f.vn_mut(outvn).update_type(tokenct.clone());
            out_resolve = high_type_read_facing(f, outvn);
        } else if matches!(tokenct, Datatype::Pointer(..)) {
            // Implied pointer AND pointer token: adopt the token unless the committed pointer points
            // to a composite (array/struct/union), which is preserved.
            if let Datatype::Pointer(_, pt) = &out_resolve {
                let composite = matches!(**pt, Datatype::Array(..) | Datatype::Struct(..));
                if !composite {
                    f.vn_mut(outvn).update_type(tokenct.clone());
                    out_resolve = high_type_read_facing(f, outvn);
                }
            }
        }
        // (Implied pointer with a NON-pointer token — the pointercmp case — takes none of these
        // arms, so it falls through and a real cast is inserted below.)
    }
    if !force {
        // `testStructOffset0` (→ PTRSUB) deferred with the struct/union lattice; always CPUI_CAST.
        if cast_standard(&out_resolve, &tokenct, false, true).is_none() {
            return; // C reconciles these silently — no cast
        }
    }
    // Generate the cast op: `vn(token) = op(...)`; `outvn = CAST(vn)`. Mirrors coreaction.cc:2594.
    let sz = f.vn(outvn).size;
    let vn = f.new_unique(sz);
    f.vn_mut(vn).update_type(tokenct);
    f.vn_mut(vn).set_implied();
    let seq = SeqNum { pc: f.op(op).seqnum.pc, uniq: 0 };
    let newop = f.new_op(OpCode::Cast, seq, vec![vn]);
    f.op_set_output(newop, outvn); // CAST writes the original output value
    f.op_set_output(op, vn); // the op now writes the token-typed unique
    f.op_insert_after(newop, op); // "Cast comes AFTER this operation"
}

/// The `ActionMarkImplied` classification for `v`, bounds-safe: varnodes created by this action
/// (CAST outputs, past the precomputed array) are set implied explicitly, so an out-of-range index
/// is treated as not-classified-here (`false`) — those cases never reach the implied-only arms.
fn is_implied(implied: &[bool], v: VarnodeId) -> bool {
    implied.get(v.0 as usize).copied().unwrap_or(false)
}

/// Ghidra `Varnode::loneDescend` (varnode.cc): the single op reading this varnode, or `None` when it
/// has zero or multiple readers.
fn lone_descend(f: &Funcdata, v: super::varnode::VarnodeId) -> Option<OpId> {
    let d = &f.vn(v).descend;
    if d.len() == 1 {
        Some(d[0])
    } else {
        None
    }
}
