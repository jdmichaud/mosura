//! Per-function RECOVERY — the survey's evidence pipeline as one library function (review R5,
//! commit a): the REPORT PASS (a render under the canonical choices that records every candidate
//! site), the `buildconfig::*_from_evidence` WITNESSES over the function's original instructions,
//! and the SECOND EVIDENCE ROUND (a render under the recovered decisions, re-assessing the
//! candidates that interact). Shared by `war2_survey` (its call site is where this code sat) and
//! the gcc ground-truth oracle (R5 commit b), so both measure the same recovery.
//!
//! Moved verbatim out of war2_survey.rs: the `RecoveredChoices` literal, the second round and the
//! `MOSURA_EMIT_DEBUG` print (an experiment leftover, carried as-is for review R6); the only
//! textual changes are the crate paths (`mosura::` → `crate::`), `&insns` → `insns` (a slice
//! parameter here) and the choices named by their role (`choices` = the canonical arm of the
//! report pass, `rec_choices` = the arm the recovered passes render under). The argument-order
//! derivation is the caller's (`call_arg_orders`): it reads cross-function tables the survey owns
//! and fills the survey's pragma list, so it comes in as a closure over the report.
use crate::decompile::emit::{EmitChoices, ShiftMask};
use crate::decompile::funcdata::Funcdata;
use crate::decompile::emit::arms::registry::Grown;
use crate::decompile::printc::{EmitReport, RecoveredChoices};
use crate::recompile::insn::NormInsn;
use std::collections::HashMap;

/// The recovered per-site decisions for `f`: `insns` its original instructions (normalized),
/// `choices` the canonical arm the report pass renders under, `rec_choices` the arm the recovered
/// passes render under, `call_arg_orders` the caller's argument-order derivation over the report.
pub fn recover(
    f: &Funcdata,
    insns: &[NormInsn],
    choices: &EmitChoices,
    rec_choices: &EmitChoices,
    call_arg_orders: impl FnOnce(&EmitReport) -> HashMap<u64, Vec<usize>>,
) -> RecoveredChoices {
    let (_, report) = crate::decompile::printc::print_c_report(f, choices);
    let call_arg_orders = call_arg_orders(&report);
    let recovered = derive(&report, insns, call_arg_orders.clone());
    // SECOND EVIDENCE ROUND (see print_c_recovered_report): decisions interact — a
    // tier-2 materialization creates the statement-carrying clause cond-form nests —
    // so re-assess candidacy on the rendering the first round produces and merge.
    let (_, report2) =
        crate::decompile::printc::print_c_recovered_report(f, rec_choices, &recovered);
    let mut recovered = recovered;
    recovered.nested_conds.sites.extend(
        crate::recompile::buildconfig::nested_conds_from_evidence(
            &report2.nested_conds.candidates,
            insns,
        ),
    );
    // FIXPOINT CHECK (review F3, 2026-09-04): two rounds is a guess at convergence. In debug
    // builds, or under `MOSURA_RECOVER_FIXPOINT=1`, render once more under the decisions and
    // derive again: a decision the third render INTRODUCES — a site, key or flag the second
    // round does not have — is named on stderr as a specimen instead of silently taking the
    // second round's answer. Growth only: a decision whose candidate the render CONSUMES (a
    // widened local no longer reads as a narrow load) vanishes from a re-derivation by design —
    // the rounds accumulate, and 179 functions show exactly that shape (the first corpus run,
    // 2026-09-04). Observation only: the returned decisions are the second round's either way.
    if cfg!(debug_assertions) || std::env::var("MOSURA_RECOVER_FIXPOINT").as_deref() == Ok("1") {
        let (_, report3) = crate::decompile::printc::print_c_recovered_report(f, rec_choices, &recovered);
        let mut again = derive(&report3, insns, call_arg_orders);
        again.nested_conds.sites.extend(crate::recompile::buildconfig::nested_conds_from_evidence(&report3.nested_conds.candidates, insns));
        let grown = again.grown_over(&recovered);
        if !grown.is_empty() {
            eprintln!("[recover] FIXPOINT VIOLATION {}: the third render introduces [{}]", f.name, grown.join(" "));
        }
    }
    debug!(crate::debug::Topic::Recover, 
            "runs={} orders={} snap={} testmem={}",
            report.port.store_runs.len(),
            recovered.port.store_orders.len(),
            recovered.snapshot.sites.len(),
            recovered.testmem.sites.len()
        );
    recovered
}

/// The witness derivation: every per-site decision judged against the original's
/// instructions, from one report pass. Called on the report pass and, for the fixpoint check
/// below, on a render under the decisions it produced.
fn derive(report: &EmitReport, insns: &[NormInsn], call_arg_orders: HashMap<u64, Vec<usize>>) -> RecoveredChoices {
    let widen = crate::recompile::buildconfig::widened_sites_from_evidence(
        &report.port.local_width_candidates,
        &report.port.tier2_candidates,
        insns,
    );
    // One witness, two fields: whether the return declaration narrows, and whether that narrow
    // declaration is signed (the sign-extended-constant idiom).
    let cmp_sign = crate::recompile::buildconfig::cmp_signs_from_evidence(&report.cmp_sign.candidates, insns);
    let narrow_ret = crate::recompile::buildconfig::narrow_return_from_evidence(
        &report.port.return_width_candidates,
        insns,
    );
    crate::decompile::printc::RecoveredChoices {
        port: crate::decompile::emit::arms::port::Sites {
            narrow_return: narrow_ret.narrow,
            narrow_return_signed: narrow_ret.signed,
            narrow_return_width: narrow_ret.width,
            widen_local_pcs: report
                .port
                .local_width_candidates
                .iter()
                .filter(|(rep, _)| widen.0.contains(rep))
                .map(|&(_, pc)| pc)
                .collect(),
            widen_local_reps: widen.0,
            tier2_sites: widen.1,
            store_orders: {
                let mut m = crate::recompile::buildconfig::store_orders_from_evidence(&report.port.store_runs, insns);
                m.extend(crate::recompile::buildconfig::stack_store_orders_from_evidence(&report.port.stack_store_runs, insns));
                m
            },
            call_arg_orders: call_arg_orders,
            arm_swap_sites: crate::recompile::buildconfig::arm_swaps_from_evidence(
                &report.port.arm_swap_candidates,
                insns,
            ),
            ilv_orders: Default::default(),
        },
        array_index: crate::decompile::emit::arms::array_index::Sites {
            sites: crate::recompile::buildconfig::array_index_sites_from_evidence(
                &report.array_index.candidates,
                insns,
            ),
        },
        cmp_order: crate::decompile::emit::arms::cmp_order::Sites {
            sites: crate::recompile::buildconfig::cmp_orders_from_evidence(
                &report.cmp_order.candidates,
                insns,
            ),
        },
        cmp_sign: crate::decompile::emit::arms::cmp_sign::Sites {
            sites: cmp_sign.0,
            globals: cmp_sign.1,
        },
        complement_cmp: crate::decompile::emit::arms::complement_cmp::Sites {
            sites: crate::recompile::buildconfig::complement_compares_from_evidence(
                &report.complement_cmp.candidates,
                insns,
            ),
        },
        counted_loop: crate::decompile::emit::arms::counted_loop::Sites {
            sites: crate::recompile::buildconfig::counted_loops_from_evidence(
                &report.counted_loop.candidates,
                insns,
            ),
        },
        ext_cast: crate::decompile::emit::arms::ext_cast::Sites {
            sites: crate::recompile::buildconfig::narrow_zexts_from_evidence(
                &report.ext_cast.candidates,
                insns,
            ),
        },
        frame_fill: crate::decompile::emit::arms::frame_fill::Sites {
            frame: crate::recompile::buildconfig::frame_from_evidence(insns),
        },
        join_narrow: crate::decompile::emit::arms::join_narrow::Sites {
            sites: crate::recompile::buildconfig::join_narrow_sites_from_evidence(
                &report.join_narrow.candidates,
                insns,
            ),
        },
        load_hoist: crate::decompile::emit::arms::load_hoist::Sites {
            sites: crate::recompile::buildconfig::load_hoists_from_evidence(
                &report.load_hoist.candidates,
                insns,
            ),
        },
        mask_cast: crate::decompile::emit::arms::mask_cast::Sites {
            sites: crate::recompile::buildconfig::masked_args_from_evidence(
                &report.mask_cast.candidates,
                insns,
            ),
        },
        nested_conds: crate::decompile::emit::arms::nested_conds::Sites {
            sites: crate::recompile::buildconfig::nested_conds_from_evidence(
                &report.nested_conds.candidates,
                insns,
            ),
        },
        ptr_offset: crate::decompile::emit::arms::ptr_offset::Sites {
            sites: crate::recompile::buildconfig::ptr_offsets_from_evidence(
                &report.ptr_offset.candidates,
                insns,
            ),
        },
        return_split: crate::decompile::emit::arms::return_split::Sites {
            split: crate::recompile::buildconfig::split_returns_from_evidence(
                &report.return_split.split,
                insns,
            ),
            const_phi: crate::recompile::buildconfig::const_phi_returns_from_evidence(
                &report.return_split.const_phi,
                insns,
            ),
            early_return: crate::recompile::buildconfig::const_phi_returns_from_evidence(
                &report.return_split.early_return,
                insns,
            ),
            branch_return: crate::recompile::buildconfig::branch_returns_from_evidence(
                &report.return_split.branch_return,
                insns,
            ),
        },
        return_widen: crate::decompile::emit::arms::return_widen::Sites {
            zero_widened: narrow_ret.zero_widened,
        },
        sdiv_pow2: crate::decompile::emit::arms::sdiv_pow2::Sites {
            sites: crate::recompile::buildconfig::sdiv_pow2_from_evidence(
                &report.sdiv_pow2.candidates,
                insns,
            ),
        },
        snapshot: crate::decompile::emit::arms::snapshot::Sites {
            sites: crate::recompile::buildconfig::entry_snapshots_from_evidence(
                &report.snapshot.candidates,
                insns,
            ),
        },
        sparse_switch: crate::decompile::emit::arms::sparse_switch::Sites {
            sites: crate::recompile::buildconfig::sparse_cmps_from_evidence(insns),
        },
        store_forward: crate::decompile::emit::arms::store_forward::Sites {
            sites: crate::recompile::buildconfig::store_forwards_from_evidence(
                &report.store_forward.candidates,
                insns,
            ),
        },
        string_ops: crate::decompile::emit::arms::string_ops::Sites {
            sites: crate::recompile::buildconfig::string_ops_from_evidence(
                &report.string_ops.candidates,
                insns,
            ),
        },
        struct_copy: crate::decompile::emit::arms::struct_copy::Sites {
            runs: crate::recompile::buildconfig::movsd_runs_from_evidence(insns),
        },
        testmem: crate::decompile::emit::arms::testmem::Sites {
            sites: crate::recompile::buildconfig::testmem_from_evidence(
                &report.testmem.candidates,
                insns,
            ),
        },
        unsigned_cmp: crate::decompile::emit::arms::unsigned_cmp::Sites {
            sites: crate::recompile::buildconfig::unsigned_cmps_from_evidence(
                &report.unsigned_cmp.candidates,
                insns,
            ),
        },
    }
}


/// The hidden struct-return DECISION for `f` — the shape (`analysis::sret::sret_shape`) plus its
/// byte witness: on the cdecl side the function's own `ret $4` (it pops exactly the pointer's
/// slot, which gcc emits on i386 only for a memory-returned struct); on the register side (the
/// pointer in slot 0 = EAX, gcc's local convention, no pop) EVERY known call site's evidence — the
/// returned pointer dead, the slot-0 argument the address of a caller local. No call site and no
/// pop is no witness. The shape alone is byte-identical to `int *fill(int *p, ..) { ..; return p; }`;
/// the caller-side witness can still match such a function whose callers drop the result, and the
/// rendering is then value-preserving either way (`local = fill(..)` performs the same stores) — a
/// false positive changes form, never values (docs/struct-return-arm.md).
pub fn struct_return(f: &Funcdata) -> Option<StructReturnFact> {
    let shape = crate::analysis::sret::sret_shape(f)?;
    let ptr = f.vn(crate::decompile::printc::rendered_param_slots(f).first()?.vn?).size;
    let on_stack = f.spaces.by_name("stack") == Some(shape.slot.space);
    let witness = if on_stack && f.ret_pop == Some(ptr) {
        SretWitness::CalleePop
    } else if !on_stack && !f.sret_callers.is_empty() && f.sret_callers.iter().all(|e| e.supports_sret()) {
        SretWitness::Callers(f.sret_callers.len())
    } else {
        debug!(crate::debug::Topic::Args, "{:#x}: struct-return shape without a witness (on_stack={on_stack} ret_pop={:?} callers={:?})", f.addr.offset, f.ret_pop, f.sret_callers);
        return None;
    };
    debug!(crate::debug::Topic::Args, "{:#x}: struct-return {} bytes, {} fields, witness {witness:?}", f.addr.offset, shape.size, shape.fields.len());
    Some(StructReturnFact { shape, witness })
}

/// A witnessed hidden struct return: the shape and what witnessed it.
#[derive(Clone, Debug, PartialEq)]
pub struct StructReturnFact {
    pub shape: crate::analysis::sret::SretShape,
    pub witness: SretWitness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SretWitness {
    /// The function pops the pointer's slot on return (`ret $4`).
    CalleePop,
    /// Every one of its n known call sites drops the returned pointer and passes a local's address.
    Callers(usize),
}

/// The Watcom-32 CANONICAL ARM SET — the survey's flagless arm, verbatim from war2_survey.rs
/// (review R5, commit b moved it here so the oracle and the survey build the same set; the
/// survey's `--arms` override and its own shift-mask rule stay the survey's).
pub fn canonical_arm() -> EmitChoices {
        // The Watcom-32 emitter's own defaults: integer extensions left to C's promotion
        // (`ext-cast=promotion`) — the measured rendering for this target (zc42 vs zc46).
        let mut c = EmitChoices::default();
        c.set("ext-cast", "promotion").expect("known axis");
        // INT3 as the prelude's `__int3()` (`#pragma aux = 0xcc`) — the D5 audit rows'
        // assert traps and `app_fatal`'s body are compiled C only under this form.
        c.set("swi", "int3").expect("known axis");
        // if/else arms in the original's layout order (A1 — the address witness).
        c.set("arm-order", "address").expect("known axis");
        // half-written 4-byte locals declared once (A2ii — the GPOINT shape).
        c.set("struct-locals", "coalesce").expect("known axis");
        // byte-of-word zero tests at the operand's width (A5).
        c.set("narrow-tests", "rewiden").expect("known axis");
        // N3: scaled-index accesses through a constant/global base as array subscripts.
        c.set("array-index", "spelled").expect("known axis");
        // N1 (join-width=consumer), now WITNESSED by the original's 8-bit constant load.
        c.set("join-width", "consumer").expect("known axis");
        // Render a witnessed REP MOVS/STOS loop as memcpy/memset so Watcom's -oi re-inlines it.
        c.set("string-ops", "intrinsic").expect("known axis");
        // Render a witnessed SBB power-of-two division as `x / 2^n` (docs/sdiv-pow2-arm.md).
        c.set("sdiv-pow2", "div").expect("known axis");
        // Declare an under-sized frame as one byte aggregate sized to the original SUB ESP frame.
        c.set("frame-fill", "aggregate").expect("known axis");
        // Print a compare tree on one scrutinee as the sparse switch the source wrote.
        c.set("sparse-switch", "switch").expect("known axis");
        c.set("struct-copy", "assign").expect("known axis");
        // (historical: zc62 measured the blanket form net-flat
        // (+0.7w) with an EXACT regression (0x2c9a8) — a constant-join whose bytes load the
        // FULL register (MOV EDX,k) not the sub-register (MOV DL,k). The two are IR-identical;
        // only the original's bytes separate them, so N1 needs a DL-vs-EDX byte witness
        // (survey-side, like ext-cast). The axis + CallSpec::param_widths stay as groundwork.
    c
}

/// The MEASURED configuration — what the survey's recovered tree is emitted with: the canonical
/// arm with the target's hardware shift mask (`shift-mask=hardware`, every survey arm has it),
/// and, for the recovered passes, `sum-order=original` (the `rec_arm` of the survey). Returned as
/// `(choices, rec_choices)`, the two arms `recover` takes.
pub fn measured_arms() -> (EmitChoices, EmitChoices) {
    let mut c = canonical_arm();
    c.shift_mask = ShiftMask::Hardware;
    let mut rec = c.clone();
    rec.set("sum-order", "original").expect("known axis");
    (c, rec)
}
