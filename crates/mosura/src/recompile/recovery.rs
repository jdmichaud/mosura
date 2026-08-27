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
use crate::decompile::emit::EmitChoices;
use crate::decompile::funcdata::Funcdata;
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
    let widen = crate::recompile::buildconfig::widened_sites_from_evidence(
        &report.local_width_candidates,
        &report.tier2_candidates,
        insns,
    );
    let call_arg_orders = call_arg_orders(&report);
    let recovered = crate::decompile::printc::RecoveredChoices {
        complement_sites: crate::recompile::buildconfig::complement_compares_from_evidence(
            &report.compare_sites,
            insns,
        ),
        return_split_sites: crate::recompile::buildconfig::split_returns_from_evidence(
            &report.return_split_candidates,
            insns,
        ),
        nested_sites: crate::recompile::buildconfig::nested_conds_from_evidence(
            &report.cond_nest_candidates,
            insns,
        ),
        narrow_return: crate::recompile::buildconfig::narrow_return_from_evidence(
            &report.return_width_candidates,
            insns,
        ),
        widen_local_reps: widen.0,
        tier2_sites: widen.1,
        snapshot_sites: crate::recompile::buildconfig::entry_snapshots_from_evidence(
            &report.snapshot_candidates,
            insns,
        ),
        testmem_sites: crate::recompile::buildconfig::testmem_from_evidence(
            &report.testmem_candidates,
            insns,
        ),
        store_orders: crate::recompile::buildconfig::store_orders_from_evidence(
            &report.store_runs,
            insns,
        ),
        call_arg_orders,
        arm_swap_sites: crate::recompile::buildconfig::arm_swaps_from_evidence(
            &report.arm_swap_candidates,
            insns,
        ),
        array_index_sites: crate::recompile::buildconfig::array_index_sites_from_evidence(
            &report.array_index_candidates,
            insns,
        ),
        join_narrow_sites: crate::recompile::buildconfig::join_narrow_sites_from_evidence(
            &report.join_narrow_candidates,
            insns,
        ),
        string_op_sites: crate::recompile::buildconfig::string_ops_from_evidence(
            &report.rep_movs_candidates,
            insns,
        ),
        sdiv_pow2_sites: crate::recompile::buildconfig::sdiv_pow2_from_evidence(
            &report.sdiv_pow2_candidates,
            insns,
        ),
        frame_fill: crate::recompile::buildconfig::frame_from_evidence(insns),
        sparse_cmp_sites: crate::recompile::buildconfig::sparse_cmps_from_evidence(insns),
        movsd_runs: crate::recompile::buildconfig::movsd_runs_from_evidence(insns),
        unsigned_cmp_sites: crate::recompile::buildconfig::unsigned_cmps_from_evidence(
            &report.allones_cmp_candidates,
            insns,
        ),
        // statement interleave (allocator thread lever 3): OFF — measured at probe
        // scale (2026-08-22) as a loser: re-sequencing a block's independent
        // statements into the original's instruction order broke 3 of 5 EXACT
        // functions (125bc, 2911c, 31c60) and moved the motivating 31c0c not at
        // all. The original's order is the SCHEDULER's output, not the source's
        // statement order, and the scheduler does not round-trip its own output
        // (source-sequence tie-breaks). The census and the orders machinery stay
        // for a model-inverse variant; MOSURA_ILV=1 enables the blind form.
        ilv_orders: if std::env::var("MOSURA_ILV").as_deref() == Ok("1") {
            crate::decompile::printc::interleave_orders(f, insns)
        } else {
            Default::default()
        },
    };
    // SECOND EVIDENCE ROUND (see print_c_recovered_report): decisions interact — a
    // tier-2 materialization creates the statement-carrying clause cond-form nests —
    // so re-assess candidacy on the rendering the first round produces and merge.
    let (_, report2) =
        crate::decompile::printc::print_c_recovered_report(f, rec_choices, &recovered);
    let mut recovered = recovered;
    recovered.nested_sites.extend(
        crate::recompile::buildconfig::nested_conds_from_evidence(
            &report2.cond_nest_candidates,
            insns,
        ),
    );
    if std::env::var_os("MOSURA_EMIT_DEBUG").is_some() {
        eprintln!(
            "[recover] runs={} orders={} snap={} testmem={}",
            report.store_runs.len(),
            recovered.store_orders.len(),
            recovered.snapshot_sites.len(),
            recovered.testmem_sites.len()
        );
    }
    recovered
}
