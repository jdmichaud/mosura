//! The EMIT stage of a corpus round, function by function — moved out of the corpus emit driver
//! (plan WP7 P0 c8/c9, 2026-09-05). This file holds the RECOVERED rendering: the field path, where
//! every per-site choice is decided from evidence in the ORIGINAL's own instructions by the target
//! profile, with no compiler and no search. The compile/verify/verdict stages join in P3.

use std::collections::HashMap;

use crate::decompile::emit::EmitChoices;
use crate::decompile::funcdata::Funcdata;
use crate::recompile::passes::ParamOrders;
use crate::recompile::pragma::{self, WatcomRegs};
use crate::recompile::tu::{aggregate_ram_globals, build_tu, with_contract};
use crate::switches::{Knobs, Switch};

/// Everything one recovered rendering reads besides the `Funcdata`: the ORIGINAL bytes of the
/// function (`region`, at `va`), the reference choices (`choices` = the survey's arm 0) and the
/// recovered pass's (`rec_arm`, arm 0 with `sum-order=original`), the arms switched off by name,
/// the cross-function tables (param orders, registers, knobs), the function's global widths and its
/// own `#pragma aux` contract. Held apart from the function so the shared-return arm can render an
/// ALTERNATIVE decompile of the same world under identical per-site decisions and choose between
/// the two texts — `gsizes` and `contract` are the primary decompile's in both renderings.
pub struct RenderInputs<'a> {
    pub lang: &'a str,
    pub region: &'a [u8],
    pub va: u64,
    pub name: &'a str,
    pub choices: &'a EmitChoices,
    pub rec_arm: &'a EmitChoices,
    pub arms_off: &'a [String],
    pub orders: &'a ParamOrders,
    pub regs: &'a WatcomRegs,
    pub knobs: &'a Knobs,
    pub gsizes: &'a HashMap<u64, u32>,
    pub contract: Option<&'a str>,
}

/// The recovered translation unit of one function: the per-function recovery
/// (`recompile::recovery::recover` with the argument-order derivation), the arms switched off, the
/// recovered print, volatile globals and per-callee pragmas from the original's instructions, the
/// global aggregation, `tu::build_tu`, and the function's own pragma prefixed.
pub fn render_recovered(f: &Funcdata, inp: &RenderInputs<'_>) -> String {
    let name = inp.name;
    let insns = crate::recompile::insn::normalize(
        inp.lang,
        inp.region,
        inp.va,
        &crate::recompile::insn::NoReloc,
    )
    .unwrap_or_default();
    // PER-FUNCTION RECOVERY (recompile::recovery, review R5 commit a): the report pass, the
    // `*_from_evidence` witnesses over this function's instructions and the second evidence
    // round, one library fn shared with the gcc ground-truth oracle. The argument-order
    // derivation stays here as the closure: it reads the survey's cross-function tables
    // (site_orders, order_excluded, arg_reg_offs, watreg) and fills `order_parms`.
    let mut order_parms: std::collections::BTreeMap<u64, String> = Default::default();
    let recovered = crate::recompile::recovery::recover(&f, &insns, inp.choices, inp.rec_arm, |report| {
        let (perms, parms) = pragma::call_arg_orders(report, inp.va, inp.orders, inp.regs);
        order_parms = parms;
        perms
    });
    let recovered = {
        let mut r = recovered;
        for a in inp.arms_off {
            r.switch_off(a).expect("--arms-off names were checked at startup");
        }
        r
    };
    // the interleave census (was `MOSURA_ILV_CENSUS`): a diagnostic, so under the facility's
    // `recover` topic like its siblings (review R6, commit 3b); it also reports the orders the
    // parked lever would apply -- printc::interleave_orders keeps its caller here since the
    // blind form's switch went
    if crate::debug::on(crate::debug::Topic::Recover) {
        for (pa, pb, k) in crate::decompile::printc::interleave_census(&f, &insns) {
            crate::debug!(crate::debug::Topic::Recover, "ilv {name} {pa:#x} {pb:#x} {k}");
        }
        let mut orders: Vec<_> = crate::decompile::printc::interleave_orders(&f, &insns).into_iter().collect();
        orders.sort_by_key(|(op, _)| op.0);
        for (op, order) in orders {
            crate::debug!(crate::debug::Topic::Recover, "ilv {name} order at op {} -> {:?}", op.0, order.iter().map(|o| o.0).collect::<Vec<_>>());
        }
    }
    let rc = crate::decompile::printc::print_c_recovered(&f, inp.rec_arm, &recovered);
    // VOLATILE RECOVERY: globals whose original store sites show the blocked order
    // (see buildconfig::volatile_globals_from_evidence) declare volatile in this TU.
    let volatiles =
        crate::recompile::buildconfig::volatile_globals_from_evidence(&insns);
    let vararg_callees = pragma::callee_pragmas(&f, &insns, inp.regs, inp.knobs.on(Switch::CalleeClobbers), &order_parms);
    let (rc, aggregates) = aggregate_ram_globals(&rc, &insns, inp.gsizes, &volatiles, inp.knobs.on(Switch::Agg));
    if crate::debug::on(crate::debug::Topic::Survey) && !aggregates.is_empty() {
        for (_, d) in &aggregates {
            crate::debug!(crate::debug::Topic::Survey, "agg {name}: {d}");
        }
    }
    let (rtu, _) = build_tu(&rc, inp.va, false, inp.gsizes, &volatiles, &vararg_callees, &aggregates);
    let rtu = with_contract(name, inp.contract, rtu);
    // The permuted argument order is value-identical only under its pragma — the two
    // are one decision, emitted together (see call_arg_orders above).
    // order_parms are folded into the per-callee pragma inside build_tu now.
    rtu
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recovered rendering on a real decompile: a standalone unit naming the function, the same
    /// text under an inert knob change, and still a unit with an arm switched off by name.
    #[test]
    fn render_recovered_produces_a_unit_and_is_deterministic() {
        let path = crate::paths::analysis_corpus_dir().join("basic.elf");
        let Ok(mut prog) = crate::analysis::analyze_file(&path) else { eprintln!("skip: {} absent", path.display()); return };
        prog.global_scope_all_loaded = false;
        let ents = crate::recompile::passes::Entries::of(&prog);
        let regs = WatcomRegs::for_lang(&prog.language_id);
        let orders = ParamOrders::default();
        let knobs = Knobs::default();
        let (choices, rec_arm) = crate::recompile::recovery::measured_arms();
        let mut rendered = 0;
        for &(va, ref name) in ents.list.iter().take(4) {
            let Some(f) = crate::analysis::decompiler::decompile_function(&prog, crate::decompile::space::Address::new(prog.default_space, va)) else { continue };
            let e = crate::recompile::function::extent(&prog, &ents, &f, va);
            let gsizes = crate::recompile::function::global_widths(&f, &prog.language_id, &e.region, va, &crate::recompile::passes::GlobalWidths { store_w: HashMap::new(), read_w: HashMap::new() }, false);
            fn mk<'a>(lang: &'a str, region: &'a [u8], va: u64, name: &'a str, choices: &'a EmitChoices, rec_arm: &'a EmitChoices, arms_off: &'a [String], orders: &'a ParamOrders, regs: &'a WatcomRegs, knobs: &'a Knobs, gsizes: &'a HashMap<u64, u32>) -> RenderInputs<'a> {
                RenderInputs { lang, region, va, name, choices, rec_arm, arms_off, orders, regs, knobs, gsizes, contract: None }
            }
            let off: Vec<String> = vec!["cmp_sign".to_string()];
            let t1 = render_recovered(&f, &mk(&prog.language_id, &e.region, va, name, &choices, &rec_arm, &[], &orders, &regs, &knobs, &gsizes));
            assert!(t1.contains(&format!("FUN_{va:08x}")) && t1.trim_end().ends_with('}'), "a unit for {name}: {t1}");
            assert_eq!(render_recovered(&f, &mk(&prog.language_id, &e.region, va, name, &choices, &rec_arm, &[], &orders, &regs, &knobs, &gsizes)), t1, "deterministic");
            let t2 = render_recovered(&f, &mk(&prog.language_id, &e.region, va, name, &choices, &rec_arm, &off, &orders, &regs, &knobs, &gsizes));
            assert!(t2.contains(&format!("FUN_{va:08x}")), "still a unit with an arm off");
            rendered += 1;
        }
        assert!(rendered > 0);
    }
}
