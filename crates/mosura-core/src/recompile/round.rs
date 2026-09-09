//! The EMIT stage of a corpus round, function by function — moved out of the corpus emit driver
//! (plan WP7 P0 c8/c9, 2026-09-05): [`EmitState::emit_function`] orchestrates one function from the
//! landed decompile to its manifest row, and [`render_recovered`] is the RECOVERED rendering: the field path, where
//! every per-site choice is decided from evidence in the ORIGINAL's own instructions by the target
//! profile, with no compiler and no search. The compile/verify/verdict stages join in P3.

use std::collections::HashMap;

use crate::decompile::emit::EmitChoices;
use crate::decompile::funcdata::Funcdata;
use crate::analysis::decompiler::decompile_function;
use crate::decompile::fspec::FuncProto;
use crate::decompile::printc::print_c_with;
use crate::decompile::space::Address;
use crate::recompile::function::{self, Extent, Metrics, OwnContract};
use crate::recompile::manifest::{self, ManifestRow, Status};
use crate::recompile::passes::{Entries, GlobalWidths, ParamOrders, Worlds};
use crate::recompile::pragma::{self, ContractTable, WatcomRegs};
use crate::recompile::tu::{aggregate_ram_globals, build_tu, contract_violations_of, with_contract};
use crate::recompile::upgrade::{upgrade, UpgradeCaches, UpgradeCtx};
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

/// The whole-program facts an emit runs over — built once by the front-end from the pre-passes
/// ([`crate::recompile::passes`]) and immutable afterwards, except the consistency world, which the
/// zap checker scopes per forced function.
pub struct ProgramFacts {
    pub lang: &'static str,
    pub knobs: Knobs,
    pub worlds: Worlds,
    pub entries: Entries,
    pub regs: WatcomRegs,
    pub orders: ParamOrders,
    pub widths: GlobalWidths,
}

/// What the front-end asked for: the rendering arms (arm 0 = the reference), the recovered pass's
/// choices (`rec_arm`), the arms switched off by name, whether the recovered emission is wanted, and
/// the `--cons-probe` census.
pub struct EmitOpts {
    pub arms: Vec<EmitChoices>,
    pub rec_arm: EmitChoices,
    pub arms_off: Vec<String>,
    pub recovered: bool,
    pub cons_probe: bool,
    /// `emit.caller-parm=witnessed`: state a callee's `parm [..]` clause on the caller side even
    /// at Watcom's positional default order, gated on the callee's own read witness
    /// (`pragma::witnessed_parm_regs`). False = today's rule.
    pub caller_parm_witnessed: bool,
}

/// The emit stage's state across functions: the facts, the options, the definition-side contract
/// table the caller-side post-pass reads, the zap checker's memo tables, and the count of
/// functions whose own returns disagree about the pop (a region-boundary symptom, counted so it
/// cannot be silent).
pub struct EmitState {
    pub facts: ProgramFacts,
    pub opts: EmitOpts,
    pub contracts: ContractTable,
    pub caches: UpgradeCaches,
    pub cleanup_undecided: usize,
}

/// Everything one function's emit produced; the front-end writes, prints or counts what it wants.
pub struct Emitted {
    /// The decompile the renderings came from (landed, or the adopted prototype-world upgrade).
    pub f: Funcdata,
    pub from_pp: bool,
    pub proto: FuncProto,
    pub extent: Extent,
    pub metrics: Metrics,
    pub gsizes: HashMap<u64, u32>,
    /// The function's own `#pragma aux` declaration.
    pub contract: Option<String>,
    /// The reference rendering under arm 0, bare (`raw/`).
    pub reference_c: String,
    /// The reference rendering as a translation unit (`src/`).
    pub reference_tu: String,
    /// The extra arms' units (`arms[1..]`), in order.
    pub arm_tus: Vec<String>,
    /// The recovered unit (`recovered/`), when asked for.
    pub recovered_tu: Option<String>,
    pub smells: Vec<String>,
    pub violations: Vec<String>,
    pub kind: &'static str,
    pub row: ManifestRow,
    /// The zap checker's diagnostics (today's `[consistency]`/`[cons-*]` lines).
    pub notes: Vec<String>,
}

/// The landed decompile failed (a panic or `None`): the row's WEIGHT downstream is the
/// decompiler-independent extent, with no coverage to clamp with and no padding trim — there is
/// no candidate to diff against. The failure's text is the front-end's (its panic hook).
pub struct Failed {
    pub weight: u64,
}

impl EmitState {
    pub fn new(facts: ProgramFacts, opts: EmitOpts) -> EmitState {
        let contracts = ContractTable { witnessed: opts.caller_parm_witnessed, ..Default::default() };
        EmitState { facts, opts, contracts, caches: UpgradeCaches::default(), cleanup_undecided: 0 }
    }

    /// Emit one function: the landed decompile under `catch_unwind`, the zap checker's upgrade,
    /// the extent, the marks, the metrics, the reference rendering, the global widths, the own
    /// contract (recorded for the caller-side post-pass), the extra arms' units, the recovered unit
    /// (with the shared-return arm re-decompiling the SAME world), the reference unit with its
    /// smells, the contract violations, the kind and the manifest row — in the driver's order.
    pub fn emit_function(&mut self, idx: usize, va: u64, name: &str) -> Result<Emitted, Failed> {
        let lang = self.facts.lang;
        let prog = &self.facts.worlds.landed;
        let ram = prog.default_space;
        let mut notes: Vec<String> = Vec::new();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            decompile_function(prog, Address::new(ram, va))
        }));
        // which world produced the final `f`: the landed program, or the prototype-injected
        // probe program (`pp`) after a kernel adoption — the shared-return arm re-decompiles
        // the SAME world.
        let mut f_from_pp = false;
        let mut f: Option<Funcdata> = match outcome {
            Ok(Some(f)) => Some(f),
            _ => None,
        };
        // PER-TU UPGRADE under the zap checker: try the prototype-informed decompile; adopt it
        // only if the scheduler model accepts the candidate call effects AND the function's own
        // parameter signature is unchanged.
        if let (Some(fl), Some(pp)) = (f.as_ref(), self.facts.worlds.pp.as_ref()) {
            let mut ctx = UpgradeCtx {
                landed: prog,
                pp,
                cons: &mut self.facts.worlds.cons,
                lang,
                next_entry: &self.facts.entries.next,
                regs: &self.facts.regs,
                order_networked: &self.facts.orders.networked,
                knobs: &self.facts.knobs,
                cons_probe: self.opts.cons_probe,
            };
            let upgraded = upgrade(&mut ctx, &mut self.caches, fl, va, name, &mut notes);
            if let Some(f2) = upgraded {
                f = Some(f2);
                f_from_pp = true;
            }
        }
        let Some(f) = f else {
            let (next, body_end) = self.facts.entries.extent_bounds(prog, va);
            let flen = match body_end {
                Some(b) => next.min(b),
                None => next,
            }
            .max(va + 1)
                - va;
            return Err(Failed { weight: flen });
        };

        let extent = function::extent(prog, &self.facts.entries, &f, va);
        let orig_len = extent.region.len();
        // The convention marks from the function's own instructions, before any rendering.
        let f = {
            let mut f = f;
            let insns = crate::recompile::insn::normalize(lang, &extent.region, va, &crate::recompile::insn::NoReloc).unwrap_or_default();
            function::apply_marks(&mut f, &insns);
            f
        };
        // Decompiling is θ-independent and dominates the cost, so every rendering the caller asked
        // for is printed from this one Funcdata.
        let reference_c = print_c_with(&f, &self.opts.arms[0]);
        let metrics = function::metrics(&f, &extent.region);
        let global_width_arm = self.facts.knobs.on(Switch::GlobalWidth);
        let gsizes = function::global_widths(&f, lang, &extent.region, va, &self.facts.widths, global_width_arm);
        let oc = function::own_contract(&f, &extent.region, va, lang, &self.facts.regs);
        if oc.own == crate::recompile::OwnPopContract::Undecided {
            self.cleanup_undecided += 1;
        }
        let OwnContract { proto, contract, stack_decl, .. } = oc;
        self.contracts.record(va, &f, &self.facts.regs, stack_decl);

        // Arms past the first: same function, same declarations, a different rendering of the body.
        let mut arm_tus: Vec<String> = Vec::new();
        for theta in self.opts.arms.iter().skip(1) {
            let ac = print_c_with(&f, theta);
            let (atu, _) = build_tu(&ac, va, false, &gsizes, &Default::default(), &Default::default(), &[]);
            arm_tus.push(with_contract(name, contract.as_deref(), atu));
        }
        // RECOVERED emission: the field path — per-site choices decided from evidence in the
        // ORIGINAL's own instructions by the target profile, with no compiler and no search.
        let recovered_tu = if self.opts.recovered {
            let inputs = RenderInputs {
                lang,
                region: &extent.region,
                va,
                name,
                choices: &self.opts.arms[0],
                rec_arm: &self.opts.rec_arm,
                arms_off: &self.opts.arms_off,
                orders: &self.facts.orders,
                regs: &self.facts.regs,
                knobs: &self.facts.knobs,
                gsizes: &gsizes,
                contract: contract.as_deref(),
            };
            let render = |f: &Funcdata| -> String { render_recovered(f, &inputs) };
            let rtu = render(&f);
            // SHARED-RETURN ARM (allocator thread; re-earns the ActionReturnSplit doctrine trade):
            // where Ghidra's split fired, render the same world WITHOUT the split and keep that
            // rendering iff it is fully structured (no goto, no label). The split is Ghidra's goto
            // elimination — where the unsplit form already has no goto the split only deforms
            // structure, and where the unsplit form needs gotos the split repairs it. Measured on the
            // six trade members: the rule separates 5 of 6. `--arms-off shared-ret` disables.
            let rtu = if f.return_splits > 0 && self.facts.knobs.on(Switch::SharedRet) {
                crate::decompile::blockjoin::set_skip_return_split(true);
                let alt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    match (f_from_pp, self.facts.worlds.pp.as_ref()) {
                        (true, Some(pp)) => decompile_function(pp, Address::new(ram, va)),
                        _ => decompile_function(prog, Address::new(ram, va)),
                    }
                }));
                crate::decompile::blockjoin::set_skip_return_split(false);
                match alt {
                    Ok(Some(fa)) => {
                        let t = render(&fa);
                        let structured = !t.contains("goto ") && !t.contains("LAB_");
                        crate::debug!(crate::debug::Topic::Survey, "sharedret {name}: splits={} unsplit structured={structured} -> {}", f.return_splits, if structured { "UNSPLIT" } else { "split" });
                        if structured { t } else { rtu }
                    }
                    _ => rtu,
                }
            } else {
                rtu
            };
            Some(rtu)
        } else {
            None
        };
        // The reference unit and the decompiler-artifact smells.
        let (tu, mut smells) = build_tu(&reference_c, va, false, &gsizes, &Default::default(), &Default::default(), &[]);
        let reference_tu = with_contract(name, contract.as_deref(), tu);
        if metrics.thunk {
            smells.push("thunk".into());
        }
        // Over BOTH renderings: the recovered TU is the one that is compiled and measured, so the
        // column must describe it (see `contract_violations_of`).
        let violations = contract_violations_of(&reference_tu, recovered_tu.as_deref());
        let orig_hex: String = extent.region.iter().map(|b| format!("{b:02x}")).collect();
        // the not-C classification reads the original's decoded instructions (see kind_of_insns)
        let norm_insns_for_kind =
            crate::recompile::insn::normalize(lang, &extent.region, va, &crate::recompile::insn::NoReloc).unwrap_or_default();
        let kind = manifest::kind_of_insns(name, &norm_insns_for_kind);
        let row = ManifestRow {
            idx,
            va,
            name: name.to_string(),
            status: Status::Ok,
            orig_len: orig_len as u64,
            cov_lo: extent.cov_lo,
            cov_hi: extent.cov_hi,
            smells: smells.clone(),
            orig_hex,
            ir_calls: metrics.ir_calls,
            blocks_cfg: metrics.blocks_cfg,
            blocks_reached: metrics.blocks_reached,
            kind,
            contract: if violations.is_empty() { "ok".to_string() } else { format!("wide:{}", violations.join("+")) },
        };
        Ok(Emitted { f, from_pp: f_from_pp, proto, extent, metrics, gsizes, contract, reference_c, reference_tu, arm_tus, recovered_tu, smells, violations, kind, row, notes })
    }
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
