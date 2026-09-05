//! The per-TU UPGRADE under the zap checker — the corpus emit's prototype-pass adoption logic,
//! moved verbatim out of the driver (plan WP7 P0 c5, 2026-09-05): the whole-program prototype
//! world's decompile of a function is adopted over the landed one only where the models prove the
//! original's placements survive — the scheduler fixed point (`watsched`), the allowed set, the
//! register-collision gate, the caller network, the signature gate, the zero-cost pass-through and
//! stack-append kernels — and, failing those, the CONSISTENCY override (memory
//! `consistency-over-score`): surgical injection of exactly the contradicted callees' prototypes,
//! constant-argument sites, and argument CARRY between calls. The diagnostics the driver printed
//! come back as `notes`, so the library prints nothing.

use std::collections::{HashMap, HashSet};

use crate::analysis::program::Program;
use crate::decompile::funcdata::Funcdata;
use crate::decompile::op::flags;
use crate::decompile::opcode::OpCode;
use crate::decompile::space::Address;
use crate::decompile::printc::print_c;
use crate::recompile::pragma::{nondefault_parm_regs, WatcomRegs};
use crate::switches::{Knobs, Switch};

/// Per-run memo tables the upgrade consults across functions: the definition-side "does this
/// callee declare NONDEFAULT parameter storage?" answer in the landed world, and each callee's
/// entry-block byte testimony ([`callee_input_evidence`]).
#[derive(Default)]
pub struct UpgradeCaches {
    pub nondefault_storage: HashMap<u64, bool>,
    pub callee_ev: HashMap<u64, Vec<Option<bool>>>,
}

/// What one function's upgrade reads: the three worlds (the consistency world is scoped and
/// cleared per forced function, hence `&mut`), the language, the successor map, the register
/// facts, the order-claimed callee network, the knobs, and the `--cons-probe` census switch.
pub struct UpgradeCtx<'a> {
    pub landed: &'a Program,
    pub pp: &'a Program,
    pub cons: &'a mut Option<Program>,
    pub lang: &'a str,
    pub next_entry: &'a HashMap<u64, u64>,
    pub regs: &'a WatcomRegs,
    pub order_networked: &'a HashSet<u64>,
    pub knobs: &'a Knobs,
    pub cons_probe: bool,
}

/// Try the prototype-informed decompile of the function at `va` (`fl` = its landed decompile);
/// `Some(f)` = adopted (the pp decompile, the forced consistency decompile, or the per-site/carry
/// edited landed clone — the caller records `from_pp = true`), `None` = refused, the landed
/// function stands. Diagnostics are appended to `notes` (today's `[consistency]`/`[cons-*]` lines).
pub fn upgrade(
    ctx: &mut UpgradeCtx<'_>,
    caches: &mut UpgradeCaches,
    fl: &Funcdata,
    va: u64,
    name: &str,
    notes: &mut Vec<String>,
) -> Option<Funcdata> {
    let ext = ctx.next_entry.get(&va).copied().unwrap_or(va + 0x1000).saturating_sub(va);
    let reg_bytes = ctx.landed.memory.read_window(Address::new(ctx.landed.default_space, va), ext as usize);
    let insns = crate::recompile::insn::normalize(
        ctx.lang,
        &reg_bytes,
        va,
        &crate::recompile::insn::NoReloc,
    )
    .unwrap_or_default();
    let outcome2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::analysis::decompiler::decompile_function(ctx.pp, Address::new(ctx.landed.default_space, va))
    }));
    if let Ok(Some(mut f2)) = outcome2 {
        let cand = candidate_call_effects(&f2);
        // Signature gate: NONDEFAULT-storage stability only. A full count+storage
        // comparison was measured to refuse every upgrade — own-arity growth IS the
        // recovery working (the gains carry it too); judging which growths are
        // allocation-safe (entry liveness, re-homing) is the phase-2 allocator
        // cost-model's job (regalloc.c CalcSavings/GiveBestReg), recorded in the
        // thread memory. Until then the allocation gate below covers the
        // call-crossing half, and the own-params half rides the corpus verdict.
        // Signature stability, three conditions (the first was the original gate;
        // the residual-defect census after the zero-cost kernel named the others):
        //   1. nondefault-storage stability (full count+storage equality was a
        //      measured dead end — every gain grows its own signature);
        //   2. EXISTING params stay verbatim — storage AND size. The prototype
        //      pass widened FUN_00034fe0's `char param_3` to `xunknown4` (the
        //      injected 4-byte call-slot width coarsened the type) and the
        //      re-typed TU compiles differently;
        //   3. a STACK-convention function stays stack: FUN_00073338 (own
        //      `parm caller []`, one stack param) grew FIVE register params —
        //      an injected callee arity manufactured phantom own-params from
        //      entry-reaching register reads. Register growth on a stack-param
        //      landed signature contradicts the recovered convention.
        let sig_stable_vs = |cand: &Funcdata| -> bool {
            let lp = crate::decompile::printc::rendered_param_slots(fl);
            let cp = crate::decompile::printc::rendered_param_slots(cand);
            let prefix_ok = cp.len() >= lp.len()
                && lp.iter().zip(cp.iter()).all(|(a, b)| a.addr == b.addr && a.size == b.size);
            let reg_space = cand.spaces.by_name("register");
            let landed_has_stack = lp.iter().any(|sl| Some(sl.addr.space) != reg_space);
            let grows_registers =
                cp.len() > lp.len() && cp[lp.len()..].iter().any(|sl| Some(sl.addr.space) == reg_space);
            nondefault_parm_regs(cand, &ctx.regs.table) == nondefault_parm_regs(fl, &ctx.regs.table)
                && prefix_ok
                && !(landed_has_stack && grows_registers)
        };
        let sig_stable = sig_stable_vs(&f2);
        // The parm-pragma network gate, PRESENCE FORM — deliberately blunt: any
        // call into a NONDEFAULT-STORAGE callee refuses the upgrade. The precise
        // form (refuse only on CHANGED ordered arg signatures at such callees) was
        // measured and does NOT land: it released ~300 more adoptions for ZERO
        // gains and two fresh EXACT losses (0x1da00, 0x2d1f0) — the census's
        // 122-function "network pool" of near-misses does not resolve through
        // arity alone, and the relaxation only buys risk. (The ordered-signature
        // hazard it did catch — the locked-prototype arg order inverting the
        // positional pairing under a `parm [..]` pragma at 0x3925c — is subsumed
        // by presence-refusal.)
        let mut networked = false;
        for op in f2.op_ids() {
            let o = f2.op(op);
            if o.code() != OpCode::Call || o.flags & (flags::DEAD | flags::MARKER) != 0 {
                continue;
            }
            let Some(t) = o.input(0) else { continue };
            let callee = f2.vn(t).loc.offset;
            if callee == 0 {
                continue;
            }
            let nd = *caches.nondefault_storage.entry(callee).or_insert_with(|| {
                ctx.order_networked.contains(&callee)
                    || std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        crate::analysis::decompiler::decompile_function(ctx.landed, Address::new(ctx.landed.default_space, callee))
                    }))
                    .ok()
                    .flatten()
                    .map(|cf| nondefault_parm_regs(&cf, &ctx.regs.table).is_some())
                    .unwrap_or(true)
            });
            if nd {
                networked = true;
                break;
            }
        }
        // PHASE-2 HYPOTHESIS (allocator model): an ADDED own-parameter whose
        // register the original body WRITES with ordinary instructions (not the
        // calls' convention effects, not the PUSH/POP save pair) is a live-in
        // COLLIDING with the body's own register usage — the FUN_0005ed78 shape.
        let no_collision = {
            let slots = |f: &Funcdata| -> Vec<u64> {
                let reg = f.spaces.by_name("register");
                crate::decompile::printc::rendered_param_slots(f)
                    .iter()
                    .filter(|sl| Some(sl.addr.space) == reg)
                    .map(|sl| sl.addr.offset & !3)
                    .collect()
            };
            let old_slots = slots(fl);
            let added: Vec<u64> =
                slots(&f2).into_iter().filter(|r| !old_slots.contains(r)).collect();
            if added.is_empty() {
                true
            } else {
                let mut body_writes: std::collections::HashSet<u64> =
                    std::collections::HashSet::new();
                for x in &insns {
                    if x.is_call || x.mnemonic == "PUSH" || x.mnemonic == "POP" {
                        continue;
                    }
                    for op in &x.sem {
                        if let Some(crate::recompile::insn::SemArg::Reg(o, _)) = op.out {
                            if o < 0x20 {
                                body_writes.insert(o & !3);
                            }
                        }
                    }
                }
                !added.iter().any(|r| body_writes.contains(r))
            }
        };
        let other_ok = sig_stable
            && !networked
            && !cand.is_empty()
            && !insns.is_empty()
            && !crate::recompile::watsched::order_regressed(&insns, &cand);
        // The allocation gate (register-allocator model, phase 1): a candidate
        // that kills a register the original visibly carries across the call
        // would have re-homed that value (FUN_00034fe0's PUSH EDI shape).
        let alloc_ok = no_collision
            && !crate::recompile::watsched::allocation_regressed(&insns, &cand);
        let mut ok = other_ok && alloc_ok;
        let mut passthrough = false;
        let mut consistency_forced = false;
        // DEFAULT-ON since the round-2 landing (targeted 299: 121/121 EXACT held,
        // +5, zero losses). `--arms-off kernel-net` restores the refusal.
        let net_kernel = ctx.knobs.on(Switch::KernelNet);
        if other_ok && !alloc_ok {
            // Allocator model phase 2, the ZERO-COST kernel (see `pass_through_only`):
            // a collision/allocation refusal whose whole delta is appended
            // self-move pass-throughs cannot change the allocator's assignment.
            let lt = print_c(fl);
            let ct = print_c(&f2);
            let sig_of2 = |t: &str| t.lines().find(|l| l.contains(&format!("FUN_{va:08x}("))).map(str::to_string);
            if pass_through_only(&lt, &ct, va) {
                ok = true;
                passthrough = true;
            } else {
                // STACK-APPEND kernel (stack-args frontier): a refusal whose whole
                // delta is appended args is admitted when every arbitrary-expression
                // element is backed by at least that many PUSH insns in the
                // original's 12-insn pre-call window (the const-evidence pattern)
                // and the signature line is untouched. Landed under the WGSS-first
                // bar (2026-08-22): the evidence-gated pool is 2 TUs, micro-round
                // 36b30 sim 0.471→0.586, 6d680 unchanged, no verdict regressions.
                // `--arms-off kernel-stackapp` restores the refusal.
                let stack_kernel = ctx.knobs.on(Switch::KernelStackApp);
                let mut consts2: Vec<(u64, u32, u64)> = Vec::new();
                let mut stacks: Vec<(u64, u32)> = Vec::new();
                if (stack_kernel || crate::debug::on(crate::debug::Topic::Survey))
                    && pass_through_report(&lt, &ct, va, Some(&mut consts2), Some(&mut stacks))
                    && !stacks.is_empty()
                {
                    let mut push_ev = std::collections::HashMap::new();
                    for (i, x) in insns.iter().enumerate() {
                        if x.is_call {
                            if let Some(t) = x.target {
                                let pushes = insns[..i]
                                    .iter()
                                    .rev()
                                    .take(12)
                                    .take_while(|y| !y.is_call && !y.is_branch)
                                    .filter(|y| y.mnemonic == "PUSH")
                                    .count();
                                let e = push_ev.entry(t).or_insert(0usize);
                                *e = (*e).max(pushes);
                            }
                        }
                    }
                    let mut need = std::collections::HashMap::new();
                    for &(c, _) in &stacks {
                        *need.entry(c).or_insert(0usize) += 1;
                    }
                    if need.iter().all(|(c, n)| push_ev.get(c).copied().unwrap_or(0) >= *n)
                        && sig_of2(&lt) == sig_of2(&ct)
                    {
                        crate::debug!(crate::debug::Topic::Survey, "shadow-stack {name} appends {:?}", need.iter().map(|(c, n)| (format!("{c:#x}"), *n)).collect::<Vec<_>>());
                        if stack_kernel {
                            ok = true;
                            passthrough = true;
                        }
                    }
                }
            }
        }
        // SHADOW CENSUS (MOSURA_KERNEL_SHADOW=1; missing-args thread): would the
        // zero-cost kernel, extended to NETWORK refusals under a tightened guard,
        // adopt this TU? Counted only — nothing adopts. The tightening beyond
        // pass_through_only: a changed callee pragma may not touch anything BEFORE
        // its `modify` clause (its `parm [..]`/`parm caller []` half must be
        // verbatim), killing the 3925c order-inversion hazard that sank the old
        // precise-network relaxation (1da00/2d1f0).
        if (crate::debug::on(crate::debug::Topic::Survey) || net_kernel)
            && !ok
            && sig_stable
            && networked
            && !cand.is_empty()
            && !insns.is_empty()
            && !crate::recompile::watsched::order_regressed(&insns, &cand)
        {
            let lt = print_c(fl);
            let ct = print_c(&f2);
            // ROUND-2 TIGHTENING (measured separation on the round-1 gain/loss sets):
            //   - callee pragmas fully VERBATIM — round 1's nine EXACT losses all
            //     carried `modify` → `modify exact` deltas (the exactness keyword's
            //     caller-side codegen, −11 solo in the ledger); the six gains had
            //     zero pragma deltas;
            //   - the OWN signature identical (no arity growth);
            //   - every appended CONSTANT must have its materializing write in the
            //     ORIGINAL bytes (`MOV reg,K` / `XOR reg,reg` for 0) — gains restore
            //     an instruction the original HAS (237dc's `MOV ECX,0x1`), losses
            //     invented one it lacks (12c58's `(0, 0)`).
            let mut appended_consts: Vec<(u64, u32, u64)> = Vec::new();
            // The TU's pragma lines are assembled from call_specs AFTER the loop
            // (callee_aux), so a render comparison cannot see them — 1da00's only
            // delta was `modify` → `modify exact` and a text check was vacuous.
            // Compare the SPECS: per callee, (caller_cleans, cdecl_modify,
            // cdecl_exact) must agree between the landed and candidate decompiles.
            // DETERMINISTIC per-callee view (second leak of the run-to-run jitter,
            // found by the full double-emit after d45c4ed): the old fold inserted
            // per site over the HashMap, last-writer-wins, so `pragmas_equal` below
            // was a random draw whenever a callee had two sites with different
            // specs — the network kernel then adopted or refused by hash order
            // (FUN_0004ac88 / callee 0x5dd14: `adopted:passthrough` vs
            // `refused:network` across runs). The view now merges exactly as the
            // TU's pragma emission does (caller_cleans from any site, modify = union,
            // exact from any site), so equality of views is equality of the pragmas
            // that would be emitted.
            let spec_view = |f: &Funcdata| -> std::collections::BTreeMap<u64, (Option<u32>, Option<std::collections::BTreeSet<u64>>, bool)> {
                let mut m: std::collections::BTreeMap<u64, (Option<u32>, Option<std::collections::BTreeSet<u64>>, bool)> =
                    std::collections::BTreeMap::new();
                for (&op, cs) in f.call_specs.iter() {
                    let Some(t) = f.op(op).input(0) else { continue };
                    let cva = f.vn(t).loc.offset;
                    if cva == 0 {
                        continue;
                    }
                    let e = m.entry(cva).or_default();
                    // the pop count: the largest any site recovered (None < Some)
                    e.0 = e.0.max(cs.caller_cleans.filter(|&n| n > 0));
                    if let Some(mm) = cs.cdecl_modify.as_ref() {
                        e.1.get_or_insert_with(Default::default).extend(mm.iter().copied());
                    }
                    e.2 |= cs.cdecl_exact;
                }
                m
            };
            let ops_input0: std::collections::HashMap<crate::decompile::op::OpId, u64> = f2
                .call_specs
                .keys()
                .filter_map(|&op| {
                    let t = f2.op(op).input(0)?;
                    let va = f2.vn(t).loc.offset;
                    (va != 0).then_some((op, va))
                })
                .collect();
            let (sv_l, sv_c) = (spec_view(fl), spec_view(&f2));
            let pragmas_equal = sv_l == sv_c;
            if crate::debug::on(crate::debug::Topic::Survey) && !pragmas_equal {
                for (k, v) in &sv_c {
                    if sv_l.get(k) != Some(v) {
                        crate::debug!(crate::debug::Topic::Survey, "shadow-diff {name} callee {k:#x} landed {:?} cand {:?}", sv_l.get(k), v);
                        break;
                    }
                }
            }
            let sig_of = |t: &str| t.lines().find(|l| l.contains(&format!("FUN_{va:08x}("))).map(str::to_string);
            // Byte evidence, WINDOWED at the call: the appended constant's
            // materializing write must sit within the 12 instructions before a call
            // to that callee (stopping at intervening calls/branches) — an extent-
            // wide search whitelisted 157a0's distant `XOR EDX,EDX` for a zero the
            // original never materializes at this site.
            let const_evidence = |appends: &[(u64, u32, u64)]| -> bool {
                appends.iter().all(|&(callee, pos, k)| {
                    if callee == 0 {
                        return false;
                    }
                    let Some(&r) = ctx.regs.arg_reg_offs.get(pos as usize) else { return false };
                    insns.iter().enumerate().filter(|(_, x)| x.is_call && x.target == Some(callee)).any(|(ci, _)| {
                        insns[..ci]
                            .iter()
                            .rev()
                            .take(12)
                            .take_while(|x| !x.is_call && !x.is_branch)
                            .any(|x| {
                                x.sem.iter().any(|op| {
                                    matches!(op.out, Some(crate::recompile::insn::SemArg::Reg(o, _)) if o & !3 == r)
                                        && (op.ins.iter().any(|i| matches!(i, crate::recompile::insn::SemArg::Const(v, _) if *v == k))
                                            || (k == 0
                                                && x.mnemonic == "XOR"
                                                && x.sem.iter().any(|op| matches!(op.out, Some(crate::recompile::insn::SemArg::Reg(o, _)) if o & !3 == r))))
                                })
                            })
                    })
                })
            };
            if pass_through_report(&lt, &ct, va, Some(&mut appended_consts), None)
                && pragmas_equal
                && sig_of(&lt) == sig_of(&ct)
                && const_evidence(&appended_consts)
            {
                if net_kernel {
                    // Landed via the round-2 targeted measurement. The adoption's
                    // PURPOSE is the appended arguments; the pragma-relevant spec
                    // fields stay the LANDED ones BY CONSTRUCTION — the gate asserts
                    // spec equality, but 1da00's `modify exact` still drifted in
                    // post-gate emission state during the first full round, so the
                    // invariant is enforced rather than assumed.
                    let landed_specs = spec_view(fl);
                    for (&op, cs) in f2.call_specs.iter_mut() {
                        let Some(t) = ops_input0.get(&op) else { continue };
                        if let Some((cleans, modify, exact)) = landed_specs.get(t) {
                            cs.caller_cleans = *cleans;
                            cs.cdecl_modify = modify.as_ref().map(|s| s.iter().copied().collect());
                            cs.cdecl_exact = *exact;
                        }
                    }
                    ok = true;
                    passthrough = true;
                } else {
                    crate::debug!(crate::debug::Topic::Survey, "{name} network-eligible consts={}", appended_consts.len());
                }
            } else if pragmas_equal && sig_of(&lt) == sig_of(&ct) {
                // ORDER-ONLY deltas stay REFUSED — measured 2026-08-21: the whole
                // pool is 6 TUs (one callee, 0x38828), the LANDED pairing already
                // follows the byte-derived site-order evidence (`parm [edx] [eax]`,
                // original `XOR EDX,EDX; MOV DL,AL; MOV EAX,const`), and adopting
                // the prototype-ordered permutation changed renders with sims
                // UNMOVED at 0.636 — the recorded 3925c inversion wart, confirmed
                // live. The census classifier stays for future shadow runs.
                if crate::debug::on(crate::debug::Topic::Survey) {
                    if let Some(cs2) = order_only_delta(&lt, &ct) {
                        let list: Vec<String> = cs2.iter().map(|c| format!("{c:#x}")).collect();
                        crate::debug!(crate::debug::Topic::Survey, "shadow-order {name} callees [{}]", list.join(" "));
                    }
                }
            }
        }
        // CONSISTENCY OVERRIDE (JD 2026-08-24; memory consistency-over-score):
        // cross-TU argument consistency outranks the byte-gates. When the LANDED
        // decompile under-calls a register-prototype callee — the callee's own TU
        // declares parameters these calls do not pass, so the linked program would
        // read garbage — and the candidate resolves every such call with genuinely
        // bound values, the candidate is adopted even where the scheduler/network/
        // allocation gates refused. Own-signature instability (`sig_stable` false)
        // still blocks: width coarsening and phantom own-params are the collateral
        // bug class, not the lottery. Score losses from these adoptions are
        // CLASSIFIED in the round report (lottery vs bug), not vetoed.
        // `--arms-off consistency` restores the pure gate stack for A/B measurement.
        let mut f_forced: Option<Funcdata> = None;
        if !ok && ctx.knobs.on(Switch::Consistency) {
            // DEFAULT-ON since the Order Y round (878 EXACT / WGSS 0.56212 on base
            // 38f1c72's 875 / 0.56115: +3, 4 flips up, 1 classified correct-code form
            // down, stable at two on byte-identical TSVs). `--arms-off cons-reach`
            // restores the 12-instruction call-stopped witness and the flat shape
            // rule, the way `--arms-off kernel-net` and `--arms-off consistency` restore
            // theirs — the A/B every round on this gate has needed.
            let reach_mode = ctx.knobs.on(Switch::ConsReach);
            // The callee's own entry block, for every direct callee of this function.
            let mut evidence: HashMap<u64, Vec<Option<bool>>> = HashMap::new();
            for op in fl.op_ids() {
                let o = fl.op(op);
                if o.code() != OpCode::Call || o.flags & (flags::DEAD | flags::MARKER) != 0 {
                    continue;
                }
                let Some(t) = o.input(0) else { continue };
                let c = fl.vn(t).loc.offset;
                if c == 0 || evidence.contains_key(&c) {
                    continue;
                }
                let e = caches.callee_ev
                    .entry(c)
                    .or_insert_with(|| {
                        let ext = ctx.next_entry
                            .get(&c)
                            .copied()
                            .unwrap_or(c + 0x100)
                            .saturating_sub(c)
                            .min(0x100);
                        let b = ctx.landed.memory.read_window(Address::new(ctx.landed.default_space, c), ext as usize);
                        let ci = crate::recompile::insn::normalize(
                            ctx.lang,
                            &b,
                            c,
                            &crate::recompile::insn::NoReloc,
                        )
                        .unwrap_or_default();
                        callee_input_evidence(&ci, &ctx.regs.arg_reg_offs)
                    })
                    .clone();
                evidence.insert(c, e);
            }
            // NO GROWTH-SIDE REFUSAL, and the reason is measured (Order Y): refusing a
            // contradiction whose claimed register the callee writes-before-reading was
            // built, run over the corpus, and REFUTED on its own criterion — it removed 4
            // benign extra-argument sites and created 4 sites that DROP a register the
            // callee's bytes say it READS. The asymmetry is real: in a positional
            // convention an UNUSED parameter slot is legal, so `written before read` does
            // not disprove parameterhood; passing a value the callee ignores is score
            // noise, while failing to pass one it reads is wrong code. The byte evidence
            // is therefore applied only where the harm is (in `call_shapes_stable`: never
            // drop a byte-proven read).
            let contradicted = under_called_register_callees(fl, ctx.pp);
            if !contradicted.is_empty() {
                let list: Vec<String> =
                    contradicted.iter().map(|&(c, n)| format!("{c:#x}/{n}")).collect();
                // SURGICAL INJECTION (zc52's lesson): do NOT adopt the ctx.pp world's
                // decompile wholesale — its call_specs shift every pragma
                // (`modify` → `modify exact`, order pragmas lost) and its other
                // locked calls can LOSE arguments (0x11b9c), the measured bug-class
                // losses. Re-decompile the LANDED world with only the contradicted
                // callees' prototypes visible (`Program::proto_scope`), so the
                // adoption carries exactly the missing arguments.
                let f3 = ctx.cons.as_mut().and_then(|pc| {
                    pc.proto_scope =
                        Some(contradicted.iter().map(|&(c, _)| c).collect());
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        crate::analysis::decompiler::decompile_function(pc, Address::new(ctx.landed.default_space, va))
                    }))
                    .ok()
                    .flatten();
                    pc.proto_scope = Some(std::collections::HashSet::new());
                    r
                });
                // BYTE EVIDENCE for constant arguments (the net-kernel's measured
                // gate, reused): a constant an injected call carries must have its
                // materializing write in the ORIGINAL's 12-instruction pre-call
                // window (`MOV reg,K`, or `XOR reg,reg` for 0). The indirect-zero
                // flag does not survive constant cloning and dead-iop collapse, so
                // 12c58's `(0, 0)` — zeros the original never places — arrives as
                // plain constants; the original's own instruction stream is the
                // reliable witness.
                // (B) REACHING WITNESS (the `cons-reach` switch, Order Y) — the landed window
                // stops at the first intervening CALL, and this defect class is DEFINED by
                // a materializing write that sits before one: `MOV EBX,0x28a0` at 0x22e61,
                // `CALL 0x59404` at 0x22e66, `CALL 0x50480` at 0x22e81. The walk crosses a
                // call only when that call's own recovered contract preserves the register
                // — the same `cdecl_modify` set our `#pragma aux .. modify [..]` already
                // asserts in the emitted C, so the witness never claims more than the
                // program we print (0x59404 saves EBX/ECX/EDX at entry: byte-confirmed).
                let preserves = |pc: u64, r: u64| -> bool {
                    fl.op_ids()
                        .find(|&op| {
                            let o = fl.op(op);
                            matches!(o.code(), OpCode::Call | OpCode::Callind)
                                && o.seqnum.pc.offset == pc
                        })
                        .and_then(|op| fl.call_specs.get(&op))
                        .and_then(|cs| cs.cdecl_modify.as_ref())
                        .is_some_and(|m| !m.iter().any(|&c| c & !3 == r))
                };
                let reach_witness = |callee: u64, r: u64, k: u64| -> bool {
                    insns
                        .iter()
                        .enumerate()
                        .filter(|(_, x)| x.is_call && x.target == Some(callee))
                        .any(|(ci, _)| {
                            for x in insns[..ci].iter().rev() {
                                if x.is_branch {
                                    return false;
                                }
                                let writes_r = x.sem.iter().any(|sop| {
                                    matches!(sop.out, Some(crate::recompile::insn::SemArg::Reg(o2, _)) if o2 & !3 == r)
                                });
                                if writes_r {
                                    return x.sem.iter().any(|sop| {
                                        matches!(sop.out, Some(crate::recompile::insn::SemArg::Reg(o2, _)) if o2 & !3 == r)
                                            && (sop.ins.iter().any(|ii| matches!(ii, crate::recompile::insn::SemArg::Const(vv, _) if *vv == k))
                                                || (k == 0 && x.mnemonic == "XOR"))
                                    });
                                }
                                if x.is_call && !preserves(x.addr, r) {
                                    return false;
                                }
                            }
                            false
                        })
                };
                let consts_witnessed = |f3: &Funcdata| -> bool {
                    for op in f3.op_ids() {
                        let o = f3.op(op);
                        if o.code() != OpCode::Call
                            || o.flags & (flags::DEAD | flags::MARKER) != 0
                        {
                            continue;
                        }
                        let Some(t) = o.input(0) else { continue };
                        let callee = f3.vn(t).loc.offset;
                        let Some(&(_, arity)) =
                            contradicted.iter().find(|&&(c, _)| c == callee)
                        else {
                            continue;
                        };
                        for i in 1..=arity.min(o.num_inputs() - 1) {
                            let Some(v) = o.input(i) else { return false };
                            let vn = f3.vn(v);
                            if !vn.is_constant() {
                                continue;
                            }
                            let k = vn.loc.offset;
                            let Some(&r) = ctx.regs.arg_reg_offs.get(i - 1) else { return false };
                            let witnessed = if reach_mode {
                                reach_witness(callee, r, k)
                            } else {
                                insns
                                .iter()
                                .enumerate()
                                .filter(|(_, x)| x.is_call && x.target == Some(callee))
                                .any(|(ci, _)| {
                                    insns[..ci]
                                        .iter()
                                        .rev()
                                        .take(12)
                                        .take_while(|x| !x.is_call && !x.is_branch)
                                        .any(|x| {
                                            x.sem.iter().any(|sop| {
                                                matches!(sop.out, Some(crate::recompile::insn::SemArg::Reg(o2, _)) if o2 & !3 == r)
                                                    && (sop.ins.iter().any(|ii| matches!(ii, crate::recompile::insn::SemArg::Const(vv, _) if *vv == k))
                                                        || (k == 0 && x.mnemonic == "XOR"))
                                            })
                                        })
                                })
                            };
                            if !witnessed {
                                return false;
                            }
                        }
                    }
                    true
                };
                // ==== ORDER Y PROBE (unlanded, `--cons-probe`) ====
                // The HELD message names four conditions at once. This splits them, and
                // for the constant-witness half re-runs the search with the intervening-
                // CALL stop REMOVED — reporting the reaching write, how many calls it had
                // to cross, and each crossed callee, so the design reads bytes not guesses.
                if ctx.cons_probe {
                    match f3.as_ref() {
                        None => notes.push(format!("[cons-probe] {name}: f3=NONE callees [{}]", list.join(" "))),
                        Some(fx) => {
                            let r1 = resolves_contradictions(fx, &contradicted);
                            let r2 = call_shapes_stable(fl, fx, &contradicted, reach_mode.then_some(&ctx.pp.recovered_protos), &evidence);
                            let r3 = sig_stable_vs(fx);
                            let r4 = consts_witnessed(fx);
                            notes.push(format!(
                                "[cons-probe] {name}: resolves={r1} shapes={r2} sig={r3} consts={r4} callees [{}]",
                                list.join(" ")
                            ));
                            if !r3 {
                                // WHICH of the three tests wearing the `sig_stable` name
                                let lp = crate::decompile::printc::rendered_param_slots(fl);
                                let cp = crate::decompile::printc::rendered_param_slots(fx);
                                let reg = fx.spaces.by_name("register");
                                let prefix_ok = cp.len() >= lp.len()
                                    && lp.iter().zip(cp.iter()).all(|(a, b)| a.addr == b.addr && a.size == b.size);
                                let landed_has_stack = lp.iter().any(|sl| Some(sl.addr.space) != reg);
                                let grows_registers = cp.len() > lp.len()
                                    && cp[lp.len()..].iter().any(|sl| Some(sl.addr.space) == reg);
                                notes.push(format!(
                                    "[cons-sig] {name} parm_regs_eq={} prefix_ok={prefix_ok} stack_to_reg={} landed={:?} cand={:?}",
                                    nondefault_parm_regs(fx, &ctx.regs.table) == nondefault_parm_regs(fl, &ctx.regs.table),
                                    landed_has_stack && grows_registers,
                                    lp.iter().map(|s| (s.addr.offset, s.size)).collect::<Vec<_>>(),
                                    cp.iter().map(|s| (s.addr.offset, s.size)).collect::<Vec<_>>()
                                ));
                            }
                            if !r2 {
                                // WHICH call drifted, and in which direction — a GROWTH at
                                // a non-contradicted callee and a LOSS are different risks.
                                let shapes = |f: &Funcdata| -> HashMap<u64, (usize, Option<u32>, u64)> {
                                    let mut m = HashMap::new();
                                    for op in f.op_ids() {
                                        let o = f.op(op);
                                        if !matches!(o.code(), OpCode::Call | OpCode::Callind)
                                            || o.flags & (flags::DEAD | flags::MARKER) != 0
                                        {
                                            continue;
                                        }
                                        let callee = if o.code() == OpCode::Call {
                                            o.input(0).map_or(0, |t| f.vn(t).loc.offset)
                                        } else {
                                            0
                                        };
                                        m.insert(
                                            o.seqnum.pc.offset,
                                            (o.num_inputs() - 1, o.output.map(|v| f.vn(v).size), callee),
                                        );
                                    }
                                    m
                                };
                                let (sl, sx) = (shapes(fl), shapes(fx));
                                let mut pcs: Vec<&u64> = sl.keys().collect();
                                pcs.sort();
                                for pc in pcs {
                                    let (n, ow, callee) = sl[pc];
                                    match sx.get(pc) {
                                        None => notes.push(format!("[cons-shape] {name} {pc:#x} callee {callee:#x} GONE (landed {n} args)")),
                                        Some(&(m, ow2, _)) if m != n || ow2 != ow => {
                                            let cont = contradicted.iter().any(|&(c, _)| c == callee);
                                            // the callee's OWN byte-derived contract, the
                                            // arbiter for whether a drift is a correction
                                            let pr = ctx.pp.recovered_protos.get(&callee);
                                            let reg = fx.spaces.by_name("register");
                                            let parity = pr.map(|p| p.params.len());
                                            let regonly = pr.map(|p| {
                                                !p.params.is_empty()
                                                    && p.params.iter().all(|s| Some(s.addr.space) == reg)
                                            });
                                            let out_used2 = fx.op_ids().find(|&o| fx.op(o).seqnum.pc.offset == *pc && matches!(fx.op(o).code(), OpCode::Call | OpCode::Callind)).and_then(|o| fx.op(o).output).map(|v| fx.vn(v).descend.len());
                                            notes.push(format!("[cons-shape]   evidence {:?} cand-out-uses {:?}", evidence.get(&callee), out_used2));
                                            notes.push(format!(
                                                "[cons-shape] {name} {pc:#x} callee {callee:#x} args {n}->{m} outw {ow:?}->{ow2:?} contradicted={cont} proto_arity={parity:?} regonly={regonly:?}"
                                            ));
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            for op in fx.op_ids() {
                                let o = fx.op(op);
                                if o.code() != OpCode::Call
                                    || o.flags & (flags::DEAD | flags::MARKER) != 0
                                {
                                    continue;
                                }
                                let Some(t) = o.input(0) else { continue };
                                let callee = fx.vn(t).loc.offset;
                                let Some(&(_, arity)) =
                                    contradicted.iter().find(|&&(c, _)| c == callee)
                                else {
                                    continue;
                                };
                                let pc = o.seqnum.pc.offset;
                                for i in 1..=arity.min(o.num_inputs() - 1) {
                                    let Some(v) = o.input(i) else { continue };
                                    let vn = fx.vn(v);
                                    if !vn.is_constant() {
                                        continue;
                                    }
                                    let k = vn.loc.offset;
                                    let Some(&r) = ctx.regs.arg_reg_offs.get(i - 1) else { continue };
                                    let Some(ci) = insns
                                        .iter()
                                        .position(|x| x.is_call && x.addr == pc)
                                    else {
                                        notes.push(format!("[cons-site] {name} {pc:#x} callee {callee:#x} arg{i} k={k:#x} NO-INSN"));
                                        continue;
                                    };
                                    // reaching write of r, crossing calls, stopping at the
                                    // first write of r (that write is the value's origin)
                                    let mut crossed: Vec<String> = Vec::new();
                                    let mut verdict = "no-write".to_string();
                                    let mut dist = 0usize;
                                    for (d, x) in insns[..ci].iter().rev().enumerate() {
                                        if x.is_branch {
                                            verdict = format!("branch@{:#x}", x.addr);
                                            dist = d;
                                            break;
                                        }
                                        let writes_r = x.sem.iter().any(|sop| {
                                            matches!(sop.out, Some(crate::recompile::insn::SemArg::Reg(o2, _)) if o2 & !3 == r)
                                        });
                                        if writes_r {
                                            let mats = x.sem.iter().any(|sop| {
                                                matches!(sop.out, Some(crate::recompile::insn::SemArg::Reg(o2, _)) if o2 & !3 == r)
                                                    && (sop.ins.iter().any(|ii| matches!(ii, crate::recompile::insn::SemArg::Const(vv, _) if *vv == k))
                                                        || (k == 0 && x.mnemonic == "XOR"))
                                            });
                                            verdict = format!(
                                                "{}@{:#x}:{}",
                                                if mats { "MATCH" } else { "other-write" },
                                                x.addr,
                                                x.mnemonic
                                            );
                                            dist = d;
                                            break;
                                        }
                                        if x.is_call {
                                            crossed.push(match x.target {
                                                Some(t) => format!("{t:#x}"),
                                                None => "ind".to_string(),
                                            });
                                        }
                                    }
                                    notes.push(format!(
                                        "[cons-site] {name} {pc:#x} callee {callee:#x} arg{i} reg{r} k={k:#x} reach={verdict} dist={dist} crossed=[{}]",
                                        crossed.join(" ")
                                    ));
                                }
                            }
                        }
                    }
                }
                let carry = if !ctx.knobs.on(Switch::ArgumentCarry) {
                    Vec::new()
                } else {
                    carry_arg_sites(fl, &ctx.pp.recovered_protos, &evidence, &insns, &ctx.regs.arg_reg_offs)
                };
                match f3 {
                    Some(f3)
                        if resolves_contradictions(&f3, &contradicted)
                            && call_shapes_stable(fl, &f3, &contradicted, reach_mode.then_some(&ctx.pp.recovered_protos), &evidence)
                            && sig_stable_vs(&f3)
                            && consts_witnessed(&f3) =>
                    {
                        // The adoption's PURPOSE is the arguments; the pragma-relevant
                        // spec fields stay the LANDED ones BY CONSTRUCTION — the same
                        // invariant the network kernel enforces. Without it the scoped
                        // callee's exactness re-derives under the injected arity and
                        // flips its clause (`modify [eax]` → `modify exact [eax]`),
                        // and one memset-class callee re-declared exact moved a caller
                        // 0.900 → 0.320 (zc54's 0x1fdbc, −140w — the round's entire
                        // down mass in one function).
                        let mut f3 = f3;
                        let landed: HashMap<u64, (Option<u32>, Option<Vec<u64>>, bool)> = fl
                            .call_specs
                            .iter()
                            .filter_map(|(&op, cs)| {
                                let t = fl.op(op).input(0)?;
                                let cva = fl.vn(t).loc.offset;
                                (cva != 0).then(|| {
                                    (cva, (cs.caller_cleans, cs.cdecl_modify.clone(), cs.cdecl_exact))
                                })
                            })
                            .collect();
                        let ops_callee: Vec<(crate::decompile::op::OpId, u64)> = f3
                            .call_specs
                            .keys()
                            .filter_map(|&op| {
                                let t = f3.op(op).input(0)?;
                                let cva = f3.vn(t).loc.offset;
                                (cva != 0).then_some((op, cva))
                            })
                            .collect();
                        for (op, cva) in ops_callee {
                            if let Some((cleans, modify, exact)) = landed.get(&cva) {
                                let cs = f3.call_specs.get_mut(&op).unwrap();
                                cs.caller_cleans = *cleans;
                                cs.cdecl_modify = modify.clone();
                                cs.cdecl_exact = *exact;
                            }
                        }
                        ok = true;
                        consistency_forced = true;
                        notes.push(format!(
                            "[consistency] {name}: FORCED — under-called callees [{}]",
                            list.join(" ")
                        ));
                        f_forced = Some(f3);
                    }
                    // PER-SITE CONSTANT-ARGUMENT ADOPTION (JD decision 2, 2026-09-04): the
                    // candidate is sound everywhere but its call shapes — it also
                    // materializes a return the next call consumes, or widens one — so the
                    // whole function stays HELD, but a call whose extra arguments are all
                    // CONSTANTS, licensed the way `call_shapes_stable` licenses a drift (the
                    // callee's register-only recovered arity, its entry block not refuting
                    // the register), takes just those constants into the LANDED function:
                    // FUN_00033668's `func_0x000596b0(g, -2)`, the `MOV EDX,-2` its bytes
                    // carry and the landed world dropped. The constants are the candidate's
                    // witnessed values (`consts_witnessed`); nothing else of the candidate
                    // crosses over — the return widths, the other calls, the signature.
                    Some(f3)
                        if resolves_contradictions(&f3, &contradicted)
                            && sig_stable_vs(&f3)
                            && consts_witnessed(&f3)
                            && !constant_arg_sites(fl, &f3, &contradicted, reach_mode.then_some(&ctx.pp.recovered_protos), &evidence, &insns).is_empty() =>
                    {
                        let sites = constant_arg_sites(fl, &f3, &contradicted, reach_mode.then_some(&ctx.pp.recovered_protos), &evidence, &insns);
                        let mut fp = fl.clone();
                        let mut added: Vec<String> = Vec::new();
                        for (op, consts) in &sites {
                            for &(slot, value, size) in consts {
                                let c = fp.new_const(size, value);
                                fp.op_insert_input(*op, slot, c);
                            }
                            added.push(format!("{:#x}+{}", fp.op(*op).seqnum.pc.offset, consts.len()));
                        }
                        ok = true;
                        consistency_forced = true;
                        notes.push(format!("[consistency] {name}: PER-SITE constant arguments adopted at [{}]", added.join(" ")));
                        f_forced = Some(fp);
                    }
                    // ARGUMENT CARRY (2026-09-04): the register arguments the landed
                    // function passes to a call beyond that callee's own arity, which the
                    // callee preserves and the NEXT call's arity names, move to the next
                    // call — `f1(x, 8, 0x14); f2();` becomes `f2(f1(x), 8, 0x14);`. Decided
                    // from the landed function and the bytes alone ([`carry_arg_sites`]);
                    // nothing else of any candidate crosses over.
                    _ if !carry.is_empty() => {
                        let mut fp = fl.clone();
                        let mut moved: Vec<String> = Vec::new();
                        for site in &carry {
                            for &(slot, _) in site.slots.iter().rev() {
                                fp.op_remove_input(site.from, slot);
                            }
                            match site.fill {
                                CarryFill::None => {}
                                CarryFill::Return => {
                                    let v = fp.new_unique(4);
                                    fp.op_set_output(site.from, v);
                                    fp.op_insert_input(site.to, 1, v);
                                }
                            }
                            for &(slot, vn) in &site.slots {
                                let v = if fp.vn(vn).is_constant() {
                                    let (sz, k) = (fp.vn(vn).size, fp.vn(vn).constant_value());
                                    fp.new_const(sz, k)
                                } else {
                                    vn
                                };
                                fp.op_insert_input(site.to, slot, v);
                            }
                            moved.push(format!(
                                "{:#x}->{:#x}+{}{}",
                                fp.op(site.from).seqnum.pc.offset,
                                fp.op(site.to).seqnum.pc.offset,
                                site.slots.len(),
                                match site.fill { CarryFill::None => "", CarryFill::Return => "r" }
                            ));
                        }
                        ok = true;
                        consistency_forced = true;
                        notes.push(format!("[consistency] {name}: CARRY adopted [{}]", moved.join(" ")));
                        f_forced = Some(fp);
                    }
                    _ => {
                        notes.push(format!(
                            "[consistency] {name}: HELD (unbound/unwitnessed value, call-shape drift, or unstable signature) — callees [{}]",
                            list.join(" ")
                        ));
                    }
                }
            }
        }
        if crate::debug::on(crate::debug::Topic::Watsched) {
            let reason = if consistency_forced {
                "adopted:consistency"
            } else if passthrough {
                "adopted:passthrough"
            } else if ok {
                "adopted"
            } else if !sig_stable {
                "refused:signature"
            } else if !no_collision {
                "refused:collision"
            } else if networked {
                "refused:network"
            } else if cand.is_empty() || insns.is_empty() {
                "refused:no-candidate"
            } else if crate::recompile::watsched::order_regressed(&insns, &cand) {
                "refused:scheduler"
            } else {
                "refused:allocation"
            };
            crate::debug!(crate::debug::Topic::Watsched, "zapcheck {name}: {reason}");
        }
        if ok {
            return Some(f_forced.unwrap_or(f2));
        }
    }
    None
}

/// The callees this decompile UNDER-CALLS: a live CALL to a callee whose whole-program
/// recovered prototype is REGISTER-ONLY with N parameters, passing fewer than N inputs.
/// This is the cross-TU contradiction of the consistency doctrine (JD 2026-08-24): the
/// callee's own TU declares those parameters, so a caller that omits them links into a
/// program that reads garbage — invisible to per-function byte comparison by construction.
pub fn under_called_register_callees(
    f: &crate::decompile::funcdata::Funcdata,
    pp: &crate::analysis::program::Program,
) -> Vec<(u64, usize)> {
    let Some(reg) = f.spaces.by_name("register") else { return Vec::new() };
    let mut out: Vec<(u64, usize)> = Vec::new();
    for op in f.op_ids() {
        let o = f.op(op);
        if o.code() != OpCode::Call || o.flags & (flags::DEAD | flags::MARKER) != 0 {
            continue;
        }
        let Some(t) = o.input(0) else { continue };
        let callee = f.vn(t).loc.offset;
        if callee == 0 {
            continue;
        }
        let Some(proto) = pp.recovered_protos.get(&callee) else { continue };
        // The register-only domain, mirroring `locked_register_inputs`: a prototype naming
        // stack storage keeps the trial path and is not this contradiction class.
        if proto.params.is_empty() || !proto.params.iter().all(|s| s.addr.space == reg) {
            continue;
        }
        // UNDER-called only (the callee reads a register the caller never set). The over-call
        // direction (A6) is reverted: its clamp dropped constant arguments the original genuinely
        // pushes when the callee's use-based prototype under-states its arity (0x5fb24: the `0`
        // at a callee that ignores its 3rd param), a wrong-code loss the byte-witness the clamp
        // cannot see would prevent — refiled for the survey side where the bytes exist.
        if o.num_inputs() - 1 < proto.params.len() && !out.iter().any(|&(c, _)| c == callee) {
            out.push((callee, proto.params.len()));
        }
    }
    out
}

/// Does the candidate decompile RESOLVE every named contradiction — each call to the callee
/// carries at least the declared register arity, every declared-parameter input holding a
/// REAL bound value (a constant, a written varnode, or a function input)? A manufactured
/// free varnode — the historical `XOR reg,reg`-from-nowhere class — fails the test: that is
/// a wrong program of a different kind, held as a bug rather than emitted.
pub fn resolves_contradictions(
    f2: &crate::decompile::funcdata::Funcdata,
    contradicted: &[(u64, usize)],
) -> bool {
    for op in f2.op_ids() {
        let o = f2.op(op);
        if o.code() != OpCode::Call || o.flags & (flags::DEAD | flags::MARKER) != 0 {
            continue;
        }
        let Some(t) = o.input(0) else { continue };
        let callee = f2.vn(t).loc.offset;
        let Some(&(_, arity)) = contradicted.iter().find(|&&(c, _)| c == callee) else { continue };
        if o.num_inputs() - 1 < arity {
            return false; // the candidate still under-calls it
        }
        for i in 1..=arity {
            let Some(v) = o.input(i) else { return false };
            let vn = f2.vn(v);
            // An INDIRECT-creation constant is a killedbycall zero manufactured by the
            // decompiler, not a value the caller places — 12c58's `(0, 0)` by name.
            if vn.is_constant() && vn.is_indirect_creation() {
                return false;
            }
            if !(vn.is_constant() || vn.is_written() || vn.is_input()) {
                return false; // unbound (manufactured) value — the XOR-zero bug class
            }
        }
    }
    true
}

/// Every call's SHAPE must be stable between the landed decompile and the surgical candidate —
/// argument count, output presence, output width — except argument GROWTH at the contradicted
/// callees (the adoption's whole purpose). Matched by instruction address, indirect calls
/// included. This subsumes the monotone rule ("propagation removed an argument" was measured as
/// a near-perfect regression predictor; zc52's 0x11b9c, and zc53's 0x2d360 where a CALLIND lost
/// its buffer argument) and catches the collateral type ripple (zc53's 0x2247c: an unrelated
/// call's return width drifted 1 → 4 and re-rendered with a cast).
/// FIRST-TOUCH evidence for the watcall argument registers in a callee's ENTRY BLOCK, read from
/// the callee's OWN bytes — the arbiter our `recovered_protos` is only testimony about (Order Y,
/// and X(3)'s rule that `PUSH`/`POP` are the save prologue, not reads):
///
///   `Some(true)`  read (or read-modified) before any write — the callee takes it as an input;
///   `Some(false)` written before any read — it CANNOT be an input (`0x4fe64`'s
///                 `mov edx,[0x99594]`, `0x678ec`'s `xor ebx,ebx`, `0x67b44`'s `mov eax,0x64`);
///   `None`        untouched before the first call or branch, so the entry block does not decide
///                 — `0x50480`'s EAX passes through to its nested call and is a real input.
///
/// The gate built on this REFUSES only `Some(false)`: undecided is not evidence against.
pub fn callee_input_evidence(
    insns: &[crate::recompile::insn::NormInsn],
    arg_regs: &[u64],
) -> Vec<Option<bool>> {
    use crate::recompile::insn::SemArg;
    let mut v = vec![None; arg_regs.len()];
    for x in insns {
        if x.is_branch || x.is_call {
            break;
        }
        if x.mnemonic == "PUSH" || x.mnemonic == "POP" {
            continue;
        }
        // `XOR r,r` / `SUB r,r` is the zero idiom: it writes r, it does not read it.
        let zero_idiom = matches!(x.mnemonic.as_str(), "XOR" | "SUB")
            && x.sem.iter().any(|o| {
                matches!((o.out.as_ref(), o.ins.first()), (Some(SemArg::Reg(a, _)), Some(SemArg::Reg(b, _))) if a == b)
            });
        for (i, &r) in arg_regs.iter().enumerate() {
            if v[i].is_some() {
                continue;
            }
            let reads = !zero_idiom
                && x.sem.iter().any(|o| {
                    o.ins.iter().any(|a| matches!(a, SemArg::Reg(o2, _) if o2 & !3 == r))
                });
            let writes = x
                .sem
                .iter()
                .any(|o| matches!(o.out, Some(SemArg::Reg(o2, _)) if o2 & !3 == r));
            if reads {
                v[i] = Some(true);
            } else if writes {
                v[i] = Some(false);
            }
        }
    }
    v
}

pub fn call_shapes_stable(
    fl: &crate::decompile::funcdata::Funcdata,
    fx: &crate::decompile::funcdata::Funcdata,
    contradicted: &[(u64, usize)],
    // CONTRACT-DIRECTED DRIFT (the `cons-reach` switch, on by default; Order Y): the callee's own recovered
    // prototype — the arity its BODY shows it reads — may license a drift the flat rule refuses.
    // Measured on the 14 arity-defect TUs: every drifting site moves TOWARD the callee's
    // register-only recovered arity and none moves away (0x59404 3->1 with proto 1, whose entry
    // `PUSH EBX/ECX/EDX` and single `MOV ECX,EAX` read make 1 the byte truth). `None` = the
    // landed flat rule.
    protos: Option<&std::collections::HashMap<u64, crate::decompile::fspec::FuncProto>>,
    // The callee's OWN entry-block testimony per argument register ([`callee_input_evidence`]):
    // a drift may never drop a register the callee is byte-proven to READ, and may never land on
    // an arity whose registers the callee is byte-proven to WRITE first.
    evidence: &HashMap<u64, Vec<Option<bool>>>,
) -> bool {
    // (args, output width, direct-callee va or 0, the output is consumed by something)
    type Shape = (usize, Option<u32>, u64, bool);
    let shapes = |f: &crate::decompile::funcdata::Funcdata| -> HashMap<u64, Shape> {
        let mut m = HashMap::new();
        for op in f.op_ids() {
            let o = f.op(op);
            if !matches!(o.code(), OpCode::Call | OpCode::Callind)
                || o.flags & (flags::DEAD | flags::MARKER) != 0
            {
                continue;
            }
            let callee = if o.code() == OpCode::Call {
                o.input(0).map_or(0, |t| f.vn(t).loc.offset)
            } else {
                0
            };
            let outw = o.output.map(|v| f.vn(v).size);
            let out_used = o.output.is_some_and(|v| !f.vn(v).descend.is_empty());
            m.insert(o.seqnum.pc.offset, (o.num_inputs() - 1, outw, callee, out_used));
        }
        m
    };
    let (l, x) = (shapes(fl), shapes(fx));
    let reg = fx.spaces.by_name("register");
    l.iter().all(|(pc, &(n, outw, callee, _))| {
        x.get(pc).is_some_and(|&(m, outw2, _, out_used2)| {
            let grows_ok = contradicted.iter().any(|&(c, _)| c == callee);
            // The candidate lands EXACTLY on a register-only recovered contract the landed world
            // missed: the drift is that callee's own testimony, not churn. Output width still has
            // to hold — a materialized return is a different class and is not licensed here.
            let ev = evidence.get(&callee);
            let byte_ok = ev.is_some_and(|e| {
                // Nothing the new arity passes may be byte-refuted, and every register it DROPS
                // must be byte-REFUTED — undecided is not permission. `None` means the entry block
                // does not decide, and `0x50480`'s EAX is the standing proof that a `None` register
                // can be a real input (untouched before the nested call it passes through to).
                // Undecided is therefore treated the SAME on both sides: growth keeps it because it
                // might be read, so a drop must keep it for the identical reason. Dropping one is
                // this thread's own wrong code with the sign reversed — and a score round cannot
                // catch it, since the wrong-code gate keys on memory writes, not on an argument
                // that stops being passed.
                (0..m).all(|i| e.get(i).copied().flatten() != Some(false))
                    && (m..n).all(|i| e.get(i).copied().flatten() == Some(false))
            });
            let contract_ok = callee != 0
                && m != n
                && byte_ok
                && protos.and_then(|p| p.get(&callee)).is_some_and(|p| {
                    !p.params.is_empty()
                        && p.params.iter().all(|s| Some(s.addr.space) == reg)
                        && p.params.len() == m
                        && p.params.len() != n
                });
            // A return value the candidate MATERIALIZES but never consumes prints the same
            // call statement as no return at all — the callee's prototype says it returns,
            // nothing in this function reads it. Only the unused case is licensed; a consumed
            // materialized return stays the different class it always was (JD's decision 2,
            // 2026-09-04: adopt the callee's arity site by site — FUN_00033668's `-2`, whose
            // five contracted drifts all land on their callees' arities and were held by
            // exactly this width change on three of them).
            let outw_ok = outw2 == outw || (outw.is_none() && outw2.is_some() && !out_used2);
            outw_ok && (contract_ok || if grows_ok { m >= n } else { m == n })
        })
    })
}

/// The per-site half of the consistency adoption (JD decision 2, 2026-09-04): the landed
/// calls whose candidate counterpart passes MORE arguments, every extra one a CONSTANT, where
/// the drift is licensed exactly as [`call_shapes_stable`] licenses one — the callee's
/// register-only recovered arity is the candidate's count and the callee's entry block refutes
/// none of the passed registers — but WITHOUT the output-width condition (the call's return is
/// not what is adopted). Returns `(landed call op, [(input slot, value, size)])` per site, the
/// slots in ascending order so insertion keeps the candidate's argument order.
///
/// The SITE's own bytes decide (JD's design): each extra constant must be MATERIALIZED into
/// its parameter register right before the call — the first write of that register walking
/// back from the call is `MOV r,imm` of that value (or `XOR r,r` for 0), with no call and no
/// branch crossed. A constant that reaches the call from an earlier write across other calls
/// (the Y-series' `func_0x00050108(0x3c, 0x1cc, 0x21330)`, FUN_00040490) is real to the
/// callee but not to the bytes: this compiler re-materializes an explicit argument, and the
/// function lost EXACT to it in round e41.
pub fn constant_arg_sites(
    fl: &crate::decompile::funcdata::Funcdata,
    fx: &crate::decompile::funcdata::Funcdata,
    contradicted: &[(u64, usize)],
    protos: Option<&std::collections::HashMap<u64, crate::decompile::fspec::FuncProto>>,
    evidence: &HashMap<u64, Vec<Option<bool>>>,
    insns: &[crate::recompile::insn::NormInsn],
) -> Vec<(crate::decompile::op::OpId, Vec<(usize, u64, u32)>)> {
    use crate::recompile::insn::SemArg;
    // the first write of register `r` (container) walking back from instruction `ci`, if it
    // is a materialization of `value` and nothing crossed is a call or a branch
    let materialized_before = |ci: usize, r: u64, value: u64, size: u32| -> bool {
        let mask = if size >= 8 { u64::MAX } else { (1u64 << (8 * size)) - 1 };
        for x in insns[..ci].iter().rev() {
            if x.is_call || x.is_branch {
                return false;
            }
            let writes_r = x.sem.iter().any(|op| matches!(op.out, Some(SemArg::Reg(o, _)) if o & !3 == r & !3));
            if !writes_r {
                continue;
            }
            let mov_imm = x.mnemonic == "MOV"
                && x.sem.iter().any(|op| {
                    matches!(op.out, Some(SemArg::Reg(o, _)) if o & !3 == r & !3)
                        && matches!(op.ins.as_slice(), [SemArg::Const(c, _)] if c & mask == value & mask)
                });
            let xor_zero = x.mnemonic == "XOR" && value & mask == 0 && x.regs.iter().all(|&(o, _)| o & !3 == r & !3);
            return mov_imm || xor_zero;
        }
        false
    };
    let reg = fx.spaces.by_name("register");
    let calls = |f: &crate::decompile::funcdata::Funcdata| -> HashMap<u64, crate::decompile::op::OpId> {
        f.op_ids()
            .filter(|&op| f.op(op).code() == OpCode::Call && f.op(op).flags & (flags::DEAD | flags::MARKER) == 0)
            .map(|op| (f.op(op).seqnum.pc.offset, op))
            .collect()
    };
    let (l, x) = (calls(fl), calls(fx));
    let mut out = Vec::new();
    let mut pcs: Vec<&u64> = l.keys().collect();
    pcs.sort();
    for pc in pcs {
        let lop = l[pc];
        let Some(&xop) = x.get(pc) else { continue };
        let (lo, xo) = (fl.op(lop), fx.op(xop));
        let Some(t) = lo.input(0) else { continue };
        let callee = fl.vn(t).loc.offset;
        if callee == 0 || xo.input(0).map(|t2| fx.vn(t2).loc.offset) != Some(callee) {
            continue;
        }
        let (n, m) = (lo.num_inputs() - 1, xo.num_inputs() - 1);
        if m <= n || !contradicted.iter().any(|&(c, _)| c == callee) {
            continue;
        }
        let byte_ok = evidence.get(&callee).is_some_and(|e| (0..m).all(|i| e.get(i).copied().flatten() != Some(false)));
        let contract_ok = byte_ok
            && protos.and_then(|p| p.get(&callee)).is_some_and(|p| {
                !p.params.is_empty() && p.params.iter().all(|s| Some(s.addr.space) == reg) && p.params.len() == m
            });
        if !contract_ok {
            continue;
        }
        // the landed prefix must be the candidate's prefix (same values), and every extra a constant
        let same_prefix = (1..=n).all(|i| match (lo.input(i), xo.input(i)) {
            (Some(a), Some(b)) => {
                let (va, vb) = (fl.vn(a), fx.vn(b));
                va.loc == vb.loc && va.size == vb.size && (!va.is_constant() || va.constant_value() == vb.constant_value())
            }
            _ => false,
        });
        if !same_prefix {
            continue;
        }
        let Some(ci) = insns.iter().position(|x| x.addr == *pc) else { continue };
        let params = protos.and_then(|p| p.get(&callee)).map(|p| &p.params);
        let mut consts = Vec::new();
        for i in (n + 1)..=m {
            let Some(v) = xo.input(i) else { break };
            let vn = fx.vn(v);
            if !vn.is_constant() {
                break;
            }
            // the parameter register of slot `i` (the candidate's order is the prototype's)
            let Some(r) = params.and_then(|ps| ps.get(i - 1)).map(|s| s.addr.offset) else { break };
            if !materialized_before(ci, r, vn.constant_value(), vn.size) {
                break;
            }
            consts.push((i, vn.constant_value(), vn.size));
        }
        if consts.len() == m - n {
            out.push((lop, consts));
        }
    }
    out
}

/// An argument CARRIED across a call (2026-09-04): a register the landed function passes to call
/// `from` BEYOND that callee's own recovered arity, which the callee's recovered clobber set
/// preserves, and which the NEXT call `to` consumes — `to`'s own arity names the register at the
/// same positional slot and the landed site does not pass that slot. The decompiler attributes a
/// register set up before a call to that call; the bytes attribute it to the consumer: the value
/// is placed before `from` (a constant by `MOV r,k` / `XOR r,r` in the pre-call window), the
/// register is never written between the two calls, and `from` preserves it. `f1(x, 8, 0x14);
/// f2();` is `f2(f1(x), 8, 0x14);` — FUN_00030ca0, FUN_0004c364; `f1(x, g); f2(k);` is
/// `f1(x); f2(k, g);` — FUN_00034370. Probed EXACT on all three before the rule was written.
///
/// `fill`: the consumer's slot 1 when the landed consumer passes nothing — `Return` when `from`
/// clobbers EAX (its value at `to` is whatever `from` returned: the nested form), `Same(v)` when
/// `from` preserves EAX (the consumer receives `from`'s own first argument).
pub enum CarryFill {
    None,
    Return,
}
pub struct CarrySite {
    from: crate::decompile::op::OpId,
    to: crate::decompile::op::OpId,
    /// (positional slot, the landed varnode at `from`), ascending
    slots: Vec<(usize, crate::decompile::varnode::VarnodeId)>,
    fill: CarryFill,
}

pub fn carry_arg_sites(
    fl: &crate::decompile::funcdata::Funcdata,
    protos: &std::collections::HashMap<u64, crate::decompile::fspec::FuncProto>,
    // each direct callee's own entry-block testimony per argument register ([`callee_input_evidence`])
    evidence: &HashMap<u64, Vec<Option<bool>>>,
    insns: &[crate::recompile::insn::NormInsn],
    arg_reg_offs: &[u64],
) -> Vec<CarrySite> {
    use crate::recompile::insn::{NormInsn, SemArg};
    let Some(reg) = fl.spaces.by_name("register") else { return Vec::new() };
    // register-only AND positional: slot k lives in the convention's k-th register, so a slot
    // beyond the recovered arity has one register too
    let positional = |p: &crate::decompile::fspec::FuncProto| -> bool {
        !p.params.is_empty()
            && p.params.len() <= arg_reg_offs.len()
            && p.params.iter().enumerate().all(|(k, s)| s.addr.space == reg && s.addr.offset == arg_reg_offs[k])
    };
    let writes = |x: &NormInsn, r: u64| -> bool {
        x.sem.iter().any(|op| matches!(op.out, Some(SemArg::Reg(o, _)) if o & !3 == r & !3))
    };
    let mut calls: Vec<(u64, crate::decompile::op::OpId, u64)> = fl
        .op_ids()
        .filter(|&op| fl.op(op).code() == OpCode::Call && fl.op(op).flags & (flags::DEAD | flags::MARKER) == 0)
        .filter_map(|op| fl.op(op).input(0).map(|t| (fl.op(op).seqnum.pc.offset, op, fl.vn(t).loc.offset)))
        .filter(|&(_, _, c)| c != 0)
        .collect();
    calls.sort();
    let mut out = Vec::new();
    for w in calls.windows(2) {
        let ((pc1, c1, a), (pc2, c2, b)) = (w[0], w[1]);
        if fl.op(c1).parent.is_none() || fl.op(c1).parent != fl.op(c2).parent {
            continue;
        }
        let (Some(pa), Some(pb)) = (protos.get(&a), protos.get(&b)) else { continue };
        // `from`'s own parameters positional, so its extra slots have positional registers too;
        // `to` register-only — the CALLER renders its call positionally (a K&R extern without a
        // `parm` clause), whatever register names its own prototype recovered
        if !positional(pa) || pb.params.is_empty() || !pb.params.iter().all(|s| s.addr.space == reg) {
            continue;
        }
        // the consumer's arity, witnessed: its use-based proto is routinely UNDER-recovered
        // (0x16bdc's body reads eax/edx/ebx, its proto shows 2), so take the widest count the
        // LANDED function itself passes to this callee anywhere as the floor. A callee the
        // program only ever calls with N args does not silently take an (N+1)th here — that is
        // 0x40490's `func_0x0004fe64(0x1cc, 4)`, whose `ebx` set before the PRIOR call is that
        // call's own third argument, not a carry.
        let nb_wit = fl
            .op_ids()
            .filter(|&op| fl.op(op).code() == OpCode::Call && fl.op(op).flags & (flags::DEAD | flags::MARKER) == 0)
            .filter(|&op| fl.op(op).input(0).map(|t| fl.vn(t).loc.offset) == Some(b))
            .map(|op| fl.op(op).num_inputs() - 1)
            .max()
            .unwrap_or(0)
            .max(pb.params.len());
        let (n1, n2) = (fl.op(c1).num_inputs() - 1, fl.op(c2).num_inputs() - 1);
        let na = pa.params.len();
        if n1 <= na {
            continue;
        }
        let Some(modify) = fl.call_specs.get(&c1).and_then(|cs| cs.cdecl_modify.as_ref()) else { continue };
        let preserved = |r: u64| !modify.iter().any(|&c| c & !3 == r & !3);
        let (Some(ca), Some(cb)) = (
            insns.iter().position(|x| x.is_call && x.addr == pc1),
            insns.iter().position(|x| x.is_call && x.addr == pc2),
        ) else {
            continue;
        };
        if ca >= cb {
            continue;
        }
        let between = &insns[ca + 1..cb];
        // Between the two calls, only ARGUMENT-REGISTER SETUP is allowed: every instruction
        // writes an argument register and touches no memory. A store between them (0x12360's
        // `mov [0x81288],eax`, consuming the prior return) means the second call is NOT reusing
        // the first's register environment — the args are separately set up and this is not a
        // carry. Nothing between (0x30ca0) or a plain `mov argreg,K` (0x34370) is the carry shape.
        let arg_set: std::collections::HashSet<u64> = arg_reg_offs.iter().map(|&r| r & !3).collect();
        let clean_between = between.iter().all(|x| {
            // writes ONLY argument registers (a `mov argreg,K`, `lea argreg,[..]`, `mov argreg,[g]`
            // consumer-arg setup) and writes NO memory. A store — 0x12360's `mov [0x81288],eax`
            // consuming the prior return — means the second call is not reusing the first's
            // register environment, so it is not a carry. Address computation and loads into an
            // arg register are the consumer setting up its own arguments and are fine.
            let is_store = x.mnemonic == "MOV" && x.sem.iter().any(|op| matches!(op.out, Some(SemArg::Mem(..)) | Some(SemArg::Space(..))));
            !x.is_call
                && !x.is_branch
                && !is_store
                && x.sem.iter().all(|op| match op.out {
                    Some(SemArg::Reg(o, _)) => arg_set.contains(&(o & !3)),
                    None => true,
                    _ => false,
                })
                && x.sem.iter().any(|op| matches!(op.out, Some(SemArg::Reg(o, _)) if arg_set.contains(&(o & !3))))
        });
        if !clean_between {
            continue;
        }
        // a SUFFIX of `from`'s extra slots (removing a middle slot would shift the ones above it
        // into other registers), each consumed at the same positional slot of `to`: the slot
        // exists in `to`'s arity, the landed consumer does not pass it, `to`'s entry block does
        // not refute the register and `from`'s does not claim it
        let (ea, eb) = (evidence.get(&a), evidence.get(&b));
        let claimed = |e: Option<&Vec<Option<bool>>>, i: usize| e.and_then(|v| v.get(i - 1).copied().flatten()) == Some(true);
        let refuted = |e: Option<&Vec<Option<bool>>>, i: usize| e.and_then(|v| v.get(i - 1).copied().flatten()) == Some(false);
        let mut slots = Vec::new();
        for i in ((na + 1)..=n1).rev() {
            // bounded by the consumer's WITNESSED arity (nb_wit), not its under-recovered
            // proto: a slot beyond every landed call to this callee is the FROM call's own
            // argument, not a carry
            if i > nb_wit || i <= n2 || claimed(ea, i) || refuted(eb, i) {
                break;
            }
            // the caller renders `to` POSITIONALLY: the emitted extern carries a `modify` pragma
            // only (the callee's own `parm [..]` clause lives in its own TU, not the caller's), so
            // argument i lands in the i-th positional register. 0x1755c's `0x17530` is in EBX =
            // slot 3's positional register, matching the original `mov ebx,0x17530`.
            let r = arg_reg_offs[i - 1];
            if !preserved(r) || between.iter().any(|x| writes(x, r)) {
                break;
            }
            let Some(vn) = fl.op(c1).input(i) else { break };
            let v = fl.vn(vn);
            if v.is_constant() {
                // the constant is placed right before `from`: the first write of r walking back
                // is `MOV r,k` (or `XOR r,r` for 0), no call and no branch crossed
                let k = v.constant_value();
                let mask = if v.size >= 8 { u64::MAX } else { (1u64 << (8 * v.size)) - 1 };
                let mut placed = false;
                for x in insns[..ca].iter().rev() {
                    if x.is_call || x.is_branch {
                        break;
                    }
                    if !writes(x, r) {
                        continue;
                    }
                    placed = (x.mnemonic == "MOV"
                        && x.sem.iter().any(|op| {
                            matches!(op.out, Some(SemArg::Reg(o, _)) if o & !3 == r & !3)
                                && matches!(op.ins.as_slice(), [SemArg::Const(c, _)] if c & mask == k & mask)
                        }))
                        || (x.mnemonic == "XOR" && k & mask == 0 && x.regs.iter().all(|&(o, _)| o & !3 == r & !3));
                    break;
                }
                if !placed {
                    break;
                }
            }
            slots.push((i, vn));
        }
        if slots.is_empty() {
            continue;
        }
        slots.reverse();
        // the consumer's slots stay contiguous from its landed count up to the highest carried
        // one; slot 1 may be filled when the landed consumer passes nothing
        let max = slots.iter().map(|s| s.0).max().unwrap();
        let mut fill = CarryFill::None;
        let eax = arg_reg_offs[0];
        let contiguous = (n2 + 1..=max).all(|s| {
            if slots.iter().any(|t| t.0 == s) {
                return true;
            }
            // slot 1 only, and only as the FROM call's RETURN (from clobbers eax, passes nothing
            // of its own there): the nested form `to(from(..), ..)`. The `Same` fill — reusing
            // from's own first argument — was removed: 0x2a6e0 rendered `f(param_1, param_1)`,
            // an argument the original never places.
            if s == 1 && n2 == 0 && !between.iter().any(|x| writes(x, eax)) && !preserved(eax) && fl.op(c1).output.is_none() {
                fill = CarryFill::Return;
                return true;
            }
            false
        });
        if !contiguous {
            continue;
        }
        out.push(CarrySite { from: c1, to: c2, slots, fill });
    }
    out
}

/// The candidate per-call register effects for the zap checker: for each direct call with
/// a recovered contract, OW `CallZap`'s arithmetic (i86reg.c:256) under the candidate
/// declarations — writes = kill set ∪ (parm.used ∪ EAX unless `exact`), reads = parm.used
/// (this call's register-located argument inputs). Calls without a contract get no entry
/// and keep the model's conservative fixed behavior.
pub fn candidate_call_effects(f: &Funcdata) -> crate::recompile::watsched::CallEffects {
    let mut out = crate::recompile::watsched::CallEffects::new();
    let Some(reg) = f.spaces.by_name("register") else { return out };
    for opid in f.op_ids() {
        let o = f.op(opid);
        if o.code() != OpCode::Call || o.flags & (flags::DEAD | flags::MARKER) != 0 {
            continue;
        }
        let Some(cs) = f.call_specs.get(&opid) else { continue };
        let Some(kill) = cs.cdecl_modify.as_ref() else { continue };
        let parms: Vec<(u64, u32)> = (1..o.num_inputs())
            .filter_map(|i| o.input(i))
            .filter_map(|v| {
                let vn = f.vn(v);
                (vn.loc.space == reg && vn.loc.offset < 0x20)
                    .then_some((vn.loc.offset, vn.size))
            })
            .collect();
        let mut writes: Vec<(u64, u32)> =
            kill.iter().filter(|&&k| k < 0x20).map(|&k| (k & !3, 4)).collect();
        if !cs.cdecl_exact {
            for &(p, sz) in &parms {
                writes.push((p, sz));
            }
            writes.push((0, 4));
        }
        writes.sort_unstable();
        writes.dedup();
        out.insert(o.seqnum.pc.offset, (parms, writes));
    }
    out
}

/// The allocator cost kernel's ZERO-COST special case (phase 2 of the register-allocator
/// model; OW regalloc.c GiveBestReg/CountRegMoves grounding): an upgrade whose ONLY effect
/// is appending pass-through arguments in their own arrival registers adds no
/// register-register moves and no conflict-graph edges, so the allocator's assignment is
/// provably unchanged — CalcSavings needn't be computed when its delta is zero. Decided on
/// the RENDERED text of the landed vs candidate decompiles, line-zipped strictly:
///
///   - callee `#pragma aux func_0x...` lines may differ (they ARE the arity/exactness
///     recovery being adopted);
///   - the own signature may only APPEND `xunknown4 param_N` parameters (an existing
///     param's storage or TYPE changing — 34fe0's char→xunknown4 — refuses);
///   - a call may only APPEND `param_N` arguments, each at argument position N−1: the
///     position IS the register (Watcom slots args by position), and position N−1 means
///     the value is consumed in the register it arrives in — a self-move. A duplicated or
///     displaced param (5ed78's `(p1,p2,p3,p1)`), a reordered prefix (659ec, 73338), or
///     any other body change refuses. A CONSTANT literal may append at any position: the
///     prototype pass binds it from the ORIGINAL's own dataflow, so the materializing
///     `MOV imm` already exists in the original bytes (6b4e0's `(0xa8744, 4)`) — declaring
///     it moves nothing;
///   - the own `#pragma aux FUN_...` line must be IDENTICAL (73338's upgrade silently
///     dropped its `parm caller []` fact);
///   - any other differing line, or a line-count change, refuses.
///
/// Measured on the force-adoption census (x-alloc round, 2026-08-22): adopts exactly the
/// 3 gains {26b18, 294dc, 6b4e0}, refuses all 6 protected EXACTs.
/// Shadow-census tightening: every callee-pragma line that CHANGES between the landed
/// and candidate renders must keep everything before its `modify` clause verbatim — the
/// `parm [..]` / `parm caller []` half is the caller-side marshalling contract, and a
/// changed one re-pairs positional arguments (the 3925c inversion wart).
pub fn parm_clauses_stable(landed: &str, cand: &str) -> bool {
    let ll: Vec<&str> = landed.lines().collect();
    let cl: Vec<&str> = cand.lines().collect();
    if ll.len() != cl.len() {
        return false;
    }
    for (l, c) in ll.iter().zip(cl.iter()) {
        if l == c || !l.starts_with("#pragma aux func_0x") {
            continue;
        }
        let head = |x: &str| x.split(" modify").next().unwrap_or(x).to_string();
        if head(l) != head(c) {
            return false;
        }
    }
    true
}

/// Order-changing census (missing-args thread): the render delta consists ONLY of call
/// lines whose top-level argument lists hold the SAME multiset in a DIFFERENT order —
/// every other line verbatim. Returns the callees of the permuted calls.
pub fn order_only_delta(landed: &str, cand: &str) -> Option<Vec<u64>> {
    let ll: Vec<&str> = landed.lines().collect();
    let cl: Vec<&str> = cand.lines().collect();
    if ll.len() != cl.len() {
        return None;
    }
    let args_of = |line: &str| -> Option<(u64, Vec<String>)> {
        let i = line.find("func_0x")?;
        let callee = u64::from_str_radix(line.get(i + 7..i + 15)?, 16).ok()?;
        let open = line[i..].find('(')? + i;
        let mut depth = 0i32;
        let mut end = None;
        for (j, ch) in line[open..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + j);
                        break;
                    }
                }
                _ => {}
            }
        }
        let inner = &line[open + 1..end?];
        let mut args = Vec::new();
        let (mut d, mut start) = (0i32, 0usize);
        for (j, ch) in inner.char_indices() {
            match ch {
                '(' | '[' => d += 1,
                ')' | ']' => d -= 1,
                ',' if d == 0 => {
                    args.push(inner[start..j].trim().to_string());
                    start = j + 1;
                }
                _ => {}
            }
        }
        if !inner[start..].trim().is_empty() {
            args.push(inner[start..].trim().to_string());
        }
        Some((callee, args))
    };
    let mut callees = Vec::new();
    for (l, c) in ll.iter().zip(cl.iter()) {
        if l == c {
            continue;
        }
        let (Some((k1, mut a1)), Some((k2, mut a2))) = (args_of(l), args_of(c)) else { return None };
        if k1 != k2 || a1.len() != a2.len() || a1 == a2 {
            return None;
        }
        // outside the arg lists the lines must agree
        let strip = |line: &str, args: &[String]| -> String {
            let mut t = line.to_string();
            for a in args {
                t = t.replacen(a.as_str(), "", 1);
            }
            t
        };
        if strip(l, &a1) != strip(c, &a2) {
            return None;
        }
        a1.sort();
        a2.sort();
        if a1 != a2 {
            return None; // different multiset — not a pure permutation
        }
        callees.push(k1);
    }
    if callees.is_empty() { None } else { Some(callees) }
}

pub fn pass_through_only(landed: &str, cand: &str, va: u64) -> bool {
    pass_through_report(landed, cand, va, None, None)
}

pub fn pass_through_report(landed: &str, cand: &str, va: u64, mut consts: Option<&mut Vec<(u64, u32, u64)>>, mut stack_appends: Option<&mut Vec<(u64, u32)>>) -> bool {
    let fun = format!("FUN_{va:08x}");
    let own_pragma = format!("#pragma aux {fun}");
    let ll: Vec<&str> = landed.lines().collect();
    let cl: Vec<&str> = cand.lines().collect();
    if ll.len() != cl.len() {
        return false;
    }
    let param_at = |args: &str, from: usize| -> Option<u32> {
        // the appended text at `from` must be `param_<N>` up to `,` or `)`
        let rest = &args[from..];
        let rest = rest.strip_prefix(", ").unwrap_or(rest);
        let num = rest.strip_prefix("param_")?;
        let digits: String = num.chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse().ok()
    };
    for (l, c) in ll.iter().zip(cl.iter()) {
        if l == c {
            continue;
        }
        if l.starts_with(&own_pragma) || c.starts_with(&own_pragma) {
            return false; // own contract facts must survive verbatim
        }
        if l.starts_with("#pragma aux func_0x") && c.starts_with("#pragma aux func_0x") {
            continue; // the callee-contract recovery itself
        }
        // First divergence: the candidate may only INSERT `param_N` arguments where the
        // landed line closes an argument list.
        let d = l.bytes().zip(c.bytes()).take_while(|(a, b)| a == b).count();
        let (ltail, ctail) = (&l[d..], &c[d..]);
        // signature growth out of `(void)`
        let is_sig = l.contains(&format!(" {fun}("));
        if is_sig && ltail.starts_with("void)") && ctail.starts_with("xunknown4 param_") {
            // candidate params must be exactly `xunknown4 param_1..param_K)`+same suffix
            let suffix = &ltail["void".len()..];
            let Some(body) = ctail.strip_suffix(suffix) else { return false };
            let mut k = 1u32;
            let mut rest = body;
            loop {
                let Some(r) = rest.strip_prefix(&format!("xunknown4 param_{k}")) else { return false };
                if r.is_empty() {
                    break;
                }
                let Some(r) = r.strip_prefix(", ") else { return false };
                rest = r;
                k += 1;
            }
            continue;
        }
        // appended text: candidate tail = inserted + landed tail, inserted at a `)` boundary
        if !ctail.ends_with(ltail) {
            return false;
        }
        let inserted = &ctail[..ctail.len() - ltail.len()];
        if inserted.is_empty() {
            return false;
        }
        if is_sig {
            // appended params: `, xunknown4 param_N`* closing where the landed list closed
            if !ltail.starts_with(')') {
                return false;
            }
            let mut rest = inserted;
            while !rest.is_empty() {
                let Some(r) = rest.strip_prefix(", xunknown4 param_") else { return false };
                let digits: String = r.chars().take_while(|ch| ch.is_ascii_digit()).collect();
                if digits.is_empty() {
                    return false;
                }
                rest = &r[digits.len()..];
            }
            continue;
        }
        // appended call args at the close of an argument list
        if !ltail.starts_with(')') {
            return false;
        }
        // argument position of the first appended arg = top-level commas before `d` since
        // the call's opening paren (nesting-aware), or 0 straight after `(`
        let head = &l[..d];
        let open = {
            let mut depth = 0i32;
            let mut open = None;
            for (i, ch) in head.char_indices() {
                match ch {
                    '(' => {
                        depth += 1;
                        if depth == 1 {
                            open = Some(i);
                        }
                    }
                    ')' => depth -= 1,
                    _ => {}
                }
            }
            // the innermost still-open paren nearest `d`
            let mut depth = 0i32;
            let mut last_open = open;
            for (i, ch) in head.char_indices() {
                match ch {
                    '(' => {
                        depth += 1;
                        last_open = Some(i);
                    }
                    ')' => {
                        depth -= 1;
                    }
                    _ => {}
                }
            }
            let _ = depth;
            last_open
        };
        let Some(open) = open else { return false };
        let mut pos = 0u32;
        let mut depth = 0i32;
        let arg_head = &head[open + 1..];
        let empty_list = arg_head.trim().is_empty();
        for ch in arg_head.chars() {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                ',' if depth == 0 => pos += 1,
                _ => {}
            }
        }
        if !empty_list {
            pos += 1; // the appended arg comes after the existing ones
        }
        let mut at = 0usize;
        let mut rest = inserted;
        let is_const = |t: &str| -> bool {
            let t = t.strip_prefix('-').unwrap_or(t);
            if let Some(h) = t.strip_prefix("0x") {
                !h.is_empty() && h.chars().all(|c| c.is_ascii_hexdigit())
            } else {
                !t.is_empty() && t.chars().all(|c| c.is_ascii_digit())
            }
        };
        while !rest.is_empty() {
            let elem = {
                let r = rest.strip_prefix(", ").unwrap_or(rest);
                let end = r.find([',', ')']).unwrap_or(r.len());
                &r[..end]
            };
            if !is_const(elem) && !elem.starts_with("param_") && stack_appends.is_some() {
                // STACK-APPEND class (stack-args frontier): an arbitrary expression element
                // is acceptable only when byte evidence backs it — the caller checks that
                // the original site PUSHes at least as many values as appended (the
                // const-evidence pattern, PUSH form). Reported for that check.
                let callee = l
                    .find("func_0x")
                    .and_then(|i| u64::from_str_radix(l.get(i + 7..i + 15)?, 16).ok())
                    .unwrap_or(0);
                if callee == 0 {
                    return false;
                }
                if let Some(out) = stack_appends.as_deref_mut() {
                    out.push((callee, pos));
                }
                let step = if at == 0 && empty_list { elem.to_string() } else { format!(", {elem}") };
                let Some(r) = rest.strip_prefix(&step) else { return false };
                rest = r;
                at += step.len();
                pos += 1;
                continue;
            }
            if is_const(elem) {
                // bound from the original's own dataflow — the MOV imm already exists
                if let Some(out) = consts.as_deref_mut() {
                    let t = elem.strip_prefix('-').unwrap_or(elem);
                    let v = if let Some(h) = t.strip_prefix("0x") {
                        u64::from_str_radix(h, 16).unwrap_or(0)
                    } else {
                        t.parse().unwrap_or(0)
                    };
                    let v = if elem.starts_with('-') { (v as i64).wrapping_neg() as u64 } else { v };
                    // The callee, for windowed byte-evidence: only direct `func_0x...` call
                    // lines qualify (an appended const on any other line form refuses).
                    let callee = l
                        .find("func_0x")
                        .and_then(|i| u64::from_str_radix(l.get(i + 7..i + 15)?, 16).ok())
                        .unwrap_or(0);
                    out.push((callee, pos, v));
                }
            } else {
                let Some(n) = param_at(inserted, at) else { return false };
                if n == 0 || n - 1 != pos {
                    return false; // not a self-move: value would need a register move
                }
            }
            let step = if at == 0 && empty_list { elem.to_string() } else { format!(", {elem}") };
            let Some(r) = rest.strip_prefix(&step) else { return false };
            rest = r;
            at += step.len();
            pos += 1;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const L: &str = "#pragma aux FUN_00001000 parm caller [];\n#pragma aux func_0x00002000 modify [eax];\nint4 FUN_00001000(int4 param_1)\n{\n  func_0x00002000(param_1);\n  return 0;\n}\n";
    fn cand(sig: &str, call: &str, own: &str, callee: &str) -> String {
        format!("{own}\n{callee}\nint4 FUN_00001000({sig})\n{{\n  func_0x00002000({call});\n  return 0;\n}}\n")
    }
    const OWN: &str = "#pragma aux FUN_00001000 parm caller [];";
    const CALLEE: &str = "#pragma aux func_0x00002000 modify [eax];";

    /// The zero-cost pass-through kernel: an appended `param_N` at argument position N−1 is a
    /// self-move and adopts; a displaced param, a changed own pragma, a changed existing
    /// parameter type, or any other line refuses; a callee-pragma line may change (it IS the
    /// recovery); a signature may append `xunknown4 param_N` or grow out of `(void)`; an appended
    /// constant is bound from the original's own dataflow and is reported with its position.
    #[test]
    fn pass_through_adopts_only_self_moves() {
        assert!(pass_through_only(L, L, 0x1000), "identical text");
        assert!(pass_through_only(L, &cand("int4 param_1, xunknown4 param_2", "param_1, param_2", OWN, CALLEE), 0x1000), "param_2 at position 1");
        assert!(!pass_through_only(L, &cand("int4 param_1, xunknown4 param_2", "param_1, param_1", OWN, CALLEE), 0x1000), "a duplicated param needs a register move");
        assert!(!pass_through_only(L, &cand("int4 param_1", "param_1", "#pragma aux FUN_00001000 parm [];", CALLEE), 0x1000), "the own contract must survive verbatim");
        assert!(pass_through_only(L, &cand("int4 param_1", "param_1", OWN, "#pragma aux func_0x00002000 parm caller [] modify [eax];"), 0x1000), "a callee pragma may change");
        assert!(!pass_through_only(L, &cand("char param_1", "param_1", OWN, CALLEE), 0x1000), "an existing parameter's type may not change");
        assert!(!pass_through_only(L, &cand("int4 param_1", "param_1, param_2", OWN, CALLEE).replace("  return 0;\n", ""), 0x1000), "a line-count change refuses");
        // growth out of (void), with the call appending param_1 at position 0
        let landed_void = L.replace("int4 param_1", "void").replace("func_0x00002000(param_1)", "func_0x00002000()");
        assert!(pass_through_only(&landed_void, &cand("xunknown4 param_1", "param_1", OWN, CALLEE), 0x1000));
        assert!(!pass_through_only(&landed_void, &cand("xunknown4 param_2", "param_2", OWN, CALLEE), 0x1000), "the grown list is param_1..K");
        // an appended constant: adopted, and reported with (callee, position, value)
        let mut consts = Vec::new();
        assert!(pass_through_report(L, &cand("int4 param_1", "param_1, 0x4", OWN, CALLEE), 0x1000, Some(&mut consts), None));
        assert_eq!(consts, vec![(0x2000, 1, 4)]);
        let mut consts = Vec::new();
        assert!(pass_through_report(L, &cand("int4 param_1", "param_1, -1", OWN, CALLEE), 0x1000, Some(&mut consts), None));
        assert_eq!(consts, vec![(0x2000, 1, u64::MAX)]);
        // an arbitrary expression appended: refused without the stack-append channel, reported with it
        assert!(!pass_through_only(L, &cand("int4 param_1", "param_1, iVar1", OWN, CALLEE), 0x1000));
        let mut appends = Vec::new();
        assert!(pass_through_report(L, &cand("int4 param_1", "param_1, iVar1", OWN, CALLEE), 0x1000, None, Some(&mut appends)));
        assert_eq!(appends, vec![(0x2000, 1)]);
    }

    /// The parm-clause tightening: a changed callee pragma must keep everything before `modify`.
    #[test]
    fn parm_clauses_must_survive_a_modify_change() {
        assert!(parm_clauses_stable(L, L));
        assert!(parm_clauses_stable(L, &L.replace("modify [eax]", "modify [eax edx]")));
        assert!(!parm_clauses_stable(L, &L.replace("#pragma aux func_0x00002000 modify [eax];", "#pragma aux func_0x00002000 parm caller [] modify [eax];")));
        assert!(!parm_clauses_stable(L, &format!("{L}\n")), "a line-count change is not stable");
    }

    /// The order-only census: a pure permutation of a call's top-level arguments names the
    /// callee; a changed multiset, a changed non-call line or an identical text decide nothing.
    #[test]
    fn order_only_delta_names_permuted_callees() {
        let landed = "  func_0x00002000(a, f(b, c), d);\n  x = 1;\n";
        assert_eq!(order_only_delta(landed, "  func_0x00002000(d, a, f(b, c));\n  x = 1;\n"), Some(vec![0x2000]));
        assert_eq!(order_only_delta(landed, "  func_0x00002000(a, f(b, c), e);\n  x = 1;\n"), None, "a different multiset");
        assert_eq!(order_only_delta(landed, landed), None, "nothing permuted");
        assert_eq!(order_only_delta(landed, "  func_0x00002000(d, a, f(b, c));\n  x = 2;\n"), None, "another line changed");
        assert_eq!(order_only_delta(landed, "  func_0x00002000(a, f(b, c), d);\n"), None, "line count");
    }

    /// First-touch evidence in a callee's entry block: a read before any write is an input, a
    /// write before any read is not, the zero idiom is a write, PUSH/POP are the prologue, and
    /// nothing after the first call or branch counts.
    #[test]
    fn callee_input_evidence_reads_the_entry_block() {
        let regs = WatcomRegs::for_lang("x86:LE:32:default");
        // PUSH EAX ; MOV EDX,[EAX] ; XOR EBX,EBX ; CALL +0 ; MOV ECX,EAX
        let bytes = [0x50, 0x8b, 0x10, 0x31, 0xdb, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x89, 0xc1];
        let insns = crate::recompile::insn::normalize("x86:LE:32:default", &bytes, 0x1000, &crate::recompile::insn::NoReloc).unwrap();
        assert_eq!(callee_input_evidence(&insns, &regs.arg_reg_offs), vec![Some(true), Some(false), Some(false), None], "EAX read, EDX written, EBX zeroed, ECX after the call");
        // a sub-register write counts for its container: MOV DL,1 ; MOV AL,[EDX] (EDX read after the write of DL)
        let bytes = [0xb2, 0x01, 0x8a, 0x02];
        let insns = crate::recompile::insn::normalize("x86:LE:32:default", &bytes, 0x1000, &crate::recompile::insn::NoReloc).unwrap();
        assert_eq!(callee_input_evidence(&insns, &regs.arg_reg_offs), vec![Some(false), Some(false), None, None]);
    }
}
