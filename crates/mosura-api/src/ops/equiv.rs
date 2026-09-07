//! `function.equiv`: is the recovered C a FAITHFUL implementation of the original, regardless of
//! the bytes?
//!
//! `function.recompile` asks whether the candidate compiles to the original's bytes — the right
//! question for a subject a compiler produced. This asks the other one, for a subject written in
//! assembler where register allocation, calling convention, frame layout and instruction selection
//! are all free and a candidate can be provably the same program while sharing barely a byte.
//!
//! Method: differential execution under the p-code interpreter ([`mosura_core::sleigh::emu`], the
//! call model re-landed from `faithful-c-equivalence`). The original and the compiled candidate run
//! over the same seeded machine state and their EFFECT TRACES are compared — the stores outside the
//! frame, the calls with their contract-named arguments, the ports and interrupts, in order. Memory
//! nobody wrote reads as a function of its address, so both runs traverse the same heap; a call is
//! an event, not entered.
//!
//! This is TESTING, not proof: sound for finding a DIFFERENCE, only ever EVIDENCE of sameness. The
//! row reports the seed count, how many ran to completion on both sides, and how many DISTINCT
//! effect traces the seeds produced — a `SAME` over one trace is marked `WEAK`.
//!
//! SCOPE (deliberate, and documented as a follow-up): this is the CONTRACT-FREE instrument. The
//! `@equiv` magic-comment layer of the branch's `equiv_check` — a callee that answers in a flag or
//! in a register the candidate's C cannot name, and the subject's own flag result — is NOT ported
//! here: it exists to model a hand-written convention that the repository's own subject does not
//! carry, and it needs that second subject to exercise. Without it the verdict is the effect trace
//! alone; the result register is reported as a SEPARATE agreement count, never folded into the
//! verdict, because a `void` function whose EAX is scratch would otherwise read as a false
//! difference. Every `emu` channel the contract layer would drive is passed empty here, which is
//! exactly `emu`'s opt-in `a_callee_without_a_flag_contract_is_unchanged` case.

use std::collections::{HashMap, HashSet};

use crate::error::Result;
use crate::ops::emit::EMIT_LANG;
use crate::ops::function::entry_of;
use crate::ops::program::program_of;
use crate::ops::round::{emitted_function, insns_of, orig_bytes, profile_flags, verify_function, window_of};
use crate::ops::schemas::EQUIV as EQUIV_SCHEMA;
use crate::ops::toolchain::toolchain_of;
use crate::ops::{Cache, Op, Progress, Tier};
use crate::options::{keys, Options};
use crate::session::Session;
use crate::table::builder::TableBuilder;
use crate::table::Table;
use mosura_core::recompile::toolchain::{CompileUnit, Toolchain};
use mosura_core::recompile::Outcome;
use mosura_core::sleigh::emu::{run_traced, Effect, FlagReturn, RegReturn, RunConfig};

pub static EQUIV: Op = Op {
    name: "function.equiv",
    doc: "is the recovered C a faithful implementation of the original, regardless of the bytes? Differential p-code execution over N seeds (`equiv.seeds`): the effect traces of the original and the compiled candidate are compared. verdict SAME (evidence, WEAK over one trace) / DIFFERS (sound) / UNMODELED (an op the interpreter does not model). Contract-free: the result register is reported apart, not folded in",
    since: "0.1",
    tier: Tier::Product,
    params: &["program", "entry", "toolchain", keys::EQUIV_SEEDS, keys::VERIFY_TABLE_WINDOW, keys::KNOBS_OFF, keys::DECOMPILE_GLOBAL_SCOPE, keys::DECOMPILE_PROTO_SCOPE, keys::EMIT_ARMS_OFF, crate::ops::function::EMIT_KEYS],
    result: "equiv",
    cache: Cache::Transient,
    run: equiv_op,
};

// x86 register-space offsets (Ghidra's `register` space); EAX is the contract-free result register.
const EAX: u64 = 0;
const ECX: u64 = 4;
const EDX: u64 = 8;
const EBX: u64 = 12;
const ESP: u64 = 16;
const GPRS: [(&str, u64); 8] =
    [("eax", 0), ("ecx", 4), ("edx", 8), ("ebx", 12), ("esp", 16), ("ebp", 20), ("esi", 24), ("edi", 28)];
const STACK_TOP: u64 = 0x0f00_0000;
const STACK_WINDOW: (u64, u64) = (STACK_TOP - 0x8000, STACK_TOP + 0x400);

fn one_row(idx: &str, va: u64, name: &str, verdict: &str, seeds: u64, finished: u64, traces: u64, agreed: u64, faults: u64, detail: &str) -> Table {
    let mut b = TableBuilder::new(&EQUIV_SCHEMA);
    b.row().str(idx).u64(va).str(name).str(verdict).u64(seeds).u64(finished).u64(traces).u64(agreed).u64(faults).str(detail);
    b.finish(false)
}

/// The first differing effect, named by kind — the one thing to know when a function differs.
fn classify(o: &[Effect], c: &[Effect]) -> String {
    for i in 0..o.len().max(c.len()) {
        match (o.get(i), c.get(i)) {
            (Some(a), Some(b)) if a == b => continue,
            (Some(Effect::Store(_, aa, _, _)), Some(Effect::Store(_, ba, _, _))) => {
                return if aa != ba { "store-address".into() } else { "store-value/width".into() }
            }
            (Some(Effect::Call(at, _)), Some(Effect::Call(bt, _))) => {
                return if at != bt { "call-target".into() } else { "call-arguments".into() }
            }
            (Some(Effect::Fault), _) | (_, Some(Effect::Fault)) => return "fault-mismatch".into(),
            (Some(_), None) => return "candidate-stops-early".into(),
            (None, Some(_)) => return "candidate-does-more".into(),
            (Some(_), Some(_)) => return "effect-order".into(),
            (None, None) => break,
        }
    }
    "result-register".into()
}

fn equiv_op(s: &mut Session, o: &Options, prog: &mut dyn Progress) -> Result<Table> {
    let (_, p) = program_of(s, o)?;
    let entry = entry_of(&p, o)?;
    let seeds: u64 = {
        let v = o.get(keys::EQUIV_SEEDS)?;
        if v.is_empty() { 128 } else { v.parse().map_err(|_| crate::error::Error::InvalidArg("equiv.seeds is not a number".into()))? }
    };
    if !prog.report("emit", 0, 3) {
        return Err(crate::error::Error::Cancelled);
    }
    let f = emitted_function(s, o, entry)?;
    let bytes = orig_bytes(&p, entry, f.orig_len);
    let insns = insns_of(&bytes, entry)?;
    let orig_n = insns.len() as u64;
    let Some(tu) = f.tu else {
        let v = if f.status == "DECOMPILE_FAIL" { Outcome::DecompileFail } else { Outcome::EmitFail };
        return Ok(one_row(&f.idx, entry, &f.name, v.as_str(), seeds, 0, 0, 0, 0, "no candidate to run"));
    };
    let (_, flags) = profile_flags(&insns)?;
    if !prog.report("compile", 1, 3) {
        return Err(crate::error::Error::Cancelled);
    }
    let object = {
        let (_, tc) = toolchain_of(s, o)?;
        tc.driver.compile(&CompileUnit { key: f.idx.clone(), source: tu, flags }).object
    };
    let Some(object) = object else {
        return Ok(one_row(&f.idx, entry, &f.name, Outcome::CompileFail.as_str(), seeds, 0, 0, 0, 0, "candidate did not compile"));
    };
    let checked = match verify_function(&p, entry, &f.name, f.orig_len, &object, window_of(o)?) {
        Ok(c) => c,
        Err(e) => return Ok(one_row(&f.idx, entry, &f.name, Outcome::ObjError.as_str(), seeds, 0, 0, 0, 0, &e)),
    };
    let cand_bytes = checked.relinked.relinked_bytes();
    if !prog.report("run", 2, 3) {
        return Err(crate::error::Error::Cancelled);
    }

    let (spec, ctx) = mosura_core::lang::load_cached(EMIT_LANG).ok_or_else(|| crate::error::Error::NotFound("x86:LE:32:default language tables".into()))?;

    // The pool the memory fill draws from: every constant the ORIGINAL mentions, its neighbours,
    // and the boundaries — so a wrong threshold is actually exercised (a uniform-random word
    // almost never lands on `x >= 9`'s boundary).
    let mut pool: Vec<u64> = vec![0, 1, 2, 0xffff_ffff, 0xffff_fffe, 0x7fff_ffff, 0x8000_0000, 0x100, 0xffff, 0xff];
    for i in &insns {
        for c in &i.consts {
            let c = *c & 0xffff_ffff;
            for d in [c, c.wrapping_sub(1) & 0xffff_ffff, c.wrapping_add(1) & 0xffff_ffff] {
                if !pool.contains(&d) {
                    pool.push(d);
                }
            }
        }
    }

    // Every channel the contract layer would drive is empty (see the module doc): this is emu's
    // opt-in `a_callee_without_a_flag_contract_is_unchanged` case on both sides.
    let call_args: HashMap<u64, Vec<(u64, u32)>> = HashMap::new();
    let call_modifies: HashMap<u64, Vec<(u64, u32)>> = HashMap::new();
    let stack_targets: HashSet<u64> = HashSet::new();
    let no_flags: HashMap<u64, FlagReturn> = HashMap::new();
    let no_regs: HashMap<u64, RegReturn> = HashMap::new();
    let default_args = [(EAX, 4u32), (EDX, 4), (EBX, 4), (ECX, 4)];
    let clobbers = [(EAX, 4u32), (ECX, 4), (EDX, 4), (EBX, 4)];
    // The x86 arithmetic flags (`ia.sinc:39`, one byte each from 0x200): CF PF AF ZF SF OF. DF
    // (0x20a) is ABI-preserved and deliberately absent.
    let flag_clobbers = [(0x200u64, 1u32), (0x202, 1), (0x204, 1), (0x206, 1), (0x207, 1), (0x20b, 1)];

    // The original's bytes, as the DATA image both runs read (a function's own extent is data too);
    // one binding so the RunConfig borrow outlives the loop.
    let image: [(u64, &[u8]); 1] = [(entry, bytes.as_slice())];
    let (mut agree, mut both_finished, mut faults, mut result_agree) = (0u64, 0u64, 0u64, 0u64);
    let mut traces: HashSet<String> = HashSet::new();
    let (mut unmodeled, mut unmodeled_ops): (u64, std::collections::BTreeSet<String>) = (0, Default::default());
    let mut first_diff: Option<String> = None;

    for si in 0..seeds {
        let seed = 0x5eed_0000_0000_0000 ^ si.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let vals: Vec<(&str, u64, u64, u32)> = GPRS
            .iter()
            .map(|&(_, off)| {
                let v = if off == ESP {
                    STACK_TOP
                } else {
                    let h = seed.rotate_left(off as u32 + 7) ^ off.wrapping_mul(0x1234_5678);
                    if h % 3 != 0 { pool[(h >> 8) as usize % pool.len()] } else { h & 0xffff_ffff }
                };
                ("register", off, v, 4u32)
            })
            .collect();
        let cfg = RunConfig {
            seed,
            scratch: STACK_WINDOW,
            call_args: &call_args,
            default_args: &default_args,
            call_clobbers: &clobbers,
            call_modifies: &call_modifies,
            call_flag_clobbers: &flag_clobbers,
            call_flag_returns: &no_flags,
            site_flag_returns: &no_flags,
            ordinal_flag_returns: &no_flags,
            call_reg_returns: &no_regs,
            site_reg_returns: &no_regs,
            ordinal_reg_returns: &no_regs,
            is_candidate_run: false,
            image: &image,
            stack_targets: &stack_targets,
            sp: (ESP, 4),
            max_steps: 20_000_000,
            pool: &pool,
            max_effects: 4_000,
        };
        let (mo, fo) = run_traced(spec, &bytes, entry, ctx, &vals, &cfg);
        let cand_cfg = RunConfig { is_candidate_run: true, ..cfg };
        let (mc, fc) = run_traced(spec, &cand_bytes, entry, ctx, &vals, &cand_cfg);

        unmodeled += mo.unmodeled as u64 + mc.unmodeled as u64;
        unmodeled_ops.extend(mo.unmodeled_ops.iter().cloned());
        unmodeled_ops.extend(mc.unmodeled_ops.iter().cloned());
        if fo && fc {
            both_finished += 1;
        }
        if matches!(mo.effects.last(), Some(Effect::Fault)) {
            faults += 1;
        }
        // When NEITHER run reached RETURN, only the common prefix is evidence: comparing the tails
        // would penalise whichever side got further, which is not a behavioural difference.
        let (eo, ec): (&[Effect], &[Effect]) = if !fo && !fc {
            let n = mo.effects.len().min(mc.effects.len());
            (&mo.effects[..n], &mc.effects[..n])
        } else {
            (&mo.effects, &mc.effects)
        };
        let (ro, rc) = (mo.read("register", EAX, 4), mc.read("register", EAX, 4));
        traces.insert(format!("{:?}|{ro:x}", mo.effects));
        if eo == ec {
            agree += 1;
            if ro == rc || (!fo && !fc) || matches!(mo.effects.last(), Some(Effect::Fault)) {
                result_agree += 1;
            }
        } else if first_diff.is_none() {
            first_diff = Some(format!("{} (seed {seed:#x})", classify(eo, ec)));
        }
    }

    let (verdict, detail) = if unmodeled > 0 {
        ("UNMODELED".to_string(), format!("interpreter met {unmodeled} unmodelled op(s): {}", unmodeled_ops.iter().cloned().collect::<Vec<_>>().join(",")))
    } else if agree == seeds {
        let weak = if traces.len() < 2 { " WEAK(one path)" } else { "" };
        ("SAME".to_string(), format!("evidence over {} trace(s){weak}; result eax agreed {result_agree}/{seeds}; orig_n={orig_n}", traces.len()))
    } else {
        ("DIFFERS".to_string(), first_diff.unwrap_or_else(|| "unknown".into()))
    };
    Ok(one_row(&f.idx, entry, &f.name, &verdict, seeds, both_finished, traces.len() as u64, agree, faults, &detail))
}


#[cfg(test)]
mod tests {
    use super::*;

    fn store(a: u64) -> Effect {
        Effect::Store("ram".into(), a, 4, 0)
    }

    /// `classify` names the FIRST divergence by kind — the one thing to know when a function
    /// differs. The differential-run semantics it reports on are pinned in
    /// `mosura-core`'s `tests/emu_call_model.rs`; this pins the reporting.
    #[test]
    fn classify_names_the_first_divergence() {
        // identical prefix, then a store to a different address
        assert_eq!(classify(&[store(0x10), store(0x20)], &[store(0x10), store(0x30)]), "store-address");
        // same address, different value/width
        assert_eq!(classify(&[store(0x10)], &[Effect::Store("ram".into(), 0x10, 2, 9)]), "store-value/width");
        // a call to a different target
        assert_eq!(classify(&[Effect::Call(0x100, vec![])], &[Effect::Call(0x200, vec![])]), "call-target");
        // the candidate stops early / does more
        assert_eq!(classify(&[store(0x10), store(0x20)], &[store(0x10)]), "candidate-stops-early");
        assert_eq!(classify(&[store(0x10)], &[store(0x10), store(0x20)]), "candidate-does-more");
        // a fault on one side only
        assert_eq!(classify(&[Effect::Fault], &[store(0x10)]), "fault-mismatch");
        // identical traces: the difference is the result register
        assert_eq!(classify(&[store(0x10)], &[store(0x10)]), "result-register");
    }
}
