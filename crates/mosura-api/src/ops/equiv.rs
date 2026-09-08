//! `function.equiv` / `program.equiv`: is the recovered C a FAITHFUL implementation of the
//! original, regardless of the bytes?
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
//! TWO SHAPES, one differential. `function.equiv` does one function end to end (emit → compile →
//! verify → run). `program.equiv` does the corpus: the program is thawed ONCE, the emission is
//! served once, every candidate is compiled in ONE batch (`compile_batch`, a handful of compiler
//! boots instead of one per unit), and only then is the differential run per row. The per-row cost
//! was measured on a second subject as ~50 s under a `function.equiv` loop — a compiler boot and a
//! program thaw per call, with the seed count barely moving it — against ~1 s cached; batching is
//! the difference between an overnight sweep and a routine gate. Same `function.*`/`program.*`
//! split as `emit`.
//!
//! SCOPE (deliberate, and documented as a follow-up): this is the CONTRACT-FREE instrument. The
//! `@equiv` magic-comment layer of the branch's `equiv_check` — a callee that answers in a flag or
//! in a register the candidate's C cannot name, and the subject's own flag result — is NOT ported
//! here: it exists to model a hand-written convention that the repository's own subject does not
//! carry, and it needs that second subject to exercise. Without it the verdict is the effect trace
//! alone; the result register is reported as a SEPARATE agreement count, never folded into the
//! verdict, because a `void` function whose EAX is scratch (or one that answers in ECX, as a live
//! row on that subject did) would otherwise read as a false difference. Every `emu` channel the
//! contract layer would drive is passed empty here, which is exactly `emu`'s opt-in
//! `a_callee_without_a_flag_contract_is_unchanged` case.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::error::{Error, Result};
use crate::ops::emit::{emission_options, EMIT_LANG};
use crate::ops::function::entry_of;
use crate::ops::program::program_of;
use crate::ops::round::{emitted_function, insns_of, orig_bytes, profile_flags, read_scope_file, verify_function, window_of};
use crate::ops::schemas::EQUIV as EQUIV_SCHEMA;
use crate::ops::toolchain::toolchain_of;
use crate::ops::{Cache, Op, Progress, Tier};
use crate::options::{keys, Options};
use crate::session::Session;
use crate::table::builder::TableBuilder;
use crate::table::Table;
use mosura_core::analysis::program::Program;
use mosura_core::recompile::insn::NormInsn;
use mosura_core::recompile::toolchain::{CompileUnit, Toolchain};
use mosura_core::recompile::Outcome;
use mosura_core::sleigh::emu::{run_traced, Effect, FlagReturn, RegReturn, RunConfig};
use mosura_core::sleigh::engine::Spec;

pub static EQUIV: Op = Op {
    name: "function.equiv",
    doc: "is the recovered C a faithful implementation of the original, regardless of the bytes? Differential p-code execution over N seeds (`equiv.seeds`): the effect traces of the original and the compiled candidate are compared. verdict SAME (evidence, WEAK over one trace) / DIFFERS (sound) / UNMODELED (an op the interpreter does not model). Contract-free: the result register is reported apart, not folded in. One function; for a corpus use program.equiv, which compiles in one batch",
    since: "0.1",
    tier: Tier::Product,
    params: &["program", "entry", "toolchain", keys::EQUIV_SEEDS, keys::VERIFY_TABLE_WINDOW, keys::KNOBS_OFF, keys::DECOMPILE_GLOBAL_SCOPE, keys::DECOMPILE_PROTO_SCOPE, keys::EMIT_ARMS_OFF, crate::ops::function::EMIT_KEYS],
    result: "equiv",
    cache: Cache::Transient,
    run: equiv_op,
};

pub static PROGRAM_EQUIV: Op = Op {
    name: "program.equiv",
    doc: "function.equiv over the emission: the program thawed once, every candidate compiled in ONE batch, then the differential per row — one `equiv` row per function in scope (round.scope: user | all | list + round.scope-file). This is the form to sweep with; a loop over function.equiv pays a compiler boot and a program thaw per call",
    since: "0.1",
    tier: Tier::Product,
    params: &["program", "toolchain", keys::EQUIV_SEEDS, keys::ROUND_SCOPE, keys::ROUND_SCOPE_FILE, keys::VERIFY_TABLE_WINDOW, keys::KNOBS_OFF, keys::DECOMPILE_GLOBAL_SCOPE, keys::DECOMPILE_PROTO_SCOPE, keys::EMIT_ARMS_OFF, crate::ops::function::EMIT_KEYS],
    result: "equiv",
    cache: Cache::Transient,
    run: program_equiv_op,
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

fn reg_by_name(name: &str) -> Option<u64> {
    let n = name.trim().to_ascii_lowercase();
    GPRS.iter().find(|(r, _)| *r == n).map(|(_, o)| *o)
}

/// The COMPILER-VISIBLE contracts the candidate TU declares: what its own `#pragma aux` lines say
/// about each callee and about the function itself. Nothing here is a magic comment — these are the
/// pragmas the emitter writes and Watcom reads, so honouring them compares the two runs on the
/// same question the compiler was asked.
///
/// Without them every call was compared on the convention's default four registers, and a
/// NON-argument register holding different scratch across two correct implementations read as a
/// `call-arguments` difference. Measured on a second subject: the branch's instrument, which
/// parsed these, scored 175/769 SAME at 32 seeds; this op without them 166/769 at 8 — stricter by
/// at least nine units in a direction fewer seeds should have made more lenient.
#[derive(Default)]
struct Contracts {
    /// callee VA -> the registers its `parm [..]` clause names, in argument order.
    call_args: HashMap<u64, Vec<(u64, u32)>>,
    /// callees whose arguments go on the STACK (`parm caller []`, `parm []`): compared by target
    /// only, since their arguments live in a frame two implementations lay out differently.
    stack_targets: HashSet<u64>,
    /// callee VA -> its declared `modify [..]` set (plus `value [..]`, modified by definition).
    modifies: HashMap<u64, Vec<(u64, u32)>>,
    /// The function's OWN result register from its `value [reg]` clause; EAX when unstated.
    result: (u64, u32),
}

/// The registers a `#pragma aux` clause names, e.g. `modify [eax ecx]` -> `[EAX, ECX]`. The clause
/// ENDS at the next keyword — `parm [eax] modify [ecx]` must not read `ecx` as an argument — and
/// `exact`/`nomemory`/`caller` are modifiers, not registers.
fn pragma_regs(tail: &str, keyword: &str) -> Option<Vec<(u64, u32)>> {
    let at = tail.find(keyword)?;
    let clause = &tail[at + keyword.len()..];
    let end = ["parm ", "value ", "modify ", "aborts", "export", "far", "near"]
        .iter()
        .filter_map(|k| clause.find(k))
        .min()
        .unwrap_or(clause.len());
    let mut regs = Vec::new();
    for group in clause[..end].split('[').skip(1) {
        let Some(inner) = group.split(']').next() else { break };
        if inner.contains("caller") {
            continue;
        }
        for r in inner.split_whitespace() {
            if let Some(off) = reg_by_name(r) {
                regs.push((off, 4u32));
            }
        }
    }
    Some(regs)
}

/// The VA a callee pragma names: `func_0x0001cc88`, `FUN_0001cc88`.
fn pragma_va(name: &str) -> Option<u64> {
    let hex = name.strip_prefix("func_0x").or_else(|| name.strip_prefix("FUN_"))?;
    u64::from_str_radix(hex.trim_end_matches('_'), 16).ok()
}

/// Read the candidate TU's `#pragma aux` lines. `own` is the function's own name, whose `value`
/// clause is the result register; every other pragma describes a callee.
fn contracts_of(tu: &str, own: &str) -> Contracts {
    let mut c = Contracts { result: (EAX, 4), ..Contracts::default() };
    for line in tu.lines() {
        let l = line.trim();
        let Some(rest) = l.strip_prefix("#pragma aux ") else { continue };
        let Some((name, tail)) = rest.split_once(' ') else { continue };
        let name = name.trim_end_matches(';');
        if name == own {
            if let Some(v) = pragma_regs(tail, "value ").and_then(|v| v.first().copied()) {
                c.result = v;
            }
            continue;
        }
        let Some(va) = pragma_va(name) else { continue };
        if tail.contains("parm ") {
            let regs = pragma_regs(tail, "parm ").unwrap_or_default();
            if regs.is_empty() {
                c.stack_targets.insert(va);
            } else {
                c.call_args.insert(va, regs);
            }
        }
        if let Some(mut m) = pragma_regs(tail, "modify ") {
            for v in pragma_regs(tail, "value ").unwrap_or_default() {
                if !m.contains(&v) {
                    m.push(v);
                }
            }
            c.modifies.insert(va, m);
        }
    }
    c
}

/// One row of the `equiv` table.
struct EquivRow {
    idx: String,
    va: u64,
    name: String,
    verdict: String,
    seeds: u64,
    finished: u64,
    traces: u64,
    agreed: u64,
    faults: u64,
    detail: String,
}

impl EquivRow {
    /// A row for a function that never reached the differential (no candidate to run).
    fn failure(idx: &str, va: u64, name: &str, outcome: Outcome, seeds: u64, detail: &str) -> EquivRow {
        EquivRow { idx: idx.into(), va, name: name.into(), verdict: outcome.as_str().into(), seeds, finished: 0, traces: 0, agreed: 0, faults: 0, detail: detail.into() }
    }
}

fn table_of(rows: &[EquivRow]) -> Table {
    let mut b = TableBuilder::new(&EQUIV_SCHEMA);
    for r in rows {
        b.row().str(&r.idx).u64(r.va).str(&r.name).str(&r.verdict).u64(r.seeds).u64(r.finished).u64(r.traces).u64(r.agreed).u64(r.faults).str(&r.detail);
    }
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

fn seeds_of(o: &Options) -> Result<u64> {
    let v = o.get(keys::EQUIV_SEEDS)?;
    if v.is_empty() {
        Ok(128)
    } else {
        v.parse().map_err(|_| Error::InvalidArg("equiv.seeds is not a number".into()))
    }
}

/// The language tables both runs decode with.
fn language() -> Result<(&'static Spec, &'static [u32])> {
    mosura_core::lang::load_cached(EMIT_LANG).ok_or_else(|| Error::NotFound("x86:LE:32:default language tables".into()))
}

/// THE DIFFERENTIAL: the original's bytes against the candidate's, at the same address, over
/// `seeds` machine states. Everything that is per-function and does not touch the session lives
/// here, so `function.equiv` and `program.equiv` cannot drift apart.
#[allow(clippy::too_many_arguments)]
fn differential(spec: &Spec, ctx: &[u32], idx: &str, entry: u64, name: &str, bytes: &[u8], cand_bytes: &[u8], insns: &[NormInsn], seeds: u64, con: &Contracts) -> EquivRow {
    let orig_n = insns.len() as u64;
    // The pool the memory fill draws from: every constant the ORIGINAL mentions, its neighbours,
    // and the boundaries — so a wrong threshold is actually exercised (a uniform-random word
    // almost never lands on `x >= 9`'s boundary).
    let mut pool: Vec<u64> = vec![0, 1, 2, 0xffff_ffff, 0xffff_fffe, 0x7fff_ffff, 0x8000_0000, 0x100, 0xffff, 0xff];
    for i in insns {
        for c in &i.consts {
            let c = *c & 0xffff_ffff;
            for d in [c, c.wrapping_sub(1) & 0xffff_ffff, c.wrapping_add(1) & 0xffff_ffff] {
                if !pool.contains(&d) {
                    pool.push(d);
                }
            }
        }
    }

    // The COMPILER-VISIBLE contracts (the TU's own pragmas) drive the call channels; the @equiv
    // flag/register-return channels stay empty (see the module doc) — emu's opt-in
    // `a_callee_without_a_flag_contract_is_unchanged` case on both sides.
    let no_flags: HashMap<u64, FlagReturn> = HashMap::new();
    let no_regs: HashMap<u64, RegReturn> = HashMap::new();
    let default_args = [(EAX, 4u32), (EDX, 4), (EBX, 4), (ECX, 4)];
    let clobbers = [(EAX, 4u32), (ECX, 4), (EDX, 4), (EBX, 4)];
    // The x86 arithmetic flags (`ia.sinc:39`, one byte each from 0x200): CF PF AF ZF SF OF. DF
    // (0x20a) is ABI-preserved and deliberately absent.
    let flag_clobbers = [(0x200u64, 1u32), (0x202, 1), (0x204, 1), (0x206, 1), (0x207, 1), (0x20b, 1)];
    // The original's bytes, as the DATA image both runs read (a function's own extent is data too).
    let image: [(u64, &[u8]); 1] = [(entry, bytes)];

    let (mut agree, mut both_finished, mut faults, mut result_agree) = (0u64, 0u64, 0u64, 0u64);
    let mut traces: HashSet<String> = HashSet::new();
    let (mut unmodeled, mut unmodeled_ops): (u64, BTreeSet<String>) = (0, BTreeSet::new());
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
            call_args: &con.call_args,
            default_args: &default_args,
            call_clobbers: &clobbers,
            call_modifies: &con.modifies,
            call_flag_clobbers: &flag_clobbers,
            call_flag_returns: &no_flags,
            site_flag_returns: &no_flags,
            ordinal_flag_returns: &no_flags,
            call_reg_returns: &no_regs,
            site_reg_returns: &no_regs,
            ordinal_reg_returns: &no_regs,
            is_candidate_run: false,
            image: &image,
            stack_targets: &con.stack_targets,
            sp: (ESP, 4),
            max_steps: 20_000_000,
            pool: &pool,
            max_effects: 4_000,
        };
        let (mo, fo) = run_traced(spec, bytes, entry, ctx, &vals, &cfg);
        let cand_cfg = RunConfig { is_candidate_run: true, ..cfg };
        let (mc, fc) = run_traced(spec, cand_bytes, entry, ctx, &vals, &cand_cfg);

        unmodeled += mo.unmodeled as u64 + mc.unmodeled as u64;
        unmodeled_ops.extend(mo.unmodeled_ops.iter().cloned());
        unmodeled_ops.extend(mc.unmodeled_ops.iter().cloned());
        if fo && fc {
            both_finished += 1;
        }
        let faulted = matches!(mo.effects.last(), Some(Effect::Fault));
        if faulted {
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
        let (ro, rc) = (mo.read("register", con.result.0, con.result.1), mc.read("register", con.result.0, con.result.1));
        traces.insert(format!("{:?}|{ro:x}", mo.effects));
        if eo == ec {
            agree += 1;
            if ro == rc || (!fo && !fc) || faulted {
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
        let rname = GPRS.iter().find(|(_, o)| *o == con.result.0).map(|(n, _)| *n).unwrap_or("?");
        ("SAME".to_string(), format!("evidence over {} trace(s){weak}; result {rname} agreed {result_agree}/{seeds}; orig_n={orig_n}; contracts: {} callee(s), {} stack", traces.len(), con.call_args.len(), con.stack_targets.len()))
    } else {
        ("DIFFERS".to_string(), first_diff.unwrap_or_else(|| "unknown".into()))
    };
    EquivRow { idx: idx.into(), va: entry, name: name.into(), verdict, seeds, finished: both_finished, traces: traces.len() as u64, agreed: agree, faults, detail }
}

// ── function.equiv: one function end to end ──

fn equiv_op(s: &mut Session, o: &Options, prog: &mut dyn Progress) -> Result<Table> {
    let (_, p) = program_of(s, o)?;
    let entry = entry_of(&p, o)?;
    let seeds = seeds_of(o)?;
    if !prog.report("emit", 0, 3) {
        return Err(Error::Cancelled);
    }
    let f = emitted_function(s, o, entry)?;
    let bytes = orig_bytes(&p, entry, f.orig_len);
    let insns = insns_of(&bytes, entry)?;
    let Some(tu) = f.tu else {
        let v = if f.status == "DECOMPILE_FAIL" { Outcome::DecompileFail } else { Outcome::EmitFail };
        return Ok(table_of(&[EquivRow::failure(&f.idx, entry, &f.name, v, seeds, "no candidate to run")]));
    };
    let (_, flags) = profile_flags(&insns)?;
    let con = contracts_of(&tu, &f.name);
    if !prog.report("compile", 1, 3) {
        return Err(Error::Cancelled);
    }
    let object = {
        let (_, tc) = toolchain_of(s, o)?;
        tc.driver.compile(&CompileUnit { key: f.idx.clone(), source: tu, flags }).object
    };
    let Some(object) = object else {
        return Ok(table_of(&[EquivRow::failure(&f.idx, entry, &f.name, Outcome::CompileFail, seeds, "candidate did not compile")]));
    };
    let checked = match verify_function(&p, entry, &f.name, f.orig_len, &object, window_of(o)?) {
        Ok(c) => c,
        Err(e) => return Ok(table_of(&[EquivRow::failure(&f.idx, entry, &f.name, Outcome::ObjError, seeds, &e)])),
    };
    let cand_bytes = checked.relinked.relinked_bytes();
    if !prog.report("run", 2, 3) {
        return Err(Error::Cancelled);
    }
    let (spec, ctx) = language()?;
    Ok(table_of(&[differential(spec, ctx, &f.idx, entry, &f.name, &bytes, &cand_bytes, &insns, seeds, &con)]))
}

// ── program.equiv: the corpus, compiled in one batch ──

fn program_equiv_op(s: &mut Session, o: &Options, prog: &mut dyn Progress) -> Result<Table> {
    let seeds = seeds_of(o)?;
    let eo = emission_options(o)?;
    let (_, p) = program_of(s, &eo)?;
    // 1. the emission (served when its key exists) — the program is thawed once, here
    if !prog.report("emit", 0, 3) {
        return Err(Error::Cancelled);
    }
    let emission = crate::ops::dispatch_inner(s, "program.emit", &eo)?;
    // 2. the scope, exactly as round.run scopes a round
    let scope = o.get(keys::ROUND_SCOPE)?.to_string();
    let listed: Option<BTreeSet<u64>> = if scope == "list" {
        let f = o.get(keys::ROUND_SCOPE_FILE)?;
        if f.is_empty() {
            return Err(Error::InvalidArg("round.scope=list needs round.scope-file".into()));
        }
        Some(read_scope_file(f)?)
    } else {
        None
    };
    struct Sel {
        idx: String,
        va: u64,
        name: String,
        orig_len: u64,
        tu: Option<String>,
        status: String,
    }
    let mut selected: Vec<Sel> = Vec::new();
    for r in 0..emission.rows() {
        let va = emission.u64(r, 1)?;
        let kind = emission.str(r, 4)?.to_string();
        let in_scope = match &listed {
            Some(l) => l.contains(&va),
            None => scope == "all" || (kind != "library" && kind != "asm"),
        };
        if !in_scope {
            continue;
        }
        let status = emission.str(r, 3)?.to_string();
        selected.push(Sel { idx: format!("{:05}", emission.u64(r, 0)?), va, name: emission.str(r, 2)?.to_string(), orig_len: emission.u64(r, 5)?, tu: if status == "OK" { Some(emission.str(r, 6)?.to_string()) } else { None }, status });
    }
    if selected.is_empty() {
        return Err(Error::NotFound("no function in scope".into()));
    }
    // 3. ONE compile batch — this is the whole point of the program form
    if !prog.report("compile", 1, 3) {
        return Err(Error::Cancelled);
    }
    let mut units: Vec<CompileUnit> = Vec::new();
    let mut unit_rows: Vec<usize> = Vec::new();
    let mut bytes_of: Vec<Option<(Vec<u8>, Vec<NormInsn>)>> = Vec::with_capacity(selected.len());
    for (i, sel) in selected.iter().enumerate() {
        let bytes = orig_bytes(&p, sel.va, sel.orig_len);
        let insns = insns_of(&bytes, sel.va)?;
        if let Some(tu) = &sel.tu {
            let (_, flags) = profile_flags(&insns)?;
            units.push(CompileUnit { key: sel.idx.clone(), source: tu.clone(), flags });
            unit_rows.push(i);
        }
        bytes_of.push(Some((bytes, insns)));
    }
    let outs = {
        let (_, tc) = toolchain_of(s, o)?;
        tc.driver.compile_batch(&units)
    };
    let mut out_by_row: BTreeMap<usize, usize> = BTreeMap::new();
    for (k, i) in unit_rows.iter().enumerate() {
        out_by_row.insert(*i, k);
    }
    // 4. the differential, per row
    if !prog.report("run", 2, 3) {
        return Err(Error::Cancelled);
    }
    let (spec, ctx) = language()?;
    let window = window_of(o)?;
    let mut rows: Vec<EquivRow> = Vec::with_capacity(selected.len());
    for (i, sel) in selected.iter().enumerate() {
        let (bytes, insns) = bytes_of[i].as_ref().expect("filled above");
        let row = match (&sel.tu, out_by_row.get(&i).map(|k| &outs[*k])) {
            (None, _) => {
                let v = if sel.status == "DECOMPILE_FAIL" { Outcome::DecompileFail } else { Outcome::EmitFail };
                EquivRow::failure(&sel.idx, sel.va, &sel.name, v, seeds, "no candidate to run")
            }
            (Some(_), Some(out)) if !out.ok() => EquivRow::failure(&sel.idx, sel.va, &sel.name, Outcome::CompileFail, seeds, "candidate did not compile"),
            (Some(_), Some(out)) => match verify_function(&p, sel.va, &sel.name, sel.orig_len, out.object.as_ref().expect("ok"), window) {
                Ok(c) => {
                    let cand_bytes = c.relinked.relinked_bytes();
                    let con = contracts_of(sel.tu.as_deref().unwrap_or(""), &sel.name);
                    differential(spec, ctx, &sel.idx, sel.va, &sel.name, bytes, &cand_bytes, insns, seeds, &con)
                }
                Err(e) => EquivRow::failure(&sel.idx, sel.va, &sel.name, Outcome::ObjError, seeds, &e),
            },
            (Some(_), None) => EquivRow::failure(&sel.idx, sel.va, &sel.name, Outcome::EmitFail, seeds, "no candidate to run"),
        };
        rows.push(row);
    }
    Ok(table_of(&rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    const EDI_OFF: u64 = 28;

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

    /// The two ops must share ONE differential: identical bytes on both sides agree on every seed
    /// with a full result-register agreement, whatever the seed count. Runs the helper directly —
    /// no toolchain, no session — over a real instruction stream.
    #[test]
    fn identical_bytes_are_same_on_every_seed() {
        let (spec, ctx) = language().expect("x86:LE:32 tables");
        // MOV EAX,[EBX+0x24] ; RET — reads through a seeded pointer, so the traces vary by seed.
        let bytes = [0x8bu8, 0x43, 0x24, 0xc3];
        let insns = mosura_core::recompile::insn::normalize(EMIT_LANG, &bytes, 0x4000, &mosura_core::recompile::insn::NoReloc).unwrap();
        let r = differential(spec, ctx, "00001", 0x4000, "f", &bytes, &bytes, &insns, 16, &Contracts { result: (EAX, 4), ..Contracts::default() });
        assert_eq!(r.verdict, "SAME", "{}", r.detail);
        assert_eq!((r.agreed, r.finished, r.faults), (16, 16, 0));
        assert!(r.detail.contains("result eax agreed 16/16"), "{}", r.detail);
    }

    /// The TU's own pragmas are the compiler-visible contract: a callee's `parm` registers, a
    /// stack-convention callee, its `modify` set (plus `value`, modified by definition), and the
    /// function's own result register. The clause ends at the next keyword, so `parm [eax] value
    /// [ebx] modify [ecx]` has ONE argument register.
    #[test]
    fn the_candidate_tus_pragmas_are_read_as_contracts() {
        let tu = "#pragma aux FUN_00001000 value [ebx] modify [eax edx];\n\
                  #pragma aux func_0x00002000 parm [edi] [eax] value [ebx] modify [ecx];\n\
                  #pragma aux func_0x00003000 parm caller [] modify exact [eax];\n\
                  #pragma aux func_0x00004000 modify [eax];\n\
                  int FUN_00001000(void) { return 0; }\n";
        let c = contracts_of(tu, "FUN_00001000");
        assert_eq!(c.result, (EBX, 4), "own value [ebx]");
        assert_eq!(c.call_args.get(&0x2000).cloned(), Some(vec![(EDI_OFF, 4), (EAX, 4)]), "parm stops at `value`");
        assert!(c.stack_targets.contains(&0x3000), "parm caller [] is a stack callee");
        assert!(!c.call_args.contains_key(&0x3000) && !c.call_args.contains_key(&0x4000));
        let m2 = c.modifies.get(&0x2000).cloned().unwrap();
        assert!(m2.contains(&(ECX, 4)) && m2.contains(&(EBX, 4)), "modify + value: {m2:?}");
        assert_eq!(c.modifies.get(&0x3000).cloned(), Some(vec![(EAX, 4)]), "`exact` is a modifier, not a register");
    }
}
