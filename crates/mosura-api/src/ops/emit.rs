//! The recompile-emit operations over P0's promoted survey logic: `program.passes` (the
//! whole-program pre-passes — tail-return marks, the prototype pass, param-order evidence, global
//! widths — as a pure set of the decompile stage) and `function.emit` (one function's RECOVERED
//! translation unit through `recompile::round::EmitState`, a pure set of the emit stage). The
//! bodies orchestrate; every decision is the core's. The recovered emitter targets Watcom x86-32:
//! another language is `Unsupported`.

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::fingerprint::Stage;
use crate::key::{key, no_annotations, Key};
use crate::options::{keys, registry as optreg, Options};
use crate::ops::function::{entry_of, EMIT_KEYS};
use crate::ops::program::{program_key, program_of};
use crate::ops::schemas::{EMISSION, EMIT_REPORT, GLOBAL_WIDTHS};
use crate::ops::{Cache, Op, Progress, Tier};
use crate::program::{freeze, thaw};
use crate::render::text_table;
use crate::session::{Provenance, Session, SetKind};
use crate::set::TableSet;
use crate::table::builder::TableBuilder;
use crate::table::Table;
use mosura_core::analysis::interface::{install_prototypes, mark_tail_return_writes};
use mosura_core::decompile::emit::EmitChoices;
use mosura_core::recompile::passes::{Entries, GlobalWidths, ParamOrders, Worlds};
use mosura_core::recompile::pragma::WatcomRegs;
use mosura_core::recompile::round::{EmitOpts, EmitState, ProgramFacts};
use mosura_core::switches::Switch;

/// The one language the recovered emitter models (the survey's `SURVEY_LANG`).
pub const EMIT_LANG: &str = "x86:LE:32:default";

pub static PASSES: Op = Op {
    name: "program.passes",
    doc: "the whole-program pre-passes of the recovered emit (tail-return marks, prototype pass, param-order evidence, global widths) as a program set; the survey emits under decompile.global-scope=standalone",
    since: "0.1",
    tier: Tier::Product,
    params: &["program", keys::KNOBS_OFF, keys::DECOMPILE_GLOBAL_SCOPE, keys::DECOMPILE_PROTO_SCOPE],
    result: "program_summary",
    cache: Cache::Pure { stage: Stage::Decompile, set: SetKind::Program },
    run: passes,
};

pub static PROGRAM_EMIT: Op = Op {
    name: "program.emit",
    doc: "the whole recovered emission (every emit entry's TU, after the caller-side callee-pragma post-pass) as a program set — the survey's `recovered/` tree; decompile.global-scope defaults to standalone here",
    since: "0.1",
    tier: Tier::Product,
    params: &["program", keys::KNOBS_OFF, keys::DECOMPILE_GLOBAL_SCOPE, keys::DECOMPILE_PROTO_SCOPE, keys::EMIT_ARMS_OFF, EMIT_KEYS],
    result: "emission",
    cache: Cache::Pure { stage: Stage::Emit, set: SetKind::Program },
    run: program_emit,
};

pub static EMIT: Op = Op {
    name: "function.emit",
    doc: "one function's recovered translation unit (the compilable emission), from the program's passes set: format=tu (default) | reference | c | table:report; caller-side callee pragmas are the round's post-pass, not this op's",
    since: "0.1",
    tier: Tier::Product,
    params: &["program", "entry", "format", keys::KNOBS_OFF, keys::DECOMPILE_GLOBAL_SCOPE, keys::DECOMPILE_PROTO_SCOPE, keys::EMIT_ARMS_OFF, EMIT_KEYS],
    result: "text",
    cache: Cache::Pure { stage: Stage::Emit, set: SetKind::Function },
    run: emit,
};

fn check_lang(p: &mosura_core::analysis::program::Program) -> Result<()> {
    if p.language_id != EMIT_LANG {
        return Err(Error::Unsupported(format!("the recovered emitter targets {EMIT_LANG} (Watcom x86-32); this program is {}", p.language_id)));
    }
    Ok(())
}

/// The key of the passes set of a program under the options' tag.
pub fn passes_key(program: &Key, o: &Options) -> Key {
    key(Stage::Decompile, PASSES.name, &[&program.0], &o.tag(), &no_annotations())
}

/// Run the pre-passes over a fresh copy of the program: the survey's pass-1 order.
fn run_passes(p: &mosura_core::analysis::program::Program, o: &Options) -> Result<TableSet> {
    let mut prog = p.clone();
    let knobs = o.knobs()?;
    let settings = o.decompile_settings()?;
    prog.knobs = knobs.clone();
    prog.global_scope_all_loaded = settings.global_scope_all_loaded;
    prog.proto_scope = settings.proto_scope.clone();
    if knobs.on(Switch::ProtoPass) {
        let _marks = mark_tail_return_writes(&mut prog, EMIT_LANG, &[]);
        let _n = install_prototypes(&mut prog, None);
    }
    // the evidence passes read the LANDED world (no prototypes) — split, collect, and freeze the
    // prototype world (the landed one is its projection at thaw)
    let regs = WatcomRegs::for_lang(EMIT_LANG);
    let landed = {
        let mut l = prog.clone();
        l.recovered_protos.clear();
        l
    };
    let ents = Entries::of(&landed);
    let orders = ParamOrders::collect(&landed, EMIT_LANG, &ents, &regs).unwrap_or_default();
    let widths = if knobs.on(Switch::GlobalWidth) { GlobalWidths::collect(&landed, EMIT_LANG, &ents) } else { GlobalWidths { store_w: HashMap::new(), read_w: HashMap::new() } };
    let mut set = freeze(&prog, &o.tag());
    set.insert("param_orders", text_table(&orders.render()));
    let mut addrs: Vec<u64> = widths.store_w.keys().chain(widths.read_w.keys()).copied().collect();
    addrs.sort_unstable();
    addrs.dedup();
    let mut b = TableBuilder::new(&GLOBAL_WIDTHS);
    for a in addrs {
        b.row().u64(a).u32(widths.store_w.get(&a).copied().unwrap_or(0)).u32(widths.read_w.get(&a).copied().unwrap_or(0));
    }
    set.insert("global_widths", b.finish(true));
    Ok(set)
}

fn passes(s: &mut Session, o: &Options, prog: &mut dyn Progress) -> Result<Table> {
    let (pk, p) = program_of(s, o)?;
    check_lang(&p)?;
    let k = passes_key(&pk, o);
    if !s.has_set(SetKind::Program, &k) {
        if !prog.report(PASSES.name, 0, 1) {
            return Err(Error::Cancelled);
        }
        let set = run_passes(&p, o)?;
        s.write_set(SetKind::Program, &k, &set, &Provenance { stage: Stage::Decompile, op: PASSES.name, inputs: &[pk.0], tag: &o.tag(), label: "passes" })?;
    }
    let set = s.read_set(SetKind::Program, &k)?;
    crate::ops::program::summary_of_set(&k, &set)
}

/// The measured arms (P0's `measured_arms`: the canonical arm with the hardware shift mask, and the
/// recovered arm adding `sum-order=original`) with the options' explicit `emit.<axis>` values on top.
fn arms_of(o: &Options) -> Result<(EmitChoices, EmitChoices)> {
    let (mut arm, mut rec) = mosura_core::recompile::recovery::measured_arms();
    for axis in EmitChoices::axes() {
        let k = optreg::emit_key(axis.name);
        if o.is_set(k) {
            let v = o.get(k)?;
            arm.set(axis.name, v).map_err(|e| Error::InvalidArg(format!("{k}: {e:?}")))?;
            rec.set(axis.name, v).map_err(|e| Error::InvalidArg(format!("{k}: {e:?}")))?;
        }
    }
    Ok((arm, rec))
}

/// Build (or reuse) the emit state for the program's passes set under the options' tag.
fn emit_state<'s>(s: &'s mut Session, o: &Options, pk: &Key) -> Result<&'s mut EmitState> {
    let passes_k = passes_key(pk, o);
    let tag = o.tag();
    let fresh = match &s.emit_state {
        Some((k, t, _)) => *k != passes_k || *t != tag,
        None => true,
    };
    if fresh {
        let set = s.read_set(SetKind::Program, &passes_k)?;
        let knobs = o.knobs()?;
        let settings = o.decompile_settings()?;
        let mut pp = thaw(&set, knobs.clone(), &settings)?;
        // The contract cache (`Program::contract_cache`, an order-dependent memo: a cycle's
        // InProgress fallback depends on which function was decompiled first) is not frozen. The
        // survey emitted on the very program object that had run pass 1, cache warmed in pass-1
        // order; re-running the pass on the thawed program warms it the same way (the recovered
        // prototypes it recomputes equal the frozen ones — the P1 round-trip test), so the
        // emission is the survey's byte for byte. Measured: without this one callee pragma's
        // `modify` list differed on watcom_hello.exe.
        if knobs.on(Switch::ProtoPass) {
            let _ = mark_tail_return_writes(&mut pp, EMIT_LANG, &[]);
            let _ = install_prototypes(&mut pp, None);
        }
        let worlds = Worlds::split(pp);
        let entries = Entries::of(&worlds.landed);
        let regs = WatcomRegs::for_lang(EMIT_LANG);
        let orders = ParamOrders::parse(set.table("param_orders")?.str(0, 0)?);
        let mut widths = GlobalWidths { store_w: HashMap::new(), read_w: HashMap::new() };
        if knobs.on(Switch::GlobalWidth) {
            let gw = set.table("global_widths")?;
            for r in 0..gw.rows() {
                let (a, sw, rw) = (gw.u64(r, 0)?, gw.u64(r, 1)? as u32, gw.u64(r, 2)? as u32);
                if sw != 0 {
                    widths.store_w.insert(a, sw);
                }
                if rw != 0 {
                    widths.read_w.insert(a, rw);
                }
            }
        }
        let (arm, rec_arm) = arms_of(o)?;
        let arms_off: Vec<String> = o.arms_off();
        let st = EmitState::new(
            ProgramFacts { lang: EMIT_LANG, knobs, worlds, entries, regs, orders, widths },
            EmitOpts { arms: vec![arm], rec_arm, arms_off, recovered: true, cons_probe: false },
        );
        s.emit_state = Some((passes_k, tag, st));
    }
    Ok(&mut s.emit_state.as_mut().expect("just built").2)
}

fn emit(s: &mut Session, o: &Options, prog: &mut dyn Progress) -> Result<Table> {
    let pk = program_key(s, o)?;
    let format = o.get("format")?.to_string();
    // the passes set is the emit's input: make it (a pure op, served when present)
    let passes_k = passes_key(&pk, o);
    if !s.has_set(SetKind::Program, &passes_k) {
        let (_, p) = program_of(s, o)?;
        check_lang(&p)?;
        if !prog.report(PASSES.name, 0, 2) {
            return Err(Error::Cancelled);
        }
        let set = run_passes(&p, o)?;
        s.write_set(SetKind::Program, &passes_k, &set, &Provenance { stage: Stage::Decompile, op: PASSES.name, inputs: &[pk.0], tag: &o.tag(), label: "passes" })?;
    }
    let entry = {
        let (_, p) = program_of(s, o)?;
        check_lang(&p)?;
        entry_of(&p, o)?
    };
    let k = key(Stage::Emit, EMIT.name, &[&passes_k.0, &entry.to_le_bytes()], &o.tag(), &no_annotations());
    if s.has_set(SetKind::Function, &k) {
        return pick(&s.read_set(SetKind::Function, &k)?, &format);
    }
    if !prog.report(EMIT.name, 1, 2) {
        return Err(Error::Cancelled);
    }
    let st = emit_state(s, o, &pk)?;
    let (idx, name) = st.facts.entries.list.iter().enumerate().find(|(_, (va, _))| *va == entry).map(|(i, (_, n))| (i, n.clone())).ok_or_else(|| Error::NotFound(format!("{entry:#x} is not an emit entry of the program")))?;
    // the survey's rendering choice for recompilation (a thread-local render flag): every
    // while-do in Ghidra's overflow form, which Watcom compiles as the original's branch
    mosura_core::decompile::structure::set_force_loop_overflow(true);
    let result = st.emit_function(idx, entry, &name);
    mosura_core::decompile::structure::set_force_loop_overflow(false);
    let e = result.map_err(|f| Error::Internal(format!("emit of {entry:#x} ({name}): the decompile failed (weight {})", f.weight)))?;
    let mut set = TableSet::default();
    set.insert("tu", text_table(e.recovered_tu.as_deref().unwrap_or(&e.reference_tu)));
    set.insert("reference", text_table(&e.reference_tu));
    set.insert("c", text_table(&e.reference_c));
    let mut b = TableBuilder::new(&EMIT_REPORT);
    let r = &e.row;
    for (kname, v) in [
        ("idx", r.idx.to_string()),
        ("va", format!("{:08x}", r.va)),
        ("name", r.name.clone()),
        ("status", if e.recovered_tu.is_some() { "OK".to_string() } else { "OK (reference only)".to_string() }),
        ("orig_len", r.orig_len.to_string()),
        ("cov_lo", format!("{:x}", r.cov_lo)),
        ("cov_hi", format!("{:x}", r.cov_hi)),
        ("smells", e.smells.join(",")),
        ("orig_hex", r.orig_hex.clone()),
        ("ir_calls", r.ir_calls.to_string()),
        ("blocks_cfg", r.blocks_cfg.to_string()),
        ("blocks_reached", r.blocks_reached.to_string()),
        ("kind", r.kind.to_string()),
        ("contract", r.contract.clone()),
        ("from_prototype_pass", e.from_pp.to_string()),
        ("violations", e.violations.join(",")),
        ("row", r.render()),
    ] {
        b.row().str(kname).str(&v);
    }
    for n in &e.notes {
        b.row().str("note").str(n);
    }
    set.insert("report", b.finish(false));
    let mut inputs = vec![passes_k.0];
    let mut eb = [0u8; 32];
    eb[..8].copy_from_slice(&entry.to_le_bytes());
    inputs.push(eb);
    s.write_set(SetKind::Function, &k, &set, &Provenance { stage: Stage::Emit, op: EMIT.name, inputs: &inputs, tag: &o.tag(), label: &name })?;
    pick(&set, &format)
}

fn pick(set: &TableSet, format: &str) -> Result<Table> {
    match format {
        "" | "tu" => set.table("tu").cloned(),
        "reference" => set.table("reference").cloned(),
        "c" => set.table("c").cloned(),
        t if t.starts_with("table:") => set.table(&t["table:".len()..]).cloned(),
        other => Err(Error::InvalidArg(format!("`format` is tu, reference, c or table:<name>, not `{other}`"))),
    }
}

/// The options of a whole-program emission: the survey models Ghidra's STANDALONE global-scope
/// context (the binary is the emitter's oracle; the application context's anchored forms cost
/// EXACTs, measured) — the default here unless the caller says otherwise.
pub fn emission_options(o: &Options) -> Result<Options> {
    let mut e = o.clone();
    if !o.is_set(keys::DECOMPILE_GLOBAL_SCOPE) {
        e.set(keys::DECOMPILE_GLOBAL_SCOPE, "standalone")?;
    }
    Ok(e)
}

/// The key of a program's emission set under `o` (after [`emission_options`]).
pub fn emission_key(passes_k: &Key, o: &Options) -> Key {
    key(Stage::Emit, PROGRAM_EMIT.name, &[&passes_k.0], &o.tag(), &no_annotations())
}

/// Make (or serve) the passes set of the program under `o`; answers its key.
pub fn ensure_passes(s: &mut Session, o: &Options, pk: &Key) -> Result<Key> {
    let passes_k = passes_key(pk, o);
    if !s.has_set(SetKind::Program, &passes_k) {
        let (_, p) = program_of(s, o)?;
        check_lang(&p)?;
        let set = run_passes(&p, o)?;
        s.write_set(SetKind::Program, &passes_k, &set, &Provenance { stage: Stage::Decompile, op: PASSES.name, inputs: &[pk.0], tag: &o.tag(), label: "passes" })?;
    }
    Ok(passes_k)
}

fn program_emit(s: &mut Session, o: &Options, prog: &mut dyn Progress) -> Result<Table> {
    let o = emission_options(o)?;
    let pk = program_key(s, &o)?;
    let passes_k = ensure_passes(s, &o, &pk)?;
    let k = emission_key(&passes_k, &o);
    if s.has_set(SetKind::Program, &k) {
        return s.read_set(SetKind::Program, &k)?.table("emission").cloned();
    }
    let st = emit_state(s, &o, &pk)?;
    let entries: Vec<(u64, String)> = st.facts.entries.list.clone();
    let total = entries.len() as u64;
    // every entry, in the survey's order, under the survey's render flag
    struct Row {
        idx: usize,
        va: u64,
        name: String,
        status: &'static str,
        kind: String,
        orig_len: u64,
        tu: Option<String>,
        row: String,
    }
    let mut rows: Vec<Row> = Vec::with_capacity(entries.len());
    mosura_core::decompile::structure::set_force_loop_overflow(true);
    for (idx, (va, name)) in entries.iter().enumerate() {
        if idx % 100 == 0 && !prog.report(PROGRAM_EMIT.name, idx as u64, total) {
            mosura_core::decompile::structure::set_force_loop_overflow(false);
            return Err(Error::Cancelled);
        }
        match st.emit_function(idx, *va, name) {
            Ok(e) => {
                let tu = e.recovered_tu.clone().unwrap_or_else(|| e.reference_tu.clone());
                rows.push(Row { idx, va: *va, name: name.clone(), status: "OK", kind: e.kind.to_string(), orig_len: e.row.orig_len, tu: Some(tu), row: e.row.render() });
            }
            Err(f) => {
                let kind = mosura_core::recompile::manifest::kind_of(name);
                let r = mosura_core::recompile::manifest::ManifestRow::decompile_fail(idx, *va, name, f.weight, kind, "");
                rows.push(Row { idx, va: *va, name: name.clone(), status: "DECOMPILE_FAIL", kind: kind.to_string(), orig_len: f.weight, tu: None, row: r.render() });
            }
        }
    }
    mosura_core::decompile::structure::set_force_loop_overflow(false);
    // the caller-side pragma post-pass: every TU externs its callees; their contracts exist only
    // once every function has been emitted
    for r in rows.iter_mut() {
        if let Some(tu) = &r.tu {
            if let Some(patched) = st.contracts.patch_caller(tu, Some(r.va)) {
                r.tu = Some(patched);
            }
        }
    }
    let arms = mosura_core::recompile::manifest::arms_stamp(&st.opts.rec_arm, &st.opts.arms_off, &st.facts.knobs);
    let mut b = TableBuilder::new(&EMISSION);
    for r in &rows {
        b.row().u32(r.idx as u32).u64(r.va).str(&r.name).str(r.status).str(&r.kind).u64(r.orig_len).str(r.tu.as_deref().unwrap_or("")).str(&r.row);
    }
    let mut set = TableSet::default();
    set.insert("emission", b.finish(false));
    set.insert("arms", text_table(&arms));
    s.write_set(SetKind::Program, &k, &set, &Provenance { stage: Stage::Emit, op: PROGRAM_EMIT.name, inputs: &[passes_k.0], tag: &o.tag(), label: &arms })?;
    set.table("emission").cloned()
}
