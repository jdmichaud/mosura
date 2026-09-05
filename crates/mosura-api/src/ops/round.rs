//! The recompile side (plan §3 P3): `function.buildconfig` (the original's build flags from its
//! own prologue), `function.verify` (a compiled object against the original), `function.recompile`
//! (one function end to end), and the ROUNDS — `round.run` (the survey's emit → compile → verify →
//! verdicts → gates as one operation writing `rounds/<name>/`), `round.compare`, `round.gates`,
//! `round.list`, `round.show`, `round.export` / `round.import` (the legacy 11-column verdict TSV
//! and 14-column divergence TSV, so the census scripts and the old series keep reading). Every
//! number is computed the way `recompile_check` and `corpus-verdicts.sh` computed it; the bodies
//! orchestrate and decide nothing.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::fingerprint::{build_id, Stage};
use crate::options::{keys, Options};
use crate::ops::emit::{emission_key, emission_options, ensure_passes, EMIT_LANG};
use crate::ops::function::{entry_of, EMIT_KEYS};
use crate::ops::program::{program_key, program_of};
use crate::ops::schemas::{BUILDCONFIG, COMPARE, DIFF, DIVERGENCES, FILES, GATES, ROUNDS, VERDICTS};
use crate::ops::toolchain::toolchain_of;
use crate::ops::{Cache, Op, Progress, Tier};
use crate::program::schemas::MANIFEST;
use crate::session::{Session, SetKind};
use crate::set::TableSet;
use crate::table::builder::TableBuilder;
use crate::table::Table;
use mosura_core::analysis::program::Program;
use mosura_core::decompile::space::Address;
use mosura_core::recompile::gates::{self, GateReport, VerdictRow};
use mosura_core::recompile::insn::{normalize, NoReloc, NormInsn};
use mosura_core::recompile::toolchain::{CompileUnit, Toolchain};
use mosura_core::recompile::{buildconfig, emitted_symbol_address, verify_with_image, AlignOp, Checked, DivergenceClass, FnKey, Outcome, Subject, DIVERGENCE_HEADER};

pub static BUILDCONFIG_OP: Op = Op { name: "function.buildconfig", doc: "the original's build flags recovered from its own prologue (shape → fact → flag, the profile's rules): rows fact/flag", since: "0.1", tier: Tier::Product, params: &["program", "entry", keys::KNOBS_OFF, keys::DECOMPILE_GLOBAL_SCOPE, keys::DECOMPILE_PROTO_SCOPE, keys::EMIT_ARMS_OFF, EMIT_KEYS], result: "buildconfig", cache: Cache::Transient, run: buildconfig_op };
pub static VERIFY: Op = Op { name: "function.verify", doc: "verify a compiled object (a session input, `object`) against the original: one verdict row; format=table:divergences for the aligned differences", since: "0.1", tier: Tier::Product, params: &["program", "entry", "object", "format", keys::VERIFY_TABLE_WINDOW, keys::KNOBS_OFF, keys::DECOMPILE_GLOBAL_SCOPE, keys::DECOMPILE_PROTO_SCOPE, keys::EMIT_ARMS_OFF, EMIT_KEYS], result: "verdicts", cache: Cache::Transient, run: verify_op };
pub static RECOMPILE: Op = Op { name: "function.recompile", doc: "one function end to end: passes → decompile → recover → TU → compile (the named toolchain, cached) → verify; format=table:divergences | table:diff (the aligned instruction diff)", since: "0.1", tier: Tier::Product, params: &["program", "entry", "toolchain", "format", keys::VERIFY_TABLE_WINDOW, keys::KNOBS_OFF, keys::DECOMPILE_GLOBAL_SCOPE, keys::DECOMPILE_PROTO_SCOPE, keys::EMIT_ARMS_OFF, EMIT_KEYS], result: "verdicts", cache: Cache::Transient, run: recompile_op };
pub static RUN: Op = Op { name: "round.run", doc: "a corpus round: the emission → text gates → compile (cached, locked) → verify → verdicts, divergences, gates and manifest under rounds/<round>; verdict gates against round.baseline; the smoke-drift gate from round.expect", since: "0.1", tier: Tier::Product, params: &["round", "toolchain", "label", "program", keys::ROUND_SCOPE, keys::ROUND_SCOPE_FILE, keys::ROUND_BASELINE, keys::ROUND_EXPECT, keys::ROUND_EXCLUDE_FOREIGN, keys::GATES_BASELINE, keys::VERIFY_TABLE_WINDOW, keys::KNOBS_OFF, keys::DECOMPILE_GLOBAL_SCOPE, keys::DECOMPILE_PROTO_SCOPE, keys::EMIT_ARMS_OFF, EMIT_KEYS], result: "manifest", cache: Cache::Transient, run: run_op };
pub static COMPARE_OP: Op = Op { name: "round.compare", doc: "two rounds joined by address: the census of each, every verdict flip, every similarity mover, the net and weighted (WGSS) deltas, membership drift", since: "0.1", tier: Tier::Product, params: &["a", "b"], result: "compare", cache: Cache::Transient, run: compare_op };
pub static GATES_OP: Op = Op { name: "round.gates", doc: "the verdict gates of a stored round (guard sets EXACT; vs round.baseline: no EXACT lost, no new failure; the smoke-drift gate from round.expect)", since: "0.1", tier: Tier::Product, params: &["round", keys::ROUND_BASELINE, keys::ROUND_EXPECT, keys::GATES_BASELINE], result: "gates", cache: Cache::Transient, run: gates_op };
pub static LIST: Op = Op { name: "round.list", doc: "the rounds of the session: program, toolchain, build, when, rows, EXACT, WGSS", since: "0.1", tier: Tier::Product, params: &[], result: "rounds", cache: Cache::Transient, run: list_op };
pub static SHOW: Op = Op { name: "round.show", doc: "a round's table: manifest (default), verdicts, divergences, gates", since: "0.1", tier: Tier::Product, params: &["round", "table"], result: "manifest", cache: Cache::Transient, run: show_op };
pub static EXPORT: Op = Op { name: "round.export", doc: "write a round as the legacy files: `out` = the 11-column verdict TSV (SIM=structural stamped), `divergences` = the 14-column divergence TSV", since: "0.1", tier: Tier::Product, params: &["round", "out", "divergences"], result: "files", cache: Cache::Transient, run: export_op };
pub static IMPORT: Op = Op { name: "round.import", doc: "store legacy files as a round: `verdicts` (the 11-column TSV), `divergences` (optional), `manifest` (an emit manifest, for its `# arms:` line; optional)", since: "0.1", tier: Tier::Product, params: &["round", "verdicts", "divergences", "manifest", "label"], result: "manifest", cache: Cache::Transient, run: import_op };

// ── one verdict row ──

#[derive(Clone, Debug)]
pub struct VRow {
    pub idx: String,
    pub va: u64,
    pub name: String,
    pub outcome: Outcome,
    pub bytes: String,
    pub primary: String,
    pub sim: f64,
    pub byte_sim: f64,
    pub equal: u64,
    pub orig_n: u64,
    pub cand_n: u64,
    pub classes: String,
}

impl VRow {
    fn failure(idx: &str, va: u64, name: &str, outcome: Outcome, orig_n: u64) -> VRow {
        VRow { idx: idx.to_string(), va, name: name.to_string(), outcome, bytes: String::new(), primary: String::new(), sim: 0.0, byte_sim: 0.0, equal: 0, orig_n, cand_n: 0, classes: String::new() }
    }

    fn verified(idx: &str, va: u64, name: &str, c: &Checked) -> VRow {
        let d = &c.diff;
        let classes = d.class_counts.iter().filter(|(k, _)| **k != DivergenceClass::Equal).map(|(k, n)| format!("{}={}", k.as_str(), n)).collect::<Vec<_>>().join(",");
        VRow { idx: idx.to_string(), va, name: name.to_string(), outcome: Outcome::Verified(d.verdict), bytes: format!("{:?}", c.bytes), primary: d.primary.map(|p| p.as_str().to_string()).unwrap_or_default(), sim: d.similarity, byte_sim: d.byte_similarity, equal: d.equal_insns as u64, orig_n: d.orig_insns as u64, cand_n: d.cand_insns as u64, classes }
    }

    /// The row as `recompile_check --out` wrote it (the 11 columns).
    pub fn legacy_line(&self) -> String {
        if self.outcome.is_failure() {
            format!("{}\t{:08x}\t{}\t{}\t\t\t\t0\t{}\t0\t", self.idx, self.va, self.name, self.outcome.as_str(), self.orig_n)
        } else {
            format!("{}\t{:08x}\t{}\t{}\t{}\t{}\t{:.3}\t{}\t{}\t{}\t{}", self.idx, self.va, self.name, self.outcome.as_str(), self.bytes, self.primary, self.sim, self.equal, self.orig_n, self.cand_n, self.classes)
        }
    }
}

pub const LEGACY_VERDICT_HEADER: &str = "idx\tva\tname\tverdict\tbytes\tprimary\tsim\tequal\torig_n\tcand_n\tclasses\tSIM=structural";

fn verdicts_table(rows: &[VRow]) -> Table {
    let mut b = TableBuilder::new(&VERDICTS);
    for r in rows {
        b.row().str(&r.idx).u64(r.va).str(&r.name).str(r.outcome.as_str()).str(&r.bytes).str(&r.primary).f64(r.sim).u64(r.equal).u64(r.orig_n).u64(r.cand_n).str(&r.classes);
    }
    b.finish(false)
}

fn verdict_rows_of(t: &Table) -> Result<Vec<VRow>> {
    let mut out = Vec::with_capacity(t.rows() as usize);
    for r in 0..t.rows() {
        let v = t.str(r, 3)?;
        let outcome = Outcome::parse(v).ok_or_else(|| Error::Format(format!("unknown verdict `{v}`")))?;
        out.push(VRow { idx: t.str(r, 0)?.to_string(), va: t.u64(r, 1)?, name: t.str(r, 2)?.to_string(), outcome, bytes: t.str(r, 4)?.to_string(), primary: t.str(r, 5)?.to_string(), sim: t.f64(r, 6)?, byte_sim: 0.0, equal: t.u64(r, 7)?, orig_n: t.u64(r, 8)?, cand_n: t.u64(r, 9)?, classes: t.str(r, 10)?.to_string() });
    }
    Ok(out)
}

/// `Σ orig_n·sim / Σ orig_n` — the canonical census (measurement rules §9); rows without a
/// candidate weigh their full original size at zero.
pub fn wgss_of(rows: &[VRow]) -> f64 {
    let (mut w, mut n) = (0f64, 0u64);
    for r in rows {
        w += r.orig_n as f64 * r.sim;
        n += r.orig_n;
    }
    if n == 0 { 0.0 } else { w / n as f64 }
}

fn census_of(rows: &[VRow]) -> BTreeMap<&'static str, usize> {
    let mut c = BTreeMap::new();
    for r in rows {
        *c.entry(r.outcome.as_str()).or_insert(0) += 1;
    }
    c
}

// ── divergences ──

fn divergence_table_from_text(text: &str) -> Result<Table> {
    let mut b = TableBuilder::new(&DIVERGENCES);
    for (i, line) in text.lines().enumerate() {
        if i == 0 || line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 14 {
            return Err(Error::Format(format!("divergence row {i}: {} columns", f.len())));
        }
        let num = |s: &str| s.parse::<i64>().unwrap_or(-1);
        b.row().str(f[0]).u64(u64::from_str_radix(f[1], 16).unwrap_or(0)).str(f[2]).u64(u64::from_str_radix(f[3], 16).unwrap_or(0)).i64(num(f[4])).i64(num(f[5])).u64(f[6].parse().unwrap_or(0)).u64(f[7].parse().unwrap_or(0)).str(f[8]).str(f[9]).str(f[10]).str(f[11]).str(f[12]).str(f[13]);
    }
    Ok(b.finish(false))
}

/// The divergence table back into the legacy TSV text (header included).
fn divergence_text_of(t: &Table) -> Result<String> {
    let mut s = String::from(DIVERGENCE_HEADER);
    for r in 0..t.rows() {
        s.push_str(&format!("{}\t{:08x}\t{}\t{:08x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n", t.str(r, 0)?, t.u64(r, 1)?, t.str(r, 2)?, t.u64(r, 3)?, t.i64(r, 4)?, t.i64(r, 5)?, t.u64(r, 6)?, t.u64(r, 7)?, t.str(r, 8)?, t.str(r, 9)?, t.str(r, 10)?, t.str(r, 11)?, t.str(r, 12)?, t.str(r, 13)?));
    }
    Ok(s)
}

// ── the original's bytes, instructions, flags ──

fn orig_bytes(p: &Program, va: u64, len: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len as usize);
    for k in 0..len {
        match p.memory.byte_at(Address::new(p.default_space, va + k)) {
            Some(b) => out.push(b),
            None => break,
        }
    }
    out
}

fn insns_of(bytes: &[u8], va: u64) -> Result<Vec<NormInsn>> {
    normalize(EMIT_LANG, bytes, va, &NoReloc).map_err(|e| Error::Unsupported(format!("{e:?}")))
}

fn profile_flags(insns: &[NormInsn]) -> Result<(buildconfig::Evidence, Vec<String>)> {
    let profile = buildconfig::watcom_10_0a();
    let (sp, fp) = profile.stack_regs().ok_or_else(|| Error::Unsupported(format!("the {} profile's stack registers could not be resolved", profile.name)))?;
    let ev = buildconfig::detect(insns, sp, fp);
    let flags = profile.flags_for(&ev);
    Ok((ev, flags))
}

/// Verify one object against the original function; the jump-table correspondence search looks
/// `window` bytes around the function (nearest match wins), as `recompile_check` did.
fn verify_function(p: &Program, va: u64, name: &str, len: u64, object: &[u8], window: u64) -> std::result::Result<Checked, String> {
    let obytes = orig_bytes(p, va, len);
    let subject = Subject { name: name.to_string(), va, len: len as usize };
    let win_lo = va.saturating_sub(window);
    let win = p.memory.read_window(Address::new(p.default_space, win_lo), ((2 * window) as usize + len as usize).min(0x10_0000));
    let find_near = |needle: &[u8]| -> Option<u64> {
        if needle.is_empty() {
            return None;
        }
        let mut best: Option<u64> = None;
        let mut pos = 0usize;
        while pos + needle.len() <= win.len() {
            match win[pos..].windows(needle.len()).position(|w| w == needle) {
                Some(rel) => {
                    let at = win_lo + (pos + rel) as u64;
                    let better = match best {
                        None => true,
                        Some(b) => at.abs_diff(va) < b.abs_diff(va),
                    };
                    if better {
                        best = Some(at);
                    }
                    pos += rel + 1;
                }
                None => break,
            }
        }
        best
    };
    verify_with_image(EMIT_LANG, &obytes, &subject, object, &emitted_symbol_address, Some(&find_near)).map_err(|e| e.to_string())
}

fn window_of(o: &Options) -> Result<u64> {
    crate::options::parse_hex(o.get(keys::VERIFY_TABLE_WINDOW)?).ok_or_else(|| Error::InvalidArg("verify.table-window is not a number".into()))
}

/// One emitted function: its emit index, name, original length and TU — from the program's
/// emission set when it exists (the post-passed TU the round measures), else from
/// `function.emit` (the survey's `--only` probe: the TU before the caller-side post-pass).
struct EmittedFn {
    idx: String,
    name: String,
    orig_len: u64,
    tu: Option<String>,
    status: String,
}

fn emitted_function(s: &mut Session, o: &Options, entry: u64) -> Result<EmittedFn> {
    let eo = emission_options(o)?;
    let pk = program_key(s, &eo)?;
    let passes_k = ensure_passes(s, &eo, &pk)?;
    let ek = emission_key(&passes_k, &eo);
    if s.has_set(SetKind::Program, &ek) {
        let set = s.read_set(SetKind::Program, &ek)?;
        let em = set.table("emission")?;
        for r in 0..em.rows() {
            if em.u64(r, 1)? == entry {
                let status = em.str(r, 3)?.to_string();
                let tu = if status == "OK" { Some(em.str(r, 6)?.to_string()) } else { None };
                return Ok(EmittedFn { idx: format!("{:05}", em.u64(r, 0)?), name: em.str(r, 2)?.to_string(), orig_len: em.u64(r, 5)?, tu, status });
            }
        }
        return Err(Error::NotFound(format!("{entry:#x} is not an emit entry of the program")));
    }
    let mut fo = eo.clone();
    fo.set("entry", &format!("{entry:#x}"))?;
    fo.set("format", "table:report")?;
    let rep = crate::ops::dispatch_inner(s, "function.emit", &fo)?;
    let field = |k: &str| -> Option<String> { (0..rep.rows()).find(|&r| rep.str(r, 0).ok() == Some(k)).and_then(|r| rep.str(r, 1).ok().map(str::to_string)) };
    let idx = field("idx").unwrap_or_else(|| "0".into()).parse::<usize>().unwrap_or(0);
    fo.set("format", "tu")?;
    let tu = crate::render(&crate::ops::dispatch_inner(s, "function.emit", &fo)?, crate::Format::Text)?;
    Ok(EmittedFn { idx: format!("{idx:05}"), name: field("name").unwrap_or_default(), orig_len: field("orig_len").and_then(|v| v.parse().ok()).unwrap_or(0), tu: Some(tu), status: "OK".into() })
}

// ── function.buildconfig ──

fn buildconfig_op(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let (_, p) = program_of(s, o)?;
    let entry = entry_of(&p, o)?;
    let f = emitted_function(s, o, entry)?;
    let bytes = orig_bytes(&p, entry, f.orig_len);
    let insns = insns_of(&bytes, entry)?;
    let (ev, flags) = profile_flags(&insns)?;
    let mut b = TableBuilder::new(&BUILDCONFIG);
    for fact in ev.facts() {
        b.row().str("fact").str(&format!("{fact:?}")).str("");
    }
    for fl in &flags {
        b.row().str("flag").str(fl).str("");
    }
    b.row().str("profile").str(&buildconfig::watcom_10_0a().name).str(&format!("{} bytes, {} instructions", bytes.len(), insns.len()));
    Ok(b.finish(false))
}

// ── function.verify / function.recompile ──

fn diff_table(c: &Checked) -> Table {
    let mut b = TableBuilder::new(&DIFF);
    let (orig, cand) = (&c.original, &c.candidate);
    for op in &c.diff.ops {
        match op {
            AlignOp::Pair { oi, ci, class } => {
                b.row().str(if *class == DivergenceClass::Equal { "=" } else { "~" }).u64(orig[*oi].addr).str(&orig[*oi].text).str(&cand[*ci].text).str(if *class == DivergenceClass::Equal { "" } else { class.as_str() });
            }
            AlignOp::OrigOnly { oi } => {
                b.row().str("-").u64(orig[*oi].addr).str(&orig[*oi].text).str("").str("missing");
            }
            AlignOp::CandOnly { ci } => {
                b.row().str("+").u64(cand[*ci].addr).str("").str(&cand[*ci].text).str("extra");
            }
        }
    }
    b.finish(false)
}

fn answer(format: &str, row: &VRow, checked: Option<&Checked>) -> Result<Table> {
    match format {
        "" | "verdicts" => Ok(verdicts_table(std::slice::from_ref(row))),
        "table:divergences" => {
            let mut text = String::from(DIVERGENCE_HEADER);
            if let Some(c) = checked {
                mosura_core::recompile::write_divergence_rows(&mut text, &FnKey { idx: row.idx.clone(), va: row.va, name: row.name.clone() }, &c.diff, &c.original, &c.candidate);
            }
            divergence_table_from_text(&text)
        }
        "table:diff" => Ok(checked.map(diff_table).unwrap_or_else(|| TableBuilder::new(&DIFF).finish(false))),
        other => Err(Error::InvalidArg(format!("`format` is verdicts, table:divergences or table:diff, not `{other}`"))),
    }
}

fn verify_op(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let (_, p) = program_of(s, o)?;
    let entry = entry_of(&p, o)?;
    let object_name = o.get("object")?;
    if object_name.is_empty() {
        return Err(Error::InvalidArg("`object` is required: a session input holding the compiled object".into()));
    }
    let object = s.input_bytes(&s.resolve_input(object_name)?)?;
    let f = emitted_function(s, o, entry)?;
    let format = o.get("format")?.to_string();
    let orig_n = insns_of(&orig_bytes(&p, entry, f.orig_len), entry)?.len() as u64;
    match verify_function(&p, entry, &f.name, f.orig_len, &object, window_of(o)?) {
        Ok(c) => answer(&format, &VRow::verified(&f.idx, entry, &f.name, &c), Some(&c)),
        Err(_) => answer(&format, &VRow::failure(&f.idx, entry, &f.name, Outcome::ObjError, orig_n), None),
    }
}

fn recompile_op(s: &mut Session, o: &Options, prog: &mut dyn Progress) -> Result<Table> {
    let (_, p) = program_of(s, o)?;
    let entry = entry_of(&p, o)?;
    let format = o.get("format")?.to_string();
    if !prog.report("emit", 0, 3) {
        return Err(Error::Cancelled);
    }
    let f = emitted_function(s, o, entry)?;
    let bytes = orig_bytes(&p, entry, f.orig_len);
    let insns = insns_of(&bytes, entry)?;
    let orig_n = insns.len() as u64;
    let Some(tu) = f.tu else { return answer(&format, &VRow::failure(&f.idx, entry, &f.name, if f.status == "DECOMPILE_FAIL" { Outcome::DecompileFail } else { Outcome::EmitFail }, orig_n), None) };
    let (_, flags) = profile_flags(&insns)?;
    if !prog.report("compile", 1, 3) {
        return Err(Error::Cancelled);
    }
    let out = {
        let (_, tc) = toolchain_of(s, o)?;
        tc.driver.compile(&CompileUnit { key: f.idx.clone(), source: tu, flags })
    };
    let Some(object) = out.object else { return answer(&format, &VRow::failure(&f.idx, entry, &f.name, Outcome::CompileFail, orig_n), None) };
    if !prog.report("verify", 2, 3) {
        return Err(Error::Cancelled);
    }
    match verify_function(&p, entry, &f.name, f.orig_len, &object, window_of(o)?) {
        Ok(c) => answer(&format, &VRow::verified(&f.idx, entry, &f.name, &c), Some(&c)),
        Err(_) => answer(&format, &VRow::failure(&f.idx, entry, &f.name, Outcome::ObjError, orig_n), None),
    }
}

// ── round.run ──

fn read_scope_file(path: &str) -> Result<BTreeSet<u64>> {
    let text = std::fs::read_to_string(path).map_err(|e| Error::io(e, PathBuf::from(path)))?;
    let mut set = BTreeSet::new();
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 2 || f[0] == "idx" {
            continue;
        }
        if let Ok(va) = u64::from_str_radix(f[1].trim().trim_start_matches("0x"), 16) {
            set.insert(va);
        }
    }
    Ok(set)
}

/// The smoke-drift gate: every `idx va name expected` row of the file must hold its verdict.
fn smoke_gate(path: &str, rows: &[VRow]) -> Result<GateReport> {
    let text = std::fs::read_to_string(path).map_err(|e| Error::io(e, PathBuf::from(path)))?;
    let by_va: BTreeMap<u64, &VRow> = rows.iter().map(|r| (r.va, r)).collect();
    let mut hits = Vec::new();
    let mut checked = 0usize;
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 4 || f[0] == "idx" {
            continue;
        }
        let Ok(va) = u64::from_str_radix(f[1].trim().trim_start_matches("0x"), 16) else { continue };
        checked += 1;
        let got = by_va.get(&va).map(|r| r.outcome.as_str()).unwrap_or("<absent>");
        if got != f[3].trim() {
            hits.push(gates::Hit { va, name: f[2].to_string(), detail: format!("expected {} got {got}", f[3].trim()) });
        }
    }
    let note = format!("({checked} sentinels checked)");
    Ok(GateReport { gate: "9 smoke-drift", outcome: if hits.is_empty() { gates::Outcome::Ok } else { gates::Outcome::Fail(hits) }, note })
}

fn gates_table(reports: &[GateReport]) -> Table {
    let mut b = TableBuilder::new(&GATES);
    for r in reports {
        let (outcome, detail) = match &r.outcome {
            gates::Outcome::Ok => ("OK".to_string(), r.note.clone()),
            gates::Outcome::Skip(why) => ("SKIP".to_string(), format!("{why} {}", r.note).trim().to_string()),
            gates::Outcome::Fail(hits) => ("FAIL".to_string(), format!("{} — {}", r.note, hits.iter().map(|h| format!("{:#x} {}: {}", h.va, h.name, h.detail)).collect::<Vec<_>>().join("; "))),
        };
        b.row().str(r.gate).str(&outcome).str(&detail);
    }
    b.finish(false)
}

fn verdict_rows_map(rows: &[VRow]) -> BTreeMap<u64, VerdictRow> {
    rows.iter().map(|r| (r.va, VerdictRow { idx: r.idx.clone(), va: r.va, name: r.name.clone(), verdict: r.outcome.as_str().to_string(), sim: r.sim, equal: r.equal, orig_n: r.orig_n })).collect()
}

/// Gates 7–8 (+9): the guard sets from `gates.baseline`, the regression check against the
/// baseline round, the smoke drift from `round.expect`.
fn verdict_gates(s: &Session, o: &Options, rows: &[VRow], partial: bool) -> Result<Vec<GateReport>> {
    let mut reports = Vec::new();
    let cur = verdict_rows_map(rows);
    let baseline_round = o.get(keys::ROUND_BASELINE)?;
    let prev = if baseline_round.is_empty() {
        None
    } else {
        let set = s.read_round(baseline_round)?;
        Some(verdict_rows_map(&verdict_rows_of(set.table("verdicts")?)?))
    };
    match o.get(keys::GATES_BASELINE)? {
        "" => {
            reports.push(GateReport::skip("7 guard-sets-exact", "no gates.baseline (the subject profile's corpus-gates.tsv)"));
            reports.push(match &prev {
                Some(p) => gates::verdict_regressions(p, &cur),
                None => GateReport::skip("8 verdict-regressions", "no round.baseline"),
            });
        }
        file => {
            let baseline = gates::Baseline::load(Path::new(file)).map_err(Error::Format)?;
            reports.extend(gates::run_verdict_gates(&cur, prev.as_ref(), &baseline, partial));
        }
    }
    let expect = o.get(keys::ROUND_EXPECT)?;
    if !expect.is_empty() {
        reports.push(smoke_gate(expect, rows)?);
    }
    Ok(reports)
}

fn manifest_rows(pairs: &[(&str, &str, String)]) -> Table {
    let mut b = TableBuilder::new(&MANIFEST);
    for (k, n, v) in pairs {
        b.row().str(k).str(n).str(v);
    }
    b.finish(false)
}

fn run_op(s: &mut Session, o: &Options, prog: &mut dyn Progress) -> Result<Table> {
    let name = o.get("round")?.to_string();
    if name.is_empty() {
        return Err(Error::InvalidArg("`round` (a name for the round) is required".into()));
    }
    if s.rounds()?.iter().any(|r| *r == name) {
        return Err(Error::InvalidArg(format!("round `{name}` exists (rounds are never overwritten)")));
    }
    let eo = emission_options(o)?;
    let (pk, p) = program_of(s, &eo)?;
    // 1. the emission (served when its key exists)
    if !prog.report("emit", 0, 4) {
        return Err(Error::Cancelled);
    }
    let emission = crate::ops::dispatch_inner(s, "program.emit", &eo)?;
    let passes_k = ensure_passes(s, &eo, &pk)?;
    let ek = emission_key(&passes_k, &eo);
    let arms = s.read_set(SetKind::Program, &ek)?.table("arms")?.str(0, 0)?.to_string();
    // 2. the scope
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
    let (foreign, foreign_stamp): (HashSet<u64>, Option<String>) = match o.get(keys::ROUND_EXCLUDE_FOREIGN)? {
        "" => (HashSet::new(), None),
        file => {
            let bytes = std::fs::read(file).map_err(|e| Error::io(e, PathBuf::from(file)))?;
            let mut h = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hash::hash_slice(&bytes, &mut h);
            let stamp = format!("{}@{:016x}", Path::new(file).file_name().and_then(|s| s.to_str()).unwrap_or("foreign"), std::hash::Hasher::finish(&h));
            let facts = mosura_core::analysis::foreign::extract_facts(&p);
            let conf = mosura_core::analysis::foreign::Confirmation::load(Path::new(file)).map_err(|e| Error::io(e, PathBuf::from(file)))?;
            let cls = mosura_core::analysis::foreign::classify(&facts, &conf);
            (cls.class.iter().filter(|(_, c)| **c == mosura_core::analysis::foreign::Class::Foreign).map(|(va, _)| *va).collect(), Some(stamp))
        }
    };
    struct Sel {
        idx: String,
        va: u64,
        name: String,
        orig_len: u64,
        tu: Option<String>,
        row: String,
    }
    let mut selected: Vec<Sel> = Vec::new();
    for r in 0..emission.rows() {
        let va = emission.u64(r, 1)?;
        let kind = emission.str(r, 4)?.to_string();
        let in_scope = match &listed {
            Some(l) => l.contains(&va),
            None => (scope == "all" || (kind != "library" && kind != "asm")) && !foreign.contains(&va),
        };
        if !in_scope {
            continue;
        }
        let status = emission.str(r, 3)?;
        selected.push(Sel { idx: format!("{:05}", emission.u64(r, 0)?), va, name: emission.str(r, 2)?.to_string(), orig_len: emission.u64(r, 5)?, tu: if status == "OK" { Some(emission.str(r, 6)?.to_string()) } else { None }, row: emission.str(r, 7)?.to_string() });
    }
    if selected.is_empty() {
        return Err(Error::NotFound("no function in scope".into()));
    }
    // 3. the text gates over the emitted TUs (1–3 always; 4–6 on a full emit)
    let full = listed.is_none();
    let mut reports: Vec<GateReport> = Vec::new();
    let columns: Vec<&str> = mosura_core::recompile::manifest::COLUMNS.split('\t').collect();
    let tus: Vec<gates::Tu> = selected.iter().filter_map(|sel| sel.tu.as_ref().map(|tu| gates::Tu { va: sel.va, name: sel.name.clone(), text: tu.clone(), columns: columns.iter().map(|c| c.to_string()).zip(sel.row.split('\t').map(str::to_string)).collect() })).collect();
    match o.get(keys::GATES_BASELINE)? {
        "" => {
            for g in ["1 declared-symbols", "2 piece-on-field", "3 call-as-argument", "4 string-ops-bar", "5 chains-never-switch", "6 switch-labels"] {
                reports.push(GateReport::skip(g, "no gates.baseline"));
            }
        }
        file => {
            let baseline = gates::Baseline::load(Path::new(file)).map_err(Error::Format)?;
            reports.extend(gates::run_text_gates(&tus, &gates::kind_is_user, &baseline, full));
        }
    }
    // 4. compile every TU in one batch (the cache makes a repeat free)
    if !prog.report("compile", 1, 4) {
        return Err(Error::Cancelled);
    }
    let mut units: Vec<CompileUnit> = Vec::new();
    let mut unit_rows: Vec<usize> = Vec::new();
    for (i, sel) in selected.iter().enumerate() {
        if let Some(tu) = &sel.tu {
            let insns = insns_of(&orig_bytes(&p, sel.va, sel.orig_len), sel.va)?;
            let (_, flags) = profile_flags(&insns)?;
            units.push(CompileUnit { key: sel.idx.clone(), source: tu.clone(), flags });
            unit_rows.push(i);
        }
    }
    let (toolchain_name, toolchain_id, toolchain_spec, outs, hits, misses) = {
        let (tn, tc) = toolchain_of(s, o)?;
        let outs = tc.driver.compile_batch(&units);
        let (h, m) = tc.driver.stats();
        (tn.to_string(), tc.id.clone(), tc.spec.clone(), outs, h, m)
    };
    // 5. verify
    if !prog.report("verify", 2, 4) {
        return Err(Error::Cancelled);
    }
    let window = window_of(o)?;
    let mut rows: Vec<VRow> = Vec::with_capacity(selected.len());
    let mut div_text = String::from(DIVERGENCE_HEADER);
    let mut out_by_row: BTreeMap<usize, &mosura_core::recompile::CompileOutput> = BTreeMap::new();
    for (k, i) in unit_rows.iter().enumerate() {
        out_by_row.insert(*i, &outs[k]);
    }
    let (mut canon_byte_w, mut canon_n) = (0f64, 0u64);
    for (i, sel) in selected.iter().enumerate() {
        let orig_n = || insns_of(&orig_bytes(&p, sel.va, sel.orig_len), sel.va).map(|v| v.len() as u64).unwrap_or(0);
        let row = match (&sel.tu, out_by_row.get(&i)) {
            (None, _) => VRow::failure(&sel.idx, sel.va, &sel.name, Outcome::EmitFail, orig_n()),
            (Some(_), Some(out)) if !out.ok() => VRow::failure(&sel.idx, sel.va, &sel.name, Outcome::CompileFail, orig_n()),
            (Some(_), Some(out)) => match verify_function(&p, sel.va, &sel.name, sel.orig_len, out.object.as_ref().expect("ok"), window) {
                Ok(c) => {
                    mosura_core::recompile::write_divergence_rows(&mut div_text, &FnKey { idx: sel.idx.clone(), va: sel.va, name: sel.name.clone() }, &c.diff, &c.original, &c.candidate);
                    VRow::verified(&sel.idx, sel.va, &sel.name, &c)
                }
                Err(_) => VRow::failure(&sel.idx, sel.va, &sel.name, Outcome::ObjError, orig_n()),
            },
            (Some(_), None) => VRow::failure(&sel.idx, sel.va, &sel.name, Outcome::EmitFail, orig_n()),
        };
        canon_byte_w += row.orig_n as f64 * row.byte_sim;
        canon_n += row.orig_n;
        rows.push(row);
    }
    // 6. verdict gates, the record
    if !prog.report("gates", 3, 4) {
        return Err(Error::Cancelled);
    }
    reports.extend(verdict_gates(s, o, &rows, !full)?);
    let census = census_of(&rows);
    let wgss = wgss_of(&rows);
    let wgss_byte = if canon_n == 0 { 0.0 } else { canon_byte_w / canon_n as f64 };
    let mut pairs: Vec<(&str, &str, String)> = vec![
        ("format", "round", "1".into()),
        ("build", "id", build_id().to_string()),
        ("stage", Stage::Emit.name(), crate::fingerprint::hex(&crate::fingerprint::fp(Stage::Emit))),
        ("stage", Stage::Recompile.name(), crate::fingerprint::hex(&crate::fingerprint::fp(Stage::Recompile))),
        ("program", "key", pk.hex()),
        ("passes", "key", passes_k.hex()),
        ("emission", "key", ek.hex()),
        ("toolchain", "name", toolchain_name),
        ("toolchain", "id", toolchain_id),
        ("toolchain", "spec", toolchain_spec),
        ("arms", "", arms.clone()),
        ("options", "tag", eo.tag()),
        ("scope", &scope, o.get(keys::ROUND_SCOPE_FILE)?.to_string()),
        ("label", "", o.get("label")?.to_string()),
        ("created", "", crate::session::store::now_string()),
        ("units", "compiled", units.len().to_string()),
        ("units", "cached", hits.to_string()),
        ("units", "fresh", misses.to_string()),
        ("rows", "", rows.len().to_string()),
        ("sim", "", "structural".into()),
        ("wgss", "structural", format!("{wgss:.4}")),
        ("wgss", "byte", format!("{wgss_byte:.4}")),
    ];
    if let Some(st) = &foreign_stamp {
        pairs.push(("exclude-foreign", "", st.clone()));
    }
    for (verdict, n) in &census {
        pairs.push(("census", verdict, n.to_string()));
    }
    for r in &reports {
        let outcome = match &r.outcome {
            gates::Outcome::Ok => "OK".to_string(),
            gates::Outcome::Skip(_) => "SKIP".to_string(),
            gates::Outcome::Fail(h) => format!("FAIL ({})", h.len()),
        };
        pairs.push(("gate", r.gate, outcome));
    }
    let manifest = manifest_rows(&pairs);
    let mut set = TableSet::default();
    set.insert("verdicts", verdicts_table(&rows));
    set.insert("divergences", divergence_table_from_text(&div_text)?);
    set.insert("gates", gates_table(&reports));
    s.write_round(&name, &set, &manifest)?;
    Ok(manifest)
}

// ── round.compare / gates / list / show / export / import ──

fn round_rows(s: &Session, name: &str) -> Result<(TableSet, Vec<VRow>)> {
    let set = s.read_round(name)?;
    let rows = verdict_rows_of(set.table("verdicts")?)?;
    Ok((set, rows))
}

fn compare_op(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let (a, b) = (o.get("a")?, o.get("b")?);
    if a.is_empty() || b.is_empty() {
        return Err(Error::InvalidArg("`a` and `b` (two round names) are required".into()));
    }
    let (_, ra) = round_rows(s, a)?;
    let (_, rb) = round_rows(s, b)?;
    let mut t = TableBuilder::new(&COMPARE);
    for (which, rows) in [("a", &ra), ("b", &rb)] {
        for (verdict, n) in census_of(rows) {
            let count = n.to_string();
            let (ca, cb) = if which == "a" { (count.as_str(), "") } else { ("", count.as_str()) };
            t.row().str("census").u64(0).str(verdict).str(ca).str(cb).str(which);
        }
        let w = format!("{:.4}", wgss_of(rows));
        let (wa, wb) = if which == "a" { (w.as_str(), "") } else { ("", w.as_str()) };
        t.row().str("wgss").u64(0).str("").str(wa).str(wb).str(which);
    }
    let ma: BTreeMap<u64, &VRow> = ra.iter().map(|r| (r.va, r)).collect();
    let mb: BTreeMap<u64, &VRow> = rb.iter().map(|r| (r.va, r)).collect();
    let (mut flips, mut moved, mut up, mut down) = (0usize, 0usize, 0usize, 0usize);
    let (mut net, mut wnet, mut w) = (0f64, 0f64, 0u64);
    let (mut only_a, mut only_b) = (0usize, 0usize);
    // similarity moves are read at the series' precision — three decimals, what every verdict
    // table has ever printed, through the SAME formatting (its tie-breaking included: a rounding
    // of our own disagreed on 14 exact ties) — so an imported legacy round and a native one
    // compare cleanly (measured: full-precision comparison of identical rounds reported 1,495
    // "movers")
    let r3 = |x: f64| format!("{x:.3}").parse::<f64>().unwrap_or(x);
    for (va, rb_) in &mb {
        let Some(ra_) = ma.get(va) else {
            t.row().str("only-b").u64(*va).str(&rb_.name).str("").str(rb_.outcome.as_str()).str("");
            only_b += 1;
            continue;
        };
        if ra_.outcome != rb_.outcome {
            t.row().str("flip").u64(*va).str(&rb_.name).str(ra_.outcome.as_str()).str(rb_.outcome.as_str()).str(&format!("sim {:.3} -> {:.3}", ra_.sim, rb_.sim));
            flips += 1;
        }
        if (r3(ra_.sim) - r3(rb_.sim)).abs() > 1e-9 {
            let d = r3(rb_.sim) - r3(ra_.sim);
            net += d;
            wnet += d * rb_.orig_n as f64;
            moved += 1;
            if d > 0.0 { up += 1 } else { down += 1 }
            t.row().str("move").u64(*va).str(&rb_.name).str(&format!("{:.3}", ra_.sim)).str(&format!("{:.3}", rb_.sim)).str(&format!("{d:+.3} × {} insns", rb_.orig_n));
        }
        w += rb_.orig_n;
    }
    for (va, ra_) in &ma {
        if !mb.contains_key(va) {
            t.row().str("only-a").u64(*va).str(&ra_.name).str(ra_.outcome.as_str()).str("").str("");
            only_a += 1;
        }
    }
    t.row().str("summary").u64(0).str("flips").str(&flips.to_string()).str("").str("");
    t.row().str("summary").u64(0).str("moved").str(&moved.to_string()).str("").str(&format!("{up} up, {down} down, net {net:+.3} sim"));
    t.row().str("summary").u64(0).str("wgss-delta").str(&format!("{:+.5}", if w > 0 { wnet / w as f64 } else { 0.0 })).str("").str(&format!("weighted net {wnet:+.1} insn-sim over {w} instructions"));
    t.row().str("summary").u64(0).str("membership").str(&format!("{only_a} only in a")).str(&format!("{only_b} only in b")).str("");
    Ok(t.finish(false))
}

fn gates_op(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let name = o.get("round")?;
    if name.is_empty() {
        return Err(Error::InvalidArg("`round` is required".into()));
    }
    let (set, rows) = round_rows(s, name)?;
    let partial = set.table("manifest").ok().map(|m| (0..m.rows()).any(|r| m.str(r, 0).ok() == Some("scope") && m.str(r, 1).ok() == Some("list"))).unwrap_or(false);
    let reports = verdict_gates(s, o, &rows, partial)?;
    Ok(gates_table(&reports))
}

fn manifest_value(m: &Table, kind: &str, name: Option<&str>) -> String {
    (0..m.rows()).find(|&r| m.str(r, 0).ok() == Some(kind) && name.is_none_or(|n| m.str(r, 1).ok() == Some(n))).and_then(|r| m.str(r, 2).ok().map(str::to_string)).unwrap_or_default()
}

fn list_op(s: &mut Session, _o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let mut b = TableBuilder::new(&ROUNDS);
    for name in s.rounds()? {
        let (set, rows) = round_rows(s, &name)?;
        let m = set.table("manifest")?;
        let exact = rows.iter().filter(|r| r.outcome.as_str() == "EXACT").count() as u64;
        b.row().str(&name).str(&manifest_value(m, "program", Some("key"))).str(&manifest_value(m, "toolchain", Some("name"))).str(&manifest_value(m, "build", Some("id"))).str(&manifest_value(m, "created", None)).u64(rows.len() as u64).u64(exact).f64(wgss_of(&rows));
    }
    Ok(b.finish(false))
}

fn show_op(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let name = o.get("round")?;
    if name.is_empty() {
        return Err(Error::InvalidArg("`round` is required".into()));
    }
    let set = s.read_round(name)?;
    let table = match o.get("table")? {
        "" => "manifest",
        t => t,
    };
    set.table(table).cloned()
}

fn export_op(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let name = o.get("round")?;
    if name.is_empty() {
        return Err(Error::InvalidArg("`round` is required".into()));
    }
    let (set, rows) = round_rows(s, name)?;
    let mut written = Vec::new();
    let out = o.get("out")?;
    if !out.is_empty() {
        let m = set.table("manifest")?;
        let foreign = manifest_value(m, "exclude-foreign", None);
        let mut text = LEGACY_VERDICT_HEADER.to_string();
        if !foreign.is_empty() {
            text.push_str(&format!("\tEXCLUDE-FOREIGN={foreign}"));
        }
        text.push('\n');
        for r in &rows {
            text.push_str(&r.legacy_line());
            text.push('\n');
        }
        std::fs::write(out, text).map_err(|e| Error::io(e, PathBuf::from(out)))?;
        written.push(out.to_string());
    }
    let div = o.get("divergences")?;
    if !div.is_empty() {
        std::fs::write(div, divergence_text_of(set.table("divergences")?)?).map_err(|e| Error::io(e, PathBuf::from(div)))?;
        written.push(div.to_string());
    }
    if written.is_empty() {
        return Err(Error::InvalidArg("give `out` (the verdict TSV) and/or `divergences` (the divergence TSV) to write".into()));
    }
    let mut b = TableBuilder::new(&FILES);
    for w in &written {
        b.row().str(w);
    }
    Ok(b.finish(false))
}

/// Parse a legacy verdict TSV (the `recompile_check --out` contract) into rows and its stamps.
pub fn parse_legacy_verdicts(text: &str) -> Result<(Vec<VRow>, Vec<String>)> {
    let mut lines = text.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty());
    let header: Vec<&str> = lines.next().ok_or_else(|| Error::Format("empty verdict table".into()))?.split('\t').collect();
    let col = |n: &str| header.iter().position(|h| *h == n).ok_or_else(|| Error::Format(format!("verdict table has no `{n}` column")));
    let (ci, cv, cn, cverd, cb, cp, cs, ce, co, cc, ccl) = (col("idx")?, col("va")?, col("name")?, col("verdict")?, col("bytes")?, col("primary")?, col("sim")?, col("equal")?, col("orig_n")?, col("cand_n")?, col("classes")?);
    let stamps: Vec<String> = header.iter().skip(11).map(|s| s.to_string()).collect();
    let mut rows = Vec::new();
    for (n, line) in lines.enumerate() {
        let f: Vec<&str> = line.split('\t').collect();
        let get = |i: usize| f.get(i).copied().unwrap_or("").trim();
        let va = u64::from_str_radix(get(cv).trim_start_matches("0x"), 16).map_err(|_| Error::Format(format!("row {}: bad va `{}`", n + 2, get(cv))))?;
        let outcome = Outcome::parse(get(cverd)).ok_or_else(|| Error::Format(format!("row {}: unknown verdict `{}`", n + 2, get(cverd))))?;
        rows.push(VRow { idx: get(ci).to_string(), va, name: get(cn).to_string(), outcome, bytes: get(cb).to_string(), primary: get(cp).to_string(), sim: get(cs).parse().unwrap_or(0.0), byte_sim: 0.0, equal: get(ce).parse().unwrap_or(0), orig_n: get(co).parse().unwrap_or(0), cand_n: get(cc).parse().unwrap_or(0), classes: get(ccl).to_string() });
    }
    Ok((rows, stamps))
}

fn import_op(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let name = o.get("round")?.to_string();
    let verdicts = o.get("verdicts")?;
    if name.is_empty() || verdicts.is_empty() {
        return Err(Error::InvalidArg("`round` (a name) and `verdicts` (the legacy TSV) are required".into()));
    }
    let text = std::fs::read_to_string(verdicts).map_err(|e| Error::io(e, PathBuf::from(verdicts)))?;
    let (rows, stamps) = parse_legacy_verdicts(&text)?;
    let div = o.get("divergences")?;
    let divergences = if div.is_empty() { divergence_table_from_text(DIVERGENCE_HEADER)? } else { divergence_table_from_text(&std::fs::read_to_string(div).map_err(|e| Error::io(e, PathBuf::from(div)))?)? };
    let manifest_path = o.get("manifest")?;
    let arms = if manifest_path.is_empty() {
        String::new()
    } else {
        std::fs::read_to_string(manifest_path).map_err(|e| Error::io(e, PathBuf::from(manifest_path)))?.lines().find_map(|l| l.strip_prefix("# arms: ").map(str::to_string)).unwrap_or_default()
    };
    let census = census_of(&rows);
    let mut pairs: Vec<(&str, &str, String)> = vec![
        ("format", "round", "1".into()),
        ("build", "id", build_id().to_string()),
        ("imported", "verdicts", verdicts.to_string()),
        ("imported", "divergences", div.to_string()),
        ("imported", "manifest", manifest_path.to_string()),
        ("arms", "", arms),
        ("label", "", o.get("label")?.to_string()),
        ("created", "", crate::session::store::now_string()),
        ("rows", "", rows.len().to_string()),
        ("sim", "", if stamps.iter().any(|s| s == "SIM=structural") { "structural".into() } else { "byte-strict".into() }),
        ("wgss", "structural", format!("{:.4}", wgss_of(&rows))),
    ];
    if let Some(st) = stamps.iter().find_map(|s| s.strip_prefix("EXCLUDE-FOREIGN=")) {
        pairs.push(("exclude-foreign", "", st.to_string()));
    }
    for (verdict, n) in &census {
        pairs.push(("census", verdict, n.to_string()));
    }
    let manifest = manifest_rows(&pairs);
    let mut set = TableSet::default();
    set.insert("verdicts", verdicts_table(&rows));
    set.insert("divergences", divergences);
    set.insert("gates", gates_table(&[]));
    s.write_round(&name, &set, &manifest)?;
    Ok(manifest)
}
