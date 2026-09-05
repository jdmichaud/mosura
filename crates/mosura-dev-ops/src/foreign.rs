//! The foreign-module proposer (`docs/foreign-scope-plan.md`, Phase 1) over the current program.
//! Read-only: it changes no measurement, and it NEVER decides foreign-vs-game itself (a `foo.c`
//! band may be the game's own module) — it proposes, the human confirms (`dev.confirm`: a file of
//! `foreign <pattern> <label>` / `reject <pattern> <label>` lines naming STRINGS, not addresses).
//! (Was `examples/foreign_propose.rs`.)
//!
//! - `dev.foreign.facts` — the raw per-function facts (VA, size, prologue, call-graph degrees,
//!   anchor), so the plan's §3 evidence is reproducible from a kept tool.
//! - `dev.foreign.propose` — the locality-clustered anchor bands to confirm or reject, ranked by
//!   seed count; the classification preview under the given confirmation is in the report.
//! - `dev.foreign.report` — the band report as text: the human-facing audit of a classification
//!   (invariant §4.3.5: every excluded function records its evidence chain), per band the span
//!   accounting and a deterministic spot-check sample, the HELD set on its own (never folded into
//!   a band), the denominator table. With `round` (a session round) each section carries its
//!   corpus weight: rows, instruction weight, EXACT count and WGSS (Σ orig_n·sim / Σ orig_n).
//!   `dev.memo-cut` prints one extra row: the score under a hand-drawn address cut, labelled as
//!   unearned — it must never become a constant in the engine (§4.2).

use std::collections::HashMap;
use std::fmt::Write;
use std::path::Path;

use mosura_api::ops::program::program_of;
use mosura_api::ops::{Cache, Op, Progress, Tier};
use mosura_api::render::text_table;
use mosura_api::{Error, Options, Result, Session, Table, TableBuilder};
use mosura_core::analysis::foreign::{self, Classification, Confirmation, Facts};

use crate::keys;
use crate::schemas::{FOREIGN_BANDS, FOREIGN_FACTS};

pub static FACTS: Op = Op { name: "dev.foreign.facts", doc: "the foreign-scope engine's raw per-function facts of the current program: size, extent, FID/loader-named, call-graph degrees, foreign fingerprint, prologue, anchor string", since: "0.1", tier: Tier::Dev, params: &["program"], result: "foreign_facts", cache: Cache::Transient, run: facts };
pub static PROPOSE: Op = Op { name: "dev.foreign.propose", doc: "propose locality-clustered anchor bands of the current program for a human to confirm as foreign or reject as the program's own (ranked by seed count); never decides itself", since: "0.1", tier: Tier::Dev, params: &["program"], result: "foreign_bands", cache: Cache::Transient, run: propose };
pub static REPORT: Op = Op { name: "dev.foreign.report", doc: "the foreign-scope band report (text): per band the status under dev.confirm, span accounting and a deterministic spot-check; the HELD set; the denominator table — with `round` joined to that round's verdicts for rows/weight/EXACT/WGSS; dev.memo-cut adds the unearned hand-drawn cut row", since: "0.1", tier: Tier::Dev, params: &["program", keys::DEV_CONFIRM, "round", keys::DEV_MEMO_CUT], result: "text", cache: Cache::Transient, run: report };

fn confirmation(o: &Options) -> Result<(Confirmation, Option<String>)> {
    let path = o.get(keys::DEV_CONFIRM)?;
    if path.is_empty() {
        return Ok((Confirmation::default(), None));
    }
    let c = Confirmation::load(Path::new(path)).map_err(|e| Error::io(e, Path::new(path).to_path_buf()))?;
    Ok((c, Some(path.to_string())))
}

fn facts(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let (_, program) = program_of(s, o)?;
    let facts = foreign::extract_facts(&program);
    let mut t = TableBuilder::new(&FOREIGN_FACTS);
    for f in &facts.fns {
        t.row().u64(f.va).u64(f.size).u64(f.lo).u64(f.hi).bool(f.identified).u64(f.callers.len() as u64).u64(f.callees.len() as u64).bool(f.foreign_fp).str(&crate::hex_bytes(&f.prologue)).str(f.anchor.as_ref().map(|a| a.text.as_str()).unwrap_or(""));
    }
    Ok(t.finish(false))
}

fn propose(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let (_, program) = program_of(s, o)?;
    let facts = foreign::extract_facts(&program);
    let bands = foreign::propose_bands(&facts, foreign::BAND_GAP);
    let mut t = TableBuilder::new(&FOREIGN_BANDS);
    for b in &bands {
        t.row().str(&b.label).str(&format!("{:?}", b.class)).u64(b.seeds.len() as u64).u64(b.span_fns as u64).f64(f64::from(b.fp_agreement) * 100.0).u64(b.fid_in_span as u64).u64(b.lo).u64(b.hi).str(&b.example);
    }
    Ok(t.finish(false))
}

/// One measured row of a round's verdict table. Rows the harness could not measure (no sim) keep
/// sim 0 so their instruction weight still counts against the denominator, as the census does.
struct Row {
    va: u64,
    verdict: String,
    sim: f64,
    orig_n: u64,
}

fn round_rows(s: &Session, name: &str) -> Result<Vec<Row>> {
    let set = s.read_round(name)?;
    let v = set.table("verdicts")?;
    let (c_va, c_verdict, c_sim, c_n) = (v.col("va").unwrap(), v.col("verdict").unwrap(), v.col("sim").unwrap(), v.col("orig_n").unwrap());
    let mut rows = Vec::with_capacity(v.rows() as usize);
    for r in 0..v.rows() {
        rows.push(Row { va: v.u64(r, c_va)?, verdict: v.str(r, c_verdict)?.to_string(), sim: v.f64(r, c_sim).unwrap_or(0.0), orig_n: v.u64(r, c_n).unwrap_or(0) });
    }
    Ok(rows)
}

/// Corpus accounting for a set of functions: measured rows, their instruction weight, how many are
/// byte-exact, and the WGSS over just those rows — Σ orig_n·sim / Σ orig_n, the canonical formula.
#[derive(Default, Clone, Copy)]
struct Acc {
    rows: usize,
    weight: u64,
    exact: usize,
    sim_weight: f64,
}

impl Acc {
    fn add(&mut self, r: &Row) {
        self.rows += 1;
        self.weight += r.orig_n;
        self.exact += usize::from(r.verdict == "EXACT");
        self.sim_weight += r.orig_n as f64 * r.sim;
    }
    fn wgss(&self) -> f64 {
        if self.weight == 0 { 0.0 } else { self.sim_weight / self.weight as f64 }
    }
    /// A section with no measured rows says so rather than printing a `WGSS 0.0000` that reads as a
    /// terrible score: the FID/loader set is `kind = library` and never measured, by construction.
    fn cells(&self) -> String {
        if self.rows == 0 {
            return "rows     0  (none measured — not in the round's rows)".to_string();
        }
        format!("rows {:>5}  weight {:>7}  EXACT {:>4}  WGSS {:.4}", self.rows, self.weight, self.exact, self.wgss())
    }
}

fn conf_desc(conf: &Confirmation, conf_path: Option<&str>) -> String {
    if conf.foreign.is_empty() && conf.reject.is_empty() {
        return "none (empty = FID/loader only, default-safe)".to_string();
    }
    format!("{} ({} foreign, {} reject)", conf_path.unwrap_or("(unnamed)"), conf.foreign.len(), conf.reject.len())
}

/// The deterministic spot-check for one section: the 2 highest-key functions, the 1–2 central ones
/// of the key-ascending order, the 2 lowest-addressed HELD ones; ties by ascending VA; shown once.
fn samples(out: &mut String, set: &[u64], held: &HashMap<u64, &String>, cls: &Classification, facts: &Facts, by_va: &HashMap<u64, &Row>, weight_of: impl Fn(u64) -> u64) {
    if set.is_empty() {
        return;
    }
    let mut asc: Vec<u64> = set.to_vec();
    asc.sort_by_key(|va| (weight_of(*va), *va));
    let mut desc: Vec<u64> = set.to_vec();
    desc.sort_by_key(|va| (std::cmp::Reverse(weight_of(*va)), *va));
    let mut picks: Vec<u64> = desc.into_iter().take(2).collect();
    for i in [asc.len() / 2, (asc.len() - 1) / 2] {
        picks.push(asc[i]);
    }
    let mut held_here: Vec<u64> = set.iter().copied().filter(|va| held.contains_key(va)).collect();
    held_here.sort_unstable();
    picks.extend(held_here.into_iter().take(2));
    let _ = writeln!(out, "   spot-check:");
    let mut shown: Vec<u64> = Vec::new();
    for va in picks {
        if shown.contains(&va) {
            continue;
        }
        shown.push(va);
        let f = facts.get(va);
        let evidence = cls.reason.get(&va).map(|s| s.as_str()).unwrap_or("in-scope (no foreign evidence)");
        let flag = if held.contains_key(&va) { "HELD " } else { "" };
        let corpus = by_va.get(&va).map(|r| format!("{:<12} sim {:.3}  n={:<4}", r.verdict, r.sim, r.orig_n)).unwrap_or_else(|| format!("{:<12} (not a measured row)", "-"));
        let anchor = f.and_then(|f| f.anchor.as_ref()).map(|a| format!("  {:?}", a.text.chars().take(46).collect::<String>())).unwrap_or_default();
        let _ = writeln!(out, "     {va:#08x}  {corpus}  {flag}{evidence}{anchor}");
    }
}

fn report(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let (pk, program) = program_of(s, o)?;
    let (conf, conf_path) = confirmation(o)?;
    let round = o.get("round")?;
    let rows: Vec<Row> = if round.is_empty() { Vec::new() } else { round_rows(s, round)? };
    let memo_cut = {
        let v = o.get(keys::DEV_MEMO_CUT)?;
        if v.is_empty() { None } else { Some(u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).map_err(|_| Error::InvalidArg(format!("`{}`: `{v}` is not hex", keys::DEV_MEMO_CUT)))?) }
    };
    let facts = foreign::extract_facts(&program);
    let cls = foreign::classify(&facts, &conf);
    let bands = foreign::propose_bands(&facts, foreign::BAND_GAP);
    let by_va: HashMap<u64, &Row> = rows.iter().map(|r| (r.va, r)).collect();
    let held: HashMap<u64, &String> = cls.held.iter().map(|(va, why)| (*va, why)).collect();
    // the sampling key: the measured instruction weight when a round is joined (what the denominator
    // counts), else the function's byte size — both properties of the binary, so the same command
    // always samples the same rows
    let weight_of = |va: u64| -> u64 { by_va.get(&va).map(|r| r.orig_n).unwrap_or_else(|| facts.get(va).map(|f| f.size).unwrap_or(0)) };
    let key_name = if rows.is_empty() { "function size in bytes" } else { "orig_n (measured instructions)" };
    let mut out = String::new();
    let _ = writeln!(out, "== FOREIGN-SCOPE BAND REPORT — program {}", pk.hex());
    let _ = writeln!(out, "   {} functions | {} FID/loader-named | {} anchored | confirmation: {}", facts.fns.len(), facts.fns.iter().filter(|f| f.identified).count(), facts.fns.iter().filter(|f| f.anchor.is_some()).count(), conf_desc(&conf, conf_path.as_deref()));
    if round.is_empty() {
        let _ = writeln!(out, "   corpus join: none (structural counts only — pass round=<name> for weights)");
    } else {
        let _ = writeln!(out, "   corpus join: round {round} ({} measured rows)", rows.len());
    }
    for w in &cls.warnings {
        let _ = writeln!(out, "   ! warning: {w}");
    }
    let _ = writeln!(out, "\n-- SAMPLING RULE (deterministic — re-running this command reprints these rows)");
    let _ = writeln!(out, "   Key = {key_name}. Within a section: the 2 highest-key functions, then the 1-2");
    let _ = writeln!(out, "   central functions of the key-ascending order (the median pair), then the 2");
    let _ = writeln!(out, "   lowest-addressed HELD functions of that section. Ties break by ascending VA;");
    let _ = writeln!(out, "   duplicates are shown once. Every sampled line prints the engine's own evidence.");
    for b in &bands {
        let members: Vec<u64> = facts.fns.iter().map(|f| f.va).filter(|va| *va >= b.lo && *va <= b.hi).collect();
        let foreign_here: Vec<u64> = members.iter().copied().filter(|va| cls.is_foreign(*va)).collect();
        let confirmed = foreign_here.iter().any(|va| cls.reason.get(va).is_some_and(|r| r.starts_with("band:")));
        let label = foreign_here.iter().find_map(|va| cls.reason.get(va).and_then(|r| r.strip_prefix("band:"))).unwrap_or("");
        let held_here: Vec<u64> = members.iter().copied().filter(|va| held.contains_key(va)).collect();
        // the span's foreign members by the evidence the engine recorded: an unconfirmed band that
        // happens to hold FID-named functions cannot read as "nothing excluded here"
        let by_evidence = |pred: fn(&str) -> bool| -> usize { foreign_here.iter().filter(|va| cls.reason.get(*va).is_some_and(|r| pred(r))).count() };
        let n_band = by_evidence(|r| r.starts_with("band:"));
        let n_fid = by_evidence(|r| r.starts_with("fid:"));
        let n_reach = by_evidence(|r| r == "reachable-private");
        let _ = writeln!(out, "\n== BAND {:<24} {:#08x}..{:#08x}", b.label, b.lo, b.hi);
        if confirmed {
            let _ = writeln!(out, "   status: CONFIRMED FOREIGN — \"{label}\" (a human named the string; the engine derived this span)");
        } else if foreign_here.is_empty() {
            let _ = writeln!(out, "   status: PROPOSED ONLY — not foreign, nothing excluded (the human has not confirmed it)");
        } else {
            let _ = writeln!(out, "   status: PROPOSED ONLY — the human has not confirmed it, but {} function(s) in this span are foreign on OTHER evidence (fid {n_fid}, reachable-private {n_reach})", foreign_here.len());
        }
        let _ = writeln!(out, "   span {} fns | seeds {} | class {:?} | fFP {:.0}% | FID in span {} | held {}", b.span_fns, b.seeds.len(), b.class, b.fp_agreement * 100.0, b.fid_in_span, held_here.len());
        let _ = writeln!(out, "   foreign in span: {} (band {n_band} | fid {n_fid} | reachable-private {n_reach})", foreign_here.len());
        if !rows.is_empty() {
            let mut acc = Acc::default();
            for va in &members {
                if let Some(r) = by_va.get(va) {
                    acc.add(r);
                }
            }
            let _ = writeln!(out, "   corpus: {}", acc.cells());
        }
        samples(&mut out, &members, &held, &cls, &facts, &by_va, weight_of);
    }
    // foreign outside every band span, bucketed by the evidence the engine recorded; `other`
    // catches an evidence kind added later, under its own heading rather than misattributed
    let in_a_band = |va: u64| bands.iter().any(|b| va >= b.lo && va <= b.hi);
    let (mut fid_only, mut reach_priv, mut other): (Vec<u64>, Vec<u64>, Vec<u64>) = (Vec::new(), Vec::new(), Vec::new());
    for f in &facts.fns {
        if !cls.is_foreign(f.va) || in_a_band(f.va) {
            continue;
        }
        match cls.reason.get(&f.va).map(|s| s.as_str()) {
            Some("reachable-private") => reach_priv.push(f.va),
            Some(r) if r.starts_with("fid:") => fid_only.push(f.va),
            _ => other.push(f.va),
        }
    }
    for (title, set, note) in [
        ("FID / LOADER-NAMED, outside every band", &fid_only, "today's `library` exclusion — in the denominator's kind filter already"),
        ("REACHABLE-PRIVATE, outside every band", &reach_priv, "callers all foreign AND corroborated by fingerprint or span (§4.1.4)"),
        ("OTHER EVIDENCE, outside every band", &other, "an evidence kind this report does not know — read the per-function reason below"),
    ] {
        if set.is_empty() && title.starts_with("OTHER") {
            continue;
        }
        let _ = writeln!(out, "\n== {title}: {} fns", set.len());
        let _ = writeln!(out, "   evidence: {note}");
        if !rows.is_empty() {
            let mut acc = Acc::default();
            for va in set.iter() {
                if let Some(r) = by_va.get(va) {
                    acc.add(r);
                }
            }
            let _ = writeln!(out, "   corpus: {}", acc.cells());
        }
        samples(&mut out, set, &held, &cls, &facts, &by_va, weight_of);
    }
    let _ = writeln!(out, "\n== HELD (uncorroborated reachables — surfaced, NOT excluded): {} fns", cls.held.len());
    let _ = writeln!(out, "   These are IN the denominator today. They are reachable only from foreign code but");
    let _ = writeln!(out, "   lack fingerprint/span corroboration, so the CALLIND-incompleteness guard keeps them.");
    let _ = writeln!(out, "   §6(c) would let a human promote them per-band; that mechanism is not built.");
    if !rows.is_empty() {
        let mut acc = Acc::default();
        for (va, _) in &cls.held {
            if let Some(r) = by_va.get(va) {
                acc.add(r);
            }
        }
        let _ = writeln!(out, "   corpus: {}", acc.cells());
    }
    let mut held_sorted: Vec<&(u64, String)> = cls.held.iter().collect();
    held_sorted.sort_by_key(|(va, _)| *va);
    for (va, why) in held_sorted.iter().take(40) {
        let w = by_va.get(va).map(|r| format!("sim {:.3}  n={:<4}", r.sim, r.orig_n)).unwrap_or_default();
        let _ = writeln!(out, "     {va:#08x}  {w}{why}");
    }
    if held_sorted.len() > 40 {
        let _ = writeln!(out, "     ... and {} more", held_sorted.len() - 40);
    }
    let _ = writeln!(out, "\n== DENOMINATOR TABLE");
    let n = facts.fns.len();
    let foreign_n = cls.foreign_count();
    let _ = writeln!(out, "   functions: {n} total | {foreign_n} classified foreign | {} in scope", n - foreign_n);
    if rows.is_empty() {
        let _ = writeln!(out, "   (no round join: pass round=<name> to score these denominators)");
        return Ok(text_table(&out));
    }
    let (mut full, mut excl, mut promoted) = (Acc::default(), Acc::default(), Acc::default());
    for r in &rows {
        full.add(r);
        if !cls.is_foreign(r.va) {
            excl.add(r);
            if !held.contains_key(&r.va) {
                promoted.add(r);
            }
        }
    }
    let _ = writeln!(out, "   {:<44} {}", "full (canonical, excludes nothing)", full.cells());
    let _ = writeln!(out, "   {:<44} {}", "evidence-excluded (this classification)", excl.cells());
    let _ = writeln!(out, "   {:<44} {}", "  + held promoted (§6c, NOT built)", promoted.cells());
    if let Some(cut) = memo_cut {
        let mut memo = Acc::default();
        for r in &rows {
            if r.va < cut {
                memo.add(r);
            }
        }
        let _ = writeln!(out, "\n   MEMO — hand-drawn cut va < {cut:#08x}, supplied on the command line:");
        let _ = writeln!(out, "   {:<44} {}", "  (NOT evidence — this is the line to earn)", memo.cells());
        let mut u = Acc::default();
        for r in rows.iter().filter(|r| r.va >= cut && !cls.is_foreign(r.va)) {
            u.add(r);
        }
        let _ = writeln!(out, "   {:<44} {}", "  gap: removed by the address, not by evidence", u.cells());
    }
    Ok(text_table(&out))
}
