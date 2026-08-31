//! Foreign-module proposer (`docs/foreign-scope-plan.md`, Phase 1). Reads a binary, proposes
//! locality-clustered anchor **bands** for a human to confirm as foreign or in-scope, and — given a
//! confirmation file — previews the resulting denominator.
//!
//! Read-only: it changes no measurement. It NEVER decides foreign-vs-game itself (a `foo.c` band
//! may be the game's own module); it proposes, the human confirms.
//!
//! ```text
//! cargo run --release --example foreign_propose -- <binary> [--native] [--confirm <file>] [--facts]
//! cargo run --release --example foreign_propose -- <binary> --report [--confirm <file>]
//!                                                  [--rec <rec.tsv>] [--memo-cut <va>]
//! ```
//! `--facts` dumps the raw per-function facts as TSV (VA, size, prologue, call-graph degrees,
//! anchor) so the `docs/foreign-scope-plan.md` §3 evidence is reproducible from a kept tool.
//!
//! `--report` is the **band report** — the human-facing audit of a classification, so that
//! invariant §4.3.5 ("every excluded function records its evidence chain … so any exclusion can be
//! challenged") is actually readable. It prints, per band, the span accounting and a deterministic
//! spot-check sample; then the *held* set on its own line (never folded into a band, so the
//! uncorroborated reachables stay visible); then the denominator table. With `--rec <rec.tsv>` (a
//! `recompile_check --out` TSV) each section also carries its corpus weight: rows, instruction
//! weight, EXACT count and WGSS (Σ orig_n·sim / Σ orig_n, the canonical formula — *not*
//! `recompile_check`'s "insn-weighted" line).
//!
//! `--memo-cut <va>` prints one extra denominator row: the score under a hand-drawn address cut.
//! That address is **data supplied on the command line and labelled as unearned** — the report
//! exists to show what evidence would have to cover before such a line could be quoted as a
//! denominator, so it must never become a constant in the engine or in this tool (§4.2:
//! "Addresses are never hand-authored").
use mosura::analysis::{self, foreign};

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let mut args = std::env::args().skip(1);
    let mut path = None;
    let mut native = false;
    let mut confirm: Option<String> = None;
    let mut facts_dump = false;
    let mut report = false;
    let mut rec: Option<String> = None;
    let mut memo_cut: Option<u64> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--native" => native = true,
            "--confirm" => confirm = args.next(),
            "--facts" => facts_dump = true,
            "--report" => report = true,
            "--rec" => rec = args.next(),
            "--memo-cut" => {
                let v = args.next().expect("--memo-cut <va>");
                let t = v.trim_start_matches("0x");
                memo_cut = Some(u64::from_str_radix(t, 16).expect("--memo-cut: hex address"));
            }
            _ => path = Some(a),
        }
    }
    let path = path.expect("usage: foreign_propose <binary> [--native] [--confirm <file>] [--facts]");
    let p = std::path::Path::new(&path);
    let prog = if native {
        analysis::analyze_native_file(p).expect("analyze_native_file")
    } else {
        analysis::analyze_le_file(p).expect("analyze_le_file")
    };

    let facts = foreign::extract_facts(&prog);
    if facts_dump {
        // FN <va> <size> <lo> <hi> <fid 0/1> <ncallers> <ncallees> <foreign_fp 0/1> <prologue_hex> <anchor|->
        println!("va\tsize\tlo\thi\tfid\tncallers\tncallees\tffp\tprologue\tanchor");
        for f in &facts.fns {
            let anchor = f.anchor.as_ref().map(|a| a.text.as_str()).unwrap_or("-");
            let prologue: String = f.prologue.iter().map(|b| format!("{b:02x}")).collect();
            println!(
                "{:x}\t{}\t{:x}\t{:x}\t{}\t{}\t{}\t{}\t{}\t{}",
                f.va, f.size, f.lo, f.hi, f.identified as u8, f.callers.len(), f.callees.len(),
                f.foreign_fp as u8, prologue, anchor
            );
        }
        return;
    }
    if report {
        let conf = match &confirm {
            Some(f) => foreign::Confirmation::load(std::path::Path::new(f)).expect("read confirm file"),
            None => foreign::Confirmation::default(),
        };
        band_report(&argv, &path, &facts, &conf, confirm.as_deref(), rec.as_deref(), memo_cut);
        return;
    }

    let n = facts.fns.len();
    let fid = facts.fns.iter().filter(|f| f.identified).count();
    let anchored = facts.fns.iter().filter(|f| f.anchor.is_some()).count();
    println!("== {path}");
    println!("   {n} functions   {fid} FID/loader-named   {anchored} anchored");

    // Phase 1: propose bands at the engine's default locality gap.
    let bands = foreign::propose_bands(&facts, foreign::BAND_GAP);
    println!("\n-- proposed module bands (confirm foreign? or reject as game's own):");
    println!(
        "   {:<22} {:<11} {:>5} {:>5} {:>5}  {:<20} example",
        "label", "class", "seeds", "span", "fFP%", "va-range"
    );
    for b in &bands {
        println!(
            "   {:<22} {:<11} {:>5} {:>5} {:>4.0}%  {:<20} {:?}",
            b.label,
            format!("{:?}", b.class),
            b.seeds.len(),
            b.span_fns,
            b.fp_agreement * 100.0,
            format!("{:#08x}..{:#08x}", b.lo, b.hi),
            b.example,
        );
    }

    // Phase 3 preview: classify with the given (or empty) confirmation.
    let conf = match &confirm {
        Some(f) => foreign::Confirmation::load(std::path::Path::new(f)).expect("read confirm file"),
        None => foreign::Confirmation::default(),
    };
    let cls = foreign::classify(&facts, &conf);
    let foreign = cls.foreign_count();
    let denom = n - foreign;
    println!(
        "\n-- classification ({}):",
        confirm.as_deref().unwrap_or("empty confirmation = FID/loader only, default-safe")
    );
    println!("   foreign (excluded): {foreign}   in-scope denominator: {denom}   held (surfaced, not dropped): {}", cls.held.len());
    for w in &cls.warnings {
        println!("   ! warning: {w}");
    }
    if !cls.held.is_empty() {
        let show = cls.held.len().min(8);
        println!("   held examples:");
        for (va, why) in cls.held.iter().take(show) {
            println!("     {va:#08x}  {why}");
        }
        if cls.held.len() > show {
            println!("     ... and {} more", cls.held.len() - show);
        }
    }
}

/// One row of a `recompile_check --out` TSV — the corpus measurement the report joins against.
/// Column contract (1-indexed, as `scripts/war2-verdicts.sh` states it): 2 va, 4 verdict, 7 sim,
/// 9 orig_n. Rows the harness could not measure (no sim) are kept with sim 0 so their instruction
/// weight still counts against the denominator, exactly as the census does.
struct Row {
    va: u64,
    verdict: String,
    sim: f64,
    orig_n: u64,
}

fn load_rec(path: &str) -> Vec<Row> {
    let text = std::fs::read_to_string(path).expect("read --rec TSV");
    let mut rows = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 9 || f[0] == "idx" || line.starts_with('#') {
            continue;
        }
        let Ok(va) = u64::from_str_radix(f[1].trim(), 16) else { continue };
        rows.push(Row {
            va,
            verdict: f[3].to_string(),
            sim: f[6].trim().parse().unwrap_or(0.0),
            orig_n: f[8].trim().parse().unwrap_or(0),
        });
    }
    rows
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
        self.exact += (r.verdict == "EXACT") as usize;
        self.sim_weight += r.orig_n as f64 * r.sim;
    }
    fn wgss(&self) -> f64 {
        if self.weight == 0 { 0.0 } else { self.sim_weight / self.weight as f64 }
    }
    /// One accounting line. A section with no measured rows prints so explicitly rather than a
    /// `WGSS 0.0000` that reads as a terrible score: the FID/loader set is `kind = library` and was
    /// filtered out of the corpus TSV before this join, so it has no rows *by construction*.
    fn cells(&self) -> String {
        if self.rows == 0 {
            return "rows     0  (none measured — filtered from the corpus TSV before this join)".to_string();
        }
        format!(
            "rows {:>5}  weight {:>7}  EXACT {:>4}  WGSS {:.4}",
            self.rows, self.weight, self.exact, self.wgss()
        )
    }
}

/// The band report: a per-band audit of a classification, its held set, and the denominator table.
///
/// It decides nothing. Every band's foreign/proposed status comes from the engine's own evidence
/// chain (`Classification::reason`), so what the report shows is exactly what the classifier would
/// exclude — the point being that a reader can challenge any single exclusion (§4.3.5).
fn band_report(
    argv: &[String],
    path: &str,
    facts: &foreign::Facts,
    conf: &foreign::Confirmation,
    conf_path: Option<&str>,
    rec: Option<&str>,
    memo_cut: Option<u64>,
) {
    let cls = foreign::classify(facts, conf);
    let bands = foreign::propose_bands(facts, foreign::BAND_GAP);
    let rows = rec.map(load_rec).unwrap_or_default();
    let by_va: std::collections::HashMap<u64, &Row> = rows.iter().map(|r| (r.va, r)).collect();
    let held: std::collections::HashMap<u64, &String> =
        cls.held.iter().map(|(va, why)| (*va, why)).collect();

    // The sampling key: the measured instruction weight when a corpus TSV is joined (what the
    // denominator actually counts), else the function's byte size. Both are properties of the
    // binary, so the same command always samples the same rows.
    let weight_of = |va: u64| -> u64 {
        by_va.get(&va).map(|r| r.orig_n).unwrap_or_else(|| facts.get(va).map(|f| f.size).unwrap_or(0))
    };
    let key_name = if rec.is_some() { "orig_n (measured instructions)" } else { "function size in bytes" };

    println!("== FOREIGN-SCOPE BAND REPORT — {path}");
    println!("   command: {}", argv.join(" "));
    println!(
        "   {} functions | {} FID/loader-named | {} anchored | confirmation: {}",
        facts.fns.len(),
        facts.fns.iter().filter(|f| f.identified).count(),
        facts.fns.iter().filter(|f| f.anchor.is_some()).count(),
        conf_desc(conf, conf_path),
    );
    match rec {
        Some(p) => println!("   corpus join: {p} ({} measured rows)", rows.len()),
        None => println!("   corpus join: none (structural counts only — pass --rec <rec.tsv> for weights)"),
    }
    for w in &cls.warnings {
        println!("   ! warning: {w}");
    }

    println!("\n-- SAMPLING RULE (deterministic — re-running this command reprints these rows)");
    println!("   Key = {key_name}. Within a section: the 2 highest-key functions, then the 1-2");
    println!("   central functions of the key-ascending order (the median pair), then the 2");
    println!("   lowest-addressed HELD functions of that section. Ties break by ascending VA;");
    println!("   duplicates are shown once. Every sampled line prints the engine's own evidence.");

    // --- per band ---------------------------------------------------------------------------
    for b in &bands {
        let members: Vec<u64> =
            facts.fns.iter().map(|f| f.va).filter(|va| *va >= b.lo && *va <= b.hi).collect();
        let foreign_here: Vec<u64> = members.iter().copied().filter(|va| cls.is_foreign(*va)).collect();
        let confirmed = foreign_here
            .iter()
            .any(|va| cls.reason.get(va).is_some_and(|r| r.starts_with("band:")));
        let label = foreign_here
            .iter()
            .find_map(|va| cls.reason.get(va).and_then(|r| r.strip_prefix("band:")))
            .unwrap_or("");
        let held_here: Vec<u64> = members.iter().copied().filter(|va| held.contains_key(va)).collect();

        // Break the span's foreign members down by the evidence the engine actually recorded, so
        // an unconfirmed band that happens to contain FID-named functions cannot read as "nothing
        // excluded here" — those functions are foreign on their own evidence, not on this band's.
        let by_evidence = |pred: fn(&str) -> bool| -> usize {
            foreign_here.iter().filter(|va| cls.reason.get(*va).is_some_and(|r| pred(r))).count()
        };
        let n_band = by_evidence(|r| r.starts_with("band:"));
        let n_fid = by_evidence(|r| r.starts_with("fid:"));
        let n_reach = by_evidence(|r| r == "reachable-private");

        println!("\n== BAND {:<24} {:#08x}..{:#08x}", b.label, b.lo, b.hi);
        if confirmed {
            println!("   status: CONFIRMED FOREIGN — \"{label}\" (a human named the string; the engine derived this span)");
        } else if foreign_here.is_empty() {
            println!("   status: PROPOSED ONLY — not foreign, nothing excluded (the human has not confirmed it)");
        } else {
            println!(
                "   status: PROPOSED ONLY — the human has not confirmed it, but {} function(s) in \
                 this span are foreign on OTHER evidence (fid {n_fid}, reachable-private {n_reach})",
                foreign_here.len()
            );
        }
        println!(
            "   span {} fns | seeds {} | class {:?} | fFP {:.0}% | FID in span {} | held {}",
            b.span_fns,
            b.seeds.len(),
            b.class,
            b.fp_agreement * 100.0,
            b.fid_in_span,
            held_here.len(),
        );
        println!(
            "   foreign in span: {} (band {n_band} | fid {n_fid} | reachable-private {n_reach})",
            foreign_here.len()
        );
        if !rows.is_empty() {
            let mut acc = Acc::default();
            for va in &members {
                if let Some(r) = by_va.get(va) {
                    acc.add(r);
                }
            }
            println!("   corpus: {}", acc.cells());
        }
        print_samples(&members, &held, &cls, facts, &by_va, weight_of);
    }

    // --- foreign outside every band span ----------------------------------------------------
    let in_a_band = |va: u64| bands.iter().any(|b| va >= b.lo && va <= b.hi);
    // Bucket by the evidence string the engine recorded. `other` catches any evidence kind added
    // to the engine later: an unrecognised reason must show up under its own heading rather than
    // be filed silently under one of these two, or the report would misattribute an exclusion —
    // the one thing an audit of exclusions must not do.
    let mut fid_only: Vec<u64> = Vec::new();
    let mut reach_priv: Vec<u64> = Vec::new();
    let mut other: Vec<u64> = Vec::new();
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
        println!("\n== {title}: {} fns", set.len());
        println!("   evidence: {note}");
        if !rows.is_empty() {
            let mut acc = Acc::default();
            for va in set.iter() {
                if let Some(r) = by_va.get(va) {
                    acc.add(r);
                }
            }
            println!("   corpus: {}", acc.cells());
        }
        print_samples(set, &held, &cls, facts, &by_va, weight_of);
    }

    // --- held: its own section, never folded into a band ------------------------------------
    println!("\n== HELD (uncorroborated reachables — surfaced, NOT excluded): {} fns", cls.held.len());
    println!("   These are IN the denominator today. They are reachable only from foreign code but");
    println!("   lack fingerprint/span corroboration, so the CALLIND-incompleteness guard keeps them.");
    println!("   §6(c) would let a human promote them per-band; that mechanism is not built.");
    if !rows.is_empty() {
        let mut acc = Acc::default();
        for (va, _) in &cls.held {
            if let Some(r) = by_va.get(va) {
                acc.add(r);
            }
        }
        println!("   corpus: {}", acc.cells());
    }
    let mut held_sorted: Vec<&(u64, String)> = cls.held.iter().collect();
    held_sorted.sort_by_key(|(va, _)| *va);
    for (va, why) in held_sorted.iter().take(40) {
        let w = by_va.get(va).map(|r| format!("sim {:.3}  n={:<4}", r.sim, r.orig_n)).unwrap_or_default();
        println!("     {va:#08x}  {w}{why}");
    }
    if held_sorted.len() > 40 {
        println!("     ... and {} more", held_sorted.len() - 40);
    }

    // --- denominator table ------------------------------------------------------------------
    println!("\n== DENOMINATOR TABLE");
    let n = facts.fns.len();
    let foreign_n = cls.foreign_count();
    println!("   functions: {n} total | {foreign_n} classified foreign | {} in scope", n - foreign_n);
    if rows.is_empty() {
        println!("   (no --rec join: pass a recompile_check TSV to score these denominators)");
        return;
    }
    let mut full = Acc::default();
    let mut excl = Acc::default();
    let mut promoted = Acc::default();
    for r in &rows {
        full.add(r);
        if !cls.is_foreign(r.va) {
            excl.add(r);
            if !held.contains_key(&r.va) {
                promoted.add(r);
            }
        }
    }
    println!("   {:<44} {}", "full (canonical, excludes nothing)", full.cells());
    println!("   {:<44} {}", "evidence-excluded (this classification)", excl.cells());
    println!("   {:<44} {}", "  + held promoted (§6c, NOT built)", promoted.cells());
    if let Some(cut) = memo_cut {
        let mut memo = Acc::default();
        for r in &rows {
            if r.va < cut {
                memo.add(r);
            }
        }
        println!("\n   MEMO — hand-drawn cut va < {cut:#08x}, supplied on the command line:");
        println!("   {:<44} {}", "  (NOT evidence — this is the line to earn)", memo.cells());
        let unearned: Vec<&Row> =
            rows.iter().filter(|r| r.va >= cut && !cls.is_foreign(r.va)).collect();
        let mut u = Acc::default();
        for r in &unearned {
            u.add(r);
        }
        println!(
            "   {:<44} {}",
            "  gap: removed by the address, not by evidence", u.cells()
        );
    }
}

/// The confirmation file's identity, for the report header — so a reader knows which data produced
/// the classification (an empty confirmation is the default-safe FID/loader-only case).
fn conf_desc(conf: &foreign::Confirmation, conf_path: Option<&str>) -> String {
    if conf.foreign.is_empty() && conf.reject.is_empty() {
        return "none (empty = FID/loader only, default-safe)".to_string();
    }
    format!(
        "{} ({} foreign, {} reject)",
        conf_path.unwrap_or("(unnamed)"),
        conf.foreign.len(),
        conf.reject.len()
    )
}

/// Print the deterministic spot-check for one section (see the printed sampling rule).
fn print_samples(
    set: &[u64],
    held: &std::collections::HashMap<u64, &String>,
    cls: &foreign::Classification,
    facts: &foreign::Facts,
    by_va: &std::collections::HashMap<u64, &Row>,
    weight_of: impl Fn(u64) -> u64,
) {
    if set.is_empty() {
        return;
    }
    let mut asc: Vec<u64> = set.to_vec();
    asc.sort_by_key(|va| (weight_of(*va), *va));
    // The two highest-key functions. Sorted descending by key but *ascending* by VA within a tie,
    // which is what the printed rule promises — reversing `asc` would break ties the other way.
    let mut desc: Vec<u64> = set.to_vec();
    desc.sort_by_key(|va| (std::cmp::Reverse(weight_of(*va)), *va));
    let mut picks: Vec<u64> = desc.into_iter().take(2).collect();
    // The median pair: the two central entries of the key-ascending order (one entry if odd).
    for i in [asc.len() / 2, (asc.len() - 1) / 2] {
        picks.push(asc[i]);
    }
    let mut held_here: Vec<u64> = set.iter().copied().filter(|va| held.contains_key(va)).collect();
    held_here.sort_unstable();
    picks.extend(held_here.into_iter().take(2));

    println!("   spot-check:");
    // The three pick rules can name the same function (a small band's top *is* its median); `shown`
    // is what makes each line unique, so the sample is 4-6 rows rather than a fixed 6.
    let mut shown: Vec<u64> = Vec::new();
    for va in picks {
        if shown.contains(&va) {
            continue;
        }
        shown.push(va);
        let f = facts.get(va);
        let evidence = cls.reason.get(&va).map(|s| s.as_str()).unwrap_or("in-scope (no foreign evidence)");
        let flag = if held.contains_key(&va) { "HELD " } else { "" };
        let corpus = by_va
            .get(&va)
            .map(|r| format!("{:<12} sim {:.3}  n={:<4}", r.verdict, r.sim, r.orig_n))
            .unwrap_or_else(|| format!("{:<12} (not a measured row)", "-"));
        let anchor = f
            .and_then(|f| f.anchor.as_ref())
            .map(|a| format!("  {:?}", a.text.chars().take(46).collect::<String>()))
            .unwrap_or_default();
        println!("     {va:#08x}  {corpus}  {flag}{evidence}{anchor}");
    }
}
