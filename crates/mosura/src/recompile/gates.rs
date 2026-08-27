//! Corpus gates (review R4, 2026-08-27) — the invariants that decided the 2026-08-26/27 landings, as
//! pure functions over the rendered TU text and the verdict rows, so a violation FAILS the round
//! instead of living in a reviewer's greps (fable-b's `rows/gates.txt`, regexes ported verbatim).
//!
//! - The bars and sets are committed data — [`Baseline`], `scripts/corpus-gates.tsv`: every row
//!   carries its own rule (`>=` a floor, `==` a count, `no-switch`, `EXACT`) and the round it was
//!   set at. A round that legitimately moves a bar edits that file in the landing commit.
//! - The scope (game vs foreign) is the CALLER's predicate over its manifest — the survey passes
//!   the manifest's `kind` ([`kind_is_user`]) — never an address in here; when the manifest gains a
//!   `scope` column the predicate changes in one line and the bars are re-stamped.
//! - Gates 1–3 run per TU on any tree; 4–6 need a FULL emit (a `--only` probe's partial tree would
//!   misfire the corpus-level bars and sets); 7–8 read verdict rows and SKIP audibly when their
//!   input is missing (no `--prev`, a guard outside `--only`) — never a silent pass. Gate 9 (fixture
//!   provenance) is `tests/fixture_provenance.rs`.
//! - Hits are sorted by va and carry the offending line.
//!
//! Callers: `war2_survey` post-emit (1–6), `recompile_check` post-verdict (7–8),
//! `examples/corpus_gates.rs` on an existing tree (all).
use regex::Regex;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::path::Path;
use std::sync::OnceLock;

/// One rendered TU: the recovered C the round measures, with its manifest columns.
#[derive(Debug, Clone)]
pub struct Tu {
    pub va: u64,
    pub name: String,
    pub text: String,
    /// The manifest's own columns (`kind`, `contract`, …), for the caller's scope predicate.
    pub columns: BTreeMap<String, String>,
}

/// The survey's scope today: the manifest's `kind` column, `user` = game code. A manifest emitted
/// before the column existed has no opinion and counts as in scope (as `recompile_check` reads it).
pub fn kind_is_user(tu: &Tu) -> bool {
    tu.columns.get("kind").map_or(true, |k| k == "user")
}

/// One violation: which TU (va 0 for a corpus-level bar), and the evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub va: u64,
    pub name: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Ok,
    Fail(Vec<Hit>),
    Skip(String),
}

/// One gate's result. `note` is printed in every outcome — the counts behind an OK, the listing
/// behind a FAIL.
#[derive(Debug, Clone)]
pub struct GateReport {
    pub gate: &'static str,
    pub outcome: Outcome,
    pub note: String,
}

/// Hits shown per gate before `... N more`.
const SHOWN: usize = 12;

impl GateReport {
    fn from_hits(gate: &'static str, mut hits: Vec<Hit>, note: String) -> Self {
        hits.sort_by(|a, b| a.va.cmp(&b.va).then_with(|| a.detail.cmp(&b.detail)));
        let outcome = if hits.is_empty() { Outcome::Ok } else { Outcome::Fail(hits) };
        GateReport { gate, outcome, note }
    }
    pub fn skip(gate: &'static str, why: &str) -> Self {
        GateReport { gate, outcome: Outcome::Skip(why.to_string()), note: String::new() }
    }
    pub fn failed(&self) -> bool {
        matches!(self.outcome, Outcome::Fail(_))
    }
    pub fn hits(&self) -> &[Hit] {
        match &self.outcome {
            Outcome::Fail(h) => h,
            _ => &[],
        }
    }
}

impl fmt::Display for GateReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let note = |f: &mut fmt::Formatter<'_>, indent: &str| -> fmt::Result {
            if self.note.is_empty() {
                return Ok(());
            }
            for (i, l) in self.note.lines().enumerate() {
                if i == 0 && indent.is_empty() {
                    write!(f, " {l}")?;
                } else {
                    write!(f, "\n{indent}{l}")?;
                }
            }
            Ok(())
        };
        match &self.outcome {
            Outcome::Ok => {
                write!(f, "OK   {}", self.gate)?;
                note(f, "")?;
                writeln!(f)
            }
            Outcome::Skip(why) => writeln!(f, "SKIP {} ({why})", self.gate),
            Outcome::Fail(hits) => {
                writeln!(f, "FAIL {}: {} hit(s)", self.gate, hits.len())?;
                for h in hits.iter().take(SHOWN) {
                    writeln!(f, "    {:#x} {}: {}", h.va, h.name, h.detail)?;
                }
                if hits.len() > SHOWN {
                    writeln!(f, "    ... {} more", hits.len() - SHOWN)?;
                }
                if !self.note.is_empty() {
                    write!(f, "    note:")?;
                    note(f, "    ")?;
                    writeln!(f)?;
                }
                Ok(())
            }
        }
    }
}

pub fn any_failed(reports: &[GateReport]) -> bool {
    reports.iter().any(|r| r.failed())
}

pub fn render(reports: &[GateReport]) -> String {
    reports.iter().map(|r| r.to_string()).collect()
}

fn re(cell: &'static OnceLock<Regex>, pat: &'static str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).expect("gate regex"))
}
static DECL: OnceLock<Regex> = OnceLock::new();
static USE: OnceLock<Regex> = OnceLock::new();
static PIECE: OnceLock<Regex> = OnceLock::new();
static CALL_ARG: OnceLock<Regex> = OnceLock::new();
static SWITCH: OnceLock<Regex> = OnceLock::new();
static CASE: OnceLock<Regex> = OnceLock::new();

/// The line of `text` around byte offset `at`, trimmed and cut — the evidence a hit carries.
fn line_at(text: &str, at: usize) -> String {
    let start = text[..at].rfind('\n').map_or(0, |i| i + 1);
    let end = text[at..].find('\n').map_or(text.len(), |i| at + i);
    snippet(&text[start..end])
}

fn snippet(line: &str) -> String {
    const MAX: usize = 120;
    let t = line.trim();
    if t.chars().count() > MAX {
        format!("{}…", t.chars().take(MAX).collect::<String>())
    } else {
        t.to_string()
    }
}

// ---------------------------------------------------------------------------------------------
// The committed bars and sets

/// One row of `scripts/corpus-gates.tsv`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineRow {
    pub gate: String,
    pub key: String,
    pub rule: String,
    pub value: String,
    pub set_at: String,
}

/// The bars and sets a round must hold, each row with its rule and the round it was set at.
#[derive(Debug, Clone, Default)]
pub struct Baseline {
    pub rows: Vec<BaselineRow>,
}

/// The rule each gate's rows take — so a reader of the TSV can tell a floor from an equality.
fn rule_of(gate: &str) -> Option<&'static str> {
    Some(match gate {
        "string_ops_bar" => ">=",
        "switch_labels" => "==",
        "chain" => "no-switch",
        "guard_frame" | "guard_volatile" => "EXACT",
        _ => return None,
    })
}

fn parse_va(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok()
}

impl Baseline {
    /// Header `gate\tkey\trule\tvalue\tset_at`, `#` comment lines; every row's rule must be the one
    /// its gate takes, counts must parse, VA keys must be hex.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut rows = Vec::new();
        let mut header_seen = false;
        for (n, line) in text.lines().enumerate() {
            // only the line ending is stripped: a trailing tab is an (empty) column
            let line = line.trim_end_matches('\r');
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            if !header_seen {
                if f != ["gate", "key", "rule", "value", "set_at"] {
                    return Err(format!("line {}: header must be gate/key/rule/value/set_at, got {f:?}", n + 1));
                }
                header_seen = true;
                continue;
            }
            if f.len() != 5 {
                return Err(format!("line {}: expected 5 columns, got {}", n + 1, f.len()));
            }
            let row = BaselineRow {
                gate: f[0].to_string(),
                key: f[1].to_string(),
                rule: f[2].to_string(),
                value: f[3].to_string(),
                set_at: f[4].to_string(),
            };
            let expect = rule_of(&row.gate).ok_or_else(|| format!("line {}: unknown gate `{}`", n + 1, row.gate))?;
            if row.rule != expect {
                return Err(format!("line {}: gate `{}` takes rule `{expect}`, got `{}`", n + 1, row.gate, row.rule));
            }
            match row.rule.as_str() {
                ">=" | "==" => {
                    row.value.parse::<usize>().map_err(|_| format!("line {}: value `{}` is not a count", n + 1, row.value))?;
                }
                _ => {}
            }
            if row.gate != "string_ops_bar" && parse_va(&row.key).is_none() {
                return Err(format!("line {}: key `{}` is not a hex VA", n + 1, row.key));
            }
            if row.set_at.is_empty() {
                return Err(format!("line {}: set_at is empty — every row names the round it was set at", n + 1));
            }
            rows.push(row);
        }
        if !header_seen {
            return Err("no header row".to_string());
        }
        Ok(Baseline { rows })
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Gate 4's floors, by the counted spelling (`memcpy(`, …).
    pub fn string_ops_bar(&self) -> BTreeMap<String, usize> {
        self.rows
            .iter()
            .filter(|r| r.gate == "string_ops_bar")
            .map(|r| (r.key.clone(), r.value.parse().unwrap_or(0)))
            .collect()
    }
    /// Gate 5's TUs.
    pub fn chains(&self) -> Vec<u64> {
        self.vas("chain")
    }
    /// Gate 6's TUs with their label counts.
    pub fn switch_labels(&self) -> BTreeMap<u64, usize> {
        self.rows
            .iter()
            .filter(|r| r.gate == "switch_labels")
            .filter_map(|r| Some((parse_va(&r.key)?, r.value.parse().ok()?)))
            .collect()
    }
    /// Gate 7's TUs: `guard_frame` or `guard_volatile`.
    pub fn guards(&self, gate: &str) -> Vec<u64> {
        self.vas(gate)
    }
    fn vas(&self, gate: &str) -> Vec<u64> {
        self.rows.iter().filter(|r| r.gate == gate).filter_map(|r| parse_va(&r.key)).collect()
    }
}

// ---------------------------------------------------------------------------------------------
// Gates 1–6: the rendered text

/// Statement keywords a declaration line never starts with: `return xStack_10;` or
/// `goto LAB_1;` are statements, not declarations of their identifier.
const STATEMENT_WORDS: [&str; 7] = ["return", "goto", "else", "case", "default", "break", "continue"];

/// Gate 1 — declared symbols: every `<prefix>Stack_<hex>` identifier a TU uses must appear in one of
/// its declaration lines (a line of words ending in the identifier and `;`, not led by a statement
/// keyword). Caught 0x4e06e — the frame aggregate had swallowed the declaration of an array whose
/// element the body still read by name (COMPILE_FAIL E1011) — and four library TUs, so it runs over
/// ALL TUs, not the game scope alone.
pub fn declared_symbols(tus: &[Tu]) -> GateReport {
    let decl = re(&DECL, r"(?m)^\s+([A-Za-z_]\w*)\s+(?:[A-Za-z_]\w*\s+)*\**\s*([A-Za-z_]\w*)\s*(?:\[\d+\])?\s*;");
    let uses = re(&USE, r"\b\w*Stack_[0-9a-f]+\b");
    let mut hits = Vec::new();
    for tu in tus {
        let declared: HashSet<&str> = decl
            .captures_iter(&tu.text)
            .filter(|c| !STATEMENT_WORDS.contains(&c.get(1).unwrap().as_str()))
            .map(|c| c.get(2).unwrap().as_str())
            .collect();
        let mut undeclared: Vec<(&str, usize)> = Vec::new();
        for m in uses.find_iter(&tu.text) {
            let name = m.as_str();
            if !declared.contains(name) && !undeclared.iter().any(|(n, _)| *n == name) {
                undeclared.push((name, m.start()));
            }
        }
        if let Some((_, at)) = undeclared.first() {
            let names: Vec<&str> = undeclared.iter().take(6).map(|(n, _)| *n).collect();
            hits.push(Hit {
                va: tu.va,
                name: tu.name.clone(),
                detail: format!("undeclared {} — {}", names.join(" "), line_at(&tu.text, *at)),
            });
        }
    }
    GateReport::from_hits("1 declared-symbols", hits, format!("({} TUs)", tus.len()))
}

fn first_match_gate(gate: &'static str, tus: &[Tu], pat: &Regex) -> GateReport {
    let hits = tus
        .iter()
        .filter_map(|tu| {
            pat.find(&tu.text).map(|m| Hit { va: tu.va, name: tu.name.clone(), detail: line_at(&tu.text, m.start()) })
        })
        .collect();
    GateReport::from_hits(gate, hits, format!("({} TUs)", tus.len()))
}

/// Gate 2 — piece-on-field: no `._<n>_<m>_` piece suffix composed onto a parenthesized field
/// expression (a SUBPIECE printed against an expression instead of a variable). Caught 0x66100.
pub fn piece_on_field(tus: &[Tu]) -> GateReport {
    first_match_gate("2 piece-on-field", tus, re(&PIECE, r"\)\._\d+_\d+_"))
}

/// Gate 3 — call-as-argument: no `mem*(` / `strlen(` whose first argument is a CALL (`func_0x…`) —
/// a copy destination or a scan argument printed from the wrong operand. Caught the w1b
/// over-strip: 10 sites in 5 TUs.
pub fn call_as_argument(tus: &[Tu]) -> GateReport {
    first_match_gate("3 call-as-argument", tus, re(&CALL_ARG, r"(mem(cpy|set|cmp)|strlen)\(\s*func_0x"))
}

/// Gate 4 — string-ops bar: the counts of `memcpy(` / `memset(` / `memcmp(` / `strlen(` over the TUs
/// in scope must not drop below the committed floors — every witnessed REP pair stays a memcpy,
/// every lifted REPNE SCASB a strlen. A landing that raises a count re-stamps the bar; the scope is
/// the caller's.
pub fn string_ops_bar<'a>(in_scope: impl Iterator<Item = &'a Tu>, bar: &BTreeMap<String, usize>) -> GateReport {
    let mut counts: BTreeMap<&str, usize> = bar.keys().map(|k| (k.as_str(), 0)).collect();
    let mut n = 0usize;
    for tu in in_scope {
        n += 1;
        for (k, c) in counts.iter_mut() {
            *c += tu.text.matches(*k).count();
        }
    }
    let hits: Vec<Hit> = bar
        .iter()
        .filter(|(k, floor)| counts[k.as_str()] < **floor)
        .map(|(k, floor)| Hit { va: 0, name: k.clone(), detail: format!("{} < the bar {floor}", counts[k.as_str()]) })
        .collect();
    let seen: Vec<String> = counts.iter().map(|(k, c)| format!("{}={c}", k.trim_end_matches('('))).collect();
    let bars: Vec<String> = bar.values().map(|v| v.to_string()).collect();
    GateReport::from_hits(
        "4 string-ops-bar",
        hits,
        format!("({n} TUs in scope; {}; bar {})", seen.join(" "), bars.join("/")),
    )
}

/// Gate 5 — chains never switch: the TUs whose original is an if-chain or a JE-only chain must
/// print no `switch (` — the sparse-switch arm needs the byte witness and a pivot, and a chain
/// printed as a switch loses EXACT. Caught 0x12360 losing EXACT. A chain TU missing from a full
/// tree is a hit.
pub fn chains_never_switch(tus: &[Tu], chains: &[u64]) -> GateReport {
    let by_va: BTreeMap<u64, &Tu> = tus.iter().map(|t| (t.va, t)).collect();
    let sw = re(&SWITCH, r"\bswitch\s*\(");
    let mut hits = Vec::new();
    for &va in chains {
        match by_va.get(&va) {
            None => hits.push(Hit { va, name: String::new(), detail: "missing from the tree".to_string() }),
            Some(tu) => {
                if let Some(m) = sw.find(&tu.text) {
                    hits.push(Hit {
                        va,
                        name: tu.name.clone(),
                        detail: format!("prints a switch — {}", line_at(&tu.text, m.start())),
                    });
                }
            }
        }
    }
    GateReport::from_hits("5 chains-never-switch", hits, format!("({} chain TUs)", chains.len()))
}

/// Gate 6 — switch labels: for the known jump-table and compare-tree switches the `case` label
/// count equals the byte-derived set. Caught 0x4ccc4 printing 2 of its 6 cases.
pub fn switch_labels(tus: &[Tu], labels: &BTreeMap<u64, usize>) -> GateReport {
    let by_va: BTreeMap<u64, &Tu> = tus.iter().map(|t| (t.va, t)).collect();
    let case = re(&CASE, r"(?m)^\s*case\b");
    let mut hits = Vec::new();
    for (&va, &want) in labels {
        match by_va.get(&va) {
            None => hits.push(Hit { va, name: String::new(), detail: "missing from the tree".to_string() }),
            Some(tu) => {
                let n = case.find_iter(&tu.text).count();
                if n != want {
                    hits.push(Hit { va, name: tu.name.clone(), detail: format!("{n} case labels, expected {want}") });
                }
            }
        }
    }
    GateReport::from_hits("6 switch-labels", hits, format!("({} switch TUs)", labels.len()))
}

// ---------------------------------------------------------------------------------------------
// Gates 7–8: the verdict rows

/// One `recompile_check --out` row.
#[derive(Debug, Clone, PartialEq)]
pub struct VerdictRow {
    pub idx: String,
    pub va: u64,
    pub name: String,
    pub verdict: String,
    pub sim: f64,
    pub equal: u64,
    pub orig_n: u64,
}

/// `recompile_check --out` rows by va: header-driven (`idx va name verdict … sim equal orig_n …`;
/// the trailing `EXCLUDE-FOREIGN=` header column and `#` lines are ignored).
pub fn parse_verdicts(tsv: &str) -> Result<BTreeMap<u64, VerdictRow>, String> {
    let mut lines = tsv.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#'));
    let header: Vec<&str> = lines.next().ok_or("empty verdict table")?.split('\t').collect();
    let col = |name: &str| header.iter().position(|h| *h == name).ok_or_else(|| format!("verdict table has no `{name}` column"));
    let (ci, cv, cn, cverd) = (col("idx")?, col("va")?, col("name")?, col("verdict")?);
    let (csim, ceq, corig) = (col("sim")?, col("equal")?, col("orig_n")?);
    let mut rows = BTreeMap::new();
    for (n, line) in lines.enumerate() {
        let f: Vec<&str> = line.split('\t').collect();
        let get = |i: usize| f.get(i).copied().unwrap_or("").trim();
        let va = parse_va(get(cv)).ok_or_else(|| format!("row {}: bad va `{}`", n + 2, get(cv)))?;
        rows.insert(
            va,
            VerdictRow {
                idx: get(ci).to_string(),
                va,
                name: get(cn).to_string(),
                verdict: get(cverd).to_string(),
                sim: get(csim).parse().unwrap_or(0.0),
                equal: get(ceq).parse().unwrap_or(0),
                orig_n: get(corig).parse().unwrap_or(0),
            },
        );
    }
    Ok(rows)
}

/// The CANONICAL census every round report quotes (`scripts/war2-verdicts.sh`, the runbook's only
/// allowed census — 0.5576 at w6a): `1 − Σ orig_n·(1−sim) / Σ orig_n` = `Σ orig_n·sim / Σ orig_n`,
/// with each row's `sim` = equal / max(orig_n, cand_n) as `recompile_check` wrote it. Not the
/// micro-average Σ equal / Σ max(orig, cand) that `recompile_check` also prints.
pub fn wgss(rows: &BTreeMap<u64, VerdictRow>) -> f64 {
    let (weighted, n) = rows.values().fold((0f64, 0u64), |(w, n), r| (w + r.orig_n as f64 * r.sim, n + r.orig_n));
    weighted / n.max(1) as f64
}

fn rank(verdict: &str) -> u8 {
    match verdict {
        "EXACT" => 5,
        "SAME_CODE" => 4,
        "SAME_SHAPE" => 3,
        "MISMATCH" => 2,
        "DECOMPILE_FAIL" => 1,
        _ => 0,
    }
}

/// The verdicts that mean "no candidate was measured": a compile failure, an unreadable object
/// (the poisoned-cache trap's signature) or a decompiler crash — one rule for all three.
fn is_failure(verdict: &str) -> bool {
    matches!(verdict, "COMPILE_FAIL" | "OBJ_ERROR" | "DECOMPILE_FAIL")
}

/// Gate 7 — guard sets stay EXACT: the frame guards (frame-fill, W4) and the volatile guards (field
/// 695) are the TUs whose EXACT the corresponding arm must never cost. A guard absent from a
/// partial (`--only`) table is skipped audibly; absent from a full one it is a hit.
pub fn guard_sets_exact(rows: &BTreeMap<u64, VerdictRow>, frame: &[u64], volatile: &[u64], partial: bool) -> GateReport {
    let mut hits = Vec::new();
    let mut skipped = 0usize;
    for (set, va) in frame.iter().map(|v| ("frame", *v)).chain(volatile.iter().map(|v| ("volatile", *v))) {
        match rows.get(&va) {
            None if partial => skipped += 1,
            None => hits.push(Hit { va, name: String::new(), detail: format!("{set} guard not in the verdict table") }),
            Some(r) if r.verdict != "EXACT" => hits.push(Hit {
                va,
                name: r.name.clone(),
                detail: format!("{set} guard is {} (sim {:.3})", r.verdict, r.sim),
            }),
            Some(_) => {}
        }
    }
    let total = frame.len() + volatile.len();
    if total > 0 && skipped == total {
        return GateReport::skip("7 guard-sets-EXACT", "no guard in the --only set");
    }
    let skipped_note = if skipped > 0 { format!(", {skipped} outside --only skipped") } else { String::new() };
    GateReport::from_hits(
        "7 guard-sets-EXACT",
        hits,
        format!("({} frame + {} volatile{skipped_note})", frame.len(), volatile.len()),
    )
}

/// Downs listed by gate 8 before `... N more`.
const DOWNS_SHOWN: usize = 40;

/// Gate 8 — verdict regressions against the previous round: FAIL on an EXACT lost or a NEW FAILURE
/// verdict (COMPILE_FAIL, OBJ_ERROR or DECOMPILE_FAIL where the previous round had a measured
/// candidate). Every other down (a lower verdict, or a lower sim at the same verdict) is LISTED
/// with old/new verdict and sim, under the WGSS delta over the rows both tables hold (the full
/// census on a full round) — their classification stays the human step: a faithful port's downs
/// can be correct-code corrections, and the gate must not pretend to know.
pub fn verdict_regressions(prev: &BTreeMap<u64, VerdictRow>, cur: &BTreeMap<u64, VerdictRow>) -> GateReport {
    let mut hits = Vec::new();
    let mut downs: Vec<String> = Vec::new();
    let mut common = 0usize;
    for (va, c) in cur {
        let Some(p) = prev.get(va) else { continue };
        common += 1;
        let (pv, cv) = (p.verdict.as_str(), c.verdict.as_str());
        if pv == "EXACT" && cv != "EXACT" {
            hits.push(Hit { va: *va, name: c.name.clone(), detail: format!("EXACT lost: now {cv} (sim {:.3} -> {:.3})", p.sim, c.sim) });
        } else if is_failure(cv) && !is_failure(pv) {
            hits.push(Hit { va: *va, name: c.name.clone(), detail: format!("new {cv} (was {pv}, sim {:.3})", p.sim) });
        } else if rank(cv) < rank(pv) || (cv == pv && c.sim + 1e-9 < p.sim) {
            downs.push(format!("{:#x} {}: {pv} -> {cv}, sim {:.3} -> {:.3}", va, c.name, p.sim, c.sim));
        }
    }
    // the delta over the rows BOTH tables hold: identical to the full census on a full round, and
    // the only comparable number when a `--only` table meets a full previous round
    let shared = |t: &BTreeMap<u64, VerdictRow>| -> BTreeMap<u64, VerdictRow> {
        t.iter().filter(|(va, _)| prev.contains_key(va) && cur.contains_key(va)).map(|(va, r)| (*va, r.clone())).collect()
    };
    let (w0, w1) = (wgss(&shared(prev)), wgss(&shared(cur)));
    let mut note = format!(
        "({common} common rows, {} new, {} gone; WGSS over the common rows {w0:.4} -> {w1:.4} ({:+.4}); {} down(s) listed",
        cur.len() - common,
        prev.len() - common,
        w1 - w0,
        downs.len()
    );
    if !downs.is_empty() {
        note.push(':');
        for d in downs.iter().take(DOWNS_SHOWN) {
            note.push('\n');
            note.push_str(d);
        }
        if downs.len() > DOWNS_SHOWN {
            note.push_str(&format!("\n... {} more", downs.len() - DOWNS_SHOWN));
        }
    }
    note.push(')');
    GateReport::from_hits("8 verdict-regressions", hits, note)
}

// ---------------------------------------------------------------------------------------------
// Trees and runners

/// The rendered TUs of a survey tree: `manifest.tsv` (header-driven, `#` lines skipped) joined with
/// `recovered/<idx>.c`. A manifest row without a file is not in the tree (a partial emit); the
/// manifest's columns ride along for the caller's scope predicate. Sorted by va.
pub fn load_tree(manifest: &Path, recovered: &Path) -> Result<Vec<Tu>, String> {
    let text = std::fs::read_to_string(manifest).map_err(|e| format!("{}: {e}", manifest.display()))?;
    let mut lines = text.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty());
    let header: Vec<String> = lines.next().ok_or("empty manifest")?.split('\t').map(String::from).collect();
    let col = |name: &str| header.iter().position(|h| h == name).ok_or_else(|| format!("manifest has no `{name}` column"));
    let (ci, cv, cn) = (col("idx")?, col("va")?, col("name")?);
    let mut tus = Vec::new();
    for line in lines {
        let f: Vec<&str> = line.split('\t').collect();
        let get = |i: usize| f.get(i).copied().unwrap_or("").trim();
        let Some(va) = parse_va(get(cv)) else { continue };
        let Ok(bytes) = std::fs::read(recovered.join(format!("{}.c", get(ci)))) else { continue };
        let columns = header.iter().cloned().zip(f.iter().map(|s| s.trim().to_string())).collect();
        tus.push(Tu { va, name: get(cn).to_string(), text: String::from_utf8_lossy(&bytes).into_owned(), columns });
    }
    tus.sort_by_key(|t| t.va);
    Ok(tus)
}

/// Gates 1–6 over a tree: 1–3 on any emit, 4–6 only on a full one (else SKIP). `in_scope` is the
/// caller's game/foreign predicate (gate 4's denominator).
pub fn run_text_gates(tus: &[Tu], in_scope: &dyn Fn(&Tu) -> bool, baseline: &Baseline, full_emit: bool) -> Vec<GateReport> {
    let mut out = vec![declared_symbols(tus), piece_on_field(tus), call_as_argument(tus)];
    if full_emit {
        out.push(string_ops_bar(tus.iter().filter(|t| in_scope(t)), &baseline.string_ops_bar()));
        out.push(chains_never_switch(tus, &baseline.chains()));
        out.push(switch_labels(tus, &baseline.switch_labels()));
    } else {
        for g in ["4 string-ops-bar", "5 chains-never-switch", "6 switch-labels"] {
            out.push(GateReport::skip(g, "partial emit"));
        }
    }
    out
}

/// Gates 7–8 over the verdict rows. `partial` = the table came from a `--only` run; without a
/// previous table gate 8 is SKIP, never a silent pass.
pub fn run_verdict_gates(
    cur: &BTreeMap<u64, VerdictRow>,
    prev: Option<&BTreeMap<u64, VerdictRow>>,
    baseline: &Baseline,
    partial: bool,
) -> Vec<GateReport> {
    vec![
        guard_sets_exact(cur, &baseline.guards("guard_frame"), &baseline.guards("guard_volatile"), partial),
        match prev {
            Some(p) => verdict_regressions(p, cur),
            None => GateReport::skip("8 verdict-regressions", "no --prev"),
        },
    ]
}
