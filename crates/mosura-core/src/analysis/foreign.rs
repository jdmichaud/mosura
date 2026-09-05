//! Foreign-module **foreign-module classification** — decides which functions belong in the recompilation
//! denominator ("the port") and which are foreign code the linker pulled in (C runtime, licensed
//! libraries like Miles/AIL or SciTech). Design & validation: `docs/foreign-scope-plan.md`.
//!
//! This is a *generic engine*: it holds only structural shapes and graph algorithms — never a
//! library name. All binary-specific knowledge is data, supplied as band confirmations
//! ([`Confirmation`]). The engine composes independent, **positive-only** evidence:
//!
//! - **FID / loader** — a function the signature matcher or loader already named ([`Function::is_identified`]).
//! - **Anchor** — a function that references a *structurally* anchored string (a self-naming
//!   `ident(` trace, a `foo.c` source reference, or a copyright/version banner). The exact strings
//!   are the binary's; only the *shapes* are hard-coded ([`anchor_class`]).
//! - **Codegen fingerprint** — a prologue matching the foreign calling convention (save esi/edi,
//!   read args off the stack), used to *corroborate*, never as a standalone seed ([`is_foreign_fingerprint`]).
//! - **Reachability** — a function reachable only from confirmed-foreign code is foreign; one also
//!   called by in-scope code is a *shared* helper and is never dropped.
//!
//! Invariants (see the plan): positive-evidence-only (in-scope unless proven foreign); the engine
//! never presumes an anchored band is foreign (a `foo.c` band may be the game's own module — the
//! human confirms); with an empty [`Confirmation`] the result is exactly today's `is_identified`
//! exclusion, so the default is safe.

use crate::analysis::program::Program;
use crate::decompile::space::{Address, SpaceId};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// The structural class of an anchoring string. Shapes only — no library names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AnchorClass {
    /// `identifier(` — a self-naming trace/API string (e.g. `AIL_startup()`).
    SelfNaming,
    /// A `<name>.c/.cpp/.asm` source-file reference — a *module name*, which may be the game's own.
    SourceRef,
    /// A copyright / version / rights banner.
    Banner,
}

fn re_self() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]{2,}\(").unwrap())
}
fn re_src() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)\b[A-Za-z_][A-Za-z0-9_]{1,}\.(c|cpp|asm)\b").unwrap())
}
fn re_banner() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    // A bare `version` over-captures game diagnostics ("Invalid data file version." — AMERICA.C),
    // so require a copyright/rights lexeme, `(c)`, or a *numbered* version ("Run-Time Version 2.5").
    R.get_or_init(|| Regex::new(r"(?i)copyright|all rights reserved|\(c\)|version\s+[0-9]").unwrap())
}

/// Classify a string by structural shape, or `None` if it is ordinary data. Order mirrors the
/// validation POC: self-naming, then source-ref, then banner.
pub fn anchor_class(s: &str) -> Option<AnchorClass> {
    if re_self().is_match(s) {
        Some(AnchorClass::SelfNaming)
    } else if re_src().is_match(s) {
        Some(AnchorClass::SourceRef)
    } else if re_banner().is_match(s) {
        Some(AnchorClass::Banner)
    } else {
        None
    }
}

/// Whether a prologue matches the *foreign* calling convention — a corroborating signal, not a
/// standalone seed (game code trips it a few percent of the time; see the plan's H5b).
///
/// Two positive forms, both from measured ground truth: leads with `push esi`/`push edi` (0x56/57 —
/// the cdecl C-nonvolatile save that precedes the frame), or reads an incoming argument off the
/// stack early (`mov r,[esp+d]` / `mov r,[ebp+d>=8]` / `push [esp|ebp+d]`).
pub fn is_foreign_fingerprint(prologue: &[u8]) -> bool {
    matches!(prologue.first(), Some(0x56 | 0x57)) || reads_stack_args(prologue)
}

fn reads_stack_args(b: &[u8]) -> bool {
    let n = b.len().min(24);
    let mut i = 0;
    while i + 2 < n {
        let op = b[i];
        if op == 0x8b {
            let modrm = b[i + 1];
            let mode = modrm >> 6;
            let rm = modrm & 7;
            if mode == 1 {
                // mov r32,[esp+disp8]  (SIB rm=100, base=esp) with disp past the return address
                if rm == 4 && i + 3 < n && b[i + 2] == 0x24 && b[i + 3] >= 0x04 {
                    return true;
                }
                // mov r32,[ebp+disp8]  with disp into the args ([ebp+8]+)
                if rm == 5 && b[i + 2] >= 0x08 {
                    return true;
                }
            }
        }
        if op == 0xff && i + 2 < n {
            let modrm = b[i + 1];
            if modrm == 0x75 && b[i + 2] >= 0x08 {
                return true; // push [ebp+d]
            }
            if modrm == 0x74 && i + 3 < n && b[i + 2] == 0x24 && b[i + 3] >= 0x04 {
                return true; // push [esp+d]
            }
        }
        i += 1;
    }
    false
}

/// A structurally-anchored string a function references.
#[derive(Clone, Debug)]
pub struct Anchor {
    pub target: u64,
    pub text: String,
    pub class: AnchorClass,
}

/// The per-function facts the engine reasons over.
#[derive(Clone, Debug)]
pub struct FnFacts {
    pub va: u64,
    pub size: u64,
    pub lo: u64,
    pub hi: u64,
    /// FID- or loader-named (today's `library` exclusion).
    pub identified: bool,
    pub name: String,
    pub prologue: Vec<u8>,
    pub foreign_fp: bool,
    pub callees: Vec<u64>,
    pub callers: Vec<u64>,
    pub anchor: Option<Anchor>,
}

/// All functions plus a va→index map, from one analysis pass.
#[derive(Clone, Debug, Default)]
pub struct Facts {
    pub fns: Vec<FnFacts>,
    pub index: HashMap<u64, usize>,
}

impl Facts {
    pub fn get(&self, va: u64) -> Option<&FnFacts> {
        self.index.get(&va).map(|&i| &self.fns[i])
    }
}

fn read_ascii(prog: &Program, ram: SpaceId, va: u64, max: u64) -> String {
    let mut s = String::new();
    for i in 0..max {
        match prog.memory.byte_at(Address::new(ram, va + i)) {
            Some(b) if (0x20..0x7f).contains(&b) => s.push(b as char),
            _ => break,
        }
    }
    s
}

/// Extract [`Facts`] from an analyzed program: prologues, the direct/indirect call graph, and the
/// first structurally-anchored string each function references.
pub fn extract_facts(prog: &Program) -> Facts {
    let ram = prog.default_space;
    let mut fns: Vec<FnFacts> = prog
        .function_manager
        .functions()
        .map(|f| {
            let va = f.entry_point().offset;
            let body = f.body();
            let mut prologue = Vec::with_capacity(24);
            for i in 0..24 {
                match prog.memory.byte_at(Address::new(ram, va + i)) {
                    Some(b) => prologue.push(b),
                    None => break,
                }
            }
            FnFacts {
                va,
                size: body.num_addresses(),
                lo: body.min_address().map(|a| a.offset).unwrap_or(va),
                hi: body.max_address().map(|a| a.offset).unwrap_or(va),
                identified: f.is_identified(),
                name: f.name().to_string(),
                foreign_fp: is_foreign_fingerprint(&prologue),
                prologue,
                callees: Vec::new(),
                callers: Vec::new(),
                anchor: None,
            }
        })
        .collect();
    fns.sort_by_key(|f| f.va);
    let index: HashMap<u64, usize> = fns.iter().enumerate().map(|(i, f)| (f.va, i)).collect();

    for r in prog.reference_manager.references() {
        let Some(from_fn) = prog.function_manager.function_containing(r.from) else { continue };
        let Some(&fi) = index.get(&from_fn.entry_point().offset) else { continue };
        let from = fns[fi].va;
        if r.ref_type.is_call() {
            if prog.function_manager.function_at(r.to).is_some() {
                fns[fi].callees.push(r.to.offset);
                if let Some(&ti) = index.get(&r.to.offset) {
                    fns[ti].callers.push(from);
                }
            }
        } else if prog.function_manager.function_at(r.to).is_none() && fns[fi].anchor.is_none() {
            let s = read_ascii(prog, ram, r.to.offset, 48);
            if let Some(class) = anchor_class(&s) {
                fns[fi].anchor = Some(Anchor { target: r.to.offset, text: s, class });
            }
        }
    }
    Facts { fns, index }
}

/// A proposed foreign-module band — the human-facing review unit. The engine never *decides* a
/// band is foreign; it proposes, the human confirms (a `SourceRef` band may be the game's own).
#[derive(Clone, Debug)]
pub struct Band {
    pub lo: u64,
    pub hi: u64,
    /// Anchored (seed) function VAs in this band.
    pub seeds: Vec<u64>,
    /// Total functions whose entry falls in `[lo,hi]`.
    pub span_fns: usize,
    pub class: AnchorClass,
    /// Longest common prefix of the seed strings (≥3 chars), else the first example.
    pub label: String,
    pub example: String,
    /// Fraction of span functions matching the foreign fingerprint (corroboration strength).
    pub fp_agreement: f32,
    /// How many span functions FID already identified.
    pub fid_in_span: usize,
}

/// Cluster anchored functions into locality bands (split where the VA gap exceeds `gap`). Ranked
/// by seed count. This is the load-bearing step — locality, not name prefix, separates a real
/// module from scattered strings.
pub fn propose_bands(facts: &Facts, gap: u64) -> Vec<Band> {
    let anchored: Vec<&FnFacts> = facts.fns.iter().filter(|f| f.anchor.is_some()).collect();
    if anchored.is_empty() {
        return Vec::new();
    }
    let mut clusters: Vec<Vec<&FnFacts>> = Vec::new();
    let mut cur: Vec<&FnFacts> = vec![anchored[0]];
    for f in &anchored[1..] {
        if f.va - cur.last().unwrap().va > gap {
            clusters.push(std::mem::take(&mut cur));
        }
        cur.push(f);
    }
    clusters.push(cur);

    let mut bands: Vec<Band> = clusters
        .into_iter()
        .map(|c| {
            let lo = c.first().unwrap().va;
            let hi = c.last().unwrap().va;
            let span: Vec<&FnFacts> =
                facts.fns.iter().filter(|f| f.va >= lo && f.va <= hi).collect();
            let strings: Vec<&str> = c.iter().map(|f| f.anchor.as_ref().unwrap().text.as_str()).collect();
            // dominant anchor class
            let mut counts: HashMap<AnchorClass, usize> = HashMap::new();
            for f in &c {
                *counts.entry(f.anchor.as_ref().unwrap().class).or_default() += 1;
            }
            let class = *counts.iter().max_by_key(|(_, n)| **n).unwrap().0;
            // label = longest common prefix of the seed strings (>=3 chars)
            let mut pref = strings[0].to_string();
            for s in &strings[1..] {
                while !s.starts_with(&pref) {
                    pref.pop();
                }
            }
            let label = if pref.len() >= 3 { pref } else { strings[0].to_string() };
            let fp = span.iter().filter(|f| f.foreign_fp).count();
            let fid = span.iter().filter(|f| f.identified).count();
            Band {
                lo,
                hi,
                seeds: c.iter().map(|f| f.va).collect(),
                span_fns: span.len(),
                class,
                label: label.chars().take(40).collect(),
                example: strings[0].chars().take(60).collect(),
                fp_agreement: fp as f32 / span.len().max(1) as f32,
                fid_in_span: fid,
            }
        })
        .collect();
    bands.sort_by_key(|b| std::cmp::Reverse(b.seeds.len()));
    bands
}

/// A human selection: an anchor-string pattern that identifies a module, plus the reason. The
/// human picks the STRING (a distinctive substring of a proposed band's string, or a FID library
/// name); the engine derives which functions it anchors and — via locality clustering — the whole
/// module span. Addresses are never hand-authored.
#[derive(Clone, Debug)]
pub struct Sel {
    pub pattern: String,
    pub label: String,
}

/// The binary-specific data behind the boundary: which anchor STRINGS the human selected as
/// foreign, and which they explicitly rejected (keep in scope, e.g. a `foo.c` band that is the
/// game's own module). An empty confirmation excludes nothing beyond today's FID/loader set.
#[derive(Clone, Debug, Default)]
pub struct Confirmation {
    pub foreign: Vec<Sel>,
    pub reject: Vec<Sel>,
}

impl Confirmation {
    /// Parse the line format — the human names STRINGS, not addresses:
    /// ```text
    /// # comment
    /// foreign AIL_     Miles/AIL audio library
    /// reject  Build.c  Build.c is the game's own module
    /// ```
    /// The second whitespace token is the pattern (a substring matched against a function's anchor
    /// string, or its FID name); the rest of the line is the reason.
    pub fn parse(text: &str) -> Confirmation {
        let mut c = Confirmation::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.split_whitespace();
            let kind = it.next().unwrap_or("");
            let Some(pattern) = it.next() else { continue };
            let sel = Sel { pattern: pattern.to_string(), label: it.collect::<Vec<_>>().join(" ") };
            match kind {
                "foreign" => c.foreign.push(sel),
                "reject" => c.reject.push(sel),
                _ => {}
            }
        }
        c
    }

    pub fn load(path: &std::path::Path) -> std::io::Result<Confirmation> {
        Ok(Confirmation::parse(&std::fs::read_to_string(path)?))
    }

    /// The label of the first foreign selection whose pattern matches `text` (an anchor string).
    fn foreign_label(&self, text: &str) -> Option<&str> {
        self.foreign.iter().find(|s| text.contains(&s.pattern)).map(|s| s.label.as_str())
    }
    /// Whether a reject selection matches `text` (matched against both the anchor and the name).
    fn rejects(&self, text: &str) -> bool {
        self.reject.iter().any(|s| text.contains(&s.pattern))
    }
}

/// The foreign/in-scope verdict for a function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Class {
    InScope,
    Foreign,
}

/// Full classification result: the class + a human-readable evidence string per function, plus the
/// *held* set — functions reachable only from foreign code but not corroborated (fingerprint/band),
/// surfaced rather than silently dropped (the CALLIND-incompleteness guard).
#[derive(Clone, Debug, Default)]
pub struct Classification {
    pub class: HashMap<u64, Class>,
    pub reason: HashMap<u64, String>,
    pub held: Vec<(u64, String)>,
    /// Non-fatal advisories to surface to the human (e.g. a pattern matched more than one band).
    pub warnings: Vec<String>,
}

impl Classification {
    pub fn is_foreign(&self, va: u64) -> bool {
        matches!(self.class.get(&va), Some(Class::Foreign))
    }
    pub fn foreign_count(&self) -> usize {
        self.class.values().filter(|c| **c == Class::Foreign).count()
    }
}

/// The default locality gap for band clustering (a page-plus, above intra-module string spacing).
pub const BAND_GAP: u64 = 0x2000;

/// Compute the class of every function from facts + the human's STRING selections.
///
/// The human names anchor strings; the engine resolves each to a proposed locality band and marks
/// that band's whole span foreign. Foreign = FID/loader-identified ∪ selected-band members ∪
/// reachability-private (callers all foreign AND corroborated by fingerprint or band), minus
/// rejects (a function whose anchor or name matches a rejected string). A reachable-only-from-
/// foreign but *uncorroborated* function is **held**, not dropped. With an empty confirmation this
/// is exactly the FID/loader set — the default-safe guarantee.
pub fn classify(facts: &Facts, conf: &Confirmation) -> Classification {
    let mut reason: HashMap<u64, String> = HashMap::new();

    // Rejects: a function whose anchor string OR name matches a rejected pattern is forced in-scope
    // (the human's "this is the game's own module" / "not actually foreign").
    let rejected: HashSet<u64> = facts
        .fns
        .iter()
        .filter(|f| {
            conf.rejects(&f.name) || f.anchor.as_ref().is_some_and(|a| conf.rejects(&a.text))
        })
        .map(|f| f.va)
        .collect();

    // Seed 1: FID / loader (unless rejected). Today's exclusion; does NOT by itself drive
    // reachability — so an empty confirmation reproduces exactly today's set.
    let mut fid_foreign: HashSet<u64> = HashSet::new();
    for f in &facts.fns {
        if f.identified && !rejected.contains(&f.va) {
            fid_foreign.insert(f.va);
            reason.insert(f.va, format!("fid:{}", f.name));
        }
    }
    // Seed 2: bands the human selected by STRING. Propose locality bands, then confirm any band one
    // of whose seed anchors matches a foreign pattern — marking the band's full derived SPAN foreign
    // (the human named a string; the engine derived the address span from the clustering).
    let bands = propose_bands(facts, BAND_GAP);
    let band_matches = |sel: &Sel, b: &Band| {
        b.seeds
            .iter()
            .filter_map(|va| facts.get(*va).and_then(|f| f.anchor.as_ref()))
            .any(|a| a.text.contains(&sel.pattern))
    };
    let mut band_derived: HashSet<u64> = HashSet::new();
    let mut confirmed_spans: Vec<(u64, u64)> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    for b in &bands {
        let label = b
            .seeds
            .iter()
            .filter_map(|va| facts.get(*va).and_then(|f| f.anchor.as_ref()))
            .find_map(|a| conf.foreign_label(&a.text));
        if let Some(label) = label {
            confirmed_spans.push((b.lo, b.hi));
            for f in &facts.fns {
                if f.va >= b.lo && f.va <= b.hi && !rejected.contains(&f.va) && band_derived.insert(f.va) {
                    reason.insert(f.va, format!("band:{label}"));
                }
            }
        }
    }
    // A pattern that matches seeds in more than one band is likely too broad — confirming it
    // silently sweeps in every matching band. Surface it rather than deciding for the human.
    for sel in &conf.foreign {
        let n = bands.iter().filter(|b| band_matches(sel, b)).count();
        if n > 1 {
            warnings.push(format!(
                "foreign pattern {:?} matches {n} bands (all confirmed foreign) — tighten it if unintended",
                sel.pattern
            ));
        }
    }
    let in_confirmed_span = |va: u64| confirmed_spans.iter().any(|(lo, hi)| va >= *lo && va <= *hi);

    let is_foreign = |v: u64, fid: &HashSet<u64>, band: &HashSet<u64>| fid.contains(&v) || band.contains(&v);

    // Seed 3: reachability, to a fixpoint. A function is pulled foreign iff it is reachable from a
    // selected BAND (some caller is band-derived), ALL its callers are foreign (only-from-foreign),
    // and it is corroborated (foreign fingerprint or inside a confirmed span). Reachability never
    // originates from a pure-FID caller, so empty confirmation adds nothing.
    loop {
        let mut changed = false;
        for f in &facts.fns {
            if is_foreign(f.va, &fid_foreign, &band_derived) || rejected.contains(&f.va) || f.callers.is_empty() {
                continue;
            }
            let all_foreign = f.callers.iter().all(|c| is_foreign(*c, &fid_foreign, &band_derived));
            let from_band = f.callers.iter().any(|c| band_derived.contains(c));
            if all_foreign && from_band && (f.foreign_fp || in_confirmed_span(f.va)) {
                band_derived.insert(f.va);
                reason.insert(f.va, "reachable-private".to_string());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // Held: reachable from a selected band and only-from-foreign, but uncorroborated (surfaced,
    // not dropped — the CALLIND-incompleteness guard).
    let mut held = Vec::new();
    for f in &facts.fns {
        if !is_foreign(f.va, &fid_foreign, &band_derived)
            && !rejected.contains(&f.va)
            && !f.callers.is_empty()
            && f.callers.iter().any(|c| band_derived.contains(c))
            && f.callers.iter().all(|c| is_foreign(*c, &fid_foreign, &band_derived))
        {
            held.push((f.va, "reachable-only-from-foreign, uncorroborated".to_string()));
        }
    }

    let foreign: HashSet<u64> = fid_foreign.union(&band_derived).copied().collect();

    let mut class = HashMap::new();
    for f in &facts.fns {
        class.insert(
            f.va,
            if foreign.contains(&f.va) { Class::Foreign } else { Class::InScope },
        );
    }
    Classification { class, reason, held, warnings }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_shapes() {
        assert_eq!(anchor_class("AIL_startup()"), Some(AnchorClass::SelfNaming));
        assert_eq!(anchor_class("Error reading int in gamesave.c"), Some(AnchorClass::SourceRef));
        assert_eq!(anchor_class("count.c (1): %d %d"), Some(AnchorClass::SourceRef));
        assert_eq!(anchor_class("DOS/4G  Copyright (C) Rational"), Some(AnchorClass::Banner));
        assert_eq!(anchor_class("DOS/16M Protected Mode Run-Time     Version 2.5"), Some(AnchorClass::Banner));
        assert_eq!(anchor_class("just a normal message"), None);
        // a bare "version" is NOT a banner — a game diagnostic, not a library tag
        assert_eq!(anchor_class("Invalid data file version."), None);
        // a self-naming trace wins over an incidental banner word
        assert_eq!(anchor_class("AIL_set_preference(%d,%d)"), Some(AnchorClass::SelfNaming));
    }

    #[test]
    fn fingerprint_bimodal() {
        // foreign: push esi;edi;ebp; mov ebp,esp  (56 57 55 8b ec)
        assert!(is_foreign_fingerprint(&[0x56, 0x57, 0x55, 0x8b, 0xec]));
        // foreign: mov edx,[esp+4]  (8b 54 24 04)
        assert!(is_foreign_fingerprint(&[0x8b, 0x54, 0x24, 0x04, 0x52]));
        // game __watcall: push ebx;ecx;edx  (53 51 52)
        assert!(!is_foreign_fingerprint(&[0x53, 0x51, 0x52, 0x55, 0x89, 0xe5]));
        // game framed: push ebp; mov ebp,esp (55 89 e5) then local use, no stack-arg read
        assert!(!is_foreign_fingerprint(&[0x55, 0x89, 0xe5, 0x31, 0xd2]));
        // [esp+0]..[esp+3] are locals/retaddr, not args -> not a stack-arg read
        assert!(!is_foreign_fingerprint(&[0x8b, 0x44, 0x24, 0x00]));
    }

    #[test]
    fn confirmation_parse() {
        // The human names STRINGS, never addresses.
        let c = Confirmation::parse(
            "# header\nforeign AIL_ Miles audio\nreject  Build.c the game's own module\n\n",
        );
        assert_eq!(c.foreign.len(), 1);
        assert_eq!(c.foreign[0].pattern, "AIL_");
        assert_eq!(c.foreign[0].label, "Miles audio");
        assert_eq!(c.reject.len(), 1);
        assert_eq!(c.reject[0].pattern, "Build.c");
        assert_eq!(c.foreign_label("AIL_startup()"), Some("Miles audio"));
        assert_eq!(c.foreign_label("printf()"), None);
        assert!(c.rejects("Error reading Build.c"));
        assert!(!c.rejects("gamesave.c"));
    }

    // Build a tiny synthetic Facts for classify() tests.
    fn mkfn(va: u64, ident: bool, fp: bool, callers: Vec<u64>) -> FnFacts {
        FnFacts {
            va,
            size: 16,
            lo: va,
            hi: va + 15,
            identified: ident,
            name: if ident { "memcpy_".into() } else { format!("FUN_{va:08x}") },
            prologue: if fp { vec![0x56, 0x57] } else { vec![0x53, 0x51] },
            foreign_fp: fp,
            callees: Vec::new(),
            callers,
            anchor: None,
        }
    }
    fn facts_of(fns: Vec<FnFacts>) -> Facts {
        let index = fns.iter().enumerate().map(|(i, f)| (f.va, i)).collect();
        Facts { fns, index }
    }
    fn mkfn_anchored(va: u64, class: AnchorClass, text: &str) -> FnFacts {
        let mut f = mkfn(va, false, false, vec![]);
        f.anchor = Some(Anchor { target: 0, text: text.to_string(), class });
        f
    }

    #[test]
    fn source_ref_band_proposed_but_not_auto_foreign() {
        // A `.c` source-ref names a module that may be the GAME's own (Descent's gamesave.c). The
        // proposer surfaces a band for review, but an empty confirmation NEVER auto-classifies it
        // foreign — the overtraining guard, as a regression test so it cannot drift.
        let facts = facts_of(vec![
            mkfn_anchored(0x2000, AnchorClass::SourceRef, "Invalid station type in fuelcen.c"),
            mkfn_anchored(0x2040, AnchorClass::SourceRef, "Error in fuelcen.c line 12"),
        ]);
        let bands = propose_bands(&facts, 0x2000);
        assert!(bands.iter().any(|b| b.class == AnchorClass::SourceRef));
        let cls = classify(&facts, &Confirmation::default());
        assert!(!cls.is_foreign(0x2000));
        assert!(!cls.is_foreign(0x2040));
        assert_eq!(cls.foreign_count(), 0);
    }

    #[test]
    fn locality_splits_scattered_anchors_from_a_tight_band() {
        // Six tight self-naming anchors = one module band; a lone far-away anchor stays its own
        // singleton (locality, not name, is the key — the load-bearing step).
        let mut fns: Vec<FnFacts> = (0..6)
            .map(|k| mkfn_anchored(0x5000 + k * 0x40, AnchorClass::SelfNaming, "AIL_thing()"))
            .collect();
        fns.push(mkfn_anchored(0x9000, AnchorClass::SelfNaming, "printf_wrapper()"));
        let facts = facts_of(fns);
        let bands = propose_bands(&facts, 0x2000);
        assert_eq!(bands.len(), 2);
        assert_eq!(bands[0].seeds.len(), 6); // ranked by seed count
        assert_eq!(bands[1].seeds.len(), 1);
    }

    #[test]
    fn empty_confirmation_is_fid_only() {
        // default-safe: only FID-identified functions are foreign, nothing else moves.
        let facts = facts_of(vec![
            mkfn(0x1000, true, false, vec![]),   // FID lib
            mkfn(0x2000, false, true, vec![]),   // game (foreign-fp but no evidence)
            mkfn(0x3000, false, false, vec![]),
        ]);
        let cls = classify(&facts, &Confirmation::default());
        assert!(cls.is_foreign(0x1000));
        assert!(!cls.is_foreign(0x2000));
        assert!(!cls.is_foreign(0x3000));
        assert_eq!(cls.foreign_count(), 1);
    }

    #[test]
    fn empty_confirmation_no_fid_reachability() {
        // A FID lib (0x1000) calls a private, foreign-fingerprinted helper (0x1100). With an EMPTY
        // confirmation the helper is NOT pulled — FID never drives reachability, so the result is
        // exactly today's is_identified set (the "changes nothing" guarantee).
        let facts = facts_of(vec![
            mkfn(0x1000, true, true, vec![]),
            mkfn(0x1100, false, true, vec![0x1000]),
        ]);
        let cls = classify(&facts, &Confirmation::default());
        assert!(cls.is_foreign(0x1000));
        assert!(!cls.is_foreign(0x1100));
        assert!(cls.held.is_empty());
        assert_eq!(cls.foreign_count(), 1);
    }

    #[test]
    fn confirmed_band_and_reachability_and_shared() {
        // The human selects the STRING "AIL_"; the engine resolves it to the band seeded at 0x5000,
        // which calls a private helper 0x5100 (only caller) and a shared helper 0x5200 (also called
        // by game 0x9000). Private+fp -> foreign; shared -> in scope. No address is authored.
        let facts = facts_of(vec![
            mkfn_anchored(0x5000, AnchorClass::SelfNaming, "AIL_start()"), // band seed (by string)
            mkfn(0x5100, false, true, vec![0x5000]),   // private, fp -> foreign
            mkfn(0x5200, false, true, vec![0x5000, 0x9000]), // shared -> in scope
            mkfn(0x9000, false, false, vec![]),        // game caller
        ]);
        let conf = Confirmation::parse("foreign AIL_ Miles audio");
        let cls = classify(&facts, &conf);
        assert!(cls.is_foreign(0x5000));
        assert!(cls.is_foreign(0x5100));
        assert!(!cls.is_foreign(0x5200)); // shared helper never dropped
        assert!(!cls.is_foreign(0x9000));
    }

    #[test]
    fn reachable_uncorroborated_is_held_not_dropped() {
        // "AIL_" band seeded at 0x5000; helper 0x5100 is reachable only from it but has a GAME
        // fingerprint -> held, not classified foreign (CALLIND guard).
        let facts = facts_of(vec![
            mkfn_anchored(0x5000, AnchorClass::SelfNaming, "AIL_start()"),
            mkfn(0x5100, false, false, vec![0x5000]), // fp=false -> uncorroborated
        ]);
        let conf = Confirmation::parse("foreign AIL_ Miles audio");
        let cls = classify(&facts, &conf);
        assert!(cls.is_foreign(0x5000));
        assert!(!cls.is_foreign(0x5100));
        assert!(cls.held.iter().any(|(va, _)| *va == 0x5100));
    }

    #[test]
    fn reject_overrides_fid() {
        // Reject matches the FID name (0x1000 is named `memcpy_`), so the human can veto a match.
        let facts = facts_of(vec![mkfn(0x1000, true, false, vec![])]);
        let conf = Confirmation::parse("reject memcpy actually the game's");
        let cls = classify(&facts, &conf);
        assert!(!cls.is_foreign(0x1000)); // reject wins over FID
    }

    #[test]
    fn unanchored_span_member_gets_band_reason() {
        // A confirmed band's span covers a silent module member with no anchor of its own; it must
        // be marked foreign with a `band:` reason, not left in scope.
        let facts = facts_of(vec![
            mkfn_anchored(0x5000, AnchorClass::SelfNaming, "AIL_a()"),
            mkfn(0x5040, false, false, vec![]), // unanchored, silent, inside the span
            mkfn_anchored(0x5080, AnchorClass::SelfNaming, "AIL_b()"),
        ]);
        let cls = classify(&facts, &Confirmation::parse("foreign AIL_ Miles"));
        assert!(cls.is_foreign(0x5040));
        assert!(cls.reason.get(&0x5040).unwrap().starts_with("band:"));
    }

    #[test]
    fn broad_pattern_matching_multiple_bands_warns() {
        // "lib" matches anchors in two far-apart bands -> warning (both still confirmed).
        let facts = facts_of(vec![
            mkfn_anchored(0x2000, AnchorClass::SelfNaming, "libfoo_init()"),
            mkfn_anchored(0x9000, AnchorClass::SelfNaming, "libbar_init()"),
        ]);
        let cls = classify(&facts, &Confirmation::parse("foreign lib both libs"));
        assert!(cls.is_foreign(0x2000) && cls.is_foreign(0x9000));
        assert!(cls.warnings.iter().any(|w| w.contains("2 bands")));
    }
}
