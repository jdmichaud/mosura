//! Compiler-**version** detection by signature vote.
//!
//! The usual way to date a binary is an in-band marker — Watcom's run-time copyright banner
//! (`loader/watcom.rs`), Borland's `Borland C++ - Copyright YYYY`, MSVC's rich header. That
//! works where a marker exists and is version-specific. It often is neither: Borland stopped
//! embedding a version string after Turbo C 1.5, so its libraries from 1990 onward carry only
//! `__turboCrt`/`__turboFloat` symbol names, and the copyright year cannot separate Turbo C 1.5
//! from 2.0 (both 1988).
//!
//! Signature databases answer the same question directly, and byte-exactly. A function's hash
//! is derived from the runtime build it came from, so if a binary's functions match
//! `watcom-11.0`'s signatures and not `watcom-10.0a`'s, **that is the version**. Where a
//! marker only dates the era, this identifies the build.
//!
//! It is a *vote*, not a lookup: runtimes share code across releases, so several databases will
//! match something. What distinguishes them is how much. The report keeps every database's
//! score so a near-tie is visible rather than silently resolved — two adjacent point releases
//! genuinely may be indistinguishable in a small binary, and saying so is more useful than
//! picking one.

use std::path::Path;

use super::analyzer::hash_function;
use super::matcher::{HashFamily, Seeker};
use super::query::{FidDatabase, FidQueryService};
use crate::analysis::program::Program;

/// One database's score against a program.
#[derive(Debug, Clone)]
pub struct VersionVote {
    /// The database's name, e.g. `watcom-11.0-x86-32`.
    pub database: String,
    pub library_family: String,
    pub library_version: String,
    /// Debug vs Release, or the memory model for a 16-bit runtime.
    pub library_variant: String,
    /// Functions of the program that matched at least one record in this database.
    pub matched: usize,
    /// Sum of the winning matches' scores — a size-weighted view, so one large agreeing
    /// function counts for more than a handful of tiny ones.
    pub score: f32,
}

/// The outcome of a detection run, most convincing first.
#[derive(Debug, Clone, Default)]
pub struct VersionReport {
    pub votes: Vec<VersionVote>,
    /// Functions the hasher could produce a quad for — the denominator the votes are out of.
    pub hashable_functions: usize,
}

impl VersionReport {
    /// The compiler **family** the vote points at, when it points convincingly.
    ///
    /// For most containers the family comes from metadata — Ghidra's PE opinion, an ELF
    /// `.comment`, a runtime banner. Some formats have none: a raw z80 `.com` is a flat image
    /// with no header, no sections and no symbol table, so there is nothing to read. sdcc also
    /// embeds no version string in compiled output (its `___sdcc_*` helper names live in the
    /// `.rel` objects and are gone once linked). For those, matched signatures are the *only*
    /// evidence available.
    ///
    /// Deliberately conservative, because this is beyond-Ghidra evidence: it answers only on a
    /// clear win — at least three matched functions and twice the runner-up's score. A thin or
    /// close result returns `None` rather than a guess.
    ///
    /// **Additive, never overriding.** This refines the picture the way
    /// [`crate::analysis::loader::compiler_version`] does; it must not replace a faithful
    /// `CompilerOpinion`.
    pub fn family(&self) -> Option<&str> {
        let best = self.votes.first()?;
        if best.matched < 3 {
            return None;
        }
        if self.votes.get(1).is_some_and(|second| second.score * 2.0 > best.score) {
            // Two databases of the same family still agree on the family, even when they
            // disagree on the version.
            if self.votes[1].library_family != best.library_family {
                return None;
            }
        }
        Some(&best.library_family)
    }

    /// The best-scoring database, if anything matched.
    pub fn best(&self) -> Option<&VersionVote> {
        self.votes.first()
    }

    /// Whether the top two are close enough that the answer is "one of these", not "this one".
    ///
    /// Adjacent point releases share most of their runtime, so a small binary genuinely may not
    /// separate them. Reporting the ambiguity is more useful than resolving it arbitrarily —
    /// the same reasoning as the matcher's multi-name gate.
    pub fn is_ambiguous(&self) -> bool {
        match (self.votes.first(), self.votes.get(1)) {
            (Some(a), Some(b)) => b.score >= a.score * 0.95,
            _ => false,
        }
    }
}

/// Score one program against every database in `dir` whose language and compiler spec match.
///
/// Each database is loaded and queried **on its own** — deliberately not merged into one
/// service, because the point is to tell them apart.
pub fn detect_version(program: &Program, dir: &Path) -> VersionReport {
    // Hash every function once; the same quads are scored against each database.
    let quads: Vec<_> = program
        .function_manager
        .functions()
        .map(|f| f.entry_point())
        .filter_map(|e| hash_function(program, e))
        .collect();
    vote(&quads, dir, &program.language_id, &program.compiler_spec_id)
}

/// Score a set of function hashes against every database in `dir` for one language.
///
/// Split out from [`detect_version`] so the vote can be exercised on hashes that did not come
/// from a loaded program — in particular a database's own records, which is how the
/// *discrimination* claim is tested: a database must out-score its neighbours on its own
/// signatures, and that is checkable for every release without a compiler for each one.
pub fn vote(
    quads: &[super::hash::FidHashQuad],
    dir: &Path,
    language_id: &str,
    compiler_spec_id: &str,
) -> VersionReport {
    let mut report = VersionReport::default();
    report.hashable_functions = quads.len();
    if quads.is_empty() {
        return report;
    }

    let Ok(entries) = std::fs::read_dir(dir) else { return report };
    let mut paths: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let n = p.file_name().unwrap_or_default().to_string_lossy();
            n.ends_with(".mfid") || n.ends_with(".mfid.gz") || n.ends_with(".fidb")
        })
        .collect();
    paths.sort();

    for path in paths {
        let Ok(data) = std::fs::read(&path) else { continue };
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let name = name.trim_end_matches(".gz").trim_end_matches(".mfid").trim_end_matches(".fidb");

        let loaded = if data.first() == Some(&0xac) {
            FidDatabase::open_packed(name, &data).ok()
        } else {
            super::store::decompress(&data)
                .ok()
                .and_then(|t| super::store::FidStore::from_text(&t).ok())
                .map(|s| s.into_database(name))
        };
        let Some(database) = loaded else { continue };
        if !database.matches_program(language_id, compiler_spec_id) {
            continue;
        }
        // A database can hold several libraries — Ghidra's `vsOlder` spans Visual Studio 1998
        // through 2010, and each shipped runtime has a Debug and a Release variant. Naming the
        // first one would report whichever happened to be stored first, so the label comes
        // from the libraries the winning records actually belong to.
        let libraries: std::collections::HashMap<i64, (String, String, String)> = database
            .libraries()
            .iter()
            .map(|l| (l.id, (l.family.clone(), l.version.clone(), l.variant.clone())))
            .collect();
        let mut library_hits: std::collections::HashMap<i64, usize> =
            std::collections::HashMap::new();

        let mut service = FidQueryService::new();
        service.attach(database);
        let seeker = Seeker::new(&service);

        let mut matched = 0usize;
        let mut score = 0.0f32;
        for &hash in quads {
            let family = HashFamily { hash: Some(hash), ..Default::default() };
            if let Some(result) = seeker.process_matches(&family) {
                matched += 1;
                score += result
                    .matches()
                    .iter()
                    .map(super::matcher::HashMatch::overall_score)
                    .fold(0.0f32, f32::max);
                for m in result.matches() {
                    *library_hits.entry(m.record.library_id).or_insert(0) += 1;
                }
            }
        }

        if matched > 0 {
            let (family, version, variant) = library_hits
                .iter()
                .max_by_key(|(_, n)| **n)
                .and_then(|(id, _)| libraries.get(id).cloned())
                .unwrap_or_default();
            report.votes.push(VersionVote {
                database: name.to_string(),
                library_family: family,
                library_version: version,
                library_variant: variant,
                matched,
                score,
            });
        }
    }

    report.votes.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    report
}

/// Record a confident signature vote on the program, as a refinement.
///
/// Runs only when a database directory is present and readable, so an installation without
/// signature data is unaffected. **Opt-in by cost**: a vote loads and queries every database of
/// the program's language, which with ~70 databases is not free — so this is a deliberate call
/// a caller makes, not something every analysis pays for.
///
/// Writes [`Program::compiler_signature`] only. `compiler` (Ghidra's faithful `CompilerOpinion`)
/// and `compiler_version` (the embedded marker) are left untouched: this is a second, additive
/// line of evidence, and where the two disagree that disagreement is worth seeing rather than
/// hiding.
pub fn apply_signature_detection(program: &mut Program, dir: &Path) -> Option<String> {
    let report = detect_version(program, dir);
    let best = report.best()?;
    report.family()?; // the confidence gate: a thin or ambiguous vote records nothing
    let label = if best.library_variant.is_empty() {
        format!("{} {}", best.library_family, best.library_version)
    } else {
        format!("{} {} {}", best.library_family, best.library_version, best.library_variant)
    };
    program.compiler_signature = Some(label.clone());
    Some(label)
}
