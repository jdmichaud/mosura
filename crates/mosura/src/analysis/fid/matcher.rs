//! The FID matcher/scorer — a faithful port of `service/FidProgramSeeker.java`
//! (+ `service/HashMatch.java`, `service/FidMatchScore.java`, `db/FidDBUtils.java`'s relation
//! keys, and the apply gate of `cmd/ApplyFidEntriesCommand.java:105-120`).
//!
//! Given a function's hash quad and the quads of its callees and callers, find the database
//! records that could be it, score them, and decide whether the answer is confident enough to
//! apply.
//!
//! **Candidates come from the full hash only** (`lookupFamily`, `:380-399`). The specific hash
//! never fetches; it only *refines the score* of a candidate already found. That is what lets a
//! function still be identified when a constant in its body differs.
//!
//! The score is a code-unit count, so it reads as "how much matched": the body's own size,
//! plus two thirds of a code unit per real scalar the specific hash agreed on, plus the sizes
//! of every callee and caller that also matched. Small leaf functions score low and are
//! rejected; a small function surrounded by matching neighbours can still clear the bar.

use std::collections::HashMap;

use super::hash::{FidHashQuad, FNV_64_PRIME};

/// `FidService.MEDIUM_HASH_CODE_UNIT_LENGTH` (`:46`) — the floor an `autoPass` record's own
/// score is raised to, so a deliberately-marked tiny function can still be identified.
pub const MEDIUM_HASH_CODE_UNIT_LENGTH: i32 = 24;
/// `FidService.SCORE_THRESHOLD` (`:47`) — total score a match must reach to be reported.
pub const SCORE_THRESHOLD: f32 = 14.6;
/// `FidService.MULTINAME_SCORE_THRESHOLD` (`:48`) — the *extra* bar a match must clear when the
/// surviving names cannot be collapsed to one.
pub const MULTINAME_SCORE_THRESHOLD: f32 = 30.0;
/// `FidProgramSeeker.MAX_NUM_PARENTS_FOR_SCORE` (`:49`) — beyond this many callers the parent
/// score is skipped entirely (it is noise, and expensive).
pub const MAX_NUM_PARENTS_FOR_SCORE: usize = 500;
/// `FidProgramSeeker.java:361` — each agreeing specific constant is worth two thirds of a code
/// unit.
pub const SPECIFIC_SCORE_WEIGHT: f32 = 0.67;

/// `FunctionRecord` flag bits (`db/FunctionRecord.java:30-34`).
pub mod flags {
    pub const HAS_TERMINATOR: u8 = 1;
    /// A full-hash match is always returned, even if the function is tiny.
    pub const AUTO_PASS: u8 = 2;
    /// A full-hash match is never returned, even though the record is still in the database.
    pub const AUTO_FAIL: u8 = 4;
    /// A full-hash match is returned only if the specific hash matched too.
    pub const FORCE_SPECIFIC: u8 = 8;
    /// A full-hash match is returned only if a parent or child also matched.
    pub const FORCE_RELATION: u8 = 16;
}

/// One candidate from the database — a row of the functions table, as the matcher needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionRecord {
    /// The record's primary key, which is also half of every relation key.
    pub key: i64,
    pub code_unit_size: i16,
    pub full_hash: u64,
    pub specific_hash_additional_size: i8,
    pub specific_hash: u64,
    pub library_id: i64,
    pub name_id: i64,
    pub name: String,
    pub flags: u8,
}

impl FunctionRecord {
    pub fn auto_pass(&self) -> bool {
        self.flags & flags::AUTO_PASS != 0
    }
    pub fn auto_fail(&self) -> bool {
        self.flags & flags::AUTO_FAIL != 0
    }
    pub fn is_force_specific(&self) -> bool {
        self.flags & flags::FORCE_SPECIFIC != 0
    }
    pub fn is_force_relation(&self) -> bool {
        self.flags & flags::FORCE_RELATION != 0
    }
}

/// Whether a candidate matched on the full hash alone or on the specific hash too
/// (`service/HashLookupListMode.java`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    Full,
    Specific,
}

/// A function's own quad plus the quads of everything it calls and everything that calls it
/// (`service/HashFamily.java`). The relations are what let a small function be identified.
#[derive(Debug, Clone, Default)]
pub struct HashFamily {
    pub hash: Option<FidHashQuad>,
    pub children: Vec<FidHashQuad>,
    pub parents: Vec<FidHashQuad>,
}

/// A scored candidate (`service/HashMatch.java`).
#[derive(Debug, Clone)]
pub struct HashMatch {
    pub record: FunctionRecord,
    pub function_score: f32,
    pub mode: MatchMode,
    pub child_score: f32,
    pub parent_score: f32,
}

impl HashMatch {
    /// `HashMatch.getOverallScore` (`:74-77`).
    pub fn overall_score(&self) -> f32 {
        self.function_score + self.child_score + self.parent_score
    }
}

/// The database side the matcher consults.
pub trait FidQuery {
    /// `findFunctionsByFullHash` — every record whose **full** hash equals this one.
    fn functions_by_full_hash(&self, full_hash: u64) -> Vec<FunctionRecord>;

    /// `getSuperiorFullRelation(superior, inferior)` — does the database record that
    /// `superior` calls something hashing like `inferior`?
    fn superior_full_relation(&self, superior: &FunctionRecord, inferior_full_hash: u64) -> bool;

    /// `getInferiorFullRelation(superior, inferior)` — does the database record that something
    /// hashing like `superior` calls `inferior`?
    fn inferior_full_relation(&self, superior_full_hash: u64, inferior: &FunctionRecord) -> bool;
}

/// `FidDBUtils.generateSuperiorFullHashSmash` (`:32-36,56-60`) — the caller's **key** mixed
/// with the callee's **full hash**. Presence of this key in the superior table *is* the
/// relation; the table has no columns.
pub fn superior_full_hash_smash(superior_key: i64, inferior_full_hash: u64) -> i64 {
    let hash_value = (superior_key as u64).wrapping_mul(FNV_64_PRIME);
    (hash_value ^ inferior_full_hash) as i64
}

/// `FidDBUtils.generateInferiorFullHashSmash` (`:44-48,68-72`) — the callee's **key** mixed
/// with the caller's **full hash**.
pub fn inferior_full_hash_smash(inferior_key: i64, superior_full_hash: u64) -> i64 {
    let hash_value = (inferior_key as u64).wrapping_mul(FNV_64_PRIME);
    (hash_value ^ superior_full_hash) as i64
}

/// The outcome of matching one function.
#[derive(Debug, Clone)]
pub enum SearchResult {
    /// Exactly one candidate survived the cull.
    Singleton(HashMatch),
    /// Several candidates tied at the top score.
    Multiple(Vec<HashMatch>),
}

impl SearchResult {
    pub fn matches(&self) -> &[HashMatch] {
        match self {
            SearchResult::Singleton(m) => std::slice::from_ref(m),
            SearchResult::Multiple(v) => v,
        }
    }
}

/// `FidProgramSeeker`.
pub struct Seeker<'a> {
    query: &'a dyn FidQuery,
    score_threshold: f32,
    medium_hash_code_unit_limit: i32,
}

impl<'a> Seeker<'a> {
    pub fn new(query: &'a dyn FidQuery) -> Seeker<'a> {
        Seeker {
            query,
            score_threshold: SCORE_THRESHOLD,
            medium_hash_code_unit_limit: MEDIUM_HASH_CODE_UNIT_LENGTH,
        }
    }

    /// `scoreMatch` (`:314-372`). `None` where Ghidra returns `null`: an `autoFail` record, a
    /// `forceSpecific` record whose specific hash did not match, a `forceRelation` record with
    /// no matching child, or a total below the threshold.
    pub fn score_match(&self, record: &FunctionRecord, family: &HashFamily) -> Option<HashMatch> {
        if record.auto_fail() {
            return None;
        }
        let hash = family.hash.as_ref()?;

        let mut function_code_units = i32::from(record.code_unit_size);
        let mut specific_code_units = 0i32;
        let mut mode = MatchMode::Full;

        // The specific hash refines an existing candidate; it never fetches one.
        if record.specific_hash == hash.specific_hash {
            specific_code_units = i32::from(record.specific_hash_additional_size);
            mode = MatchMode::Specific;
        }

        if record.is_force_specific() && mode != MatchMode::Specific {
            return None;
        }
        if record.auto_pass() && function_code_units < self.medium_hash_code_unit_limit {
            function_code_units = self.medium_hash_code_unit_limit;
        }

        // Every callee whose hash the database records this function as calling.
        let mut child_code_units = 0i32;
        for child in &family.children {
            if self.query.superior_full_relation(record, child.full_hash) {
                child_code_units += i32::from(child.code_unit_size);
            }
        }
        if record.is_force_relation() && child_code_units == 0 {
            return None;
        }

        // Callers, unless there are so many that the signal is noise (`:351`).
        let mut parent_code_units = 0i32;
        if family.parents.len() < MAX_NUM_PARENTS_FOR_SCORE {
            for parent in &family.parents {
                if self.query.inferior_full_relation(parent.full_hash, record) {
                    parent_code_units += i32::from(parent.code_unit_size);
                }
            }
        }

        let function_score =
            function_code_units as f32 + SPECIFIC_SCORE_WEIGHT * specific_code_units as f32;
        let child_score = child_code_units as f32;
        let parent_score = parent_code_units as f32;

        if function_score + child_score + parent_score < self.score_threshold {
            return None;
        }

        Some(HashMatch {
            record: record.clone(),
            function_score,
            mode,
            child_score,
            parent_score,
        })
    }

    /// `lookupFamily` (`:380-399`) — score every full-hash candidate, most significant first.
    pub fn lookup_family(&self, family: &HashFamily) -> Vec<HashMatch> {
        let Some(hash) = family.hash.as_ref() else { return Vec::new() };
        let mut result: Vec<HashMatch> = self
            .query
            .functions_by_full_hash(hash.full_hash)
            .iter()
            .filter_map(|r| self.score_match(r, family))
            .collect();
        // `MOST_SIGNIFICANT` (`:41-47`) — descending overall score. Ghidra's comparator returns
        // 0 for equal scores and `Collections.sort` is stable, so ties keep lookup order.
        result.sort_by(|a, b| {
            b.overall_score().partial_cmp(&a.overall_score()).unwrap_or(std::cmp::Ordering::Equal)
        });
        result
    }

    /// `processMatches` (`:212-243`) — keep only the candidates tied at the top score.
    ///
    /// The cull is a strict `<` break over the sorted list, so anything scoring *equal* to the
    /// best survives and anything below is dropped the moment it appears.
    pub fn process_matches(&self, family: &HashFamily) -> Option<SearchResult> {
        let matches = self.lookup_family(family);
        if matches.is_empty() {
            return None;
        }
        if matches.len() == 1 {
            return Some(SearchResult::Singleton(matches.into_iter().next().unwrap()));
        }

        let max_overall = matches[0].overall_score();
        let mut culled = Vec::with_capacity(1);
        for m in matches {
            if m.overall_score() < max_overall && !culled.is_empty() {
                break;
            }
            culled.push(m);
        }
        if culled.len() == 1 {
            Some(SearchResult::Singleton(culled.into_iter().next().unwrap()))
        } else {
            Some(SearchResult::Multiple(culled))
        }
    }
}

// ---------------------------------------------------------------------------------------
// Name collapsing (service/MatchNameAnalysis.java + service/NameVersions.java)
// ---------------------------------------------------------------------------------------

/// The name variants Ghidra derives for collapsing (`NameVersions.generate`): the raw symbol,
/// the same with leading underscores stripped, and — for a mangled name — the demangled form
/// with and without template arguments.
///
/// mosura demangles Itanium C++ via `cpp_demangle` elsewhere; the MSVC databases hold MSVC
/// mangling, which is not decoded here. Collapsing therefore works on the raw and
/// underscore-stripped forms, which is what actually separates `_strcpy` / `__strcpy` /
/// `strcpy`. An undecoded mangled name simply fails to collapse and falls to the stricter
/// multi-name gate — the conservative direction.
pub fn name_variants(name: &str) -> Vec<String> {
    let mut out = vec![name.to_string()];
    let stripped = name.trim_start_matches('_');
    if stripped != name && !stripped.is_empty() {
        out.push(stripped.to_string());
    }
    out
}

/// `MatchNameAnalysis` — do the surviving matches agree on a single name?
///
/// Returns `Some(name)` when every match shares a variant, `None` when they genuinely disagree.
/// Ghidra's `getMostOptimisticCount() > 1` is exactly this returning `None`.
pub fn collapse_names(matches: &[HashMatch]) -> Option<String> {
    if matches.is_empty() {
        return None;
    }
    // Count how many distinct matches each candidate variant covers.
    let mut coverage: HashMap<&str, usize> = HashMap::new();
    let variants: Vec<Vec<String>> =
        matches.iter().map(|m| name_variants(&m.record.name)).collect();
    for vs in &variants {
        // A variant is counted once per match even if it appears twice in that match's list.
        let mut seen: Vec<&str> = Vec::new();
        for v in vs {
            if !seen.contains(&v.as_str()) {
                seen.push(v.as_str());
                *coverage.entry(v.as_str()).or_insert(0) += 1;
            }
        }
    }

    let n = matches.len();
    // Prefer the name as written when it is itself common to all; otherwise any shared variant.
    let mut common: Vec<&str> =
        coverage.iter().filter(|(_, &c)| c == n).map(|(&v, _)| v).collect();
    if common.is_empty() {
        return None;
    }
    common.sort_unstable();
    // The longest shared variant is the most specific (`_strcpy` over `strcpy` only when both
    // are shared by every match, which means every match wrote it the same way).
    common.sort_by_key(|v| std::cmp::Reverse(v.len()));
    Some(common[0].to_string())
}

/// `ApplyFidEntriesCommand.processMatches` (`:105-120`) — the gate a result must clear before
/// its name is written onto a function.
///
/// Every match here already scored at least `SCORE_THRESHOLD`. The additional rule is about
/// *confidence in the name*: if the matches cannot be collapsed to one name, the top score must
/// also reach `MULTINAME_SCORE_THRESHOLD`. Below that, Ghidra applies nothing at all rather
/// than guess — which is the behaviour that keeps a wrong name off a function.
pub fn apply_name(result: &SearchResult) -> Option<String> {
    apply_markup(result).name
}

/// What FID decided about a function — `ApplyFidEntriesCommand.processMatches` (`:105-150`) in
/// full, not just the name half.
///
/// **A match that cannot be narrowed to one name still produces markup.** Ghidra calls
/// `applyMarkup(function, newFunctionName, plateComment, bookmark, monitor)` with a NULL name in
/// that case: it declines to rename — two functions with identical code cannot be told apart, and
/// guessing would put a wrong name on one — but it records what it found. Returning only
/// `Option<String>` threw that away, so a recognised-but-ambiguous function was indistinguishable
/// from an unrecognised one. Measured on WAR2: 3 functions are in exactly this state, two of them
/// scoring 75.0 against a pair of names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FidMarkup {
    /// The name to apply, or `None` when the matches cannot be collapsed to one.
    pub name: Option<String>,
    /// The plate comment (`generateComment`: a header line, the matched names, the libraries).
    /// Empty when nothing should be applied at all.
    pub plate: String,
}

pub fn apply_markup(result: &SearchResult) -> FidMarkup {
    let none = FidMarkup { name: None, plate: String::new() };
    let matches = result.matches();
    if matches.is_empty() {
        return none;
    }
    let collapsed = collapse_names(matches);
    if collapsed.is_none() {
        // `getMostOptimisticCount() > 1` — genuinely different base names. Below the multi-name
        // bar Ghidra returns before applying anything, comment included.
        let top = matches.iter().map(HashMatch::overall_score).fold(f32::MIN, f32::max);
        if top < MULTINAME_SCORE_THRESHOLD {
            return none;
        }
    }

    // `generateComment(header)`: header, then up to 4 names, then the libraries.
    let header = if collapsed.is_some() {
        "Library Function - Single Match"
    } else {
        "Library Function - Multiple Matches With Different Base Names"
    };
    let mut names: Vec<&str> = matches.iter().map(|m| m.record.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    let mut plate = String::from(header);
    plate.push('\n');
    for n in names.iter().take(4) {
        plate.push(' ');
        plate.push_str(n);
        plate.push('\n');
    }
    if names.len() > 4 {
        plate.push_str(" ...\n");
    }
    // Ghidra's `generateComment` ends with `listLibraries`, which we omit: a `FunctionRecord`
    // carries `library_id`, and resolving it to a NAME needs the database, which the matcher
    // does not hold. Printing the raw id would be noise, so the line is left out rather than
    // faked — the header and the candidate names are the part that tells a reader what happened.

    FidMarkup { name: collapsed, plate }
}
