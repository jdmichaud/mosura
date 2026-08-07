//! Stage 4 gate (`docs/fid-port-plan.md` §5): the matcher's scoring, culling and apply rules.
//!
//! Ghidra-free by construction — the scoring is arithmetic over constants, so every case here
//! is a hand-built database and a hand-computed expectation. Each test names the specific rule
//! it pins and is built so it *can* fail: thresholds are probed from **both sides**, and each
//! flag is tested against the same record without the flag.

use mosura::analysis::fid::hash::FidHashQuad;
use mosura::analysis::fid::matcher::{
    apply_name, collapse_names, flags, inferior_full_hash_smash, superior_full_hash_smash,
    FidQuery, FunctionRecord, HashFamily, MatchMode, SearchResult, Seeker,
    MULTINAME_SCORE_THRESHOLD, SCORE_THRESHOLD,
};

const FULL: u64 = 0xaaaa_bbbb_cccc_dddd;
const SPEC: u64 = 0x1111_2222_3333_4444;

fn quad(code_unit_size: i16, full: u64, add: i8, spec: u64) -> FidHashQuad {
    FidHashQuad {
        code_unit_size,
        full_hash: full,
        specific_hash_additional_size: add,
        specific_hash: spec,
    }
}

fn record(name: &str, code_unit_size: i16, add: i8, flags: u8) -> FunctionRecord {
    FunctionRecord {
        key: 1,
        code_unit_size,
        full_hash: FULL,
        specific_hash_additional_size: add,
        specific_hash: SPEC,
        library_id: 7,
        name_id: 1,
        name: name.to_string(),
        flags,
    }
}

/// A hand-built database: a set of records plus explicit relation keys.
#[derive(Default)]
struct Db {
    records: Vec<FunctionRecord>,
    superior: Vec<i64>,
    inferior: Vec<i64>,
}

impl FidQuery for Db {
    fn functions_by_full_hash(&self, full_hash: u64) -> Vec<FunctionRecord> {
        self.records.iter().filter(|r| r.full_hash == full_hash).cloned().collect()
    }
    fn superior_full_relation(&self, superior: &FunctionRecord, inferior_full_hash: u64) -> bool {
        self.superior.contains(&superior_full_hash_smash(superior.key, inferior_full_hash))
    }
    fn inferior_full_relation(&self, superior_full_hash: u64, inferior: &FunctionRecord) -> bool {
        self.inferior.contains(&inferior_full_hash_smash(inferior.key, superior_full_hash))
    }
}

fn family(code_unit_size: i16, spec: u64) -> HashFamily {
    HashFamily { hash: Some(quad(code_unit_size, FULL, 3, spec)), ..Default::default() }
}

// ---------------------------------------------------------------------------------------
// Candidate lookup
// ---------------------------------------------------------------------------------------

/// Candidates come from the **full hash only**. A record whose specific hash matches but whose
/// full hash does not is never even considered — the specific hash refines, it does not fetch.
#[test]
fn candidates_come_from_the_full_hash_only() {
    let mut other = record("other", 40, 3, 0);
    other.full_hash = 0xdead_beef_dead_beef; // different full hash, same specific hash
    let db = Db { records: vec![record("wanted", 40, 3, 0), other], ..Default::default() };

    let matches = Seeker::new(&db).lookup_family(&family(40, SPEC));
    assert_eq!(matches.len(), 1, "only the full-hash candidate is fetched");
    assert_eq!(matches[0].record.name, "wanted");
}

// ---------------------------------------------------------------------------------------
// The 14.6 threshold, probed from both sides
// ---------------------------------------------------------------------------------------

/// `functionScore = codeUnitSize + 0.67 * specificAddSize`, rejected below `14.6`.
///
/// With no specific match, 14 code units scores 14.0 (rejected) and 15 scores 15.0 (accepted) —
/// so the boundary is exercised in both directions rather than assumed.
#[test]
fn score_threshold_is_probed_from_both_sides() {
    for (size, expected) in [(14i16, false), (15, true)] {
        // A deliberately different specific hash, so only the code-unit size counts.
        let db = Db { records: vec![record("f", size, 3, 0)], ..Default::default() };
        let got = Seeker::new(&db).process_matches(&family(size, 0xffff)).is_some();
        assert_eq!(got, expected, "{size} code units, no specific match (threshold {SCORE_THRESHOLD})");
    }
}

/// The specific-hash bonus is what carries a body that would otherwise fall short:
/// 14 code units + 0.67 × 1 = 14.67, over the 14.6 bar. A single agreeing constant flips it.
#[test]
fn specific_hash_bonus_can_carry_a_borderline_match() {
    let db = Db { records: vec![record("f", 14, 1, 0)], ..Default::default() };
    let seeker = Seeker::new(&db);

    // Specific hash agrees: 14 + 0.67 = 14.67 >= 14.6.
    let matched = seeker.process_matches(&family(14, SPEC)).expect("14.67 clears the bar");
    let m = &matched.matches()[0];
    assert_eq!(m.mode, MatchMode::Specific);
    assert!((m.function_score - 14.67).abs() < 1e-4, "score was {}", m.function_score);

    // Specific hash differs: 14.0 < 14.6.
    assert!(
        seeker.process_matches(&family(14, 0xffff)).is_none(),
        "without the specific match the same record falls short"
    );
}

// ---------------------------------------------------------------------------------------
// The record flags
// ---------------------------------------------------------------------------------------

/// `autoFail` — never returned, however well it scores.
#[test]
fn auto_fail_is_never_returned() {
    let big = 100i16;
    let plain = Db { records: vec![record("f", big, 3, 0)], ..Default::default() };
    assert!(Seeker::new(&plain).process_matches(&family(big, SPEC)).is_some(), "control");

    let failed = Db { records: vec![record("f", big, 3, flags::AUTO_FAIL)], ..Default::default() };
    assert!(Seeker::new(&failed).process_matches(&family(big, SPEC)).is_none());
}

/// `autoPass` raises a tiny record's own score to the medium-hash floor of 24, so a function
/// too small to clear 14.6 on its own is still identified.
#[test]
fn auto_pass_floors_the_score_at_the_medium_hash_length() {
    let tiny = 5i16;
    let plain = Db { records: vec![record("f", tiny, 0, 0)], ..Default::default() };
    assert!(
        Seeker::new(&plain).process_matches(&family(tiny, 0xffff)).is_none(),
        "5 code units is below the bar without autoPass"
    );

    let passed = Db { records: vec![record("f", tiny, 0, flags::AUTO_PASS)], ..Default::default() };
    let m = Seeker::new(&passed).process_matches(&family(tiny, 0xffff)).expect("autoPass");
    assert_eq!(m.matches()[0].function_score, 24.0, "floored to MEDIUM_HASH_CODE_UNIT_LENGTH");
}

/// `forceSpecific` — a full-hash-only match is rejected; the same record with the specific
/// hash agreeing is accepted.
#[test]
fn force_specific_requires_the_specific_hash() {
    let db = Db { records: vec![record("f", 40, 3, flags::FORCE_SPECIFIC)], ..Default::default() };
    let seeker = Seeker::new(&db);
    assert!(seeker.process_matches(&family(40, 0xffff)).is_none(), "full-hash only is rejected");
    assert!(seeker.process_matches(&family(40, SPEC)).is_some(), "specific match is accepted");
}

/// `forceRelation` — rejected unless a callee also matched. This is the rule that disambiguates
/// the short, near-identical bodies a byte search cannot separate.
#[test]
fn force_relation_requires_a_matching_child() {
    let callee = quad(20, 0x5555_5555_5555_5555, 0, 0);
    let rec = record("f", 40, 3, flags::FORCE_RELATION);

    // No relations recorded: rejected despite a healthy score.
    let bare = Db { records: vec![rec.clone()], ..Default::default() };
    let mut fam = family(40, SPEC);
    fam.children = vec![callee];
    assert!(Seeker::new(&bare).process_matches(&fam).is_none(), "no child relation");

    // The database records that this function calls something hashing like `callee`.
    let linked = Db {
        records: vec![rec],
        superior: vec![superior_full_hash_smash(1, callee.full_hash)],
        ..Default::default()
    };
    let m = Seeker::new(&linked).process_matches(&fam).expect("child relation present");
    assert_eq!(m.matches()[0].child_score, 20.0, "the callee's code units are added");
}

// ---------------------------------------------------------------------------------------
// Relation scoring
// ---------------------------------------------------------------------------------------

/// Callers and callees both contribute their code-unit sizes, which is what lets a small
/// function be identified by the company it keeps: 5 code units alone is far below 14.6, but
/// with a matching caller and callee it clears the bar.
#[test]
fn relations_can_carry_a_function_too_small_to_stand_alone() {
    let child = quad(12, 0x1111_1111_1111_1111, 0, 0);
    let parent = quad(30, 0x2222_2222_2222_2222, 0, 0);
    let rec = record("small", 5, 0, 0);

    let mut fam = family(5, 0xffff);
    fam.children = vec![child];
    fam.parents = vec![parent];

    let alone = Db { records: vec![rec.clone()], ..Default::default() };
    assert!(Seeker::new(&alone).process_matches(&fam).is_none(), "5.0 alone is below 14.6");

    let related = Db {
        records: vec![rec],
        superior: vec![superior_full_hash_smash(1, child.full_hash)],
        inferior: vec![inferior_full_hash_smash(1, parent.full_hash)],
    };
    let m = Seeker::new(&related).process_matches(&fam).expect("relations carry it");
    let m = &m.matches()[0];
    assert_eq!(m.function_score, 5.0);
    assert_eq!(m.child_score, 12.0);
    assert_eq!(m.parent_score, 30.0);
    assert_eq!(m.overall_score(), 47.0);
}

/// Beyond 500 callers the parent score is skipped entirely — the signal is noise at that point,
/// and Ghidra refuses to pay for it.
#[test]
fn parent_score_is_skipped_past_the_cutoff() {
    let parent = quad(30, 0x2222_2222_2222_2222, 0, 0);
    let db = Db {
        records: vec![record("f", 40, 3, 0)],
        inferior: vec![inferior_full_hash_smash(1, parent.full_hash)],
        ..Default::default()
    };
    let seeker = Seeker::new(&db);

    let mut just_under = family(40, SPEC);
    just_under.parents = vec![parent; 499];
    let m = seeker.process_matches(&just_under).expect("match");
    assert_eq!(m.matches()[0].parent_score, 499.0 * 30.0, "499 parents are scored");

    let mut at_cutoff = family(40, SPEC);
    at_cutoff.parents = vec![parent; 500];
    let m = seeker.process_matches(&at_cutoff).expect("match");
    assert_eq!(m.matches()[0].parent_score, 0.0, "500 parents are skipped entirely");
}

/// The two relation smashes are the **same arithmetic** — `key * FNV_PRIME ^ otherFullHash` —
/// and are told apart by *which* function supplies each half, plus which table the key lands
/// in. For a caller C and callee E the superior key is `key(C) ^ hash(E)` while the inferior
/// key is `key(E) ^ hash(C)`, so a relation recorded in one direction does not answer a query
/// in the other.
#[test]
fn relation_keys_distinguish_direction_by_their_arguments() {
    let (caller_key, caller_hash) = (0x1111_1111i64, 0xaaaa_aaaa_aaaa_aaaau64);
    let (callee_key, callee_hash) = (0x2222_2222i64, 0xbbbb_bbbb_bbbb_bbbbu64);

    let superior = superior_full_hash_smash(caller_key, callee_hash);
    let inferior = inferior_full_hash_smash(callee_key, caller_hash);
    assert_ne!(superior, inferior, "the two directions key differently for the same pair");

    // Both halves genuinely participate: change either and the key moves.
    assert_ne!(superior, superior_full_hash_smash(caller_key + 1, callee_hash), "key matters");
    assert_ne!(superior, superior_full_hash_smash(caller_key, callee_hash ^ 1), "hash matters");

    // Same formula, by construction — documented so the equality is not mistaken for a bug.
    assert_eq!(
        superior_full_hash_smash(caller_key, callee_hash),
        inferior_full_hash_smash(caller_key, callee_hash),
        "identical arithmetic; only the arguments and the destination table differ"
    );
}

// ---------------------------------------------------------------------------------------
// Culling and the apply gate
// ---------------------------------------------------------------------------------------

/// Only candidates tied at the top score survive; anything scoring lower is dropped.
#[test]
fn cull_keeps_only_the_top_score() {
    let db = Db {
        records: vec![
            record("winner", 40, 3, 0),
            {
                let mut r = record("tied", 40, 3, 0);
                r.key = 2;
                r
            },
            {
                let mut r = record("loser", 20, 3, 0);
                r.key = 3;
                r
            },
        ],
        ..Default::default()
    };
    let result = Seeker::new(&db).process_matches(&family(40, SPEC)).expect("matches");
    let names: Vec<&str> = result.matches().iter().map(|m| m.record.name.as_str()).collect();
    assert_eq!(names.len(), 2, "the lower-scoring candidate is culled: {names:?}");
    assert!(names.contains(&"winner") && names.contains(&"tied"));
}

/// Names collapse across a leading-underscore difference — `_strcpy`, `__strcpy` and `strcpy`
/// are one name — but genuinely different names do not collapse.
#[test]
fn names_collapse_across_underscores_only() {
    let mk = |n: &str, k: i64| {
        let mut r = record(n, 40, 3, 0);
        r.key = k;
        r
    };
    let db = Db { records: vec![mk("_strcpy", 1), mk("__strcpy", 2)], ..Default::default() };
    let result = Seeker::new(&db).process_matches(&family(40, SPEC)).expect("matches");
    assert_eq!(collapse_names(result.matches()).as_deref(), Some("strcpy"));

    let db = Db { records: vec![mk("strcpy", 1), mk("memcpy", 2)], ..Default::default() };
    let result = Seeker::new(&db).process_matches(&family(40, SPEC)).expect("matches");
    assert_eq!(collapse_names(result.matches()), None, "different functions do not collapse");
}

/// **The apply gate.** When names cannot be collapsed, the top score must additionally reach
/// 30 — otherwise nothing is applied at all. A wrong name is worse than no name, and this is
/// the rule that enforces it.
#[test]
fn multi_name_matches_need_the_higher_threshold() {
    let mk = |n: &str, k: i64, size: i16| {
        let mut r = record(n, size, 0, 0);
        r.key = k;
        r
    };

    // Two irreconcilable names at 20 code units: over 14.6, under 30 → apply nothing.
    let db = Db { records: vec![mk("alpha", 1, 20), mk("beta", 2, 20)], ..Default::default() };
    let result = Seeker::new(&db).process_matches(&family(20, 0xffff)).expect("matches");
    assert_eq!(result.matches().len(), 2);
    assert_eq!(apply_name(&result), None, "20 < {MULTINAME_SCORE_THRESHOLD}, so no name is applied");

    // The same disagreement at 40 code units clears the higher bar... but still has no single
    // name to apply, so nothing is written either way.
    let db = Db { records: vec![mk("alpha", 1, 40), mk("beta", 2, 40)], ..Default::default() };
    let result = Seeker::new(&db).process_matches(&family(40, 0xffff)).expect("matches");
    assert_eq!(apply_name(&result), None, "no collapsed name to apply");

    // A single unambiguous match applies at any score above 14.6.
    let db = Db { records: vec![mk("strlen", 1, 20)], ..Default::default() };
    let result = Seeker::new(&db).process_matches(&family(20, 0xffff)).expect("match");
    assert!(matches!(result, SearchResult::Singleton(_)));
    assert_eq!(apply_name(&result).as_deref(), Some("strlen"));
}
