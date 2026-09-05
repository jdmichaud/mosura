//! **The discrimination gate**: every shipped database must win the vote on its own signatures.
//!
//! Version detection had been verified end-to-end on exactly two binaries — a VC6 probe and a
//! Turbo C 2.0 program. Every other release was believed to work "by construction", which is
//! the assumption this track has had wrong repeatedly. Compiling a probe with each of fifteen
//! historical toolchains is not practical (most are not staged, and several will not run under
//! dosemu), but the claim that actually needs testing does not require one.
//!
//! The claim is *discrimination*: can the vote tell Turbo C 2.0 from 2.01, Watcom 10.6 from
//! 11.0, Borland C++ 4.5 from 4.52? Those releases share most of their runtime, so a vote that
//! merely matched "something Borland" would be useless. Scoring a database's own records
//! against the whole set answers exactly that — a database trivially matches itself, but
//! whether it **out-scores its neighbours** is not trivial at all, and is the property the
//! feature rests on.
//!
//! Ghidra-free: the inputs are the databases mosura built.

use std::collections::BTreeMap;

use mosura::analysis::fid::detect::vote;
use mosura::analysis::fid::hash::FidHashQuad;
use mosura::analysis::fid::store;
use mosura::paths;

fn db_dir() -> std::path::PathBuf {
    paths::workspace_root().join("data/fid")
}

/// Every database must rank first on its own signatures.
#[test]
fn each_database_wins_the_vote_on_its_own_signatures() {
    let dir = db_dir();
    if !dir.exists() {
        return;
    }
    let mut names: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .expect("db dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().ends_with(".mfid.gz"))
        .collect();
    names.sort();
    assert!(names.len() > 20, "the full database set is present");

    let mut wins = 0usize;
    let mut checked = 0usize;
    let mut failures: Vec<String> = Vec::new();
    let mut runner_up: BTreeMap<String, String> = BTreeMap::new();

    for path in &names {
        let stem = path.file_name().unwrap().to_string_lossy().replace(".mfid.gz", "");
        let s = store::read_file(path).unwrap_or_else(|e| panic!("{stem}: {e}"));

        // Sample the largest records: the vote is score-weighted, and a handful of substantial
        // functions is what a real binary contributes. Taking the biggest also avoids testing
        // only tiny bodies that legitimately appear in several releases.
        let mut records = s.functions.clone();
        records.sort_by_key(|r| std::cmp::Reverse(r.code_unit_size));
        let quads: Vec<FidHashQuad> = records
            .iter()
            .take(40)
            .map(|r| FidHashQuad {
                code_unit_size: r.code_unit_size,
                full_hash: r.full_hash,
                specific_hash_additional_size: r.specific_hash_additional_size,
                specific_hash: r.specific_hash,
            })
            .collect();
        if quads.is_empty() {
            continue;
        }

        let report = vote(&quads, &dir, &s.language_id, &s.compiler_spec_id);
        let Some(best) = report.best() else {
            failures.push(format!("{stem}: its own signatures matched nothing"));
            continue;
        };
        checked += 1;
        if best.database == stem {
            wins += 1;
            if let Some(second) = report.votes.get(1) {
                runner_up.insert(stem.clone(), format!("{} ({:.0}%)", second.database,
                    second.score / best.score * 100.0));
            }
        } else {
            // A genuine tie is a correct answer, not a failure. Borland C++ 4.52 is a patch
            // release whose 32-bit runtime is 940-of-941 functions identical to 4.5's, so no
            // signature can separate them — and the vote says so by scoring them equal and
            // reporting `is_ambiguous`. What must never happen is losing to a DIFFERENT
            // runtime, or losing on score.
            let own = report.votes.iter().find(|v| v.database == stem).map(|v| v.score).unwrap_or(0.0);
            if (own - best.score).abs() < f32::EPSILON && report.is_ambiguous() {
                wins += 1;
                runner_up.insert(stem.clone(), format!("TIED with {}", best.database));
            } else {
                failures.push(format!(
                    "{stem}: lost to {} ({:.0} against {:.0})",
                    best.database, best.score, own
                ));
            }
        }
    }

    eprintln!("discrimination: {wins}/{checked} databases win on their own signatures");
    for (db, second) in runner_up.iter().take(8) {
        eprintln!("   {db:<34} runner-up {second}");
    }
    assert!(failures.is_empty(), "databases that did not win:\n  {}", failures.join("\n  "));
    assert_eq!(wins, checked, "every database must win — or genuinely tie — its own vote");
}

/// The hard cases: adjacent releases that share most of their runtime. These are the pairs the
/// support table marks ambiguous, and the ones a version answer is actually asked about.
#[test]
fn adjacent_releases_are_told_apart() {
    let dir = db_dir();
    if !dir.exists() {
        return;
    }
    let pairs = [
        ("borland-tc2.0-cs-x86-16", "borland-tc2.01-cs-x86-16"),
        ("borland-bc4.5-cs-x86-16", "borland-bc4.52-cs-x86-16"),
        ("borland-tcpp1.0-cs-x86-16", "borland-tcpp1.01-cs-x86-16"),
        ("watcom-10.5-x86-32", "watcom-10.6-x86-32"),
        ("watcom-10.6-x86-32", "watcom-11.0-x86-32"),
    ];

    for (a, b) in pairs {
        let pa = dir.join(format!("{a}.mfid.gz"));
        if !pa.exists() || !dir.join(format!("{b}.mfid.gz")).exists() {
            continue;
        }
        let s = store::read_file(&pa).expect("read");
        let mut records = s.functions.clone();
        records.sort_by_key(|r| std::cmp::Reverse(r.code_unit_size));
        let quads: Vec<FidHashQuad> = records
            .iter()
            .take(40)
            .map(|r| FidHashQuad {
                code_unit_size: r.code_unit_size,
                full_hash: r.full_hash,
                specific_hash_additional_size: r.specific_hash_additional_size,
                specific_hash: r.specific_hash,
            })
            .collect();

        let report = vote(&quads, &dir, &s.language_id, &s.compiler_spec_id);
        let best = report.best().expect("a match");
        let neighbour = report.votes.iter().find(|v| v.database == b).map(|v| v.score).unwrap_or(0.0);
        eprintln!("{a} vs {b}: {:.0} against {:.0}", best.score, neighbour);
        assert!(
            best.database == a || (neighbour - best.score).abs() < f32::EPSILON,
            "{a} must out-score its neighbour {b}, or tie it exactly; winner was {}",
            best.database
        );
    }
}
