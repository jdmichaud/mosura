//! **The database-vs-hasher drift gate.**
//!
//! A committed `.mfid` database is a *cache of the hasher's output*. Change the hasher and every
//! record in it becomes a hash the current code no longer produces — so identifying a real binary
//! against that database silently MISSES. The database is still internally consistent, still
//! loads, still self-scores perfectly; it is simply answering a question nobody asks any more.
//!
//! **This is not hypothetical, and nothing else caught it.** Gating the empty-mask fallback
//! (`85284c9`, the R7 fix) changed operand value masks on x86-16 and z80, which moved 60 of the 71
//! committed databases — sdcc alone in 574 of its 632 records. All 23 FID integration tests stayed
//! green through it:
//!
//! - `fid_detect_versions` scores each database against **its own** records, so a stale database
//!   still out-scores its neighbours exactly as before — stale-vs-stale agrees perfectly.
//! - `fid_identify` uses Ghidra's shipped `.fidb` (x86-32/x86-64), which that change did not move.
//!
//! Neither ever hashes a real binary and looks it up in a committed database, which is the one
//! thing that would have gone red. This test does exactly that: re-ingest the source library with
//! the *current* hasher and require the result to be byte-identical to what is committed.
//!
//! **Skips, loudly, when a source is absent.** Most of these libraries come from historical
//! install media that is staged outside the repo, so this cannot fail merely because a machine
//! lacks them — but a silent skip would make the gate vacuous, so the count of what was actually
//! checked is printed, and it is an error for *nothing* to be checkable.

use std::path::{Path, PathBuf};

use mosura::analysis::fid::build::{build_from_files, BuildSpec};

/// A committed database and the library it was ingested from.
///
/// Paths are the ones `docs/fid-building-databases.md` documents. They are deliberately absolute
/// and machine-specific: the alternative is copying vendor runtimes into the repo, and the point
/// of this gate is to check the *committed* databases, not a fixture that stands in for them.
struct Source {
    /// File name under `oracle/fid/db/`.
    database: &'static str,
    library: &'static str,
    family: &'static str,
    version: &'static str,
    variant: &'static str,
}

const SOURCES: &[Source] = &[
    // sdcc ships its runtime in a distro package, so this one is checkable on any machine with
    // sdcc installed — the most reliable entry here, and the column with NO Ghidra parity
    // goldens, which makes a drift check the only automated cover it has.
    Source {
        database: "sdcc-4.5.0-z80.mfid.gz",
        library: "/usr/share/sdcc/lib/z80/z80.lib",
        family: "sdcc",
        version: "4.5.0",
        variant: "z80",
    },
    // Open Watcom, built from the source tree. NOTE the exact path: there are many `clib3r.lib`
    // copies in that tree and only this one reproduces the database — see the trap recorded in
    // docs/fid-building-databases.md.
    Source {
        database: "watcom-ow2-x86-32.mfid.gz",
        library: "/data/open-watcom-v2/bld/clib/library/msdos.386/ms_r/clib3r.lib",
        family: "Watcom",
        version: "ow2",
        variant: "Release",
    },
    // Borland 4.5 — the one Borland install that lives on persistent storage. Covers x86-16,
    // which is where the R7 drift actually landed, and x86-32 as a control.
    Source {
        database: "borland-bc4.5-cs-x86-16.mfid.gz",
        library: "/data/borland/BC45/LIB/CS.LIB",
        family: "Borland",
        version: "bc4.5",
        variant: "cs",
    },
    Source {
        database: "borland-bc4.5-flat-x86-32.mfid.gz",
        library: "/data/borland/BC45/LIB/CW32.LIB",
        family: "Borland",
        version: "bc4.5",
        variant: "flat",
    },
];

fn db_dir() -> PathBuf {
    mosura::paths::workspace_root().join("oracle/fid/db")
}

/// Decompressed text of a committed database.
fn committed_text(path: &Path) -> Option<String> {
    let raw = std::fs::read(path).ok()?;
    mosura::analysis::fid::store::decompress(&raw).ok()
}

#[test]
fn committed_databases_match_the_current_hasher() {
    let dir = db_dir();
    let mut checked = 0usize;
    let mut skipped = Vec::new();
    let mut drifted = Vec::new();

    for src in SOURCES {
        let lib = Path::new(src.library);
        let db = dir.join(src.database);
        if !lib.exists() {
            skipped.push(format!("{} (no {})", src.database, src.library));
            continue;
        }
        let Some(want) = committed_text(&db) else {
            skipped.push(format!("{} (database unreadable)", src.database));
            continue;
        };

        let spec = BuildSpec {
            family: src.family.to_string(),
            version: src.version.to_string(),
            variant: src.variant.to_string(),
            common_symbols: Vec::new(),
            symbol_map: std::collections::HashMap::new(),
        };
        let (store, _) = build_from_files(&[lib.to_path_buf()], &spec)
            .unwrap_or_else(|e| panic!("{}: re-ingest failed: {e}", src.database));
        let got = store.to_text();

        checked += 1;
        if got != want {
            // Report the shape of the drift, not a 600-line diff.
            let (a, b): (Vec<&str>, Vec<&str>) = (want.lines().collect(), got.lines().collect());
            let changed = a.iter().zip(&b).filter(|(x, y)| x != y).count()
                + a.len().abs_diff(b.len());
            drifted.push(format!(
                "{}: {changed} of {} records differ (committed {} lines, rebuilt {} lines)",
                src.database,
                a.len().max(b.len()),
                a.len(),
                b.len()
            ));
        }
    }

    eprintln!("database drift: {checked} checked, {} skipped", skipped.len());
    for s in &skipped {
        eprintln!("  skipped {s}");
    }

    // A gate that checks nothing passes trivially. If every source is missing, that is a broken
    // environment, not a clean run.
    assert!(
        checked > 0,
        "no database source was available — this gate measured nothing:\n  {}",
        skipped.join("\n  ")
    );

    assert!(
        drifted.is_empty(),
        "committed databases no longer match the hasher that must query them.\n\
         Re-ingesting their sources produces different records, so identifying a real binary \
         against them will MISS.\n\
         Regenerate them (docs/fid-building-databases.md) in the SAME commit as the hasher \
         change.\n  {}",
        drifted.join("\n  ")
    );
}
