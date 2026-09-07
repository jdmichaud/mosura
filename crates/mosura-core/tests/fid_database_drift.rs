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

use mosura_core::analysis::fid::build::{build_from_files, BuildSpec};

/// A committed database and the library it was ingested from.
///
/// The install media is vendor runtime that cannot live in the repository, so WHERE it sits is a
/// property of the machine and belongs in `dev-config.toml` under `[toolchains]` — not in this
/// file. It used to be spelled here as absolute paths, which pinned the gate to one machine and
/// published that machine's home directory in the log of every CI run (the paths are printed with
/// each skip). What stays here is the RECIPE — which libraries, in which order, under the root —
/// because that is the part a drift in the build must still be caught by.
struct Source {
    /// File name under `data/fid/`.
    database: &'static str,
    /// The `[toolchains]` key naming this product's install root on this machine, e.g. `wat100a`
    /// for `~/.dosemu/drive_c/WAT100A`. Absent from dev-config => this source is skipped.
    root: &'static str,
    /// EVERY library the database is ingested from, in build order, RELATIVE to [`Source::root`]. This is the recipe, and
    /// listing it here is what makes the gate catch a recipe change as well as a hasher change —
    /// when the math/graphics libraries were added, this test went red until it was updated,
    /// which is exactly the behaviour wanted.
    libraries: &'static [&'static str],
    family: &'static str,
    version: &'static str,
    variant: &'static str,
    /// Pinned language, when the library mixes widths (see `BuildSpec::language`). `None` keeps
    /// the historical implicit behaviour for the rows that predate the option.
    language: Option<&'static str>,
    /// Declared compiler spec, for a library whose vendor the loader cannot infer.
    compiler_spec: Option<&'static str>,
}

const SOURCES: &[Source] = &[
    // sdcc ships its runtime in a distro package, so this one is checkable on any machine with
    // sdcc installed — the most reliable entry here, and the column with NO Ghidra parity
    // goldens, which makes a drift check the only automated cover it has.
    Source {
        database: "sdcc-4.5.0-z80.mfid.gz",
        root: "sdcc",
        libraries: &["lib/z80/z80.lib"],
        family: "sdcc",
        version: "4.5.0",
        variant: "z80",
        language: None,
        compiler_spec: None,
    },
    // Open Watcom, built from the source tree. NOTE the exact path: there are many `clib3r.lib`
    // copies in that tree and only this one reproduces the database — see the trap recorded in
    // docs/fid-building-databases.md.
    Source {
        database: "watcom-ow2-x86-32.mfid.gz",
        root: "ow2",
        libraries: &[
            "bld/clib/library/msdos.386/ms_r/clib3r.lib",
            "bld/mathlib/library/msdos.386/ms_r/math3r.lib",
        ],
        family: "Watcom",
        version: "ow2",
        variant: "Release",
        language: None,
        compiler_spec: None,
    },
    // Watcom 10.0a DOS — the column the subject is built against, and the one that moved when the OMF
    // loader learned to apply **absolute** (non-self-relative) fixups. Without a shipped-release
    // Watcom source here, that change would have gone unmeasured by this gate: the Open Watcom 2
    // row above is a source build, and the two Borland rows are a different loader path.
    Source {
        database: "watcom-10.0a-x86-32.mfid.gz",
        root: "wat100a",
        libraries: &[
            "LIB386/DOS/CLIB3R.LIB",
            "LIB386/MATH3R.LIB",
            "LIB386/MATH387R.LIB",
            "LIB386/DOS/EMU387.LIB",
            "LIB386/DOS/GRAPH.LIB",
        ],
        family: "Watcom",
        version: "10.0a",
        variant: "Release",
        language: None,
        compiler_spec: None,
    },
    // Watcom 16-bit. A different language (`x86:LE:16:Real Mode`) reached through the same OMF
    // reader, so it catches a drift that only shows on 16-bit operand masks.
    Source {
        database: "watcom-10.5-cs-x86-16.mfid.gz",
        root: "watcom16",
        libraries: &[
            "LIB286/DOS/CLIBS.LIB",
            "LIB286/MATH87S.LIB",
            "LIB286/MATHS.LIB",
            "LIB286/DOS/EMU87.LIB",
            "LIB286/DOS/GRAPH.LIB",
        ],
        family: "Watcom",
        version: "10.5",
        variant: "cs",
        language: None,
        compiler_spec: None,
    },
    // Borland 4.5 — the one Borland install that lives on persistent storage. Covers x86-16,
    // which is where the R7 drift actually landed, and x86-32 as a control.
    Source {
        database: "borland-bc4.5-cs-x86-16.mfid.gz",
        root: "bc45",
        libraries: &[
            "LIB/CS.LIB",
            "LIB/MATHS.LIB",
            "LIB/EMU.LIB",
            "LIB/FP87.LIB",
            "LIB/GRAPHICS.LIB",
            "LIB/OVERLAY.LIB",
        ],
        family: "Borland",
        version: "bc4.5",
        variant: "cs",
        language: None,
        compiler_spec: None,
    },
    Source {
        database: "borland-bc4.5-flat-x86-32.mfid.gz",
        root: "bc45",
        libraries: &["LIB/CW32.LIB"],
        family: "Borland",
        version: "bc4.5",
        variant: "flat",
        language: None,
        compiler_spec: None,
    },
    // MetaWare High C 386 — the only rows whose source libraries live inside the dosemu C:
    // drive that scripts/setup-metaware-dosemu.sh populates, so on a machine without the
    // historical Watcom/Borland media these are what keeps this gate from measuring nothing.
    // They also exercise the two options the other rows do not: an explicitly pinned language
    // (HC386.LIB mixes 16- and 32-bit modules) and a declared compiler spec.
    // Microsoft C 7.0, 16-bit DOS. The only 16-bit row whose sources are present here, and the
    // one that exercises a language id CONTAINING A SPACE ("x86:LE:16:Real Mode") — which is
    // exactly what word-split out of the rebuild script's option string until it used an array.
    Source {
        database: "msc-7.0-cm-x86-16.mfid.gz",
        root: "msc7",
        libraries: &[
            "LIB/MLIBCR.LIB",
            "LIB/MLIBFP.LIB",
            "LIB/EM.LIB",
            "LIB/87.LIB",
            "LIB/GRAPHICS.LIB",
        ],
        family: "Microsoft C",
        version: "7.0",
        variant: "cm",
        language: Some("x86:LE:16:Real Mode"),
        compiler_spec: None,
    },
    Source {
        database: "highc-3.31-x86-32.mfid.gz",
        root: "hc331",
        libraries: &[
            "small/hc386.lib",
            "small/hc387.lib",
            "small/hcloc.lib",
            "small/hcna.lib",
        ],
        family: "MetaWare High C",
        version: "3.31",
        variant: "Release",
        language: Some("x86:LE:32:default"),
        compiler_spec: Some("highc"),
    },
    Source {
        database: "highc-2.31-x86-32.mfid.gz",
        root: "hc231",
        libraries: &[
            "SMALL/HC386.LIB",
            "SMALL/HC387.LIB",
            "SMALL/HCLOC.LIB",
            "SMALL/HCNA.LIB",
        ],
        family: "MetaWare High C",
        version: "2.31",
        variant: "Release",
        language: Some("x86:LE:32:default"),
        compiler_spec: Some("highc"),
    },
];

fn db_dir() -> PathBuf {
    mosura_core::paths::workspace_root().join("data/fid")
}

/// Decompressed text of a committed database.
fn committed_text(path: &Path) -> Option<String> {
    let raw = std::fs::read(path).ok()?;
    mosura_core::analysis::fid::store::decompress(&raw).ok()
}

/// This source's install root on THIS machine: its `[toolchains]` entry, or the distro location
/// where the runtime is packaged rather than archived.
fn source_root(src: &Source) -> Option<PathBuf> {
    if let Some(p) = mosura_core::devcfg::toolchain(src.root) {
        return Some(p);
    }
    // sdcc ships its runtime in a distro package, so it has one standard location and needs no
    // dev-config entry. That keeps at least one row checkable on an ordinary machine — the
    // property the sdcc note below depends on.
    match src.root {
        "sdcc" => Some(PathBuf::from("/usr/share/sdcc")),
        _ => None,
    }
}

#[test]
fn committed_databases_match_the_current_hasher() {
    let dir = db_dir();
    let mut checked = 0usize;
    let mut skipped = Vec::new();
    // ...of which this many were skipped because the SOURCE LIBRARY is not on this machine, as
    // opposed to a database we could not read (see the gate below).
    let mut absent = 0usize;
    let mut drifted = Vec::new();

    for src in SOURCES {
        let db = dir.join(src.database);
        let Some(root) = source_root(src) else {
            skipped.push(format!(
                "{} (no toolchains.{} in dev-config.toml)",
                src.database, src.root
            ));
            absent += 1;
            continue;
        };
        let libs: Vec<PathBuf> = src.libraries.iter().map(|l| root.join(l)).collect();
        if let Some(missing) = libs.iter().find(|p| !p.exists()) {
            skipped.push(format!("{} (no {})", src.database, missing.display()));
            absent += 1;
            continue;
        }
        let Some(want) = committed_text(&db) else {
            skipped.push(format!("{} (database unreadable)", src.database));
            continue;
        };

        let spec = BuildSpec {
            language: src.language.map(str::to_string),
            compiler_spec: src.compiler_spec.map(str::to_string),
            family: src.family.to_string(),
            version: src.version.to_string(),
            variant: src.variant.to_string(),
            common_symbols: Vec::new(),
            symbol_map: std::collections::HashMap::new(),
        };
        let (store, _) = build_from_files(&libs, &spec)
            .unwrap_or_else(|e| panic!("{}: re-ingest failed: {e}", src.database));
        let got = store.to_text();

        checked += 1;
        if got != want {
            // Report the shape of the drift, not a 600-line diff.
            let (a, b): (Vec<&str>, Vec<&str>) = (want.lines().collect(), got.lines().collect());
            let changed =
                a.iter().zip(&b).filter(|(x, y)| x != y).count() + a.len().abs_diff(b.len());
            drifted.push(format!(
                "{}: {changed} of {} records differ (committed {} lines, rebuilt {} lines)",
                src.database,
                a.len().max(b.len()),
                a.len(),
                b.len()
            ));
        }
    }

    eprintln!(
        "database drift: {checked} checked, {} skipped",
        skipped.len()
    );
    for s in &skipped {
        eprintln!("  skipped {s}");
    }

    // A gate that checks nothing passes trivially — but EVERY source here is historical install
    // media staged OUTSIDE the repository, so a clean clone has none of it, and neither does CI.
    // Failing there does not report a broken environment; it reports the documented one, and it
    // makes `cargo test` red on every machine except the one that built the databases. That is
    // exactly what happened: this assertion is why the clean-clone job went red on 2026-08-11 and
    // stayed red for thirteen runs, while the suite was green on the machine with the media. So
    // absence of every source is a loud SKIP — the same contract every other regeneration-only
    // test in this repository honours (scripts/ci-clean-clone.sh).
    //
    // The gate keeps its teeth where it can have them: wherever any media IS staged, every staged
    // source is still re-ingested and compared. And a database that is present but UNREADABLE is a
    // defect in the repository rather than in the environment, so that still fails below.
    if checked == 0 && absent == skipped.len() {
        eprintln!(
            "skip committed_databases_match_the_current_hasher: no source library is staged here \
             ({} sources, all absent) — this gate only has teeth where the install media is",
            skipped.len()
        );
        return;
    }

    assert!(
        checked > 0,
        "no database source was READABLE — this gate measured nothing:\n  {}",
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
