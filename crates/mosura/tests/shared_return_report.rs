//! The shared-return INSTRUMENT (task #3 — "invocation granularity; why is `0x67f40` missing?").
//!
//! `SharedReturnAnalyzer::report_scan` replays the `assumeContiguousFunctions` scan read-only and
//! puts each source's CARRIED verdict beside the verdict a FRESH cursor pair would give — a fresh
//! pair being exactly what a finer invocation hands the command, since
//! `SharedReturnAnalyzer.added` constructs a new `SharedReturnAnalysisCmd` every time
//! (SharedReturnAnalyzer.java:79-82). This file prints it, and answers the specific question:
//! **for a destination that has no function, which of the three possible reasons applies?**
//!
//! 1. no source jumps to it at all;
//! 2. a source does, but it is **not in `jumpScanSet`** — `checkBelowFunction` deletes a
//!    contiguous function's own body from the scan on its own account
//!    (SharedReturnAnalysisCmd.java:326-337) and only another function's `checkAboveFunction`
//!    puts it back;
//! 3. it is scanned, and the cursor test declines it — with the fresh column saying whether a
//!    finer invocation would have decided otherwise.
//!
//! ⚠️ **VALIDITY.** The report suppresses creations, so it answers "with the function set held
//! FIXED, what does each source decide". That is the right question for "was the set missing
//! something when this source was scanned?" and the wrong one for "what did the live round do end
//! to end", which creates as it goes. Take it on a converged program.
//!
//! ```sh
//! # the subject native-LE — the 0x67f40 case. Lead-owned.
//! cargo test --release --test shared_return_report -- --ignored --nocapture subjects_le
//! cargo test --release --test shared_return_report -- --ignored --nocapture subjects_mz
//! # Cheap corpus run (in the normal suite).
//! cargo test --release --test shared_return_report
//! ```

use mosura::analysis::analyzers::shared_return::SharedReturnAnalyzer;
use mosura::analysis::program::{AddressSet, Program};
use mosura::decompile::space::Address;
use mosura::paths::{analysis_corpus_dir, comcom32_exe};

/// The destinations a subject is known to miss come from its profile (`shared_return.watch` in
/// `expect.toml`, task #3). Printed in full whether or not they were created, so an absent row is
/// itself the finding.
fn watch_of(s: &mosura::devcfg::Subject) -> Vec<u64> {
    s.expect_list_u64("shared_return.watch").unwrap_or_default()
}

/// Replay round 1 of `analysis::shared_return_pass`: the whole function set, which is the set that
/// pass hands the command (`analysis/mod.rs:369`).
fn report_all(program: &Program) -> Option<(SharedReturnAnalyzer, mosura::analysis::analyzers::shared_return::ScanReport)>
{
    let sr = SharedReturnAnalyzer::for_program(program)?;
    let mut all = AddressSet::new();
    for f in program.function_manager.functions() {
        let e = f.entry_point();
        all.add_range(e.space, e.offset, e.offset);
    }
    let report = sr.report_scan(program, &all);
    Some((sr, report))
}

fn print_report(name: &str, program: &Program, watch: &[u64]) {
    let Some((_sr, r)) = report_all(program) else {
        eprintln!("skip {name}: no SLEIGH tables");
        return;
    };
    let ram = program.default_space;
    let created = r.decisions.iter().filter(|d| d.carried_creates).count();
    let fresh_created = r.decisions.iter().filter(|d| d.fresh_creates).count();
    let diverging: Vec<_> = r.decisions.iter().filter(|d| d.diverges()).collect();

    eprintln!("\n===== shared-return scan: {name} =====");
    eprintln!("function entries in the set                {}", r.set_entries);
    eprintln!("jumpScanSet ranges                         {}", r.scan.ranges().count());
    eprintln!("unconditional-jump sources scanned         {}", r.decisions.len());
    eprintln!("  ...createFunction under CARRIED cursors  {created}");
    eprintln!("  ...createFunction under FRESH cursors    {fresh_created}");
    eprintln!("  ...where the two DISAGREE                {}", diverging.len());
    // The rows that mean WORK LEFT UNDONE: the scan says create, and nothing is there yet. At the
    // pass's own fixpoint this should be empty; a non-empty list is a missing invocation, since
    // `createFunction` on an existing function only re-processes its jump refs (:260-263).
    let guarded = r
        .decisions
        .iter()
        .filter(|d| d.carried_creates && !d.dest_is_function && d.blocked_by_fallthru_guard)
        .count();
    let pending: Vec<_> = r
        .decisions
        .iter()
        .filter(|d| d.carried_creates && !d.dest_is_function && !d.blocked_by_fallthru_guard)
        .collect();
    eprintln!("  ...create verdict, declined by the fall-through guard {guarded}");
    eprintln!("  ...create verdict, NO function there yet {}   <- work left undone", pending.len());
    for d in pending.iter().take(40) {
        eprintln!(
            "    PENDING {:08x} -> {:08x}  {}  fresh={}",
            d.src.offset,
            d.dest.offset,
            d.ref_type.name(),
            d.fresh_creates
        );
    }
    for d in diverging.iter().take(40) {
        eprintln!(
            "    {:08x} -> {:08x}  {}  carried={} fresh={}  carried_in=(after={:x?} before={:x?})  dest_is_fn={}",
            d.src.offset,
            d.dest.offset,
            d.ref_type.name(),
            d.carried_creates,
            d.fresh_creates,
            d.carried_in.after,
            d.carried_in.before,
            d.dest_is_function
        );
    }

    for &w in watch {
        let addr = Address::new(ram, w);
        let is_fn = program.function_manager.function_at(addr).is_some();
        let in_scan = r.scan.contains(addr);
        let containing = program
            .function_manager
            .function_containing(addr)
            .map(|f| f.entry_point().offset);
        eprintln!(
            "-- watch {w:08x}: function_at={is_fn}  in_jumpScanSet={in_scan}  contained_by={containing:08x?}"
        );
        // Reason 1: is there any jump reference into it?
        let jump_refs: Vec<(u64, String)> = program
            .reference_manager
            .refs_to(addr)
            .filter(|rf| rf.ref_type.is_flow())
            .map(|rf| (rf.from.offset, rf.ref_type.name().to_string()))
            .collect();
        eprintln!("     inbound flow refs: {jump_refs:x?}");
        // Reason 2/3: for each of those sources, was it scanned, and what did it decide?
        for (from, _) in &jump_refs {
            let src = Address::new(ram, *from);
            let row = r.decisions.iter().find(|d| d.src == src);
            match row {
                None => eprintln!(
                    "     src {from:08x}: NOT EVALUATED (in_jumpScanSet={}, contained_by={:08x?})",
                    r.scan.contains(src),
                    program
                        .function_manager
                        .function_containing(src)
                        .map(|f| f.entry_point().offset)
                ),
                Some(d) => eprintln!(
                    "     src {from:08x}: carried={} fresh={} carried_in=(after={:x?} before={:x?}) fresh_before={:08x?}",
                    d.carried_creates,
                    d.fresh_creates,
                    d.carried_in.after,
                    d.carried_in.before,
                    program
                        .function_manager
                        .function_before(src)
                        .map(|f| f.entry_point().offset)
                ),
            }
        }
    }
    eprintln!("===== end {name} =====\n");
}

/// The configured subjects, native-LE — where the watched destinations are missing.
#[test]
#[ignore = "subject run — minutes; lead-owned"]
fn subjects_le_shared_return_report() {
    for s in mosura::devcfg::subjects() {
        if !s.path.exists() {
            eprintln!("skip subject {}: binary absent", s.id);
            continue;
        }
        let prog = mosura::analysis::analyze_le_file(&s.path).expect("native-LE analysis of the subject");
        print_report(&format!("subject {} (le)", s.id), &prog, &watch_of(s));
    }
}

/// The configured subjects through the default MZ path.
#[test]
#[ignore = "subject run — minutes; lead-owned"]
fn subjects_mz_shared_return_report() {
    for s in mosura::devcfg::subjects() {
        if !s.path.exists() {
            eprintln!("skip subject {}: binary absent", s.id);
            continue;
        }
        let prog = mosura::analysis::analyze_file(&s.path).expect("MZ analysis of the subject");
        print_report(&format!("subject {} (mz)", s.id), &prog, &watch_of(s));
    }
}

/// The corpus run — cheap, and it prints the same columns so the subject output has a baseline.
#[test]
fn corpus_shared_return_report() {
    let mut fixtures: Vec<(String, std::path::PathBuf)> = ["basic", "freestanding"]
        .iter()
        .map(|n| (n.to_string(), analysis_corpus_dir().join(format!("{n}.elf"))))
        .collect();
    fixtures.push(("comcom32".to_string(), comcom32_exe()));
    for (name, path) in fixtures {
        if !path.exists() {
            eprintln!("skip {name}: {} not present", path.display());
            continue;
        }
        let prog = mosura::analysis::analyze_file(&path).expect("analysis of the corpus fixture");
        print_report(&name, &prog, &[]);
    }
}
