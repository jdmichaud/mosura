//! A0/A2 — the auto-analysis parity harness (plan `docs/analysis-port-plan.md` §3).
//!
//! Two gates, scored separately (the plan's per-phase model):
//! - **memory map** (A2 loader): mosura's loader blocks vs the **loader-stage**
//!   (`-noanalysis`) golden `<name>.loaded.snapshot` — the loader's own output, before
//!   analysis adds artificial blocks (e.g. PE's `tdb`);
//! - **functions** (A4): mosura's functions vs the converged `<name>.snapshot`. 0 until
//!   disassembly/discovery lands.
//!
//! Mandatory corpus is the committed ELFs; PE (`cnv.exe`) is user-provided and skipped
//! if absent (its binary isn't redistributable, but its golden is committed).

use std::path::PathBuf;

use mosura::analysis::{self, snapshot};
use mosura::conformance::Tally;
use mosura::paths::{analysis_corpus_dir, analysis_goldens_dir};

/// Committed ELF corpus (always present).
const MANDATORY: &[&str] = &["freestanding", "basic"];

/// (name, binary path, mandatory?) — externals are user-provided, skipped if absent.
fn corpus() -> Vec<(&'static str, PathBuf, bool)> {
    let mut v: Vec<(&str, PathBuf, bool)> = MANDATORY
        .iter()
        .map(|n| (*n, analysis_corpus_dir().join(format!("{n}.elf")), true))
        .collect();
    v.push(("cnv", PathBuf::from("/home/jd/cnv.exe"), false)); // PE, user-provided
    v.push(("comcom32", PathBuf::from("/home/jd/.local/share/comcom32/comcom32.exe"), false)); // MZ
    v.push(("war2", PathBuf::from("/home/jd/WAR2.EXE"), false)); // MZ (DOS/4GW stub), user-provided
    v
}

#[test]
fn memory_map_parity() {
    let goldens = analysis_goldens_dir();
    let mut blocks = Tally::default();
    let mut evaluated = Vec::new();

    for (name, path, mandatory) in corpus() {
        if !path.exists() {
            assert!(!mandatory, "mandatory corpus binary missing: {}", path.display());
            eprintln!("  skip {name}: {} not present", path.display());
            continue;
        }
        let golden = snapshot::parse(
            &std::fs::read_to_string(goldens.join(format!("{name}.loaded.snapshot")))
                .unwrap_or_else(|e| panic!("loader-stage golden for {name}: {e}")),
        );
        let produced = analysis::analyze_binary(&path).unwrap_or_else(|e| panic!("analyze {name}: {e}"));
        let ok = produced.blocks == golden.blocks;
        if !ok {
            eprintln!("  [{name}] memory map differs: {} blocks vs golden {}", produced.blocks.len(), golden.blocks.len());
        }
        blocks.record(ok);
        evaluated.push(name);
    }

    eprintln!("memory-map parity: {blocks} ({:?})", evaluated);
    assert!(evaluated.contains(&"freestanding") && evaluated.contains(&"basic"), "ELF corpus must run");
    assert_eq!(blocks.passed, blocks.total, "every evaluated binary's memory map must match its loader-stage golden");
}

#[test]
fn loader_detail_parity() {
    let goldens = analysis_goldens_dir();
    let mut detail = Tally::default();
    let mut evaluated = Vec::new();
    for (name, path, mandatory) in corpus() {
        if !path.exists() {
            assert!(!mandatory, "mandatory corpus binary missing: {}", path.display());
            continue;
        }
        let golden = snapshot::parse(
            &std::fs::read_to_string(goldens.join(format!("{name}.loaded.snapshot")))
                .unwrap_or_else(|e| panic!("loader-stage golden for {name}: {e}")),
        );
        let p = analysis::analyze_binary(&path).unwrap_or_else(|e| panic!("analyze {name}: {e}"));
        let ok = p.functions == golden.functions
            && p.entries == golden.entries
            && p.symbols == golden.symbols;
        if !ok {
            eprintln!(
                "  [{name}] detail differs: func {}/{}, entry {}/{}, sym {}/{}",
                p.functions.len(), golden.functions.len(),
                p.entries.len(), golden.entries.len(),
                p.symbols.len(), golden.symbols.len(),
            );
        }
        detail.record(ok);
        evaluated.push(name);
    }
    eprintln!("loader-detail parity: {detail} ({evaluated:?})");
    assert!(evaluated.contains(&"freestanding") && evaluated.contains(&"basic"), "ELF corpus must run");
    assert_eq!(detail.passed, detail.total, "every evaluated binary's loader detail must match its golden");
}
