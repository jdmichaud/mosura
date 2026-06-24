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

/// PE robustness (cnv, ~1MB / 1808 functions). `#[ignore]`d — full analysis takes ~140s
/// and cnv's converged golden is too large to commit, so this is opt-in
/// (`cargo test -- --ignored`). Asserts analysis completes without panic and every
/// recovered reference targets mapped memory (the no-spurious-reference invariant).
#[test]
#[ignore = "slow (~140s); run with --ignored"]
fn pe_robustness_cnv() {
    let path = "/home/jd/cnv.exe";
    if !std::path::Path::new(path).exists() {
        eprintln!("skip: {path} absent");
        return;
    }
    let program = analysis::analyze_file(std::path::Path::new(path)).unwrap();
    assert!(program.function_manager.function_count() > 1000, "cnv should recover its functions");
    for r in program.reference_manager.references() {
        assert!(program.memory.contains(r.to), "cnv: reference to unmapped {:08x}", r.to.offset);
    }
    eprintln!("cnv: {} functions, analysis clean", program.function_manager.function_count());
}

/// PE/MZ convergence — extends the A4/A5 checks beyond ELF. mosura must create no
/// function Ghidra lacks (HARD, every format), and its disassembly must stay within a
/// small, bounded misalignment of Ghidra's. comcom32 (MZ) is exact; war2 (16-bit DOS) has
/// a handful of over-decodes where mosura runs past a function into inter-function padding
/// that Ghidra's later data analysis (A6/A7) would claim — bounded and tracked here. cnv
/// (PE) is smoke-tested in [`analysis_robustness`] (its converged golden is too large to
/// commit). All skip-if-absent (user-provided binaries).
#[test]
fn pe_mz_convergence_parity() {
    use std::collections::BTreeSet;
    let goldens = analysis_goldens_dir();
    // (name, path, max tolerated misaligned decodes)
    let cases: &[(&str, &str, usize)] = &[
        ("comcom32", "/home/jd/.local/share/comcom32/comcom32.exe", 0),
        ("war2", "/home/jd/WAR2.EXE", 8),
    ];
    let mut evaluated = 0;
    for &(name, path, max_misaligned) in cases {
        let golden_path = goldens.join(format!("{name}.snapshot"));
        if !std::path::Path::new(path).exists() || !golden_path.exists() {
            eprintln!("  skip {name}: binary or golden absent");
            continue;
        }
        let golden = snapshot::parse(&std::fs::read_to_string(&golden_path).unwrap());
        let snap = analysis::analyze_file(std::path::Path::new(path)).unwrap().snapshot();

        let mf: BTreeSet<u64> = snap.functions.iter().map(|f| f.entry).collect();
        let gf: BTreeSet<u64> = golden.functions.iter().map(|f| f.entry).collect();
        let spurious_fns: Vec<_> = mf.difference(&gf).collect();
        assert!(spurious_fns.is_empty(), "{name}: spurious functions vs Ghidra: {spurious_fns:x?}");

        let mi: BTreeSet<u64> = snap.code_units.iter().copied().collect();
        let gi: BTreeSet<u64> = golden.code_units.iter().copied().collect();
        let misaligned = mi.difference(&gi).count();
        assert!(
            misaligned <= max_misaligned,
            "{name}: {misaligned} misaligned decodes (max {max_misaligned}) — over-decode regressed"
        );
        eprintln!(
            "  [{name}] funcs {}/{} (0 spurious), insns {}/{} ({misaligned} misaligned ≤ {max_misaligned})",
            mf.intersection(&gf).count(), gf.len(), mi.intersection(&gi).count(), gi.len()
        );
        evaluated += 1;
    }
    eprintln!("PE/MZ convergence: {evaluated} binary(ies) evaluated");
}

/// A2 — loader-stage references. mosura's loader must emit no reference Ghidra's
/// `-noanalysis` loader doesn't (HARD subset), with a recall ratchet. Today mosura emits
/// the dynamic-relocation references (GOT/PLT slot → EXTERNAL symbol); the rest of
/// Ghidra's loader-stage refs come from ELF header / program-header / dynamic-table /
/// init-array data-structure markup (the documented remaining sub-project).
#[test]
fn loader_reference_parity() {
    use std::collections::BTreeSet;
    let goldens = analysis_goldens_dir();
    let corpus_dir = analysis_corpus_dir();
    let mut recall = Tally::default();
    for name in MANDATORY {
        let golden = snapshot::parse(
            &std::fs::read_to_string(goldens.join(format!("{name}.loaded.snapshot"))).unwrap(),
        );
        // analyze_binary is the load-only (loader-stage) snapshot.
        let snap = analysis::analyze_binary(&corpus_dir.join(format!("{name}.elf"))).unwrap();
        let mine: BTreeSet<(u64, u64, String)> =
            snap.refs.iter().map(|r| (r.from, r.to, r.kind.clone())).collect();
        let gold: BTreeSet<(u64, u64, String)> =
            golden.refs.iter().map(|r| (r.from, r.to, r.kind.clone())).collect();
        let spurious: Vec<_> = mine.difference(&gold).collect();
        assert!(spurious.is_empty(), "{name}: loader emitted refs Ghidra doesn't: {spurious:x?}");
        let matched = mine.intersection(&gold).count();
        eprintln!("  [{name}] loader-ref recall {matched}/{} (0 spurious)", gold.len());
        for _ in 0..matched {
            recall.record(true);
        }
        for _ in 0..(gold.len() - matched) {
            recall.record(false);
        }
    }
    eprintln!("loader-reference parity: {recall} (0 spurious)");
    // basic 3 relocation refs (freestanding has no dynamic relocations); the remainder is
    // the ELF structure-markup sub-project (TODO).
    assert!(recall.passed >= 3, "loader-reference recall regressed below 3");
}

/// A4 — disassembly parity. Every instruction mosura decodes must match a Ghidra
/// instruction at the same address (HARD subset: no misaligned/spurious decodes), and we
/// ratchet recall. Missing instructions live in functions mosura doesn't yet reach (PLT
/// stubs, GOT-indirect).
#[test]
fn disassembly_parity() {
    use std::collections::BTreeSet;
    let goldens = analysis_goldens_dir();
    let corpus_dir = analysis_corpus_dir();
    let mut recall = Tally::default();
    for name in MANDATORY {
        let golden = snapshot::parse(
            &std::fs::read_to_string(goldens.join(format!("{name}.snapshot"))).unwrap(),
        );
        let snap = analysis::analyze_file(&corpus_dir.join(format!("{name}.elf"))).unwrap().snapshot();
        let mine: BTreeSet<u64> = snap.code_units.iter().copied().collect();
        let gold: BTreeSet<u64> = golden.code_units.iter().copied().collect();
        let misaligned: Vec<_> = mine.difference(&gold).collect();
        assert!(
            misaligned.is_empty(),
            "{name}: mosura decoded {} instruction(s) Ghidra didn't (misaligned?): {misaligned:x?}",
            misaligned.len()
        );
        let matched = mine.intersection(&gold).count();
        eprintln!("  [{name}] code-unit recall {matched}/{} (0 misaligned)", gold.len());
        for _ in 0..matched {
            recall.record(true);
        }
        for _ in 0..(gold.len() - matched) {
            recall.record(false);
        }
    }
    eprintln!("disassembly parity: {recall} (0 misaligned decodes)");
    // freestanding 40/40 + basic 102/106 = 142 instructions, 0 misaligned.
    assert!(recall.passed >= 142, "disassembly recall regressed below 142");
}

/// A4 — converged function-set parity. Every function mosura discovers must be a Ghidra
/// function (HARD subset: no spurious functions), with a recall ratchet. The missing
/// remainder is reached only via PLT-stub disassembly / GOT pointer-following.
#[test]
fn function_parity() {
    use std::collections::BTreeSet;
    let goldens = analysis_goldens_dir();
    let corpus_dir = analysis_corpus_dir();
    let mut recall = Tally::default();
    for name in MANDATORY {
        let golden = snapshot::parse(
            &std::fs::read_to_string(goldens.join(format!("{name}.snapshot"))).unwrap(),
        );
        let snap = analysis::analyze_file(&corpus_dir.join(format!("{name}.elf"))).unwrap().snapshot();
        let mine: BTreeSet<u64> = snap.functions.iter().map(|f| f.entry).collect();
        let gold: BTreeSet<u64> = golden.functions.iter().map(|f| f.entry).collect();
        let spurious: Vec<_> = mine.difference(&gold).collect();
        assert!(
            spurious.is_empty(),
            "{name}: mosura created {} function(s) Ghidra didn't: {spurious:x?}",
            spurious.len()
        );
        let matched = mine.intersection(&gold).count();
        eprintln!("  [{name}] function recall {matched}/{}", gold.len());
        for _ in 0..matched {
            recall.record(true);
        }
        for _ in 0..(gold.len() - matched) {
            recall.record(false);
        }
    }
    eprintln!("function parity: {recall}");
    // freestanding 3/3 + basic 14/16 = 17.
    assert!(recall.passed >= 17, "function recall regressed below 17");
}

/// A4 — function-body parity. For every function mosura *and* Ghidra both have, the body
/// (the address ranges the function owns, Ghidra `Function.getBody`) must match **exactly**
/// — a HARD assert, plus a ratchet on how many bodies are validated.
#[test]
fn function_body_parity() {
    use std::collections::BTreeMap;
    let goldens = analysis_goldens_dir();
    let corpus_dir = analysis_corpus_dir();
    let mut validated = 0usize;
    for name in MANDATORY {
        let golden = snapshot::parse(
            &std::fs::read_to_string(goldens.join(format!("{name}.snapshot"))).unwrap(),
        );
        let snap = analysis::analyze_file(&corpus_dir.join(format!("{name}.elf"))).unwrap().snapshot();
        let mine: BTreeMap<u64, Vec<(u64, u64)>> =
            snap.bodies.iter().map(|b| (b.entry, b.ranges.clone())).collect();
        let mut matched = 0usize;
        for b in &golden.bodies {
            if let Some(mr) = mine.get(&b.entry) {
                assert_eq!(*mr, b.ranges, "{name}: function {:08x} body differs from Ghidra", b.entry);
                matched += 1;
            }
        }
        eprintln!("  [{name}] function bodies {matched}/{} exact (the rest are undiscovered functions)", golden.bodies.len());
        validated += matched;
    }
    eprintln!("function-body parity: {validated} exact bodies");
    // freestanding 3 + basic 14 = 17 bodies validated exactly.
    assert!(validated >= 17, "function-body validation regressed below 17");
}

/// A5 — references parity. mosura's analysis must never invent a reference Ghidra
/// doesn't have (a HARD subset gate over references **from executable code**), and we
/// ratchet how many of Ghidra's code references it recovers. The missing remainder is
/// A6-level analysis (computed calls, parameters, indirection) + deeper propagation.
#[test]
fn reference_parity() {
    use std::collections::BTreeSet;
    let goldens = analysis_goldens_dir();
    let corpus_dir = analysis_corpus_dir();
    let mut recall = Tally::default();
    for name in MANDATORY {
        let golden = snapshot::parse(
            &std::fs::read_to_string(goldens.join(format!("{name}.snapshot"))).unwrap(),
        );
        let program = analysis::analyze_file(&corpus_dir.join(format!("{name}.elf"))).unwrap();
        let snap = program.snapshot();

        // References whose source is executable memory — what disassembly + the
        // SymbolicPropogator are responsible for (compared on (from, to); Ghidra refines
        // some types to PARAM/INDIRECTION/CALL via A6 analyzers we haven't ported).
        let exec: Vec<(u64, u64)> = program
            .memory
            .blocks()
            .filter(|b| b.is_execute())
            .map(|b| (b.start().offset, b.end().offset))
            .collect();
        let in_code = |a: u64| exec.iter().any(|&(s, e)| a >= s && a <= e);
        let mine: BTreeSet<(u64, u64)> =
            snap.refs.iter().filter(|r| in_code(r.from)).map(|r| (r.from, r.to)).collect();
        let gold: BTreeSet<(u64, u64)> =
            golden.refs.iter().filter(|r| in_code(r.from)).map(|r| (r.from, r.to)).collect();

        let false_positives: Vec<_> = mine.difference(&gold).collect();
        assert!(
            false_positives.is_empty(),
            "{name}: mosura invented {} reference(s) absent from Ghidra: {false_positives:x?}",
            false_positives.len()
        );
        let matched = mine.intersection(&gold).count();
        eprintln!("  [{name}] code-ref recall {matched}/{} (0 false positives)", gold.len());
        for _ in 0..matched {
            recall.record(true);
        }
        for _ in 0..(gold.len() - matched) {
            recall.record(false);
        }
    }
    eprintln!("reference parity: {recall} (recovered code refs, 0 false positives)");
    // Ratchet: freestanding 4/4 + basic 25/33 = 29 recovered today (raise as the
    // propagator + A6 analyzers land). The remaining misses are A6 analyses
    // (COMPUTED_CALL/INDIRECTION/PARAM), PLT stubs, and GOT pointer-following.
    assert!(recall.passed >= 29, "code-reference recall regressed below 29");
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
