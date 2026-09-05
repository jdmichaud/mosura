//! Snapshot v1 parity on the TABLE path: the text a frozen program renders equals what the live
//! `Program` renders, at the loader stage and converged, over the committed analysis corpus; and
//! the analysis-parity harness's golden assertions (memory map, loader refs, disassembly,
//! function subset) hold when re-run from the tables instead of the live program.

use std::collections::BTreeSet;

use mosura_api::program::{freeze, snapshot_table, snapshot_text};
use mosura_api::render::{render, Format};
use mosura_core::analysis::{self, loader, snapshot};
use mosura_core::paths::{analysis_corpus_dir, analysis_goldens_dir};
use mosura_core::switches::Knobs;

/// The committed corpus, minus the two MinGW PEs (analysis of `mingw_hello32.exe` alone is ~45 s
/// and `freeze_thaw.rs` already round-trips it); the loader stage covers every binary.
const CONVERGED: &[&str] = &["freestanding.elf", "basic.elf", "aarch64.elf", "riscv.elf", "m68k.elf", "m68k_dyn.elf", "switchtab.elf", "cppsym.elf", "clang_hello.elf", "watcom_hello.exe", "z80.com"];
const LOADED: &[&str] = &["freestanding.elf", "basic.elf", "aarch64.elf", "riscv.elf", "m68k.elf", "m68k_dyn.elf", "switchtab.elf", "cppsym.elf", "clang_hello.elf", "watcom_hello.exe", "z80.com", "mingw_hello.exe", "mingw_hello32.exe"];
/// The parity harness's mandatory ELF set (its goldens are always present).
const MANDATORY: &[&str] = &["freestanding", "basic", "aarch64", "riscv", "m68k"];

fn golden(name: &str) -> snapshot::Snapshot {
    snapshot::parse(&std::fs::read_to_string(analysis_goldens_dir().join(name)).unwrap_or_else(|e| panic!("golden {name}: {e}")))
}

#[test]
fn loader_stage_text_equals_live_and_the_memory_map_gate_holds_on_tables() {
    for name in LOADED {
        let path = analysis_corpus_dir().join(name);
        let data = std::fs::read(&path).unwrap();
        let p = loader::load_path_with(&path, &data, &Knobs::default()).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let set = freeze(&p, "default");
        let text = snapshot_text(&set).unwrap();
        assert_eq!(text, p.snapshot().render(), "{name}: loader-stage snapshot text");
        assert_eq!(render(&snapshot_table(&set).unwrap(), Format::Text).unwrap(), text, "{name}: TEXT render of the snapshot table");
        // the harness's memory-map and loader-reference gates, from the tables
        let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
        if MANDATORY.contains(&stem) {
            let g = golden(&format!("{stem}.loaded.snapshot"));
            let mine = snapshot::parse(&text);
            assert_eq!(mine.blocks, g.blocks, "{name}: memory map vs the loader-stage golden");
            let refs: BTreeSet<(u64, u64, String)> = mine.refs.iter().map(|r| (r.from, r.to, r.kind.clone())).collect();
            let gold: BTreeSet<(u64, u64, String)> = g.refs.iter().map(|r| (r.from, r.to, r.kind.clone())).collect();
            let spurious: Vec<_> = refs.difference(&gold).collect();
            assert!(spurious.is_empty(), "{name}: loader refs Ghidra lacks: {spurious:x?}");
        }
    }
}

#[test]
fn converged_text_equals_live_and_the_disassembly_gates_hold_on_tables() {
    let mut recall = 0usize;
    for name in CONVERGED {
        let path = analysis_corpus_dir().join(name);
        let p = analysis::analyze_file_with(&path, &Knobs::default()).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let set = freeze(&p, "default");
        let text = snapshot_text(&set).unwrap();
        assert_eq!(text, p.snapshot().render(), "{name}: converged snapshot text");
        let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
        if MANDATORY.contains(&stem) {
            let g = golden(&format!("{stem}.snapshot"));
            let mine = snapshot::parse(&text);
            let mf: BTreeSet<u64> = mine.functions.iter().map(|f| f.entry).collect();
            let gf: BTreeSet<u64> = g.functions.iter().map(|f| f.entry).collect();
            let spurious: Vec<_> = mf.difference(&gf).collect();
            assert!(spurious.is_empty(), "{name}: spurious functions vs Ghidra: {spurious:x?}");
            let mi: BTreeSet<u64> = mine.code_units.iter().copied().collect();
            let gi: BTreeSet<u64> = g.code_units.iter().copied().collect();
            let misaligned: Vec<_> = mi.difference(&gi).collect();
            assert!(misaligned.is_empty(), "{name}: misaligned decodes: {misaligned:x?}");
            recall += mi.intersection(&gi).count();
        }
    }
    // the harness's ratchet: freestanding 40 + basic 106 + aarch64 39 + riscv 66 + m68k 31
    assert!(recall >= 282, "disassembly recall from the tables regressed below 282: {recall}");
}
