//! A6 gate: the faithfully recovered jump tables (`Funcdata::jump_tables`) the analysis-track
//! switch analyzer reads back must match Ghidra's recovered case targets exactly.
//!
//! Validated here against the build-time table read (which matches Ghidra for these functions) for
//! the canonical 0-based switch form. Offset/range switches (ifswitch, switchhide) need the
//! CircleRange range-pullback, and switchmulti needs the addrtied heritage guards — those forms
//! are tracked under A6-1 and are not yet asserted.

use mosura::decompile::build::raw_funcdata_flow_image;
use mosura::decompile::pipeline;
use mosura::sleigh::engine::Spec;
use mosura::{datatest, paths};

/// Decompile a datatest and return (faithfully-recovered tables, build-time heuristic targets).
fn tables(name: &str) -> Option<(Vec<Vec<u64>>, Vec<Vec<u64>>)> {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        return None;
    }
    let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    let dt = datatest::parse_file(&paths::datatests_dir().join(format!("{name}.xml"))).unwrap();
    let img: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let mut f = raw_funcdata_flow_image(&spec, "func", &img, dt.chunks[0].offset, &ctx);
    let mut heur: Vec<Vec<u64>> = f.switch_targets.values().cloned().collect();
    heur.sort();
    pipeline::decompile(&mut f);
    let mut faithful: Vec<Vec<u64>> = f.jump_tables().into_iter().map(|t| t.targets).collect();
    faithful.sort();
    Some((faithful, heur))
}

#[test]
fn switchind_recovers_eleven_targets() {
    let Some((faithful, heur)) = tables("switchind") else { return };
    assert_eq!(faithful.len(), 1);
    assert_eq!(faithful[0].len(), 11, "11 case targets");
    assert_eq!(faithful, heur, "faithful recovery matches the (Ghidra-matching) build-time table");
}

#[test]
fn switchloop_recovers_nine_targets() {
    let Some((faithful, heur)) = tables("switchloop") else { return };
    assert_eq!(faithful.len(), 1);
    assert_eq!(faithful[0].len(), 9);
    assert_eq!(faithful, heur);
}

#[test]
fn ifswitch_offset_switch_recovers_twentyone_targets() {
    // An offset switch (index = param_1, cases up to 0x14 in Ghidra ⇒ table indices 0..20).
    // The faithful guard-range recovery gets 21; the build-time heuristic over-reads one entry
    // past the guard bound (its 22 is wrong) — so we assert the Ghidra-correct count, not a match.
    let Some((faithful, _heur)) = tables("ifswitch") else { return };
    assert_eq!(faithful.len(), 1);
    assert_eq!(faithful[0].len(), 21, "Ghidra's ifswitch table is indices 0..0x14 = 21 entries");
}
