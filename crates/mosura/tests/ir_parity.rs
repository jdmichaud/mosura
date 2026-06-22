//! IR-parity gate (port-plan.md §3). Compares the faithful `decompile` pipeline's IR
//! against Ghidra's own IR (`oracle/capture --ir <action>`, which runs Ghidra's pipeline
//! to the start of a named action and dumps `Funcdata::printRaw`).
//!
//! P0 establishes the plumbing and a structural check that mosura's lifted/loaded
//! Funcdata covers exactly the instruction addresses Ghidra's pre-heritage IR does. As
//! each phase lands (P1 heritage → …), this file grows a normalized op-graph diff at that
//! phase's breakpoint; that diff is the gate for moving on.
//!
//! Skips when the x86-64 `.sla` or the `oracle/capture` binary isn't present.

use std::collections::BTreeSet;
use std::process::Command;

use mosura::decompile::build::raw_funcdata;
use mosura::sleigh::engine::Spec;
use mosura::{datatest, paths};

fn x86_64() -> Option<(Spec, Vec<u32>)> {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        eprintln!("skip: {} not found", sla.display());
        return None;
    }
    let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).ok()?;
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    Some((spec, ctx))
}

/// Run `oracle/capture <ghidra> <fixture> --ir <action>` and return Ghidra's IR dump.
fn ghidra_ir(fixture: &std::path::Path, action: &str) -> Option<String> {
    let capture = paths::workspace_root().join("oracle/capture");
    if !capture.exists() {
        eprintln!("skip: {} not built", capture.display());
        return None;
    }
    let out = Command::new(capture)
        .arg(paths::ghidra_src())
        .arg(fixture)
        .arg("--ir")
        .arg(action)
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The set of instruction addresses appearing in a `printRaw`-style dump — lines of the
/// form `0x<addr>:<uniq>:\t…`. Robust to Ghidra-vs-mosura formatting (register names,
/// operator rendering, zero-padding) since it keys only on the parsed instruction address.
fn instr_addrs(dump: &str) -> BTreeSet<u64> {
    dump.lines()
        .filter_map(|l| {
            let l = l.trim_start();
            let rest = l.strip_prefix("0x")?;
            let (hex, after) = rest.split_once(':')?;
            // require a second `:` (the uniq field) to avoid matching block-range lines
            after.split_once(':')?;
            u64::from_str_radix(hex, 16).ok()
        })
        .collect()
}

/// Ghidra's `printRaw` block headers: `Basic Block N 0x<start>-0x<stop>`. Returns the
/// sorted `(start, stop)` instruction ranges (with multiplicity).
fn ghidra_block_ranges(dump: &str) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = dump
        .lines()
        .filter_map(|l| {
            let rest = l.trim_start().strip_prefix("Basic Block ")?;
            let range = rest.split_whitespace().nth(1)?; // "0xSTART-0xSTOP"
            let (a, b) = range.split_once('-')?;
            let a = u64::from_str_radix(a.trim().strip_prefix("0x")?, 16).ok()?;
            let b = u64::from_str_radix(b.trim().strip_prefix("0x")?, 16).ok()?;
            Some((a, b))
        })
        .collect();
    v.sort_unstable();
    v
}

/// mosura's block ranges for a fixture, sorted, after building the CFG.
fn mosura_block_ranges(spec: &Spec, ctx: &[u32], fixture: &std::path::Path) -> Vec<(u64, u64)> {
    let dt = datatest::parse_file(fixture).expect("fixture");
    let mut f = raw_funcdata(spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, ctx);
    mosura::decompile::cfg::build_cfg(&mut f);
    let mut got: Vec<(u64, u64)> = (0..f.num_blocks() as u32)
        .filter_map(|b| f.block_range(mosura::decompile::BlockId(b)))
        .collect();
    got.sort_unstable();
    got
}

fn fixture_path(name: &str) -> std::path::PathBuf {
    if name == "x86_64_sem" {
        paths::oracle_fixtures_dir().join("x86_64_sem.xml")
    } else {
        paths::datatests_dir().join(format!("{name}.xml"))
    }
}

#[test]
fn cfg_block_ranges_match_ghidra() {
    let Some((spec, ctx)) = x86_64() else { return };
    // Verified-aligned set: mosura's reachable instruction stream agrees with Ghidra's,
    // so the CFG *cutting* logic (leaders, edges, reachability prune) must reproduce
    // Ghidra's block ranges exactly. Regressions here are real cutting bugs.
    for name in ["x86_64_sem", "elseif"] {
        let fixture = fixture_path(name);
        if !fixture.exists() {
            continue;
        }
        let Some(ghidra) = ghidra_ir(&fixture, "heritage") else { return };
        let expected = ghidra_block_ranges(&ghidra);
        if expected.is_empty() {
            continue;
        }
        assert_eq!(mosura_block_ranges(&spec, &ctx, &fixture), expected, "block ranges differ for {name}");
    }
}

/// Survey (non-failing): which functions' CFGs already match Ghidra and which still need
/// flow-following decode (mosura's linear lifter drifts out of alignment — e.g. condconst's
/// jump target is off by one). This catalogs the next P1 sub-task without gating on it.
#[test]
fn cfg_survey_flow_following_gap() {
    let Some((spec, ctx)) = x86_64() else { return };
    let names = [
        "x86_64_sem", "elseif", "condconst", "boolless", "twodim", "threedim", "ifswitch",
    ];
    let (mut matched, mut needs_flow) = (Vec::new(), Vec::new());
    for name in names {
        let fixture = fixture_path(name);
        if !fixture.exists() {
            continue;
        }
        let Some(ghidra) = ghidra_ir(&fixture, "heritage") else { return };
        let expected = ghidra_block_ranges(&ghidra);
        if expected.is_empty() {
            continue;
        }
        if mosura_block_ranges(&spec, &ctx, &fixture) == expected {
            matched.push(name);
        } else {
            needs_flow.push(name);
        }
    }
    eprintln!("CFG matches Ghidra: {matched:?}");
    eprintln!("needs flow-following decode (P1 next): {needs_flow:?}");
    assert!(!matched.is_empty(), "no CFGs matched Ghidra");
}

#[test]
fn raw_ir_covers_ghidra_instruction_addresses() {
    let Some((spec, ctx)) = x86_64() else { return };
    let fixture = paths::oracle_fixtures_dir().join("x86_64_sem.xml");
    let Some(ghidra) = ghidra_ir(&fixture, "heritage") else { return };

    let dt = datatest::parse_file(&fixture).expect("fixture");
    let f = raw_funcdata(&spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);
    let mosura = f.print_raw();

    let g = instr_addrs(&ghidra);
    let m = instr_addrs(&mosura);
    assert!(!g.is_empty(), "Ghidra IR produced no addressed ops:\n{ghidra}");
    assert!(!m.is_empty(), "mosura IR produced no addressed ops");

    // Every instruction Ghidra lifts, mosura's loader also covers (and vice versa). This
    // validates the data model + load step against Ghidra's actual pre-heritage IR.
    assert_eq!(
        m, g,
        "instruction-address coverage differs\n  mosura-only: {:x?}\n  ghidra-only: {:x?}",
        m.difference(&g).collect::<Vec<_>>(),
        g.difference(&m).collect::<Vec<_>>()
    );
}
