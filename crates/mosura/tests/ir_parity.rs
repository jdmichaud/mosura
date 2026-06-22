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
