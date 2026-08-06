//! An **absolute** measure of over-decode — see `docs/over-decode-measure.md`.
//!
//! §6 ("7,322 extra instruction starts, 104.4% of Ghidra's code coverage") is stated as a
//! differential against Ghidra's decode. A differential cannot see a defect present on both sides,
//! and — as §1's entry-shift artifact showed twice — it can also manufacture a difference that is
//! a defect on neither. This reports only what the binary itself can settle: bytes mosura decoded
//! that the **producer's own metadata** says are not code, plus two self-consistency checks that
//! reference nothing outside mosura's own listing.
//!
//!     cargo run --release --example over_decode -- <binary> [--le]
//!     cargo run --release --example over_decode -- --self-test
//!
//! `--le` selects `analyze_le_file` (the DOS/4GW path WAR2 uses).
//!
//! **`--self-test` is not optional ceremony.** Every corpus fixture reports zero on every check,
//! so a zero from this tool is indistinguishable from the tool being broken. The self-test feeds
//! each predicate a synthetic input containing exactly one planted violation and asserts it is
//! found — the positive control `docs/over-decode-measure.md` requires before any result here is
//! believed. Run it alongside any real measurement and quote both.

use mosura::analysis::{self, program::CodeUnit};

/// `(start, length)` of each decoded instruction, sorted by start.
type Insns = [(u64, u64)];

/// **A1** — instruction starts inside a region the producer marks non-executable (the LE object
/// table, the ELF section flags), or outside every mapped block. Absolute: the container's own
/// statement of what is code.
fn a1_non_executable(insns: &Insns, exec: &[(u64, u64)]) -> Vec<(u64, u64)> {
    insns
        .iter()
        .copied()
        .filter(|&(a, _)| !exec.iter().any(|&(s, e)| a >= s && a <= e))
        .collect()
}

/// **A2** — an instruction start strictly inside another instruction's extent. A byte cannot be
/// both mid-instruction and a start; pure self-consistency, no oracle of any kind.
fn a2_offcut_starts(insns: &Insns) -> Vec<u64> {
    insns.windows(2).filter(|w| w[1].0 < w[0].0 + w[0].1).map(|w| w[1].0).collect()
}

/// **A3** — a flow edge whose target lands inside an instruction rather than at one.
fn a3_offcut_flow(edges: &[(u64, u64)], insns: &Insns) -> Vec<(u64, u64)> {
    let offcut = |t: u64| match insns.binary_search_by(|(a, _)| a.cmp(&t)) {
        Ok(_) => false,
        Err(i) => i > 0 && t < insns[i - 1].0 + insns[i - 1].1,
    };
    edges.iter().copied().filter(|&(_, t)| offcut(t)).collect()
}

/// Merge `(start, len)` pairs into contiguous runs.
fn runs(mut a: Vec<(u64, u64)>) -> Vec<(u64, u64, usize)> {
    a.sort();
    let mut out: Vec<(u64, u64, usize)> = Vec::new();
    for (s, l) in a {
        match out.last_mut() {
            Some(r) if s <= r.1 => {
                r.1 = r.1.max(s + l);
                r.2 += 1;
            }
            _ => out.push((s, s + l, 1)),
        }
    }
    out
}

/// THE POSITIVE CONTROL. Each predicate gets a synthetic input with exactly one planted
/// violation, plus a clean input that must stay silent. Without this a zero on WAR2 says nothing.
fn self_test() {
    // A1: three instructions, the middle one outside the single executable range.
    let insns = [(0x1000, 4), (0x9000, 4), (0x1008, 4)];
    let mut sorted = insns;
    sorted.sort();
    let hits = a1_non_executable(&sorted, &[(0x1000, 0x1fff)]);
    assert_eq!(hits, vec![(0x9000, 4)], "A1 must flag the instruction outside the exec range");
    assert!(
        a1_non_executable(&[(0x1000, 4)], &[(0x1000, 0x1fff)]).is_empty(),
        "A1 must stay silent on a clean input"
    );

    // A2: 0x1000 is 8 bytes long, so a start at 0x1004 is offcut.
    assert_eq!(a2_offcut_starts(&[(0x1000, 8), (0x1004, 4)]), vec![0x1004], "A2 must flag offcut");
    assert!(
        a2_offcut_starts(&[(0x1000, 4), (0x1004, 4)]).is_empty(),
        "A2 must stay silent on abutting instructions"
    );

    // A3: a branch into the middle of the instruction at 0x1000.
    let insns = [(0x1000, 8), (0x1008, 4)];
    assert_eq!(
        a3_offcut_flow(&[(0x2000, 0x1004)], &insns),
        vec![(0x2000, 0x1004)],
        "A3 must flag flow into mid-instruction"
    );
    assert!(
        a3_offcut_flow(&[(0x2000, 0x1008)], &insns).is_empty(),
        "A3 must stay silent on flow to a real start"
    );

    println!("self-test: A1, A2, A3 each detect a planted violation and stay silent when clean");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--self-test") {
        self_test();
        return;
    }
    let Some(path) = args.first() else {
        eprintln!("usage: over_decode <binary> [--le] | --self-test");
        std::process::exit(2);
    };
    self_test(); // never report a measurement without its control
    let p = std::path::Path::new(path);
    let prog = if args.iter().any(|a| a == "--le") {
        analysis::analyze_le_file(p).expect("analyze_le_file")
    } else {
        analysis::analyze_file(p).expect("analyze_file")
    };

    let mut insns: Vec<(u64, u64)> = prog
        .listing
        .code_units()
        .filter_map(|(a, u)| match u {
            CodeUnit::Instruction { length, .. } => Some((a.offset, *length as u64)),
            _ => None,
        })
        .collect();
    insns.sort();
    let exec: Vec<(u64, u64)> = prog
        .memory
        .blocks()
        .filter(|b| b.is_execute())
        .map(|b| (b.start().offset, b.end().offset))
        .collect();
    let edges: Vec<(u64, u64)> = prog
        .reference_manager
        .references()
        .filter(|r| r.ref_type.is_flow())
        .map(|r| (r.from.offset, r.to.offset))
        .collect();

    println!("\n== {} ==", p.display());
    println!("instructions {}  decoded bytes {}", insns.len(), insns.iter().map(|(_, l)| l).sum::<u64>());
    for b in prog.memory.blocks() {
        println!(
            "  {:20} {:08x}..{:08x} exec={} init={}",
            b.name(),
            b.start().offset,
            b.end().offset,
            b.is_execute(),
            b.is_initialized()
        );
    }

    let a1 = a1_non_executable(&insns, &exec);
    let a1r = runs(a1.clone());
    println!(
        "\nA1 non-executable decode     starts={} bytes={} runs={}",
        a1.len(),
        a1.iter().map(|(_, l)| l).sum::<u64>(),
        a1r.len()
    );
    for (s, e, n) in a1r.iter().take(20) {
        println!("     {s:08x}..{e:08x}  {n} insns");
    }

    let a2 = a2_offcut_starts(&insns);
    println!("A2 offcut starts             {}", a2.len());
    for s in a2.iter().take(20) {
        println!("     {s:08x}");
    }

    let a3 = a3_offcut_flow(&edges, &insns);
    println!("A3 flow into mid-instruction {}", a3.len());
    for (f, t) in a3.iter().take(20) {
        println!("     {f:08x} -> {t:08x}");
    }

    // A5 — starts with no inbound flow and no fall-through predecessor: the seed set, and the
    // entry point for the ablation half of docs/over-decode-measure.md.
    let inbound: std::collections::BTreeSet<u64> = edges.iter().map(|(_, t)| *t).collect();
    let entries: std::collections::BTreeSet<u64> =
        prog.function_manager.functions().map(|f| f.entry_point().offset).collect();
    let mut prev_end = u64::MAX;
    let mut a5: Vec<(u64, u64)> = Vec::new();
    for &(a, l) in &insns {
        if a != prev_end && !inbound.contains(&a) && !entries.contains(&a) {
            a5.push((a, l));
        }
        prev_end = a + l;
    }
    println!("A5 unreachable starts        {} (runs {})", a5.len(), runs(a5.clone()).len());
    for (s, _) in a5.iter().take(20) {
        println!("     {s:08x}");
    }
}
