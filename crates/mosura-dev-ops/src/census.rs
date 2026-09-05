//! Two population instruments over the current program's analysis.
//!
//! `dev.census.over-decode` — an ABSOLUTE measure of over-decode (`docs/over-decode-measure.md`):
//! bytes mosura decoded that the producer's own metadata says are not code, plus self-consistency
//! checks that reference nothing outside mosura's own listing. A differential against Ghidra
//! cannot see a defect present on both sides and can manufacture one present on neither. The
//! positive control runs first, every time: each predicate is fed a synthetic input with exactly
//! one planted violation and must find it (and stay silent on a clean input) — every corpus
//! fixture reports zero on every check, so a zero is otherwise indistinguishable from a broken
//! tool. (Was `examples/over_decode.rs`.)
//!
//! `dev.census.terminator-rate` — do the functions we recovered END like functions (`ret`, `jmp`,
//! `jmp indirect` as p-code RETURN/BRANCH/BRANCHIND)? Meaningful ONLY against the control arm it
//! always prints beside: the same predicate over the entries an external truth source
//! (`dev.truth`: a corpus `.truth` file or a tracker CSV) corroborates. A detector, not an
//! estimator (failures cluster); says these are functions, nothing about their extents; a
//! `jmp indirect` counts as a terminator and must keep counting. (Was `examples/terminator_rate.rs`.)

use std::collections::BTreeSet;
use std::path::Path;

use mosura_api::ops::program::program_of;
use mosura_api::ops::{Cache, Op, Progress, Tier};
use mosura_api::{Error, Options, Result, Session, Table, TableBuilder};
use mosura_core::analysis::program::CodeUnit;
use mosura_core::decompile::opcode::OpCode;
use mosura_core::decompile::space::Address;

use crate::keys;
use crate::schemas::{OVER_DECODE, TERMINATOR_RATE};

pub static OVER_DECODE_OP: Op = Op {
    name: "dev.census.over-decode",
    doc: "the absolute over-decode measure of the current program: A1 decode outside executable memory, A2 offcut instruction starts, A3 flow into mid-instruction, A4 fixup targets mid-instruction (with their code-targeted denominator), A5 unreachable starts; the planted-violation self-test runs first",
    since: "0.1",
    tier: Tier::Dev,
    params: &["program"],
    result: "over_decode",
    cache: Cache::Transient,
    run: over_decode,
};

pub static TERMINATOR_RATE_OP: Op = Op {
    name: "dev.census.terminator-rate",
    doc: "do recovered functions end like functions? the terminating-last-instruction rate of the current program's functions, ALWAYS beside the control arm the truth source (dev.truth: .truth file or tracker CSV) corroborates within dev.shift bytes; dev.list-failures adds one row per non-terminating entry. Read the uncorroborated row only against the corroborated one",
    since: "0.1",
    tier: Tier::Dev,
    params: &["program", keys::DEV_TRUTH, keys::DEV_SHIFT, keys::DEV_LIST_FAILURES],
    result: "terminator_rate",
    cache: Cache::Transient,
    run: terminator_rate,
};

/// `(start, length)` of each decoded instruction, sorted by start.
type Insns = [(u64, u64)];

/// **A1** — instruction starts inside a region the producer marks non-executable, or outside every
/// mapped block. Absolute: the container's own statement of what is code.
pub fn a1_non_executable(insns: &Insns, exec: &[(u64, u64)]) -> Vec<(u64, u64)> {
    insns.iter().copied().filter(|&(a, _)| !exec.iter().any(|&(s, e)| a >= s && a <= e)).collect()
}

/// **A2** — an instruction start strictly inside another instruction's extent.
pub fn a2_offcut_starts(insns: &Insns) -> Vec<u64> {
    insns.windows(2).filter(|w| w[1].0 < w[0].0 + w[0].1).map(|w| w[1].0).collect()
}

fn offcut(insns: &Insns, t: u64) -> bool {
    match insns.binary_search_by(|(a, _)| a.cmp(&t)) {
        Ok(_) => false,
        Err(i) => i > 0 && t < insns[i - 1].0 + insns[i - 1].1,
    }
}

/// **A3** — a flow edge whose target lands inside an instruction rather than at one.
pub fn a3_offcut_flow(edges: &[(u64, u64)], insns: &Insns) -> Vec<(u64, u64)> {
    edges.iter().copied().filter(|&(_, t)| offcut(insns, t)).collect()
}

/// **A4** — a relocation TARGET in executable memory with no instruction STARTING there: the file
/// supplies both the address and the claim that it is code. Returns `(offcut targets, how many
/// targets were code-targeted)` — the second is A4's real denominator. NOT "an instruction
/// overlapping a fixup slot": fixups routinely patch operands inside instructions.
pub fn a4_offcut_reloc_targets(targets: &[u64], insns: &Insns, exec: &[(u64, u64)]) -> (Vec<u64>, usize) {
    let code_targeted: Vec<u64> = targets.iter().copied().filter(|&t| exec.iter().any(|&(s, e)| t >= s && t <= e)).collect();
    let off = code_targeted.iter().copied().filter(|&t| offcut(insns, t)).collect();
    (off, code_targeted.len())
}

/// Merge `(start, len)` pairs into contiguous runs `(start, end, count)`.
pub fn runs(mut a: Vec<(u64, u64)>) -> Vec<(u64, u64, usize)> {
    a.sort_unstable();
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

/// THE POSITIVE CONTROL: each predicate finds exactly one planted violation and stays silent on a
/// clean input. A failure is a panic (the dispatcher reports it as an internal error) — no
/// measurement is ever answered without its control.
pub fn self_test() {
    let mut insns = [(0x1000, 4), (0x9000, 4), (0x1008, 4)];
    insns.sort_unstable();
    assert_eq!(a1_non_executable(&insns, &[(0x1000, 0x1fff)]), vec![(0x9000, 4)], "A1 must flag the instruction outside the exec range");
    assert!(a1_non_executable(&[(0x1000, 4)], &[(0x1000, 0x1fff)]).is_empty(), "A1 must stay silent on a clean input");
    assert_eq!(a2_offcut_starts(&[(0x1000, 8), (0x1004, 4)]), vec![0x1004], "A2 must flag offcut");
    assert!(a2_offcut_starts(&[(0x1000, 4), (0x1004, 4)]).is_empty(), "A2 must stay silent on abutting instructions");
    let insns = [(0x1000, 8), (0x1008, 4)];
    assert_eq!(a3_offcut_flow(&[(0x2000, 0x1004)], &insns), vec![(0x2000, 0x1004)], "A3 must flag flow into mid-instruction");
    assert!(a3_offcut_flow(&[(0x2000, 0x1008)], &insns).is_empty(), "A3 must stay silent on flow to a real start");
    assert_eq!(a4_offcut_reloc_targets(&[0x1004], &insns, &[(0x1000, 0x1fff)]), (vec![0x1004], 1), "A4 must flag a fixup target landing mid-instruction");
    assert_eq!(a4_offcut_reloc_targets(&[0x1008], &insns, &[(0x1000, 0x1fff)]), (vec![], 1), "A4 must stay silent when the target is a real start, and still count it");
    assert_eq!(a4_offcut_reloc_targets(&[0x1004], &insns, &[(0x8000, 0x8fff)]), (vec![], 0), "A4 must ignore targets outside executable memory and not count them");
}

fn over_decode(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    self_test(); // never report a measurement without its control
    let (_, prog) = program_of(s, o)?;
    let mut insns: Vec<(u64, u64)> = prog.listing.code_units().filter_map(|(a, u)| match u { CodeUnit::Instruction { length, .. } => Some((a.offset, *length as u64)), _ => None }).collect();
    insns.sort_unstable();
    let exec: Vec<(u64, u64)> = prog.memory.blocks().filter(|b| b.is_execute()).map(|b| (b.start().offset, b.end().offset)).collect();
    let edges: Vec<(u64, u64)> = prog.reference_manager.references().filter(|r| r.ref_type.is_flow()).map(|r| (r.from.offset, r.to.offset)).collect();
    let hex = |a: u64, n: usize| -> String { crate::hex_bytes(&prog.memory.read_window(Address::new(prog.default_space, a), n)).as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap_or("")).collect::<Vec<_>>().join(" ") };
    let mut t = TableBuilder::new(&OVER_DECODE);
    t.row().str("self-test").u64(4).u64(4).str("A1, A2, A3, A4 each detect a planted violation and stay silent when clean");
    t.row().str("instructions").u64(insns.len() as u64).u64(insns.iter().map(|(_, l)| l).sum::<u64>()).str("count, decoded bytes");
    for b in prog.memory.blocks() {
        t.row().str("block").u64(0).u64(0).str(&format!("{} {:08x}..{:08x} exec={} init={}", b.name(), b.start().offset, b.end().offset, b.is_execute(), b.is_initialized()));
    }
    let a1 = a1_non_executable(&insns, &exec);
    let a1r = runs(a1.clone());
    t.row().str("A1 non-executable decode").u64(a1.len() as u64).u64(a1.iter().map(|(_, l)| l).sum::<u64>()).str(&format!("starts, bytes; runs={}", a1r.len()));
    for (st, e, n) in a1r.iter().take(20) {
        t.row().str("A1 run").u64(*n as u64).u64(0).str(&format!("{st:08x}..{e:08x} {n} insns"));
    }
    let a2 = a2_offcut_starts(&insns);
    t.row().str("A2 offcut starts").u64(a2.len() as u64).u64(0).str("");
    for st in a2.iter().take(20) {
        t.row().str("A2 offcut").u64(0).u64(0).str(&format!("{st:08x}"));
    }
    let a3 = a3_offcut_flow(&edges, &insns);
    t.row().str("A3 flow into mid-instruction").u64(a3.len() as u64).u64(0).str("");
    for &(f, tgt) in a3.iter().take(20) {
        // the instruction the target lands INSIDE, so the row itself diagnoses the violation
        let owner = match insns.binary_search_by(|(a, _)| a.cmp(&tgt)) { Ok(i) => Some(insns[i]), Err(i) if i > 0 => Some(insns[i - 1]), Err(_) => None };
        let owner_s = match owner { Some((st, l)) => format!("owner {st:08x}+{l} (target is +{} into it): {}", tgt - st, hex(st, (l as usize).max(16))), None => "owner: none".to_string() };
        t.row().str("A3 edge").u64(0).u64(0).str(&format!("{f:08x} -> {tgt:08x}; src {}; {owner_s}", hex(f, 16)));
    }
    let reloc_targets: Vec<u64> = prog.relocation_table.relocations().map(|r| r.value).collect();
    let (a4, code_targeted) = a4_offcut_reloc_targets(&reloc_targets, &insns, &exec);
    t.row().str("A4 fixup target mid-instruction").u64(a4.len() as u64).u64(code_targeted as u64).str(&format!("of the CODE-TARGETED fixups; {} relocations total", reloc_targets.len()));
    for tgt in a4.iter().take(20) {
        t.row().str("A4 target").u64(0).u64(0).str(&format!("{tgt:08x}"));
    }
    // A5 — starts with no inbound flow and no fall-through predecessor: the seed set
    let inbound: BTreeSet<u64> = edges.iter().map(|(_, tgt)| *tgt).collect();
    let entries: BTreeSet<u64> = prog.function_manager.functions().map(|f| f.entry_point().offset).collect();
    let mut prev_end = u64::MAX;
    let mut a5: Vec<(u64, u64)> = Vec::new();
    for &(a, l) in &insns {
        if a != prev_end && !inbound.contains(&a) && !entries.contains(&a) {
            a5.push((a, l));
        }
        prev_end = a + l;
    }
    t.row().str("A5 unreachable starts").u64(a5.len() as u64).u64(runs(a5.clone()).len() as u64).str("starts, runs");
    for (st, _) in a5.iter().take(20) {
        t.row().str("A5 start").u64(0).u64(0).str(&format!("{st:08x}"));
    }
    Ok(t.finish(false))
}

/// The flow-ending opcodes, as p-code so the instrument is arch-neutral.
fn is_terminator(op: Option<OpCode>) -> bool {
    matches!(op, Some(OpCode::Return | OpCode::Branch | OpCode::Branchind))
}

/// Addresses from either truth source: corpus `.truth` lines (`func <hex> <size> <name> <class>`)
/// or a tracker CSV (first column `0x…`). Sizes are deliberately not read: the Watcom column of the
/// ground-truth corpus carries `size 0` for every symbol, so size-keyed logic would be silently
/// inert exactly where it matters. Corroboration is by ADDRESS only.
pub fn read_truth(text: &str) -> BTreeSet<u64> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("func ") {
            if let Some(tok) = rest.split_whitespace().next() {
                if let Ok(v) = u64::from_str_radix(tok, 16) {
                    out.insert(v);
                    continue;
                }
            }
        }
        let first = line.split(',').next().unwrap_or("");
        if let Some(hex) = first.trim().strip_prefix("0x") {
            if let Ok(v) = u64::from_str_radix(hex, 16) {
                out.insert(v);
            }
        }
    }
    out
}

fn terminator_rate(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let truth_path = o.get(keys::DEV_TRUTH)?;
    if truth_path.is_empty() {
        // the refusal that keeps the control attached to the number
        return Err(Error::InvalidArg(format!("`{}` is required: without a control population the rate is not interpretable", keys::DEV_TRUTH)));
    }
    let text = std::fs::read_to_string(truth_path).map_err(|e| Error::io(e, Path::new(truth_path).to_path_buf()))?;
    let truth = read_truth(&text);
    if truth.is_empty() {
        return Err(Error::Format(format!("no addresses parsed from {truth_path} — wrong truth format?")));
    }
    let shift = o.get(keys::DEV_SHIFT)?.trim().parse::<u64>().unwrap_or(8);
    let list_failures = crate::flag(o, keys::DEV_LIST_FAILURES)?;
    let (_, program) = program_of(s, o)?;
    let ram = program.default_space;
    let (spec, ctx) = mosura_core::lang::load_cached(&program.language_id).ok_or_else(|| Error::Unsupported(format!("no SLEIGH tables for {}", program.language_id)))?;
    // (corroborated, uncorroborated) x (total, terminating)
    let mut arms = [[0usize; 2]; 2];
    let mut failures: Vec<String> = Vec::new();
    let (mut misaligned, mut listing_blind) = (0usize, 0usize);
    for f in program.function_manager.functions() {
        let entry = f.entry_point().offset;
        // corroborated when a truth address lies within `shift` bytes AT OR AFTER the entry: the
        // tracker anchors save-first functions mid-prologue, so its address is >= the true entry
        let corroborated = truth.range(entry..=entry.saturating_add(shift)).next().is_some() || truth.contains(&entry);
        let arm = usize::from(!corroborated);
        // the last instruction of the body: decode forward through the highest range
        let Some(last_range) = f.body().ranges().max_by_key(|r| r.max) else { continue };
        let (mut cursor, mut last) = (last_range.min, None);
        while cursor <= last_range.max {
            let w = program.memory.read_window(Address::new(ram, cursor), 16);
            let Some(insn) = spec.disassemble_ctx(&w, cursor, ctx).into_iter().next() else { break };
            let len = insn.bytes.len() as u64;
            if len == 0 {
                break;
            }
            last = Some((cursor, insn));
            cursor += len;
        }
        // calibration diagnostics: the two ways a re-decoding instrument disagrees with a
        // listing-based one (a mis-synchronised stream; a body end the listing never disassembled)
        if cursor != last_range.max + 1 {
            misaligned += 1;
        }
        if program.listing.code_unit_containing(Address::new(ram, last_range.max), 16).is_none() {
            listing_blind += 1;
        }
        arms[arm][0] += 1;
        match &last {
            Some((_, insn)) if is_terminator(insn.ops.last().and_then(|op| OpCode::from_u32(op.opcode))) => arms[arm][1] += 1,
            _ => {
                if list_failures {
                    let (la, mnem) = match &last { Some((a, i)) => (*a, i.mnemonic.clone()), None => (last_range.max, "<undecodable>".to_string()) };
                    failures.push(format!("{entry:08x}  body {:08x}..{:08x} ({} bytes)  last {la:08x} {mnem}  [{}]", last_range.min, last_range.max, last_range.max - last_range.min + 1, if corroborated { "corroborated" } else { "uncorroborated" }));
                }
            }
        }
    }
    let mut t = TableBuilder::new(&TERMINATOR_RATE);
    t.row().str("truth").u64(truth.len() as u64).u64(shift).f64(0.0).str(&format!("{truth_path} ({} addresses); corroboration window {shift} bytes", truth.len()));
    // BOTH arms, always: the control is what makes the second row readable; an empty arm has no
    // rate (0.0 with the note), never NaN
    for (name, a) in [("corroborated (CONTROL)", arms[0]), ("uncorroborated", arms[1])] {
        let (total, ok) = (a[0], a[1]);
        let (rate, note) = if total == 0 { (0.0, "no entries in this arm — no rate") } else { (100.0 * ok as f64 / total as f64, "") };
        t.row().str(name).u64(ok as u64).u64(total as u64).f64(rate).str(note);
    }
    t.row().str("diag").u64(misaligned as u64).u64(listing_blind as u64).f64(0.0).str("misaligned last-range decode, body end with NO listing unit");
    t.row().str("read").u64(0).u64(0).f64(0.0).str("the uncorroborated row ONLY against the control; a detector, not an estimator (failures cluster); says these are functions, nothing about their extents");
    for l in &failures {
        t.row().str("failure").u64(0).u64(0).f64(0.0).str(l);
    }
    Ok(t.finish(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_control_passes_and_truth_sources_parse() {
        self_test();
        let truth = read_truth("func 08048106 0 main class\n0x0001000a,foo\nnonsense\n");
        assert_eq!(truth.into_iter().collect::<Vec<_>>(), vec![0x1000a, 0x8048106]);
        assert_eq!(runs(vec![(0x10, 4), (0x14, 4), (0x30, 2)]), vec![(0x10, 0x18, 2), (0x30, 0x32, 1)]);
    }
}
