//! Evidence that a region of a binary was **not** produced by a given toolchain.
//!
//! Some functions in a real binary cannot be reproduced from C by the toolchain under test, and no
//! amount of decompiler work will change that: hand-written assembler, or objects linked in from a
//! library built by another compiler. Left unexamined they are indistinguishable from functions the
//! decompiler simply failed on, and the two need opposite responses.
//!
//! # Why this is not a vocabulary
//!
//! The obvious instrument is [`crate::recompile::Vocabulary`]: collect every (operation shape,
//! encoding form) pair a compiler has been seen to emit, then flag anything absent from it. That
//! was measured before this module was written and it does not survive calibration. Built from N
//! functions of *verified* output of the toolchain and then run against held-out functions of the
//! same verified output — where every flag is a false positive by construction — it gives:
//!
//! | vocabulary | instructions seen | false positives |
//! |---|---|---|
//! | 25 functions | 570 | 57.9% |
//! | 100 functions | 2,156 | 34.4% |
//! | 400 functions | 8,423 | 10.1% |
//! | 516 functions | 10,092 | 6.2% |
//!
//! Still 6% wrong at ten thousand instructions and still falling steeply, and among the forms it
//! called foreign were `f3 a5` (`REP MOVSD`) and `fc` (`CLD`) — which this compiler certainly does
//! emit; an entire emit arm exists because it does. Absence in a vocabulary means "unexercised" far
//! more often than it means "impossible", and a corpus large enough to fix that is larger than any
//! we can regenerate from source.
//!
//! # What this is instead
//!
//! A small curated table of **encoding dichotomies**. A dichotomy is one operation with two legal
//! encodings, where the toolchain is observed to use one and never the other. Each is verified
//! individually against known-good output of that toolchain before it is admitted, so each carries
//! its own measured false-positive rate rather than inheriting a corpus-wide one.
//!
//! The reasoning is still one-directional and the report reflects that: counts and the instructions
//! behind them, never a verdict. A function using the alternative encoding was not built by this
//! toolchain *at these settings*; that is a statement about toolchains, not about authorship, and
//! not about whether a human wrote it.

use std::collections::HashMap;

use crate::analysis::program::Program;
use crate::decompile::space::Address;
use crate::recompile::insn::{normalize, NoReloc, NormInsn, SemArg};

/// One operation with two legal encodings, where a toolchain uses one and never the other.
pub struct Dichotomy {
    pub name: &'static str,
    /// What the operation is, and what each encoding means — printed with the finding.
    pub doc: &'static str,
    /// Does this instruction belong to the operation class the dichotomy is about?
    pub selects: fn(&NormInsn) -> bool,
    /// The leading form byte this toolchain uses for that class.
    pub native: u8,
    /// The legal alternative it has never been observed to use.
    pub foreign: u8,
}

/// A register-to-register `MOV`: exactly one COPY, register to register, no memory operand.
fn is_reg_reg_mov(i: &NormInsn) -> bool {
    if i.is_nop() || i.sem.len() != 1 {
        return false;
    }
    let op = &i.sem[0];
    matches!(op.out.as_ref(), Some(SemArg::Reg(..))) && matches!(op.ins.first(), Some(SemArg::Reg(..)))
}

/// The verified dichotomies for Watcom 10.0a on x86-32.
///
/// Admission bar: the alternative encoding must appear **zero** times in known-good output of the
/// toolchain, measured on two independent populations, one of which anyone with this repository can
/// regenerate. `reg-reg-mov` was admitted on 62 moves across 28 committed self-compiled fixtures
/// (`mosura dev mve.fixtures`) and 1,876 moves across the subject's byte-exact functions — code
/// recompiled to identical bytes by this toolchain, so demonstrably within its reach — with no
/// load-form move in either.
pub static WATCOM_X86_32: &[Dichotomy] = &[Dichotomy {
    name: "reg-reg-mov",
    doc: "a register-to-register MOV has two legal encodings; this toolchain writes 89 /r (store form) and never 8b /r (load form)",
    selects: is_reg_reg_mov,
    native: 0x89,
    foreign: 0x8b,
}];

/// The dichotomy table for a (language, compiler spec) pair, if one is known.
pub fn table_for(language_id: &str, compiler_spec_id: &str) -> Option<&'static [Dichotomy]> {
    match (language_id, compiler_spec_id) {
        ("x86:LE:32:default", "watcom") => Some(WATCOM_X86_32),
        _ => None,
    }
}

/// One instruction using the encoding the toolchain does not use.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Entry of the function the instruction is in.
    pub function: u64,
    pub addr: u64,
    pub text: String,
    pub dichotomy: &'static str,
}

/// Per-dichotomy tallies over the scanned population.
#[derive(Debug, Clone)]
pub struct Tally {
    pub name: &'static str,
    pub doc: &'static str,
    /// Instructions using the toolchain's own encoding.
    pub native: usize,
    /// Instructions using the alternative it never emits.
    pub foreign: usize,
}

/// A contiguous run of flagged functions: linked-in objects sit together, decompiler defects do not.
#[derive(Debug, Clone)]
pub struct Band {
    pub lo: u64,
    pub hi: u64,
    pub functions: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Evidence {
    pub tallies: Vec<Tally>,
    pub findings: Vec<Finding>,
    /// Entries of the functions carrying at least one finding, ascending.
    pub flagged: Vec<u64>,
    pub bands: Vec<Band>,
    /// Functions examined (those with decodable bodies).
    pub scanned: usize,
}

/// The default locality gap for banding, matching the foreign-scope engine's.
pub const BAND_GAP: u64 = 0x2000;

/// Cluster ascending addresses into runs, splitting where the gap exceeds `gap`.
fn bands_of(flagged: &[u64], gap: u64) -> Vec<Band> {
    let mut out: Vec<Band> = Vec::new();
    for &va in flagged {
        match out.last_mut() {
            Some(b) if va.saturating_sub(b.hi) <= gap => {
                b.hi = va;
                b.functions += 1;
            }
            _ => out.push(Band { lo: va, hi: va, functions: 1 }),
        }
    }
    out
}

/// Apply a dichotomy table to already-decoded instructions, grouped by function entry.
pub fn survey_functions(functions: &[(u64, Vec<NormInsn>)], table: &'static [Dichotomy]) -> Evidence {
    let mut counts: HashMap<&'static str, (usize, usize)> = HashMap::new();
    let mut findings = Vec::new();
    let mut flagged: Vec<u64> = Vec::new();
    for (va, insns) in functions {
        let mut hit = false;
        for i in insns {
            for d in table {
                if !(d.selects)(i) {
                    continue;
                }
                let e = counts.entry(d.name).or_default();
                match i.form.first() {
                    Some(b) if *b == d.native => e.0 += 1,
                    Some(b) if *b == d.foreign => {
                        e.1 += 1;
                        hit = true;
                        findings.push(Finding { function: *va, addr: i.addr, text: i.text.trim().to_string(), dichotomy: d.name });
                    }
                    _ => {}
                }
            }
        }
        if hit {
            flagged.push(*va);
        }
    }
    flagged.sort_unstable();
    let tallies = table
        .iter()
        .map(|d| {
            let (native, foreign) = counts.get(d.name).copied().unwrap_or((0, 0));
            Tally { name: d.name, doc: d.doc, native, foreign }
        })
        .collect();
    let bands = bands_of(&flagged, BAND_GAP);
    Evidence { tallies, findings, flagged, bands, scanned: functions.len() }
}

/// Survey an analysed program with the table for its own language and compiler spec.
///
/// `None` when no dichotomy has been verified for that pair — the honest answer, rather than
/// applying another toolchain's habits to it.
pub fn survey(prog: &Program) -> Option<Evidence> {
    let table = table_for(&prog.language_id, &prog.compiler_spec_id)?;
    let ram = prog.default_space;
    let mut functions: Vec<(u64, Vec<NormInsn>)> = Vec::new();
    for f in prog.function_manager.functions() {
        let va = f.entry_point().offset;
        let body = f.body();
        let (Some(lo), Some(hi)) = (body.min_address(), body.max_address()) else { continue };
        let len = (hi.offset.saturating_sub(lo.offset) + 1) as usize;
        let mut bytes = Vec::with_capacity(len);
        for i in 0..len as u64 {
            match prog.memory.byte_at(Address::new(ram, lo.offset + i)) {
                Some(b) => bytes.push(b),
                None => break,
            }
        }
        if bytes.is_empty() {
            continue;
        }
        let Ok(insns) = normalize(&prog.language_id, &bytes, lo.offset, &NoReloc) else { continue };
        if insns.is_empty() {
            continue;
        }
        functions.push((va, insns));
    }
    functions.sort_by_key(|(va, _)| *va);
    Some(survey_functions(&functions, table))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lift(hex: &str) -> Vec<NormInsn> {
        let bytes: Vec<u8> =
            (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap()).collect();
        normalize("x86:LE:32:default", &bytes, 0x1000, &NoReloc).expect("language tables")
    }

    /// The dichotomy separates the two spellings of the same operation, and nothing else.
    #[test]
    fn the_two_spellings_of_a_register_move_are_told_apart() {
        let native = lift("89e5"); // mov ebp,esp — the toolchain's spelling
        let foreign = lift("8bec"); // mov ebp,esp — the same operation, the other encoding
        assert!(is_reg_reg_mov(&native[0]) && is_reg_reg_mov(&foreign[0]));
        let ev = survey_functions(&[(0x1000, native), (0x2000, foreign)], WATCOM_X86_32);
        assert_eq!(ev.tallies[0].native, 1);
        assert_eq!(ev.tallies[0].foreign, 1);
        assert_eq!(ev.flagged, vec![0x2000], "only the function using the other encoding is flagged");
        assert_eq!(ev.findings.len(), 1);
    }

    /// A move to or from memory uses `8b` legitimately and must never be selected: rejecting the
    /// whole opcode would flag most of a binary and mean nothing.
    #[test]
    fn a_load_from_memory_is_not_the_dichotomy() {
        let load = lift("8b4508"); // mov eax,[ebp+8]
        assert!(!is_reg_reg_mov(&load[0]), "a memory load is not a register-to-register move");
        let ev = survey_functions(&[(0x1000, load)], WATCOM_X86_32);
        assert_eq!(ev.tallies[0].foreign, 0);
        assert!(ev.flagged.is_empty());
    }

    /// Padding must not accuse a function; a self-move is a no-op however it is spelled.
    #[test]
    fn a_self_move_is_padding_not_evidence() {
        let pad = lift("8bc0"); // mov eax,eax
        assert!(pad[0].is_nop());
        let ev = survey_functions(&[(0x1000, pad)], WATCOM_X86_32);
        assert_eq!(ev.tallies[0].foreign, 0, "an interior self-move is not an instruction selection");
        assert!(ev.flagged.is_empty());
    }

    /// Flagged functions are banded so that linked-in objects, which sit together, are
    /// distinguishable from scattered findings.
    #[test]
    fn flagged_functions_cluster_into_bands() {
        let b = bands_of(&[0x1000, 0x1800, 0x9000, 0x9100], BAND_GAP);
        assert_eq!(b.len(), 2);
        assert_eq!((b[0].lo, b[0].hi, b[0].functions), (0x1000, 0x1800, 2));
        assert_eq!((b[1].lo, b[1].hi, b[1].functions), (0x9000, 0x9100, 2));
    }

    /// A toolchain with no verified dichotomy gets no table, rather than another one's habits.
    #[test]
    fn an_unverified_toolchain_has_no_table() {
        assert!(table_for("x86:LE:32:default", "watcom").is_some());
        assert!(table_for("x86:LE:32:default", "gcc").is_none());
        assert!(table_for("x86:LE:64:default", "watcom").is_none());
    }
}
