//! **BEYOND-GHIDRA** — seeding disassembly from the loader's relocation records.
//!
//! # Why this is not a port
//!
//! Ghidra has no LE/LX loader. WAR2 reaches Ghidra only through warcraft2-re's LE→ELF conversion
//! (`tools/ghidra/relocate_war2_elf.py`), which *bakes the patched pointer values into the image
//! and discards the fixup records*. Ghidra therefore never sees the linker's index of stored
//! pointers and must rediscover them statistically — which is what
//! [`AddressTableAnalyzer`](super::address_table) does, by looking for runs of things that
//! resemble pointers. A run-of-pointers heuristic cannot see an **isolated** pointer, one stored
//! between non-pointer struct fields; the fixup table names it exactly.
//!
//! mosura's LE loader has the records: 17,511 slots on WAR2, 3,178 pointing into the code
//! object — corroborated exactly against warcraft2-re's independent `le_fixups.py`.
//!
//! # Oracle
//!
//! Not Ghidra, which cannot do this at all. Validated against the **expert function tracker**
//! (`warcraft2-re/analysis/decomp-tracker.csv`, 2120 functions) and the self-compiled
//! `lestruct.watcom-le` MVE, whose truth comes from the Open Watcom linker map
//! (`ground_truth_parity::data_pointer_le_seeding`).
//!
//! # Additive, never substitutive
//!
//! [`AddressTableAnalyzer`](super::address_table) stays fully live and runs first; this pass adds
//! only seeds it did not produce, so its independent contribution stays measurable by disabling
//! this one.
//!
//! # The validator
//!
//! Each candidate goes through [`PseudoDisassembler::is_valid_subroutine`] — `mustTerminate=true`.
//! That is which of Ghidra's two validators fits the evidence, not a tuning choice: the permissive
//! `isValidCode` is what `AddressTable.getFunctionEntries` (:785) uses for a target corroborated
//! by a whole pointer run agreeing, and the strict `isValidSubroutine` is what
//! `OperandReferenceAnalyzer` (:434) uses for an **isolated** pointer. A relocation slot is the
//! isolated case.
//!
//! **Measured caveat, recorded so it is not rediscovered:** on WAR2 the two validators produce
//! *identical* results (same 1965 functions, same coverage, same extra-decode runs).
//! `mustTerminate` is close to vacuous at that scale because `checkValidSubroutine`'s terminal
//! condition is `didTerminate || !mustTerminate || didCallValidSubroutine`, and a walk through
//! arbitrary bytes on a program with ~1600 known functions almost always meets a `0xc3` or
//! reaches a call to some known function. The strict one is used anyway because it is the correct
//! match to the evidence; it simply does not discriminate here.
//!
//! # What it does NOT do
//!
//! It creates no functions. Each validated target goes to the same downstream path the
//! address-table analyzer feeds — disassembly — and functions arise from the direct calls inside
//! the newly decoded code, the discipline Ghidra applies to every data-derived address
//! (`AddressTableAnalyzer.java:281,294`; `OperandReferenceAnalyzer.java:617`;
//! `DataOperandReferenceAnalyzer.java:39`).

use crate::analysis::analyzer::{Analyzer, AnalyzerType};
use crate::analysis::manager::Scheduling;
use crate::analysis::priority::AnalysisPriority;
use crate::analysis::program::{AddressSet, Program};
use crate::analysis::pseudo_disassembler::PseudoDisassembler;
use crate::decompile::space::Address;

pub struct RelocationSeedAnalyzer {
    pdis: PseudoDisassembler,
}

impl RelocationSeedAnalyzer {
    /// Build the pass, or `None` when the program carries no relocation records (every non-LE
    /// format today) or the SLEIGH tables are unavailable — in either case it is inert.
    pub fn for_program(program: &Program) -> Option<RelocationSeedAnalyzer> {
        if program.relocation_table.is_empty() {
            return None;
        }
        Some(RelocationSeedAnalyzer { pdis: PseudoDisassembler::for_program(program)? })
    }
}

impl Analyzer for RelocationSeedAnalyzer {
    fn name(&self) -> &str {
        "Relocation Pointer Seeds (beyond-Ghidra)"
    }
    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Byte
    }
    /// Immediately after `AddressTableAnalyzer` (`DATA_TYPE_PROPOGATION.before()`), so the
    /// faithful analyzer gets first refusal on every address.
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::DATA_TYPE_PROPAGATION
    }

    fn added(&self, program: &mut Program, _set: &AddressSet, sched: &mut Scheduling) -> bool {
        // Executable memory bounds the candidates: a relocation pointing at data is a data
        // pointer, and nothing here tries to guess otherwise.
        let mut exec = AddressSet::new();
        for b in program.memory.blocks().filter(|b| b.is_execute()) {
            exec.add_range(b.start().space, b.start().offset, b.end().offset);
        }
        if exec.is_empty() {
            return true;
        }

        let targets: Vec<Address> = program
            .relocation_table
            .relocations()
            .map(|r| Address::new(r.address.space, r.value))
            .filter(|t| exec.contains(*t))
            .collect();

        let mut seeds = AddressSet::new();
        for t in targets {
            // Already decoded — the question is settled.
            if program.listing.code_unit_at(t).is_some() {
                continue;
            }
            // `allow_existing_code` mirrors Ghidra's `instr == null` at
            // OperandReferenceAnalyzer:434 — the reference comes from data, so true.
            if !self.pdis.is_valid_subroutine(program, t, true) {
                continue;
            }
            seeds.add_range(t.space, t.offset, t.offset);
        }
        if !seeds.is_empty() {
            sched.code_defined(&seeds);
        }
        true
    }
}
