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
//! # Known defects, measured on WAR2 — do not let the headline number launder these
//!
//! **Over-decoding: 7322 extra instruction starts in 255 contiguous runs** (104.4% of Ghidra's
//! instruction bytes in the code object), i.e. ~168-255 seeds each decoding a long stretch of
//! data as code. It creates almost no bad functions, but it is real. The discriminator has not
//! been found: `mustTerminate=true` was the candidate and is measurably dead (see above), and
//! the flow-disassembler bounds are also measured not to address it.
//!
//! **Three entries inside known function bodies**, at depths 37/59/65 bytes — NOT the benign
//! 1-5 byte Watcom prologue shift. Investigated rather than assumed, and the evidence says they
//! are secondary ENTRY POINTS, not extent corruption:
//!
//! ```text
//!   00010bb1  +37 into FUN_00010b8c         6 inbound UNCONDITIONAL_CALLs, NO fixup slot
//!   000604c4  +59 into __do_exit_with_msg__ 9 inbound UNCONDITIONAL_CALLs, NO fixup slot
//!             (crt-known; Ghidra has it too)
//!   00064c1c  +65 into FUN_00064bdb         2 UNCONDITIONAL_CALLs + 2 DATA (Ghidra has it too;
//!             mosura had it BEFORE this pass existed)
//! ```
//!
//! Two of the three have no relocation slot pointing at them at all, so this pass did not put
//! them there — they are ordinary direct-call targets, called from 6 and 9 distinct sites. An
//! address called from nine places is a real entry point; `__do_exit_with_msg__ + 59` is the
//! shape of a Watcom CRT alternate entry that skips the message setup. `00064c1c` predates this
//! pass entirely (present in the analyzer-only configuration).
//!
//! So the tracker records one function where the binary has two entries, and only `00010bb1` is
//! mosura-only — and it too is call-reached, not seeded here.
//!
//! **51 functions in neither oracle** — see `docs/war2-relocation-seed-candidates.md`. All sit
//! in inter-function gaps (median gap 422 bytes), so they are plausible unrecorded functions
//! rather than damage, but they are unadjudicated.
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
            sched.disassemble(&seeds);
        }
        true
    }
}
