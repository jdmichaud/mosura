//! **BEYOND-GHIDRA** — make a function at a code pointer stored in data, found by scanning.
//!
//! # Why this is not a port, and why it is off by default
//!
//! Ghidra creates a pointer at a data location whose value is a code address and disassembles the
//! target, but "never makes a function from a data pointer" (DataOperandReferenceAnalyzer.java:39;
//! AddressTableAnalyzer.java:281,294). [`RelocationSeedAnalyzer`](super::relocation_seed) already
//! disassembles such a target when the LE fixup table names its slot. Neither reaches a handler
//! stored as a FIELD in a data record on a flat image with no relocations: the second subject's
//! menu handlers sit at `record + 0xc`, reached only `table -> record -> field` through a runtime
//! index, so no instruction carries the field's address (nothing references it), the fields are
//! isolated between non-pointer members (no run for [`AddressTableAnalyzer`](super::address_table)),
//! the index is opaque to the constant propagator, and an X-32 image keeps no fixups
//! (docs/tasklist-2026-09-08.md §12, the data-held-pointer shape). The only static evidence they
//! are code is that a pointer-sized word in data holds a valid subroutine's address.
//!
//! So this pass scans initialized, non-executable memory for a pointer-sized word whose value is a
//! valid subroutine in executable memory, and — crossing Ghidra's policy deliberately, which is why
//! it is gated by [`Knobs::data_pointer_functions`](crate::switches::Knobs) and off by default —
//! makes a function there. The strict validator carries it: a blind scan of a data segment turns up
//! hundreds of words that merely LAND in the code range (fixed-point constants and the like), and
//! [`PseudoDisassembler::is_valid_subroutine`] (`mustTerminate`) is what separates a real routine
//! from a number, the same validator `relocation_seed` trusts for an isolated pointer. It is the
//! whole false-positive defence, so it is not relaxed.
//!
//! # Additive, and after the faithful analyzers
//!
//! Runs after [`AddressTableAnalyzer`](super::address_table) and
//! [`RelocationSeedAnalyzer`](super::relocation_seed) (`DATA_TYPE_PROPAGATION.after()`), and skips a
//! target that is already a function, so it only adds what the faithful and fixup paths did not —
//! its independent contribution stays measurable by leaving the option off. Gated by
//! `ground_truth_parity::data_pointer_functions_recovers_the_handlers` on the `datastruct` MVE (an
//! ELF whose `relocations` are empty, so it isolates the scan) in both directions.

use std::collections::HashSet;

use crate::analysis::analyzer::{Analyzer, AnalyzerType};
use crate::analysis::analyzers::address_table::MINIMUM_SAFE_ADDRESS;
use crate::analysis::manager::Scheduling;
use crate::analysis::priority::AnalysisPriority;
use crate::analysis::program::{AddressSet, Program};
use crate::analysis::pseudo_disassembler::PseudoDisassembler;
use crate::decompile::space::{Address, SpaceId};

pub struct DataPointerScanAnalyzer {
    pdis: PseudoDisassembler,
    ram: SpaceId,
}

impl DataPointerScanAnalyzer {
    /// `None` unless [`Knobs::data_pointer_functions`](crate::switches::Knobs) is on — the pass
    /// exists only for a caller that has asked to cross Ghidra's no-function-from-a-data-pointer
    /// policy.
    pub fn for_program(program: &Program) -> Option<DataPointerScanAnalyzer> {
        if !program.knobs.data_pointer_functions {
            return None;
        }
        Some(DataPointerScanAnalyzer {
            pdis: PseudoDisassembler::for_program(program)?,
            ram: program.default_space,
        })
    }
}

impl Analyzer for DataPointerScanAnalyzer {
    fn name(&self) -> &str {
        "Data Pointer Functions (beyond-Ghidra)"
    }
    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Byte
    }
    /// After `AddressTableAnalyzer` and `RelocationSeedAnalyzer`, so the faithful and fixup paths
    /// get first refusal and this adds only what they left.
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::DATA_TYPE_PROPAGATION.after()
    }
    fn added(&self, program: &mut Program, _set: &AddressSet, sched: &mut Scheduling) -> bool {
        // The values must point into executable memory to be code.
        let mut exec = AddressSet::new();
        for b in program.memory.blocks().filter(|b| b.is_execute()) {
            exec.add_range(b.start().space, b.start().offset, b.end().offset);
        }
        if exec.is_empty() {
            return true;
        }

        let addr_size = (program.addr_size_bits / 8) as usize;
        if addr_size != 4 && addr_size != 8 {
            return true;
        }
        let big_endian = program.big_endian;

        // Scan each initialized, non-executable block for a pointer-sized word — at ANY alignment,
        // because a record field need not fall on a pointer boundary (the subject's records stride
        // 0x1e) — whose value is a valid subroutine not already a function.
        let mut funcs = AddressSet::new();
        let mut seen: HashSet<u64> = HashSet::new();
        let blocks: Vec<(Address, u64)> = program
            .memory
            .blocks()
            .filter(|b| b.is_initialized() && !b.is_execute())
            .map(|b| (b.start(), b.size()))
            .collect();
        for (start, size) in blocks {
            let bytes = program.memory.read_window(start, size as usize);
            if bytes.len() < addr_size {
                continue;
            }
            for off in 0..=(bytes.len() - addr_size) {
                let w = &bytes[off..off + addr_size];
                let val = if addr_size == 4 {
                    let a: [u8; 4] = w.try_into().unwrap();
                    u64::from(if big_endian { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) })
                } else {
                    let a: [u8; 8] = w.try_into().unwrap();
                    if big_endian { u64::from_be_bytes(a) } else { u64::from_le_bytes(a) }
                };
                if val < MINIMUM_SAFE_ADDRESS {
                    continue;
                }
                let target = Address::new(self.ram, val);
                if !exec.contains(target) {
                    continue;
                }
                if !seen.insert(val) {
                    continue;
                }
                // Already a function — nothing to add (also the fast, common case).
                if program.function_manager.function_at(target).is_some() {
                    continue;
                }
                // The strict validator is the whole false-positive defence: a number that merely
                // lands in the code range does not decode into a terminating subroutine.
                // `allow_existing_code` matches `relocation_seed` / OperandReferenceAnalyzer:434 —
                // the evidence comes from data.
                if !self.pdis.is_valid_subroutine(program, target, true) {
                    continue;
                }
                funcs.add_range(target.space, target.offset, target.offset);
            }
        }
        if !funcs.is_empty() {
            sched.create_function(&funcs);
        }
        true
    }
}
