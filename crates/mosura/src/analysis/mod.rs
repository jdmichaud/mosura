//! The **auto-analysis port** (A0+; plan `docs/analysis-port-plan.md`).
//!
//! A faithful port of Ghidra's auto-analysis — the subsystem that takes a binary
//! *file* and decides *what to decompile*: loaders, the priority-worklist analyzer
//! framework, disassembly + function discovery, references + `SymbolicPropogator`,
//! and the decompiler-driven switch/parameter analyzers. Distinct from the
//! decompiler port (`crate::decompile`), which works on one already-located
//! function.
//!
//! **A0 (this module today): the oracle contract + harness only.** [`snapshot`]
//! defines the canonical converged-`Program` view captured from Ghidra and
//! committed under `goldens/analysis/`; [`analyze_binary`] is the entry point
//! mosura's analyzers will implement, returning [`Unimplemented`] until A1–A4
//! land. `tests/analysis_parity.rs` holds the red baseline against the goldens.

pub mod analyzer;
pub mod analyzers;
pub mod decompiler;
pub mod flowtype;
pub mod loader;
pub mod manager;
pub mod priority;
pub mod program;
pub mod snapshot;
pub mod symbolic;

pub use program::Program;
pub use snapshot::Snapshot;

use std::path::Path;

/// An error from [`analyze_binary`].
#[derive(Debug)]
pub enum AnalysisError {
    Io(std::io::Error),
    Load(loader::LoadError),
}
impl std::fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalysisError::Io(e) => write!(f, "io: {e}"),
            AnalysisError::Load(e) => write!(f, "load: {e}"),
        }
    }
}
impl std::error::Error for AnalysisError {}
impl From<std::io::Error> for AnalysisError {
    fn from(e: std::io::Error) -> Self {
        AnalysisError::Io(e)
    }
}
impl From<loader::LoadError> for AnalysisError {
    fn from(e: loader::LoadError) -> Self {
        AnalysisError::Load(e)
    }
}

/// Run mosura's auto-analysis over a binary file and produce its converged
/// [`Snapshot`], to be diffed against the Ghidra golden.
///
/// Returns the **loader-stage** snapshot (memory map + loader functions/entries/symbols),
/// the state the loader-detail goldens are captured at. The auto-analysis passes
/// ([`analyze`]) run separately and produce a converged state that A4–A7 will gate against
/// their own goldens (A4's partial analysis matches no converged golden yet).
pub fn analyze_binary(path: &Path) -> Result<Snapshot, AnalysisError> {
    let data = std::fs::read(path)?;
    let program = loader::load(&data)?;
    Ok(program.snapshot())
}

/// Load a binary and run the full auto-analysis pipeline ([`analyze`]), returning the
/// converged [`Program`].
pub fn analyze_file(path: &Path) -> Result<Program, AnalysisError> {
    let data = std::fs::read(path)?;
    let mut program = loader::load(&data)?;
    analyze(&mut program);
    Ok(program)
}

/// Run the auto-analysis pipeline over a loaded [`Program`] (A3 framework + A4 analyzers):
/// recursive-descent disassembly from the loader's functions and entry points, creating
/// code units and discovering functions at call targets, to a fixpoint.
pub fn analyze(program: &mut Program) {
    use crate::analysis::manager::AutoAnalysisManager;
    use crate::analysis::program::AddressSet;

    // A7 Task 3: flag the known non-returning library functions (exit/abort/longjmp/…) by
    // name before disassembly, so a direct call to one stops linear fall-through (Ghidra
    // NoReturnFunctionAnalyzer, FORMAT_ANALYSIS — before disassembly). Faithful name lists
    // from Ghidra's data/ElfFunctionsThatDoNotReturn + PEFunctionsThatDoNotReturn.
    analyzers::noreturn::analyze(program);

    let mut mgr = AutoAnalysisManager::new();
    if let Some(d) = analyzers::Disassembler::for_program(program) {
        mgr.add_analyzer(Box::new(d), program);
    }
    mgr.add_analyzer(Box::new(analyzers::FunctionCreator::new(program)), program);
    if let Some(cp) = analyzers::ConstantPropagationAnalyzer::for_program(program) {
        mgr.add_analyzer(Box::new(cp), program);
    }
    // A6: decompiler-driven switch recovery (COMPUTED_JUMP refs from recovered jump tables).
    mgr.add_analyzer(Box::new(analyzers::switch::DecompilerSwitchAnalyzer::new(program)), program);
    // A6: external-jump flow override — a PLT tail-call `jmp *[GOT]` into the EXTERNAL block
    // becomes COMPUTED_CALL_TERMINATOR (Ghidra OperandReferenceAnalyzer.checkForExternalJump).
    mgr.add_analyzer(Box::new(analyzers::external_jump::ExternalJumpAnalyzer::new()), program);

    // Seed disassembly from the loader's functions + entry points. Entry points are
    // filtered to executable memory here (Ghidra `createEntryFunction`'s `isExecute`
    // check — a data export like `__bss_start` is not a function); call targets found
    // during disassembly are *not* gated this way (Ghidra makes a function at every
    // direct call target, even one pointing into data).
    let mut seed = AddressSet::new();
    for f in program.function_manager.functions() {
        let e = f.entry_point();
        seed.add_range(e.space, e.offset, e.offset);
    }
    for e in &program.entry_points {
        if program.memory.block_at(*e).is_some_and(|b| b.is_execute()) {
            seed.add_range(e.space, e.offset, e.offset);
        }
    }
    mgr.scheduling().function_defined(&seed);
    mgr.run(program);

    // ELF GOT/PLT markup (Ghidra `ElfDefaultGotPltMarkup.processLinkageTable`, invoked by
    // `ElfProgramBuilder.processGotPlt` during load): linearly disassemble the whole `.plt`
    // section so the lazy-resolve stubs — unreachable by normal flow after relocation (e.g.
    // PLT[0] and each entry's `push; jmp PLT[0]` tail) — get decoded. Done here rather than
    // in the loader because mosura's SLEIGH-driven disassembly lives in the analysis phase;
    // the closure (re-seeding each gap, following flow) matches Ghidra's `disassemble` loop.
    plt_linear_sweep(&mut mgr, program);

    // Compute function bodies once disassembly has converged (Ghidra `Function.getBody`).
    if let Some((spec, ctx)) = crate::lang::load(&program.language_id) {
        analyzers::compute_function_bodies(&spec, &ctx, program);
    }

    // A7 Task 2: GCC exception-frame analysis — the `.eh_frame_hdr` FDE table's INDIRECTION
    // (function start) + DATA (FDE) references (Ghidra GccExceptionAnalyzer →
    // EhFrameHeaderSection → FdeTable).
    analyzers::eh_frame::analyze(program);

    // A7 Task 1: shared-return tail calls (Ghidra SharedReturnAnalyzer + SharedReturnAnalysisCmd).
    // Run after disassembly + reference recovery + body computation have converged, which is
    // the state Ghidra's FUNCTION_ANALYZER precondition assumes (functions, flow refs, and
    // bodies present). In Ghidra the PLT stubs are disassembled during load, so the resolve-
    // tail jumps already exist when each PLT function is created; mosura disassembles the PLT
    // in the deferred `plt_linear_sweep`, so the shared-return scan must follow it.
    shared_return_pass(program);
}

/// Run the shared-return analysis over the full converged function set (Ghidra
/// `SharedReturnAnalysisCmd.applyTo` driven by `SharedReturnAnalyzer`). If it creates a new
/// function (a contiguous-function boundary-crossing tail call, e.g. `basic`'s PLT[0]),
/// recover that function's references and recompute bodies so the new code is fully analyzed.
fn shared_return_pass(program: &mut Program) {
    use crate::analysis::analyzer::Analyzer;
    use crate::analysis::program::AddressSet;
    let Some(sr) = analyzers::shared_return::SharedReturnAnalyzer::for_program(program) else {
        return;
    };
    // The "added" set is every current function (the destination functions to examine).
    let mut all_funcs = AddressSet::new();
    for f in program.function_manager.functions() {
        let e = f.entry_point();
        all_funcs.add_range(e.space, e.offset, e.offset);
    }
    let before: std::collections::HashSet<(u32, u64)> = program
        .function_manager
        .functions()
        .map(|f| (f.entry_point().space.0, f.entry_point().offset))
        .collect();
    let mut sched = crate::analysis::manager::Scheduling::default();
    sr.added(program, &all_funcs, &mut sched);
    // If new functions were created (e.g. PLT[0]), recover the references of *only the new*
    // functions (the constant propagator emits the READ at `0x401020 → 0x403ff0`) and
    // recompute bodies. Re-running the propagator over already-analyzed functions would
    // re-introduce the raw flow references that later analyzers (external-jump) had already
    // retyped, so the new-function set is isolated here.
    let new_entries: Vec<crate::decompile::space::Address> = program
        .function_manager
        .functions()
        .map(|f| f.entry_point())
        .filter(|e| !before.contains(&(e.space.0, e.offset)))
        .collect();
    if !new_entries.is_empty() {
        if let Some(cp) = analyzers::ConstantPropagationAnalyzer::for_program(program) {
            let mut set = AddressSet::new();
            for e in &new_entries {
                set.add_range(e.space, e.offset, e.offset);
            }
            let mut s = crate::analysis::manager::Scheduling::default();
            cp.added(program, &set, &mut s);
        }
        if let Some((spec, ctx)) = crate::lang::load(&program.language_id) {
            analyzers::compute_function_bodies(&spec, &ctx, program);
        }
    }
}

/// Ghidra `ElfDefaultGotPltMarkup.processPLTSection` head size — the assumed PLT head
/// (`PLT[0]`, the lazy-resolver stub) skipped by the linear sweep; it is reached only via
/// the flow from each entry's resolve tail (`push; jmp PLT[0]`), so its internal padding
/// never gets seeded. (x86; ARM/AARCH64 use 0, but mosura's ELF path is x86-64.)
const ASSUMED_PLT_HEAD_SIZE: u64 = 16;

/// Linearly disassemble the `.plt` section (Ghidra `ElfDefaultGotPltMarkup.disassemble`,
/// from `processPLTSection`): seed at `pltBlock.start + 16` (skipping the head) and, while
/// any address in the range is undecoded, seed disassembly at the lowest gap and run to a
/// fixpoint (flow-following), then advance past what was decoded — exactly Ghidra's
/// `while (!set.isEmpty()) { disassemble(set.getMinAddress()); set.delete(disset); }`. The
/// head (`PLT[0]`) is decoded only by the flow reaching it from a resolve tail, so its
/// padding is never seeded directly (Ghidra leaves it undefined too).
fn plt_linear_sweep(mgr: &mut crate::analysis::manager::AutoAnalysisManager, program: &mut Program) {
    use crate::analysis::program::AddressSet;
    use crate::decompile::space::Address;
    let ram = program.default_space;
    let Some((block_start, end)) =
        program.memory.blocks().find(|b| b.name() == ".plt").map(|b| (b.start().offset, b.end().offset))
    else {
        return; // no .plt section (e.g. statically linked / non-ELF)
    };
    let start = block_start + ASSUMED_PLT_HEAD_SIZE;
    // Bounded by the number of code units the range can hold.
    let mut a = start;
    while a <= end {
        if program.listing.code_unit_at(Address::new(ram, a)).is_some() {
            // Skip the already-decoded instruction.
            let len = program.listing.code_unit_at(Address::new(ram, a)).map(|c| c.length()).unwrap_or(1);
            a += u64::from(len.max(1));
            continue;
        }
        // Seed this gap and let the flow disassembler (+ follow-on analyzers) run.
        let mut s = AddressSet::new();
        s.add_range(ram, a, a);
        mgr.scheduling().code_defined(&s);
        mgr.run(program);
        // Advance: if the gap decoded, step past it; otherwise move on by one byte.
        let len = program.listing.code_unit_at(Address::new(ram, a)).map(|c| c.length()).unwrap_or(0);
        a += u64::from(len.max(1));
    }
}

#[cfg(test)]
mod a4_tests {
    use super::*;

    #[test]
    fn freestanding_recursive_descent_disassembly() {
        let data = std::fs::read(crate::paths::analysis_corpus_dir().join("freestanding.elf"))
            .expect("freestanding.elf");
        let mut program = loader::load(&data).expect("load");
        let funcs_before = program.function_manager.function_count();
        analyze(&mut program);

        // Disassembly happened (code units laid down)…
        assert!(!program.listing.is_empty(), "no code units produced — SLEIGH tables present?");
        // …covering every function's entry (recursive descent reached them all).
        for f in program.function_manager.functions() {
            assert!(
                program.listing.code_unit_at(f.entry_point()).is_some(),
                "no code unit at function {}",
                f.name()
            );
        }
        // freestanding's 3 functions are all loader-known; none newly discovered.
        assert_eq!(program.function_manager.function_count(), funcs_before);

        // _start calls add + sum_to → two UNCONDITIONAL_CALL references to them.
        let call_targets: std::collections::BTreeSet<u64> = program
            .reference_manager
            .references()
            .filter(|r| r.ref_type == crate::analysis::program::RefType::UnconditionalCall)
            .map(|r| r.to.offset)
            .collect();
        assert!(
            call_targets.contains(&0x0040_1000) && call_targets.contains(&0x0040_1014),
            "expected call refs to add(0x401000) + sum_to(0x401014), got {call_targets:x?}"
        );
    }
}

#[cfg(test)]
mod a6_tests {
    use super::*;
    use std::collections::BTreeSet;

    /// A6: the decompiler-driven switch analyzer recovers `switchtab`'s jump table and
    /// emits exactly Ghidra's COMPUTED_JUMP edges (BRANCHIND → the 7 case targets).
    #[test]
    fn switch_analyzer_matches_ghidra_computed_jumps() {
        if crate::lang::load("x86:LE:64:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        let p = analyze_file(&crate::paths::analysis_corpus_dir().join("switchtab.elf")).unwrap();
        let snap = p.snapshot();
        let golden = crate::analysis::snapshot::parse(
            &std::fs::read_to_string(crate::paths::analysis_goldens_dir().join("switchtab.snapshot"))
                .unwrap(),
        );
        let cj = |s: &crate::analysis::snapshot::Snapshot| -> BTreeSet<(u64, u64)> {
            s.refs.iter().filter(|r| r.kind == "COMPUTED_JUMP").map(|r| (r.from, r.to)).collect()
        };
        let (mine, gold) = (cj(&snap), cj(&golden));
        assert_eq!(mine, gold, "switch COMPUTED_JUMP edges must match Ghidra exactly");
        assert_eq!(mine.len(), 7, "7 case targets");
    }
}

#[cfg(test)]
mod a5_tests {
    use super::*;

    /// The SymbolicPropogator recovers data references on a real binary: every data
    /// reference target lies in mapped memory, and basic's GOT-relative reads are found.
    #[test]
    fn basic_recovers_data_references() {
        use crate::analysis::program::RefType;
        let data = std::fs::read(crate::paths::analysis_corpus_dir().join("basic.elf")).unwrap();
        let mut p = loader::load(&data).unwrap();
        analyze(&mut p);

        let data_refs: Vec<_> = p
            .reference_manager
            .references()
            .filter(|r| matches!(r.ref_type, RefType::Read | RefType::Write | RefType::Data))
            .collect();
        assert!(data_refs.len() >= 5, "expected several data refs, got {}", data_refs.len());
        // Every recovered reference targets mapped memory (the makeReference gate).
        for r in &data_refs {
            assert!(p.memory.contains(r.to), "ref to unmapped {:08x}", r.to.offset);
        }
    }
}




#[cfg(test)]
mod a6_typed_refs {
    use super::*;

    /// A6 indirect-flow + parameter analysis emit Ghidra's *exact* reference types on
    /// basic, not just the (from,to) pairs the recall gate checks: the PLT tail-call's
    /// COMPUTED_CALL_TERMINATOR, PLT[0]'s INDIRECTION, and the two pointer-argument PARAMs
    /// (with no stray DATA at the param-set instructions).
    #[test]
    fn basic_indirect_flow_and_param_types_match_ghidra() {
        if crate::lang::load("x86:LE:64:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        let p = analyze_file(&crate::paths::analysis_corpus_dir().join("basic.elf")).unwrap();
        let typed = |from: u64, to: u64| -> Vec<&'static str> {
            let ram = p.default_space;
            use crate::decompile::space::Address;
            p.reference_manager
                .references()
                .filter(|r| r.from == Address::new(ram, from) && r.to == Address::new(ram, to))
                .map(|r| r.ref_type.name())
                .collect()
        };
        // Task 1: the PLT `jmp *[GOT]` resolving to the external printf is a tail call.
        assert_eq!(typed(0x40_1030, 0x40_5008), vec!["COMPUTED_CALL_TERMINATOR"]);
        // Task 2: PLT[0]'s `jmp *[GOT]` to the resolver slot is an INDIRECTION.
        assert_eq!(typed(0x40_1026, 0x40_3ff8), vec!["INDIRECTION"]);
        // Task 3: pointer arguments at the two call sites are PARAM — and only PARAM (the
        // speculative DATA ref the scalar analyzer would skip is dropped).
        assert_eq!(typed(0x40_1054, 0x40_1168), vec!["PARAM"]);
        assert_eq!(typed(0x40_1194, 0x40_2004), vec!["PARAM"]);
    }
}

#[cfg(test)]
mod a7_shared_return {
    use super::*;

    /// A7 Task 1 — the SharedReturnAnalyzer recovers PLT[0] as a function and retypes its
    /// inbound resolve-tail jump as a call (Ghidra SharedReturnAnalysisCmd).
    #[test]
    fn basic_shared_return_recovers_plt0() {
        if crate::lang::load("x86:LE:64:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        let p = analyze_file(&crate::paths::analysis_corpus_dir().join("basic.elf")).unwrap();
        let ram = p.default_space;
        use crate::decompile::space::Address;

        // FUN_00401020 (PLT[0]) is now a function — the contiguous-function boundary-crossing
        // backward jump from the printf@plt resolve tail created it.
        assert!(
            p.function_manager.function_at(Address::new(ram, 0x40_1020)).is_some(),
            "FUN_00401020 (PLT[0]) must be recovered as a function"
        );

        let typed = |from: u64, to: u64| -> Vec<&'static str> {
            p.reference_manager
                .references()
                .filter(|r| r.from == Address::new(ram, from) && r.to == Address::new(ram, to))
                .map(|r| r.ref_type.name())
                .collect()
        };
        // The resolve-tail `jmp 0x401020` is retyped JUMP → CALL (CALL_TERMINATOR flow →
        // UNCONDITIONAL_CALL reference, per RefType.CALL_TERMINATOR's doc).
        assert_eq!(typed(0x40_103b, 0x40_1020), vec!["UNCONDITIONAL_CALL"]);
        // The READ inside PLT[0] (`push 0x403ff0(%rip)`) is recovered once the function exists.
        assert_eq!(typed(0x40_1020, 0x40_3ff0), vec!["READ"]);
    }
}

#[cfg(test)]
mod a7_eh_frame {
    use super::*;
    use std::collections::BTreeSet;

    /// A7 Task 2 — the EH-frame analyzer recovers the `.eh_frame_hdr` FDE-table references
    /// (Ghidra GccExceptionAnalyzer → EhFrameHeaderSection → FdeTable): the 6 INDIRECTION refs
    /// to the protected functions, exactly matching the golden, with no spurious additions.
    #[test]
    fn basic_eh_frame_hdr_indirection_refs() {
        if crate::lang::load("x86:LE:64:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        let p = analyze_file(&crate::paths::analysis_corpus_dir().join("basic.elf")).unwrap();
        let snap = p.snapshot();
        let golden = crate::analysis::snapshot::parse(
            &std::fs::read_to_string(crate::paths::analysis_goldens_dir().join("basic.snapshot")).unwrap(),
        );
        let indir = |s: &crate::analysis::snapshot::Snapshot| -> BTreeSet<(u64, u64)> {
            // The .eh_frame_hdr table's INDIRECTION refs (the FDE initial_loc → function).
            s.refs
                .iter()
                .filter(|r| r.kind == "INDIRECTION" && (0x40_2008..=0x40_2043).contains(&r.from))
                .map(|r| (r.from, r.to))
                .collect()
        };
        let (mine, gold) = (indir(&snap), indir(&golden));
        assert_eq!(mine, gold, ".eh_frame_hdr INDIRECTION refs must match Ghidra exactly");
        assert_eq!(mine.len(), 6, "6 FDE-table entries");
    }

    /// A7 Task 5 — the EH-frame analyzer defines the data units Ghidra's
    /// `EhFrameHeaderSection`/`FdeTable` create (the `eh_frame_hdr` struct, the encoded
    /// `eh_frame_ptr` + `fde_count` `dword`s, a `fde_table_entry` per FDE-table row) **and**
    /// the field-level `.eh_frame` CIE/FDE markup (`Cie.create`/`FrameDescriptionEntry.create`:
    /// length/id `dword`s, version `byte`, augmentation `string`, code/data-align
    /// `uleb128`/`sleb128`, RA `byte`, aug-data-length `uleb128`, FDE-encoding `dwfenc`, the
    /// CFI `byte[]`s, the FDE pc_begin/pc_range, and the end-of-frame `dword`). Verified
    /// against the Ghidra oracle (`getDefinedData`) for basic.elf, scoped to the two EH-frame
    /// blocks (`0x402008..=0x402128`) — the rest of `defined_data` is loader markup.
    #[test]
    fn basic_eh_frame_defines_data_units() {
        if crate::lang::load("x86:LE:64:default").is_none() {
            return;
        }
        let p = analyze_file(&crate::paths::analysis_corpus_dir().join("basic.elf")).unwrap();
        let mut mine: Vec<(u64, String, u32)> = p
            .defined_data
            .iter()
            .map(|(a, ty, len)| (a.offset, ty.clone(), *len))
            .filter(|(a, _, _)| (0x40_2008..=0x40_2128).contains(a))
            .collect();
        mine.sort();
        let expect: Vec<(u64, String, u32)> = vec![
            (0x402008, "eh_frame_hdr".into(), 4),
            (0x40200c, "dword".into(), 4),
            (0x402010, "dword".into(), 4),
            (0x402014, "fde_table_entry".into(), 8),
            (0x40201c, "fde_table_entry".into(), 8),
            (0x402024, "fde_table_entry".into(), 8),
            (0x40202c, "fde_table_entry".into(), 8),
            (0x402034, "fde_table_entry".into(), 8),
            (0x40203c, "fde_table_entry".into(), 8),
            (0x402048, "dword".into(), 4),
            (0x40204c, "dword".into(), 4),
            (0x402050, "byte".into(), 1),
            (0x402051, "string".into(), 3),
            (0x402054, "uleb128".into(), 1),
            (0x402055, "sleb128".into(), 1),
            (0x402056, "byte".into(), 1),
            (0x402057, "uleb128".into(), 1),
            (0x402058, "dwfenc".into(), 1),
            (0x402059, "byte[7]".into(), 7),
            (0x402060, "dword".into(), 4),
            (0x402064, "dword".into(), 4),
            (0x402068, "dword".into(), 4),
            (0x40206c, "qword".into(), 8),
            (0x402074, "dword".into(), 4),
            (0x402078, "dword".into(), 4),
            (0x40207c, "byte".into(), 1),
            (0x40207d, "string".into(), 3),
            (0x402080, "uleb128".into(), 1),
            (0x402081, "sleb128".into(), 1),
            (0x402082, "byte".into(), 1),
            (0x402083, "uleb128".into(), 1),
            (0x402084, "dwfenc".into(), 1),
            (0x402085, "byte[7]".into(), 7),
            (0x40208c, "dword".into(), 4),
            (0x402090, "dword".into(), 4),
            (0x402094, "dword".into(), 4),
            (0x402098, "qword".into(), 8),
            (0x4020a0, "dword".into(), 4),
            (0x4020a4, "dword".into(), 4),
            (0x4020a8, "dword".into(), 4),
            (0x4020ac, "dword".into(), 4),
            (0x4020b0, "uleb128".into(), 1),
            (0x4020b1, "byte[23]".into(), 23),
            (0x4020c8, "dword".into(), 4),
            (0x4020cc, "dword".into(), 4),
            (0x4020d0, "dword".into(), 4),
            (0x4020d4, "dword".into(), 4),
            (0x4020d8, "uleb128".into(), 1),
            (0x4020d9, "byte[15]".into(), 15),
            (0x4020e8, "dword".into(), 4),
            (0x4020ec, "dword".into(), 4),
            (0x4020f0, "dword".into(), 4),
            (0x4020f4, "dword".into(), 4),
            (0x4020f8, "uleb128".into(), 1),
            (0x4020f9, "byte[15]".into(), 15),
            (0x402108, "dword".into(), 4),
            (0x40210c, "dword".into(), 4),
            (0x402110, "dword".into(), 4),
            (0x402114, "dword".into(), 4),
            (0x402118, "uleb128".into(), 1),
            (0x402119, "byte[15]".into(), 15),
            (0x402128, "dword".into(), 4),
        ];
        assert_eq!(mine, expect, "eh_frame data units must match the Ghidra oracle");
    }
}

#[cfg(test)]
mod a7_diag_noreturn {
    use super::*;
    #[test]
    #[ignore]
    fn cnv_noreturn_count() {
        let path = std::path::Path::new("/home/jd/cnv.exe");
        if !path.exists() { eprintln!("no cnv"); return; }
        let p = analyze_file(path).unwrap();
        eprintln!("cnv noreturn-flagged: {}", p.noreturn_functions.len());
        eprintln!("cnv functions: {}", p.function_manager.function_count());
        // sanity: every flagged address is in mapped memory
        use crate::decompile::space::Address;
        let ram = p.default_space;
        for (s,o) in &p.noreturn_functions {
            assert!(p.memory.contains(Address::new(crate::decompile::space::SpaceId(*s), *o)) || *s != ram.0);
        }
    }
}
