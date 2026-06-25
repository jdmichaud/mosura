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

    // Compute function bodies once disassembly has converged (Ghidra `Function.getBody`).
    if let Some((spec, ctx)) = crate::lang::load(&program.language_id) {
        analyzers::compute_function_bodies(&spec, &ctx, program);
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
mod a6_probe {
    use super::*;
    #[test]
    #[ignore]
    fn dump_basic_refs() {
        if crate::lang::load("x86:LE:64:default").is_none() { return; }
        let p = analyze_file(&crate::paths::analysis_corpus_dir().join("basic.elf")).unwrap();
        let mut refs: Vec<_> = p.reference_manager.references()
            .filter(|r| r.from.offset >= 0x401020 && r.from.offset < 0x4011b0)
            .map(|r| (r.from.offset, r.to.offset, r.ref_type.name())).collect();
        refs.sort();
        for (f,t,k) in refs { eprintln!("ref {f:08x} {t:08x} {k}"); }
    }
}
