//! `NoReturnFunctionAnalyzer` (A7 Task 3) — a port of Ghidra's
//! `app/plugin/core/analysis/NoReturnFunctionAnalyzer.java` ("Non-Returning Functions -
//! Known"), which flags by-name the standard library functions that do not return
//! (`exit`, `abort`, `longjmp`, `__stack_chk_fail`, `_Unwind_Resume`, …) so the
//! disassembler stops linear fall-through after a call to one.
//!
//! The function-name lists are **taken verbatim from Ghidra's data files**
//! (`Ghidra/Features/Base/data/ElfFunctionsThatDoNotReturn`,
//! `…/PEFunctionsThatDoNotReturn`), selected by `noReturnFunctionConstraints.xml`
//! (ELF→Elf…, PE→PE…). They are NOT hand-derived. The matching logic is Ghidra's
//! `added()`: strip leading `_` from the symbol name, then exact-match against the list
//! (which is itself stored without leading `_`). No list entry carries a `*` wildcard, so
//! the wildcard-prefix branch is unused in practice but ported for fidelity.
//!
//! Observable effect in the snapshot: the disassembler does not over-decode the bytes that
//! fall through a *direct* call to a non-returning function. On the **entire currently
//! available corpus this analyzer is inert**, which was verified, not assumed:
//!   - `basic`/`freestanding` (ELF): no listed function is reached by a direct call in
//!     decoded code, so there is nothing to truncate (a clean no-op).
//!   - `cnv` (PE): mosura surfaces no symbol whose underscore-stripped name is on the PE
//!     list (its imports are not exposed as `exit`/`abort`/`ExitProcess`/… symbols mosura
//!     iterates), so 0 functions are flagged — measured via the `a7_diag_noreturn`
//!     diagnostic (`cnv noreturn-flagged: 0`, full analysis).
//! The port is therefore faithful in its name lists and matching/flow logic but has **no
//! validatable effect on the available binaries**; it would fire on a binary that issues a
//! direct `call` to a listed function whose symbol mosura resolves at this stage. The "No
//! Return" flag itself (`Function.setNoReturn`) is not part of the analysis snapshot schema,
//! so even when it fires the only snapshot-visible consequence is fewer `insn`/`ref` lines
//! after the call — a subset-preserving reduction, never a new fact.
//!
//! Ghidra runs this as a BYTE_ANALYZER at `FORMAT_ANALYSIS.before().before().before()` —
//! before disassembly, "since non-returning functions cause many issues that are slow to
//! fix later." mosura runs it as a pre-disassembly pass over the loader's symbols, marking
//! `Program::noreturn_functions` (entries + the PLT thunks that resolve to them) so the
//! disassembler's fall-through decision can consult it.

use crate::analysis::program::{Program, RefType};
use crate::decompile::space::Address;

/// `ElfFunctionsThatDoNotReturn` — verbatim from
/// `Ghidra/Features/Base/data/ElfFunctionsThatDoNotReturn` (comments stripped). Names are
/// stored without leading `_` (Ghidra strips both list and symbol names before matching).
const ELF_NORETURN_NAMES: &[&str] = &[
    "exit",
    "cexit",
    "c_exit",
    "abort",
    "reboot",
    "longjmp",
    "longjmp_chk",
    "siglongjmp",
    "panic",
    "stack_chk_fail",
    "cxa_throw",
    "cxa_terminate",
    "cxa_call_unexpected",
    "cxa_bad_cast",
    "Unwind_Resume",
    "assert_fail",
    "assert_rtn",
    "fortify_fail",
    "ZSt9terminatev",
    "ZN10__cxxabiv111__terminateEPFvvE",
    "pthread_exit",
];

/// `PEFunctionsThatDoNotReturn` — verbatim from
/// `Ghidra/Features/Base/data/PEFunctionsThatDoNotReturn` (leading `_` stripped by the
/// loader of the list, matching Ghidra's load-time strip).
const PE_NORETURN_NAMES: &[&str] = &[
    "abort",
    "CxxThrowException",
    "CxxThrowException@8",
    "CxxFrameHandler3",
    "crtExitProcess",
    "ExitProcess",
    "ExitThread",
    "exit",
    "ExRaiseAccessViolation",
    "ExRaiseDatatypeMisalignment",
    "ExRaiseStatus",
    "FreeLibraryAndExitThread",
    "invalid_parameter_noinfo_noreturn",
    "invoke_watson",
    "KeBugCheck",
    "KeBugCheckEx",
    "longjmp",
    "quick_exit",
    "RpcRaiseException",
    "terminate",
    "raise_securityfailure",       // ___raise_securityfailure → strip leading underscores
    "report_rangecheckfailure",    // ___report_rangecheckfailure
    "?_Xregex_error@std@@YAXW4error_type@regex_constant@1@@Z",
    "?_Xbad_alloc@std@@YAXXZ",
    "?_Xlength_error@std@@YAXPBD@Z",
    "?_Xout_of_range@std@@YAXPBD@Z",
    "?_Xbad_function_call@std@@YAXXZ",
    "?terminate@@YAXXZ",
];

/// Strip the leading `_` characters from a symbol name (Ghidra's `added()` strip).
fn strip_leading_underscores(name: &str) -> &str {
    name.trim_start_matches('_')
}

/// Whether `name` (already a raw symbol name) matches the no-return list for `names` after
/// the leading-underscore strip — Ghidra `functionNames.contains(name)` plus the
/// `wildcardFunctionNames` prefix branch (no list entry uses `*`, so only exact matches
/// arise).
fn matches_noreturn(name: &str, names: &[&str]) -> bool {
    let stripped = strip_leading_underscores(name);
    names.iter().any(|&n| n == stripped)
}

/// Run the known-non-returning-function analysis: flag every symbol whose (underscore-
/// stripped) name is on the format's list. Populates `program.noreturn_functions` with the
/// flagged address and, for an external symbol reached through a PLT thunk, the thunk's
/// entry too (so a `call thunk` stops falling through, as Ghidra's noreturn propagates to
/// the thunk).
///
/// Run *before* disassembly (the loader's symbols are already present). No-op for formats
/// without a Ghidra constraint-file entry (e.g. raw MZ), matching `canAnalyze`.
pub fn analyze(program: &mut Program) {
    // Select the name list by executable format (noReturnFunctionConstraints.xml). mosura's
    // language/loader doesn't carry the Ghidra format string, so infer from the memory map:
    // an ELF has section blocks like `.dynsym`; a PE has the `tdb`/import structure. We key
    // off the EXTERNAL block + whether a `.plt`/`.dynsym` block exists (ELF) vs not (PE).
    let names: &[&str] = if program.memory.block_by_name(".dynsym").is_some()
        || program.memory.block_by_name(".plt").is_some()
    {
        ELF_NORETURN_NAMES
    } else if program.memory.block_by_name("EXTERNAL").is_some() {
        // A PE/COFF import-based program (no ELF dynamic sections) with externals.
        PE_NORETURN_NAMES
    } else {
        return; // no recognizable import structure (e.g. raw MZ) → analyzer does not run
    };

    // Collect the flagged addresses first (immutable borrow), then mark.
    let mut flagged: Vec<Address> = Vec::new();
    for sym in program.symbol_table.symbols() {
        if matches_noreturn(sym.name(), names) {
            flagged.push(sym.address());
        }
    }

    // Propagate to PLT thunks: a thunk is a function whose single flow reference targets a
    // flagged (external) address. mosura models the PLT tail-call as a COMPUTED_CALL(_TERMINATOR)
    // / jump into the EXTERNAL slot, so a thunk entry that references a flagged external is
    // itself non-returning.
    let flagged_set: std::collections::HashSet<(u32, u64)> =
        flagged.iter().map(|a| (a.space.0, a.offset)).collect();
    let mut thunks: Vec<Address> = Vec::new();
    for f in program.function_manager.functions() {
        let entry = f.entry_point();
        // Any reference out of the function body to a flagged external marks the thunk.
        let to_flagged = program
            .reference_manager
            .references()
            .filter(|r| f.body().contains(r.from) || r.from == entry)
            .any(|r| {
                (r.ref_type.is_call() || r.ref_type.is_jump_like() || r.ref_type == RefType::Indirection)
                    && flagged_set.contains(&(r.to.space.0, r.to.offset))
            });
        if to_flagged {
            thunks.push(entry);
        }
    }

    for a in flagged.into_iter().chain(thunks) {
        program.noreturn_functions.insert((a.space.0, a.offset));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_underscores_and_matches() {
        // Ghidra strips leading '_' from the symbol name before matching the (already
        // underscore-free) list.
        assert!(matches_noreturn("exit", ELF_NORETURN_NAMES));
        assert!(matches_noreturn("_exit", ELF_NORETURN_NAMES));
        assert!(matches_noreturn("__stack_chk_fail", ELF_NORETURN_NAMES)); // → stack_chk_fail
        assert!(matches_noreturn("_Unwind_Resume", ELF_NORETURN_NAMES)); // → Unwind_Resume
        assert!(matches_noreturn("__assert_fail", ELF_NORETURN_NAMES)); // → assert_fail
        assert!(!matches_noreturn("printf", ELF_NORETURN_NAMES));
        assert!(!matches_noreturn("__libc_start_main", ELF_NORETURN_NAMES)); // not on the list
        // PE list.
        assert!(matches_noreturn("ExitProcess", PE_NORETURN_NAMES));
        assert!(matches_noreturn("_abort", PE_NORETURN_NAMES));
    }
}
