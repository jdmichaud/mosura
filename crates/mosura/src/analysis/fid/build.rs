//! Building a signature database from real binaries — the driver that turns analyzed programs
//! into [`ingest`](super::ingest) input.
//!
//! Separated from the ingest algorithm so the algorithm stays testable without a loader, and
//! so the same driver serves every compiler × architecture column: nothing here is
//! architecture-specific. Run it from `cargo xtask fid-build`
//! (see `docs/fid-building-databases.md`).

use std::collections::HashMap;
use std::path::Path;

use super::analyzer::hash_function;
use super::ingest::{ChildRef, Ingest, IngestFunction, IngestResult};
use super::store::FidStore;
use crate::analysis::program::Program;

/// Everything needed to describe the library being built.
#[derive(Debug, Clone)]
pub struct BuildSpec {
    pub family: String,
    pub version: String,
    pub variant: String,
    /// Symbols whose presence as a callee distinguishes nothing (`memcpy`, `malloc`, …).
    /// One per line in a text file, `#` comments allowed — the shape of Ghidra's own
    /// `common_symbols_win32.txt`.
    pub common_symbols: Vec<String>,
}

/// Parse a common-symbols list, in the format Ghidra's populate dialog accepts.
pub fn parse_common_symbols(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Turn one analyzed program into ingest input: every function, its hash, and its callees.
///
/// A function's name comes from the symbol table. A binary with no symbols yields nothing
/// usable — which is the honest outcome, since a signature database is only as good as the
/// names in it (`docs/fid-port-plan.md` §8 R6).
pub fn program_functions(program: &Program) -> Vec<IngestFunction> {
    // Which entries are functions, so a call can be resolved to one.
    let entries: Vec<crate::decompile::space::Address> =
        program.function_manager.functions().map(|f| f.entry_point()).collect();

    let mut children_of: HashMap<u64, Vec<ChildRef>> = HashMap::new();
    for r in program.reference_manager.references() {
        if !r.ref_type.is_call() {
            continue;
        }
        let Some(from_fn) = program.function_manager.function_containing(r.from) else { continue };
        let from = from_fn.entry_point().offset;
        let symbol = program.symbol_table.primary_at(r.to);

        // Check EXTERNAL first. Analysis creates a function at any call target in an executable
        // block, including the synthetic slots an object file's undefined symbols get — so
        // `function_at` is true there too. Preferring `Local` in that case threw the name away
        // and left a child that could never resolve: for Watcom's CLIB3R that was 542 `Local`
        // children against 23 `Named`, when nearly every one is a cross-module call by name.
        if let Some(sym) = symbol.filter(|s| s.is_external()) {
            children_of.entry(from).or_default().push(ChildRef::Named(sym.name().to_string()));
        } else if program.function_manager.function_at(r.to).is_some() {
            children_of.entry(from).or_default().push(ChildRef::Local(r.to.offset));
        } else if let Some(sym) = symbol {
            children_of.entry(from).or_default().push(ChildRef::Named(sym.name().to_string()));
        }
    }

    entries
        .into_iter()
        .map(|entry| {
            let symbol = program.symbol_table.primary_at(entry);
            let name = symbol
                .map(|s| s.name().to_string())
                .filter(|n| !n.starts_with("FUN_") && !n.is_empty());
            IngestFunction {
                entry: entry.offset,
                name,
                quad: hash_function(program, entry),
                children: children_of.remove(&entry.offset).unwrap_or_default(),
                is_thunk: false,
                is_external: symbol.is_some_and(|s| s.is_external()),
                has_terminator: true,
            }
        })
        .collect()
}

/// Expand each input into the programs it contains: an OMF `.LIB` becomes one program per
/// member module, anything else is a single program.
///
/// This is what lets `--dir` point straight at a runtime library rather than at a directory of
/// pre-extracted objects — Watcom and Borland ship OMF archives, and extracting them otherwise
/// needs the vendor's own `wlib` under an emulator.
fn expand_input(file: &Path) -> Vec<crate::analysis::program::Program> {
    let Ok(data) = std::fs::read(file) else { return Vec::new() };

    if data.first() == Some(&0xf0) {
        let members = crate::analysis::loader::omf::split_library(&data);
        if !members.is_empty() {
            let mut out = Vec::new();
            for member in members {
                if let Ok(mut program) = crate::analysis::loader::omf::load_omf_object(member) {
                    crate::analysis::analyze(&mut program);
                    out.push(program);
                }
            }
            return out;
        }
    }

    match crate::analysis::analyze_file(file) {
        Ok(p) => vec![p],
        Err(e) => {
            eprintln!("  skip {}: {e:?}", file.display());
            Vec::new()
        }
    }
}

/// Build a database from a list of binaries (object files, OMF libraries, or whole programs).
/// Every input must share one language and compiler spec — that is what a library record pins,
/// and what keeps a match from crossing architectures.
pub fn build_from_files(
    files: &[std::path::PathBuf],
    spec: &BuildSpec,
) -> Result<(FidStore, IngestResult), String> {
    let mut ingest: Option<Ingest> = None;
    let mut language = String::new();

    for program in files.iter().flat_map(|f| expand_input(f)) {
        if ingest.is_none() {
            language = program.language_id.clone();
            let mut new = Ingest::new(
                &program.language_id,
                &program.compiler_spec_id,
                &spec.family,
                &spec.version,
                &spec.variant,
            );
            new.mark_common_symbols(spec.common_symbols.iter().cloned());
            ingest = Some(new);
        } else if program.language_id != language {
            eprintln!(
                "  skip a module: language {} != {language} (one library, one language)",
                program.language_id
            );
            continue;
        }

        let functions = program_functions(&program);
        ingest.as_mut().unwrap().add_program(&functions);
    }

    match ingest {
        Some(i) => Ok(i.finish()),
        None => Err("no input program could be analyzed".to_string()),
    }
}

/// Build and write, printing a short report. The path is the caller's choice; by convention
/// databases live in `oracle/fid/db/<family>-<version>-<arch>.mfid`.
pub fn build_to_file(
    files: &[std::path::PathBuf],
    spec: &BuildSpec,
    out: &Path,
) -> Result<IngestResult, String> {
    let (store, result) = build_from_files(files, spec)?;
    super::store::write_file(out, &store).map_err(|e| e.to_string())?;
    Ok(result)
}
