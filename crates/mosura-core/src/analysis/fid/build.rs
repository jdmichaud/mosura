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
    /// The language every ingested module must be, e.g. `x86:LE:32:default`. `None` keeps the
    /// historical behaviour of taking it from whichever module happens to come first.
    ///
    /// ⚠️ Why this exists. "One library, one language" is right — a library record pins one
    /// language, and that is what stops a match crossing architectures. Inferring it *implicitly*
    /// is what is wrong: a real vendor runtime mixes widths. MetaWare High C's `HC386.LIB` holds
    /// 16-bit real-mode helpers alongside the 32-bit runtime, so the first module decided
    /// `x86:LE:16:Real Mode` and all 252 32-bit modules were skipped — the build reported
    /// `ingested 0` and the documented health check ("symbols did not survive extraction")
    /// pointed at the wrong cause entirely. Say which language you want.
    pub language: Option<String>,
    /// The compiler spec to record on the library, overriding whatever the loader guessed.
    /// An OMF module does not say which vendor produced it — `loader::omf` defaults 32-bit
    /// modules to `watcom` because that is the spec mosura ships for x86-32 OMF — but the
    /// operator naming the library DOES know. Without this, a MetaWare High C database is
    /// labelled `compilerspec watcom`, which is both wrong and makes it unusable for a program
    /// analysed with any other spec (FID selects databases by language AND spec).
    pub compiler_spec: Option<String>,
    /// Names by address, from a linker map.
    ///
    /// A **linked** image is the better ingest input than a pile of object files: the vendor's
    /// own linker has resolved every call, so auto-analysis sees the true call graph instead of
    /// `call 0000:0000` placeholders whose targets live only in relocation records. But a DOS
    /// `.EXE` carries no symbol table, so the names have to come from the map the linker emits
    /// alongside it (`tcc -M`, `tlink /m`). Addresses are relative to the load image; the
    /// program's image base is added.
    pub symbol_map: HashMap<u64, String>,
}

/// Where the loader placed the start of the load image, which is what a linker map's
/// addresses are relative to.
///
/// For a DOS MZ that is segment `0x1000` — Ghidra's convention, mirrored by `loader/mz.rs` —
/// while `image_base` is left at 0. For every other container the two coincide.
fn load_image_base(program: &Program) -> u64 {
    if program.language_id.starts_with("x86:LE:16") {
        0x1_0000
    } else {
        program.image_base.offset
    }
}

/// Parse a Borland/Microsoft linker map's "Publics by Value" section.
///
/// ```text
///   Address         Publics by Value
///
///  0000:010D       __exit
///  0000:01AF       _abort
/// ```
///
/// The address is `segment:offset` in real-mode form, so the offset within the load image is
/// `segment * 16 + offset`. `Abs` entries are absolute constants, not code, and are skipped.
pub fn parse_linker_map(text: &str) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    let mut in_publics = false;
    for line in text.lines() {
        if line.contains("Publics by Value") {
            in_publics = true;
            continue;
        }
        if !in_publics {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 2 {
            continue;
        }
        let Some((seg, off)) = f[0].split_once(':') else { continue };
        let (Ok(seg), Ok(off)) = (u64::from_str_radix(seg, 16), u64::from_str_radix(off, 16))
        else {
            continue;
        };
        // `Abs` marks an absolute symbol with no location in the image.
        let name = if f[1] == "Abs" { f.get(2) } else { f.get(1) };
        let Some(name) = name else { continue };
        out.entry(seg * 16 + off).or_insert_with(|| (*name).to_string());
    }
    out
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
    program_functions_with_map(program, &HashMap::new())
}

/// As [`program_functions`], naming functions from a linker map when one is supplied.
pub fn program_functions_with_map(
    program: &Program,
    symbol_map: &HashMap<u64, String>,
) -> Vec<IngestFunction> {
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
            // A linker map wins: it is the only source of names for a linked DOS image, which
            // carries no symbol table of its own. Map addresses are relative to the load image,
            // which the MZ loader places at segment 0x1000 (`loader/mz.rs` INITIAL_SEGMENT) —
            // note that is NOT `image_base`, which stays 0 to match Ghidra's reporting.
            let name = symbol_map
                .get(&entry.offset.wrapping_sub(load_image_base(program)))
                .cloned()
                .or_else(|| {
                    symbol
                        .map(|s| s.name().to_string())
                        .filter(|n| !n.starts_with("FUN_") && !n.is_empty())
                });
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

    // SDCC ships its runtime as an `ar` archive of ASCII `.rel` objects.
    if data.starts_with(b"!<arch>\n") {
        let members = crate::analysis::loader::rel::split_archive(&data);
        let mut out = Vec::new();
        for member in members {
            let Ok(text) = std::str::from_utf8(member) else { continue };
            if !crate::analysis::loader::rel::is_rel(member) {
                continue;
            }
            if let Ok(mut program) = crate::analysis::loader::rel::load_rel_object(text) {
                crate::analysis::analyze(&mut program);
                out.push(program);
            }
        }
        if !out.is_empty() {
            return out;
        }
    }

    match crate::analysis::analyze_file(file) {
        Ok(p) => vec![p],
        Err(e) => {
            warn!("fid build: skip {}: {e:?}", file.display());
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
    let mut language = spec.language.clone().unwrap_or_default();
    let mut skipped: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();

    for program in files.iter().flat_map(|f| expand_input(f)) {
        // An explicitly pinned language filters before the first module is allowed to set it.
        if let Some(want) = &spec.language {
            if &program.language_id != want {
                *skipped.entry(program.language_id.clone()).or_default() += 1;
                continue;
            }
        }
        if ingest.is_none() {
            language = program.language_id.clone();
            let mut new = Ingest::new(
                &program.language_id,
                spec.compiler_spec.as_deref().unwrap_or(&program.compiler_spec_id),
                &spec.family,
                &spec.version,
                &spec.variant,
            );
            new.mark_common_symbols(spec.common_symbols.iter().cloned());
            ingest = Some(new);
        } else if program.language_id != language {
            *skipped.entry(program.language_id.clone()).or_default() += 1;
            continue;
        }

        let functions = program_functions_with_map(&program, &spec.symbol_map);
        ingest.as_mut().unwrap().add_program(&functions);
    }

    // One summarised line per skipped language, not one per module: a mixed-width runtime skips
    // hundreds, and 252 identical lines buried the fact that nothing was ingested.
    for (lang, n) in &skipped {
        warn!("fid build: skipped {n} module(s): language {lang} != {language}");
    }

    match ingest {
        Some(i) => Ok(i.finish()),
        None => Err(format!(
            "no input program could be analyzed{}",
            match &spec.language {
                Some(l) if !skipped.is_empty() =>
                    format!(" — every module was skipped; is --language {l} right?"),
                _ => String::new(),
            }
        )),
    }
}

/// Build and write, printing a short report. The path is the caller's choice; by convention
/// databases live in `data/fid/<family>-<version>-<arch>.mfid`.
pub fn build_to_file(
    files: &[std::path::PathBuf],
    spec: &BuildSpec,
    out: &Path,
) -> Result<IngestResult, String> {
    let (store, result) = build_from_files(files, spec)?;
    super::store::write_file(out, &store).map_err(|e| e.to_string())?;
    Ok(result)
}
