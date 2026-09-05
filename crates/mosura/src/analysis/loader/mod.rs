//! Binary loaders (A2) — file bytes → a [`Program`](crate::analysis::program::Program)
//! memory map, porting the *output* of Ghidra's loaders (`app/util/opinion/`). ELF and
//! PE (x86-64) today; MZ (16-bit DOS) next. Containers are decoded with the `object`
//! crate — only the block-layout logic is ported.

pub mod com;
pub mod compiler_version;
pub mod elf;
pub mod le;
pub mod metaware;
pub mod mz;
pub mod omf;
pub mod pe;
pub mod read;
pub mod rel;
pub mod pe_opinion;
pub mod watcom;
pub mod x32;

pub use com::load_com;
pub use elf::{load_elf, load_elf_with, LoadError};
pub use le::{detect_le, load_le, load_le_with};
pub use x32::{detect_x32, is_x32_image, load_x32, load_x32_with};
pub use mz::load_mz;
pub use pe::load_pe;

use std::path::Path;

use crate::analysis::program::Program;
use crate::switches::Knobs;

/// Dispatch to a loader using the file path as well as its bytes. A raw CP/M `.COM` has no
/// container magic (it is a flat Z80 image), so — like Ghidra, which needs the format chosen
/// manually for a raw binary — it is selected by its `.com` extension; every other format is
/// detected by magic via [`load`].
pub fn load_path(path: &Path, data: &[u8]) -> Result<Program, LoadError> {
    load_path_with(path, data, &Knobs::default())
}

/// [`load_path`] under explicit [`Knobs`]: the declared x86-32 compiler spec reaches the loader's
/// cspec decision, and the loaded program carries the knobs for the analysis and every decompile.
pub fn load_path_with(path: &Path, data: &[u8], knobs: &Knobs) -> Result<Program, LoadError> {
    if path.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("com")) {
        let mut program = with_compiler_version(data, com::load_com(data)?);
        program.knobs = knobs.clone();
        return Ok(program);
    }
    load_with(data, knobs)
}

/// Load `data` by container, then refine it with the beyond-Ghidra compiler-**version** marker.
pub fn load(data: &[u8]) -> Result<Program, LoadError> {
    load_with(data, &Knobs::default())
}

/// [`load`] under explicit [`Knobs`] (see [`load_path_with`]).
pub fn load_with(data: &[u8], knobs: &Knobs) -> Result<Program, LoadError> {
    let mut program = with_compiler_version(data, load_container(data, knobs)?);
    program.knobs = knobs.clone();
    Ok(program)
}

/// Record the embedded compiler-version marker (`compiler_version::detect` — container-agnostic,
/// it scans the raw image) on the program. This *refines* the loader's family opinion and never
/// overrides it: Ghidra's faithful CompilerOpinion label (`program.compiler`) is left untouched.
/// `pub(crate)` so out-of-dispatch entry points (the native-LE `analyze_le_file`) apply the same
/// refinement.
pub(crate) fn with_compiler_version(data: &[u8], mut program: Program) -> Program {
    program.compiler_version = compiler_version::detect(data).map(|id| id.label());
    program
}

/// Detect the container format by magic and dispatch to the matching loader, mirroring
/// Ghidra's loader-opinion selection for the formats we support.
fn load_container(data: &[u8], knobs: &Knobs) -> Result<Program, LoadError> {
    // OMF object modules (`THEADR`/`LHEADR`). Ghidra has an `OmfLoader`; ours covers the
    // slice FID's library ingest needs — see `loader::omf`. Checked before ELF/PE/MZ because
    // an object file carries none of their magics.
    if matches!(data.first(), Some(0x80 | 0x82)) {
        return omf::load_omf_object(data);
    }
    if data.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return load_elf_with(data, knobs);
    }
    if data.starts_with(b"MZ") {
        // MZ stub: a PE if it carries a "PE\0\0" signature at e_lfanew, else a DOS MZ.
        if let Some(off) = data.get(0x3c..0x40).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize) {
            if data.get(off..off + 4) == Some(b"PE\0\0") {
                return load_pe(data);
            }
            // A *standalone* Linear Executable: e_lfanew points at a valid "LE" header
            // (Ghidra has no LE loader; mosura loads its 32-bit objects natively — see
            // `le.rs`). A DOS-extender-*bound* exe (DOS/4GW WAR2.EXE) sets e_lfanew invalid,
            // so it does NOT match here and falls through to the 16-bit MZ stub — preserving
            // the war2 Ghidra-parity gates, which compare against Ghidra's MZ interpretation.
            if le::is_le_header(data, off) {
                return load_le_with(data, knobs);
            }
        }
        // A bare DOS MZ, or a bound DOS-extender stub whose `e_lfanew` is invalid/non-PE
        // (e.g. DOS/4GW WAR2.EXE) — Ghidra loads the 16-bit MZ stub in both cases.
        return load_mz(data);
    }
    Err(LoadError::Unsupported("unrecognized container (not ELF/PE)".into()))
}
