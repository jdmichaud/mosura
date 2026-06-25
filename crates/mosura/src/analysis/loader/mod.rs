//! Binary loaders (A2) — file bytes → a [`Program`](crate::analysis::program::Program)
//! memory map, porting the *output* of Ghidra's loaders (`app/util/opinion/`). ELF and
//! PE (x86-64) today; MZ (16-bit DOS) next. Containers are decoded with the `object`
//! crate — only the block-layout logic is ported.

pub mod elf;
pub mod le;
pub mod mz;
pub mod pe;

pub use elf::{load_elf, LoadError};
pub use le::{detect_le, load_le};
pub use mz::load_mz;
pub use pe::load_pe;

use crate::analysis::program::Program;

/// Detect the container format by magic and dispatch to the matching loader, mirroring
/// Ghidra's loader-opinion selection for the formats we support.
pub fn load(data: &[u8]) -> Result<Program, LoadError> {
    if data.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return load_elf(data);
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
                return load_le(data);
            }
        }
        // A bare DOS MZ, or a bound DOS-extender stub whose `e_lfanew` is invalid/non-PE
        // (e.g. DOS/4GW WAR2.EXE) — Ghidra loads the 16-bit MZ stub in both cases.
        return load_mz(data);
    }
    Err(LoadError::Unsupported("unrecognized container (not ELF/PE)".into()))
}
