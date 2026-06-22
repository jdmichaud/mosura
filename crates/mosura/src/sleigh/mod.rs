//! The SLEIGH engine — mosura's first port target.
//!
//! Two sub-stages (design §2):
//! - **1a** the SLEIGH compiler: `.slaspec`/`.sinc` → internal tables;
//! - **1b** the runtime: tables + bytes → instructions + raw p-code.
//!
//! Everything here is currently a stub returning [`Unimplemented`]. The
//! conformance harness calls these entry points to hold a clean red baseline; as
//! the port lands, the stubs are replaced and the baseline ratchets toward the
//! reference oracle's 599/599.

pub mod emu;
pub mod engine;
pub mod pcode;
pub mod sla;

use pcode::PcodeOp;

use crate::Unimplemented;

/// One disassembled instruction with its lifted raw p-code (stage 1b output).
///
/// `pcode` lines are the normalized textual form used by the disasm/p-code
/// goldens (see `docs/testing-baseline.md` §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub body: String,
    /// Rendered p-code text (golden format) — a view of [`Self::ops`].
    pub pcode: Vec<String>,
    /// Structured p-code (the IR consumed by the interpreter + decompiler).
    pub ops: Vec<PcodeOp>,
}

/// Disassemble and lift a byte range for `lang_id` (stage 1b), using the SLEIGH
/// engine driven by Ghidra's compiled tables for that language. Returns
/// [`Unimplemented`] only when the language's tables aren't available (e.g. the
/// Ghidra tree isn't set up).
pub fn disassemble(lang_id: &str, bytes: &[u8], base: u64) -> Result<Vec<Instruction>, Unimplemented> {
    match crate::lang::load(lang_id) {
        Some((spec, ctx)) => Ok(spec.disassemble_ctx(bytes, base, &ctx)),
        None => Err(Unimplemented("sleigh::disassemble: language tables unavailable")),
    }
}

/// Decompile to C (covers the datatest baseline). Not yet ported — depends on the
/// SLEIGH engine plus the decompiler stage.
pub fn decompile(_lang_id: &str, _bytes: &[u8], _base: u64) -> Result<String, Unimplemented> {
    Err(Unimplemented("decompiler"))
}
