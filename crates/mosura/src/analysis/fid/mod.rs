//! FID (Function ID) — identifying statically-linked runtime/standard-library functions
//! by fingerprinting a function body and matching it against a signature database.
//!
//! A faithful port of Ghidra's `Ghidra/Features/FunctionID/` subsystem. The hashes this
//! module produces are **byte-identical to Ghidra's**, which is what lets mosura match
//! against Ghidra's own shipped databases (`third_party/ghidra-data/FunctionID/`).
//!
//! Distinct from [`crate::analysis::codegen_fingerprint`], which identifies the *compiler
//! of the whole binary*; FID identifies an *individual function*.
//!
//! Staged per `docs/fid-port-plan.md`:
//! - Stage 0 ✅ `sleigh::disassemble_fingerprint` — the disassembly-level ingredients.
//! - Stage 1 → [`hash`] — the `FidHashQuad` hasher.

pub mod analyzer;
pub mod bufferfile;
pub mod build;
pub mod db;
pub mod hash;
pub mod ingest;
pub mod matcher;
pub mod packed;
pub mod query;
pub mod store;
