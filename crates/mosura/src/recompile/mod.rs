//! Recompilation — turning "the C we emit" into "the bytes the original build produced".
//!
//! The decompiler answers *what a function computes*. Byte-exactness asks a strictly harder
//! question: *which of the many semantically-equivalent C sources does this toolchain map to
//! exactly these bytes*. That is an inverse-compilation problem, and it cannot be settled by
//! looking at C alone — it needs the target compiler in the loop and a comparison that can say
//! **why** two byte strings differ.
//!
//! This module is that machinery, and it is deliberately independent of any one binary:
//!
//! - [`candidate`] — take a compiled object and **symbolically relink it to the original's
//!   addresses**. A one-function translation unit necessarily emits relocations where the
//!   original has resolved addresses; resolving them (rather than masking the bytes) makes the
//!   two sides directly comparable and keeps a wrong target a *failure* instead of a hidden
//!   mask.
//! - [`insn`] — normalize both sides into instructions carrying a canonical p-code semantic
//!   form. Comparing lifted semantics rather than text is what makes the instrument
//!   architecture-agnostic: it works wherever SLEIGH does.
//! - [`toolchain`] — drive the target compiler itself, batched and cached, because the only
//!   authority on what a 1994 compiler emits is that compiler, and a search puts it in the loop.
//! - [`vocab`] — what the toolchain is *able* to emit, learned from its own output, so a
//!   function it could never have produced is excluded on evidence rather than by opinion.
//! - [`align`] — align the two instruction streams and attribute every divergence to a named
//!   class (encoding, register allocation, immediate, selection, extra/missing computation…).
//!
//! The point of the taxonomy is triage: a byte-percentage cannot distinguish "the decompiler
//! lost a computation" (our defect, and a wrong-code bug) from "the compiler chose ESI where
//! the original chose EDI" (a codegen-form difference reachable by changing the C we emit) from
//! "this was written in assembler" (not reachable from C at all). Those three need completely
//! different responses, and until they are separated the population cannot be worked.
pub mod align;
pub mod groundtruth;
pub mod buildconfig;
pub mod candidate;
pub mod convention;
pub mod gates;
pub mod insn;
pub mod report;
pub mod toolchain;
pub mod verify;
pub mod vocab;
pub mod watsched;

pub use buildconfig::{BuildConfig, Evidence, Profile};
pub use align::{AlignOp, Divergence, DivergenceClass, FnDiff, Verdict, compare};
pub use candidate::{CandTable, Candidate, CandFixup, SymbolResolver, load_object_function};
pub use convention::callee_stack_cleanup;
pub use insn::{NormInsn, normalize};
pub use report::{DIVERGENCE_HEADER, FnKey, write_divergence_rows};
pub use toolchain::{CompileOutput, CompileUnit, Toolchain};
pub use verify::{ByteVerdict, Checked, Subject, emitted_symbol_address, trim_padding, verify, verify_with_image};
pub use vocab::Vocabulary;
