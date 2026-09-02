//! Driving the target compiler — the half of byte-exactness that is not decompilation.
//!
//! Byte-exact output cannot be reasoned into existence: the only authority on what a 1994
//! compiler emits for a given source is that compiler. So it belongs *inside* the loop, and the
//! loop's speed is what decides whether a search over source forms is a real technique or a
//! thought experiment. One translation unit through dosemu2 costs about a second; a search that
//! tries thirty candidates for each of three thousand functions cannot pay that per candidate.
//!
//! Hence a driver rather than a `system()` call:
//!
//! - **batching** — many units per compiler session, so the session cost is amortized;
//! - **isolation on failure** — one unit that makes the compiler abort takes the rest of its
//!   session with it, and a silently truncated batch is far worse than a slow one, because the
//!   missing objects read as failures of the code rather than of the run;
//! - **caching** — content-addressed on (toolchain identity, flags, source), so re-proposing a
//!   candidate that was already compiled is free. A search revisits constantly.
//!
//! The [`Toolchain`] trait is the seam where a compiler's specifics stop. Everything above it
//! deals in "source in, object out"; everything a particular compiler needs — DOS emulation,
//! 8.3 filenames, its own diagnostic format — stays below.

pub mod cache;
pub mod driver;
pub mod spec;
pub mod watcom;

pub use cache::Cached;
pub use driver::{CompilerDriver, DriverRole};
pub use spec::{CompilerSpec, Invocation, ObjectFormat};
pub use watcom::WatcomDos;

/// One translation unit to compile.
#[derive(Debug, Clone)]
pub struct CompileUnit {
    /// Caller's identifier, returned on the output so batches can be matched up. Must be usable
    /// as a filename stem on the target platform (DOS: 8 characters, no extension).
    pub key: String,
    pub source: String,
    pub flags: Vec<String>,
}

/// The result of compiling one unit.
#[derive(Debug, Clone)]
pub struct CompileOutput {
    pub key: String,
    /// The object file's bytes, or `None` when the compiler produced none.
    pub object: Option<Vec<u8>>,
    /// Diagnostics for this unit, as the compiler printed them.
    pub log: String,
    /// Did the compiler actually reach a verdict on THIS unit — produce its object, or reject it
    /// and say so? False when nothing adjudicated it: the toolchain was unreachable, the session
    /// aborted, the driver never ran.
    ///
    /// This exists to keep such a non-answer OUT of the cache. A failure that never reached the
    /// compiler is not a property of the source, so caching it under the source's key makes an
    /// environment fault permanent — the run that fixes the environment hits the stored verdict
    /// and never recompiles. Measured: a detached run under `env -i` with no `dosemu` on PATH
    /// stored 32 COMPILE_FAILs, and the corrected run reported "32 cached, 0 fresh" in 0.0s and
    /// re-served every one of them. `Toolchain::id` cannot cover this the way it covers the
    /// prelude (see `the_prelude_is_part_of_the_toolchain_identity`): the identity describes the
    /// compiler we MEANT to run, and this is the case where no compiler ran at all.
    pub adjudicated: bool,
}

impl CompileOutput {
    pub fn ok(&self) -> bool {
        self.object.is_some()
    }
}

/// A compiler mosura can drive.
pub trait Toolchain {
    /// Stable identity of this toolchain — vendor, version, and anything else that changes the
    /// bytes it emits. It is part of the cache key, so an inaccurate one silently serves another
    /// compiler's objects.
    fn id(&self) -> String;

    /// Compile a batch. The result has one entry per input, in the same order.
    fn compile_batch(&self, units: &[CompileUnit]) -> Vec<CompileOutput>;

    /// Compile one unit.
    fn compile(&self, unit: &CompileUnit) -> CompileOutput {
        self.compile_batch(std::slice::from_ref(unit)).pop().expect("one output per input")
    }
}
