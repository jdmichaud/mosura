//! mosura — the safe Rust binding over the C ABI of `mosura-capi` (`docs/product/architecture.md`
//! §3, §6.6). Mechanical: every type wraps a handle released on `Drop`, every `mosura_status`
//! becomes a `Result` carrying the per-thread message, every view becomes a slice or a copy. It
//! calls the capi functions as ordinary Rust functions (the crate is a dependency), so a Rust user
//! links no shared library; the `.so` path is what the C smoke test exercises. This is the crate a
//! Rust user of the product depends on, and the CLI's only route to the library.

mod handle;

pub mod ctx;
pub mod error;
pub mod function;
pub mod language;
pub mod options;
pub mod program;
pub mod session;
pub mod table;

pub use ctx::{Ctx, CtxConfig, Level};
pub use error::{Error, Result, Status};
pub use function::Function;
pub use language::Language;
pub use options::Options;
pub use program::Program;
pub use session::Session;
pub use table::{ColType, Format, Table};

/// The runtime ABI version, `(major << 16) | minor`.
pub fn abi_version() -> u32 {
    mosura_capi::mosura_abi_version()
}

/// The library version string (crate version + the content-derived build id).
pub fn version() -> &'static str {
    unsafe { std::ffi::CStr::from_ptr(mosura_capi::mosura_version()) }.to_str().unwrap_or("?")
}
