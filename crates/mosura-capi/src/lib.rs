//! mosura-capi — the product's ONE public surface (`docs/product/architecture.md` §3, §4.5): every
//! capability of `mosura-api` as `extern "C"` one-liners behind a boundary that turns Rust
//! failures into a status code + a thread-local message and never lets a panic cross. Types are
//! spelled with their C names so cbindgen writes the committed `include/mosura.h` verbatim.
//!
//! Every function: check the handle (NULL, foreign, released, wrong kind, poisoned → INVALID_ARG /
//! INTERNAL), check the pointers, call api, put the result behind the out pointer. No logic here.

#![allow(non_camel_case_types, clippy::missing_safety_doc)]

pub mod boundary;
pub mod ctx;
pub mod handle;
pub mod mem;
pub mod ops;
pub mod options;
pub mod session;
pub mod status;
pub mod table;

use std::ffi::{c_char, CString};
use std::sync::OnceLock;

// every C-named type and every `extern "C"` function at the crate root: `use mosura_capi::*` is the
// whole ABI (the binding and the tests read it that way; cbindgen reads the modules)
pub use ctx::*;
pub use mem::*;
pub use ops::*;
pub use options::*;
pub use session::*;
pub use status::*;
pub use table::*;

/// The API version this library implements; a client checks the major first.
pub const MOSURA_API_VERSION_MAJOR: u32 = 0;
pub const MOSURA_API_VERSION_MINOR: u32 = 1;

/// Runtime ABI version, `(major << 16) | minor`.
#[no_mangle]
pub extern "C" fn mosura_abi_version() -> u32 {
    (MOSURA_API_VERSION_MAJOR << 16) | MOSURA_API_VERSION_MINOR
}

/// The human version string: the crate version plus the content-derived build id that also keys
/// the session store (e.g. `0.1.0 (0.0.0+3f2a9c1b7d4e)`). Static; never freed.
#[no_mangle]
pub extern "C" fn mosura_version() -> *const c_char {
    static VERSION: OnceLock<CString> = OnceLock::new();
    VERSION.get_or_init(|| CString::new(format!("{} ({})", env!("CARGO_PKG_VERSION"), mosura_api::fingerprint::build_id())).expect("no NUL")).as_ptr()
}

/// Release any handle. NULL is a no-op; a pointer that is not a live handle is refused (and
/// reported through `mosura_last_error`) rather than freed. A handle should outlive the handles
/// derived from it; the derived handles hold their own references, so releasing early is safe,
/// only surprising.
#[no_mangle]
pub unsafe extern "C" fn mosura_release(h: *mut std::ffi::c_void) {
    if h.is_null() {
        return;
    }
    if let Err(e) = handle::release(h) {
        status::set(mosura_status::from(&e), &e.to_string());
    }
}
