//! §4 Options — the ONLY way a knob reaches the library.

use std::ffi::{c_char, c_void};

use crate::boundary::guard;
use crate::ctx::{ctx_of, mosura_ctx};
use crate::handle::{self, Kind};
use crate::mem::{bytes, cstr, out_ptr, view, mosura_bytes, mosura_view};
use crate::status::mosura_status;
use crate::table::{mosura_table, new_table};
use mosura_api::{Options, Result};

/// A validated key/value option set (opaque).
#[repr(C)]
pub struct mosura_options {
    _private: [u8; 0],
}

pub(crate) unsafe fn options_of<'a>(p: *const mosura_options) -> Result<&'a Options> {
    handle::as_ref::<Options>(p as *const c_void, Kind::Options)
}

/// An optional options handle (NULL = empty options).
pub(crate) unsafe fn options_or_default(p: *const mosura_options) -> Result<Options> {
    if p.is_null() { Ok(Options::new()) } else { options_of(p).cloned() }
}

/// An empty option set.
#[no_mangle]
pub unsafe extern "C" fn mosura_options_new(ctx: *mut mosura_ctx, out: *mut *mut mosura_options) -> mosura_status {
    guard(|| {
        let _ = ctx_of(ctx)?;
        let out = out_ptr(out, "out")?;
        *out = handle::new(Kind::Options, Options::new()) as *mut mosura_options;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn mosura_options_clone(src: *const mosura_options, out: *mut *mut mosura_options) -> mosura_status {
    guard(|| {
        let o = options_of(src)?.clone();
        let out = out_ptr(out, "out")?;
        *out = handle::new(Kind::Options, o) as *mut mosura_options;
        Ok(())
    })
}

/// Set a key. Unknown keys and ill-typed values are MOSURA_ERR_INVALID_ARG with the registry's
/// doc line in the error message. Keys are dotted lower-case ("load.loader", "emit.return-width").
#[no_mangle]
pub unsafe extern "C" fn mosura_options_set(o: *mut mosura_options, key: *const c_char, value: *const c_char) -> mosura_status {
    guard(|| {
        let key = cstr(key, "key")?;
        let value = cstr(value, "value")?;
        let mut o = handle::as_mut::<Options>(o as *mut c_void, Kind::Options)?;
        o.set(key, value)
    })
}

#[no_mangle]
pub unsafe extern "C" fn mosura_options_unset(o: *mut mosura_options, key: *const c_char) -> mosura_status {
    guard(|| {
        let key = cstr(key, "key")?;
        let mut o = handle::as_mut::<Options>(o as *mut c_void, Kind::Options)?;
        o.unset(key)
    })
}

/// The effective value (explicit or default). The view is valid until the next mutation of `o`.
#[no_mangle]
pub unsafe extern "C" fn mosura_options_get(o: *const mosura_options, key: *const c_char, out: *mut mosura_view) -> mosura_status {
    guard(|| {
        let key = cstr(key, "key")?;
        let out = out_ptr(out, "out")?;
        let v = options_of(o)?.get(key)?;
        *out = view(v.as_bytes());
        Ok(())
    })
}

/// Canonical string of the RESULT-affecting subset — the option digest used in cache keys.
#[no_mangle]
pub unsafe extern "C" fn mosura_options_tag(o: *const mosura_options, out: *mut mosura_bytes) -> mosura_status {
    guard(|| {
        let out = out_ptr(out, "out")?;
        *out = bytes(options_of(o)?.tag().into_bytes());
        Ok(())
    })
}

/// Parse "key=value;key=value" (a bare key sets a Bool to true).
#[no_mangle]
pub unsafe extern "C" fn mosura_options_assign(o: *mut mosura_options, spec: *const c_char) -> mosura_status {
    guard(|| {
        let spec = cstr(spec, "spec")?;
        let mut o = handle::as_mut::<Options>(o as *mut c_void, Kind::Options)?;
        o.assign(spec)
    })
}

/// The registry: one row per key — key, type, default, doc, since, affects.
#[no_mangle]
pub unsafe extern "C" fn mosura_options_registry(ctx: *mut mosura_ctx, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let _ = ctx_of(ctx)?;
        let out = out_ptr(out, "out")?;
        *out = new_table(mosura_api::options::registry::registry_table());
        Ok(())
    })
}
