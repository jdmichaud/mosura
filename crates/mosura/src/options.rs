//! A validated key/value option set.

use std::ffi::CString;

use crate::ctx::Ctx;
use crate::error::{check, Result};
use crate::handle::{empty_bytes, slice_of, take_string, Raw};
use mosura_capi::{mosura_options, mosura_view};

pub struct Options {
    raw: Raw<mosura_options>,
}

impl Options {
    pub(crate) fn new(ctx: &Ctx) -> Result<Options> {
        let mut out: *mut mosura_options = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_options_new(ctx.ptr(), &mut out) })?;
        Ok(Options { raw: Raw::new(out) })
    }

    pub(crate) fn ptr(&self) -> *mut mosura_options {
        self.raw.ptr()
    }

    /// Set a key; an unknown key or an ill-typed value is an error carrying the registry's doc.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let (k, v) = (CString::new(key).unwrap_or_default(), CString::new(value).unwrap_or_default());
        check(unsafe { mosura_capi::mosura_options_set(self.ptr(), k.as_ptr(), v.as_ptr()) })
    }

    /// `set`, chaining.
    pub fn with(mut self, key: &str, value: &str) -> Result<Options> {
        self.set(key, value)?;
        Ok(self)
    }

    pub fn unset(&mut self, key: &str) -> Result<()> {
        let k = CString::new(key).unwrap_or_default();
        check(unsafe { mosura_capi::mosura_options_unset(self.ptr(), k.as_ptr()) })
    }

    /// The effective value (explicit or default).
    pub fn get(&self, key: &str) -> Result<String> {
        let k = CString::new(key).unwrap_or_default();
        let mut v = mosura_view { ptr: std::ptr::null(), len: 0 };
        check(unsafe { mosura_capi::mosura_options_get(self.ptr(), k.as_ptr(), &mut v) })?;
        Ok(String::from_utf8_lossy(unsafe { slice_of(v) }).into_owned())
    }

    /// The canonical string of the result-affecting subset (the cache-key digest).
    pub fn tag(&self) -> Result<String> {
        let mut b = empty_bytes();
        check(unsafe { mosura_capi::mosura_options_tag(self.ptr(), &mut b) })?;
        Ok(take_string(b))
    }

    /// Parse `key=value;key=value`.
    pub fn assign(&mut self, spec: &str) -> Result<()> {
        let s = CString::new(spec).unwrap_or_default();
        check(unsafe { mosura_capi::mosura_options_assign(self.ptr(), s.as_ptr()) })
    }

    pub fn try_clone(&self) -> Result<Options> {
        let mut out: *mut mosura_options = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_options_clone(self.ptr(), &mut out) })?;
        Ok(Options { raw: Raw::new(out) })
    }
}

impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Options({})", self.tag().unwrap_or_default())
    }
}
