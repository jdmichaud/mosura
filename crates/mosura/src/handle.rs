//! An owned C handle: released exactly once on drop. Not `Send`/`Sync` (the C contract: one
//! caller at a time per handle), except where a type says otherwise.

use std::ffi::c_void;
use std::ptr::NonNull;

pub(crate) struct Raw<T>(NonNull<T>);

impl<T> Raw<T> {
    /// Wrap a pointer a capi constructor just filled (never NULL after MOSURA_OK).
    pub(crate) fn new(p: *mut T) -> Raw<T> {
        Raw(NonNull::new(p).expect("a successful mosura constructor never leaves NULL"))
    }
    pub(crate) fn ptr(&self) -> *mut T {
        self.0.as_ptr()
    }
}

impl<T> Drop for Raw<T> {
    fn drop(&mut self) {
        unsafe { mosura_capi::mosura_release(self.0.as_ptr() as *mut c_void) }
    }
}

/// Owned bytes handed out by the library, copied into a `Vec` and disposed.
pub(crate) fn take_bytes(mut b: mosura_capi::mosura_bytes) -> Vec<u8> {
    let v = if b.ptr.is_null() { Vec::new() } else { unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec() };
    unsafe { mosura_capi::mosura_bytes_dispose(&mut b) };
    v
}

pub(crate) fn take_string(b: mosura_capi::mosura_bytes) -> String {
    String::from_utf8_lossy(&take_bytes(b)).into_owned()
}

pub(crate) fn empty_bytes() -> mosura_capi::mosura_bytes {
    mosura_capi::mosura_bytes { ptr: std::ptr::null_mut(), len: 0, cap: 0 }
}

pub(crate) fn view_of(s: &[u8]) -> mosura_capi::mosura_view {
    mosura_capi::mosura_view { ptr: s.as_ptr(), len: s.len() }
}

pub(crate) unsafe fn slice_of<'a>(v: mosura_capi::mosura_view) -> &'a [u8] {
    if v.ptr.is_null() { &[] } else { std::slice::from_raw_parts(v.ptr, v.len) }
}
