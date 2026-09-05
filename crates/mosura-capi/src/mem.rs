//! Views (borrowed bytes), owned byte buffers, and the pointer checks every function performs.

use std::ffi::{c_char, CStr};

use mosura_api::{Error, Result};

/// Borrowed, immutable bytes. Lifetime = the handle documented at the producing function.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct mosura_view {
    pub ptr: *const u8,
    pub len: usize,
}

/// Owned bytes. Dispose exactly once with `mosura_bytes_dispose`. Zero-initialized is a valid
/// empty value.
#[repr(C)]
#[derive(Debug)]
pub struct mosura_bytes {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

pub fn view(s: &[u8]) -> mosura_view {
    mosura_view { ptr: s.as_ptr(), len: s.len() }
}

pub fn bytes(v: Vec<u8>) -> mosura_bytes {
    let mut v = v;
    let b = mosura_bytes { ptr: v.as_mut_ptr(), len: v.len(), cap: v.capacity() };
    std::mem::forget(v);
    b
}

/// Free a buffer handed out as `mosura_bytes`; NULL or an empty value is a no-op, and the struct
/// is zeroed so a second dispose is harmless.
#[no_mangle]
pub unsafe extern "C" fn mosura_bytes_dispose(b: *mut mosura_bytes) {
    if b.is_null() {
        return;
    }
    let b = &mut *b;
    if !b.ptr.is_null() && b.cap != 0 {
        drop(Vec::from_raw_parts(b.ptr, b.len, b.cap));
    }
    b.ptr = std::ptr::null_mut();
    b.len = 0;
    b.cap = 0;
}

/// A NUL-terminated UTF-8 string parameter.
pub unsafe fn cstr<'a>(p: *const c_char, what: &str) -> Result<&'a str> {
    if p.is_null() {
        return Err(Error::InvalidArg(format!("NULL `{what}`")));
    }
    CStr::from_ptr(p).to_str().map_err(|_| Error::InvalidArg(format!("`{what}` is not UTF-8")))
}

/// An optional NUL-terminated string (NULL = None).
pub unsafe fn cstr_opt<'a>(p: *const c_char, what: &str) -> Result<Option<&'a str>> {
    if p.is_null() { Ok(None) } else { cstr(p, what).map(Some) }
}

/// An out-pointer.
pub unsafe fn out_ptr<'a, T>(p: *mut T, what: &str) -> Result<&'a mut T> {
    if p.is_null() {
        return Err(Error::InvalidArg(format!("NULL out pointer `{what}`")));
    }
    Ok(&mut *p)
}

/// The bytes a view points at (NULL with a non-zero length is refused; NULL/0 is empty).
pub unsafe fn view_bytes<'a>(v: mosura_view, what: &str) -> Result<&'a [u8]> {
    if v.ptr.is_null() {
        if v.len == 0 {
            return Ok(&[]);
        }
        return Err(Error::InvalidArg(format!("`{what}`: NULL view with length {}", v.len)));
    }
    Ok(std::slice::from_raw_parts(v.ptr, v.len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_and_dispose_twice_is_harmless() {
        let mut b = bytes(b"hello".to_vec());
        assert_eq!(unsafe { std::slice::from_raw_parts(b.ptr, b.len) }, b"hello");
        unsafe { mosura_bytes_dispose(&mut b) };
        assert!(b.ptr.is_null() && b.len == 0 && b.cap == 0);
        unsafe { mosura_bytes_dispose(&mut b) };
        unsafe { mosura_bytes_dispose(std::ptr::null_mut()) };
        let mut empty = bytes(Vec::new());
        unsafe { mosura_bytes_dispose(&mut empty) };
    }

    #[test]
    fn pointer_checks() {
        unsafe {
            assert!(matches!(cstr(std::ptr::null(), "key"), Err(Error::InvalidArg(m)) if m.contains("NULL `key`")));
            let s = std::ffi::CString::new("ok").unwrap();
            assert_eq!(cstr(s.as_ptr(), "key").unwrap(), "ok");
            assert_eq!(cstr_opt(std::ptr::null(), "x").unwrap(), None);
            let bad = [0xffu8, 0xfe, 0];
            assert!(matches!(cstr(bad.as_ptr() as *const c_char, "key"), Err(Error::InvalidArg(m)) if m.contains("UTF-8")));
            assert!(out_ptr::<u32>(std::ptr::null_mut(), "out").is_err());
            assert_eq!(view_bytes(mosura_view { ptr: std::ptr::null(), len: 0 }, "v").unwrap(), &[] as &[u8]);
            assert!(view_bytes(mosura_view { ptr: std::ptr::null(), len: 3 }, "v").is_err());
            assert_eq!(view_bytes(view(b"abc"), "v").unwrap(), b"abc");
        }
    }
}
