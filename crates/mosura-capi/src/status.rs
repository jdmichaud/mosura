//! `mosura_status` and the thread-local last-error message.

use std::cell::RefCell;
use std::ffi::{c_char, CString};

use mosura_api::Error;

/// Every function returns one of these; details via `mosura_last_error()`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum mosura_status {
    MOSURA_OK = 0,
    /// NULL where a value is required, bad option key/value, bad handle kind, a released handle
    MOSURA_ERR_INVALID_ARG,
    /// no such function / table / operation / cache entry
    MOSURA_ERR_NOT_FOUND,
    /// session directory, input file, toolchain work dir
    MOSURA_ERR_IO,
    /// unreadable input, corrupt .tbl, unknown schema version
    MOSURA_ERR_FORMAT,
    /// no loader claims the file, language has no tables, op not built in
    MOSURA_ERR_UNSUPPORTED,
    /// the compiler could not be run (not: the source failed to compile)
    MOSURA_ERR_TOOLCHAIN,
    /// a progress callback returned non-zero
    MOSURA_ERR_CANCELLED,
    /// struct size/version mismatch, or a session written by an incompatible build
    MOSURA_ERR_VERSION,
    /// a panic was caught at the boundary; message = the panic text
    MOSURA_ERR_INTERNAL,
}

impl From<&Error> for mosura_status {
    fn from(e: &Error) -> mosura_status {
        use mosura_status::*;
        match e {
            Error::InvalidArg(_) => MOSURA_ERR_INVALID_ARG,
            Error::NotFound(_) => MOSURA_ERR_NOT_FOUND,
            Error::Io(..) => MOSURA_ERR_IO,
            Error::Format(_) => MOSURA_ERR_FORMAT,
            Error::Unsupported(_) => MOSURA_ERR_UNSUPPORTED,
            Error::Version { .. } => MOSURA_ERR_VERSION,
            Error::Cancelled => MOSURA_ERR_CANCELLED,
            Error::Internal(_) => MOSURA_ERR_INTERNAL,
        }
    }
}

thread_local! {
    static LAST: RefCell<CString> = RefCell::new(CString::default());
    static LAST_STATUS: std::cell::Cell<mosura_status> = const { std::cell::Cell::new(mosura_status::MOSURA_OK) };
}

/// Record a failure for this thread (interior NULs are replaced).
pub fn set(status: mosura_status, msg: &str) {
    let msg = CString::new(msg.replace('\0', "\u{fffd}")).unwrap_or_default();
    LAST.with(|l| *l.borrow_mut() = msg);
    LAST_STATUS.with(|s| s.set(status));
}

/// A call succeeded: the message is cleared.
pub fn clear() {
    LAST.with(|l| {
        if !l.borrow().as_bytes().is_empty() {
            *l.borrow_mut() = CString::default();
        }
    });
    LAST_STATUS.with(|s| s.set(mosura_status::MOSURA_OK));
}

/// The status recorded with the last message (tests; the C side has the return value).
pub fn last_status() -> mosura_status {
    LAST_STATUS.with(|s| s.get())
}

/// The message for the last non-OK status on THIS thread. Valid until the next mosura call on
/// the thread. Never NULL (empty when there is none).
#[no_mangle]
pub extern "C" fn mosura_last_error() -> *const c_char {
    LAST.with(|l| l.borrow().as_ptr())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_message_is_per_thread_and_cleared_on_success() {
        set(mosura_status::MOSURA_ERR_IO, "disk on fire");
        let here = unsafe { std::ffi::CStr::from_ptr(mosura_last_error()) }.to_str().unwrap().to_string();
        assert_eq!(here, "disk on fire");
        assert_eq!(last_status(), mosura_status::MOSURA_ERR_IO);
        let other = std::thread::spawn(|| unsafe { std::ffi::CStr::from_ptr(mosura_last_error()) }.to_str().unwrap().to_string()).join().unwrap();
        assert_eq!(other, "", "another thread sees its own (empty) message");
        clear();
        assert_eq!(unsafe { std::ffi::CStr::from_ptr(mosura_last_error()) }.to_bytes(), b"");
        set(mosura_status::MOSURA_ERR_INTERNAL, "a\0b");
        assert_eq!(unsafe { std::ffi::CStr::from_ptr(mosura_last_error()) }.to_str().unwrap(), "a\u{fffd}b");
    }

    #[test]
    fn every_api_error_maps_to_a_status() {
        use mosura_status::*;
        assert_eq!(mosura_status::from(&Error::InvalidArg("x".into())), MOSURA_ERR_INVALID_ARG);
        assert_eq!(mosura_status::from(&Error::NotFound("x".into())), MOSURA_ERR_NOT_FOUND);
        assert_eq!(mosura_status::from(&Error::Io(std::io::Error::other("x"), "/p".into())), MOSURA_ERR_IO);
        assert_eq!(mosura_status::from(&Error::Format("x".into())), MOSURA_ERR_FORMAT);
        assert_eq!(mosura_status::from(&Error::Unsupported("x".into())), MOSURA_ERR_UNSUPPORTED);
        assert_eq!(mosura_status::from(&Error::Version { found: "1".into(), expected: "2".into() }), MOSURA_ERR_VERSION);
        assert_eq!(mosura_status::from(&Error::Cancelled), MOSURA_ERR_CANCELLED);
        assert_eq!(mosura_status::from(&Error::Internal("x".into())), MOSURA_ERR_INTERNAL);
        assert_eq!(MOSURA_ERR_INTERNAL as u32, 9, "the enum's C values are the header's");
    }
}
