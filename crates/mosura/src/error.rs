//! `mosura_status` as a `Result`: a non-OK status becomes an `Error` carrying the code and the
//! per-thread message read at once.

use std::ffi::CStr;

pub use mosura_capi::mosura_status as Status;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub status: Status,
    pub message: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.status, self.message)
    }
}
impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Turn a status into a `Result`, reading the message while it is still this call's.
pub(crate) fn check(s: Status) -> Result<()> {
    if s == Status::MOSURA_OK {
        return Ok(());
    }
    let message = unsafe { CStr::from_ptr(mosura_capi::mosura_last_error()) }.to_string_lossy().into_owned();
    Err(Error { status: s, message })
}
