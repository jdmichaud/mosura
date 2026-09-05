//! The api's error: one variant per `mosura_status` code of the C surface (`docs/product/mosura.h`
//! §1), so the boundary maps it one-to-one and a message travels with every failure.

use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum Error {
    /// NULL where a value is required, a bad option key or value, a bad handle kind, a type mismatch.
    InvalidArg(String),
    /// No such function, table, operation, cache entry or column.
    NotFound(String),
    /// The session directory, an input file, a toolchain work dir.
    Io(std::io::Error, PathBuf),
    /// An unreadable input, a corrupt `.tbl`, an unknown schema version.
    Format(String),
    /// No loader claims the file, a language without tables, an operation not built in.
    Unsupported(String),
    /// A struct size/version mismatch, or a store written by an incompatible build.
    Version { found: String, expected: String },
    /// A progress callback asked to stop; the session holds no partial state.
    Cancelled,
    /// A panic caught at the boundary; the message is the panic text.
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidArg(m) => write!(f, "invalid argument: {m}"),
            Error::NotFound(m) => write!(f, "not found: {m}"),
            Error::Io(e, p) => write!(f, "{}: {e}", p.display()),
            Error::Format(m) => write!(f, "format: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
            Error::Version { found, expected } => write!(f, "version: found {found}, this build expects {expected}"),
            Error::Cancelled => write!(f, "cancelled"),
            Error::Internal(m) => write!(f, "internal: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    pub fn io(e: std::io::Error, path: impl Into<PathBuf>) -> Error {
        Error::Io(e, path.into())
    }
}
