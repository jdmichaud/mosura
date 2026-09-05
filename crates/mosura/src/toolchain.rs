//! A compiler mosura can drive, open in a session.

use std::ffi::CString;

use crate::error::{check, Result};
use crate::handle::Raw;
use crate::options::Options;
use crate::session::Session;
use crate::table::Table;
use mosura_capi::{mosura_table, mosura_toolchain};

pub struct Toolchain {
    raw: Raw<mosura_toolchain>,
}

impl Toolchain {
    pub(crate) fn open(s: &mut Session, name: &str, opts: Option<&Options>) -> Result<Toolchain> {
        let n = CString::new(name).unwrap_or_default();
        let mut out: *mut mosura_toolchain = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_toolchain_open(s.ptr(), n.as_ptr(), opts.map(|o| o.ptr() as *const _).unwrap_or(std::ptr::null()), &mut out) })?;
        Ok(Toolchain { raw: Raw::new(out) })
    }

    pub(crate) fn ptr(&self) -> *mut mosura_toolchain {
        self.raw.ptr()
    }

    /// Compile a batch (a `compile_units` table: key, source, flags) → `compile_outputs`.
    pub fn compile(&self, units: &Table) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_toolchain_compile(self.ptr(), units.ptr(), &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// The liveness probe: one tiny unit through the compiler.
    pub fn check(&self) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_toolchain_check(self.ptr(), &mut out) })?;
        Ok(Table::from_raw(out))
    }
}

impl std::fmt::Debug for Toolchain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Toolchain")
    }
}
