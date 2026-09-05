//! A SLEIGH language over raw bytes.

use std::ffi::CString;

use crate::ctx::Ctx;
use crate::error::{check, Result};
use crate::handle::{view_of, Raw};
use crate::options::Options;
use crate::table::Table;
use mosura_capi::{mosura_language, mosura_table};

pub struct Language {
    raw: Raw<mosura_language>,
}

impl Language {
    pub(crate) fn open(ctx: &Ctx, id: &str) -> Result<Language> {
        let id = CString::new(id).unwrap_or_default();
        let mut out: *mut mosura_language = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_language_open(ctx.ptr(), id.as_ptr(), &mut out) })?;
        Ok(Language { raw: Raw::new(out) })
    }

    /// registers: name, space, offset, size.
    pub fn registers(&self) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_language_registers(self.raw.ptr(), &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// Disassemble raw bytes at `base`; `ctx_regs` carries the context settings in its `ctx` key.
    pub fn disassemble(&self, bytes: &[u8], base: u64, ctx_regs: Option<&Options>) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_disassemble(self.raw.ptr(), view_of(bytes), base, ctx_regs.map(|o| o.ptr() as *const _).unwrap_or(std::ptr::null()), &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// Lift raw bytes to raw p-code.
    pub fn lift(&self, bytes: &[u8], base: u64, ctx_regs: Option<&Options>) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_lift(self.raw.ptr(), view_of(bytes), base, ctx_regs.map(|o| o.ptr() as *const _).unwrap_or(std::ptr::null()), &mut out) })?;
        Ok(Table::from_raw(out))
    }
}

impl std::fmt::Debug for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Language")
    }
}
