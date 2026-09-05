//! One decompiled function.

use std::ffi::CString;

use crate::error::{check, Result};
use crate::handle::{empty_bytes, take_string, Raw};
use crate::options::Options;
use crate::program::Program;
use crate::table::{Format, Table};
use crate::toolchain::Toolchain;
use mosura_capi::{mosura_function, mosura_table};

pub struct Function {
    raw: Raw<mosura_function>,
}

fn opt_ptr(o: Option<&Options>) -> *const mosura_capi::mosura_options {
    o.map(|o| o.ptr() as *const _).unwrap_or(std::ptr::null())
}

impl Function {
    pub(crate) fn decompile(p: &Program, entry: u64, opts: Option<&Options>) -> Result<Function> {
        let mut out: *mut mosura_function = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_function_decompile(p.ptr(), entry, opt_ptr(opts), &mut out) })?;
        Ok(Function { raw: Raw::new(out) })
    }

    /// The C under the handle's options.
    pub fn c(&self) -> Result<String> {
        let mut b = empty_bytes();
        check(unsafe { mosura_capi::mosura_function_c(self.raw.ptr(), &mut b) })?;
        Ok(take_string(b))
    }

    /// The C under explicit emit choices.
    pub fn render(&self, emit_choices: &Options) -> Result<String> {
        let mut b = empty_bytes();
        check(unsafe { mosura_capi::mosura_function_render(self.raw.ptr(), emit_choices.ptr(), &mut b) })?;
        Ok(take_string(b))
    }

    /// The IR at `stage` ("post") in `format` (TEXT).
    pub fn ir(&self, stage: &str, format: Format) -> Result<String> {
        let s = CString::new(stage).unwrap_or_default();
        let mut b = empty_bytes();
        check(unsafe { mosura_capi::mosura_function_ir(self.raw.ptr(), s.as_ptr(), format, &mut b) })?;
        Ok(take_string(b))
    }

    /// A function table: prototype, jumptables, calls, report.
    pub fn table(&self, name: &str) -> Result<Table> {
        let n = CString::new(name).unwrap_or_default();
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_function_table(self.raw.ptr(), n.as_ptr(), &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// The build flags recovered from the original's prologue (rows fact/flag).
    pub fn buildconfig(&self, opts: Option<&Options>) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_function_buildconfig(self.raw.ptr(), opt_ptr(opts), &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// Verify a compiled object against the original (one `verdicts` row; opts: format, window).
    pub fn verify(&self, object: &[u8], opts: Option<&Options>) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_function_verify(self.raw.ptr(), crate::handle::view_of(object), opt_ptr(opts), &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// Emit → compile through `tc` → verify (one `verdicts` row; opts: format=table:divergences|table:diff).
    pub fn recompile(&self, tc: &Toolchain, opts: Option<&Options>) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_function_recompile(self.raw.ptr(), tc.ptr(), opt_ptr(opts), &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// The recovered translation unit (Watcom x86-32).
    pub fn tu(&self, opts: Option<&Options>) -> Result<String> {
        let mut b = empty_bytes();
        check(unsafe { mosura_capi::mosura_function_tu(self.raw.ptr(), opt_ptr(opts), &mut b) })?;
        Ok(take_string(b))
    }
}

impl std::fmt::Debug for Function {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Function")
    }
}
