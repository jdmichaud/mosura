//! A session store, and `call` — the plumbing that reaches every operation.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::path::Path;

use crate::ctx::Ctx;
use crate::error::{check, Result};
use crate::handle::{empty_bytes, take_string, view_of, Raw};
use crate::options::Options;
use crate::program::Program;
use crate::table::Table;
use mosura_capi::{mosura_progress_fn, mosura_session, mosura_table};

/// A progress callback: (stage, done, total) → keep going?
pub type ProgressFn<'a> = &'a mut dyn FnMut(&str, u64, u64) -> bool;

unsafe extern "C" fn progress_trampoline(user: *mut c_void, stage: *const c_char, done: u64, total: u64) -> c_int {
    let f = &mut *(user as *mut ProgressFn<'_>);
    let stage = if stage.is_null() { "" } else { CStr::from_ptr(stage).to_str().unwrap_or("") };
    // a callback must not unwind into the library: a panic cancels
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(stage, done, total))) {
        Ok(true) => 0,
        _ => 1,
    }
}

/// The (callback, user) pair the C side takes.
pub(crate) fn progress_args(p: Option<&mut ProgressFn<'_>>) -> (mosura_progress_fn, *mut c_void) {
    match p {
        None => (None, std::ptr::null_mut()),
        Some(f) => (Some(progress_trampoline as unsafe extern "C" fn(*mut c_void, *const c_char, u64, u64) -> c_int), f as *mut ProgressFn<'_> as *mut c_void),
    }
}

pub struct Session {
    raw: Raw<mosura_session>,
}

impl Session {
    /// Open or create a session at `dir` (None = in memory). `config` is written into the
    /// session's config table and supplies defaults for every operation run in it.
    pub fn open(ctx: &Ctx, dir: Option<&Path>, config: Option<&Options>) -> Result<Session> {
        let dir_c = dir.map(|d| CString::new(d.to_string_lossy().into_owned()).unwrap_or_default());
        let mut out: *mut mosura_session = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_session_open(ctx.ptr(), dir_c.as_ref().map(|d| d.as_ptr()).unwrap_or(std::ptr::null()), config.map(|c| c.ptr() as *const _).unwrap_or(std::ptr::null()), &mut out) })?;
        Ok(Session { raw: Raw::new(out) })
    }

    pub(crate) fn ptr(&self) -> *mut mosura_session {
        self.raw.ptr()
    }

    /// Add an input (content-addressed); `label` is also the file name the loaders see. Returns
    /// the 64-hex digest.
    pub fn add_input(&mut self, bytes: &[u8], label: &str) -> Result<String> {
        let l = CString::new(label).unwrap_or_default();
        let mut d = empty_bytes();
        check(unsafe { mosura_capi::mosura_session_add_input(self.ptr(), view_of(bytes), l.as_ptr(), &mut d) })?;
        Ok(take_string(d))
    }

    pub fn inputs(&self) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_session_inputs(self.ptr(), &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// Provenance of a stored set (a program or function key).
    pub fn explain(&self, key: &str) -> Result<Table> {
        let k = CString::new(key).unwrap_or_default();
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_session_explain(self.ptr(), k.as_ptr(), &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// The stored sets (dry run); removal is not in this version.
    pub fn gc(&self, dry_run: bool) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_session_gc(self.ptr(), dry_run as c_int, &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// Any operation by name with its parameters as option keys.
    pub fn call(&mut self, op: &str, params: Option<&Options>, progress: Option<ProgressFn<'_>>) -> Result<Table> {
        let o = CString::new(op).unwrap_or_default();
        let mut p = progress;
        let (f, user) = progress_args(p.as_mut());
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_call(self.ptr(), o.as_ptr(), params.map(|p| p.ptr() as *const _).unwrap_or(std::ptr::null()), f, user, &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// Load an input (None = the only one) into a program (no analysis yet).
    pub fn program_open(&mut self, input: Option<&str>, load_opts: Option<&Options>) -> Result<Program> {
        Program::open(self, input, load_opts)
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Session")
    }
}
