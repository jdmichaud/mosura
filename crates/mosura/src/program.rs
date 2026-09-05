//! A loaded (and possibly analyzed) program of a session.

use std::ffi::CString;

use crate::error::{check, Result};
use crate::function::Function;
use crate::handle::{empty_bytes, slice_of, take_string, Raw};
use crate::options::Options;
use crate::session::{progress_args, ProgressFn, Session};
use crate::table::Table;
use mosura_capi::{mosura_program, mosura_table, mosura_view};

pub struct Program {
    raw: Raw<mosura_program>,
}

fn opt_ptr(o: Option<&Options>) -> *const mosura_capi::mosura_options {
    o.map(|o| o.ptr() as *const _).unwrap_or(std::ptr::null())
}

impl Program {
    pub(crate) fn open(s: &mut Session, input: Option<&str>, load_opts: Option<&Options>) -> Result<Program> {
        let input_c = input.map(|i| CString::new(i).unwrap_or_default());
        let mut out: *mut mosura_program = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_program_open(s.ptr(), input_c.as_ref().map(|c| c.as_ptr()).unwrap_or(std::ptr::null()), opt_ptr(load_opts), &mut out) })?;
        Ok(Program { raw: Raw::new(out) })
    }

    pub(crate) fn ptr(&self) -> *mut mosura_program {
        self.raw.ptr()
    }

    /// Auto-analysis to convergence (served from the store when its key exists).
    pub fn analyze(&mut self, opts: Option<&Options>, progress: Option<ProgressFn<'_>>) -> Result<()> {
        let mut p = progress;
        let (f, user) = progress_args(p.as_mut());
        check(unsafe { mosura_capi::mosura_program_analyze(self.ptr(), opt_ptr(opts), f, user) })
    }

    /// The whole-program passes that feed emission.
    pub fn passes(&mut self, opts: Option<&Options>, progress: Option<ProgressFn<'_>>) -> Result<()> {
        let mut p = progress;
        let (f, user) = progress_args(p.as_mut());
        check(unsafe { mosura_capi::mosura_program_passes(self.ptr(), opt_ptr(opts), f, user) })
    }

    /// A program table by name (the virtual `snapshot` included; "" lists the tables).
    pub fn table(&self, name: &str) -> Result<Table> {
        let n = CString::new(name).unwrap_or_default();
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_program_table(self.ptr(), n.as_ptr(), &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// The loaded bytes at `addr` (copied).
    pub fn read(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut v = mosura_view { ptr: std::ptr::null(), len: 0 };
        check(unsafe { mosura_capi::mosura_program_read(self.ptr(), addr, len, &mut v) })?;
        Ok(unsafe { slice_of(v) }.to_vec())
    }

    /// The listing's code units over `addr`, `len`, with their text.
    pub fn disassemble(&self, addr: u64, len: usize) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_program_disassemble(self.ptr(), addr, len, &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// The program set's key (64 hex).
    pub fn key(&self) -> Result<String> {
        let mut b = empty_bytes();
        check(unsafe { mosura_capi::mosura_program_key(self.ptr(), &mut b) })?;
        Ok(take_string(b))
    }

    /// The Snapshot v1 text.
    pub fn snapshot(&self) -> Result<String> {
        let mut b = empty_bytes();
        check(unsafe { mosura_capi::mosura_program_snapshot(self.ptr(), &mut b) })?;
        Ok(take_string(b))
    }

    /// Annotations are not in this version (an `Unsupported` error).
    pub fn annotate(&mut self, kind: &str, addr: u64, payload: &str) -> Result<()> {
        let (k, p) = (CString::new(kind).unwrap_or_default(), CString::new(payload).unwrap_or_default());
        check(unsafe { mosura_capi::mosura_program_annotate(self.ptr(), k.as_ptr(), addr, p.as_ptr()) })
    }

    /// Decompile the function at `entry` (its set is made or served now).
    pub fn decompile(&self, entry: u64, opts: Option<&Options>) -> Result<Function> {
        Function::decompile(self, entry, opts)
    }
}

impl std::fmt::Debug for Program {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Program({})", self.key().unwrap_or_default())
    }
}
