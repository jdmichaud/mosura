//! §9 Identify, load, analyze — the Program. A program handle is a KEY into the session store plus
//! the options it was made with; every accessor is an operation call served from the store.

use std::ffi::{c_char, c_void};

use crate::boundary::guard;
use crate::ctx::{ctx_of, mosura_ctx, mosura_progress_fn};
use crate::handle::{self, Kind};
use crate::mem::{bytes, cstr, cstr_opt, out_ptr, view, view_bytes, mosura_bytes, mosura_view};
use crate::ops::{call_on, keys_for, text_of};
use crate::options::{mosura_options, options_or_default};
use crate::session::{mosura_session, session_of, SessionCell};
use crate::status::mosura_status;
use crate::table::{mosura_table, new_table};
use mosura_api::key::Key;
use mosura_api::{Error, Options, Result, Session};

/// A loaded (and possibly analyzed) binary (opaque).
pub struct mosura_program {
    _private: [u8; 0],
}

pub(crate) struct ProgramCell {
    pub shared: SessionCell,
    /// The program set's key (load, then analyze).
    pub key: Key,
    /// The options the program was made with (load.*, analysis.*, knobs.off): carried into every
    /// derived operation that accepts them.
    pub base: Options,
    /// The last `mosura_program_read` answer (the view points into it).
    last_read: Vec<u8>,
}

pub(crate) unsafe fn program_of<'a>(p: *const mosura_program) -> Result<&'a ProgramCell> {
    handle::as_ref::<ProgramCell>(p as *const c_void, Kind::Program)
}

fn key_of_summary(t: &mosura_api::Table) -> Result<Key> {
    Key::from_hex(t.str(0, 0)?).ok_or_else(|| Error::Internal("summary without a key".into()))
}

/// The parameters of an operation on this program: the base options it accepts, then `extra`,
/// then `program=<key>`.
pub(crate) fn program_params(cell: &ProgramCell, op: &str, extra: Option<&Options>) -> Result<Options> {
    let mut o = keys_for(op, &cell.base);
    if let Some(x) = extra {
        for (k, v) in x.explicit() {
            o.set(k, v)?;
        }
    }
    o.set("program", &cell.key.hex())?;
    Ok(o)
}

/// Everything mosura can say about a file without analysing it: one row per fact (key, value,
/// evidence). Runs on a private in-memory session.
#[no_mangle]
pub unsafe extern "C" fn mosura_identify(ctx: *mut mosura_ctx, bytes_in: mosura_view, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let c = ctx_of(ctx)?;
        let data = view_bytes(bytes_in, "bytes")?;
        let out = out_ptr(out, "out")?;
        let mut s = Session::open(None)?;
        s.add_input(data, "input", None)?;
        let cell = SessionCell { ctx: std::sync::Arc::clone(c), session: std::sync::Arc::new(std::sync::Mutex::new(s)) };
        *out = new_table(call_on(&cell, "identify", None, None, std::ptr::null_mut())?);
        Ok(())
    })
}

/// Load an input of the session (`input` = a label or digest; NULL = the only one) into a
/// Program. `load_opts` (NULL = defaults): load.loader, load.language, load.base,
/// load.cspec-x86-32, analysis.disable, knobs.off. Served from the store when the key exists.
#[no_mangle]
pub unsafe extern "C" fn mosura_program_open(s: *mut mosura_session, input: *const c_char, load_opts: *const mosura_options, out: *mut *mut mosura_program) -> mosura_status {
    guard(|| {
        let cell = session_of(s)?.clone();
        let input = cstr_opt(input, "input")?;
        let mut base = options_or_default(load_opts)?;
        if let Some(i) = input {
            base.set("input", i)?;
        }
        let out = out_ptr(out, "out")?;
        let params = keys_for("program.load", &base);
        let summary = call_on(&cell, "program.load", Some(&params), None, std::ptr::null_mut())?;
        let key = key_of_summary(&summary)?;
        *out = handle::new(Kind::Program, ProgramCell { shared: cell, key, base, last_read: Vec::new() }) as *mut mosura_program;
        Ok(())
    })
}

/// Run auto-analysis to convergence (`opts`, NULL = none: analysis.disable, knobs.off — added to
/// the program's options). The program's key becomes the analyzed set's; a cached one returns
/// immediately.
#[no_mangle]
pub unsafe extern "C" fn mosura_program_analyze(p: *mut mosura_program, opts: *const mosura_options, progress: mosura_progress_fn, progress_user: *mut c_void) -> mosura_status {
    guard(|| {
        let extra = options_or_default(opts)?;
        let mut cell = handle::as_mut::<ProgramCell>(p as *mut c_void, Kind::Program)?;
        for (k, v) in extra.explicit() {
            cell.base.set(k, v)?;
        }
        let params = keys_for("program.analyze", &cell.base);
        let summary = call_on(&cell.shared, "program.analyze", Some(&params), progress, progress_user)?;
        cell.key = key_of_summary(&summary)?;
        Ok(())
    })
}

/// Whole-program passes that feed emission (the survey's pass 1, promoted): prototype recovery,
/// tail-return marks, parameter-order evidence, global widths. `opts` (NULL = none): knobs.off,
/// decompile.global-scope, decompile.proto-scope (the survey used `standalone`).
#[no_mangle]
pub unsafe extern "C" fn mosura_program_passes(p: *mut mosura_program, opts: *const mosura_options, progress: mosura_progress_fn, progress_user: *mut c_void) -> mosura_status {
    guard(|| {
        let extra = options_or_default(opts)?;
        let mut cell = handle::as_mut::<ProgramCell>(p as *mut c_void, Kind::Program)?;
        for (k, v) in extra.explicit() {
            cell.base.set(k, v)?;
        }
        let params = program_params(&cell, "program.passes", None)?;
        call_on(&cell.shared, "program.passes", Some(&params), progress, progress_user)?;
        Ok(())
    })
}

/// A program table by name ("functions", "symbols", "references", "blocks", "listing", …, and
/// the virtual "snapshot"); an empty name lists the tables. Unknown name: MOSURA_ERR_NOT_FOUND.
#[no_mangle]
pub unsafe extern "C" fn mosura_program_table(p: *mut mosura_program, name: *const c_char, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let cell = program_of(p)?;
        let name = cstr(name, "name")?;
        let out = out_ptr(out, "out")?;
        let mut extra = Options::new();
        extra.set("table", name)?;
        let params = program_params(cell, "program.tables", Some(&extra))?;
        *out = new_table(call_on(&cell.shared, "program.tables", Some(&params), None, std::ptr::null_mut())?);
        Ok(())
    })
}

/// Bytes of the loaded image at `addr`. The view is valid until the next `mosura_program_read`
/// on this handle (or its release). An unloaded address is MOSURA_ERR_NOT_FOUND.
#[no_mangle]
pub unsafe extern "C" fn mosura_program_read(p: *mut mosura_program, addr: u64, len: usize, out: *mut mosura_view) -> mosura_status {
    guard(|| {
        let out = out_ptr(out, "out")?;
        let mut cell = handle::as_mut::<ProgramCell>(p as *mut c_void, Kind::Program)?;
        let mut extra = Options::new();
        extra.set("addr", &format!("{addr:#x}"))?;
        extra.set("len", &len.to_string())?;
        let params = program_params(&cell, "program.read", Some(&extra))?;
        let t = call_on(&cell.shared, "program.read", Some(&params), None, std::ptr::null_mut())?;
        cell.last_read = t.bytes(0, 1)?.to_vec();
        *out = view(&cell.last_read);
        Ok(())
    })
}

/// Disassembly of a range from the listing (decoded on demand; text is never stored).
#[no_mangle]
pub unsafe extern "C" fn mosura_program_disassemble(p: *mut mosura_program, addr: u64, len: usize, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let cell = program_of(p)?;
        let out = out_ptr(out, "out")?;
        let mut extra = Options::new();
        extra.set("addr", &format!("{addr:#x}"))?;
        extra.set("len", &len.to_string())?;
        let params = program_params(cell, "program.disassemble", Some(&extra))?;
        *out = new_table(call_on(&cell.shared, "program.disassemble", Some(&params), None, std::ptr::null_mut())?);
        Ok(())
    })
}

/// The session's stable key for this program (64 hex; the directory under program/).
#[no_mangle]
pub unsafe extern "C" fn mosura_program_key(p: *mut mosura_program, key_hex: *mut mosura_bytes) -> mosura_status {
    guard(|| {
        let cell = program_of(p)?;
        let out = out_ptr(key_hex, "key_hex")?;
        *out = bytes(cell.key.hex().into_bytes());
        Ok(())
    })
}

/// User annotations. Not in this version (MOSURA_ERR_UNSUPPORTED).
#[no_mangle]
pub unsafe extern "C" fn mosura_program_annotate(p: *mut mosura_program, _kind: *const c_char, _addr: u64, _payload: *const c_char) -> mosura_status {
    guard(|| {
        let _ = program_of(p)?;
        Err(Error::Unsupported("annotations are not in this version".into()))
    })
}

#[no_mangle]
pub unsafe extern "C" fn mosura_program_unannotate(p: *mut mosura_program, _kind: *const c_char, _addr: u64) -> mosura_status {
    guard(|| {
        let _ = program_of(p)?;
        Err(Error::Unsupported("annotations are not in this version".into()))
    })
}

/// The Snapshot v1 text (the analysis golden format) — the TEXT rendering of the program's tables.
#[no_mangle]
pub unsafe extern "C" fn mosura_program_snapshot(p: *mut mosura_program, out: *mut mosura_bytes) -> mosura_status {
    guard(|| {
        let cell = program_of(p)?;
        let out = out_ptr(out, "out")?;
        let mut extra = Options::new();
        extra.set("table", "snapshot")?;
        let params = program_params(cell, "program.tables", Some(&extra))?;
        let t = call_on(&cell.shared, "program.tables", Some(&params), None, std::ptr::null_mut())?;
        *out = bytes(text_of(&t)?.into_bytes());
        Ok(())
    })
}
