//! §6 Operations — the generic spine: the registry and schemas as tables, and `mosura_call`,
//! which reaches every operation by name with its parameters as option keys.

use std::ffi::{c_char, c_int, c_void, CString};

use crate::boundary::guard;
use crate::ctx::{ctx_of, mosura_ctx, mosura_progress_fn};
use crate::mem::{cstr, out_ptr};
use crate::options::{mosura_options, options_of};
use crate::session::{mosura_session, session_of, SessionCell};
use crate::status::mosura_status;
use crate::table::{mosura_table, new_table};
use mosura_api::ops::{self, Progress, Tier};
use mosura_api::{Error, Options, Result, Session, Table};

/// The C progress callback as the api's `Progress` (non-zero from C cancels).
pub(crate) struct CProgress {
    pub f: mosura_progress_fn,
    pub user: *mut c_void,
}

impl Progress for CProgress {
    fn report(&mut self, what: &str, done: u64, total: u64) -> bool {
        match self.f {
            None => true,
            Some(f) => {
                let stage = CString::new(what.replace('\0', " ")).unwrap_or_default();
                unsafe { f(self.user, stage.as_ptr(), done, total) == 0 }
            }
        }
    }
}

/// The parameters of a call: the explicit ones over the session config's defaults, restricted to
/// what the operation accepts (the session config may carry keys for other operations).
pub(crate) fn merged_params(session: &Session, op: &str, params: Option<&Options>) -> Result<Options> {
    let mut o = params.cloned().unwrap_or_default();
    if let Some(spec) = ops::lookup(op) {
        for (k, v) in session.config() {
            if !o.is_set(k) && ops::accepts(spec, k) {
                o.set(k, v).map_err(|e| Error::InvalidArg(format!("session config: {e}")))?;
            }
        }
    }
    Ok(o)
}

/// Run one operation on a session's shared cell (the typed entry points hold a clone of it).
pub(crate) fn call_on(cell: &SessionCell, op: &str, params: Option<&Options>, progress: mosura_progress_fn, user: *mut c_void) -> Result<Table> {
    let mut session = cell.session.lock().unwrap_or_else(|p| p.into_inner());
    let merged = merged_params(&session, op, params)?;
    let mut prog = CProgress { f: progress, user };
    ops::dispatch(&cell.ctx, &mut session, op, &merged, &mut prog)
}

/// Run one operation on a session handle.
pub(crate) unsafe fn call(s: *mut mosura_session, op: &str, params: Option<&Options>, progress: mosura_progress_fn, user: *mut c_void) -> Result<Table> {
    call_on(session_of(s)?, op, params, progress, user)
}

/// The text of a one-row `text` table (what the text-answering operations return).
pub(crate) fn text_of(t: &Table) -> Result<String> {
    mosura_api::render(t, mosura_api::Format::Text)
}

/// The keys of `from` that `op` accepts, as a fresh option set (a program's load/analysis options
/// carried into its function operations, for example).
pub(crate) fn keys_for(op: &str, from: &Options) -> Options {
    let mut o = Options::new();
    if let Some(spec) = ops::lookup(op) {
        for (k, v) in from.explicit() {
            if ops::accepts(spec, k) {
                let _ = o.set(k, v);
            }
        }
    }
    o
}

/// The operation registry as a table: name, tier, since, cache, params, result, doc. `include_dev`
/// adds the dev tier (none in a release build).
#[no_mangle]
pub unsafe extern "C" fn mosura_ops(ctx: *mut mosura_ctx, include_dev: c_int, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let _ = ctx_of(ctx)?;
        let out = out_ptr(out, "out")?;
        *out = new_table(ops::ops_table(if include_dev != 0 { None } else { Some(Tier::Product) }));
        Ok(())
    })
}

/// The schema of a named table type, as a table of columns (col, type, hint).
#[no_mangle]
pub unsafe extern "C" fn mosura_schema(ctx: *mut mosura_ctx, table_name: *const c_char, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let _ = ctx_of(ctx)?;
        let name = cstr(table_name, "table_name")?;
        let out = out_ptr(out, "out")?;
        *out = new_table(ops::schema_table(name)?);
        Ok(())
    })
}

/// Invoke any operation by name. `params` (NULL = none) carries the op's parameters as option
/// keys ("input", "entry", "format", … are ordinary keys); the session config supplies defaults
/// for the keys the op accepts. The result is a table; text results are a one-row `text` table.
/// Pure operations are served from the session store when their key is present.
#[no_mangle]
pub unsafe extern "C" fn mosura_call(s: *mut mosura_session, op: *const c_char, params: *const mosura_options, progress: mosura_progress_fn, progress_user: *mut c_void, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let op = cstr(op, "op")?;
        let out = out_ptr(out, "out")?;
        let params = if params.is_null() { None } else { Some(options_of(params)?) };
        let t = call(s, op, params, progress, progress_user)?;
        *out = new_table(t);
        Ok(())
    })
}
