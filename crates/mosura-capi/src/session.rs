//! §7 The session store: open (a directory, or memory), inputs, provenance, gc.

use std::ffi::{c_char, c_int, c_void};
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::boundary::guard;
use crate::ctx::{ctx_of, mosura_ctx};
use crate::handle::{self, Kind};
use crate::mem::{bytes, cstr, cstr_opt, out_ptr, view_bytes, mosura_bytes, mosura_view};
use crate::options::options_or_default;
use crate::status::mosura_status;
use crate::table::{mosura_table, new_table};
use mosura_api::key::Key;
use mosura_api::{Context, Error, Result, Session, SetKind};

/// A session store: a directory or memory (opaque).
#[repr(C)]
pub struct mosura_session {
    _private: [u8; 0],
}

/// The handle's payload: the session shared with the program and function handles derived from
/// it (so releasing the session first is safe), and the context that runs its operations.
#[derive(Clone)]
pub(crate) struct SessionCell {
    pub ctx: Arc<Context>,
    pub session: Arc<Mutex<Session>>,
}

pub(crate) unsafe fn session_of<'a>(p: *const mosura_session) -> Result<&'a SessionCell> {
    handle::as_ref::<SessionCell>(p as *const c_void, Kind::Session)
}

/// Open or create a session. `dir == NULL` is an in-memory session (nothing persists). The
/// session's own config table supplies option defaults for every operation run in it; `config`
/// (NULL = none) is written into it.
#[no_mangle]
pub unsafe extern "C" fn mosura_session_open(ctx: *mut mosura_ctx, dir: *const c_char, config: *const crate::options::mosura_options, out: *mut *mut mosura_session) -> mosura_status {
    guard(|| {
        let c = Arc::clone(ctx_of(ctx)?);
        let dir = cstr_opt(dir, "dir")?;
        let cfg = options_or_default(config)?;
        let out = out_ptr(out, "out")?;
        let mut s = Session::open(dir.map(Path::new))?;
        for (k, v) in cfg.explicit() {
            s.config_set(k, v)?;
        }
        *out = handle::new(Kind::Session, SessionCell { ctx: c, session: Arc::new(Mutex::new(s)) }) as *mut mosura_session;
        Ok(())
    })
}

/// Add an input binary (content-addressed). `label` (NULL = "input") names it for the commands
/// and is also the file name the container dispatch sees — pass the file's name (with its
/// extension) for `.com` detection, or select the loader with `load.loader`. Re-adding identical
/// bytes is a no-op answering the same digest. `digest_hex` (NULL = not wanted) receives the
/// 64-hex blake3 digest.
#[no_mangle]
pub unsafe extern "C" fn mosura_session_add_input(s: *mut mosura_session, bytes_in: mosura_view, label: *const c_char, digest_hex: *mut mosura_bytes) -> mosura_status {
    guard(|| {
        let cell = session_of(s)?;
        let data = view_bytes(bytes_in, "bytes")?;
        let label = cstr_opt(label, "label")?.unwrap_or("input");
        let mut session = cell.session.lock().unwrap_or_else(|p| p.into_inner());
        let d = session.add_input(data, label, Some(label))?;
        if !digest_hex.is_null() {
            *digest_hex = bytes(mosura_api::fingerprint::hex(&d).into_bytes());
        }
        Ok(())
    })
}

/// inputs: label, digest, size, filename, added.
#[no_mangle]
pub unsafe extern "C" fn mosura_session_inputs(s: *mut mosura_session, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let cell = session_of(s)?;
        let out = out_ptr(out, "out")?;
        let session = cell.session.lock().unwrap_or_else(|p| p.into_inner());
        *out = new_table(session.inputs_table());
        Ok(())
    })
}

/// Provenance of a stored table set (a program or function key, 64 hex): kind, name, value rows
/// — inputs, options tag, stage fingerprint, build id, creation time, tables.
#[no_mangle]
pub unsafe extern "C" fn mosura_session_explain(s: *mut mosura_session, key: *const c_char, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let cell = session_of(s)?;
        let key_s = cstr(key, "key")?;
        let out = out_ptr(out, "out")?;
        let k = Key::from_hex(key_s).ok_or_else(|| Error::InvalidArg(format!("`key` is not a 64-hex key: {key_s}")))?;
        let session = cell.session.lock().unwrap_or_else(|p| p.into_inner());
        let t = match session.explain(SetKind::Program, &k) {
            Ok(t) => t,
            Err(Error::NotFound(_)) => session.explain(SetKind::Function, &k)?,
            Err(e) => return Err(e),
        };
        *out = new_table(t);
        Ok(())
    })
}

/// The stored table sets (kind, key, tables, bytes). This version lists only: `dry_run` must be
/// non-zero (removal is MOSURA_ERR_UNSUPPORTED until rounds exist to define reachability).
#[no_mangle]
pub unsafe extern "C" fn mosura_session_gc(s: *mut mosura_session, dry_run: c_int, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let cell = session_of(s)?;
        let out = out_ptr(out, "out")?;
        if dry_run == 0 {
            return Err(Error::Unsupported("cache gc removes nothing in this version (no rounds to define reachability); dry run lists the sets".into()));
        }
        let session = cell.session.lock().unwrap_or_else(|p| p.into_inner());
        *out = new_table(session.sets()?);
        Ok(())
    })
}
