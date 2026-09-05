//! §3 Context: `mosura_ctx_config` (size/version-prefixed), the log sink, `mosura_ctx_new`, the
//! embedded-data export and listing.

use std::ffi::{c_char, c_int, c_void, CString};
use std::mem::offset_of;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::boundary::{guard, ABORT_ON_PANIC};
use crate::handle::{self, Kind};
use crate::mem::{cstr, cstr_opt, out_ptr};
use crate::status::mosura_status;
use crate::table::mosura_table;
use mosura_api::{Context, ContextConfig, Error, Result};
use mosura_core::debug::{Config, Level};

/// The library: spec registry, caches, log sink (opaque).
pub struct mosura_ctx {
    _private: [u8; 0],
}

/// Diagnostic level of a log message.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum mosura_log_level {
    MOSURA_LOG_ERROR = 0,
    MOSURA_LOG_WARN,
    MOSURA_LOG_INFO,
    MOSURA_LOG_DEBUG,
}

/// Diagnostic sink. `topic` is the debug topic (`sparse-switch`, `analysis`, …) or "" for
/// untopiced messages; `msg` is NUL-terminated and `msg_len` its byte length. Replaces every
/// stderr print in the library.
pub type mosura_log_fn = Option<unsafe extern "C" fn(user: *mut c_void, level: mosura_log_level, topic: *const c_char, msg: *const c_char, msg_len: usize)>;

/// Progress callback for long operations. Return non-zero to cancel; the operation then fails
/// with MOSURA_ERR_CANCELLED and leaves no partial state in the session.
pub type mosura_progress_fn = Option<unsafe extern "C" fn(user: *mut c_void, stage: *const c_char, done: u64, total: u64) -> c_int>;

/// Context configuration. Starts with `size` + `version`; use MOSURA_CTX_CONFIG_INIT. The library
/// reads only the fields `size` covers.
#[repr(C)]
pub struct mosura_ctx_config {
    /// sizeof(mosura_ctx_config)
    pub size: u32,
    /// 1
    pub version: u32,
    /// Directories searched for spec data (`.ldefs`/`.sla`/`.pspec`/`.cspec`) BEFORE the embedded
    /// set — the user's override folder (`mosura data export` writes one).
    pub spec_dirs: *const *const c_char,
    pub spec_dirs_len: usize,
    /// Directories searched for FID databases (`.mfid[.gz]`, `.fidb`) before the embedded ones.
    pub fid_dirs: *const *const c_char,
    pub fid_dirs_len: usize,
    /// Machine-level cache for frozen specs etc. NULL = none. (Accepted; unused in this version.)
    pub cache_dir: *const c_char,
    pub log: mosura_log_fn,
    pub log_user: *mut c_void,
    /// Development aid: non-zero makes the boundary re-raise an internal panic (the process dies
    /// with its backtrace) instead of catching it into MOSURA_ERR_INTERNAL. Release clients
    /// leave it 0.
    pub abort_on_panic: c_int,
}

/// The C log callback as the core's sink. The callback contract is the caller's: it must be
/// callable from any thread the library uses.
struct CSink {
    f: unsafe extern "C" fn(*mut c_void, mosura_log_level, *const c_char, *const c_char, usize),
    user: usize,
}
unsafe impl Send for CSink {}
unsafe impl Sync for CSink {}

impl CSink {
    fn call(&self, level: Level, topic: &str, msg: &str) {
        let lvl = match level {
            Level::Warn => mosura_log_level::MOSURA_LOG_WARN,
            Level::Debug => mosura_log_level::MOSURA_LOG_DEBUG,
        };
        let topic_c = CString::new(topic.replace('\0', " ")).unwrap_or_default();
        let msg_c = CString::new(msg.replace('\0', " ")).unwrap_or_default();
        unsafe { (self.f)(self.user as *mut c_void, lvl, topic_c.as_ptr(), msg_c.as_ptr(), msg_c.as_bytes().len()) }
    }
}

unsafe fn dirs(p: *const *const c_char, n: usize, what: &str) -> Result<Vec<PathBuf>> {
    if n == 0 {
        return Ok(Vec::new());
    }
    if p.is_null() {
        return Err(Error::InvalidArg(format!("`{what}`: NULL with length {n}")));
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        out.push(PathBuf::from(cstr(*p.add(i), what)?));
    }
    Ok(out)
}

/// Create the library context. Thread-safe once created; everything derived from it is not,
/// unless stated. One configuration per process in this version: a second call with the same
/// override directories and panic policy answers the same context, a different one is
/// MOSURA_ERR_UNSUPPORTED.
#[no_mangle]
pub unsafe extern "C" fn mosura_ctx_new(config: *const mosura_ctx_config, out: *mut *mut mosura_ctx) -> mosura_status {
    guard(|| {
        let out = out_ptr(out, "out")?;
        if config.is_null() {
            return Err(Error::InvalidArg("NULL `config`".into()));
        }
        let size = (*config).size as usize;
        if size < 8 {
            return Err(Error::Version { found: format!("size {size}"), expected: "size >= 8".into() });
        }
        if (*config).version != 1 {
            return Err(Error::Version { found: format!("mosura_ctx_config version {}", (*config).version), expected: "version 1".into() });
        }
        let covers = |field: usize| size >= field;
        let mut cfg = ContextConfig::default();
        let mut data_dirs = Vec::new();
        if covers(offset_of!(mosura_ctx_config, spec_dirs_len) + std::mem::size_of::<usize>()) {
            data_dirs.extend(dirs((*config).spec_dirs, (*config).spec_dirs_len, "spec_dirs")?);
        }
        if covers(offset_of!(mosura_ctx_config, fid_dirs_len) + std::mem::size_of::<usize>()) {
            data_dirs.extend(dirs((*config).fid_dirs, (*config).fid_dirs_len, "fid_dirs")?);
        }
        if covers(offset_of!(mosura_ctx_config, cache_dir) + std::mem::size_of::<*const c_char>()) {
            let _ = cstr_opt((*config).cache_dir, "cache_dir")?; // accepted, unused in this version
        }
        let mut debug = Config::default();
        if covers(offset_of!(mosura_ctx_config, log_user) + std::mem::size_of::<*mut c_void>()) {
            if let Some(f) = (*config).log {
                let sink = CSink { f, user: (*config).log_user as usize };
                debug.sink = Some(Arc::new(move |level, topic, msg| sink.call(level, topic, msg)));
            }
        }
        let abort = covers(offset_of!(mosura_ctx_config, abort_on_panic) + std::mem::size_of::<c_int>()) && (*config).abort_on_panic != 0;
        cfg.data_dirs = data_dirs;
        cfg.debug = debug;
        cfg.abort_on_panic = abort;
        let ctx = Context::new(cfg)?;
        ABORT_ON_PANIC.store(abort, Ordering::Relaxed);
        *out = handle::new(Kind::Ctx, Arc::new(ctx)) as *mut mosura_ctx;
        Ok(())
    })
}

pub(crate) unsafe fn ctx_of<'a>(p: *const mosura_ctx) -> Result<&'a Arc<Context>> {
    handle::as_ref::<Arc<Context>>(p as *const c_void, Kind::Ctx)
}

/// Write the EMBEDDED data into `dir` as the source files it was built from: `what` = "specs",
/// "fid" or "all". Existing files are kept unless `overwrite` is non-zero. Answers the files
/// written (`files`).
#[no_mangle]
pub unsafe extern "C" fn mosura_ctx_export_data(ctx: *mut mosura_ctx, dir: *const c_char, what: *const c_char, overwrite: c_int, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let c = ctx_of(ctx)?;
        let dir = PathBuf::from(cstr(dir, "dir")?);
        let what = cstr(what, "what")?;
        let out = out_ptr(out, "out")?;
        let t = mosura_api::ops::export_data(c, &dir, what, overwrite != 0)?;
        *out = crate::table::new_table(t);
        Ok(())
    })
}

/// What is in effect after overrides: name, source (`embedded` or the directory).
#[no_mangle]
pub unsafe extern "C" fn mosura_ctx_data_list(ctx: *mut mosura_ctx, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let c = ctx_of(ctx)?;
        let out = out_ptr(out, "out")?;
        *out = crate::table::new_table(mosura_api::ops::data_list(c));
        Ok(())
    })
}
