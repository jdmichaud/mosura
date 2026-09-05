//! The library context.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::path::{Path, PathBuf};

use crate::error::{check, Result};
use crate::handle::{view_of, Raw};
use crate::language::Language;
use crate::options::Options;
use crate::table::Table;
use mosura_capi::{mosura_ctx, mosura_ctx_config, mosura_log_level, mosura_table};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
}

pub type LogFn = Box<dyn Fn(Level, &str, &str) + Send + Sync>;

/// What `Ctx::new` takes; `Default` is the embedded data, no log sink, panics caught.
#[derive(Default)]
pub struct CtxConfig {
    /// Override directories for spec data, searched before the embedded set.
    pub spec_dirs: Vec<PathBuf>,
    /// Override directories for FID databases.
    pub fid_dirs: Vec<PathBuf>,
    /// Accepted; unused in this version.
    pub cache_dir: Option<PathBuf>,
    /// The diagnostic sink (level, topic, message).
    pub log: Option<LogFn>,
    /// Development aid: let an internal panic propagate instead of `Status::MOSURA_ERR_INTERNAL`.
    pub abort_on_panic: bool,
}

unsafe extern "C" fn log_trampoline(user: *mut c_void, level: mosura_log_level, topic: *const c_char, msg: *const c_char, _msg_len: usize) {
    // a callback must not unwind into the library
    let _ = std::panic::catch_unwind(|| {
        let f = &*(user as *const LogFn);
        let lvl = match level {
            mosura_log_level::MOSURA_LOG_ERROR => Level::Error,
            mosura_log_level::MOSURA_LOG_WARN => Level::Warn,
            mosura_log_level::MOSURA_LOG_INFO => Level::Info,
            mosura_log_level::MOSURA_LOG_DEBUG => Level::Debug,
        };
        let topic = if topic.is_null() { "" } else { CStr::from_ptr(topic).to_str().unwrap_or("") };
        let msg = if msg.is_null() { "" } else { CStr::from_ptr(msg).to_str().unwrap_or("") };
        f(lvl, topic, msg);
    });
}

/// The library: spec registry, caches, log sink. Thread-safe once created.
pub struct Ctx {
    raw: Raw<mosura_ctx>,
    /// The sink the context calls; boxed so its address is stable for the library's lifetime.
    _log: Option<Box<LogFn>>,
}

unsafe impl Send for Ctx {}
unsafe impl Sync for Ctx {}

fn c_strings(paths: &[PathBuf]) -> Vec<CString> {
    paths.iter().map(|p| CString::new(p.to_string_lossy().into_owned()).unwrap_or_default()).collect()
}

impl Ctx {
    pub fn new(cfg: CtxConfig) -> Result<Ctx> {
        let spec = c_strings(&cfg.spec_dirs);
        let fid = c_strings(&cfg.fid_dirs);
        let spec_ptrs: Vec<*const c_char> = spec.iter().map(|s| s.as_ptr()).collect();
        let fid_ptrs: Vec<*const c_char> = fid.iter().map(|s| s.as_ptr()).collect();
        let cache = cfg.cache_dir.as_ref().map(|p| CString::new(p.to_string_lossy().into_owned()).unwrap_or_default());
        let log: Option<Box<LogFn>> = cfg.log.map(Box::new);
        let c = mosura_ctx_config {
            size: std::mem::size_of::<mosura_ctx_config>() as u32,
            version: 1,
            spec_dirs: if spec_ptrs.is_empty() { std::ptr::null() } else { spec_ptrs.as_ptr() },
            spec_dirs_len: spec_ptrs.len(),
            fid_dirs: if fid_ptrs.is_empty() { std::ptr::null() } else { fid_ptrs.as_ptr() },
            fid_dirs_len: fid_ptrs.len(),
            cache_dir: cache.as_ref().map(|c| c.as_ptr()).unwrap_or(std::ptr::null()),
            log: log.as_ref().map(|_| log_trampoline as unsafe extern "C" fn(*mut c_void, mosura_log_level, *const c_char, *const c_char, usize)),
            log_user: log.as_ref().map(|b| &**b as *const LogFn as *mut c_void).unwrap_or(std::ptr::null_mut()),
            abort_on_panic: cfg.abort_on_panic as c_int,
        };
        let mut out: *mut mosura_ctx = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_ctx_new(&c, &mut out) })?;
        Ok(Ctx { raw: Raw::new(out), _log: log })
    }

    pub(crate) fn ptr(&self) -> *mut mosura_ctx {
        self.raw.ptr()
    }

    /// Write the embedded data into `dir` (`what` = "specs" | "fid" | "all"); the files written.
    pub fn export_data(&self, dir: &Path, what: &str, overwrite: bool) -> Result<Table> {
        let dir = CString::new(dir.to_string_lossy().into_owned()).unwrap_or_default();
        let what = CString::new(what).unwrap_or_default();
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_ctx_export_data(self.ptr(), dir.as_ptr(), what.as_ptr(), overwrite as c_int, &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// Every resource in effect and where it comes from.
    pub fn data_list(&self) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_ctx_data_list(self.ptr(), &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// An empty option set.
    pub fn options(&self) -> Result<Options> {
        Options::new(self)
    }

    /// The option registry as a table.
    pub fn options_registry(&self) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_options_registry(self.ptr(), &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// The operation registry as a table.
    pub fn ops(&self, include_dev: bool) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_ops(self.ptr(), include_dev as c_int, &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// The schema of a table type.
    pub fn schema(&self, name: &str) -> Result<Table> {
        let name = CString::new(name).unwrap_or_default();
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_schema(self.ptr(), name.as_ptr(), &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// Everything the loaders can say about `bytes` without analysis (key, value, evidence).
    pub fn identify(&self, bytes: &[u8]) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_identify(self.ptr(), view_of(bytes), &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// The `.ldefs` catalogue.
    pub fn languages(&self) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_languages(self.ptr(), &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// A language by Ghidra id.
    pub fn language(&self, id: &str) -> Result<Language> {
        Language::open(self, id)
    }

    /// The emit axes (name, values, default, doc).
    pub fn emit_axes(&self) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_emit_axes(self.ptr(), &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// The compiler specs the library knows (name, host, doc).
    pub fn toolchain_specs(&self) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_toolchain_specs(self.ptr(), &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// The emit arms (the names `emit.arms-off` accepts).
    pub fn emit_arms(&self) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_emit_arms(self.ptr(), &mut out) })?;
        Ok(Table::from_raw(out))
    }
}

impl std::fmt::Debug for Ctx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ctx({})", crate::version())
    }
}
