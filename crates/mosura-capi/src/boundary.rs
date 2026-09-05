//! The panic boundary: every `extern "C"` body runs inside `guard`, which turns an `Err` into its
//! status + message and a panic into `MOSURA_ERR_INTERNAL` + the panic text — unless the context
//! asked to abort on panic (a development aid: the process dies with its backtrace).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::status::{self, mosura_status};
use mosura_api::Result;

/// Set by `mosura_ctx_new` from `mosura_ctx_config.abort_on_panic` (process-wide, like the panic
/// hook it is about).
pub static ABORT_ON_PANIC: AtomicBool = AtomicBool::new(false);

fn finish(r: Result<()>) -> mosura_status {
    match r {
        Ok(()) => {
            status::clear();
            mosura_status::MOSURA_OK
        }
        Err(e) => {
            let s = mosura_status::from(&e);
            status::set(s, &e.to_string());
            s
        }
    }
}

/// The text of a panic payload.
pub fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload.downcast_ref::<String>().cloned().or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_else(|| "panic".to_string())
}

/// Run a boundary body.
pub fn guard(f: impl FnOnce() -> Result<()>) -> mosura_status {
    if ABORT_ON_PANIC.load(Ordering::Relaxed) {
        return finish(f());
    }
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => finish(r),
        Err(payload) => {
            let msg = panic_text(&*payload);
            status::set(mosura_status::MOSURA_ERR_INTERNAL, &msg);
            mosura_status::MOSURA_ERR_INTERNAL
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mosura_api::Error;

    #[test]
    fn ok_clears_err_records_panic_is_internal_with_its_text() {
        assert_eq!(guard(|| Err(Error::NotFound("thing".into()))), mosura_status::MOSURA_ERR_NOT_FOUND);
        assert!(unsafe { std::ffi::CStr::from_ptr(status::mosura_last_error()) }.to_str().unwrap().contains("thing"));
        assert_eq!(guard(|| Ok(())), mosura_status::MOSURA_OK);
        assert_eq!(unsafe { std::ffi::CStr::from_ptr(status::mosura_last_error()) }.to_bytes(), b"");
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // keep the test output clean
        let s = guard(|| -> Result<()> { panic!("boom {}", 42) });
        std::panic::set_hook(prev);
        assert_eq!(s, mosura_status::MOSURA_ERR_INTERNAL);
        assert_eq!(unsafe { std::ffi::CStr::from_ptr(status::mosura_last_error()) }.to_str().unwrap(), "boom 42");
    }
}
