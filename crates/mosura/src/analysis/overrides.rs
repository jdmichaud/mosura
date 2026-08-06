//! Per-thread analysis overrides — the measurement switches, without the process-global race.
//!
//! Two knobs exist so that a run can be *measured*: `MOSURA_DISABLE_ANALYZERS` (run with one
//! analyzer off, which is how any contribution is attributed — Ghidra's own model, a
//! `-preScript` flipping `Program.ANALYSIS_PROPERTIES`) and `MOSURA_X86_32_CSPEC` (route an
//! x86-32 binary through a chosen compiler spec, because no ground-truth binary carries a Watcom
//! run-time banner and the `watcom` pattern file is otherwise unreachable).
//!
//! # Why they are not read from `std::env` at the point of use
//!
//! They were, and it made the test suite **fail under default parallelism while passing in
//! isolation and under `--test-threads=1`**. `cargo test` runs a binary's tests on parallel
//! threads in one process; `std::env::set_var` mutates state shared by all of them. So a test
//! that set a switch for its own analysis had that switch leak into whatever another test was
//! analysing at the same moment — two tests failed for exactly that reason, and neither was
//! failing for the thing it tested. An "is it inert when unset?" check cannot catch this: the
//! hazard is not the unset case, it is *concurrent mutation*, and no amount of restoring the
//! previous value afterwards helps when the race is inside the window.
//!
//! An analysis runs entirely on its caller's thread (the same property
//! `analyzers::function_start`'s per-run memos rely on), so a **thread-local** override is
//! private to the analysis that set it. No lock, no serialization, and no shared mutable state
//! for a future test to trip over.
//!
//! The environment variables still work, as the fallback, so setting one in a shell to measure a
//! single run behaves exactly as before. Only the in-process path changed.

use std::cell::RefCell;

thread_local! {
    /// Overrides `MOSURA_DISABLE_ANALYZERS` for this thread.
    static DISABLE_ANALYZERS: RefCell<Option<String>> = const { RefCell::new(None) };
    /// Overrides `MOSURA_X86_32_CSPEC` for this thread.
    static X86_32_CSPEC: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// The disabled-analyzer list in effect: this thread's override, else the environment.
pub fn disabled_analyzers() -> Option<String> {
    DISABLE_ANALYZERS
        .with(|c| c.borrow().clone())
        .or_else(|| std::env::var("MOSURA_DISABLE_ANALYZERS").ok())
}

/// The forced x86-32 compiler spec in effect: this thread's override, else the environment.
pub fn x86_32_cspec() -> Option<String> {
    X86_32_CSPEC.with(|c| c.borrow().clone()).or_else(|| std::env::var("MOSURA_X86_32_CSPEC").ok())
}

/// Restores the previous value of an override when dropped, so a panicking test cannot leave one
/// set for the next analysis on this thread.
#[must_use = "the override is reverted as soon as this guard is dropped"]
pub struct OverrideGuard {
    key: &'static std::thread::LocalKey<RefCell<Option<String>>>,
    previous: Option<String>,
}

impl Drop for OverrideGuard {
    fn drop(&mut self) {
        let prev = self.previous.take();
        self.key.with(|c| *c.borrow_mut() = prev);
    }
}

fn set(
    key: &'static std::thread::LocalKey<RefCell<Option<String>>>,
    value: Option<&str>,
) -> OverrideGuard {
    let previous = key.with(|c| c.replace(value.map(str::to_string)));
    OverrideGuard { key, previous }
}

/// Disable the named analyzers for analyses on *this thread* until the guard drops.
pub fn disable_analyzers(list: &str) -> OverrideGuard {
    set(&DISABLE_ANALYZERS, Some(list))
}

/// Force the x86-32 compiler spec for analyses on *this thread* until the guard drops.
/// `None` restores detection.
pub fn force_x86_32_cspec(cspec: Option<&str>) -> OverrideGuard {
    set(&X86_32_CSPEC, cspec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_is_scoped_and_restores() {
        assert!(x86_32_cspec().is_none() || std::env::var("MOSURA_X86_32_CSPEC").is_ok());
        {
            let _g = force_x86_32_cspec(Some("watcom"));
            assert_eq!(x86_32_cspec().as_deref(), Some("watcom"));
            {
                let _inner = force_x86_32_cspec(Some("gcc"));
                assert_eq!(x86_32_cspec().as_deref(), Some("gcc"));
            }
            assert_eq!(x86_32_cspec().as_deref(), Some("watcom"), "inner guard must restore");
        }
        assert!(
            X86_32_CSPEC.with(|c| c.borrow().is_none()),
            "the outer guard must clear the override"
        );
    }

    /// The property the whole module exists for: one thread's override is invisible to another.
    #[test]
    fn override_does_not_leak_across_threads() {
        let _g = force_x86_32_cspec(Some("watcom"));
        let seen = std::thread::spawn(|| X86_32_CSPEC.with(|c| c.borrow().clone())).join().unwrap();
        assert_eq!(seen, None, "an override must not be visible on another thread");
    }
}
