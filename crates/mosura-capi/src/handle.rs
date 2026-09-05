//! Handles: a heap cell `Handle<T> { hdr, val }` behind an opaque pointer. The header carries a
//! magic, the kind, a poison flag and the typed drop; a global set of live handle addresses lets a
//! released or foreign pointer be refused BEFORE its memory is touched. Handles are not
//! thread-safe (the C contract: one caller at a time per handle); the live-set is.

use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::Mutex;

use mosura_api::{Error, Result};

const MAGIC: u32 = 0x4d4f_5355; // "MOSU"

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Ctx = 1,
    Options,
    Table,
    Session,
    Language,
    Program,
    Function,
    Toolchain,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Ctx => "mosura_ctx",
            Kind::Options => "mosura_options",
            Kind::Table => "mosura_table",
            Kind::Session => "mosura_session",
            Kind::Language => "mosura_language",
            Kind::Program => "mosura_program",
            Kind::Function => "mosura_function",
            Kind::Toolchain => "mosura_toolchain",
        }
    }
}

#[repr(C)]
pub struct Header {
    magic: u32,
    kind: u32,
    poisoned: bool,
    drop: unsafe fn(*mut c_void),
}

#[repr(C)]
pub struct Handle<T> {
    hdr: Header,
    pub val: T,
}

static LIVE: Mutex<Option<HashSet<usize>>> = Mutex::new(None);

fn with_live<R>(f: impl FnOnce(&mut HashSet<usize>) -> R) -> R {
    let mut g = LIVE.lock().unwrap_or_else(|p| p.into_inner());
    f(g.get_or_insert_with(HashSet::new))
}

unsafe fn drop_handle<T>(p: *mut c_void) {
    drop(Box::from_raw(p as *mut Handle<T>));
}

/// Allocate a handle; the returned pointer is the C handle (cast to the opaque type).
pub fn new<T>(kind: Kind, val: T) -> *mut c_void {
    let b = Box::new(Handle { hdr: Header { magic: MAGIC, kind: kind as u32, poisoned: false, drop: drop_handle::<T> }, val });
    let p = Box::into_raw(b) as *mut c_void;
    with_live(|s| s.insert(p as usize));
    p
}

/// Check a pointer: non-NULL, live, our magic, the expected kind.
unsafe fn check<'a, T>(p: *const c_void, kind: Kind) -> Result<&'a mut Handle<T>> {
    if p.is_null() {
        return Err(Error::InvalidArg(format!("NULL {} handle", kind.name())));
    }
    if !with_live(|s| s.contains(&(p as usize))) {
        return Err(Error::InvalidArg(format!("{:p} is not a live mosura handle (released, or never one)", p)));
    }
    let h = &mut *(p as *mut Handle<T>);
    if h.hdr.magic != MAGIC {
        return Err(Error::InvalidArg(format!("{:p} is not a mosura handle", p)));
    }
    if h.hdr.kind != kind as u32 {
        let actual = [Kind::Ctx, Kind::Options, Kind::Table, Kind::Session, Kind::Language, Kind::Program, Kind::Function, Kind::Toolchain].iter().find(|k| **k as u32 == h.hdr.kind).map(|k| k.name()).unwrap_or("?");
        return Err(Error::InvalidArg(format!("handle is a {actual}, not a {}", kind.name())));
    }
    Ok(h)
}

/// Shared access to a handle's value.
pub unsafe fn as_ref<'a, T>(p: *const c_void, kind: Kind) -> Result<&'a T> {
    let h = check::<T>(p, kind)?;
    if h.hdr.poisoned {
        return Err(Error::Internal(format!("{} handle poisoned by an earlier panic", kind.name())));
    }
    Ok(&h.val)
}

/// Exclusive access; the handle is poisoned while the operation runs and unpoisoned when the
/// guard drops normally — a panic (unwinding through the guard) leaves it poisoned.
pub struct MutGuard<'a, T> {
    h: &'a mut Handle<T>,
}

impl<T> std::ops::Deref for MutGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.h.val
    }
}
impl<T> std::ops::DerefMut for MutGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.h.val
    }
}
impl<T> Drop for MutGuard<'_, T> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            self.h.hdr.poisoned = false;
        }
    }
}

pub unsafe fn as_mut<'a, T>(p: *mut c_void, kind: Kind) -> Result<MutGuard<'a, T>> {
    let h = check::<T>(p, kind)?;
    if h.hdr.poisoned {
        return Err(Error::Internal(format!("{} handle poisoned by an earlier panic", kind.name())));
    }
    h.hdr.poisoned = true;
    Ok(MutGuard { h })
}

/// Free a handle of any kind (its typed drop is in the header); a non-live pointer is refused.
pub unsafe fn release(p: *mut c_void) -> Result<()> {
    if !with_live(|s| s.remove(&(p as usize))) {
        return Err(Error::InvalidArg(format!("{:p} is not a live mosura handle (double release?)", p)));
    }
    let hdr = &*(p as *const Header);
    if hdr.magic != MAGIC {
        return Err(Error::InvalidArg(format!("{:p} is not a mosura handle", p)));
    }
    (hdr.drop)(p);
    Ok(())
}

/// How many handles are live (tests).
pub fn live_count() -> usize {
    with_live(|s| s.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Payload(Vec<u8>, std::sync::Arc<()>);

    #[test]
    fn handles_are_checked_before_their_memory_is_touched() {
        let marker = std::sync::Arc::new(());
        let p = new(Kind::Table, Payload(vec![1, 2, 3], marker.clone()));
        assert_eq!(std::sync::Arc::strong_count(&marker), 2);
        unsafe {
            assert_eq!(as_ref::<Payload>(p, Kind::Table).unwrap().0, vec![1, 2, 3]);
            assert!(matches!(as_ref::<Payload>(p, Kind::Ctx), Err(Error::InvalidArg(m)) if m.contains("is a mosura_table, not a mosura_ctx")));
            assert!(matches!(as_ref::<Payload>(std::ptr::null(), Kind::Table), Err(Error::InvalidArg(m)) if m.contains("NULL")));
            let stack = 7u64;
            let foreign = &stack as *const u64 as *const c_void;
            assert!(matches!(as_ref::<Payload>(foreign, Kind::Table), Err(Error::InvalidArg(m)) if m.contains("not a live mosura handle")));
            {
                let mut g = as_mut::<Payload>(p, Kind::Table).unwrap();
                g.0.push(4);
            }
            assert_eq!(as_ref::<Payload>(p, Kind::Table).unwrap().0.len(), 4);
            release(p).unwrap();
        }
        assert_eq!(std::sync::Arc::strong_count(&marker), 1, "the payload was dropped");
        unsafe {
            assert!(matches!(release(p), Err(Error::InvalidArg(m)) if m.contains("double release")));
            assert!(as_ref::<Payload>(p, Kind::Table).is_err(), "a released handle is refused before its memory is read");
        }
    }

    #[test]
    fn a_panic_inside_a_mutable_operation_poisons_the_handle() {
        let p = new(Kind::Session, Payload(vec![], std::sync::Arc::new(())));
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            let _g = as_mut::<Payload>(p, Kind::Session).unwrap();
            panic!("mid-operation");
        }));
        std::panic::set_hook(prev);
        assert!(r.is_err());
        unsafe {
            assert!(matches!(as_ref::<Payload>(p, Kind::Session), Err(Error::Internal(m)) if m.contains("poisoned")));
            assert!(matches!(as_mut::<Payload>(p, Kind::Session), Err(Error::Internal(_))));
            release(p).unwrap(); // a poisoned handle can still be released
        }
    }
}
