//! §8 Languages and the SLEIGH engine over raw bytes.

use std::ffi::{c_char, c_void};

use crate::boundary::guard;
use crate::ctx::{ctx_of, mosura_ctx};
use crate::handle::{self, Kind};
use crate::mem::{cstr, out_ptr, view_bytes, mosura_view};
use crate::ops::call_on;
use crate::options::{mosura_options, options_of};
use crate::session::SessionCell;
use crate::status::mosura_status;
use crate::table::{mosura_table, new_table};
use mosura_api::{Error, Options, Result, Session};

/// A SLEIGH language: tables + default context (opaque).
#[repr(C)]
pub struct mosura_language {
    _private: [u8; 0],
}

pub(crate) struct LanguageCell {
    id: String,
    /// The sleigh operations are transient; they run on a private in-memory session.
    shared: SessionCell,
}

unsafe fn language_of<'a>(p: *const mosura_language) -> Result<&'a LanguageCell> {
    handle::as_ref::<LanguageCell>(p as *const c_void, Kind::Language)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// languages: id, processor, endian, size, variant, version, description, cspecs (comma list).
#[no_mangle]
pub unsafe extern "C" fn mosura_languages(ctx: *mut mosura_ctx, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let _ = ctx_of(ctx)?;
        let out = out_ptr(out, "out")?;
        *out = new_table(mosura_api::ops::language::languages_table());
        Ok(())
    })
}

/// Load a language by Ghidra id ("x86:LE:32:default"); MOSURA_ERR_NOT_FOUND when its tables
/// are not available.
#[no_mangle]
pub unsafe extern "C" fn mosura_language_open(ctx: *mut mosura_ctx, language_id: *const c_char, out: *mut *mut mosura_language) -> mosura_status {
    guard(|| {
        let c = ctx_of(ctx)?;
        let id = cstr(language_id, "language_id")?;
        let out = out_ptr(out, "out")?;
        if mosura_core::lang::load_cached(id).is_none() {
            return Err(Error::NotFound(format!("language `{id}` (no tables)")));
        }
        let shared = SessionCell { ctx: std::sync::Arc::clone(c), session: std::sync::Arc::new(std::sync::Mutex::new(Session::open(None)?)) };
        *out = handle::new(Kind::Language, LanguageCell { id: id.to_string(), shared }) as *mut mosura_language;
        Ok(())
    })
}

/// registers: name, space, offset, size.
#[no_mangle]
pub unsafe extern "C" fn mosura_language_registers(l: *mut mosura_language, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let l = language_of(l)?;
        let out = out_ptr(out, "out")?;
        *out = new_table(mosura_api::ops::language::registers_table(&l.id)?);
        Ok(())
    })
}

unsafe fn sleigh_params(l: &LanguageCell, bytes: mosura_view, base: u64, ctx_regs: *const mosura_options) -> Result<Options> {
    let data = view_bytes(bytes, "bytes")?;
    let mut o = Options::new();
    o.set("lang", &l.id)?;
    o.set("bytes", &hex(data))?;
    o.set("base", &format!("{base:#x}"))?;
    if !ctx_regs.is_null() {
        let regs = options_of(ctx_regs)?;
        if regs.is_set("ctx") {
            o.set("ctx", regs.get("ctx")?)?;
        }
    }
    Ok(o)
}

/// Disassemble raw bytes. `ctx_regs` (NULL = the `.pspec` defaults) is an option set whose `ctx`
/// key holds the context register settings ("addrsize=1;opsize=1").
/// instructions: addr, len, bytes, mnemonic, operands, flow columns (empty for a raw decode).
#[no_mangle]
pub unsafe extern "C" fn mosura_disassemble(l: *mut mosura_language, bytes: mosura_view, base: u64, ctx_regs: *const mosura_options, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let l = language_of(l)?;
        let out = out_ptr(out, "out")?;
        let params = sleigh_params(l, bytes, base, ctx_regs)?;
        *out = new_table(call_on(&l.shared, "sleigh.disassemble", Some(&params), None, std::ptr::null_mut())?);
        Ok(())
    })
}

/// Lift raw bytes to raw p-code. pcode: addr, seq, opcode, mnemonic, output (space, offset,
/// size), inputs (spaces, offsets, sizes), text (the golden form).
#[no_mangle]
pub unsafe extern "C" fn mosura_lift(l: *mut mosura_language, bytes: mosura_view, base: u64, ctx_regs: *const mosura_options, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let l = language_of(l)?;
        let out = out_ptr(out, "out")?;
        let params = sleigh_params(l, bytes, base, ctx_regs)?;
        *out = new_table(call_on(&l.shared, "sleigh.lift", Some(&params), None, std::ptr::null_mut())?);
        Ok(())
    })
}

/// Execute the p-code of a byte range with an initial state. Not in this version
/// (MOSURA_ERR_UNSUPPORTED).
#[no_mangle]
pub unsafe extern "C" fn mosura_emulate(l: *mut mosura_language, _bytes: mosura_view, _base: u64, _initial_state: *const mosura_options, _out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let _ = language_of(l)?;
        Err(Error::Unsupported("mosura_emulate is not in this version".into()))
    })
}

/// FID fingerprints for a byte range. Not in this version (MOSURA_ERR_UNSUPPORTED).
#[no_mangle]
pub unsafe extern "C" fn mosura_fingerprint(l: *mut mosura_language, _bytes: mosura_view, _base: u64, _out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let _ = language_of(l)?;
        Err(Error::Unsupported("mosura_fingerprint is not in this version".into()))
    })
}
