//! §11 Recompile — toolchains, verification, rounds.

use std::ffi::{c_char, c_void};

use crate::boundary::guard;
use crate::ctx::{ctx_of, mosura_ctx, mosura_progress_fn};
use crate::function::{function_params_of, mosura_function};
use crate::handle::{self, Kind};
use crate::mem::{cstr, cstr_opt, out_ptr, view_bytes, mosura_view};
use crate::options::{mosura_options, options_of, options_or_default};
use crate::program::{mosura_program, program_of};
use crate::session::{mosura_session, session_of, SessionCell};
use crate::status::mosura_status;
use crate::table::{mosura_table, new_table, table_of};
use crate::ops::call_on;
use mosura_api::{Options, Result};

/// A compiler mosura can drive, open in a session (opaque).
pub struct mosura_toolchain {
    _private: [u8; 0],
}

pub(crate) struct ToolchainCell {
    shared: SessionCell,
    name: String,
}

unsafe fn toolchain_of<'a>(p: *const mosura_toolchain) -> Result<&'a ToolchainCell> {
    handle::as_ref::<ToolchainCell>(p as *const c_void, Kind::Toolchain)
}

/// The compiler specs known to the library: name, host (dos|native), doc.
#[no_mangle]
pub unsafe extern "C" fn mosura_toolchain_specs(ctx: *mut mosura_ctx, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let _ = ctx_of(ctx)?;
        let out = out_ptr(out, "out")?;
        *out = new_table(mosura_api::ops::toolchain::specs_table());
        Ok(())
    })
}

/// Open a toolchain in this session under `name`. `opts`: toolchain.spec (one of the specs),
/// toolchain.install (this machine's location), compile.cache (default <session>/compile). The
/// driver runs nothing here; a session without a directory refuses (UNSUPPORTED).
#[no_mangle]
pub unsafe extern "C" fn mosura_toolchain_open(s: *mut mosura_session, name: *const c_char, opts: *const mosura_options, out: *mut *mut mosura_toolchain) -> mosura_status {
    guard(|| {
        let cell = session_of(s)?.clone();
        let name = cstr(name, "name")?;
        let mut o = options_or_default(opts)?;
        o.set("toolchain", name)?;
        let out = out_ptr(out, "out")?;
        call_on(&cell, "toolchain.open", Some(&o), None, std::ptr::null_mut())?;
        *out = handle::new(Kind::Toolchain, ToolchainCell { shared: cell, name: name.to_string() }) as *mut mosura_toolchain;
        Ok(())
    })
}

/// Compile a batch: `units` is a table with columns key, source, flags (space-separated).
/// outputs: key, ok, adjudicated, object (bytes), log.
#[no_mangle]
pub unsafe extern "C" fn mosura_toolchain_compile(tc: *mut mosura_toolchain, units: *const mosura_table, outputs: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let tc = toolchain_of(tc)?;
        let units = table_of(units)?;
        let out = out_ptr(outputs, "outputs")?;
        let session = tc.shared.session.lock().unwrap_or_else(|p| p.into_inner());
        *out = new_table(mosura_api::ops::toolchain::compile_table(&session, &tc.name, units)?);
        Ok(())
    })
}

/// The explicit liveness probe: one tiny unit through the compiler (name, ok, adjudicated, log).
#[no_mangle]
pub unsafe extern "C" fn mosura_toolchain_check(tc: *mut mosura_toolchain, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let tc = toolchain_of(tc)?;
        let out = out_ptr(out, "out")?;
        let mut o = Options::new();
        o.set("toolchain", &tc.name)?;
        *out = new_table(call_on(&tc.shared, "toolchain.check", Some(&o), None, std::ptr::null_mut())?);
        Ok(())
    })
}

/// The build flags of a function recovered from the original's own bytes (rows fact/flag).
#[no_mangle]
pub unsafe extern "C" fn mosura_function_buildconfig(f: *mut mosura_function, opts: *const mosura_options, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let out = out_ptr(out, "out")?;
        let (shared, params) = function_params_of(f, "function.buildconfig", if opts.is_null() { None } else { Some(options_of(opts)?) })?;
        *out = new_table(call_on(&shared, "function.buildconfig", Some(&params), None, std::ptr::null_mut())?);
        Ok(())
    })
}

/// Verify a compiled object against the original: one `verdicts` row (`opts` may set
/// verify.table-window; format=table:divergences for the aligned differences). The object bytes
/// are added to the session as an input.
#[no_mangle]
pub unsafe extern "C" fn mosura_function_verify(f: *mut mosura_function, object: mosura_view, opts: *const mosura_options, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let out = out_ptr(out, "out")?;
        let object = view_bytes(object, "object")?;
        let mut extra = if opts.is_null() { Options::new() } else { options_of(opts)?.clone() };
        let (shared, _) = function_params_of(f, "function.verify", None)?;
        let digest = {
            let mut session = shared.session.lock().unwrap_or_else(|p| p.into_inner());
            session.add_input(object, "object", Some(&format!("object-{}", &mosura_api::fingerprint::hex(&mosura_api::key::digest(object))[..12])))?
        };
        extra.set("object", &mosura_api::fingerprint::hex(&digest))?;
        let (shared, params) = function_params_of(f, "function.verify", Some(&extra))?;
        *out = new_table(call_on(&shared, "function.verify", Some(&params), None, std::ptr::null_mut())?);
        Ok(())
    })
}

/// One function end to end through `tc`: emit → compile → verify (one verdict row;
/// format=table:divergences | table:diff).
#[no_mangle]
pub unsafe extern "C" fn mosura_function_recompile(f: *mut mosura_function, tc: *mut mosura_toolchain, opts: *const mosura_options, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let out = out_ptr(out, "out")?;
        let tc = toolchain_of(tc)?;
        let mut extra = if opts.is_null() { Options::new() } else { options_of(opts)?.clone() };
        extra.set("toolchain", &tc.name)?;
        let (shared, params) = function_params_of(f, "function.recompile", Some(&extra))?;
        *out = new_table(call_on(&shared, "function.recompile", Some(&params), None, std::ptr::null_mut())?);
        Ok(())
    })
}

/// A round: every in-scope function of `p` through the recompile pipeline with `tc`, stored under
/// rounds/<name>. `opts`: round.scope, round.scope-file, round.baseline, round.expect,
/// round.exclude-foreign, gates.baseline, label, verify.table-window, the decompile/emit keys.
/// `summary` = the round's manifest.
#[no_mangle]
pub unsafe extern "C" fn mosura_round_run(s: *mut mosura_session, name: *const c_char, p: *mut mosura_program, tc: *mut mosura_toolchain, opts: *const mosura_options, progress: mosura_progress_fn, progress_user: *mut c_void, summary: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let cell = session_of(s)?.clone();
        let name = cstr(name, "name")?;
        let prog = program_of(p)?;
        let tc = toolchain_of(tc)?;
        let out = out_ptr(summary, "summary")?;
        let mut o = crate::program::program_params(prog, "round.run", if opts.is_null() { None } else { Some(options_of(opts)?) })?;
        o.set("round", name)?;
        o.set("toolchain", &tc.name)?;
        *out = new_table(call_on(&cell, "round.run", Some(&o), progress, progress_user)?);
        Ok(())
    })
}

/// rounds: name, program, toolchain, build, created, rows, exact, wgss.
#[no_mangle]
pub unsafe extern "C" fn mosura_rounds(s: *mut mosura_session, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let cell = session_of(s)?;
        let out = out_ptr(out, "out")?;
        *out = new_table(call_on(cell, "round.list", None, None, std::ptr::null_mut())?);
        Ok(())
    })
}

/// Compare two rounds by address: census, flips, movers, the weighted delta, membership drift.
#[no_mangle]
pub unsafe extern "C" fn mosura_round_compare(s: *mut mosura_session, a: *const c_char, b: *const c_char, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let cell = session_of(s)?;
        let (a, b) = (cstr(a, "a")?, cstr(b, "b")?);
        let out = out_ptr(out, "out")?;
        let mut o = Options::new();
        o.set("a", a)?;
        o.set("b", b)?;
        *out = new_table(call_on(cell, "round.compare", Some(&o), None, std::ptr::null_mut())?);
        Ok(())
    })
}

/// The verdict gates of a stored round against `baseline` (NULL = none): gate, outcome, detail.
/// `opts` (NULL = none) may carry gates.baseline and round.expect.
#[no_mangle]
pub unsafe extern "C" fn mosura_round_gates(s: *mut mosura_session, round: *const c_char, baseline: *const c_char, opts: *const mosura_options, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let cell = session_of(s)?;
        let round = cstr(round, "round")?;
        let out = out_ptr(out, "out")?;
        let mut o = options_or_default(opts)?;
        o.set("round", round)?;
        if let Some(b) = cstr_opt(baseline, "baseline")? {
            o.set("round.baseline", b)?;
        }
        *out = new_table(call_on(cell, "round.gates", Some(&o), None, std::ptr::null_mut())?);
        Ok(())
    })
}

/// A stored round's table: manifest (NULL or ""), verdicts, divergences, gates.
#[no_mangle]
pub unsafe extern "C" fn mosura_round_table(s: *mut mosura_session, round: *const c_char, table: *const c_char, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let cell = session_of(s)?;
        let round = cstr(round, "round")?;
        let out = out_ptr(out, "out")?;
        let mut o = Options::new();
        o.set("round", round)?;
        if let Some(t) = cstr_opt(table, "table")? {
            o.set("table", t)?;
        }
        *out = new_table(call_on(cell, "round.show", Some(&o), None, std::ptr::null_mut())?);
        Ok(())
    })
}

