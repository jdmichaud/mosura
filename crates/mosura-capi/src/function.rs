//! §10 Decompile and emit — one function. A function handle is (program key, entry, options); the
//! decompile set is made when the handle is, and every accessor is served from the store.

use std::ffi::{c_char, c_void};

use crate::boundary::guard;
use crate::ctx::{ctx_of, mosura_ctx};
use crate::handle::{self, Kind};
use crate::mem::{bytes, cstr, out_ptr, mosura_bytes};
use crate::ops::{call_on, keys_for, text_of};
use crate::options::{mosura_options, options_of, options_or_default};
use crate::program::{mosura_program, program_of};
use crate::session::SessionCell;
use crate::status::mosura_status;
use crate::table::{mosura_format, mosura_table, new_table};
use mosura_api::key::Key;
use mosura_api::{Error, Options, Result};

/// One decompiled function (opaque).
pub struct mosura_function {
    _private: [u8; 0],
}

pub(crate) struct FunctionCell {
    shared: SessionCell,
    program: Key,
    entry: u64,
    /// The decompile options (the program's carried keys + the handle's own).
    opts: Options,
}

unsafe fn function_of<'a>(p: *const mosura_function) -> Result<&'a FunctionCell> {
    handle::as_ref::<FunctionCell>(p as *const c_void, Kind::Function)
}

/// The parameters of an operation on this function: its options that `op` accepts, `extra`, then
/// program and entry.
fn function_params(cell: &FunctionCell, op: &str, extra: Option<&Options>) -> Result<Options> {
    let mut o = keys_for(op, &cell.opts);
    if let Some(x) = extra {
        for (k, v) in x.explicit() {
            o.set(k, v)?;
        }
    }
    o.set("program", &cell.program.hex())?;
    o.set("entry", &format!("{:#x}", cell.entry))?;
    Ok(o)
}

/// Decompile the function at `entry`. `opts` (NULL = none): decompile.global-scope,
/// decompile.proto-scope, knobs.off, and any emit.<axis> for the default rendering. The
/// decompile set is made now (or served); the handle then answers from it.
#[no_mangle]
pub unsafe extern "C" fn mosura_function_decompile(p: *mut mosura_program, entry: u64, opts: *const mosura_options, out: *mut *mut mosura_function) -> mosura_status {
    guard(|| {
        let prog = program_of(p)?;
        let extra = options_or_default(opts)?;
        let out = out_ptr(out, "out")?;
        let mut fopts = keys_for("function.decompile", &prog.base);
        for (k, v) in extra.explicit() {
            fopts.set(k, v)?;
        }
        let cell = FunctionCell { shared: prog.shared.clone(), program: prog.key, entry, opts: fopts };
        let params = function_params(&cell, "function.decompile", None)?;
        call_on(&cell.shared, "function.decompile", Some(&params), None, std::ptr::null_mut())?;
        *out = handle::new(Kind::Function, cell) as *mut mosura_function;
        Ok(())
    })
}

fn decompile_text(cell: &FunctionCell, format: &str, extra: Option<&Options>) -> Result<String> {
    let mut x = extra.cloned().unwrap_or_default();
    x.set("format", format)?;
    let params = function_params(cell, "function.decompile", Some(&x))?;
    text_of(&call_on(&cell.shared, "function.decompile", Some(&params), None, std::ptr::null_mut())?)
}

/// The C rendering under the handle's options (Ghidra's behaviour by default).
#[no_mangle]
pub unsafe extern "C" fn mosura_function_c(f: *mut mosura_function, out: *mut mosura_bytes) -> mosura_status {
    guard(|| {
        let cell = function_of(f)?;
        let out = out_ptr(out, "out")?;
        *out = bytes(decompile_text(cell, "c", None)?.into_bytes());
        Ok(())
    })
}

/// The C rendering under explicit emit choices (`emit.<axis>` keys) — the θ render.
#[no_mangle]
pub unsafe extern "C" fn mosura_function_render(f: *mut mosura_function, emit_choices: *const mosura_options, out: *mut mosura_bytes) -> mosura_status {
    guard(|| {
        let cell = function_of(f)?;
        let out = out_ptr(out, "out")?;
        let choices = if emit_choices.is_null() { Options::new() } else { keys_for("function.decompile", options_of(emit_choices)?) };
        *out = bytes(decompile_text(cell, "c", Some(&choices))?.into_bytes());
        Ok(())
    })
}

/// The IR: `stage` = "post" (after the pipeline; also "raw"), `format` TEXT = Ghidra `printRaw`
/// form. Other stages and formats are MOSURA_ERR_UNSUPPORTED in this version (no per-stage stop).
#[no_mangle]
pub unsafe extern "C" fn mosura_function_ir(f: *mut mosura_function, stage: *const c_char, format: mosura_format, out: *mut mosura_bytes) -> mosura_status {
    guard(|| {
        let cell = function_of(f)?;
        let stage = cstr(stage, "stage")?;
        let out = out_ptr(out, "out")?;
        if !matches!(stage, "post" | "raw") {
            return Err(Error::Unsupported(format!("IR stage `{stage}`: only `post` (the pipeline's output) exists in this version")));
        }
        if format != mosura_format::MOSURA_FMT_TEXT {
            return Err(Error::Unsupported("the IR is TEXT (printRaw) in this version".into()));
        }
        *out = bytes(decompile_text(cell, "raw", None)?.into_bytes());
        Ok(())
    })
}

/// A function table by name: "prototype", "jumptables", "calls" (the decompile set); "report"
/// (the emit set's manifest row and notes). Others: MOSURA_ERR_NOT_FOUND / UNSUPPORTED.
#[no_mangle]
pub unsafe extern "C" fn mosura_function_table(f: *mut mosura_function, name: *const c_char, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let cell = function_of(f)?;
        let name = cstr(name, "name")?;
        let out = out_ptr(out, "out")?;
        let mut x = Options::new();
        let (op, fmt) = match name {
            "prototype" | "jumptables" | "calls" => ("function.decompile", format!("table:{name}")),
            "report" => ("function.emit", "table:report".to_string()),
            "recovered" | "locals" | "globals" | "blocks" | "varnodes" | "ops" | "structure" | "trace" | "divergences" => return Err(Error::Unsupported(format!("function table `{name}` is not in this version"))),
            other => return Err(Error::NotFound(format!("function table `{other}`"))),
        };
        x.set("format", &fmt)?;
        let params = function_params(cell, op, Some(&x))?;
        *out = new_table(call_on(&cell.shared, op, Some(&params), None, std::ptr::null_mut())?);
        Ok(())
    })
}

/// The standalone translation unit for the Watcom x86-32 toolchain: declarations, pragmas and
/// the recovered body (`function.emit`). `opts` (NULL = none): emit.<axis>, emit.arms-off,
/// knobs.off, decompile.*. The program's passes set is made when absent.
#[no_mangle]
pub unsafe extern "C" fn mosura_function_tu(f: *mut mosura_function, opts: *const mosura_options, out: *mut mosura_bytes) -> mosura_status {
    guard(|| {
        let cell = function_of(f)?;
        let out = out_ptr(out, "out")?;
        let mut x = if opts.is_null() { Options::new() } else { keys_for("function.emit", options_of(opts)?) };
        x.set("format", "tu")?;
        let params = function_params(cell, "function.emit", Some(&x))?;
        *out = bytes(text_of(&call_on(&cell.shared, "function.emit", Some(&params), None, std::ptr::null_mut())?)?.into_bytes());
        Ok(())
    })
}

/// The witness pass as a separate step. In this version recovery is part of `mosura_function_tu`
/// (MOSURA_ERR_UNSUPPORTED here).
#[no_mangle]
pub unsafe extern "C" fn mosura_function_recover(f: *mut mosura_function, _opts: *const mosura_options, _out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let _ = function_of(f)?;
        Err(Error::Unsupported("the witness pass runs inside mosura_function_tu in this version".into()))
    })
}

/// The emit axes (`EmitChoices::axes`): name, values, default, doc.
#[no_mangle]
pub unsafe extern "C" fn mosura_emit_axes(ctx: *mut mosura_ctx, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let _ = ctx_of(ctx)?;
        let out = out_ptr(out, "out")?;
        *out = new_table(mosura_api::ops::language::emit_axes_table());
        Ok(())
    })
}

/// The emit arms (`Recovered::ARMS`): the names `emit.arms-off` accepts.
#[no_mangle]
pub unsafe extern "C" fn mosura_emit_arms(ctx: *mut mosura_ctx, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let _ = ctx_of(ctx)?;
        let out = out_ptr(out, "out")?;
        *out = new_table(mosura_api::ops::language::emit_arms_table());
        Ok(())
    })
}
