//! §6–§7 through the C functions: an in-memory session, inputs, `mosura_call` over the program
//! operations, session-config defaults, provenance, gc dry run, a cancelling progress callback.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;

use mosura_capi::mosura_status::*;
use mosura_capi::*;

fn last() -> String {
    unsafe { CStr::from_ptr(mosura_capi::status::mosura_last_error()) }.to_str().unwrap().to_string()
}

fn ctx() -> *mut mosura_ctx {
    let cfg = mosura_ctx_config { size: std::mem::size_of::<mosura_ctx_config>() as u32, version: 1, spec_dirs: ptr::null(), spec_dirs_len: 0, fid_dirs: ptr::null(), fid_dirs_len: 0, cache_dir: ptr::null(), log: None, log_user: ptr::null_mut(), abort_on_panic: 0 };
    let mut c: *mut mosura_ctx = ptr::null_mut();
    assert_eq!(unsafe { mosura_ctx_new(&cfg, &mut c) }, MOSURA_OK, "{}", last());
    c
}

fn corpus(name: &str) -> Vec<u8> {
    std::fs::read(mosura_core::paths::analysis_corpus_dir().join(name)).unwrap()
}

fn opts(c: *mut mosura_ctx, pairs: &[(&str, &str)]) -> *mut mosura_options {
    let mut o: *mut mosura_options = ptr::null_mut();
    assert_eq!(unsafe { mosura_options_new(c, &mut o) }, MOSURA_OK);
    for (k, v) in pairs {
        let (k, v) = (CString::new(*k).unwrap(), CString::new(*v).unwrap());
        assert_eq!(unsafe { mosura_options_set(o, k.as_ptr(), v.as_ptr()) }, MOSURA_OK, "{}", last());
    }
    o
}

fn cell_str(t: *const mosura_table, row: u64, col: u32) -> String {
    let mut v = mosura_view { ptr: ptr::null(), len: 0 };
    assert_eq!(unsafe { mosura_table_str(t, row, col, &mut v) }, MOSURA_OK, "{}", last());
    String::from_utf8(unsafe { std::slice::from_raw_parts(v.ptr, v.len) }.to_vec()).unwrap()
}

fn call(s: *mut mosura_session, op: &str, params: *const mosura_options) -> Result<*mut mosura_table, mosura_status> {
    let op = CString::new(op).unwrap();
    let mut t: *mut mosura_table = ptr::null_mut();
    match unsafe { mosura_call(s, op.as_ptr(), params, None, ptr::null_mut(), &mut t) } {
        MOSURA_OK => Ok(t),
        e => Err(e),
    }
}

unsafe extern "C" fn cancel(_user: *mut c_void, _stage: *const c_char, _done: u64, _total: u64) -> c_int {
    1
}

unsafe extern "C" fn count(user: *mut c_void, _stage: *const c_char, _done: u64, _total: u64) -> c_int {
    *(user as *mut u32) += 1;
    0
}

#[test]
fn a_session_runs_the_program_operations_through_call() {
    let c = ctx();
    let mut s: *mut mosura_session = ptr::null_mut();
    assert_eq!(unsafe { mosura_session_open(c, ptr::null(), ptr::null(), &mut s) }, MOSURA_OK, "{}", last());
    let data = corpus("basic.elf");
    let label = CString::new("basic.elf").unwrap();
    let mut digest = mosura_bytes { ptr: ptr::null_mut(), len: 0, cap: 0 };
    assert_eq!(unsafe { mosura_session_add_input(s, mosura_view { ptr: data.as_ptr(), len: data.len() }, label.as_ptr(), &mut digest) }, MOSURA_OK, "{}", last());
    assert_eq!(digest.len, 64);
    unsafe { mosura_bytes_dispose(&mut digest) };
    let mut inputs: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_session_inputs(s, &mut inputs) }, MOSURA_OK);
    assert_eq!(unsafe { mosura_table_rows(inputs) }, 1);
    assert_eq!(cell_str(inputs, 0, 0), "basic.elf");
    // analyze with a counting progress callback
    let op = CString::new("program.analyze").unwrap();
    let mut calls = 0u32;
    let mut summary: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_call(s, op.as_ptr(), ptr::null(), Some(count), &mut calls as *mut u32 as *mut c_void, &mut summary) }, MOSURA_OK, "{}", last());
    assert!(calls >= 2, "progress reported {calls} times");
    assert_eq!(unsafe { mosura_table_rows(summary) }, 1);
    let key = cell_str(summary, 0, 0);
    assert_eq!(cell_str(summary, 0, 1), "x86:LE:64:default");
    // served on the second call: no progress reports
    calls = 0;
    let mut again: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_call(s, op.as_ptr(), ptr::null(), Some(count), &mut calls as *mut u32 as *mut c_void, &mut again) }, MOSURA_OK);
    assert_eq!(calls, 0, "a cache hit reports no progress");
    assert_eq!(cell_str(again, 0, 0), key);
    // the functions table, the snapshot text
    let p = opts(c, &[("table", "functions")]);
    let fns = call(s, "program.tables", p).unwrap();
    assert!(unsafe { mosura_table_rows(fns) } >= 13);
    let p2 = opts(c, &[("table", "snapshot")]);
    let snap = call(s, "program.tables", p2).unwrap();
    let mut text = mosura_bytes { ptr: ptr::null_mut(), len: 0, cap: 0 };
    assert_eq!(unsafe { mosura_table_render(snap, mosura_format::MOSURA_FMT_TEXT, &mut text) }, MOSURA_OK);
    let snapshot = String::from_utf8(unsafe { std::slice::from_raw_parts(text.ptr, text.len) }.to_vec()).unwrap();
    unsafe { mosura_bytes_dispose(&mut text) };
    assert!(snapshot.starts_with("# mosura-analysis-snapshot v1"), "{}", &snapshot[..60.min(snapshot.len())]);
    // provenance and the gc listing
    let key_c = CString::new(key.clone()).unwrap();
    let mut prov: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_session_explain(s, key_c.as_ptr(), &mut prov) }, MOSURA_OK, "{}", last());
    let rows = unsafe { mosura_table_rows(prov) };
    assert!(rows > 5);
    assert!((0..rows).any(|r| cell_str(prov, r, 0) == "op" && cell_str(prov, r, 1) == "program.analyze"));
    let bad = CString::new("nothex").unwrap();
    assert_eq!(unsafe { mosura_session_explain(s, bad.as_ptr(), &mut prov) }, MOSURA_ERR_INVALID_ARG);
    let missing = CString::new("0".repeat(64)).unwrap();
    assert_eq!(unsafe { mosura_session_explain(s, missing.as_ptr(), &mut prov) }, MOSURA_ERR_NOT_FOUND);
    let mut sets: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_session_gc(s, 1, &mut sets) }, MOSURA_OK);
    assert_eq!(unsafe { mosura_table_rows(sets) }, 1);
    assert_eq!(unsafe { mosura_session_gc(s, 0, &mut sets) }, MOSURA_ERR_UNSUPPORTED);
    // refusals through call
    assert_eq!(call(s, "program.nope", ptr::null()), Err(MOSURA_ERR_NOT_FOUND));
    let foreign = opts(c, &[("entry", "0x10")]);
    assert_eq!(call(s, "program.analyze", foreign), Err(MOSURA_ERR_INVALID_ARG));
    assert!(last().contains("not a parameter of `program.analyze`"), "{}", last());
    // the registry and a schema
    let mut ops: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_ops(c, 0, &mut ops) }, MOSURA_OK);
    assert!(unsafe { mosura_table_rows(ops) } >= 11);
    let name = CString::new("program_summary").unwrap();
    let mut sch: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_schema(c, name.as_ptr(), &mut sch) }, MOSURA_OK);
    assert_eq!(unsafe { mosura_table_rows(sch) }, 12);
    for h in [inputs, summary, again, fns, snap, prov, sets, ops, sch] {
        unsafe { mosura_release(h as *mut c_void) };
    }
    for h in [p, p2, foreign] {
        unsafe { mosura_release(h as *mut c_void) };
    }
    unsafe {
        mosura_release(s as *mut c_void);
        mosura_release(c as *mut c_void);
    }
}

#[test]
fn session_config_supplies_defaults_and_a_cancel_leaves_no_set() {
    let c = ctx();
    // two sessions over the same input: one with a Result-affecting default in its config
    let cfg = opts(c, &[("knobs.off", "ret-split")]);
    let mut plain: *mut mosura_session = ptr::null_mut();
    let mut tuned: *mut mosura_session = ptr::null_mut();
    assert_eq!(unsafe { mosura_session_open(c, ptr::null(), ptr::null(), &mut plain) }, MOSURA_OK);
    assert_eq!(unsafe { mosura_session_open(c, ptr::null(), cfg, &mut tuned) }, MOSURA_OK, "{}", last());
    let data = corpus("switchtab.elf");
    let label = CString::new("switchtab.elf").unwrap();
    for s in [plain, tuned] {
        assert_eq!(unsafe { mosura_session_add_input(s, mosura_view { ptr: data.as_ptr(), len: data.len() }, label.as_ptr(), ptr::null_mut()) }, MOSURA_OK);
    }
    // a cancelling callback: CANCELLED, and the session has no program afterwards
    let op = CString::new("program.analyze").unwrap();
    let mut t: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_call(plain, op.as_ptr(), ptr::null(), Some(cancel), ptr::null_mut(), &mut t) }, MOSURA_ERR_CANCELLED);
    assert_eq!(call(plain, "program.tables", ptr::null()), Err(MOSURA_ERR_NOT_FOUND), "no set was written");
    let a = call(plain, "program.analyze", ptr::null()).unwrap();
    let b = call(tuned, "program.analyze", ptr::null()).unwrap();
    assert_ne!(cell_str(a, 0, 0), cell_str(b, 0, 0), "the session config's knob is in the key");
    // an explicit parameter wins over the config default: the same key as the plain session
    let explicit = opts(c, &[("knobs.off", "")]);
    let b2 = call(tuned, "program.analyze", explicit).unwrap();
    assert_eq!(cell_str(b2, 0, 0), cell_str(a, 0, 0));
    for h in [a, b, b2] {
        unsafe { mosura_release(h as *mut c_void) };
    }
    unsafe {
        mosura_release(cfg as *mut c_void);
        mosura_release(explicit as *mut c_void);
        mosura_release(plain as *mut c_void);
        mosura_release(tuned as *mut c_void);
        mosura_release(c as *mut c_void);
    }
}
