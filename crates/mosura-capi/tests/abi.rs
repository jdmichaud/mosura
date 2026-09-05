//! The C ABI through its own functions: the config struct's size/version rule, NULL and wrong-kind
//! handles, options round trips with the registry's doc in the message, tables end to end
//! (schema, cells, column views, render, serialize → open), double release.

use std::ffi::{c_void, CStr, CString};
use std::mem::size_of;
use std::ptr;

use mosura_capi::mosura_status::*;
use mosura_capi::*;

fn last() -> String {
    unsafe { CStr::from_ptr(mosura_capi::status::mosura_last_error()) }.to_str().unwrap().to_string()
}

fn config() -> mosura_ctx_config {
    mosura_ctx_config { size: size_of::<mosura_ctx_config>() as u32, version: 1, spec_dirs: ptr::null(), spec_dirs_len: 0, fid_dirs: ptr::null(), fid_dirs_len: 0, cache_dir: ptr::null(), log: None, log_user: ptr::null_mut(), abort_on_panic: 0 }
}

fn ctx() -> *mut mosura_ctx {
    let mut c: *mut mosura_ctx = ptr::null_mut();
    assert_eq!(unsafe { mosura_ctx_new(&config(), &mut c) }, MOSURA_OK, "{}", last());
    assert!(!c.is_null());
    c
}

fn s(view: mosura_view) -> String {
    String::from_utf8(unsafe { std::slice::from_raw_parts(view.ptr, view.len) }.to_vec()).unwrap()
}

fn owned(b: &mut mosura_bytes) -> Vec<u8> {
    let v = unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec();
    unsafe { mosura_bytes_dispose(b) };
    v
}

#[test]
fn version_and_size_rule_and_null_pointers() {
    assert_eq!(mosura_abi_version(), 1, "0.1");
    assert!(unsafe { CStr::from_ptr(mosura_version()) }.to_str().unwrap().starts_with("0.1.0 ("));
    let mut c: *mut mosura_ctx = ptr::null_mut();
    assert_eq!(unsafe { mosura_ctx_new(ptr::null(), &mut c) }, MOSURA_ERR_INVALID_ARG);
    assert_eq!(unsafe { mosura_ctx_new(&config(), ptr::null_mut()) }, MOSURA_ERR_INVALID_ARG);
    let mut bad = config();
    bad.version = 2;
    assert_eq!(unsafe { mosura_ctx_new(&bad, &mut c) }, MOSURA_ERR_VERSION);
    assert!(last().contains("version 2"), "{}", last());
    let mut tiny = config();
    tiny.size = 4;
    assert_eq!(unsafe { mosura_ctx_new(&tiny, &mut c) }, MOSURA_ERR_VERSION);
    // a shorter (older) struct that covers only size+version is accepted: the rest is defaulted
    let mut short = config();
    short.size = 8;
    assert_eq!(unsafe { mosura_ctx_new(&short, &mut c) }, MOSURA_OK, "{}", last());
    unsafe { mosura_release(c as *mut c_void) };
    // a missing override directory is refused before anything is installed
    let dir = CString::new("/nonexistent/mosura-override").unwrap();
    let dirs = [dir.as_ptr()];
    let mut with_dir = config();
    with_dir.spec_dirs = dirs.as_ptr();
    with_dir.spec_dirs_len = 1;
    assert_eq!(unsafe { mosura_ctx_new(&with_dir, &mut c) }, MOSURA_ERR_IO);
    // NULL release is a no-op; a foreign pointer is refused (and not freed)
    unsafe { mosura_release(ptr::null_mut()) };
    let stack = 5u64;
    unsafe { mosura_release(&stack as *const u64 as *mut c_void) };
    assert!(last().contains("not a live mosura handle"));
}

#[test]
fn options_round_trip_with_the_registry_doc_in_errors() {
    let c = ctx();
    let mut o: *mut mosura_options = ptr::null_mut();
    assert_eq!(unsafe { mosura_options_new(c, &mut o) }, MOSURA_OK);
    let (k, v) = (CString::new("load.loader").unwrap(), CString::new("le").unwrap());
    assert_eq!(unsafe { mosura_options_set(o, k.as_ptr(), v.as_ptr()) }, MOSURA_OK);
    let mut view = mosura_view { ptr: ptr::null(), len: 0 };
    assert_eq!(unsafe { mosura_options_get(o, k.as_ptr(), &mut view) }, MOSURA_OK);
    assert_eq!(s(view), "le");
    let bad = CString::new("sideways").unwrap();
    assert_eq!(unsafe { mosura_options_set(o, k.as_ptr(), bad.as_ptr()) }, MOSURA_ERR_INVALID_ARG);
    assert!(last().contains("load.loader:") && last().contains("which loader"), "{}", last());
    let nokey = CString::new("no.such").unwrap();
    assert_eq!(unsafe { mosura_options_set(o, nokey.as_ptr(), v.as_ptr()) }, MOSURA_ERR_INVALID_ARG);
    assert!(last().contains("unknown option key"));
    assert_eq!(unsafe { mosura_options_set(o, ptr::null(), v.as_ptr()) }, MOSURA_ERR_INVALID_ARG);
    let mut tag = mosura_bytes { ptr: ptr::null_mut(), len: 0, cap: 0 };
    assert_eq!(unsafe { mosura_options_tag(o, &mut tag) }, MOSURA_OK);
    assert_eq!(owned(&mut tag), b"load.loader=le");
    let spec = CString::new("analysis.disable=Stack;debug.fixpoint").unwrap();
    assert_eq!(unsafe { mosura_options_assign(o, spec.as_ptr()) }, MOSURA_OK);
    let mut o2: *mut mosura_options = ptr::null_mut();
    assert_eq!(unsafe { mosura_options_clone(o, &mut o2) }, MOSURA_OK);
    assert_eq!(unsafe { mosura_options_unset(o2, k.as_ptr()) }, MOSURA_OK);
    assert_eq!(unsafe { mosura_options_get(o2, k.as_ptr(), &mut view) }, MOSURA_OK);
    assert_eq!(s(view), "default", "unset restores the default; the original is untouched");
    assert_eq!(unsafe { mosura_options_get(o, k.as_ptr(), &mut view) }, MOSURA_OK);
    assert_eq!(s(view), "le");
    // the registry as a table
    let mut reg: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_options_registry(c, &mut reg) }, MOSURA_OK);
    assert!(unsafe { mosura_table_rows(reg) } > 40);
    // wrong kind: an options handle where a table is expected
    assert_eq!(unsafe { mosura_table_rows(o as *const mosura_table) }, 0);
    assert!(last().contains("is a mosura_options, not a mosura_table"), "{}", last());
    for h in [o as *mut c_void, o2 as *mut c_void, reg as *mut c_void] {
        unsafe { mosura_release(h) };
    }
    unsafe { mosura_release(o as *mut c_void) };
    assert!(last().contains("double release"));
    unsafe { mosura_release(c as *mut c_void) };
}

#[test]
fn tables_end_to_end() {
    let c = ctx();
    let mut reg: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_options_registry(c, &mut reg) }, MOSURA_OK);
    let (mut name, mut version, mut ncols) = (mosura_view { ptr: ptr::null(), len: 0 }, 0u32, 0u32);
    assert_eq!(unsafe { mosura_table_schema(reg, &mut name, &mut version, &mut ncols) }, MOSURA_OK);
    assert_eq!((s(name).as_str(), version, ncols), ("option_registry", 1, 6));
    let mut ty = mosura_col_type::MOSURA_COL_U8;
    assert_eq!(unsafe { mosura_table_column_info(reg, 0, &mut name, &mut ty) }, MOSURA_OK);
    assert_eq!((s(name).as_str(), ty), ("key", mosura_col_type::MOSURA_COL_STR));
    assert_eq!(unsafe { mosura_table_column_info(reg, 9, &mut name, &mut ty) }, MOSURA_ERR_INVALID_ARG);
    let mut col = 99u32;
    let doc = CString::new("doc").unwrap();
    assert_eq!(unsafe { mosura_table_column_index(reg, doc.as_ptr(), &mut col) }, MOSURA_OK);
    assert_eq!(col, 3);
    let nope = CString::new("nope").unwrap();
    assert_eq!(unsafe { mosura_table_column_index(reg, nope.as_ptr(), &mut col) }, MOSURA_ERR_NOT_FOUND);
    let rows = unsafe { mosura_table_rows(reg) };
    let mut cell = mosura_view { ptr: ptr::null(), len: 0 };
    assert_eq!(unsafe { mosura_table_str(reg, 0, 0, &mut cell) }, MOSURA_OK);
    let first = s(cell);
    assert!(first < "b".to_string(), "sorted by key: {first}");
    assert_eq!(unsafe { mosura_table_str(reg, rows, 0, &mut cell) }, MOSURA_ERR_NOT_FOUND, "a row past the end");
    let mut u = 0u64;
    assert_eq!(unsafe { mosura_table_u64(reg, 0, 0, &mut u) }, MOSURA_ERR_INVALID_ARG, "type mismatch");
    // render + serialize → open → equal
    let mut tsv = mosura_bytes { ptr: ptr::null_mut(), len: 0, cap: 0 };
    assert_eq!(unsafe { mosura_table_render(reg, mosura_format::MOSURA_FMT_TSV, &mut tsv) }, MOSURA_OK);
    let tsv = String::from_utf8(owned(&mut tsv)).unwrap();
    assert!(tsv.starts_with("key\ttype\tdefault\tdoc\tsince\taffects\n"));
    assert_eq!(tsv.lines().count() as u64, rows + 1);
    let mut img = mosura_bytes { ptr: ptr::null_mut(), len: 0, cap: 0 };
    assert_eq!(unsafe { mosura_table_serialize(reg, &mut img) }, MOSURA_OK);
    let image = owned(&mut img);
    assert!(image.starts_with(b"MOSTBL01"));
    let mut back: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_table_open(c, mosura_view { ptr: image.as_ptr(), len: image.len() }, 0, &mut back) }, MOSURA_OK, "{}", last());
    assert_eq!(unsafe { mosura_table_rows(back) }, rows);
    let mut json_a = mosura_bytes { ptr: ptr::null_mut(), len: 0, cap: 0 };
    let mut json_b = mosura_bytes { ptr: ptr::null_mut(), len: 0, cap: 0 };
    unsafe {
        mosura_table_render(reg, mosura_format::MOSURA_FMT_JSON, &mut json_a);
        mosura_table_render(back, mosura_format::MOSURA_FMT_JSON, &mut json_b);
    }
    assert_eq!(owned(&mut json_a), owned(&mut json_b));
    // a corrupt image is FORMAT
    let mut corrupt = image.clone();
    corrupt[100] ^= 0xff;
    assert_eq!(unsafe { mosura_table_open(c, mosura_view { ptr: corrupt.as_ptr(), len: corrupt.len() }, 0, &mut back) }, MOSURA_ERR_FORMAT);
    // a fixed-width column view over a sorted numeric table: the ops table has none; use find on
    // a Str column → NOT_FOUND
    let mut row = 0u64;
    assert_eq!(unsafe { mosura_table_find(reg, 0, 42, &mut row) }, MOSURA_ERR_NOT_FOUND);
    unsafe {
        mosura_release(reg as *mut c_void);
        mosura_release(c as *mut c_void);
    }
}
