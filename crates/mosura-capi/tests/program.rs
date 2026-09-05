//! §8–§10 through the C functions: languages and registers, disassemble/lift over bytes equal
//! the operations, identify, the program handle (open → analyze → tables → read → disassemble →
//! key → snapshot), the function handle (c, render, ir, tables, tu on a Watcom binary) and the
//! UNSUPPORTED stubs.

use std::ffi::{c_void, CStr, CString};
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

fn owned(b: &mut mosura_bytes) -> String {
    let v = unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec();
    unsafe { mosura_bytes_dispose(b) };
    String::from_utf8(v).unwrap()
}

fn session_with(c: *mut mosura_ctx, name: &str) -> (*mut mosura_session, Vec<u8>) {
    let mut s: *mut mosura_session = ptr::null_mut();
    assert_eq!(unsafe { mosura_session_open(c, ptr::null(), ptr::null(), &mut s) }, MOSURA_OK);
    let data = corpus(name);
    let label = CString::new(name).unwrap();
    assert_eq!(unsafe { mosura_session_add_input(s, mosura_view { ptr: data.as_ptr(), len: data.len() }, label.as_ptr(), ptr::null_mut()) }, MOSURA_OK);
    (s, data)
}

fn find_row(t: *const mosura_table, col: u32, value: &str) -> Option<u64> {
    (0..unsafe { mosura_table_rows(t) }).find(|&r| cell_str(t, r, col) == value)
}

#[test]
fn languages_registers_and_raw_decoding() {
    let c = ctx();
    let mut langs: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_languages(c, &mut langs) }, MOSURA_OK, "{}", last());
    assert!(unsafe { mosura_table_rows(langs) } > 50, "{}", unsafe { mosura_table_rows(langs) });
    let x86 = find_row(langs, 0, "x86:LE:32:default").expect("x86:LE:32:default listed");
    assert_eq!(cell_str(langs, x86, 1), "x86");
    // the cspecs column is Ghidra's `.ldefs` list; mosura's own `watcom` spec resolves by id (`lang::resolve_cspec`)
    assert!(cell_str(langs, x86, 7).contains("gcc") && cell_str(langs, x86, 7).contains("windows"), "cspecs: {}", cell_str(langs, x86, 7));
    let id = CString::new("x86:LE:32:default").unwrap();
    let mut l: *mut mosura_language = ptr::null_mut();
    assert_eq!(unsafe { mosura_language_open(c, id.as_ptr(), &mut l) }, MOSURA_OK, "{}", last());
    let nope = CString::new("nope:LE:32:default").unwrap();
    let mut l2: *mut mosura_language = ptr::null_mut();
    assert_eq!(unsafe { mosura_language_open(c, nope.as_ptr(), &mut l2) }, MOSURA_ERR_NOT_FOUND);
    let mut regs: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_language_registers(l, &mut regs) }, MOSURA_OK);
    let eax = find_row(regs, 0, "EAX").expect("EAX");
    let mut size = 0u64;
    assert_eq!(unsafe { mosura_table_u64(regs, eax, 3, &mut size) }, MOSURA_OK, "integer getters widen a U32 cell");
    assert_eq!(size, 4);
    // disassemble + lift over bytes equal the operations
    let code = [0x55u8, 0x89, 0xe5, 0x5d, 0xc3];
    let bytes = mosura_view { ptr: code.as_ptr(), len: code.len() };
    let mut d: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_disassemble(l, bytes, 0x1000, ptr::null(), &mut d) }, MOSURA_OK, "{}", last());
    assert_eq!(unsafe { mosura_table_rows(d) }, 4);
    assert_eq!(cell_str(d, 0, 3), "PUSH");
    let mut p: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_lift(l, bytes, 0x1000, ptr::null(), &mut p) }, MOSURA_OK);
    assert!(unsafe { mosura_table_rows(p) } >= 8);
    let regs16 = opts(c, &[("ctx", "addrsize=0;opsize=0")]);
    let mut d16: *mut mosura_table = ptr::null_mut();
    let word = [0xb8u8, 0x34, 0x12, 0x00, 0x00];
    assert_eq!(unsafe { mosura_disassemble(l, mosura_view { ptr: word.as_ptr(), len: word.len() }, 0, regs16, &mut d16) }, MOSURA_OK, "{}", last());
    assert_eq!(cell_str(d16, 0, 4), "AX,0x1234");
    // the stubs
    let mut t: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_emulate(l, bytes, 0, ptr::null(), &mut t) }, MOSURA_ERR_UNSUPPORTED);
    assert_eq!(unsafe { mosura_fingerprint(l, bytes, 0, &mut t) }, MOSURA_ERR_UNSUPPORTED);
    // emit axes and arms
    let mut axes: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_emit_axes(c, &mut axes) }, MOSURA_OK);
    assert_eq!(unsafe { mosura_table_rows(axes) }, 21);
    let mut arms: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_emit_arms(c, &mut arms) }, MOSURA_OK);
    assert_eq!(unsafe { mosura_table_rows(arms) }, 29);
    for h in [langs, regs, d, p, d16, axes, arms] {
        unsafe { mosura_release(h as *mut c_void) };
    }
    unsafe {
        mosura_release(regs16 as *mut c_void);
        mosura_release(l as *mut c_void);
        mosura_release(c as *mut c_void);
    }
}

#[test]
fn identify_program_and_function_handles() {
    let c = ctx();
    let (s, data) = session_with(c, "basic.elf");
    // identify without a session
    let mut id: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_identify(c, mosura_view { ptr: data.as_ptr(), len: data.len() }, &mut id) }, MOSURA_OK, "{}", last());
    let lang_row = find_row(id, 0, "language").expect("language row");
    assert_eq!(cell_str(id, lang_row, 1), "x86:LE:64:default");
    // open (load only) → analyze → tables
    let mut p: *mut mosura_program = ptr::null_mut();
    assert_eq!(unsafe { mosura_program_open(s, ptr::null(), ptr::null(), &mut p) }, MOSURA_OK, "{}", last());
    let mut key1 = mosura_bytes { ptr: ptr::null_mut(), len: 0, cap: 0 };
    assert_eq!(unsafe { mosura_program_key(p, &mut key1) }, MOSURA_OK);
    let k1 = owned(&mut key1);
    assert_eq!(k1.len(), 64);
    assert_eq!(unsafe { mosura_program_analyze(p, ptr::null(), None, ptr::null_mut()) }, MOSURA_OK, "{}", last());
    let mut key2 = mosura_bytes { ptr: ptr::null_mut(), len: 0, cap: 0 };
    assert_eq!(unsafe { mosura_program_key(p, &mut key2) }, MOSURA_OK);
    let k2 = owned(&mut key2);
    assert_ne!(k1, k2, "the analyzed set has its own key");
    let name = CString::new("functions").unwrap();
    let mut fns: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_program_table(p, name.as_ptr(), &mut fns) }, MOSURA_OK, "{}", last());
    let nfns = unsafe { mosura_table_rows(fns) };
    assert!(nfns >= 13);
    let main_row = find_row(fns, 2, "main").expect("main");
    let mut entry = 0u64;
    assert_eq!(unsafe { mosura_table_u64(fns, main_row, 1, &mut entry) }, MOSURA_OK);
    let bad = CString::new("nope").unwrap();
    assert_eq!(unsafe { mosura_program_table(p, bad.as_ptr(), &mut fns) }, MOSURA_ERR_NOT_FOUND);
    // read, disassemble, snapshot
    let mut view = mosura_view { ptr: ptr::null(), len: 0 };
    assert_eq!(unsafe { mosura_program_read(p, entry, 4, &mut view) }, MOSURA_OK, "{}", last());
    assert_eq!(view.len, 4);
    let first = unsafe { std::slice::from_raw_parts(view.ptr, view.len) }.to_vec();
    assert_eq!(unsafe { mosura_program_read(p, 1, 4, &mut view) }, MOSURA_ERR_NOT_FOUND);
    let mut dis: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_program_disassemble(p, entry, 8, &mut dis) }, MOSURA_OK, "{}", last());
    assert!(unsafe { mosura_table_rows(dis) } >= 1);
    let mut b = mosura_view { ptr: ptr::null(), len: 0 };
    assert_eq!(unsafe { mosura_table_bytes(dis, 0, 2, &mut b) }, MOSURA_OK);
    assert_eq!(&unsafe { std::slice::from_raw_parts(b.ptr, b.len) }[..1], &first[..1]);
    let mut snap = mosura_bytes { ptr: ptr::null_mut(), len: 0, cap: 0 };
    assert_eq!(unsafe { mosura_program_snapshot(p, &mut snap) }, MOSURA_OK);
    assert!(owned(&mut snap).starts_with("# mosura-analysis-snapshot v1"));
    let kind = CString::new("name").unwrap();
    assert_eq!(unsafe { mosura_program_annotate(p, kind.as_ptr(), entry, kind.as_ptr()) }, MOSURA_ERR_UNSUPPORTED);
    // the function: c equals the operation's text; ir; tables; render under an emit key
    let mut f: *mut mosura_function = ptr::null_mut();
    assert_eq!(unsafe { mosura_function_decompile(p, entry, ptr::null(), &mut f) }, MOSURA_OK, "{}", last());
    let mut ctext = mosura_bytes { ptr: ptr::null_mut(), len: 0, cap: 0 };
    assert_eq!(unsafe { mosura_function_c(f, &mut ctext) }, MOSURA_OK);
    let ctext = owned(&mut ctext);
    // the bridge decompiles in the multi-function context and names functions `FUN_<entry>`
    assert!(ctext.contains(&format!("FUN_{entry:08x}")), "{ctext}");
    let op = CString::new("function.decompile").unwrap();
    let params = opts(c, &[("entry", &format!("{entry:#x}"))]);
    let mut via_call: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_call(s, op.as_ptr(), params, None, ptr::null_mut(), &mut via_call) }, MOSURA_OK, "{}", last());
    let mut rendered = mosura_bytes { ptr: ptr::null_mut(), len: 0, cap: 0 };
    assert_eq!(unsafe { mosura_table_render(via_call, mosura_format::MOSURA_FMT_TEXT, &mut rendered) }, MOSURA_OK);
    assert_eq!(owned(&mut rendered), ctext);
    let post = CString::new("post").unwrap();
    let mut ir = mosura_bytes { ptr: ptr::null_mut(), len: 0, cap: 0 };
    assert_eq!(unsafe { mosura_function_ir(f, post.as_ptr(), mosura_format::MOSURA_FMT_TEXT, &mut ir) }, MOSURA_OK, "{}", last());
    assert!(!owned(&mut ir).is_empty());
    let pre = CString::new("pre").unwrap();
    assert_eq!(unsafe { mosura_function_ir(f, pre.as_ptr(), mosura_format::MOSURA_FMT_TEXT, &mut ir) }, MOSURA_ERR_UNSUPPORTED);
    let calls = CString::new("calls").unwrap();
    let mut t: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_function_table(f, calls.as_ptr(), &mut t) }, MOSURA_OK, "{}", last());
    let proto = CString::new("prototype").unwrap();
    assert_eq!(unsafe { mosura_function_table(f, proto.as_ptr(), &mut t) }, MOSURA_OK);
    let locals = CString::new("locals").unwrap();
    assert_eq!(unsafe { mosura_function_table(f, locals.as_ptr(), &mut t) }, MOSURA_ERR_UNSUPPORTED);
    let odd = CString::new("odd").unwrap();
    assert_eq!(unsafe { mosura_function_table(f, odd.as_ptr(), &mut t) }, MOSURA_ERR_NOT_FOUND);
    let choices = opts(c, &[("emit.arm-order", "address")]);
    let mut r = mosura_bytes { ptr: ptr::null_mut(), len: 0, cap: 0 };
    assert_eq!(unsafe { mosura_function_render(f, choices, &mut r) }, MOSURA_OK, "{}", last());
    assert!(owned(&mut r).contains(&format!("FUN_{entry:08x}")));
    assert_eq!(unsafe { mosura_function_recover(f, ptr::null(), &mut t) }, MOSURA_ERR_UNSUPPORTED);
    // a TU needs the Watcom x86-32 emitter: basic.elf is x86-64 → UNSUPPORTED
    let mut tu = mosura_bytes { ptr: ptr::null_mut(), len: 0, cap: 0 };
    assert_eq!(unsafe { mosura_function_tu(f, ptr::null(), &mut tu) }, MOSURA_ERR_UNSUPPORTED, "{}", last());
    for h in [id, fns, dis, via_call, t] {
        unsafe { mosura_release(h as *mut c_void) };
    }
    unsafe {
        mosura_release(params as *mut c_void);
        mosura_release(choices as *mut c_void);
        mosura_release(f as *mut c_void);
        // the session goes first: the program handle keeps its own reference
        mosura_release(s as *mut c_void);
        mosura_release(p as *mut c_void);
        mosura_release(c as *mut c_void);
    }
}

#[test]
fn a_watcom_function_emits_a_translation_unit() {
    let c = ctx();
    let (s, _) = session_with(c, "watcom_hello.exe");
    let mut p: *mut mosura_program = ptr::null_mut();
    assert_eq!(unsafe { mosura_program_open(s, ptr::null(), ptr::null(), &mut p) }, MOSURA_OK, "{}", last());
    assert_eq!(unsafe { mosura_program_analyze(p, ptr::null(), None, ptr::null_mut()) }, MOSURA_OK, "{}", last());
    let standalone = opts(c, &[("decompile.global-scope", "standalone")]);
    assert_eq!(unsafe { mosura_program_passes(p, standalone, None, ptr::null_mut()) }, MOSURA_OK, "{}", last());
    let name = CString::new("functions").unwrap();
    let mut fns: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_program_table(p, name.as_ptr(), &mut fns) }, MOSURA_OK);
    let mut entry = 0u64;
    assert_eq!(unsafe { mosura_table_u64(fns, 0, 1, &mut entry) }, MOSURA_OK);
    let mut f: *mut mosura_function = ptr::null_mut();
    assert_eq!(unsafe { mosura_function_decompile(p, entry, ptr::null(), &mut f) }, MOSURA_OK, "{}", last());
    let mut tu = mosura_bytes { ptr: ptr::null_mut(), len: 0, cap: 0 };
    assert_eq!(unsafe { mosura_function_tu(f, ptr::null(), &mut tu) }, MOSURA_OK, "{}", last());
    let tu = owned(&mut tu);
    assert!(tu.contains("FUN_") || tu.contains("void") || tu.contains("int"), "{tu}");
    let report = CString::new("report").unwrap();
    let mut rep: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_function_table(f, report.as_ptr(), &mut rep) }, MOSURA_OK, "{}", last());
    assert!(find_row(rep, 0, "row").is_some());
    let off = opts(c, &[("emit.arms-off", "cmp_sign")]);
    let mut tu2 = mosura_bytes { ptr: ptr::null_mut(), len: 0, cap: 0 };
    assert_eq!(unsafe { mosura_function_tu(f, off, &mut tu2) }, MOSURA_OK, "{}", last());
    let _ = owned(&mut tu2);
    unsafe {
        for h in [fns as *mut c_void, rep as *mut c_void, standalone as *mut c_void, off as *mut c_void, f as *mut c_void, p as *mut c_void, s as *mut c_void, c as *mut c_void] {
            mosura_release(h);
        }
    }
}
