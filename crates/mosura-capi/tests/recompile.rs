//! §11 through the C functions, without a compiler: the specs, opening a toolchain, the empty
//! rounds table, build flags from the prologue, a verify against junk (OBJ_ERROR), the round
//! store through `mosura_call` (import) and the typed round accessors.

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

fn workspace() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2).unwrap().to_path_buf()
}

#[test]
fn toolchains_rounds_buildconfig_and_verify_without_a_compiler() {
    let c = ctx();
    let mut specs: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_toolchain_specs(c, &mut specs) }, MOSURA_OK);
    assert_eq!(unsafe { mosura_table_rows(specs) }, 3);
    let dir = workspace().join("target/capi-test-sessions/recompile");
    let _ = std::fs::remove_dir_all(&dir);
    let dir_c = CString::new(dir.to_str().unwrap()).unwrap();
    let mut s: *mut mosura_session = ptr::null_mut();
    assert_eq!(unsafe { mosura_session_open(c, dir_c.as_ptr(), ptr::null(), &mut s) }, MOSURA_OK, "{}", last());
    // a toolchain opens (the driver runs nothing)
    let tco = opts(c, &[("toolchain.spec", "gcc-native"), ("toolchain.install", "cc")]);
    let name = CString::new("cc").unwrap();
    let mut tc: *mut mosura_toolchain = ptr::null_mut();
    assert_eq!(unsafe { mosura_toolchain_open(s, name.as_ptr(), tco, &mut tc) }, MOSURA_OK, "{}", last());
    // no rounds yet; comparing missing rounds is NOT_FOUND
    let mut rounds: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_rounds(s, &mut rounds) }, MOSURA_OK);
    assert_eq!(unsafe { mosura_table_rows(rounds) }, 0);
    let (a, b) = (CString::new("x").unwrap(), CString::new("y").unwrap());
    let mut cmp: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_round_compare(s, a.as_ptr(), b.as_ptr(), &mut cmp) }, MOSURA_ERR_NOT_FOUND);
    // a Watcom program: build flags from the prologue; verify against junk is OBJ_ERROR
    let data = std::fs::read(workspace().join("oracle/analysis-corpus/watcom_hello.exe")).unwrap();
    let label = CString::new("watcom_hello.exe").unwrap();
    assert_eq!(unsafe { mosura_session_add_input(s, mosura_view { ptr: data.as_ptr(), len: data.len() }, label.as_ptr(), ptr::null_mut()) }, MOSURA_OK);
    let mut p: *mut mosura_program = ptr::null_mut();
    assert_eq!(unsafe { mosura_program_open(s, label.as_ptr(), ptr::null(), &mut p) }, MOSURA_OK, "{}", last());
    assert_eq!(unsafe { mosura_program_analyze(p, ptr::null(), None, ptr::null_mut()) }, MOSURA_OK, "{}", last());
    let fns_name = CString::new("functions").unwrap();
    let mut fns: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_program_table(p, fns_name.as_ptr(), &mut fns) }, MOSURA_OK);
    let mut entry = 0u64;
    assert_eq!(unsafe { mosura_table_u64(fns, 0, 1, &mut entry) }, MOSURA_OK);
    let mut f: *mut mosura_function = ptr::null_mut();
    assert_eq!(unsafe { mosura_function_decompile(p, entry, ptr::null(), &mut f) }, MOSURA_OK, "{}", last());
    let mut bc: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_function_buildconfig(f, ptr::null(), &mut bc) }, MOSURA_OK, "{}", last());
    let flags: Vec<String> = (0..unsafe { mosura_table_rows(bc) }).filter(|&r| cell_str(bc, r, 0) == "flag").map(|r| cell_str(bc, r, 1)).collect();
    assert!(flags.contains(&"-5r".to_string()), "{flags:?}");
    let junk = b"not an object";
    let mut v: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_function_verify(f, mosura_view { ptr: junk.as_ptr(), len: junk.len() }, ptr::null(), &mut v) }, MOSURA_OK, "{}", last());
    assert_eq!(unsafe { mosura_table_rows(v) }, 1);
    assert_eq!(cell_str(v, 0, 3), "OBJ_ERROR");
    // the round store: import two legacy tables through call, then the typed accessors
    std::fs::write(dir.join("a.tsv"), "idx\tva\tname\tverdict\tbytes\tprimary\tsim\tequal\torig_n\tcand_n\tclasses\tSIM=structural\n00001\t00010063\tF1\tEXACT\tIdentical\t\t1.000\t29\t29\t29\t\n").unwrap();
    std::fs::write(dir.join("b.tsv"), "idx\tva\tname\tverdict\tbytes\tprimary\tsim\tequal\torig_n\tcand_n\tclasses\tSIM=structural\n00001\t00010063\tF1\tMISMATCH\tDifferent\textra\t0.500\t10\t29\t30\textra=5\n").unwrap();
    for (r, file) in [("ra", "a.tsv"), ("rb", "b.tsv")] {
        let op = CString::new("round.import").unwrap();
        let params = opts(c, &[("round", r), ("verdicts", dir.join(file).to_str().unwrap())]);
        let mut out: *mut mosura_table = ptr::null_mut();
        assert_eq!(unsafe { mosura_call(s, op.as_ptr(), params, None, ptr::null_mut(), &mut out) }, MOSURA_OK, "{}", last());
        unsafe { mosura_release(out as *mut c_void) };
        unsafe { mosura_release(params as *mut c_void) };
    }
    assert_eq!(unsafe { mosura_rounds(s, &mut rounds) }, MOSURA_OK);
    assert_eq!(unsafe { mosura_table_rows(rounds) }, 2);
    let (ra, rb) = (CString::new("ra").unwrap(), CString::new("rb").unwrap());
    assert_eq!(unsafe { mosura_round_compare(s, ra.as_ptr(), rb.as_ptr(), &mut cmp) }, MOSURA_OK, "{}", last());
    assert!((0..unsafe { mosura_table_rows(cmp) }).any(|r| cell_str(cmp, r, 0) == "flip"));
    let mut gates: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_round_gates(s, rb.as_ptr(), ra.as_ptr(), ptr::null(), &mut gates) }, MOSURA_OK, "{}", last());
    let g8 = (0..unsafe { mosura_table_rows(gates) }).find(|&r| cell_str(gates, r, 0).starts_with("8 ")).unwrap();
    assert_eq!(cell_str(gates, g8, 1), "FAIL", "an EXACT lost");
    let verdicts = CString::new("verdicts").unwrap();
    let mut t: *mut mosura_table = ptr::null_mut();
    assert_eq!(unsafe { mosura_round_table(s, ra.as_ptr(), verdicts.as_ptr(), &mut t) }, MOSURA_OK);
    assert_eq!(cell_str(t, 0, 3), "EXACT");
    assert_eq!(unsafe { mosura_round_table(s, ra.as_ptr(), ptr::null(), &mut t) }, MOSURA_OK, "the manifest by default");
    for h in [specs, rounds, cmp, fns, bc, v, gates, t] {
        unsafe { mosura_release(h as *mut c_void) };
    }
    unsafe {
        mosura_release(tco as *mut c_void);
        mosura_release(f as *mut c_void);
        mosura_release(p as *mut c_void);
        mosura_release(tc as *mut c_void);
        mosura_release(s as *mut c_void);
        mosura_release(c as *mut c_void);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
