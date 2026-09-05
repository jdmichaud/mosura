//! The session store: rename-atomic sets, one set per key, mapped read-back equal to what was
//! written, the in-memory session mirroring the disk one, provenance, the format-version
//! refusal, content-addressed inputs, the lock, and the config file.

use std::path::PathBuf;
use std::time::Duration;

use mosura_api::key::{key, no_annotations, Key};
use mosura_api::program::freeze;
use mosura_api::session::{lock::Lock, Provenance, Session, SetKind, FORMAT_VERSION};
use mosura_api::{Stage, TableBuilder, TableSet};
use mosura_core::analysis;
use mosura_core::switches::Knobs;

fn scratch(name: &str) -> PathBuf {
    let d = mosura_core::paths::workspace_root().join("target").join("api-test-sessions").join(name);
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn basic() -> (Vec<u8>, TableSet, Key) {
    let path = mosura_core::paths::analysis_corpus_dir().join("basic.elf");
    let bytes = std::fs::read(&path).unwrap();
    let p = analysis::analyze_file_with(&path, &Knobs::default()).unwrap();
    let set = freeze(&p, "default");
    let k = key(Stage::Analysis, "program.analyze", &[&mosura_api::key::digest(&bytes)], "default", &no_annotations());
    (bytes, set, k)
}

fn prov<'a>(inputs: &'a [[u8; 32]]) -> Provenance<'a> {
    Provenance { stage: Stage::Analysis, op: "program.analyze", inputs, tag: "default", label: "" }
}

#[test]
fn write_set_is_atomic_and_reads_back_equal() {
    let dir = scratch("atomic");
    let (bytes, set, k) = basic();
    let mut s = Session::open(Some(&dir)).unwrap();
    assert!(!s.has_set(SetKind::Program, &k));
    let inputs = [mosura_api::key::digest(&bytes)];
    s.write_set(SetKind::Program, &k, &set, &prov(&inputs)).unwrap();
    assert!(s.has_set(SetKind::Program, &k));
    // no temp directory left behind; exactly one set directory
    let names: Vec<String> = std::fs::read_dir(dir.join("program")).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(names, vec![k.hex()], "{names:?}");
    let back = s.read_set(SetKind::Program, &k).unwrap();
    assert_eq!(back.digests(), set.digests());
    assert_eq!(back.tables.len(), set.tables.len());
    // cells through the mapping equal the live table
    let (a, b) = (&set.tables["functions"], &back.tables["functions"]);
    for r in 0..a.rows() {
        assert_eq!(a.u64(r, 1).unwrap(), b.u64(r, 1).unwrap());
        assert_eq!(a.str(r, 2).unwrap(), b.str(r, 2).unwrap());
    }
    assert_eq!(back.blob("bytes").unwrap(), set.blob("bytes").unwrap());
    // provenance
    let m = s.explain(SetKind::Program, &k).unwrap();
    let rows: Vec<(String, String, String)> = (0..m.rows()).map(|r| (m.str(r, 0).unwrap().into(), m.str(r, 1).unwrap().into(), m.str(r, 2).unwrap().into())).collect();
    assert!(rows.iter().any(|(k, n, _)| k == "stage" && n == "analysis"));
    assert!(rows.iter().any(|(k, n, _)| k == "op" && n == "program.analyze"));
    assert!(rows.iter().any(|(k, _, v)| k == "input" && *v == mosura_api::fingerprint::hex(&inputs[0])));
    assert!(rows.iter().any(|(k, _, v)| k == "build" && v == mosura_api::fingerprint::build_id()));
    assert!(rows.iter().any(|(k, n, _)| k == "table" && n == "functions"));
    assert!(rows.iter().any(|(k, n, _)| k == "blob" && n == "bytes"));
    // the listing
    let sets = s.sets().unwrap();
    assert_eq!(sets.rows(), 1);
    assert_eq!(sets.str(0, 1).unwrap(), k.hex());
    assert_eq!(sets.u64(0, 2).unwrap() as usize, set.tables.len() + 1, "tables + manifest");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_same_key_written_twice_is_one_set() {
    let dir = scratch("twice");
    let (bytes, set, k) = basic();
    let inputs = [mosura_api::key::digest(&bytes)];
    let mut s = Session::open(Some(&dir)).unwrap();
    s.write_set(SetKind::Program, &k, &set, &prov(&inputs)).unwrap();
    let before = std::fs::metadata(dir.join("program").join(k.hex()).join("manifest.tbl")).unwrap().modified().unwrap();
    s.write_set(SetKind::Program, &k, &set, &prov(&inputs)).unwrap();
    let after = std::fs::metadata(dir.join("program").join(k.hex()).join("manifest.tbl")).unwrap().modified().unwrap();
    assert_eq!(before, after, "the first producer's set is left alone");
    assert_eq!(std::fs::read_dir(dir.join("program")).unwrap().count(), 1);
    assert_eq!(s.read_set(SetKind::Program, &k).unwrap().digests(), set.digests());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_in_memory_session_mirrors_the_disk_one() {
    let dir = scratch("mirror");
    let (bytes, set, k) = basic();
    let inputs = [mosura_api::key::digest(&bytes)];
    let mut disk = Session::open(Some(&dir)).unwrap();
    let mut mem = Session::open(None).unwrap();
    for s in [&mut disk, &mut mem] {
        let d = s.add_input(&bytes, "basic.elf", None).unwrap();
        assert_eq!(d, inputs[0]);
        s.write_set(SetKind::Program, &k, &set, &prov(&inputs)).unwrap();
    }
    assert_eq!(mem.read_set(SetKind::Program, &k).unwrap().digests(), disk.read_set(SetKind::Program, &k).unwrap().digests());
    assert_eq!(mem.input_bytes(&inputs[0]).unwrap(), disk.input_bytes(&inputs[0]).unwrap());
    let (a, b) = (mem.inputs_table(), disk.inputs_table());
    for c in [0u32, 1, 2, 3] {
        assert_eq!(mosura_api::render::cell_text(&a, 0, c).unwrap(), mosura_api::render::cell_text(&b, 0, c).unwrap());
    }
    assert_eq!(mem.sets().unwrap().rows(), 1);
    assert!(mem.explain(SetKind::Program, &k).unwrap().rows() > 5);
    assert!(mem.lock(Duration::ZERO).unwrap().is_none());
    assert!(disk.lock(Duration::ZERO).unwrap().is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_session_of_another_format_version_is_refused() {
    let dir = scratch("version");
    std::fs::create_dir_all(&dir).unwrap();
    let mut b = TableBuilder::new(&mosura_api::session::schemas::SESSION_MANIFEST);
    b.row().u32(FORMAT_VERSION + 1).str("9.9").str("x").str("2026-09-05T00:00:00Z");
    std::fs::write(dir.join("manifest.tbl"), mosura_api::tbl::write(&b.finish(false))).unwrap();
    match Session::open(Some(&dir)) {
        Err(mosura_api::Error::Version { found, expected }) => {
            assert_eq!(found, format!("session format {}", FORMAT_VERSION + 1));
            assert_eq!(expected, format!("session format {FORMAT_VERSION}"));
        }
        other => panic!("expected a version refusal, got {:?}", other.map(|_| ())),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn inputs_are_content_addressed_and_a_re_add_is_a_no_op() {
    let dir = scratch("inputs");
    let bytes = std::fs::read(mosura_core::paths::analysis_corpus_dir().join("basic.elf")).unwrap();
    let mut s = Session::open(Some(&dir)).unwrap();
    let d1 = s.add_input(&bytes, "basic.elf", None).unwrap();
    let d2 = s.add_input(&bytes, "other-name.elf", Some("second")).unwrap();
    assert_eq!(d1, d2);
    assert_eq!(s.inputs_table().rows(), 1);
    assert_eq!(s.inputs_table().str(0, 0).unwrap(), "basic", "the first label stays");
    assert_eq!(s.input_bytes(&d1).unwrap(), bytes);
    assert_eq!(s.resolve_input("basic").unwrap(), d1);
    assert_eq!(s.resolve_input(&mosura_api::fingerprint::hex(&d1)[..12]).unwrap(), d1);
    assert_eq!(s.only_input().unwrap(), d1);
    assert!(s.resolve_input("nope").is_err());
    assert_eq!(std::fs::read_dir(dir.join("inputs")).unwrap().count(), 1);
    // the second input
    let d3 = s.add_input(b"raw bytes", "raw.bin", Some("raw")).unwrap();
    assert_ne!(d3, d1);
    assert!(s.only_input().is_err(), "two inputs: name one");
    // a reopened session sees both
    let s2 = Session::open(Some(&dir)).unwrap();
    assert_eq!(s2.inputs_table().rows(), 2);
    assert_eq!(s2.resolve_input("raw").unwrap(), d3);
    assert_eq!(s2.input_filename(&d3), Some("raw.bin"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_lock_is_exclusive_and_a_dead_holder_is_taken_over() {
    let dir = scratch("lock");
    std::fs::create_dir_all(&dir).unwrap();
    let held = Lock::acquire(&dir, Duration::ZERO).unwrap();
    match Lock::acquire(&dir, Duration::ZERO) {
        Err(mosura_api::Error::Io(e, _)) => assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock),
        other => panic!("expected WouldBlock, got {:?}", other.map(|_| ())),
    }
    drop(held);
    assert!(!dir.join("lock").exists(), "dropping the lock removes the file");
    // a lock whose holder pid no longer exists is stale
    std::fs::write(dir.join("lock"), "999999999\n").unwrap();
    let taken = Lock::acquire(&dir, Duration::ZERO).unwrap();
    assert_eq!(std::fs::read_to_string(dir.join("lock")).unwrap().trim(), std::process::id().to_string());
    drop(taken);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn config_persists_across_open() {
    let dir = scratch("config");
    let mut s = Session::open(Some(&dir)).unwrap();
    s.config_set("compile.cache", "/data/cache").unwrap();
    s.config_set("gates.baseline", "profile/corpus-gates.tsv").unwrap();
    s.config_set("gates.baseline", "").unwrap();
    let s2 = Session::open(Some(&dir)).unwrap();
    assert_eq!(s2.config().get("compile.cache").map(String::as_str), Some("/data/cache"));
    assert!(!s2.config().contains_key("gates.baseline"));
    assert_eq!(s2.config_table().rows(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}
