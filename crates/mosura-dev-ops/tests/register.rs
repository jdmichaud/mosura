//! The dev tier registers once (idempotent), every operation is valid against the registries
//! (parameters are registered keys, results are known schemas, names sorted and unique), and the
//! operations run through the ordinary dispatcher over an in-memory session.

use std::path::{Path, PathBuf};

use mosura_api::ops::{self, Tier};
use mosura_api::options::registry as optreg;
use mosura_api::{Options, Session};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2).unwrap().to_path_buf()
}

/// A self-compiled Watcom object from the repository's codegen probes.
fn omf_fixture() -> PathBuf {
    workspace().join("oracle/codegen-probes/watcom/10.0a.obj")
}

#[test]
fn the_dev_tier_registers_once_and_its_operations_are_valid() {
    mosura_dev_ops::register().unwrap();
    mosura_dev_ops::register().unwrap();
    assert!(ops::has_dev_tier());
    let names: Vec<&str> = mosura_dev_ops::OPS.iter().map(|o| o.name).collect();
    assert!(names.windows(2).all(|w| w[0] < w[1]), "OPS sorted and unique: {names:?}");
    for op in mosura_dev_ops::OPS {
        assert!(op.name.starts_with("dev."), "{}: dev operations are named dev.*", op.name);
        assert_eq!(op.tier, Tier::Dev, "{}", op.name);
        assert!(!op.doc.is_empty(), "{} has a doc line", op.name);
        for p in op.params {
            // `emit.*` is the api's marker for "every emit axis", not a key
            assert!(*p == "emit.*" || optreg::lookup(p).is_some(), "{}: param `{p}` is not a registered option key", op.name);
        }
        assert!(ops::schema(op.result).is_some(), "{}: result schema `{}` unknown", op.name, op.result);
        assert!(ops::lookup(op.name).is_some(), "{} is registered", op.name);
    }
    assert_eq!(ops::ops_table(Some(Tier::Dev)).rows() as usize, mosura_dev_ops::OPS.len());
    let all: Vec<&str> = ops::registry().iter().map(|o| o.name).collect();
    assert!(all.windows(2).all(|w| w[0] < w[1]), "the merged registry stays sorted");
    assert!(optreg::registry().windows(2).all(|w| w[0].key < w[1].key), "the merged option registry stays sorted");
    // an unknown dev name is NotFound once the tier is in — "not built in" is the release answer
    assert!(matches!(ops::dispatch_inner(&mut Session::open(None).unwrap(), "dev.nope", &Options::new()), Err(mosura_api::Error::NotFound(_))));
}

#[test]
fn omf_dump_lists_the_object_and_extracts_a_public() {
    mosura_dev_ops::register().unwrap();
    let mut s = Session::open(None).unwrap();
    let mut o = Options::new();
    o.set("dev.path", omf_fixture().to_str().unwrap()).unwrap();
    let t = ops::dispatch_inner(&mut s, "dev.omf.dump", &o).unwrap();
    assert_eq!(t.schema().name(), "omf_dump");
    let kinds: Vec<&str> = (0..t.rows()).map(|r| t.str(r, 0).unwrap()).collect();
    assert!(kinds.contains(&"segment") && kinds.contains(&"public"), "{kinds:?}");
    let first_public = (0..t.rows()).find(|&r| t.str(r, 0).unwrap() == "public").map(|r| t.str(r, 1).unwrap().to_string()).expect("a public");
    o.set("dev.symbol", &first_public).unwrap();
    o.set("base", "0x10000").unwrap();
    let t2 = ops::dispatch_inner(&mut s, "dev.omf.dump", &o).unwrap();
    let cand = (0..t2.rows()).find(|&r| t2.str(r, 0).unwrap() == "candidate").expect("a candidate row");
    assert_eq!(t2.str(cand, 1).unwrap(), first_public);
    assert_eq!(t2.u64(cand, 3).unwrap(), 0x10000);
    assert!(t2.u64(cand, 4).unwrap() > 0, "the candidate has bytes");
    assert!((0..t2.rows()).any(|r| t2.str(r, 0).unwrap() == "insn"), "normalized instructions follow");
    // a missing path is a usage error, an unreadable one an io error
    assert!(matches!(ops::dispatch_inner(&mut s, "dev.omf.dump", &Options::new()), Err(mosura_api::Error::InvalidArg(_))));
    let mut bad = Options::new();
    bad.set("dev.path", "/nonexistent/x.obj").unwrap();
    assert!(matches!(ops::dispatch_inner(&mut s, "dev.omf.dump", &bad), Err(mosura_api::Error::Io(..))));
}
