//! The toolchain driver against the real compiler.
//!
//! Skips when no Watcom installation is configured (`MOSURA_WATCOM_DIR`), like every other gate
//! that needs a user-provided toolchain. What it proves cannot be proved without one: that
//! mosura can drive the compiler, tell success from failure, attribute a diagnostic to the unit
//! that caused it, and survive a unit that takes its session down.
use mosura::recompile::toolchain::{Cached, CompileUnit, Toolchain, WatcomDos};

fn watcom() -> Option<WatcomDos> {
    let dir = mosura::paths::watcom_dir();
    if !dir.join("BINW").is_dir() && !dir.join("binw").is_dir() {
        eprintln!("skipping: no Watcom at {} (set MOSURA_WATCOM_DIR)", dir.display());
        return None;
    }
    if which_dosemu().is_none() {
        eprintln!("skipping: dosemu not on PATH");
        return None;
    }
    let work = std::env::temp_dir().join(format!("mosura-wcc-{}", std::process::id()));
    Some(WatcomDos::new(dir, work, "10.0a").expect("work dir"))
}

fn which_dosemu() -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p).map(|d| d.join("dosemu")).find(|c| c.is_file())
    })
}

const FLAGS: [&str; 5] = ["-4r", "-fpi87", "-s", "-of+", "-onatx"];

fn unit(key: &str, source: &str) -> CompileUnit {
    CompileUnit {
        key: key.into(),
        source: source.into(),
        flags: FLAGS.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn compiles_a_batch_and_reports_each_unit() {
    let Some(wcc) = watcom() else { return };
    let units = vec![
        unit("T00000", "int add2(int a, int b) { return a + b; }"),
        // A unit the compiler must REJECT. Without a failing case the driver could be reporting
        // success unconditionally and every test here would still pass.
        unit("T00001", "int broken(void) { return undeclared_thing(; }"),
        unit("T00002", "int mul3(int a) { return a * 3; }"),
    ];
    let out = wcc.compile_batch(&units);
    assert_eq!(out.len(), 3);
    assert!(out[0].ok(), "first unit should compile: {}", out[0].log);
    assert!(!out[1].ok(), "malformed unit must not produce an object");
    assert!(
        !out[1].log.trim().is_empty(),
        "a rejected unit must carry its diagnostic, not an empty log"
    );
    assert!(out[2].ok(), "a unit AFTER a failing one must still compile: {}", out[2].log);

    // The object is real: it holds the code for the function we asked for.
    let obj = out[0].object.as_ref().unwrap();
    let cand = mosura::recompile::load_object_function(obj, "add2_", 0x1000, &(|_: &str| None))
        .expect("extract add2");
    assert!(!cand.bytes.is_empty(), "no code bytes in the object");
}

#[test]
fn the_cache_serves_the_same_object_without_recompiling() {
    let Some(wcc) = watcom() else { return };
    let dir = std::env::temp_dir().join(format!("mosura-wcc-cache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cached = Cached::new(wcc, &dir).expect("cache dir");
    let u = unit("T00003", "int sub2(int a, int b) { return a - b; }");

    let first = cached.compile(&u);
    assert!(first.ok(), "{}", first.log);
    let second = cached.compile(&u);
    assert_eq!(first.object, second.object, "cache must return the identical object");
    assert_eq!(cached.stats(), (1, 1), "expected exactly one hit and one miss");

    // A different source must NOT hit the same entry.
    let v = unit("T00003", "int sub2(int a, int b) { return b - a; }");
    let third = cached.compile(&v);
    assert!(third.ok(), "{}", third.log);
    assert_ne!(first.object, third.object, "different source must compile differently");
    let _ = std::fs::remove_dir_all(&dir);
}
