//! The toolchain driver against the real compiler.
//!
//! **These tests FAIL when no toolchain is configured; they do not skip.** They used to skip, and
//! that is precisely how the driver came to report every unit as a compile failure on a machine
//! where the compiler worked perfectly: the default path (`$HOME/watcom`) did not exist, both
//! tests printed one line and passed, and the whole recompile/verify path stayed inert and green.
//! A gate that goes quiet when its subject is missing is not a gate. Set `MOSURA_WATCOM_DIR` (and
//! have `dosemu` on PATH) to run them.
//!
//! What they prove cannot be proved without a real compiler: that mosura can drive it, tell
//! success from failure, attribute a diagnostic to the unit that caused it, and survive a unit
//! that takes its session down.
use mosura::recompile::toolchain::{Cached, CompileUnit, Toolchain, WatcomDos};

/// Serialize the dosemu sessions — this target runs single-threaded by construction rather than
/// by remembering `--test-threads=1`.
///
/// Each test gets its OWN work directory (see [`watcom`]), so the sessions no longer corrupt each
/// other's sources; but one emulator per machine at a time is still the honest assumption, and
/// serializing here costs ~5s while making the target's behaviour independent of how cargo
/// schedules it.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn watcom(tag: &str) -> WatcomDos {
    let dir = mosura::paths::watcom_dir();
    assert!(
        dir.join("BINW").is_dir() || dir.join("binw").is_dir(),
        "no Watcom installation at {} — set MOSURA_WATCOM_DIR to a Watcom 10.0a tree (the one \
         holding BINW/). These tests deliberately fail rather than skip: a silent skip is what \
         kept a broken compile driver green.",
        dir.display()
    );
    assert!(
        which_dosemu().is_some(),
        "dosemu is not on PATH — the Watcom compiler is a 16-bit DOS program and cannot be run \
         without it. Install dosemu2 or put it on PATH."
    );
    // Per-TEST work directory. Keying only on the process id gave every test in this binary the
    // SAME directory, so two running concurrently overwrote each other's .C files, _BUILD.BAT and
    // objects — which read as "the compiler produced nothing" and hung the pair for >10 minutes.
    let work = std::env::temp_dir().join(format!("mosura-wcc-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    WatcomDos::new(dir, work, "10.0a").expect("work dir")
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
    let _serial = serial();
    let wcc = watcom("batch");
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
    let _serial = serial();
    let wcc = watcom("cache");
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
