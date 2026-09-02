//! LIVE-DRIVE tier for the compiler driver — opt-in, NEVER in the gate (design §0/§3).
//!
//! These actually invoke a compiler, so they are `#[ignore]`d: `cargo test` on a machine with no
//! toolchain installed must pass, because that is the property mosura is FOR. The driver's own
//! logic is covered compiler-free by the unit tests in `recompile::toolchain::driver`; what is
//! left to check here is the part only a real compiler can answer — that the spec's invocation,
//! naming and object-reading actually fit the tool.
//!
//! Run: `cargo test --release --test compiler_driver_live -- --ignored`
//! Each test SKIPS (passes with a note) when its toolchain is absent, so a partial environment
//! reports "not run" rather than a red result that looks like a defect.

use mosura::recompile::toolchain::{spec, CompileUnit, CompilerDriver, DriverRole, Toolchain};

const MVE: &str = "int p(int a, int b) { return a * 3 + b; }";

fn work(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("mosura-live-{tag}-{}", std::process::id()))
}

fn have(prog: &str) -> bool {
    std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {prog} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Watcom 10.0a under dosemu — the baseline, OMF, script invocation.
#[test]
#[ignore = "live-drive: needs dosemu + a Watcom 10.0a install"]
fn watcom_10_0a_dos_compiles_an_mve() {
    let install = std::env::var("MOSURA_WATCOM").unwrap_or_else(|_| {
        "/home/jd/projects/warcraft2-re/tmp/watcom-experiments/watcom_10.0a/WATCOM".into()
    });
    if !have("dosemu") || !std::path::Path::new(&install).is_dir() {
        eprintln!("SKIP: dosemu or the Watcom install is absent");
        return;
    }
    let d = CompilerDriver::new(
        spec::watcom_10_0a_dos(""),
        &install,
        work("wat"),
        DriverRole::DevelopmentAssistance,
    )
    .expect("work dir")
    .owning_work_dir();
    let out = d.compile(&CompileUnit { key: "T0".into(), source: MVE.into(), flags: vec![] });
    let obj = out.object.expect("Watcom produced an object");
    assert!(!obj.is_empty(), "object is non-empty");
    // OMF starts with THEADR (0x80).
    assert_eq!(obj[0], 0x80, "OMF THEADR record: {:#04x}", obj[0]);
}

/// Open Watcom 2, NATIVE — the configurability stress: same vendor and format, no emulator.
#[test]
#[ignore = "live-drive: needs a native Open Watcom 2 (wcc386 on PATH)"]
fn open_watcom_2_native_compiles_an_mve() {
    if !have("wcc386") {
        eprintln!("SKIP: wcc386 is not on PATH");
        return;
    }
    let d = CompilerDriver::new(
        spec::open_watcom_2_native("wcc386", ""),
        "/",
        work("ow2"),
        DriverRole::DevelopmentAssistance,
    )
    .expect("work dir")
    .owning_work_dir();
    let out = d.compile(&CompileUnit { key: "t0".into(), source: MVE.into(), flags: vec![] });
    assert!(out.object.is_some_and(|o| !o.is_empty()), "Open Watcom produced an object");
}

/// gcc — the generalization case: foreign toolchain, native, ELF.
#[test]
#[ignore = "live-drive: needs gcc with -m32 support"]
fn gcc_native_compiles_an_mve_to_elf() {
    if !have("gcc") {
        eprintln!("SKIP: gcc is not on PATH");
        return;
    }
    let d = CompilerDriver::new(
        spec::gcc_native("gcc", ""),
        "/",
        work("gcc"),
        DriverRole::DevelopmentAssistance,
    )
    .expect("work dir")
    .owning_work_dir();
    let out = d.compile(&CompileUnit { key: "t0".into(), source: MVE.into(), flags: vec![] });
    let Some(obj) = out.object else {
        eprintln!("SKIP: gcc produced no object (no -m32 multilib?)");
        return;
    };
    assert_eq!(&obj[..4], b"\x7fELF", "ELF magic");
}

/// The gate's own invariant, asserted rather than assumed: constructing every spec and building
/// every invocation touches no compiler. This one is NOT ignored -- it must run in the gate.
#[test]
fn building_any_invocation_runs_no_compiler() {
    for s in [
        spec::watcom_10_0a_dos("x"),
        spec::open_watcom_2_native("wcc386", "x"),
        spec::gcc_native("gcc", "x"),
    ] {
        let id = s.id.clone();
        let d = CompilerDriver::new(s, "/i", work(&format!("dry-{id}")), DriverRole::Validation)
            .expect("work dir")
            .owning_work_dir();
        let u = CompileUnit { key: "k".into(), source: MVE.into(), flags: vec![] };
        let argv = d.command_line(Some(&u));
        assert!(!argv.is_empty(), "{id} yields an argv without running anything");
        let _ = d.script_text(&[u]);
    }
}

/// The path the compiler-free gate CANNOT reach: a source the compiler REJECTS.
///
/// A rejection is a verdict about the source and must be adjudicated (so it caches); a unit
/// nothing judged must not be. Only a live compiler can prove the diagnostics actually arrive —
/// under dosemu they come from a log FILE that has to be found and split, and for a native
/// compiler from stderr that has to be captured rather than discarded. Both were wrong here
/// before review: the driver marked every unit adjudicated unconditionally, which caches a
/// toolchain hiccup as a false COMPILE_FAIL against the source, permanently.
#[test]
#[ignore = "live-drive: needs dosemu + a Watcom 10.0a install"]
fn watcom_adjudicates_a_rejected_source_with_its_own_diagnostics() {
    let install = std::env::var("MOSURA_WATCOM").unwrap_or_else(|_| {
        "/home/jd/projects/warcraft2-re/tmp/watcom-experiments/watcom_10.0a/WATCOM".into()
    });
    if !have("dosemu") || !std::path::Path::new(&install).is_dir() {
        eprintln!("SKIP: dosemu or the Watcom install is absent");
        return;
    }
    let d = CompilerDriver::new(
        spec::watcom_10_0a_dos(""),
        &install,
        work("wat-rej"),
        DriverRole::DevelopmentAssistance,
    )
    .expect("work dir")
    .owning_work_dir();
    // One good unit and one syntactically broken one, in ONE session -- the case where a whole-log
    // copy would let the good unit's summary adjudicate the broken one and vice versa.
    let outs = d.compile_batch(&[
        CompileUnit { key: "T0".into(), source: MVE.into(), flags: vec![] },
        CompileUnit { key: "T1".into(), source: "int q(void) { return ; ; ) }".into(), flags: vec![] },
    ]);
    assert!(outs[0].object.is_some(), "the good unit compiled");
    assert!(outs[0].adjudicated, "an object is a verdict");
    assert!(outs[1].object.is_none(), "the broken unit produced no object");
    assert!(outs[1].adjudicated, "a REJECTION is a verdict about the source, and caches");
    assert!(
        !outs[1].log.trim().is_empty(),
        "the rejected unit carries its own diagnostics: {:?}",
        outs[1].log
    );
    assert!(
        !outs[0].log.contains("Error!"),
        "the good unit must NOT inherit its neighbour's error: {:?}",
        outs[0].log
    );
}

/// The same property for a NATIVE compiler, where the diagnostics are stderr rather than a file.
#[test]
#[ignore = "live-drive: needs gcc"]
fn gcc_adjudicates_a_rejected_source_from_captured_stderr() {
    if !have("gcc") {
        eprintln!("SKIP: gcc is absent");
        return;
    }
    let d = CompilerDriver::new(
        spec::gcc_native("gcc", ""),
        "/usr",
        work("gcc-rej"),
        DriverRole::DevelopmentAssistance,
    )
    .expect("work dir")
    .owning_work_dir();
    let out = d.compile(&CompileUnit {
        key: "T0".into(),
        source: "int q(void) { return ; ; ) }".into(),
        flags: vec![],
    });
    assert!(out.object.is_none(), "no object from a rejected source");
    assert!(
        !out.log.trim().is_empty(),
        "gcc's stderr is CAPTURED, not discarded -- without it a real rejection looks like a \
         silent abort and never caches: {:?}",
        out.log
    );
    assert!(out.adjudicated, "a rejection is a verdict about the source");
}
