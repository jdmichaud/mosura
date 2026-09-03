//! Review R5 (commit d): the MVE TWIN BUILD — the gcc ground-truth oracle over the arm TUs.
//!
//! For every MVE of `recompile::mve::MVES`, `gcc -m32` builds the MVE's own source and mosura's
//! decompilation of the Watcom fixture made from it (real bytes, real witnesses), both against
//! one compilation of the recording stubs and the driver; the traces must be byte-identical.
//! The decompiled side runs PLAIN and ARMS: a plain mismatch is a DECOMPILER finding (printed,
//! not asserted here — it is its own faithful-port question); an ARMS-ONLY mismatch (source ==
//! plain, plain != arms) is a WRONG-CODE ARM on exactly the shape the arm exists for — the
//! finding class this oracle exists to catch, asserted, never baselined. A fixture without the
//! `externs:` header line fails loudly. Cost: 14 MVEs x 3 tiny gcc -m32 builds — seconds.
//!
//! ## OPT-IN (§0): this needs gcc, so it is not in the default gate
//!
//! Run: `cargo test --release -p mosura --test mve_twin_build -- --ignored`
//!
//! mosura must build and test on a machine with ZERO toolchains installed -- no Watcom, no Open
//! Watcom, no gcc. This test hard-asserts gcc, so until 2026-09-03 it made `cargo test` FAIL on a
//! clean machine and "the gate is compiler-free" was a label rather than a fact. It joins gt-arms
//! in the opt-in tier, which is where JD already put the rest of this gcc ground-truth family;
//! `scripts/gate-compiler-free.sh` proves the invariant by running the gate with no toolchain
//! reachable. The cost is real and accepted: this no longer runs per-commit, so run it at plan
//! closure, or whenever a commit changes what it measures.
use mosura::recompile::mve::MVES;
use mosura::recompile::twin::twin;

#[test]
#[ignore = "opt-in: needs gcc (§0 -- the default gate must pass with zero toolchains)"]
fn every_arm_rendering_of_an_mve_behaves_as_its_source() {
    let workdir = mosura::paths::workspace_root().join("build/mve-twin");
    std::fs::create_dir_all(&workdir).unwrap();
    let mut wrong_code: Vec<String> = Vec::new();
    let mut decompiler_findings: Vec<String> = Vec::new();
    let mut probable_wrong_code: Vec<String> = Vec::new();
    let (mut n, mut plain_ok, mut arms_ok) = (0usize, 0usize, 0usize);
    for m in MVES {
        let r = twin(m, &workdir).unwrap_or_else(|e| panic!("{}: {e}", m.key));
        n += 1;
        let pm = r.plain_matches();
        let am = r.arms_matches();
        plain_ok += pm as usize;
        arms_ok += am as usize;
        // three ways: source vs plain, source vs arms, plain vs arms — every MVE labelled
        println!("twin {}: plain {} | arms {} | {}", m.key, if pm { "SAME" } else { "DIFF" }, if am { "SAME" } else { "DIFF" }, r.class());
        if !pm {
            decompiler_findings.push(format!("{}: {} — plain: {}", m.key, r.class(), r.first_diff(&r.plain)));
            if !am && !r.arms_eq_plain() {
                probable_wrong_code.push(format!("{}: both wrong, differently — arms: {}", m.key, r.first_diff(&r.arms)));
            }
        }
        if pm && !am {
            wrong_code.push(format!("{}: arms-only mismatch — {}", m.key, r.first_diff(&r.arms)));
            println!("--- {} source trace ---\n{}--- arms trace ---\n{}--- arms TU ---\n{}", m.key, r.source_trace, r.arms.clone().unwrap_or_else(|e| e), r.arms_tu);
        }
        if !pm {
            println!("--- {} source trace ---\n{}--- plain trace ---\n{}--- plain TU ---\n{}", m.key, r.source_trace, r.plain.clone().unwrap_or_else(|e| e), r.plain_tu);
            if !r.arms_eq_plain() {
                println!("--- {} arms trace ---\n{}", m.key, r.arms.clone().unwrap_or_else(|e| e));
            }
        }
    }
    println!("twin summary: {n} MVEs, plain SAME {plain_ok}, arms SAME {arms_ok}");
    if !decompiler_findings.is_empty() {
        println!("DECOMPILER findings (plain differs from the source; not asserted here):\n  {}", decompiler_findings.join("\n  "));
    }
    if !probable_wrong_code.is_empty() {
        println!("PROBABLE wrong-code arms (both wrong, differently — a decompiler finding AND an arm that changed behaviour on top; not asserted, for JD):\n  {}", probable_wrong_code.join("\n  "));
    }
    assert!(
        wrong_code.is_empty(),
        "WRONG-CODE ARM findings (source == plain, plain != arms) — for JD, never baselined:\n  {}",
        wrong_code.join("\n  ")
    );
}
