//! Review R5 (commit b): the gcc ground-truth oracle over ARM-ENABLED emit, in the 32-bit column.
//!
//! Every program of oracle/ground-truth/src is built with `gcc -m32` and recompiled twice from
//! mosura's decompilation — PLAIN (the reference rendering) and ARMS (the survey's measured
//! configuration: the canonical arm set, `sum-order=original` on the recovered pass, the
//! per-function recovery over the program's own instructions) — and each recompiled program is
//! RUN against the original. The invariant this test holds: a program that PASSes plain must PASS
//! arm-enabled. A PASS→FAIL under the arms is a WRONG-CODE ARM — the finding class this oracle
//! exists to catch — listed here as a finding for JD, never baselined silently, not fixed here.
//!
//! What this test does NOT assert: the plain-32 verdicts. The i386 SysV path through the ELF
//! analysis has never been measured (every existing baseline is the 64-bit host column); plain-32
//! is REPORTED per program, and a plain-32 FAIL is its own finding, outside this invariant.
//! COVERAGE is reported too: the ARM TUs of a program are the functions whose arm-enabled text
//! differs from the plain text — the only functions the arms touched; gcc rarely emits the Watcom
//! idioms the witnesses look for, so most witness-gated arms fire on few or no gcc functions, and
//! that is said here rather than hidden (there is deliberately no stress mode: an unwitnessed
//! candidate rendered as if witnessed executes a rendering the measured configuration never
//! produces, and some arms are value-identical only because of their witness).
//!
//! COST: 27 programs x 2 passes, each a `gcc -m32` build, decompile, recompile and run -- about
//! 7 minutes on master. It is a PLAN-CLOSURE test (JD, 2026-08-28), `#[ignore]`d so that no
//! per-commit iteration suite pays for it: the attribute is the mechanism (no environment variable
//! to remember) and the `ignored` count in every suite summary is the visible sign. It runs alone,
//! `cargo test --release --test ground_truth_recompile_arms -- --ignored`, at the end of a plan (the
//! acceptance chain's closure suite) and for any commit that changes what it tests -- the gt
//! oracle, the emit plan or an arm -- where the contract "a wrong-code arm fails the suite" is held.
use mosura::recompile::groundtruth::{gcc_available, gcc_programs, recompile_program, EmitPlan, Target};

#[test]
#[ignore = "plan-closure test (~7 min on master): run with `cargo test --release --test ground_truth_recompile_arms -- --ignored` at the end of a plan or when a commit changes the gt oracle, the emit plan or an arm"]
fn arm_enabled_emit_passes_wherever_plain_passes_in_the_32bit_column() {
    assert!(gcc_available(), "gcc is required by the development environment (ground-truth recompile gate)");
    let workdir = mosura::paths::workspace_root().join("build/gt-recompile");
    std::fs::create_dir_all(&workdir).unwrap();
    let mut findings: Vec<String> = Vec::new();
    let (mut programs, mut plain_pass, mut arm_tus_total, mut fns_total) = (0usize, 0usize, 0usize, 0usize);
    for src in gcc_programs() {
        let plain = recompile_program(&src, &workdir, Target::Gcc32, &EmitPlan::plain())
            .unwrap_or_else(|e| panic!("{} (plain-32): {e}", src.display()));
        let arms = recompile_program(&src, &workdir, Target::Gcc32, &EmitPlan::arms())
            .unwrap_or_else(|e| panic!("{} (arms-32): {e}", src.display()));
        // the arm TUs: the functions whose arm-enabled text differs from the plain text
        let arm_tus: Vec<&str> = arms
            .functions
            .iter()
            .filter(|a| plain.functions.iter().any(|p| p.symbol == a.symbol && p.c != a.c))
            .map(|a| a.symbol.as_str())
            .collect();
        println!(
            "gt-arms {}: plain-32 {} | arms-32 {} | arm TUs {}/{}{}{}",
            plain.program,
            plain.functional,
            arms.functional,
            arm_tus.len(),
            arms.functions.len(),
            if arm_tus.is_empty() { "" } else { ": " },
            arm_tus.join(" ")
        );
        programs += 1;
        arm_tus_total += arm_tus.len();
        fns_total += arms.functions.len();
        if plain.functional == "PASS" {
            plain_pass += 1;
            if arms.functional != "PASS" {
                findings.push(format!(
                    "{}: plain-32 PASS but arms-32 {} (arm TUs: {})",
                    plain.program,
                    arms.functional,
                    if arm_tus.is_empty() { "none".to_string() } else { arm_tus.join(" ") }
                ));
            }
        }
    }
    println!(
        "gt-arms summary: {programs} programs, plain-32 PASS {plain_pass}, arm TUs {arm_tus_total}/{fns_total} functions"
    );
    assert!(
        findings.is_empty(),
        "WRONG-CODE ARM findings (a program that PASSes plain fails arm-enabled) -- for JD, not to be baselined:\n  {}",
        findings.join("\n  ")
    );
}
