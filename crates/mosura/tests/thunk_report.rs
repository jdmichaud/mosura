//! The thunk-resolution INSTRUMENT (task #4 — "does the thunk port under-fire?").
//!
//! `analyzers::thunk::report` runs the ported resolution + creation chain read-only over every
//! function entry and names the arm that decided each one. This file is the printer: it renders
//! the report so the question "the port fired on 1 of N jump-shaped entries — why not the others?"
//! is answered per entry, per guard, instead of argued.
//!
//! ⚠️ **WHEN THE REPORT IS VALID.** Two guards are state-dependent (`FunctionAlreadyAtTarget` reads
//! the function set, `TargetInsideFunctionBody` reads bodies), so the answer depends on when it is
//! asked — the trap that already bit this port, where bodies were empty and the veto was vacuous.
//! Every caller here takes it **after analysis has converged**, which is exactly the state the
//! final live `resolve_thunks` ran in: `compute_function_bodies` loops walk-then-resolve until a
//! resolve creates nothing, so at return the function set and the bodies are the ones that last
//! call saw. `WouldCreate` must therefore be empty — that is the loop's own exit condition, and
//! [`thunk_report_is_taken_at_the_fixpoint`] asserts it on the committed corpus.
//!
//! What the report cannot distinguish, and does not claim to: an entry the port fired on in an
//! *earlier* round now reads `FunctionAlreadyAtTarget`, the same as a target some other analyzer
//! created. The `inbound=` column carries the evidence — a target with an inbound CALL would be a
//! function without this port; one whose only inbound edge is the thunk's own jump would not.
//!
//! ```sh
//! # WAR2 native-LE (the campaign view). ~minutes — lead-owned.
//! cargo test --release --test thunk_report -- --ignored --nocapture war2_le
//! # WAR2 the default MZ view.
//! cargo test --release --test thunk_report -- --ignored --nocapture war2_mz
//! # The cheap fixpoint gate (runs in the normal suite).
//! cargo test --release --test thunk_report -- thunk_report_is_taken_at_the_fixpoint
//! ```

use mosura::analysis::analyzers::thunk::{self, Candidate, Outcome};
use mosura::analysis::program::{Program, RefType};
use mosura::decompile::space::Address;
use mosura::paths::{analysis_corpus_dir, comcom32_exe, war2_exe};

/// Take the report on a converged program (see the module note on why that timing is the whole
/// validity argument).
fn report_of(program: &Program) -> Vec<Candidate> {
    let (spec, ctx) =
        mosura::lang::load_cached(&program.language_id).expect("SLEIGH tables for the program");
    thunk::report(program, spec, ctx)
}

/// Is this entry part of the population the question is about — resolution produced a thunked
/// address, **or** the entry's raw first instruction is an unconditional direct jump? The second
/// half is the proper form of the crude "entry begins with 0xeb/0xe9" probe: SLEIGH decodes every
/// encoding, and it is computed from memory, so an entry that is not even in the listing still
/// shows up (that decline, `NoInstructionAtEntry`, would otherwise be invisible).
/// third, the entries the unported multi-instruction walk could reach a *new* target from — the
/// only rows where an omitted arm, rather than a guard, is the reason there is no function.
fn interesting(c: &Candidate) -> bool {
    c.outcome.resolved()
        || c.raw_uncond_jump_target.is_some()
        || (c.multi_insn_upper_bound.is_some() && !c.multi_insn_target_is_function)
}

fn print_report(name: &str, program: &Program) {
    let report = report_of(program);
    let mut by_outcome: std::collections::BTreeMap<String, usize> = Default::default();
    for c in &report {
        // Collapse the payload variants so the histogram has one row per guard.
        let key = match c.outcome {
            Outcome::MultipleFlows(_) => "MultipleFlows".to_string(),
            Outcome::TargetInsideFunctionBody(_) => "TargetInsideFunctionBody".to_string(),
            o => format!("{o:?}"),
        };
        *by_outcome.entry(key).or_default() += 1;
    }

    let resolved = report.iter().filter(|c| c.outcome.resolved()).count();
    let raw_jumps = report.iter().filter(|c| c.raw_uncond_jump_target.is_some()).count();
    let raw_jump_target_is_fn = report
        .iter()
        .filter(|c| c.raw_uncond_jump_target.is_some() && c.target_is_function)
        .count();
    let would_create = report.iter().filter(|c| c.outcome == Outcome::WouldCreate).count();
    // The unported multi-instruction arm's ceiling: entries resolution could not touch at all,
    // that walk could reach a target from, and where that target is NOT already a function. Only
    // the last of those three is a number of *missing functions* — and it is an upper bound (the
    // probe omits Ghidra's register side-effect rejection, so it over-accepts).
    let multi = report.iter().filter(|c| c.multi_insn_upper_bound.is_some()).count();
    let multi_new = report
        .iter()
        .filter(|c| c.multi_insn_upper_bound.is_some() && !c.multi_insn_target_is_function)
        .count();

    eprintln!("\n===== thunk report: {name} =====");
    eprintln!("function entries                                  {}", report.len());
    eprintln!("thunk-SHAPED (resolution produced a target)        {resolved}");
    eprintln!("raw first insn is an unconditional direct jump     {raw_jumps}");
    eprintln!("  ...of those, a function exists at the target     {raw_jump_target_is_fn}");
    eprintln!("WouldCreate (must be 0 at the fixpoint)            {would_create}");
    eprintln!("unported multi-insn walk COULD reach a target      {multi}   (UPPER BOUND)");
    eprintln!("  ...of those, no function there yet               {multi_new}   <- what that arm could add");
    eprintln!("-- by deciding arm ------------------------------------------------");
    for (k, n) in &by_outcome {
        eprintln!("  {n:>6}  {k}");
    }

    let pop: Vec<&Candidate> = report.iter().filter(|c| interesting(c)).collect();
    eprintln!("-- per entry ({} jump-shaped or resolved) -------------------------", pop.len());
    for c in &pop {
        let raw = match (&c.raw_mnemonic, c.raw_uncond_jump_target) {
            (Some(m), Some(t)) => format!("{m}({}) -> {t:08x}", c.raw_len),
            (Some(m), None) => format!("{m}({})", c.raw_len),
            (None, _) => "<undecodable>".to_string(),
        };
        let thunked = match c.thunked {
            Some(t) => format!("{:08x}", t.offset),
            None => "--------".to_string(),
        };
        let fmt_refs = |v: &[(RefType, Address)]| {
            if v.is_empty() {
                return "none".to_string();
            }
            v.iter().map(|(t, a)| format!("{}@{:08x}", t.name(), a.offset)).collect::<Vec<_>>().join(",")
        };
        eprintln!(
            "  {:08x}  raw={raw:<28}  thunked={thunked}  target_fn={}  {:?}",
            c.entry.offset,
            if c.target_is_function { "yes" } else { "NO " },
            c.outcome,
        );
        eprintln!(
            "            out=[{}]  in(target)=[{}]",
            fmt_refs(&c.entry_outbound),
            fmt_refs(&c.target_inbound)
        );
        if let Some((t, n)) = c.multi_insn_upper_bound {
            eprintln!(
                "            multi-insn UPPER BOUND: {n} insn -> {:08x} (function there: {})",
                t.offset,
                if c.multi_insn_target_is_function { "yes" } else { "NO" }
            );
        }
    }
    eprintln!("===== end {name} =====\n");
}

/// WAR2, native-LE (`analyze_le_file`) — the campaign view, where the +1 was measured.
/// Lead-owned: minutes, not seconds.
#[test]
#[ignore = "WAR2 run — minutes; lead-owned"]
fn war2_le_thunk_report() {
    let path = war2_exe();
    if !path.exists() {
        eprintln!("skip war2_le_thunk_report: WAR2.EXE absent (MOSURA_WAR2_EXE)");
        return;
    }
    let prog = mosura::analysis::analyze_le_file(&path).expect("native-LE analysis of WAR2.EXE");
    print_report("war2-le", &prog);
}

/// WAR2 through the default MZ/DOS-4GW-stub path (`analyze_file`) — the view the committed Ghidra
/// golden `war2.snapshot` is compared against, and where the MZ thunk cluster
/// (`0x17c4c` / `0x17c50` -> `0x17dbe`) lives.
#[test]
#[ignore = "WAR2 run — minutes; lead-owned"]
fn war2_mz_thunk_report() {
    let path = war2_exe();
    if !path.exists() {
        eprintln!("skip war2_mz_thunk_report: WAR2.EXE absent (MOSURA_WAR2_EXE)");
        return;
    }
    let prog = mosura::analysis::analyze_file(&path).expect("MZ analysis of WAR2.EXE");
    print_report("war2-mz", &prog);
}

/// The instrument's own gate, on the committed corpus: a report taken after `analyze_file`
/// returns must contain no `WouldCreate`.
///
/// **It can fail.** `WouldCreate` means every ported guard passed and a live `resolve_thunks` at
/// this moment would mint a function — i.e. `compute_function_bodies` returned before its own
/// walk/resolve loop reached a fixpoint. That is a real pipeline property, not a restatement of
/// how the report is computed. It also pins the timing the whole instrument depends on: taken
/// before the body walk instead, the containment veto reads empty bodies, permits everything, and
/// this assertion trips on any binary with a thunk.
#[test]
fn thunk_report_is_taken_at_the_fixpoint() {
    // The committed ELFs plus `comcom32` (a DJGPP MZ, user-provided, skipped if absent) — the
    // only fixture here with enough functions for the jump-shaped population to be non-trivial.
    let mut fixtures: Vec<(String, std::path::PathBuf)> = ["basic", "freestanding"]
        .iter()
        .map(|n| (n.to_string(), analysis_corpus_dir().join(format!("{n}.elf"))))
        .collect();
    fixtures.push(("comcom32".to_string(), comcom32_exe()));
    for (name, path) in fixtures {
        if !path.exists() {
            eprintln!("skip {name}: {} not present", path.display());
            continue;
        }
        let prog = mosura::analysis::analyze_file(&path).expect("analysis of the corpus fixture");
        let report = report_of(&prog);
        let pending: Vec<String> = report
            .iter()
            .filter(|c| c.outcome == Outcome::WouldCreate)
            .map(|c| format!("{:08x} -> {:08x?}", c.entry.offset, c.thunked.map(|t| t.offset)))
            .collect();
        assert!(
            pending.is_empty(),
            "{name}: compute_function_bodies left {} thunk(s) unresolved: {pending:?}",
            pending.len()
        );
        print_report(&name, &prog);
    }
}
