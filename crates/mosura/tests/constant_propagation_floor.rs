//! ⭐ THE FLOOR GATE — Constant Propagation must cost what it *walks*, not a fixed amount
//! per start location.
//!
//! # What is being gated, and why the obvious gate is the wrong one
//!
//! Profiled on WAR2 (`MOSURA_ANALYSIS_TRACE=1`), `Constant Propagation` spent 122.4 s over 95
//! invocations with a per-invocation cost that **did not track the added set**:
//!
//! ```text
//! set=21 -> 1.56 s · set=236 -> 1.56 s · set=3869 -> 1.65 s · set=87072 -> 5.72 s
//! ```
//!
//! A 21-address set costing the same as a 3869-address one is the signature of a fixed cost paid
//! per invocation, independent of the work handed in. A gate on the *total* time would have passed
//! for the wrong reasons (and is vacuous on the fast corpus), so this gate scores the **shape**:
//! two invocations that differ ONLY in how much code the propagator has to walk.
//!
//! The floor lives one level below the analyzer, in
//! [`mosura::analysis::symbolic::flow_constants`], which is called once per start location. Its
//! setup asked the compiler spec for the default calling convention's argument registers
//! (`integer_arg_registers` → `cspec::default_input_paramlist` → `lang::resolve_cspec`), and
//! `resolve_cspec` walked every processor directory re-reading and re-XML-parsing every `.ldefs`
//! file — **35 ms, on every call**. Measured on this very fixture, per `flow_constants` call:
//!
//! ```text
//! start=140001430 visited=3     setup=31.7 ms   walk=0.10 ms
//! start=140004ec0 visited=1386  setup=~40  ms   walk=59.2  ms
//! ```
//!
//! So the number of *start locations* — not the number of addresses — set the price, and the
//! location count barely moves with set size (pass 1 of `findLocationsRemoveFunctionBodies`
//! contributes one entry per overlapping function, pass 3 one per remaining range). That is why a
//! 21-address set and a 3869-address set cost the same on WAR2.
//!
//! Ghidra has no such cost: `LanguageService` parses every `.ldefs` once and hands out
//! `LanguageDescription`s, and `program.getCompilerSpec()` returns an already-built
//! `BasicCompilerSpec`, so `getDefaultCallingConvention()` is a field read. mosura already ports
//! that caching on the SLEIGH side (`lang::load_cached`); the compiler-spec side is the same layer
//! with the cache missing.
//!
//! # The measurement
//!
//! Both invocations hand the analyzer a **one-address set** at a function entry, so both reduce to
//! exactly one start location. The only difference is the function: the program's smallest body
//! versus its largest. The walk work differs by ~500×; if the elapsed time does not, the price is
//! being set by a per-location constant rather than by the code.
//!
//! Scored as a ratio so it is independent of machine speed. With the floor present the ratio is
//! ~2.5 (35 ms of setup swamps both sides); without it, ~400. The bar is 20 — an order of
//! magnitude clear of both.

use std::time::{Duration, Instant};

use mosura::analysis::analyzer::Analyzer;
use mosura::analysis::analyzers::ConstantPropagationAnalyzer;
use mosura::analysis::manager::Scheduling;
use mosura::analysis::program::{AddressSet, Program};
use mosura::decompile::space::Address;
use mosura::paths::analysis_corpus_dir;

/// The cheapest of `n` runs of `added` over the one-address set `{at}`.
///
/// The minimum rather than the mean: this measures a *floor*, and the minimum is the estimator
/// least polluted by scheduler noise. `added` only adds references (deduplicated) and schedules
/// follow-on work into a throwaway `Scheduling`, so repeating it is idempotent.
fn time_one_location(program: &mut Program, cp: &ConstantPropagationAnalyzer, at: Address, n: u32) -> Duration {
    let mut set = AddressSet::new();
    set.add_range(at.space, at.offset, at.offset);
    let mut best = Duration::MAX;
    for _ in 0..n {
        let mut sched = Scheduling::default();
        let t = Instant::now();
        cp.added(program, &set, &mut sched);
        best = best.min(t.elapsed());
    }
    best
}

#[test]
#[ignore = "RED: the floor is present — measured ratio 2.6 against a bar of 20. Un-ignore with the fix."]
fn constant_propagation_cost_tracks_the_walk_not_a_per_location_floor() {
    let path = analysis_corpus_dir().join("mingw_hello.exe");
    assert!(path.exists(), "committed corpus binary missing: {}", path.display());

    let mut program = mosura::analysis::analyze_file(&path).expect("analyze mingw_hello.exe");
    let Some(cp) = ConstantPropagationAnalyzer::for_program(&program) else {
        eprintln!("skip: SLEIGH tables for {} unavailable", program.language_id);
        return;
    };

    // Smallest and largest function by body size — the two ends of "how much is there to walk".
    // Bodies are computed once analysis converges, so they are populated here.
    let mut by_size: Vec<(u64, Address)> = program
        .function_manager
        .functions()
        .map(|f| (f.body().num_addresses(), f.entry_point()))
        .filter(|(n, _)| *n > 0)
        .collect();
    by_size.sort_unstable_by_key(|(n, a)| (*n, a.offset));
    assert!(by_size.len() >= 2, "need at least two functions with bodies, got {}", by_size.len());
    let (small_bytes, small) = by_size[0];
    let (large_bytes, large) = *by_size.last().unwrap();
    assert!(
        large_bytes >= 20 * small_bytes.max(1),
        "fixture no longer spans a wide enough range of function sizes: \
         smallest {small_bytes} bytes, largest {large_bytes} bytes"
    );

    // Warm every process-level cache (SLEIGH spec, compiler spec) before timing, so the first
    // timed call is not paying a one-off startup cost that this gate is not about.
    time_one_location(&mut program, &cp, large, 1);

    let t_small = time_one_location(&mut program, &cp, small, 5);
    let t_large = time_one_location(&mut program, &cp, large, 3);

    let ratio = t_large.as_secs_f64() / t_small.as_secs_f64().max(f64::MIN_POSITIVE);
    eprintln!(
        "smallest fn {small:?} ({small_bytes} bytes) took {t_small:?}; \
         largest fn {large:?} ({large_bytes} bytes) took {t_large:?}; ratio {ratio:.1}"
    );

    assert!(
        ratio > 20.0,
        "Constant Propagation pays a per-start-location FLOOR: propagating the smallest function \
         ({small_bytes} bytes) took {t_small:?} while the largest ({large_bytes} bytes, {}× more \
         code) took only {t_large:?} — a ratio of {ratio:.1}, where the work differs by orders of \
         magnitude. The cost is being set by fixed per-location setup, not by the code walked. \
         See this file's header: `flow_constants` re-resolves and re-parses the compiler spec from \
         disk on every call, which Ghidra's LanguageService/CompilerSpec objects never do.",
        large_bytes / small_bytes.max(1),
    );
}
