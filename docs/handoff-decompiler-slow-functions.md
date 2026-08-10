# Handoff to the decompiler track: three functions are 71% of every WAR2 analysis

*From the analysis track, 2026-08-10, measured at `162fedb` on `analysis-port`.*

## The result in one line

Decompiling **three** WAR2 functions costs **140 seconds** — 71% of a 196-second whole-program
analysis. Everything else in the run, including all 3022 function discoveries, is the other 29%.

## The measurement

`DecompilerSwitchAnalyzer::added` (`crates/mosura/src/analysis/analyzers/switch.rs:67-92`) is a thin
loop: `find_functions`, then `decompile_function` per entry, then read the jump tables. A
`std::time::Instant` around each `decompile_function` call, baseline configuration
(`analyze_le_file`, no overrides, `funcs=3022`, total 196.3 s):

```
Decompiler Switch total     126.4 s of 196.3 s   (64% of the run)
worst single invocation     125.2 s
functions decompiled         27  across 55 invocations

    0007a5b0    71.63 s
    000793e0    55.43 s
    00051298    13.14 s
    the other 24 functions   < 1 s each
                             ------
                             140.2 s in three functions
```

Independently, `MOSURA_ANALYSIS_TRACE=1` gives the same top line with no code change at all — one
line per analyzer invocation with name, set size and duration:

```
126.4s   55 calls   Decompiler Switch          <- worst call 125.2s
  9.9s  292 calls   Disassembly
  6.8s  119 calls   Create Address Tables
  6.8s   58 calls   Constant Propagation
```

## Reproducing it

No analysis-side setup is needed — decompile the three addresses directly.

```rust
let prog = analysis::analyze_le_file(std::path::Path::new("/home/jd/WAR2.EXE")).unwrap();
let ram = prog.default_space;
for off in [0x0007a5b0u64, 0x000793e0, 0x00051298] {
    let t = std::time::Instant::now();
    let _ = analysis::decompiler::decompile_function(&prog, Address::new(ram, off));
    eprintln!("{off:08x} {:.2}s", t.elapsed().as_secs_f64());
}
```

⚠️ A WAR2 analysis is ~3.3 minutes before you decompile anything, so cache the `Program` if you
iterate. The three functions are reachable in the LE body (`analyze_le_file`), **not** the MZ view.

## Why this is worth the decompiler track's time

1. **It roughly halves every WAR2 analysis run** — including every verification run both tracks
   depend on. This session spent well over an hour of wall-clock waiting on runs whose cost was
   dominated by these three functions.
2. **It unblocks a reverted correctness fix.** The analyzer-channel change (`83fc4c6`, reverted at
   `ddeaa7a` purely on cost) measured 4.1× on WAR2. After the analysis-side fixes below it is
   ~2.2×, and **~145 s of the remaining gap is these three functions**, not the change itself. Fix
   them and that change becomes affordable, which in turn unblocks the last shared-return recall
   defect behind it.
3. It is three inputs, not a systemic slowdown — 24 of the 27 decompilations in the same loop are
   free.

## What it is NOT — three framings this track disproved along the way

- ⛔ **Not a channel-configuration problem.** It was framed that way for most of the session because
  it first showed up in a profile of the reverted change. It costs 126.4 s in the **ordinary**
  baseline run.
- ⛔ **Not an analysis-layer defect.** `DecompilerSwitchAnalyzer` is doing the right work; it is a
  faithful port of `DecompilerSwitchAnalysisCmd` and the loop is three statements.
- ⛔ **Not "two pathological invocations with a discriminator in the set contents"** — that was the
  earlier reading from the invocation-level profile. Those two calls are these same three function
  decompilations, re-entered. The discriminator is *which functions the set causes to be
  decompiled*, and it only became visible by timing one level down.

**Method note, since it took too long to get here:** `MOSURA_ANALYSIS_TRACE=1` named the expensive
analyzer in a single run. The correct next step was a timer *inside* its loop. Instead a chain of
hypotheses was pursued across the layer boundary — compiler-spec parsing, a supposed per-invocation
floor, caching — each of which was measured and refuted. **Instrument the level below; do not
theorise across it.**

## Analysis-side performance work already landed (context, not asks)

These are on `analysis-port` and reduce the surrounding cost; none of them touch the three
functions.

| SHA | change | measured |
| --- | --- | --- |
| `b6754d2` | body walk reads the listing (`FollowFlow.followInstruction`) rather than re-parsing bytes | body-walk SLEIGH decodes 25 652 → **0** |
| `f435e89` + `5760850` | compiler spec resolved/decoded **once**; uncached loaders made private | 118 ms (windows) / 42 ms (gcc-64) / 35 ms (gcc-32) per call removed. ⚠️ WAR2 is unaffected — `watcom` + `x86:LE:32` short-circuits at `lang.rs:49` and pays 1.14 ms |
| `2464d84` + `90dd655` | constant-propagation walk stops decoding a 16-byte window to keep one instruction | **7.13×** on x86-32 decode (measured over 4000 real instructions); corpus CP 3.2× / 2.6× / 6.0×, reference counts identical |

⚠️ **Known regression at `162fedb`, being fixed, blocks the merge to master:**
`pe_mz_convergence_parity` fails with `war2: spurious functions vs Ghidra: [1d74e]` — mosura creates
a function on the MZ image that Ghidra does not. Green at `15d8741`, so it is from one of the four
commits above. Do not build on `analysis-port` until that clears.

## Contact points in the code

- `crates/mosura/src/analysis/analyzers/switch.rs:67` — the loop, and where the timer goes
- `crates/mosura/src/analysis/decompiler.rs` — `decompile_function`, the entry point being timed
- `crates/mosura/src/analysis/manager.rs:178` — the `MOSURA_ANALYSIS_TRACE` hook
