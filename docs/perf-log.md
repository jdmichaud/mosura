# Performance log — porting-loop iteration cost

Goal: the porting loop's iteration is dominated by running mosura (debug-build test
suite + incremental rebuild). This log records each measurement as optimizations land,
all **byte-neutral**: corpus avg 0.8649 / 54 of 60 ≥0.70, 254/254 disasm goldens, and all
16 test binaries green after every row.

Machine: 5 cores, linux 6.12, GNU ld (no mold/lld available). "suite" = `cargo test
--workspace` wall time, build warm. "rebuild" = `cargo build --workspace --tests` after
touching `decompile/rules.rs` (a typical loop edit — mostly relink cost). "pipeline" =
`examples/perf_corpus` total over the 62 x86-64 datatests (no oracle spawns).

| # | change | suite | rebuild | pipeline | notes |
|---|--------|------:|--------:|---------:|-------|
| 0 | baseline @ f59dc35 | 51.9s | 23.6s | 8.0s | corpus test 26.5s — of which oracle spawns ~23s (0.1–3s each; the 0.1s first sample was a small-fixture outlier) |
| 1 | `2518317` merge: incremental full-membership map | — | — | 4.2s | merge_same_storage rebuilt rep→members (O(varnodes)) once per union; modulo fixture 4025→1109ms |
| 2 | `223f856` heritage: phis-by-block index, no ops clones | — | — | 2.7s | rename() rescanned the whole phi map per CFG edge |
| 3 | `95723c7` oracle disk cache + ccompare LCS intern/trim | 26.4s | — | — | build/oracle-cache keyed on (capture mtime+len, fixture bytes, args); corpus test 26.5→6.0s warm |
| 4 | `2ced853` per-process Spec cache in tests | 23.1s | — | — | .sla parse ~0.5–1s each; decompile_corpus paid 6× |
| 5 | `c3d8c79` dev profile: line-tables-only + opt-level 1 | **13.0s** | **11.6s** | 0.46s | debuginfo dominated GNU ld relink of 16 test binaries; opt1 cold build 34→37s |

**Net: one loop iteration (rebuild + suite) ~75s → ~25s (3×).** The decompiler pipeline
itself (what `decompile_corpus`/graph-heavy fixtures exercise) is ~17× faster over the
corpus (8.0s → 0.46s).

## Tools added (all inert unless enabled)

- `MOSURA_PERF=1` — per-action / per-rule / per-print-substep wall-clock accounting
  (`decompile::action::perf`), dumped by `examples/perf_corpus`.
- `cargo run -q --example perf_corpus [stem]` — per-fixture build/decompile/print timing
  over the x86-64 datatests, worst first; no oracle spawns.
- `build/oracle-cache/` — oracle stdout cache (self-invalidating; `rm -rf` to clear).
- `mosura::speccache::get(path)` — per-process parsed-`.sla` cache for tests.

## Next candidates (measured, unexploited)

- disasm_golden 2.3s / decompile_corpus 2.25s are now the slowest binaries; both are
  dominated by real work (254 goldens; 62 pipelines + ccompare) at opt1.
- `ActionPool::apply` re-collects + sorts every op id each fixpoint round and re-walks
  every op even when a round changed nothing new — a Ghidra-faithful worklist would need
  care to stay output-identical; at opt1 the pool is ~15% of pipeline time.
- The heritage alias probe (`ActionHeritage` first call) fully decompiles a clone of every
  function — inherent to the current design; it rides all pipeline wins.
- A fast linker (mold/lld, needs install) would cut the 11.6s rebuild further — link is
  ~80% of it.
- If the loop only needs the decompile-track tests, `cargo test -p mosura --test
  decompile_corpus --test ir_parity --test disasm_golden` avoids relinking/running the
  other 13 binaries.
