# Performance log — porting-loop iteration cost

Goal: the porting loop's iteration is dominated by running mosura (debug-build test
suite). This log records each measurement as optimizations land, all **byte-neutral**
(identical test results, identical corpus scores, 254/254 disasm goldens).

Machine: 5 cores, linux 6.12. All timings are `cargo test --workspace` wall time with
the build already warm (compile cost noted separately when it changes).

| # | change | suite wall | decompile_corpus | disasm_golden | lib tests | ir_parity | notes |
|---|--------|-----------:|-----------------:|--------------:|----------:|----------:|-------|
| 0 | baseline @ f59dc35 (debug, no cargo profile tweaks) | 51.9s | 26.51s | 5.87s | 5.15s | 3.18s | oracle spawns are ~23s of the corpus test (0.1–3s each), NOT ~6s as first sampled |
| 1 | merge: incremental full-membership map (`2518317`) | — | — | — | 2.88s | — | modulo fixture 4025→1109ms; corpus pipeline 8.0→4.2s (perf_corpus) |
| 2 | heritage: phis-by-block index, no ops clones (`e40f9c9`-ish) | — | — | — | — | — | corpus pipeline 4.2→2.7s (some run noise) |
| 3 | oracle disk cache + ccompare intern/trim | 26.4s | 5.97s (warm) | 5.74s | 3.11s | 1.97s | build/oracle-cache; cold first run unchanged |

## Notes

- Corpus = ~60 x86-64 datatests: `build::raw_funcdata_flow_image` + `pipeline::decompile`
  + `printc::print_c` per fixture, plus one `oracle/capture --c` spawn each.
- Cold `cargo build --workspace --tests`: 34.4s.
