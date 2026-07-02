# Performance log — porting-loop iteration cost

Goal: the porting loop's iteration is dominated by running mosura (debug-build test
suite). This log records each measurement as optimizations land, all **byte-neutral**
(identical test results, identical corpus scores, 254/254 disasm goldens).

Machine: 5 cores, linux 6.12. All timings are `cargo test --workspace` wall time with
the build already warm (compile cost noted separately when it changes).

| # | change | suite wall | decompile_corpus | disasm_golden | lib tests | ir_parity | notes |
|---|--------|-----------:|-----------------:|--------------:|----------:|----------:|-------|
| 0 | baseline @ f59dc35 (debug, no cargo profile tweaks) | 51.9s | 26.51s | 5.87s | 5.15s | 3.18s | oracle `capture --c` ~0.1s/fixture (~6s of corpus) |

## Notes

- Corpus = ~60 x86-64 datatests: `build::raw_funcdata_flow_image` + `pipeline::decompile`
  + `printc::print_c` per fixture, plus one `oracle/capture --c` spawn each.
- Cold `cargo build --workspace --tests`: 34.4s.
