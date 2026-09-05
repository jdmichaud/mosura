# `cp-floor-instrument.patch` — decompose the subject Constant Propagation floor

Diagnostic only. **Never land it**: it puts two `Instant::now()` pairs on the per-instruction path.

Applies cleanly to `46cccf5` and compiles (both verified).

```sh
git apply held-patches/cp-floor-instrument.patch
cargo build --release
MOSURA_ANALYSIS_TRACE=1 <your the subject LE run> > /tmp/subject-fc.log 2>&1
git checkout -- crates/mosura/src/analysis/symbolic.rs crates/mosura/src/analysis/analyzers/mod.rs
```

No new knob — it rides the `MOSURA_ANALYSIS_TRACE` you already set. The env var is read once per
walk and once per invocation, never per instruction, and every counter is a function-local: no
shared state, so it cannot turn the suite red under concurrency
(cf. `.claude/memory/inert-is-not-thread-safe.md`).

## What it prints

One line per analyzer invocation, and one per symbolic walk:

```
[cp] set=122 ranges=122 entries=122 uninit=33.093µs findloc=76.132µs nloc=122 flow=374.457714ms
[fc] start=140001000 visited=1  n_dis=1  t_arg=57.553046ms t_dis=72.757µs  t_ops=3.697µs   total=57.63533ms
[fc] start=140001010 visited=64 n_dis=64 t_arg=6.643µs     t_dis=6.977755ms t_ops=118.285µs total=7.388974ms
```

**The three `[cp]` phases account for the whole invocation**, so the 1.5 s is read off directly
rather than inferred from a shortfall. Verified on `mingw_hello.exe`: `uninit 33µs + findloc 76µs
+ flow 374.46ms` against the manager's `took=374.60ms`, and 126 `[fc]` lines for `nloc 122 + 4`.

## Reading it

| what you see | what it means |
|---|---|
| `findloc=` holds the time | **candidate 2** — `find_locations_remove_function_bodies`. Prime suspect inside it: `in_body.union(f.body())` over 3022 functions, where `AddressSet::add_range` re-sorts the whole vector on every insert (O(K² log K)), now that Part A populates bodies. Cross-check: `findloc` should scale with `entries=`, not with `set=`. |
| `flow=` holds it, and `t_dis` dominates the `[fc]` lines | **candidate 1** — the walk re-decodes raw bytes instead of reading the listing (`symbolic.rs:481`), bounded only by landing *exactly* on another function's entry (`symbolic.rs:478`). Same class as Part A, one layer down. Corroborate with `visited`/`n_dis`: ~40 µs per instruction was the mingw_hello rate, so ~37,000 decodes buys 1.5 s. |
| `t_arg` dominates | the compiler-spec setup — i.e. `f435e89`/`5760850` did **not** take on this target. Should be ~1.1 ms on the first walk and ~µs after, since `x86:LE:32`+`watcom` short-circuits (`lang.rs:49`). If it is ~35 ms, the run resolved `gcc`, not `watcom`. |
| `t_ops` dominates | neither candidate — the p-code interpretation itself, which nobody has suspected yet. |

`visited` far exceeding a plausible function size is independent evidence for candidate 1's
unbounded-walk half, regardless of which timer wins.

## Aggregating

the subject will emit one `[fc]` per walk across ~95 invocations, so expect a large file.

```sh
# where the time went, per phase, across the whole run
awk -F'flow=' '/^\[cp\]/{print $2}' /tmp/subject-fc.log | head -40
# the 20 most expensive walks
grep '^\[fc\]' /tmp/subject-fc.log | sed 's/.*total=//' | sort -rh | head -20
# total decodes across all walks — multiply by ~40µs for the candidate-1 prediction
grep -o 'n_dis=[0-9]*' /tmp/subject-fc.log | cut -d= -f2 | paste -sd+ | bc
```

## Caveat

Four clock reads per decoded instruction. At ~37,000 decodes that is ~3–7 ms against 1.5 s
(<1%), so it will not move the attribution — but do not quote `total=` as a clean timing.
