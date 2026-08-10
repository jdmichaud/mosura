---
name: perf-constants-are-configuration-scoped
description: "A per-call cost measured on one (language, compiler spec) is not that cost on another — resolve_cspec spans 1.14ms to 118.6ms across four configurations, and extrapolating produced a confident wrong root cause for WAR2"
metadata:
  node_type: memory
  type: feedback
---

**A performance constant measured on one `(language_id, compiler_spec_id)` says NOTHING about
another until you measure that pair too.** Before carrying a per-call cost from the binary you
profiled onto the binary you care about, check that both take the same path.

**Why, concretely (2026-08-10).** `lang::resolve_cspec` re-walked every processor directory and
re-XML-parsed every `.ldefs` on each call. Measured on `mingw_hello.exe` (`x86:LE:64` + `windows`)
at **34.7–118.6 ms/call**, it was 94% of Constant Propagation. Real defect, correctly found, fix
landed (`f435e89`, `5760850`). Then I extrapolated that constant onto WAR2 to explain its ~1.5 s
per-invocation floor — and WAR2 **never pays it**:

```
x86:LE:64:default  windows   118.6 ms      x86:LE:32:default  watcom     1.14 ms
x86:LE:64:default  gcc        42.1 ms      x86:LE:32:default  gcc       34.7 ms
```

`resolve_cspec` short-circuits at `lang.rs:49` on the mosura-authored `specs/x86-32-watcom.cspec`
and returns **before the tree walk starts**. WAR2 LE is `x86:LE:32:default` + `watcom`
(`loader/le.rs:243`), so its per-walk setup is ~1.7 ms — **22× smaller**. A factor of ~100 hides
between two rows of the same function. Correction: `22f7216`.

**What exposed it:** the lead cross-checked my story against profile data I had not seen and it
failed (`ms/range` spanned 4.4 → 1558, not a constant). ⭐ **A mechanism can be right, measured, and
fixed while the account of WHERE it bites is wrong.** The fix's own numbers cannot catch that —
they are from the configuration that does pay.

**Two sub-lessons from the same episode:**
- **Never infer start-location count from the trace's `ranges=` column.** Measured: `ranges=2 ->
  nloc=4`. Pass 1 of `findLocationsRemoveFunctionBodies` contributes function entries that are
  nobody's range minimum. That bad bridge is what let the wrong story look checkable.
- **Counter beats inference for "how often is this called".** `integer_arg_registers` is once per
  `flow_constants` (126 calls / 126 walks), not per call site. One `AtomicU64` settled a question
  two people had hypotheses about.

**How to apply:** when a fix is justified by a per-call constant, name the configuration the
constant came from **in the commit message and the doc comment**, and put the per-configuration
table where the next reader will hit it. If the target binary is a different `(language, cspec)`,
measure that pair — it costs one probe and seconds. Predict only for configurations you measured.

Related: [[numbers-stale-unless-sha-stamped]] (a number is stale unless stamped — this is its
sibling: a number is *scoped* unless the configuration is stated),
[[gate-what-you-measured-not-what-you-guessed]], [[could-it-have-come-out-otherwise]],
[[make-the-uncached-path-private]].
