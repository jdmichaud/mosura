---
name: mosura-ships-its-own-pattern-constraints
description: "Function-start pattern lookup merges EVERY module's patterns dir — mosura's own specs/patterns adds the (x86:LE:32:default, watcom) node, so reading Ghidra's patternconstraints.xml alone says 'no watcom patterns' and is WRONG."
metadata:
  node_type: memory
  type: feedback
---

`pattern_dirs()` (`crates/mosura/src/analysis/analyzers/function_start.rs:286`) returns the SLEIGH
processor tree **plus** `specs/patterns`, mirroring `Patterns.java:42-55`, which merges the
`patternconstraints.xml` of every module into one decision tree. mosura's own
`specs/patterns/patternconstraints.xml` contributes exactly one node:
**`(x86:LE:32:default, watcom) -> x86watcom_patterns.xml`** — beyond-Ghidra, because Ghidra ships
no Watcom compiler spec at all.

Measured (`FunctionStartAnalyzer::for_program`, per kind):

```
x86:LE:32:default / watcom      -> Search, AfterCode, AfterData
x86:LE:32:default / gcc         -> all four
x86:LE:16:Real Mode / default   -> Search
```

**Why:** on 2026-08-10 I concluded "the Function Start Search block never runs on WAR2 LE, so a
new invocation after it is inert" from Ghidra's
`Processors/x86/data/patterns/patternconstraints.xml`, which lists only windows / borlandcpp /
borlanddelphi / gcc for `x86:LE:32:default`. The block in fact runs on WAR2 — the Watcom pattern
set is what took it from ~1303 to ~2900 functions. Same shape as the FID two-directory bug fixed at
`3fd317e`: **the vendored Ghidra directory is never the whole search path.**

⚠️ The disproof was already in my own output and I overrode it. A probe placed INSIDE the
`if any { … }` block printed a line for `watcom_hello.exe` — which can only happen when the block
RAN — and I read its `fs_created=0` (a 17-function hello-world where the patterns found nothing
new) as "the block was skipped". A measurement that contradicts a source-reading is the
measurement's win: reconcile them before concluding, and state which one the conclusion rests on.

**How to apply:** for anything keyed on `(language, compiler)` — patterns, FID databases, cspecs —
enumerate the ACTUAL search path in code, or call the lookup and print the answer. Never conclude
"no support for X" from the vendored tree. And distinguish "the stage did not run" from "the stage
ran and produced nothing": a count of zero does not tell you which.

Related: [[pattern-gate-cspec-routing]], [[gate-what-you-measured-not-what-you-guessed]],
[[executable-recipe-or-the-gap-is-invisible]].
