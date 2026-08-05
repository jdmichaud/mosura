# mosura's function-start pattern module (BEYOND-GHIDRA)

Ghidra's **Function Start Search** analyzers find functions by recognising prologue byte
patterns, and pick the pattern file from `(language, compiler)` through
`Processors/<proc>/data/patterns/patternconstraints.xml`. `Application.findModuleSubDirectories(
"data/patterns")` merges the constraints file of **every** module that has one, so an extra module
directory is Ghidra's own extension point — not a modification of its files. This is that
directory (`crate::analysis::analyzers::function_start::pattern_dirs` appends it after the SLEIGH
processor tree, the same way `specs/` is appended for mosura-authored compiler specs).

## What is ours, and what is a port

| Thing | Status |
| --- | --- |
| `ghidra.util.bytesearch` engine (`crates/mosura/src/analysis/bytesearch/`) | faithful port |
| `FunctionStartAnalyzer` + its three siblings | faithful port |
| the `(language, compiler) -> patternfile` lookup | faithful port |
| **the `watcom` mapping entry** (`patternconstraints.xml` here) | **mosura's** |
| **`x86watcom_patterns.xml`** | **mosura's** |

## Why the Watcom entry exists

Ghidra ships **no Watcom compiler spec**, so `patternconstraints.xml` has no `watcom` node and a
strictly faithful port contributes exactly zero on a Watcom binary. Ghidra reaches WAR2's
prologues at all only because auto-detect labels the warcraft2-re ELF wrapper `gcc`; mosura's
loader correctly reports `watcom`.

## Oracle

**Not Ghidra.** The pattern contents are validated against

- the warcraft2-re expert function tracker (`analysis/decomp-tracker.csv`, 2120 hand-verified
  functions), and
- the self-compiled ground-truth program `fnpattern.watcom-x86-32` (`oracle/ground-truth/`),
  whose truth comes from the Open Watcom build, gated by
  `tests/ground_truth_parity.rs::function_start_pattern_search`.

`x86watcom_patterns.xml`'s header records the measurements that produced each pattern family,
including the gcc-vs-win comparison that was run before choosing.

## Additive, never substitutive

Nothing here replaces or edits a Ghidra file. Ghidra's `x86gcc_patterns.xml` stays live and is
what a program whose compiler spec is `gcc` still gets — including the Watcom ELF column of the
ground-truth corpus, whose `CompilerOpinion` says `gcc`. Deleting this directory returns mosura to
exactly Ghidra's behaviour.
