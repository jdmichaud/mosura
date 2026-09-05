---
name: pattern-gate-cspec-routing
description: "A gate on a Watcom fixture silently measures Ghidra's GCC pattern file — check the cspec routing (and whether recall is call-reachable) before trusting any function-start measurement."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-06T09:26:17.141Z
---

**Two ways a function-start pattern gate is VACUOUS while looking green.** Both were live in
`ground_truth_parity` on 2026-08-06 and both were found only by measuring, not by reading.

1. **Wrong pattern file.** The pattern-file decision tree is keyed on `(language, compiler)`, and
   `loader::watcom::compiler_spec_id` reads the **run-time copyright banner** — a string in the C
   run-time, not in compiler output. The ground-truth corpus links `option nodefaultlib` with a
   hand-written `_cstart_`, so **no fixture carries the banner and every Watcom ELF reports
   `cspec=gcc`**. Result: `specs/patterns/x86watcom_patterns.xml` had ZERO fixture coverage, and
   any gate written against a Watcom-compiled fixture was measuring `x86gcc_patterns.xml`.
   `--cspec watcom|gcc` / `Knobs::x86_32_cspec` (added `cd70db7` as an environment variable, a value since 2026-09-05) routes one binary through both.
2. **Call-reachable recall.** If every function in the fixture is called from `main`, the
   reference-driven analyzers recover them all and the pattern set is never load-bearing.
   Measured on `wprologue_sf` before the orphan existed: **15/15 recall and 0 spurious with the
   byte-pattern analyzers switched OFF.** A pattern gate needs an ORPHAN (nothing references it),
   the way `fnpattern.c` properties 2-5 specify.

**Why:** a pattern set can only be specified where BOTH recall and precision are decidable, which
is a self-compiled binary where every function is known — never WAR2 (its tracker covers 71.4%, so
a hit in a gap is undecidable). See [[war2-per-function-ghidra-oracle]] for the WAR2 side.

**How to apply:** before believing any function-start number, print `prog.compiler_spec_id` and
re-run with `Knobs::disabled_analyzers` (`--disable-analyzers`) naming the four byte-pattern analyzers. If the number does
not move, the gate is not measuring the pattern set. This is [[oracle-same-question-not-just-same-tool]]
in a new place: reading a green test is not enough, verify it was asked the right question.

Related: [[self-compiled-ground-truth]], [[war2-issues-become-source-tests]].
