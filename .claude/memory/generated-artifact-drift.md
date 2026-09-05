---
name: generated-artifact-drift
description: A hand-edit to a GENERATED file survives only until the next regeneration — the E1052 double-park was caused by exactly that.
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-29T18:01:30.613Z
---

`<subject-survey>/prelude.h` is generated from the `PRELUDE` constant in
`crates/mosura/examples/corpus_emit.rs`, and every EMIT overwrites it. A `code`-typedef fix was
hand-applied to the generated FILE, measured (COMPILE_FAIL 75 → 29, E1052 47 → 0), and written up in
commit `26db108` as though it were the state of the tree — while the constant still said `void`. The
next EMIT silently restored `void`, 47 E1052 failures came back, and they were then re-adjudicated
as a decompiler ceiling against `docs/decompiler-nonbug-e1052-void-indirect-call-faithful.md`.

**Why:** a measured delta attached to a file nobody owns is not a result; it evaporates and the
symptom gets re-explained by whatever doc is nearest. The re-explanation is the expensive part.

**How to apply:** before recording a measurement, ask what WROTE the input that produced it and
whether that input is generated. Fix generated content at its source, give it a cheap regeneration
path (`corpus_emit --prelude-only <dir>`), and STAMP its hash into the artifact chain so a run can
never be attributed to an input it did not use (`compile.sh` writes `prelude_sha=` into
`.compile-complete`; `compare.py` stamps it into `results.tsv` and refuses to score on a mismatch).
Companion rule from the same incident: **a verified-faithful RENDER is a decompiler ceiling; whether
it COMPILES is a separate axis owned by the prelude/extern declarations, and is legitimately
fixable.** "Do not fix" binds the decompiler, not the harness.
Related: [[numbers-stale-unless-sha-stamped]], [[variablepiece-extended-cover]],
(subject-profile note `recompile-survey`).
