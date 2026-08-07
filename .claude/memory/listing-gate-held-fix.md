---
name: listing-gate-held-fix
description: "The listing fix is BUILT and HELD in held-patches/listing-command-channel.patch, blocked by the inline-parameter thunk; the gate is committed RED and #[ignore]d."
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-06T18:56:30.478Z
---

2026-08-06, branch `analysis-port`. Two commits: `9d2f0e9` (gate) and `71876a2` (diagnosis +
held patch). Suite 625/0/3 at both.

`ground_truth_parity::recovered_functions_are_in_the_listing` is committed **FAILING and
`#[ignore]`d** — 5 violations of a population of 386, each named with its cause. The point of
landing it red is that the gate's ability to fail is proved **by git history** rather than by a
revert-check someone has to trust, while the workspace stays green. Un-ignore it in the same commit
that lands the fix; it goes 5 -> 0 in one step.

The fix itself is in `held-patches/listing-command-channel.patch` (388 lines, applies cleanly at
`71876a2`). It closes [[command-vs-notification-channel]] and [[r-min-range-iteration-misport]] and
deletes `SCHEDULED`/`PROPOSED`. It is **blocked**, not abandoned: on the war2 MZ stub it decodes an
inline call parameter and destroys a real instruction —
[[war2-mz-inline-call-parameters]]. Wrong code, so the "a faithful port lands" rule does not apply.

**How to apply:** the unblocker is a **fall-through override model** (`Instruction.getFallThrough()`
as analysis output, not opcode-derived), MVE first, and never by special-casing the `0x13a56` shape.
Do not raise `pe_mz_convergence_parity`'s `max 8` to land the patch — that bound is holding wrong
code, not a cosmetic divergence.
