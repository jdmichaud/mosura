---
name: gauge-counting-traps
description: The subject absolute gauge had two OPPOSITE one-sided counting bugs; half-fixing a two-sided counter is worse than not fixing it.
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-29T18:01:15.118Z
---

`scripts/corpus-absolute-gauge.py` carried two counting bugs at once, in opposite directions
(found and fixed 2026-07-29, `68e7d7a` + `719d46f`):

- **TRAP 3** — `\b(?:FUN_|func_0x)` cannot match `thunk_FUN_00067d38(`: the char before `FUN_` is
  `_`, a word char. 30 Ghidra call sites invisible. mosura emits no `thunk_` name, so it was
  ONE-SIDED and manufactured surplus.
- **TRAP 4** — Ghidra names a thunk entry after its TARGET, so `FUN_00051c2c` comes back as
  `void thunk_FUN_00067d45(void)`; the own-VA definition-line filter didn't recognise it and scored
  that DEFINITION as a call.

**Why:** fixing TRAP 3 alone inflates the base deficit to a phantom 37 fns/69 calls and would have
sent a whole stage chasing nine already-correct functions. With both fixed the deficit is
bit-for-bit what the blind predicate always reported — base 28 fns/60 calls, Stage A 4 fns/9 calls,
same functions, same per-function counts. Only surplus (18 fns/45 calls → 4/17) and the
"% of Ghidra" totals were ever wrong.

**How to apply:** when you fix a measurement predicate, look for its OPPOSITE-SIGN twin before
quoting any new number, and verify the SET membership changed the way you expect — not just the
total. `--selftest` carries the positive and negative controls; the gauge also now reports any
column-0 line it drops that is not definition-shaped, so a new render shape announces itself.
Related: [[absolute-vs-differential-wrongcode]], [[measurement-determinism-first]],
[[numbers-stale-unless-sha-stamped]].
