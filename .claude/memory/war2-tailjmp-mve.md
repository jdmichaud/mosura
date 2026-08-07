---
name: war2-tailjmp-mve
description: "The tailjmp ground-truth MVE — a Watcom fixture whose functions are reachable only by a tail-call jmp; built WITHOUT -oc, which is what enables the shape."
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-05T10:46:41.241Z
---

`oracle/ground-truth/src/tailjmp.c` + `tailjmp_cstart.asm` (landed `9d9ae35`, 2026-08-05) is the
self-compiled repro for shared-return tail-call function discovery. Gated by
`ground_truth_parity` (recall) and `ground_truth_parity::tail_jump_shared_return` (mechanism: the
inbound jump must also be retyped `UNCONDITIONAL_CALL` by the CALL_RETURN override).

Two traps worth remembering for any future Watcom fixture:

- **`-oc` suppresses tail calls.** Every other watcom-x86-32 fixture is built with `-oc`, which
  disables Watcom's `call X; ret` → `jmp X` rewrite — i.e. it suppresses exactly this shape.
  `build_watcom` now takes per-program flags (`build_watcom tailjmp ""`); the default stays `-oc`
  so the existing binaries remain byte-identical.
- **wcc386 will not emit a FORWARD tail-call jump from C.** It always lays the callee adjacent to
  or before its caller, and when adjacent it elides the jump entirely — which also makes the
  callee fall-through-only, so it becomes unrecoverable by any analysis and the recall gate fails
  for the wrong reason. The forward arm lives in the `_cstart.asm` stub, where emission order is
  the written order.

Related: [[shared-return-cursor-cache-is-semantic]], [[mve-first-then-solve-the-mve]],
[[war2-issues-become-source-tests]].
