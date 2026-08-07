---
name: war2-exact-reference-mismatch
description: The WAR2 EXACT headline compares against RAW on-disk bytes while mosura decompiles the LE-FIXUP-APPLIED image — any relocated operand is scored MISMATCH even when the recompile is byte-perfect.
metadata: 
  node_type: memory
  type: project
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-29T13:04:34.114Z
---

The "N of 1286 EXACT" headline and mosura read the binary through **different references**, and the
difference is exactly the LE fixup delta (+0x80000 for WAR2.EXE).

- mosura decompiles the image **with LE fixups applied** (`load_le`, `cbd6295`) — see
  [[war2-le-fixups-root-cause]].
- `war2-survey/compare.py` slices the **raw on-disk bytes** via
  `wardiff.LEBinary.slice_at_linear(va, len)`.

Found 2026-07-29 on `FUN_0005f84c` (`mov eax,0x88d0c; ret`), the task-#1 target. After `6e1b113` the
emitted C is `xunknown4 FUN_0005f84c(void) { return 0x88d0c; }`; real wcc386 compiles it to
`b8 0c 8d 08 00 c3`, **identical to the manifest's `orig_hex`** (which mosura writes from the
fixup-applied image). `compare.py` nonetheless reports `MISMATCH @+3`, because its target reads
`b8 0c 8d 00 00 c3` — the un-relocated operand `0x8d0c` instead of `0x88d0c`. Outside the 4-byte
immediate the two are identical.

The existing `RELOC_EXACT` masking cannot fire: the original's fixup lives in the LE fixup table,
which `slice_at_linear` does not consult, and the candidate `.OBJ` has no FIXUPP because mosura
renders the relocated address as a bare integer literal rather than a symbol reference.

**How to apply:** never quote an EXACT/RELOC_EXACT count without stating which reference produced
it. Two fixes, not exclusive — (1) measurement: score against the fixup-applied bytes (the
manifest's `orig_hex` column is exactly those bytes, so no new tooling is needed); (2) emitter, the
honest end state: render a relocated address operand as a symbol/pointer so wcc386 emits a FIXUPP
and the existing masking fires on both sides. Related: [[war2-recompile-survey]],
[[war2-byte-exact-campaign]].
