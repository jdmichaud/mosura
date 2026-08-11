---
name: byte-exact-class-map-2026-08-11
description: "Measured sizes of every byte-exact defect class at M1 — no single class is worth more than 216 functions, and the biggest may be a toolchain issue"
metadata:
  type: project
---

**Measured 2026-08-11 at M1 (`a3bb2b2`, 133 byte-clean of 1633 attributable). The point of this
file: STOP LOOKING FOR ONE BIG LEVER. There isn't one.**

## The distribution

Every one of the 2834 mismatches differs from the original in LENGTH — **zero** are same-length-
wrong-bytes. Delta concentration:

| delta | n | share |
|---|---|---|
| +3 | 216 | 7.9% |
| +1 | 106 | |
| +2 | 82 | |
| top 12 deltas combined | 924 | 34% |

Long-tailed. `indirect_call` (2182) and `void_proto` (961) look huge but are weak signals —
`indirect_call` fires on any `func_0x` mention, i.e. "this function calls something", and
`void_proto` on any `FUN_x(void)`.

## Classes with a measured size

| class | n | status |
|---|---|---|
| `+3` = `lea esp,[ebp-N]`, register saved after the frame | 216 | root-caused, see [[plus3-is-lea-esp-prologue-order]]. May be a COMPILER-VERSION artifact, not ours. |
| `pc*` global declared `int *` instead of `code *` | 53 | FIXED `bd556f7`/`171b785`, verified against real wcc386 |
| extents SHORT vs the tracker's true size | 39 (28 by exactly 1 byte) | a 1-byte truncation cuts the last instruction and the decompile is GARBAGE — `0x51c27` is `e9 0c610100` (a 5-byte tail-call shim) truncated to 4 and decompiled as `iRam… = iRam… + 1` |
| `ret imm16` (stack parameter, callee-pop) recovered as `(void)` | 31 | the RETURN operand IS the parameter count; not yet used |
| COMPILE_FAIL total | 50 | ceiling on that whole lane |
| thunks | 9 | mostly the truncated-extent class above |

Optimistically these sum to ~340 potential, overlapping, and only functions whose LAST defect falls
actually flip. **Without cracking `+3`, 300 byte-clean is not reachable** — and `+3` may be a
toolchain question (which wcc386) rather than a decompiler one.

## The Phase-1 lane is the honest target

264 functions the tracker proves reproducible; we hold 83 (34 EXACT + 49 RELOC_EXACT), 177 miss,
4 COMPILE_FAIL. `void_proto` is on 110 of the 177. **warcraft2-re's `src/util/*.c` is proven
byte-exact C for these** — diffing mosura's output against it is the sharpest oracle available for
the watcall path, and far better than guessing. Two diffs done that way immediately explained two
failures (the stack-param stub, the truncated shim).

## What the diffs already settled

- `#pragma aux ... modify [eax]` on a callee EQUALS the compiler's default, so emitting it is a
  no-op — which is why the pragma experiment gained 0 (and lost 7 where the scan over-approximated).
  Reverted at `7c8c823`. Do not retry without an exact preservation proof.
- mosura already nails the common wrapper shape (`FUN_00010d1c` is RELOC_EXACT and matches
  warcraft2-re's `cwrap1.c` almost token for token).

Related: [[war2-byte-exact-campaign]], [[plus3-is-lea-esp-prologue-order]],
[[void-proto-is-body-elimination]], [[war2-function-set-ground-truth]],
[[gate-what-you-measured-not-what-you-guessed]].
