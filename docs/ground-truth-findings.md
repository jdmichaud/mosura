# Ground-truth recompile — findings (branch `gt-recompile`)

*What decompiling our own binaries shows, read against the source. Instrument:
`recompile::groundtruth` (`cargo run --release --example gt_recompile`), per-function three-way
files under `build/gt-recompile/<program>/<function>.3way.txt` — original source, our C, aligned
instructions. Numbers from the 2026-08-23 run: host gcc 14, `-O2`, 20 programs, 70 functions,
937 original instructions, **WGSS 0.288**, 17 EXACT.*

## What the instrument removes, and what it leaves

With the compiler held fixed, the score measures the decompiler alone, and the class profile is
WAR2's: selection 23 %, extra 21 %, missing 16 %, operand-form 13 %, regalloc 10 %. Three
instrument artifacts were found and removed before reading anything (each would have looked like
a decompiler defect): unprototyped callee declarations (gcc zeroes `EAX` before every
unprototyped call — the first "extra `XOR R,R`" mass, 51 rows, was this), `extern long
syscall();` in the prelude (same mechanism), and arity mismatches between a call site and the
callee's recovered signature (now re-declared at the call site's arity, so the bytes show the
defect's true cost instead of the fallback's). Two corpus-style artifacts remain and are excluded
from the reading: the programs use `volatile` locals to defeat gcc's folding (a decompiler cannot
know `volatile`; `tables/_start` reloads `[RSP+x]` where we pass constants), and every `_start`
renders the `syscall` instruction as a call (15 missing `SYSCALL` rows / 9 functions — WAR2's
`swi`/`int 21h` is the same class).

## Mechanisms, read against source

| # | mechanism | source | our C | bytes | reach here | WAR2 |
|---|---|---|---|---|---|---|
| 1 | **callee-clobber model.** gcc `-fipa-ra` keeps a caller's value in a register it *knows* the callee doesn't clobber; the convention says every call kills it. | `sum_to`: `for (i…) acc += square(i);` — `i` lives in `EDX` across the call | `while ((int4)uVar1 != (int4)extraout_RDX)` — the counter comes back as a call-produced value, the increment is lost: **wrong code** | the loop is gone; every caller of a small leaf is affected | `cube`, `sum_to`, `tables/_start`, … (the `extraout_*` reads) | the survey recovers per-callee `modify` lists for Watcom and it is what makes WAR2's calls come out right; this says callee-clobber recovery belongs in the decompiler (P2), not in the survey |
| 2 | **return width over-widening.** The recovered return is the register's full width. | `static int l1(int x) { return l2(x) - 9; }` | `int8 FUN_…(void)` | `CDQE` after every result: 12 rows / 8 functions; `MOVSXD` at call sites 9 / 7 | all of `deepchain`, `arith` | WAR2's `return-width` family (EAX vs AL), already an axis there — the same defect one level up |
| 3 | **whole-TU facts lost by per-function recompilation.** The originals are `static` and gcc elides the ABI stack re-alignment around their calls; our one-function-per-TU makes every function external. | `static … l1` | `FUN_…` (external) | `SUB/ADD RSP,8`: 21 rows / 9 functions; `PUSH/POP RBX` | `deepchain`, every small caller | a limit of the METHOD, not the decompiler: Watcom's TU-level effects (`-oe` inlining of statics, pooling order) are the P4 "TU grouping" question; per-function recompilation cannot reach them |
| 4 | **signedness inference.** Bit operations on a parameter make it `uint`. | `classify(int x, int y)`: `y \| 256` | `uint4 param_2`: `param_2 \| 0x100` | `OR AH,1` (int) vs `OR EAX,0x100` (unsigned) | `classify` | WAR2's typing rows (operand-form / selection) |
| 5 | **argument arity at call sites.** Leftover registers read as arguments, or a parameter the callee never reads. | `dense(a, c)` | `func_0x…(7, 5, extraout_RDX, xVar1)` | extra argument moves; with mechanism 1 it is the same root | 16 of 70 functions had a call site disagreeing with the callee's signature | WAR2's `extra`/`missing` interface mass (P2) |
| 6 | **return-type disagreement.** A callee recovered as `void` whose caller uses its value. | `is_even` ↔ `is_odd` | `void FUN_…` vs `iVar = func_0x…()` | return setup missing | `recursion` | P2 |
| 7 | **constant propagation past memory the compiler kept.** (corpus artifact: `volatile`) | `volatile int a = 7` | `func(7, …)` | missing stores / reloads | `tables/_start` and all `_start`s | real only for WAR2's volatile globals (sb95: five) |

## What this says

1. The three largest mechanisms (1, 2, 5) are **interface recovery** — prototypes, return widths,
   callee clobbers — exactly the P2 class the architecture doc calls "the largest measured defect
   class, and a correctness bug rather than a cosmetic one". On this corpus it is not cosmetic:
   `sum_to` is wrong code.
2. Mechanism 1 is the decisive one for gcc-built programs and it has a known answer in this
   repo: the WAR2 survey's recovered `modify` lists. Moving callee-clobber recovery into the
   decompiler (decompile callees first, record the registers they actually write, use that set
   at the call site instead of the convention's `killedbycall`) fixes 1 and most of 5 at once,
   for both gcc and Watcom — and is the first thing this branch should build, because the
   instrument can then measure it against source immediately.
3. Mechanism 3 bounds the method: a per-function recompile can never reproduce TU-level
   decisions. For WAR2 that is a ceiling to *name* (how many functions show it), not to fix.
4. The corpus must grow toward WAR2's loss band (20–200-instruction functions, structs, globals,
   compare ladders, strings, no `volatile`) before its WGSS means anything in absolute terms; at
   937 instructions it is a mechanism finder, not a score.

## Next on this branch

- Callee-clobber recovery as a decompiler feature (mechanism 1 + 5), measured here first.
- Return-width recovery from the callers' reads (mechanism 2).
- Two or three era-style programs (no `volatile`, no `_start` shim in the scored set) so the
  size mix matches WAR2's; score `_start`/shim functions separately.

## Update (2026-08-23): the functional oracle, and the first transfer test

**Functional check.** The programs are freestanding and return their result through the exit
status, so the instrument now links every recompiled function into one program and RUNS it
against the original (`recompile::groundtruth::functional_check`: the original source compiled
once more with `static` stripped is the harness — it supplies `_start`, the data and the
source-named calls; our objects come first under `--allow-multiple-definition`; our address-named
globals map onto the original's data symbols with `--defsym`; compiler-private constants with no
symbol are DEFINED from the image bytes). Result on the 20 programs: **10 PASS, 10 FAIL** —
`arith`, `arith64`, `floats`, `fnptr`, `irreducible`, `ptrarith`, `recursion`, `strdata`,
`structval`, `varargs` compute a different result from the original. The gate now treats a
PASS → FAIL as a regression. This is the oracle the similarity score cannot be: `sum_to` went
from one wrong rendering (`extraout_RDX`) to another (an off-by-one: `iVar3 = iVar3 + 1` after
the call and `!= iVar3 + 1` in the condition) while its similarity moved by a few rows.

**Mechanism 1, acted on and measured.** `guard_calls` already downgrades a convention-killed
register to preserved when a complete walk of the callee never writes it, but refused every
register in the convention's OUTPUT list; on SysV x86-64 that is `RDX` (the high half of a
128-bit return), so the evidence was ignored exactly where `-fipa-ra` had relied on it. The
exception now holds for the PRIMARY return register always and for all return storage when the
evidence is absent, and releases secondary return storage on a complete never-written walk.
Control corpus: `cube` and `sum_to` regain their parameters (`return iVar1 * param_1`, the loop
counter back in the loop); no function's functional verdict changed (the two are still FAIL for
other reasons), and similarity fell slightly because gcc, recompiling our single-function TU,
cannot know `square`'s clobbers and must now save `R12/RBP/RBX` around the call — mechanism 3.
**WAR2 zc34 vs zc33: byte-identical, 0 movers** — Watcom's second return register was never
gated in practice. A correctness fix at zero WAR2 cost; nothing to land on master from it yet.

**Where this leaves the experiment.** Two things it has that WAR2 does not: a source to read
each divergence against, and a yes/no correctness oracle. Its list is now ten wrong programs,
each a decompiler bug with the source beside it. Its limits are also clear: gcc `-O2`'s
interprocedural optimizations (`-fipa-ra`, static-call alignment) cap what per-function
recompilation can match on this corpus regardless of the C, so its *similarity* is a weak
signal here; its *functional* verdict is strong.
