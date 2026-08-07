---
name: subregister-write-not-merged
description: "⭐ ROOT CAUSE 2026-07-29: a sub-register write (AL) is NOT merged into the containing register read (EAX), so the wide read binds to a stale def. Causes WRONG CODE in 92 WAR2 functions / 246 dropped calls. This IS foundation-menu item A (coarse-SSA / normalizeWriteSize), now measured."
metadata:
  type: project
---

# The AL-into-EAX gap: a sub-register write the wide read never sees

mosura heritages each exact `(space, offset, size)` as its **own SSA location**, so `r0x0:1` (AL)
and `r0x0:4` (EAX) are separate variables unless width-normalization unifies them. It does not, on
the first pass, for this shape.

## The evidence (WAR2 `FUN_0001bd30`, baseline master, no patches)
Original: `xor eax,eax` / `mov al,[esi+0x1f]` / `cmp eax,0x5c` / `jne`.
mosura IR:
```
0x1bd56:139  r0x0:4(0x1bd56:139) = INT_XOR r0x0:4 r0x0:4     ; eax = 0
0x1bd58:148  r0x0:1(0x1bd58:148) = COPY u0x17000:1           ; al = loaded byte
0x1bd5b:149  u0x66100:4          = COPY r0x0:4(0x1bd56:139)  ; cmp reads EAX
```
**The 4-byte read binds to the XOR def and ignores the 1-byte write in between.**

Everything after is correct logic on a false premise, and every step is visible in the trace:
1. `earlyremoval` destroys the AL write — no readers, because the wide read never referenced it.
2. `equal2zero` rewrites `INT_EQUAL (x-0x5c),0` -> `INT_EQUAL #0x0:4 #0x5c:4` (constant 0 for eax).
3. `constfold` -> ZF = `COPY #0x0`; `propagatecopy` carries it; the CBRANCH condition becomes `#0x1:1`.
4. `ActionDeterminedBranch` (which only fires on a CONSTANT condition) correctly deletes the
   now-unreachable loop body — **3 real CALLs + both conditional stores**.

⇒ `determinedbranch` is the **executioner, not the culprit**. Do not "fix" it.

## Why it is not already handled
`normalize_write_size` IS implemented (`heritage.rs:712`) — Ghidra `normalizeWriteSize`,
heritage.cc:416 — but its driver `normalize_ranges` is scoped to **widening re-entry only** and is
documented in-file as "a dormant no-op today". First-pass normalization is left to pass-0 batch
heuristics (`normalize_read_size`'s single-write-width hack + `refine_overlaps`' register-only
Normalize mode), which do not cover a narrow write feeding a wider read of the same base.

## Why it matters
**This is foundation-menu item A (coarse-SSA / normalizeWriteSize) with a price tag attached:**
92 of 1286 WAR2 functions emit fewer calls than Ghidra, 246 calls missing, all rendered correctly by
Ghidra. It is no longer an abstract investment choice.
Plausibly also explains the stack-pointer patch's 12-call regression (same shape: a read resolving to
a stale def, then a branch wrongly determined) — which would mean fixing A subsumes it. NOT verified.

## Class confirmation (2 specimens in depth + a population check)
`0003dd60` (the loudest: Ghidra 31 calls, mosura **0**) has the SAME chain as `FUN_0001bd30`,
verified by trace not inferred: `u0x66100:4 = COPY r0x0:4(0x3dd67:21)` -> `COPY #0x0:4`, i.e. the
4-byte read binds to `xor eax,eax` and ignores the `mov al,[ebx+0x802c8]` at 0x3dd69; then
`equal2zero` -> `INT_EQUAL #0x0:4 #0x1:4` -> `constfold` -> constant CBRANCH -> body deleted.

**The trigger is a compiler idiom**, which is why the class is large: Watcom's zero-extended byte
load `xor r32,r32 ; mov r8,[mem] ; cmp r32,imm ; jcc`. In `0003dd60` it repeats for every field
tested (0x802c8, 0x80248, 0x80258, 0x80278, ...), and the first one skips the whole 0x2b2-byte body.

Population check over raw bytes (crude pattern, so a LOWER bound):
- deficit functions containing the idiom: **47/92 (51%)**
- control (no deficit): **119/1194 (10%)**
⇒ **5x enrichment.** Strong evidence it drives a large share of the class; NOT proof it is the sole
cause — ~45 deficit functions did not match the crude pattern and may have other triggers.

Work queue: `scratchpad/deficits.txt` (92 VAs, worst first).

Found by query, no ad-hoc probe: `MOSURA_OPACTION=1` (action-level, [[print-raw-has-no-dead-filter]])
then `MOSURA_TRACE=1` (rule-level). Reference = [[war2-per-function-ghidra-oracle]].

Related: [[absolute-vs-differential-wrongcode]], [[war2-stackptr-wrong-code]], [[bounded-levers-exhausted]].
