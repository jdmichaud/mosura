---
name: plus3-is-lea-esp-prologue-order
description: "The survey's biggest mismatch bucket (+3 bytes on 216 functions) is `lea esp,[ebp-N]`, caused by register saves landing after the frame setup instead of before"
metadata:
  type: project
---

**⭐ The largest single byte-delta bucket in the WAR2 survey — +3 bytes on 216 functions — is
`8d 65 fc` (`lea esp,[ebp-4]`). Measured 2026-08-11 by diffing idx 00045/00046/00050 against
their originals.**

```
original    52 | 55 89e5 | a1.. 31d2 e8.. 8915.. | 5d 5a c3
            push edx ; push ebp ; mov ebp,esp ; ... ; pop ebp ; pop edx ; ret

candidate   55 89e5 | 52 | a1.. 31d2 e8.. 8915.. | 8d65fc | 5a 5d c3
            push ebp ; mov ebp,esp ; push edx ; ... ; lea esp,[ebp-4] ; pop edx ; pop ebp ; ret
```

Same instructions, same order, same count — except the original saves its preserved register
**before** establishing the frame, so its epilogue is bare pops. Ours saves it **after**, which
forces wcc386 to restore ESP with a 3-byte `lea` before popping.

**This also explains why ZERO of the 2834 mismatches have equal length.** A 3-byte insertion near
the top shifts every later byte, so these functions score 0–8% byte-match while being otherwise
identical instruction-for-instruction. Any "% match" reading of this population is measuring
alignment, not correctness — do not use it to rank work.

**NOT a mosura defect, as far as measured.** The emitted C is semantically right, and the
`#pragma aux ... modify [...]` work (`c5b8ac5`) already fixed the surrounding shape: the candidate
now computes `31d2` before the call and stores `8915` after, matching the original's dataflow. The
residual is purely prologue/epilogue *scheduling*.

Compiler-version sensitivity is confirmed but the rule is NOT identified. Open Watcom 2.x on the
same source produces a third shape entirely (`55 89e5 a1.. e8.. 31c0 a3.. 89ec 5d c3` — no EDX
save at all), so this scheduling is not something our C controls.

**SETTLED 2026-08-11 — WATCOM 10.0a CANNOT PRODUCE THE ORIGINAL PROLOGUE.** A/B'd the same
emitted C under real 10.0a via dosemu across `-of+ -onatx`, `-of`, `-of+ -onat`, `-of+ -oaxt`,
`-of+ -zp4`, `-of+` without `-s`, and `-of+ -od`:

```
ORIG   52 | 55 89e5 | ... | 5d 5a c3           save FIRST, then frame        25b
-of+   55 89e5 | 52 | ... | 8d65fc 5a 5d c3    frame first, save after + lea 28b
-of    52 | ... | 5a c3                        save first, NO frame          21b
```

Every framed variant puts `push ebp ; mov ebp,esp` first and the register save after, which is
exactly what forces the 3-byte `lea esp,[ebp-N]`. Every frameless variant puts the save first but
emits no frame. **The frameless build is byte-identical to the original apart from the missing
frame**, so the emitted C is right and only the code generator's prologue SCHEDULING differs.

⇒ The 216-function `+3` class is a TOOLCHAIN question — which wcc386 built WAR2 — and is NOT
mosura's to fix. Direct evidence for the 10.0a vs 10.0-beta known-unknown in
`war2-survey/BYTE-EXACT-PLAN.md`. Do not spend decompiler effort here; spend it on obtaining the
other compiler.

Recipe for repeating the A/B (the harness is fiddly): the DOS batch MUST carry the environment
header or `WCC386` is not on PATH and dosemu exits silently with no output —
`@echo off / SET WATCOM=F:\ / SET PATH=F:\BINB;F:\BIN;F:\BINP / SET INCLUDE=F:\H / G:` — the
working directory must be under the project root (a `/tmp` path is not reachable from the guest),
and wcc386 writes objects LOWERCASE.

**SUPERSEDED NEXT-EXPERIMENT LIST** (kept for the record):
**NEXT EXPERIMENT** (do not skip to a fix): decide between
1. compiler VERSION — the 10.0a vs 10.0-beta known-unknown in `war2-survey/BYTE-EXACT-PLAN.md`.
   The systematic uniformity across 216 functions fits a version difference well. No 10.0-beta
   wcc386 is on disk; obtaining one is the blocking step.
2. a wcc386 FLAG combination that moves the register save ahead of the frame setup.
3. a postlink normalization, only if 1 and 2 both come back negative — the original genuinely
   lacks the `lea`, so this would be papering over a real codegen difference.

Related: [[war2-byte-exact-campaign]], [[war2-recompile-survey]],
[[gate-what-you-measured-not-what-you-guessed]], [[goal-is-the-binary-not-ghidra]].
