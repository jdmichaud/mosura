---
name: plus3-is-lea-esp-prologue-order
description: "The survey's biggest mismatch bucket (+3 bytes on 216 functions) is `lea esp,[ebp-N]`, caused by register saves landing after the frame setup instead of before"
metadata:
  type: project
---

**⭐ The largest single byte-delta bucket in the subject survey — +3 bytes on 216 functions — is
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

**⚠️ RETRACTED — IT IS NOT A COMPILER-VERSION ARTIFACT.** An earlier revision of this file
concluded "SETTLED: a toolchain question, do not spend decompiler effort here". That was wrong and
was based on flag A/Bs under 10.0a alone. **Tested directly against the 10.0 BETA**
(`~/.wine/drive_c/WBETA/BINNT/WCC386.EXE` under wine — the compiler this project already
fingerprinted, docs/watcom-10.0-beta-codegen.md): it emits **byte-identical output to 10.0a** for
this case, same frame-first prologue, same `lea esp,[ebp-4]`. Both compilers, one answer.

What IS established, by A/B under real 10.0a and the 10.0 beta:

```
ORIG    52 | 55 89e5 | ... 31d2 ... e8.. | 8915.. | 5d 5a c3        save FIRST, ONE xor   25b
ours    55 89e5 | 52 | ... 31d2 e8.. 31d2 8915.. | 8d65fc 5a 5d c3  frame first, TWO xor  28b
-of     52 | ... | 5a c3                                            save first, NO frame  21b
```

Two separate differences, and neither is the compiler:
1. **A MISSING CALL ARGUMENT.** Under `__watcall` EDX is the SECOND argument register, so the
   original's `xor edx,edx` before the call is argument 2 — the call is `f([g], 0)`. mosura emits
   `func_0x00059344(xRam0008126c)`, one argument. That is a recovery defect, not codegen.
2. **The prologue order** remains unexplained. NONE of these reproduced the original's
   save-before-frame form: `-of+`/`-of`/`-onat`/`-oaxt`/`-zp4`/`-od`/no-`-s`, two-argument call,
   a shared temporary for the 0, `#pragma aux` on the callee with explicit `parm caller [eax] [edx]`,
   and a self-`pragma aux` on the function under test.

Also measured: with `modify [eax]` on the callee, wcc386 still REMATERIALISES the 0 after the call
(two `31d2`) rather than holding it in EDX, where the original holds it. So the original's callee
contract differs from anything we have declared.

DO NOT record a conclusion here again without an A/B that includes the beta.

**FIVE COMPILERS, ONE ANSWER (2026-08-11).** Same emitted C, `-4r -fpi87 -s -of+ -onatx`:

| compiler | where | result |
|---|---|---|
| 10.0a retail | dosemu | `5589e552 ... 8d65fc 5a5dc3` |
| 10.0 Limited Availability (beta) | wine `C:\WBETA` | IDENTICAL |
| 10.5 | wine `C:\W105` | IDENTICAL |
| 10.6 | dosemu `C:\WAT106` | IDENTICAL |
| 11.0 | dosemu `C:\WAT110` | IDENTICAL |

All five put `push ebp ; mov ebp,esp` FIRST and the register save after, forcing the `lea`. The
original does the opposite. The version hypothesis is dead for the entire 10.0–11.0 lineage.

**9.01 TESTED TOO — SIX COMPILERS, ALL FRAME-FIRST.** 9.01 is the different codegen family per
the fingerprint doc, and it still puts the frame first:
`5589e5 a1........ e8........ c705........00000000 89ec 5d c3` (it materialises the constant with
`c705` instead of holding EDX, so its body differs — but the PROLOGUE order does not).

⇒ **No Watcom C/386 from 9.01 to 11.0 emits save-before-frame.** The `+3` class is not explained
by any compiler in the lineage, any flag, or any source shape tried.

**THE REMAINING HYPOTHESIS, and it is not about the compiler:** the ENTRY POINT. The original is
`52 | 55 89e5 | ... | 5d | 5a c3` and our candidate is `55 89e5 | 52 | ... | 8d65fc | 5a 5d c3`.
Strip the original's leading `52` and our `52`+`8d65fc`, and the remainders are IDENTICAL. So the
whole class may be an off-by-N function START, not a codegen difference — which is exactly what
(subject-profile note `tracker-anchors-mid-prologue`) warns about ("the tracker anchors save-first entries at
`push ebp`; score SHIFT-TOLERANTLY"). Test that before touching the decompiler again: re-score the
216 with a shift-tolerant alignment and see how many become clean.

**Staging 9.01 (the script cannot — floppy set, .WPK runtime):** `7z x` the archive, then `7z x`
`Disk01.img`; `WCC386.DOS` is UNPACKED (116 KB) — copy it to `C:\WAT901\BIN\WCC386.EXE` and
borrow `DOS4GW.EXE`/`W32RUN.EXE` from a staged 10.x tree. No headers needed for a self-contained
probe. Period-correct flags: `-onatx` and `-onat` do NOT exist in 9.01 (E1074) — use `-oat`.

Staging recipe for the ISO revisions, which does work:
`scripts/setup-watcom-dosemu.sh <rev>` stages to `C:\WAT<REV>`; then a dosemu BAT with
`set WATCOM=C:\WAT110 / set PATH=C:\WAT110\BIN / set INCLUDE=C:\WAT110\H`, work dir passed as
a single `-d` (it lands on **F:**, not G:), and objects come out lowercase.

Source shapes tested and REJECTED, all under the beta, none reproducing save-before-frame:
`-of+` / `-of` / `-onat` / `-oaxt` / `-zp4` / `-od` / no `-s`; a two-argument call; a shared
temporary for the constant; `#pragma aux` on the CALLEE with explicit `parm caller [eax] [edx]`;
and on the FUNCTION ITSELF `modify [eax]`, `modify [eax edx ebx ecx]`, `modify [eax ebx ecx]`,
`parm [] modify [eax ebx ecx]`.

One of those IS worth keeping: `modify [eax edx ebx ecx]` on the function under test removes the
save and the `lea` entirely (28 -> 25 bytes, 23 after postlink). It does not match here — this
function's contract genuinely preserves EDX — but the RE tracker's proven sources declare exactly
that list on most functions (`src/util/g2ac70.c`), and mosura's emitter declares NOTHING for the
function it emits. That per-function contract is the untested lever, not the compiler.

**THE `modify` LEVER IS DEAD TOO — SIZED BEFORE BUILDING (2026-08-11).** The surviving idea was
that mosura's emitter declares no contract for the function it emits, so wcc386 saves registers the
original's declared `modify` list would have let it destroy. Counted first: of the 216 delta+3
functions, **216 save a register before the frame** and only 2 do not (`53 52`, `52`, `53 51 52`
prefixes ahead of `55 89e5`). So these functions genuinely PRESERVE those registers — declaring
them modifiable would be a lie about the binary, and the save has to happen either way. The only
difference is WHERE, and no compiler available emits it before the frame.

**⇒ The +3 class (216 functions, ~13% of the 1634 attributable) is BLOCKED on a compiler that
emits save-before-frame.** 10.0a, the 10.0 beta and 10.5 all emit save-after-frame. 9.01 and 11.0
are fingerprinted (docs/watcom-codegen-fingerprint.md) but NOT installed — only `C:\WBETA` and
`C:\W105` exist under wine. Testing one of those, or accepting that these functions came from
assembly/a library, is the next step. Do not spend more decompiler or emitter effort on this class
until that is settled.

**SUPERSEDED**SUPERSEDED**SUPERSEDED — the flag-sweep list below was written before the beta test:**

**NEXT EXPERIMENT** (do not skip to a fix): decide between
1. compiler VERSION — the 10.0a vs 10.0-beta known-unknown in `<subject-survey>/BYTE-EXACT-PLAN.md`.
   The systematic uniformity across 216 functions fits a version difference well. No 10.0-beta
   wcc386 is on disk; obtaining one is the blocking step.
2. a wcc386 FLAG combination that moves the register save ahead of the frame setup.
3. a postlink normalization, only if 1 and 2 both come back negative — the original genuinely
   lacks the `lea`, so this would be papering over a real codegen difference.

Related: (subject-profile note `byte-exact-campaign`), (subject-profile note `recompile-survey`),
[[gate-what-you-measured-not-what-you-guessed]], [[goal-is-the-binary-not-ghidra]].
