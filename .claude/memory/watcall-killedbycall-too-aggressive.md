---
name: watcall-killedbycall-too-aggressive
description: "mosura's x86-32-watcom.cspec declares killedbycall [EAX,ECX,EDX] but wcc386 keeps EDX live across an indirect call — the spurious clobber emits infinite loops"
metadata: 
  node_type: memory
  type: project
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-08-05T10:29:27.728Z
---

**`specs/x86-32-watcom.cspec` `<default_proto>` `__watcall` declares
`killedbycall = [EAX, ECX, EDX]`. The compiler disagrees, and the compiler is the ground truth.**

Measured 2026-08-05 by disassembling a self-compiled MVE
(`oracle/ground-truth/src/callclob.c`, wcc386 `-bt=linux -s -oc`):

```asm
walk_  53              push ebx        ; saved because it USES ebx
       51              push ecx        ; saved because it USES ecx
       31 d2           xor edx,edx     ; i = 0        <- COUNTER IN EDX
       42              inc edx         ; i = i + 1
       89 d0           mov eax,edx     ; arg = i
       ff d3           call ebx        ; INDIRECT CALL
       eb f5           jmp back        ; <- EDX STILL LIVE
sink_  01 05 6c 90 04 08  add [0x804906c],eax
       c3              ret             ; <- touches ONLY EAX
```

wcc386 keeps a live loop counter in EDX **across an indirect call**. It would never do that if a
callee could destroy EDX. Corroborated independently by
`the RE tracker/analysis/toolchain.md` (~line 590): the subject functions save ECX in their prologues
project-wide, which only makes sense under `#pragma aux DEFAULT … modify exact [eax]` — every
function preserves everything except EAX.

**The symptom is WRONG CODE.** The spurious `killedbycall` on EDX makes `Heritage::guardCalls`
insert an INDIRECT that takes over the loop phi's tail input; the `INT_ADD` update's only
surviving consumer becomes the call argument, so no update statement is emitted and the loop
cannot terminate. Seen on the subject's `FUN_00057034` and reproduced on the MVE.

**Fix belongs in the cspec** (the owner's standing rule: compiler behaviour goes through the
cspec, never `if (target)` in the core). Before changing the list, verify: (a) re-derive from
`/data/open-watcom-v2` — the likeliest error is the `parm` list being mistaken for the `modify`
list, which are different clauses; (b) whether the killed set is per-call-site, since Watcom's
`parm caller [eax edx ebx ecx]` uses only as many registers as the call has arguments; (c) write
a callee that genuinely clobbers EDX and see whether the caller spills. Blast radius is every
call in the binary.

## ⚠️ Ghidra is NOT a valid oracle for any call-effect question on the subject

**Ghidra has no Watcom cspec.** Its x86 options are gcc / win / borland / delphi / golang. Asked
to decompile the same MVE it reported `CSPEC=gcc default=__cdecl` and emitted

```c
while (iVar1 < param_1) { (*param_2)(param_3); param_1 = extraout_ECX; iVar1 = extraout_EDX; }
```

— also wrong, merely not infinite. It is modelling a different calling convention than the
binary uses. The `for` in `<subject-survey>/ghidra-all.txt` that motivated this whole investigation is
a per-function-oracle artefact ([[oracle-same-question-not-just-same-tool]]).

**This is [[goal-is-the-binary-not-ghidra]] in its sharpest form yet:** two of us spent an
afternoon on "Ghidra emits a `for` and we don't" when neither tool was right and the answer was
in five lines of objdump. When the question is about calling convention or call effects, go to
the compiler's own output first — [[self-compiled-ground-truth]].

Related: [[mve-first-then-solve-the-mve]] (callclob.c is the gate),
[[could-it-have-come-out-otherwise]], (subject-profile note `dos4gw-le`).
