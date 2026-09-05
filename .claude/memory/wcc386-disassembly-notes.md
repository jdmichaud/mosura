---
name: wcc386-disassembly-notes
description: "How to get at wcc386 10.0a's code — LX stub plus a flat appended payload, load base, code region — for the prologue-emission investigation"
metadata:
  type: reference
---

**Groundwork for disassembling Watcom's own compiler, done 2026-08-11 while chasing where the
the subject prologue swap comes from. mosura can now LOAD it; finding the prologue emitter is still open.**

## Getting at the code

`WATCOM/BINB/WCC386.EXE` (10.0a, 541364 bytes) is **LX**, not LE — mosura rejected it outright
until `05ee0b9` added LX support. It is NOT one image:

- the LX proper is a **~4 KB loader stub**: 3 objects at bases `0x10000` / `0x20000` / `0x30000`
  with virtual sizes `0x68` / `0xeb7` / `0x8200`, and only 104 + 3767 + 471 bytes physically
  present (the third is mostly BSS). `num_pages` is 3.
- everything from about `0x2000` to EOF is an **appended flat payload** the stub loads. It is NOT
  compressed (entropy ~6) and NOT another LE/LX image — the `LE` bytes at `0xcb70` / `0x72925` /
  `0x73e6d` are coincidences inside strings; their header fields are garbage.

> ### ⚠️ CORRECTED 2026-08-22 — the load base is NOT file offset
>
> **For the code and read-only data region, `VA = file offset − 0x2200`.** Pinned on a datum with
> no interpretive slack: the 4-byte register-allocation table is at **file** `0x7ba50`, and the
> accessor at file `0x4052b` is `MOV EAX,0x79850 ; RET`, while file `0x79850` holds unrelated
> instruction-encoding tables. Six pointer slots (`RegSets[RL_DOUBLE]` at file `0x7bb54`, plus
> five `ParmSets`/`Parm8087` entries) all store `0x79850`. Searching for a table's *file* offset
> as a dword finds nothing; searching for `file − 0x2200` finds every reference.
>
> The pointer-matching below was a coincidence: the dword `0x755dc` in the file is a pointer to
> the `__GETDS`/`__EPI` symbol blob at file `0x777dc`, **not** to the `-of` help text that happens
> to sit at file `0x755dc`. Two strings 0x2200 apart, and the search matched the wrong one.
>
> Practical consequence: offsets quoted below (`0x3ff36`, `0x482f1`, `0x404a2` …) are **file**
> offsets — correct for `dumpraw` and for patching, which is what they were used for — but their
> runtime addresses are `0x2200` lower. Absolute addresses appearing *inside* instructions
> (`[0x7f8b0]`, `[0x7f89c]`, `[0x7f884]`) are VAs and are **not** file offsets.
> Worked through in `docs/watcom-dial-patch-results.md` §4.2.

**Load base: file offset == address.** *(superseded — see the correction above.)* Established by pointer-matching: u32s equal to the file
offsets of `Access violation` (`0x206e`) and the `-of` help text (`0x755dc`) appear in the file, and
no other base matches. So a raw disassembly can be read at face value.

**Map so far:** `0x2000`- runtime/fault strings; code from roughly `0x30000` to `0x71000`; message
and help strings `0x73aab`-`0x75d7f` (NUL-separated, no adjacent option table).

## What the binary confirmed that OW2's source did not

10.0a's own help text distinguishes what `bld/cc/c/cmdlnx86.c` blurs:

```
f   -> generate traceable stack frames AS NEEDED
f+  -> ALWAYS generate traceable stack frames
o   -> continue compilation if low on memory   (= CGSW_GEN_MEMORY_LOW_FAILS)
s   -> favor code size over execution time
```

Measured anyway: `-of` and `-of+` produce IDENTICAL code in 10.0a, matching OW2 where both set
`NEED_STACK_FRAME`. **Read OW2 for mechanism, never for which 10.0a flag sets which switch** —
`-oo` did not behave as that source predicts.

## Leads for whoever continues

- wcc386 is SELF-HOSTED, so its own functions open `55 89 e5`. 29 such prologues in the code region
  give free function boundaries to build a map from.
- The instruction emitter is TABLE-DRIVEN: there is no literal `8d 65` (`lea esp,[ebp-N]`) anywhere
  in the code region, so searching for emitted opcodes will not find the prologue writer.
- Promising shape already spotted at `0x482f1`: `mov eax,[0x7f8b0]` then
  `test byte ptr [eax+0x54],0x80` — a global struct pointer with a flags byte, which is what the
  `CHAIN_FRAME` decision looks like in OW2 terms (`TargetSwitches` + `CurrProc->state.attr`).
  Mapping `[0x7f8b0]` and the meaning of `+0x54` is the next concrete step.

## ⭐ FOUND IT — the CHAIN_FRAME decision in 10.0a machine code

**`0x3ff36` is the predicate. `-of`/`-of+` set the bit it tests. Its caller branches into two
different emitters. That is the swap, in the shipped compiler.**

How it was reached (the method that worked, after four that did not):
1. `[0x7f8b0]` is `CurrProc` — 234 code references. Clustering them gave a 111-reference region
   `0x404ed`-`0x41a17`: the procedure prologue/epilogue module.
2. Inside it, `0x404a2` builds a REGISTER SET from switch bits, which identified the switches word:

```asm
404a2:  testb $0x40,0x7f89c  /  404ab: or $0x40000000,%eax   ; HW_EBPH
404b0:  testb $0x80,0x7f89c  /  404b9: or $0x80000000,%eax   ; HW_ESPH
404be:  testb $0x10,0x7f89d  /  404c7: or $0x200000c,%eax
```

   ⇒ the target-switches word lives at **`0x7f89c`** (bytes `0x7f89c`/`0x7f89d`/`0x7f89e`).
3. `CGSW_X86_NEED_STACK_FRAME = 0x00010000` (OW2 `bld/cg/intel/h/x86swi.h:49`) = bit 16 = byte
   `0x7f89e` mask `0x01`. Searching for `testb $1,[0x7f89e]` gives exactly ONE site: `0x3ff36`.

```asm
0003ff36 <chain_frame_p>:              ; CHAIN_FRAME
  3ff36:  testb $0x1,0x7f89e           ; NEED_STACK_FRAME  <- set by -of AND -of+
  3ff3d:  jne   3ff51                  ;   -> true
  3ff3f:  testb $0x4,0x7f89d           ; bit 10
  3ff46:  je    3ff54                  ;   -> false
  3ff48:  testb $0x2,0x7f89d           ; bit 9
  3ff4f:  je    3ff54                  ;   -> false
  3ff51:  mov   $1,%al ; ret           ; TRUE
  3ff54:  xor   %al,%al ; ret          ; FALSE
                                        ; == NEED_STACK_FRAME || (bit10 && bit9)

  3ff69:  call  3ff36                  ; the caller branches on it
  3ff6e:  test  %al,%al
  3ff70:  je    3ff7d
  3ff72:  call  38809                  ; TRUE  path: reads [0x7fab2], tags 5
  3ff7d:  call  38802                  ; FALSE path: reads [0x7fab0], tags 1
```

So the shipped 10.0a really does carry the two-path structure OW2's `GenProlog` describes, the
selector really is the `-of` switch bit, and `-of`/`-of+` really are the same bit — which is why
they measure identical. The behavioural finding and the source reading are now both grounded in
this binary.

## ⚠️ OW2 CONSTANTS: PARTLY TRANSFER — earlier claim CORRECTED

An earlier revision said they do not transfer at all. That was wrong for the register sets:
`or $0x40000000` at `0x404ab` IS OW2's `HW_EBPH`. My search failed because I looked for the
COMPOUND `HW_EBP` (`HW_EBPH|HW_BP` = 0x40000400); the code uses the bare high part. Switch bit
values transfer too (`NEED_STACK_FRAME = 0x10000` located the predicate).

What genuinely does NOT transfer is FLAG BEHAVIOUR: `-oo` does not act as OW2's `AddCacheRegs`
predicts. Read OW2 for structure and constants; verify behaviour on the binary.

Related: [[prologue-order-is-chain-frame]], [[analysis-external-toolchains]].
