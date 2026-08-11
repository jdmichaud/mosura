---
name: wcc386-disassembly-notes
description: "How to get at wcc386 10.0a's code — LX stub plus a flat appended payload, load base, code region — for the prologue-emission investigation"
metadata:
  type: reference
---

**Groundwork for disassembling Watcom's own compiler, done 2026-08-11 while chasing where the
WAR2 prologue swap comes from. mosura can now LOAD it; finding the prologue emitter is still open.**

## Getting at the code

`WATCOM/BINB/WCC386.EXE` (10.0a, 541364 bytes) is **LX**, not LE — mosura rejected it outright
until `05ee0b9` added LX support. It is NOT one image:

- the LX proper is a **~4 KB loader stub**: 3 objects at bases `0x10000` / `0x20000` / `0x30000`
  with virtual sizes `0x68` / `0xeb7` / `0x8200`, and only 104 + 3767 + 471 bytes physically
  present (the third is mostly BSS). `num_pages` is 3.
- everything from about `0x2000` to EOF is an **appended flat payload** the stub loads. It is NOT
  compressed (entropy ~6) and NOT another LE/LX image — the `LE` bytes at `0xcb70` / `0x72925` /
  `0x73e6d` are coincidences inside strings; their header fields are garbage.

**Load base: file offset == address.** Established by pointer-matching: u32s equal to the file
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

Related: [[prologue-order-is-chain-frame]], [[analysis-external-toolchains]].
