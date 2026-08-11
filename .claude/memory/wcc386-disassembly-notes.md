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

## ⚠️ OW2 CONSTANTS DO NOT TRANSFER TO 10.0a — three strikes

1. `-oo` does not behave as OW2's `AddCacheRegs` predicts.
2. OW2's register-set encoding (`HW_EBP = HW_EBPH|HW_BP = 0x40000400`, cgx86reg.h) appears
   NOWHERE in 10.0a's code region. The single apparent `HW_ESP` (0x80000800) hit at `0x5687c` is a
   FALSE POSITIVE: bytes `00 08 00 80` straddling a `mov %eax,0x80094` operand and the following
   opcode.
3. The emitter is table-driven, so no emitted-opcode constant (`8d 65`) exists to search for.

⇒ Anchoring 10.0a code by OW2 constant values does not work. Whoever continues must recover
10.0a's OWN encodings first — e.g. start from the option parser (find the `-o` letter dispatch),
learn which global holds the switches, then find its readers. `[0x7f8b0]` (a struct pointer with
flags at `+0x54`, fields at `+0x34`/`+0x50`) is a confirmed live lead seen at `0x482f1`.

**Dead ends already burned — do not repeat:**
- OW2 constant values (register sets, switch bits) — see the three strikes above.
- Searching for emitted opcodes (`8d 65`, `55`, `89 e5`): the encoder is table-driven, and the
  `55 89 e5` hits are wcc386's OWN prologues (it is self-hosted).
- `or [mem], imm` scans for a switches global: only 3 sites in the whole code region
  (`0x7d52c`, `0x7f6ac`, `0x7f620`), so the option parser does not use that idiom.
- Clustering `cmp al,<option letter>`: every cluster found (`0x35600`, `0x36c00`, `0x36200`,
  `0x2c200`) is PRINTF, not option parsing — `%i %u %x %X %d %o %e %c %f %s` collide with the
  option letters. `0x35600` is a vsprintf-style formatter.

**What does NOT need the disassembly:** the swap itself is already understood and behaviourally
confirmed on 10.0a — two prologue paths, chosen by whether traceable stack frames are requested
(`-of`/`-of+` -> frame first then saves, needing `lea esp,[ebp-N]`; neither -> saves first then
`Enter()`). The disassembly was only to locate that code IN 10.0a, not to discover the mechanism.

Related: [[prologue-order-is-chain-frame]], [[analysis-external-toolchains]].
