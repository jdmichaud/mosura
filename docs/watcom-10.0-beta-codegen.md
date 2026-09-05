# The Watcom 10.0 beta, and why 10.0a is a one-release excursion

Measured 2026-08-08 from self-compiled ground truth. Artefacts:
`oracle/codegen-probes/watcom/10.0-beta.{obj,code}`, gated by
`watcom_10_0a_is_a_one_release_excursion`.

## The result in one line

The 10.0 **beta** emits code **byte-identical to 9.5b, 10.5 and 10.6** — and **different from 10.0a
retail**, which sits between them in release order.

| revision | date | probe code | promotes the byte compare? |
| --- | --- | --- | --- |
| 9.01 | 1992 | 150 bytes | no |
| 9.5b | 1993 | **156 bytes** | no |
| **10.0 beta** (LA preprod) | 16 Mar 1994 | **156 bytes** | **no** |
| 10.0a retail | 1994 | 162 bytes | **YES** |
| 10.5 | 1995 | **156 bytes** | no |
| 10.6 | 1995 | **156 bytes** | no |
| 11.0 | 1997 | 158 bytes | no |

The four **156**-byte rows are byte-identical to each other, not merely the same length.

## The actual difference

Source: `int cmpbyte(unsigned char c){ return c == 5; }`. Watcom's register calling convention
passes `c` in `EAX`, so only `AL` is meaningful — the upper 24 bits are undefined on entry.

**10.0 beta / 9.5b / 10.5 / 10.6** — compare the byte where it lives:

```asm
cmp    al, 0x5          ; 2 bytes
sete   al
and    eax, 0xff        ; zero-extend the bool result
ret
```

**10.0a retail** — widen the compare to 32 bits, which *forces* a mask first:

```asm
and    eax, 0xff        ; <-- THE EXTRA INSTRUCTION: clear the undefined upper bits
cmp    eax, 0x5         ; now a 32-bit compare
sete   al
and    eax, 0xff        ; same bool zero-extension as above
ret
```

Note the trailing `and eax,0xff` is present in **both** — that is the `int` return
zero-extension, and it is not the signal. The signal is the *leading* `and` plus the widened
compare.

The 6-byte delta accounts exactly for the 156 → 162 size change: +5 for the added
`and eax,0xff`, and +1 because `cmp eax,imm8` is one byte longer than `cmp al,imm8`. Everything
after `cmpbyte` — the counted loop, the switch, both divisions — is identical in all of them,
merely shifted by 6 bytes.

**This is a pessimisation, not extra safety.** Both forms are correct; comparing `AL` directly
needs no mask at all, so 10.0a spends 6 bytes to reach the same answer. Whatever motivated it did
not survive into 10.5.

## Why it matters

**It sharpens the subject's identification.** the subject is identified by the promoting form. That form was
previously understood as marking "the 10.0 line". It does not: it is unique to **10.0a retail**,
with two measured revisions on each side emitting the non-promoting form. The anchor is
narrower — and therefore stronger — than it was.

**It is the strongest available argument against interpolation.** 10.0a cannot be inferred from
its neighbours, and nothing can be inferred *through* it:

- guess the 10.0 beta from 9.5b → right, by luck
- guess the 10.0 beta from 10.0a (its own retail release, one release later) → **wrong**
- guess 10.5 from 10.0a → **wrong**
- guess 10.0a from anything → **wrong**

Three of the four available inferences fail. This is the same lesson 9.01 taught when it inverted
the meaning of the `CDQ`/`MOVZX` anchors — a boundary read off the ends of the version set you
happen to own is a boundary of your corpus, not of the compiler.

**A corollary for dating binaries.** A binary showing the non-promoting form is *not* thereby
"10.5 or later" — 9.5b and the 10.0 beta produce it too. Only the promoting form is a positive
single-release anchor; its absence spans 1993 to 1997 and means very little on its own.

## Reproducing it

The beta media resisted three obvious routes; the one that works is short. See
[`watcom-codegen-fingerprint.md`](watcom-codegen-fingerprint.md) for the full recipe and the dead
ends, but in brief:

```sh
# 1. WPACK.EXE — the vendor's own archiver, matching era — ships UNPACKED on the beta ISO.
#    Extract is its DEFAULT verb (-l lists, -a adds, -d DELETES).
wpack PACK0022        # -> wcc386.exe, 517,764 bytes, 16 Mar 1994
wpack PACK0156        # -> wcc386.exe, 7,168-byte PE32 console launcher

# 2. Run it under wine via that launcher. NOTE: the beta looks for its sibling in BINB,
#    where 10.5 looks in BINW.
#    BINNT/WCC386.EXE = the 7,168-byte launcher ; BINB/WCC386.EXE = the 517,764-byte payload
cd "$WINEPREFIX/drive_c" && wine 'C:\WBETA\BINNT\WCC386.EXE' WATCOM_C.C
#  -> WATCOM C32 Optimizing Compiler  Version 10.0 Limited Availability
#     WATCOM_C.C: 6 lines, 0 warnings, 0 errors     Code size: 156
```

`oracle/wpack/` (our own decoder) does **not** read this media — it handles the 1995 format only.
That is fine and needs no fixing: the vendor tool is right there on the disc. The diagnosis is
recorded in the fingerprint doc for anyone who wants it anyway.

## What the banner says

`WATCOM International Corp. 1988-1993` — the only `1993` max-era in the whole 10.0–11.0 lineage,
so the **banner alone identifies the beta**, which the codegen cannot (it shares a row with
9.5b/10.5/10.6). Another instance of the standing rule: the banner is the cheap first check, and
the codegen fingerprint is for what the banner cannot separate.
