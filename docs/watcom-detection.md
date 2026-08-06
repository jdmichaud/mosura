# Watcom compiler detection (two-oracle extension)

This is a **beyond-Ghidra** extension. Ghidra's only Watcom awareness is
`OmfLoader.mapTranslator`, which maps the OMF `"WATCOM"` translator comment to the
`"watcom"` opinion secondary; there is **no watcom compiler spec in any Ghidra processor**,
and Ghidra reports `Compiler = unknown` for a Watcom PE/MZ/LE. So this is validated against a
**second oracle** — real Watcom-toolchain output — not against Ghidra.

## Mechanism

The Watcom C run-time startup (`_cstart_`) embeds a copyright banner immediately after the
entry jump (WAR2.EXE's entry is `EB 76`, a short jump over the inline string). `loader::watcom`
scans the image for it (LE and MZ loaders call it) and records the detected era as the
program `Compiler` info property (the `compilerinfo=` snapshot field).

## Banner grammar (oracle: Open Watcom source)

Grounded in `open-watcom-v2 bld/clib/startup/h/msgcpyrt.h`, which composes the string:

    "<Open >?Watcom C[/C++][ 16|32|386] Run-Time system. " + <copyright line>

- **Classic** (through 11.0, "WATCOM International Corp."):
  `... (c) Copyright by WATCOM International Corp. YYYY-YYYY. All rights reserved.`
- **Open Watcom** (2003+): `... Copyright (c) Open Watcom Contributors 2002-<CYEAR>. Portions
  Copyright (C) Sybase, Inc. 1988-2002.` (the era year range is the Contributors line, whose
  end is the build year).

## The banner is an *era* fingerprint, not a precise release

A grounded finding, not a hidden limitation: the **run-time** banner (the one embedded in the
compiled image) carries the copyright **year range**, not the `wcc`/`wpp` release. One
toolchain ships several run-time libraries with different ranges — the real Watcom **10.0a**
toolchain's libraries carry both `1988-1993` (older `C 386` / `C/C++32` runtimes) and
`1988-1994` (the `C/C++` ones) — and WAR2.EXE, built by a compiler *older* than 10.0a (per the
`warcraft2-re` codegen investigation), carries the same `1988-1994` banner as 10.0a. The
precise release lives in the **tool** banner (`wcc386` startup: "Version 10.0a"), not in the
compiled binary. So the detector reports the honest era fingerprint
(`watcom:<year-range>` / `watcom:open:<year-range>`), never an invented version number.

## Second-oracle validation (`watcom_detection` test)

| Fixture | Source | Detected |
| --- | --- | --- |
| `watcom_hello.exe` (committed, 16 KB) | freshly built with a real Watcom **10.0a** toolchain under dosemu2 (DOS/4GW LE; `src/watcom_hello.c`) | `watcom:1988-1994` |
| `WAR2.EXE` (user-provided) | real DOS/4GW-bound Watcom LE (ground truth) | `watcom:1988-1994` (LE + MZ) |
| 10.0a `CLIB3R.LIB` banner strings | real toolchain runtime libraries | 4 variants (unit tests) |
| Open Watcom banner grammar | `open-watcom-v2 msgcpyrt.h` | `watcom:open:YYYY-YYYY` (unit test) |
| `comcom32.exe` (DJGPP) | non-Watcom MZ | no match → `unknown` (no false positive) |

## watcall calling convention (`specs/x86-32-watcom.cspec`)

No Ghidra x86 processor ships a watcom compiler spec, so mosura authors one:
`specs/x86-32-watcom.cspec`, resolved by `lang::resolve_cspec` ahead of the Ghidra tree for
`(x86:LE:32*, "watcom")`. It models the default 32-bit Watcom register convention `__watcall`,
grounded in Open Watcom source: integer/pointer args in **EAX, EDX, EBX, ECX** then the stack
(`bld/watcom/h/owflat.h:519` `__parm [__eax] [__edx] [__ebx] [__ecx]`; `bld/wasm/c/asmins.c:935`
`{ "eax", "edx", "ebx", "ecx" }`); return in EAX; caller-saved EAX/ECX/EDX and callee-saved
EBX/ESI/EDI/EBP (`docs/doc/cg/cpwcc.gml`). The LE loader selects it whenever the Watcom banner
is detected (replacing the `gcc` placeholder). Register-convention symbols carry a trailing
underscore (`foo_`) — a symbol-decoration detail, not part of the storage model.

Validated two ways. **Decode** (`cspec.rs::watcall_default_is_eax_edx_ebx_ecx`): the cspec loads
and decodes to the EAX/EDX/EBX/ECX arg order, and the LE loader assigns `compiler_spec_id =
"watcom"` for the Watcom fixtures. **Empirical, against the real toolchain**
(`cspec.rs::watcall_convention_confirmed_against_wcc386`): a `__watcall` probe
(`oracle/analysis-corpus/src/watcall_probe.c`) compiled with a real Open Watcom 2.0 `wcc386`
(`~/tools/open-watcom-v2/rel/binl/wcc386`), disassembled by **mosura's own engine**, loads the
five args as `mov eax,a; mov edx,b; mov ebx,c; mov ecx,d; push e` and the callee returns in EAX
with `ret 4` (callee stack cleanup) — exactly the convention the cspec declares. The **decompiler-side** consumption (recovering war2 function
prototypes with watcall and validating them against the warcraft2-re recovered signatures) is
the decompiler's job — that lives in `crates/mosura/src/decompile/` and is task #9's main-agent
handoff; the cspec is written and ready for it. The 16-bit MZ watcall variant is a follow-up.

## Coverage — measured across the 10.0–11.0 lineage

The classic-era grammar is now validated against **every Watcom C/C++ 10.0–11.0 toolchain** —
their install ISOs streamed through `strings` (the runtime `.lib` banners are the second
oracle; no dosemu needed, the libraries are stored plainly on the ISOs). The table below is
the set of **concatenated runtime banners** each toolchain ships — the exact string a linked
binary embeds and `detect()` reads:

| Toolchain | `WATCOM C 386` | `WATCOM C/C++16` | `WATCOM C/C++32` | max era |
| --- | --- | --- | --- | --- |
| 10.0 LE preprod (Mar 1994) | `1988-1993` | — | — | **1993** |
| 10.0 retail | `1988-1993` | `1988-1994` | `1988-1993`, `1988-1994` | **1994** |
| 10.0a | `1988-1993` | `1988-1994` | `1988-1993`, `1988-1994` | **1994** |
| 10.5 | — | `1988-1994`, `1988-1995` | `1988-1994`, `1988-1995` | **1995** |
| 10.6 | — | `1988-1994`, `1988-1995` | `1988-1994`, `1988-1995` | **1995** |
| 11.0 / 11.0A / 11.0B | — | `1988-1994`, `1988-1995` | `1988-1994`, `1988-1995` | **1995** |

Findings (measured, not inferred):

- **The copyright range is an era stamp on the individual runtime lib, and it accumulates** —
  a toolchain ships its older-era libs alongside the new one, so the *max* range present is
  the build era. No runtime banner in the whole 10.0–11.0 lineage exceeds `1988-1995`.
- **10.5 through 11.0B are indistinguishable by runtime banner** (all carry the `1994`+`1995`
  libs). This confirms the "era fingerprint, not release" property across the full lineage —
  not just 10.0a. The precise release lives only in the tool banner (`wcc386` "Version 10.6").
- **`WATCOM C 386`** (the standalone pre-C++ 386 runtime, always `1988-1993`) exists only in
  10.0x; it is gone by 10.5.
- Every toolchain uses the `WATCOM International Corp.` vendor line and the documented banner
  shape, so **the detector's grammar already matches the entire 10.0–11.0 range** — now
  measured against 8 real ISOs (`detects_watcom_lineage_eras`), not assumed.
- **WAR2.EXE's `1988-1994` cap** is consistent with a 10.0/10.0a-era toolchain and excludes
  10.5+ (which would make a `1988-1995` lib available) — the `warcraft2-re` cap argument, now
  empirically grounded.

## Follow-up: pre-10.0 (floppy) toolchains

The 7.0 / 8.5a / 9.01 / 9.5b distributions are floppy-image sets whose runtime libraries are
**packed** (`WATCOMC.WPK` / `.HPK`, expanded by the installer's `unpack`), so `strings` on the
raw images sees only installer text, not the embedded runtime banner. 9.01's installer text
does reveal an *earlier vendor wording* — `(c) Copyright by WATCOM Systems Inc. 1990-1991`
(**"Systems Inc."**, not "International Corp.") — which the current regex would **not** match.
Whether a 9.01-*compiled* binary actually embeds that wording (vs. the installer merely using
it) needs the packed `.wpk` unpacked via a dosemu install to confirm; if it does, the vendor
alternation gains a `Systems Inc.` arm plus a real fixture. Open Watcom 1.x/2.0 (`Open Watcom
Contributors`) remains grammar-covered + unit-tested; a per-release fixture is a further
follow-up.

### ✅ ANSWERED 2026-08-06 — confirmed, and the year range is a TRAP

9.01 was installed from its floppies (`INSTALL.EXE` under dosemu — see
`watcom-codegen-fingerprint.md`) and used to compile **and link** a DOS/4GW image (`MZ` + `LE`, the
same format family as WAR2). Read from the produced binary, not from installer text:

```
9.01-linked image   WATCOM C Run-Time system code is provided on an "as is" basis and is
                    (c) Copyright by WATCOM Systems Inc. 1988-1991.
```

**So a 9.01-compiled binary really does embed the `Systems Inc.` wording, and the vendor
alternation needs the extra arm.** ⚠️ The predicted *year range* was wrong: the runtime says
**1988-1991**, not the installer's `1990-1991`. Anchor the arm on the vendor name, not the years.

Runtime banner read from each release's `clib3r.lib` (or the linked image, for 9.01):

| release | embedded runtime banner |
| --- | --- |
| 9.01  | `WATCOM Systems Inc. 1988-1991` |
| 10.0a | `WATCOM International Corp. 1988-1994` |
| 10.5  | `WATCOM International Corp. 1988-1995` |
| 10.6  | `WATCOM International Corp. 1988-1995` |
| 11.0  | `WATCOM International Corp. 1988-1994` |
| **WAR2.EXE** | `WATCOM International Corp. 1988-1993` |

**Two things fall out, and the second is a trap:**

1. **The vendor name is a real discriminator.** `Systems Inc.` → pre-10.0; `International Corp.` →
   10.0 onward. That is the corporate rename, and it is a *categorical* signal.
2. **⚠️ The end year is NOT monotonic and must never be used as a version ordinal.** 11.0 (1997)
   embeds `1988-1994` while 10.5 and 10.6 (1995) embed `1988-1995`. Any "later end year ⇒ later
   release" heuristic silently orders 11.0 *before* 10.5. The banner is an **era** stamp, exactly as
   the top of this document says — this table is the measured proof of it.

**And WAR2's `1988-1993` matches none of the four installed releases**, all of which are ≥1994. Its
runtime therefore predates 10.0a, which is independently consistent with the codegen fingerprint
placing it on the *early 10.0 line* (the promoting `cmp eax,5`). ⚠️ Not yet pinned to a release: the
10.0 ISOs here are packed floppy images (`DISK04/CLIBIHP.1` …) whose `clib3r.lib` needs an install
to extract, so **no 10.0-proper banner has been measured** — this is a bound, not an identification.
