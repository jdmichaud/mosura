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

## Coverage / follow-up

The **classic Watcom C/C++ 10.x era** (`WATCOM International Corp.`, `1988-1994`) is validated
end-to-end against two real binaries + the toolchain's own runtime strings. The banner grammar
covers the classic (`WATCOM International Corp.`) and Open Watcom (`Open Watcom Contributors`)
vendor lines. Per-version fixtures for the full 8.0–11.0c + Open Watcom 1.x/2.0 range need
historical toolchains not on hand (only 10.0a + the Open Watcom source are available) — a
follow-up when those toolchains exist; the detector already recognizes their banner shapes.
