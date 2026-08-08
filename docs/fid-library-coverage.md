# FID library coverage — what we ingested, and what we did not

Audited 2026-08-08, prompted by a simple question that turned out to have an uncomfortable
answer: *did we ingest all of each runtime?* No. Every column ingests the **C run-time library
only**, which is a defensible default but was never written down, so "the Watcom column is
complete" in [`fid-building-databases.md`](fid-building-databases.md) meant "complete across
*versions*", not "complete across *libraries*". This file is the missing half.

## The short version

| compiler | libraries ingested | libraries shipped | coverage |
| --- | --- | --- | --- |
| **sdcc** (z80) | `z80.lib` | 1 | **100%** — nothing to miss |
| **Watcom** (per version) | `LIB386/DOS/CLIB3R.LIB` | 51 (10.0a) … 187 (11.0) | 1 file |
| **Borland** (per product) | `C{C,H,L,M,S}.LIB` + `CW32.LIB` | 13 (tc2.0) … 88 (bc4.5) | 5–6 files |
| **MSVC** | Ghidra's shipped `.fidb` | n/a | vendored, not ours |

The raw ratios look alarming and mostly are not. Most of what is *not* ingested is genuinely
irrelevant to identifying a C program: OS/2 and Win32 target libraries, C++ class frameworks
(`OWL*`, `BIDS*`, `OCF*`, `PLIB*`), OLE/VBX bindings, DPMI extender support. A signature
database is not free — every record is a candidate the matcher scores, and records a target
never links can only produce false positives or dilute the version vote — so "ingest everything
on the disc" is the wrong instinct.

**One gap is real, though, and it is the same one in every column.**

## The real gap: the floating-point/math libraries

Every vendor of this era splits `printf`-family float formatting, `sqrt`/`sin`/`pow`, and the
80x87 emulator out of the C library into a separate archive that the linker pulls in *only* when
the program uses them:

| compiler | not ingested | what is in it |
| --- | --- | --- |
| Watcom | `MATH3R.LIB`, `MATH387R.LIB`, `EMU387.LIB` | math + x87 emulation |
| Borland | `MATH{C,H,L,M,S}.LIB` (per memory model), `EMU.LIB`, `FP87.LIB` | math + FP emulation |

A real program that does any floating-point work links these, so their functions are present in
the target and absent from our databases — they cannot be identified. Borland ships 5 math
libraries per product (9 for bc3.0+, adding the Windows models), one per memory model, so this is
5–9 files per product rather than one.

Watcom also ships `GRAPH.LIB` (its graphics API). Whether that is worth ingesting depends on the
target; a game like WAR2 is more likely to use its own renderer.

## Watcom, in detail

Ingested, all six versions: **`LIB386/DOS/CLIB3R.LIB`** — the 32-bit DOS C run-time, *register*
calling convention (`3` = 386, `R` = register). That is the right single choice: DOS/4GW programs
are 32-bit and Watcom's default is `-3r`.

Not ingested, grouped by whether it could matter for a DOS C program:

- **Could matter** — `MATH3R.LIB`, `MATH387R.LIB`, `EMU387.LIB`, `NOEMU387.LIB`, `GRAPH.LIB`
- **Wrong calling convention** — every `*3S.LIB` (stack-based; the `-3s` variant of the same code)
- **Wrong target** — `NT.LIB`, `OS2286.LIB`, `OS2386.LIB`, `WIN386.LIB`, `RAFX*`, `SAFX*`,
  `REXX.LIB`, `SOM.LIB`, `VDH.LIB`
- **C++ / class libraries** — `PLIB*`, `PLBX*`, `CPLX*`

Open Watcom 2 ingests `bld/clib/library/msdos.386/ms_r/clib3r.lib` from the source tree, which is
the same choice made against a build rather than a release (with the provenance caveat already in
`fid-building-databases.md`).

## Borland, in detail

Ingested per product: **`CC/CH/CL/CM/CS.LIB`** — the C run-time, one per memory model (compact,
huge, large, medium, small) — plus **`CW32.LIB`** for the 32-bit flat products (bc4.0, bc4.5,
bc4.52) and **`CW32.LIB` + `CW32MT.LIB`** for C++ Builder 5. bc3.0 uses its Windows models
(`CW{C,L,M,S}.LIB`).

That is the correct axis to cover — memory model changes the code, so each model needs its own
database — and it is why Borland has 64 databases against Watcom's 6.

Not ingested: the math set above, plus `GRAPHICS.LIB`, `OVERLAY.LIB`, `OBSOLETE.LIB`, and the
large C++/Windows framework set (`OWL*`, `BIDS*`, `OCF*`, `BWCC*`, `OLE2W*`, `IMPORT*`, `CTL3D*`,
`BIVBX*`, `W32SUT*`, `GLAUX`, `NOEH*`, `CRTLDLL`).

## sdcc

`/usr/share/sdcc/lib/z80/z80.lib` is the only library the z80 target ships. This column is
complete by construction.

## What this audit did NOT explain

The investigation started from 8 functions FID misses in WAR2 (`malloc_`, `free_`, `clock_`,
`close_`, `delay_`, `heap_walk_static_`, `_asctime_static_`, `_localtime_static_`). **The missing
math libraries do not explain them** — those names are symbols of `CLIB3R.LIB`, the library we
*do* ingest, and they are not in the database anyway.

Two things were ruled out along the way, so nobody repeats them:

- **Our ingest is not dropping functions from a library it reads.** Auditing `CLIB3R.LIB`
  independently (394 members, 0 load failures) produced a set of named functions that the
  committed database is a strict superset of, bar one name.
- **A name appearing in a `.LIB` is not proof it is defined there.** A member can *reference* a
  function defined elsewhere, and a text search cannot tell the two apart — that mistake sent
  this investigation in the wrong direction once already.

So the 8 remain open (task: "Close the 8-function Watcom library data gap", whose title now
overstates what is known). The likely explanation is that these are aliases or thunks rather than
distinct library members — our database has `_nmalloc_` but not `malloc_`, and Watcom implements
the ANSI names on top of the near/far/based allocators — but that needs the OMF `PUBDEF` records
read directly rather than inferred.

## If you want to close the math gap

Per column, ingest the math library alongside the C library into the **same** database (same
family/version/variant — it is one runtime), then regenerate and re-run `fid_database_drift`,
which compares against the committed file and will go red by design until the new file is
committed in the same change. Expect the record count to rise, and re-run the WAR2 comparison to
see whether it moves the needle on a real target before doing it for all 71.
