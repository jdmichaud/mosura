# FID library coverage — what we ingested, and what we did not

Audited 2026-08-08, prompted by a simple question that turned out to have an uncomfortable
answer: *did we ingest all of each runtime?* No. Every column ingests the **C run-time library
only**, which is a defensible default but was never written down, so "the Watcom column is
complete" in [`fid-building-databases.md`](fid-building-databases.md) meant "complete across
*versions*", not "complete across *libraries*". This file is the missing half.

## The short version — CLOSED

All gaps below were closed on 2026-08-08. **71 databases / 43,925 records -> 85 databases /
~68,000 records.**

| compiler | now ingested | previously |
| --- | --- | --- |
| **Watcom** 32-bit, per version | `CLIB3R` + `MATH3R` + `MATH387R` + `EMU387` + `GRAPH` | `CLIB3R` only |
| **Watcom** stack ABI, per version | `CLIB3S` + `MATH3S` + `MATH387S` — **5 new databases** | nothing |
| **Watcom** 16-bit (10.5) | `CLIB{C,H,L,M,S}` + `EMU87` + `GRAPH` — **5 new databases** | nothing |
| **Borland** 16-bit, per model | `C<M>` + `MATH<M>` + `EMU` + `FP87` + `GRAPHICS` + `OVERLAY` | `C<M>` only |
| **Borland** 32-bit flat | `CW32` (math is built in — no `MATH32` exists) | unchanged, already complete |
| **Watcom** C++, per version | `PLIB3R` + `PLBX3R` + `CPLX3R` — **4 new databases** | nothing (ingested to 0) |
| **sdcc** z80 | `z80.lib` | unchanged, complete by construction |
| **MSVC** | Ghidra's vendored `.fidb` | unchanged, not ours |

What is still deliberately excluded, and why: OS/2 and Win32 target libraries (`NT`, `OS2*`,
`WIN386`, `RAFX*`, `SAFX*`, `REXX`, `SOM`, `VDH`), the GUI/application frameworks (`OWL*`,
`BIDS*`, `OCF*`, `BWCC*`, `OLE2W*`, `IMPORT*`, `CTL3D*`, `BIVBX*`), and `OBSOLETE.LIB`. These are
application libraries, not runtime: a program links them only if it uses that framework, and every
record is a candidate the matcher scores, so carrying them costs false-positive surface for no
identification gain on ordinary C programs.

**The C++ runtimes are now covered too** (`watcom-<ver>-cpp-x86-32`, 4 databases, 502–578 records
each). They ingested to *zero* functions until the OMF reader learned `COMDAT` (0xC2/0xC3): C++
emits template instantiations and inline functions as COMDATs so the linker can dedupe them, so a
C++ archive is almost entirely COMDAT — PLIB3R has 33 COMDAT32 against 3 PUBDEF32 in a sampled
prefix, where CLIB3R has none. Ghidra does not support COMDAT either (it logs the record as
unsupported), so this is beyond-Ghidra and additive.

**Borland needed nothing**: its libraries use classic PUBDEF/LEDATA, and its C++ runtime already
lives inside the C libraries we ingest — 409 mangled names such as `@string@copy$qpcui` are in
`borland-bc4.5-cs` today.

## What this bought on a real target: nothing, and that is worth stating

WAR2.EXE named **121 functions before and 121 after** (one name refined, `___FPEHandlerEnd_` ->
`FPEHandlerEnd_`). The +50% of records changed nothing there because WAR2 links none of the added
libraries — it has its own renderer and does no library float work.

That is not an argument against the change. It is the difference between *coverage* and *this
binary*: the gap was real for any program that does use `sqrt`, BGI graphics, or the `-3s` ABI,
and none of those programs could be identified before. It does mean the WAR2 misses (task: the
8 CRT functions) were never a library-coverage problem, which is what the audit was originally
chasing.

## Watcom, in detail

Ingested, all six versions (`-3r`, the default): **`LIB386/DOS/CLIB3R.LIB` + `LIB386/MATH3R.LIB`
+ `LIB386/MATH387R.LIB` + `LIB386/DOS/EMU387.LIB` + `LIB386/DOS/GRAPH.LIB`**.

Ingested as a separate `Stack` variant (`-3s`): **`CLIB3S` + `MATH3S` + `MATH387S`** — 5 databases
named `watcom-<ver>-stack-x86-32`. A separate database, not merged: it is a different build of the
same functions, and merging would file two different bodies under one name.

Ingested for 16-bit (10.5, from the ISO's `LIB286/`): **`CLIB{C,H,L,M,S}` + `EMU87` + `GRAPH`** —
5 databases `watcom-10.5-c{c,h,l,m,s}-x86-16`, language `x86:LE:16:Real Mode`, cspec `default`.

⚠️ **`find | head -1` is a trap here.** A Watcom tree contains several `CLIB3R.LIB` — under
`LIB386/DOS/`, `LIB386/OS2/`, and more. Picking the wrong one silently builds an OS/2 database
labelled DOS. Always use the explicit `LIB386/DOS/...` path; the same trap is recorded for
Open Watcom 2's many `clib3r.lib` copies.

Still not ingested, and deliberately: `NT.LIB`, `OS2286/OS2386`, `WIN386`, `RAFX*`, `SAFX*`,
`REXX`, `SOM`, `VDH` (other targets), and `PLIB*`/`PLBX*`/`CPLX*` (C++ — see the open item above).

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

Now ingested per 16-bit model `M`: **`C<M>.LIB` + `MATH<M>.LIB` + `EMU.LIB` + `FP87.LIB` +
`GRAPHICS.LIB` + `OVERLAY.LIB`** (bc3.0 uses its Windows models `CW<M>` + `MATHW<M>`). The 32-bit
flat databases (`CW32`, `CW32MT`) are unchanged — there is no `MATH32`, the math is inside the
runtime.

Still not ingested, deliberately: `OBSOLETE.LIB` and the C++/Windows framework set (`OWL*`,
`BIDS*`, `OCF*`, `BWCC*`, `OLE2W*`, `IMPORT*`, `CTL3D*`, `BIVBX*`, `W32SUT*`, `GLAUX`, `NOEH*`,
`CRTLDLL`) — application libraries, not runtime.

## sdcc

`/usr/share/sdcc/lib/z80/z80.lib` is the only library the z80 target ships. This column is
complete by construction.

## How to compare against warcraft2-re's list (and how NOT to)

⚠️ **Compare by ADDRESS, not by name.** FID names the *implementation* using Watcom's internal
symbol; the tracker names the *ANSI alias*, often at a thunk. A name-keyed diff therefore invents
misses that are not misses:

| tracker says | FID says | relationship |
| --- | --- | --- |
| `unlink_` @ 0x72357 | `unlink_` @ 0x64058 | 0x72357 is `jmp 0x64058` — a thunk |
| `delay_` @ 0x63f76 | `__delay_` @ 0x723bf | thunk + internal name |
| `close_` @ 0x6525d | `__close_` @ 0x72325 | thunk + internal name |
| `heap_walk_static_` @ 0x64427 | `_nheapwalk_` @ 0x64427 | SAME address, near-variant name |

5 of the 152 tracker entries are `jmp rel32` thunks. Resolving them and matching on address gives
the honest score:

    FID named at that address     112
    FID named the thunk's target    4   -> 116 of 152
    genuinely unnamed              36   -> of which 16 are the tracker's OWN invented
                                            names (FUN_*, crt_litconst_*, thunk_*), which
                                            FID cannot produce and should not be scored on

So **116 of 136 nameable**, not the 107 a name-keyed diff reports. The `unlink_` "disagreement"
that prompted this was never a disagreement: both are right about different addresses.

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

## Regenerating

The recipe now lives in TWO places that must agree: `docs/fid-building-databases.md` (prose) and
`crates/mosura/tests/fid_database_drift.rs` (executable — each `Source` lists every library of one
database). That gate re-ingests and byte-compares, so it goes red when the recipe changes and is
what proves a regeneration reproduced the committed file. It caught this change correctly.

Historical note: the original text below described closing the math gap, which is now done.

Per column, ingest the math library alongside the C library into the **same** database (same
family/version/variant — it is one runtime), then regenerate and re-run `fid_database_drift`,
which compares against the committed file and will go red by design until the new file is
committed in the same change. Expect the record count to rise, and re-run the WAR2 comparison to
see whether it moves the needle on a real target before doing it for all 71.
