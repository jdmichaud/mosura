# Worms (Team17, 1995) — a standalone-LE corpus entry

What the disc holds, what mosura does with it, and how the executables relate. Added because it is
the first real binary exercising the **standalone** DOS/4GW LE dispatch — the branch WAR2 and
Descent do *not* take.

Media: a mixed-mode CD (`CDWORMS.bin` + `.cue`), track 1 `MODE1/2352` data (44417 sectors), tracks
2+ CD audio. Convert track 1 by taking 2048 user bytes at offset 16 of each raw sector; volume
`CDWORMS`, dated 1995-10-19, 68 files.

> A second disc of the same game exists as a later re-release, and it is **not** the same thing:
> it adds a Delphi `MENU.EXE`, an MSVC patch installer, `MSVBVM50.DLL` and a `DATANOW/` tree of
> IE5/Acrobat/Shockwave redistributables. Its DOS binaries are *different builds* of identical size
> (e.g. `WRMS.EXE` differs in 1448 of 426117 bytes, first at `0x7f8`; no byte shift improves the
> match, so it is a genuine rebuild, not a bad rip). Prefer the 1995 disc: it is the DOS release
> with none of the Windows shell around it.

## Everything loads, with no new work

| file | container | functions | FID named | compiler marker |
| --- | --- | --- | --- | --- |
| `WRMS.EXE` — the game | **standalone LE**, `x86:LE:32:default watcom` | 869 | **123** | `WATCOM C/C++32 … 1988-1994` |
| `FMV/PLAY.EXE` — video player | standalone LE | 568 | **130** | Watcom C/C++32 |
| `BLACK.EXE` — helper | standalone LE | 34 | 16 | Watcom C/C++32 |
| `WORMS.EXE` — launcher | 16-bit MZ | 119 | 36 | `WATCOM C/C++16 …` |
| `SETUP.EXE` — installer | 16-bit MZ | 170 | 38 | Watcom C/C++16 |
| `DOS4GW.EXE` — the extender | 16-bit MZ | 302 | 9 | **`MS Run-Time Library … 1990`** |
| `T17VIEW.EXE` | 16-bit MZ | 1 | 0 | none (a 6.6 KB stub) |

No loader, compiler spec or FID column had to be added. Two things are worth drawing out:

**FID coverage here is the best of any game in the corpus** — 123 of 869 functions in the game
itself (14%), against WAR2's 130 of 3023 (4%) and Descent's 43 of 1973 (2%). Same reason in each
case: Worms is Watcom-built and the Watcom columns are the best-populated ones we have.

**`DOS4GW.EXE` is identified by the 16-bit Microsoft marker added for Flashback** — Rational
Systems built the extender with MS C, so it reports `msvc:16bit:1990`. That is an independent
confirmation that the marker generalises beyond the binary it was written for.

## Standalone versus bound — the dispatch difference

`WRMS.EXE`, `FMV/PLAY.EXE` and `BLACK.EXE` all set a **valid** `e_lfanew` (`0x2a50`) pointing at an
`LE` signature, because the extender ships beside them as a separate `DOS4GW.EXE` that their stub
loads at run time. Descent sets `e_lfanew` to garbage (`0x09b40000`) because DOS/4GW is *bound*
into the image.

That distinction picks the code path:

| shape | `e_lfanew` | default dispatch | example |
| --- | --- | --- | --- |
| standalone | valid, → `LE` | **straight to `load_le`** — 32-bit view, no flag needed | Worms |
| bound | invalid on purpose | the 16-bit MZ stub, Ghidra-parity; 32-bit view is opt-in | WAR2, Descent |

The standalone branch existed in `load_container` from the start but had **no real-binary
coverage**, and the synthetic gates only exercised the scan (bound) path. Worms is the binary that
shows it works, and `tests/le_loader.rs` now covers it too:
`a_standalone_le_is_claimed_by_the_default_dispatch` and `bound_and_standalone_are_distinguished`.

## How the executables relate

Plain DOS process spawning, no overlays:

```
INSTALL.BAT  ->  "setup"
SETUP.EXE        16-bit; writes SETUP.CFG / WORMS.CFG, names WORMS.EXE, WRMS.EXE, T17VIEW.EXE;
                 DOS EXEC (INT 21h AH=4Bh) at image+0x727b
WORMS.EXE        16-bit launcher; names WRMS.EXE and BLACK.EXE, reads SETUP.CFG;
                 DOS EXEC at image+0x2edd
WRMS.EXE         the 32-bit game; its stub names "dos4gw.exe" / "RATIONAL DOS/4G" and loads the
                 extender from disk at run time; opens DATA\\AUDIO\\WORMS*.SFX
FMV/PLAY.EXE     the video player, shipped with its OWN copy of DOS4GW.EXE
```

So the runtime chain is `SETUP.EXE` (once) → `WORMS.EXE` → `WRMS.EXE` + `DOS4GW.EXE`, with
`FMV/PLAY.EXE` and `BLACK.EXE` spawned as needed. Contrast Flashback, where the launcher swaps
*itself* out to XMS/EMS/disk before spawning: Worms needs no such trick, because the game is a
32-bit protected-mode program and the 16-bit launcher is tiny.

## Reproducing

```sh
# track 1 of the mixed-mode CD -> a plain ISO (2048 user bytes at +16 of each 2352-byte sector)
# then extract the executables and analyse; nothing needs a flag:
cargo run --release --example fidnames -- <WRMS.EXE>      # 869 functions, 123 named
```
