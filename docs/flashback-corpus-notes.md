# Flashback (1992/95 DOS) — a 16-bit real-mode corpus entry

What this binary set is, what mosura does with it today, and how its three executables relate.
Added because it is the corpus's **16-bit segmented real-mode** axis: everything else in the
analysis corpus is 32-bit flat (Watcom LE, X-32, ELF) or a 16-bit stub, so this is the only entry
exercising `x86:LE:16:Real Mode` on a real program of substance.

The files are user-provided and not committed. Sizes/hashes are recorded so a reader can confirm
they have the same artifacts.

| file | bytes | what it is | mosura loads | FID names |
| --- | --- | --- | --- | --- |
| `GAME_E.OVL` | 162012 | **the game** — Delphine Software, Microsoft C 7.0 | 651 functions | **30** |
| `CINI.OVL` | 7892 | a CD movie player — **Tiertex Ltd**, not Delphine | 47 functions | 0 |
| `FB.EXE` | 6656 | the launcher/swapper | 18 functions | 0 |

Three different origins in one game, which is the first surprise: the game is French
(Delphine — `Passage en mode graphique.`), the movie player is a British third party, and the
launcher is a hand-written swapper that belongs to neither.

## Loading works

All three load as `x86:LE:16:Real Mode` through the ordinary MZ path — no new loader needed, no
opt-in view. `GAME_E.OVL` is a complete MZ despite the extension (`cs:ip=1768:00d8`, 1350
relocations); `GAME_{F,G,I,S}.OVL` on the CD are the same code for other languages.

## FID identification — it did not work, and why; then it did

Out of the box: **0 names on all three**, with 50057 signature records attached. The cause was not
the binaries. It was that **no 16-bit Microsoft column existed**: the committed 16-bit columns were
Borland and Watcom, and Ghidra's shipped `.fidb` are 32-bit Visual Studio. So the one compiler that
actually built this game had no database at all.

Fixed by building one from the real thing — **Microsoft C/C++ 7.0 (3-20-1992)**, whose runtime
banner is present verbatim in the game. Its media ships libraries KWAJ-compressed as `*.LI$`;
Microsoft's own `DECOMP.EXE` (on the profiler disk) expands them, run under dosemu2. Four columns,
one per memory model, `msc-7.0-c{s,m,c,l}-x86-16`, ~888 records each.

Result on `GAME_E.OVL`: **30 functions named** — `_printf`, `_sprintf`, `_sscanf`, `_vsprintf`,
`_strlen`, `_strstr`, `_strpbrk`, `_fgets`, `__fsopen`, `_exit`, `__ctermsub`, `__bios_keybrd`, …

### FID also settled the memory model

Attaching one model at a time is a clean discriminator, and it is decisive:

| model | named |
| --- | --- |
| **medium** | **30** |
| large | 11 |
| small | 5 |
| compact | 3 |

So the game is Microsoft C 7.0, **medium model** (far code, near data) — which fits a 162 KB image
with a single data segment. That answer comes from the databases, not from a guess about the size.

`FB.EXE` and `CINI.OVL` still name 0, consistent with neither being an MS C build: `FB.EXE` looks
hand-written (its code is all DOS/XMS/EMS calls, no runtime), and `CINI.OVL` is a third party's.

### Detection gap this exposed

The game carries `MS Run-Time Library - Copyright (c) 1992, Microsoft Corp`, and mosura's
compiler-version detector reported **nothing** — it only knew the 32-bit-era
`Microsoft Visual C++ Runtime Library`, which this era never emits. `compiler_version::msvc` now
also matches the 16-bit DOS banner (grounded: the same string is in MS C 7.0's `SLIBCR.LIB`), so
the game reports `msvc:16bit:1992`.

## How FB.EXE relates to the two .OVL files

Not overlay linking, and not a linked overlay manager: **FB.EXE spawns each `.OVL` as a separate
DOS child process.** From the image (`FB.EXE` header 512 B, image 6144 B):

```
image+0x041   int 21h AH=4Ah    shrink its own memory block
image+0x14a   ba 4a 0d          mov dx, 0x0d4a   -> the GAME_?.OVL name table
              bb d8 0d          mov bx, 0x0dd8   -> the shared EXEC parameter block
              b8 00 4b cd 21    int 21h AH=4B00  -> LOAD AND EXECUTE (a real child, not AH=4B03)
image+0x253   ba 81 0d          mov dx, 0x0d81   -> CINI.OVL
              b8 00 4b cd 21    int 21h AH=4B00  -> same mechanism, second call site
              (on failure: mov dx,0x0b3f; AH=09 -> "cannot execute overlay.")
```

Both call sites use `AH=4B00`, **not** `AH=4B03` (load-overlay), so each `.OVL` really is an
independent program with its own PSP. The `.OVL` extension is a naming convention, nothing more —
which is consistent with `GAME_E.OVL` being a complete MZ.

The filename comes from a contiguous, NUL-separated, **11-byte-stride table** that is indexed:

```
0x0d4a GAME_E.OVL  0x0d55 GAME_F.OVL  0x0d60 GAME_G.OVL  0x0d6b GAME_S.OVL  0x0d76 GAME_I.OVL
0x0d81 CINI.OVL    0x0d8a ?:swapfile.tmp   0x0d99 FB.CFG   0x0da9 SWAPAREA DATA\
```

and the selection is a language index — `cmp ax,4 / je` picks `0x0d76` (GAME_I) over the table
base, i.e. entry 4 of five.

### Why a launcher exists at all: it swaps itself out

`FB.EXE`'s whole purpose is to give the child nearly all of conventional memory. Its strings spell
out the design, and the code matches: `int 21h AH=4Ah` to shrink itself, `AH=48h`/`AH=49h` to
juggle blocks, two `int 2Fh` multiplex calls, and messages for

```
Memory swap / to XMS / to EMS / to disk / XMS, EMS or disk not available.
... SWAPPING ...  ... RETURNING ...  ... RESTORING MEM ...  ... RETURNING TO CALLING PROCESS
SWAP: Cannot find arena chain / memory arena mis-match / Bad Environment Block / ...
8086$286$386$486$ CPU detected.   ... require 386 minimum
```

"Arena chain" and "Bad Environment Block" are DOS MCB walking: it edits the memory-control-block
chain to free itself before `EXEC`, having parked its own image in XMS, EMS, or `?:swapfile.tmp`.
`FB.CFG` is the shared configuration — the game reads it too (`c:fb.cfg` appears in
`GAME_E.OVL`), and the game prints `Execute FB.EXE` if it is started without the launcher.

So the runtime relationship is: **FB.EXE → (swap self out) → EXEC one of GAME_?.OVL or CINI.OVL →
(child exits) → restore → repeat**, with the launcher alternating between the game and the movie
player and never resident alongside them.

## Reproducing

```sh
# the FID columns (needs the MS C 7.0 media staged; see scripts/rebuild-fid-db.sh)
scripts/rebuild-fid-db.sh msc

cargo run --release --example fidnames -- <GAME_E.OVL>     # 651 functions, 30 named
```
