# MetaWare High C/C++ support — detection, compiler spec, FID databases

**Status: step 0 (toolchain recon) done — findings below.** The compiler-side track that makes the
X-32 container ([`x32-loader-notes.md`](x32-loader-notes.md)) analysable rather than merely mapped.

Three deliverables, each with its own oracle:

| # | Deliverable | Kind | Oracle |
| --- | --- | --- | --- |
| 1 | `loader/metaware.rs` — compiler + era detection | code | binaries we compile ourselves, + a no-false-positive gate |
| 2 | `specs/x86-32-highc.cspec` — the calling convention | **data** | the toolchain's own generated code |
| 3 | `oracle/fid/db/highc-<ver>-x86-32.mfid.gz` — library signatures, one per build | **data** | the toolchain's own libraries |

Per [`x32-loader-notes.md`](x32-loader-notes.md) §"How Ghidra structures this": a container needs
code, a calling convention is data. Only #1 is code.

## Step 0 results — toolchain availability

Archives at `~/software/MetaWare.Compilers` (locate via an env var, `METAWARE_ARCHIVES`, as
`setup-watcom-dosemu.sh` does with `WATCOM_ARCHIVES`).

| Version | Packaging | Usable now? |
| --- | --- | --- |
| **High C 386 v2.31** (1992, C only) | **uncompressed** 1.2 MB floppies | ✅ libraries + `LIB/SRC/*.ASM` runtime sources, no installer needed |
| **High C++ v3.03** | `highc.zip` = an already-installed tree | ✅ `LIB/*.LIB`, `BIN/` compiler, 158 `INC/` headers — **compiles today** |
| High C++ v3.04 (1993) | packed `MWHC.001`–`.007` + `INSTALL.EXE` | ✅ installer driven unattended — 373 files, 23 `.LIB` |
| High C++ v3.31 | packed `MWHC.001`–`.007` + `INSTALL.EXE` | ✅ same installer, same recipe — 426 files, 37 `.LIB` |
| High C++ v3.2 (OS/2, Mar 1994) | ISO → `HCOS2_1.ZOO` + `ZOO.EXE` | ❌ ZOO archive, and an OS/2 host — wrong target, not pursued |

All four DOS-hosted versions install with one command, so every deliverable below has as many
version columns as it needs.

## Installing them — one command, and why each piece of it is there

```sh
scripts/setup-metaware-dosemu.sh 2.31|3.03|3.04|3.31 [--compile file.c] [--serial NNNNNN]
```

Sibling of `setup-watcom-dosemu.sh` (archives via `METAWARE_ARCHIVES`, `mktemp` work dir, stage
into `DOSEMU_C`). The packed versions are driven by `scripts/kd-install-driver.py`, which runs
dosemu on a pty and reads the rendered screen. Verified end to end:

| version | result |
| --- | --- |
| 2.31 | 9 `.LIB` |
| 3.03 | 39 `.LIB`, and `--compile` produces an OMF object |
| 3.04 | 373 files, 9.4 MB, 23 `.LIB` |
| 3.31 | 426 files, 12 MB, 37 `.LIB` |

**Each version installs to its own `C:\HC<tag>`.** The installer hardcodes
`@Subdir = "\HIGHC"`, so two versions installed unmodified **silently merge into one tree**.
The script rewrites `@Subdir` in the staged `INSTALL.DAT`.

### The five things that had to be true (none of them guessable)

The engine is **Knowledge Dynamics INSTALL 3.10.00**. Getting it to run unattended took five
findings; each one presented as a different, misleading symptom.

1. **Source and target must be different DOS drives.** Staging the volumes under `C:` and
   installing to `C:` fails with *"The output drive cannot be the same as the input drive"*.
   The volumes are staged outside the C: drive and mounted with `dosemu -d`, landing on `F:`.
   *Symptom before the fix: every screen answered correctly, then nothing installed.*
2. **All seven `@DefineDisk` blocks must be merged into one.** The engine prompts *"place Disk
   #N in drive F:"* at each block boundary and re-verifies `DISK.ID`, which can only ever say
   disk 1 when all volumes sit in one directory. *Symptom: the install ran, wrote 25 files, and
   then quietly stalled — flattened, the same run writes 373.* The `@BeginLib MWHC.0NN`
   references stay valid because every volume is present.
3. **`@OutDrive` must be pinned to `C`.** v3.04 ships `@OutDrive = C` and works; **v3.31 ships
   `@OutDrive = Z`**, which leaves the drive-selection list opened on the wrong entry. The
   widget ignores a typed drive letter, so Enter accepts whatever is highlighted — `F:`, the
   source — and it dies with the same "output drive" error as (1). *This is why a recipe proven
   on v3.04 failed on v3.31.*
4. **The option checkbox must be left alone.** Its defaults are already
   `Install the C/C++ compiler = YES` / `Install the debugger = YES`, set by `@SetOption(1)` /
   `@SetOption(2)`. `SPACE` toggles the highlighted line, i.e. switches the **compiler off**.
   *Symptom: a successful-looking install containing no compiler.* Send `CR` only.
5. **Drive it through a pty, reading the screen.** In dosemu's dumb mode (`-td`) the checkbox
   sub-window is direct-video and never reaches stdout, so you are typing blind; keys piped as
   bytes cannot express an arrow (an ANSI arrow starts with `ESC`, which the installer treats as
   *"STOP the installation"*); and DOS's BIOS keyboard buffer is 16 bytes, so a burst of keys is
   mostly discarded. Slang mode (`-t`) on a pty renders real ANSI, which the driver reconstructs
   into an 80×25 buffer and answers one screen at a time.

Screens and keys, for reference:

| Screen | Key |
| --- | --- |
| welcome / any `@pause` / "place Disk #N" | `CR` |
| Specify Compiler Drive | drive letter then `CR` (`CR` alone never completes the list) |
| Specify Compiler Directory | `CR` (accepts `@Subdir`) |
| Verify Compiler Directory | **`SPACE`** then `CR` — the checkbox defaults to **No**, and `CR` alone loops back forever |
| Enter Serial Number | any 6 digits — a **format** check (`1-nnnnnn`), not a licence check; the distribution's own note says to enter any number |
| Choose Installation Options | `CR` only — see (4) |

Two more things that wasted time and are worth knowing:

- **dosemu creates the target directory lower case** on a case-sensitive host, so a perfectly
  good install reads as "0 files" if you only check the upper-case path. The script and the
  driver both check either spelling.
- **`$_hogthreshold = (0)`** is passed to dosemu. Without it dosemu sleeps whenever the DOS
  program looks idle, and this installer polls the keyboard between file operations — so it
  looks idle *while decompressing*, measured at ~5 % host CPU. The unpack was mostly dosemu
  sleeping, not work.

### The compiler runs

v3.03 staged into the dosemu2 C: drive compiles to OMF objects:

```
C:\HIGHC\BIN\HC386.EXE -c C:\PROBE.C     -> probe.obj, exit 0
```

`HC386.EXE` is only the 16-bit driver; the passes are `HCD3861/2.EXE`, and `CFIG386.EXE` shows the
kit ships Phar Lap's 386|DOS-Extender. dosemu2 runs all of it. Each object carries its own banner
in a COMENT record — `MetaWare High C [dosomf v2.05b(4pcs)]` plus the command line
`hc3.0@a2 -O1 -386` — which is useful grounding for the FID library records.

**A linker is not needed.** The convention is visible in the `.OBJ`, so #2 needs only compilation.

### The libraries are OMF, and FID already ingests them

Every `.LIB` is a standard OMF library (`0xF0` LIBHDR, page size 16) with names intact. Probed with
the existing `cargo xtask fid-build`, no code changes:

| Library | ingested | language-skipped |
| --- | --- | --- |
| v2.31 `SMALL/HC386.LIB` | **297** | 145 |
| v3.31 `small/hc386.lib` | **300** | — |
| v3.03 `LIB/HCC386.LIB` | **211** | 0 |
| v3.03 `LIB/HC386.LIB` | 0 | **252** |
| v3.04 `small/hc386.lib` | 0 | (same first-module pin) |
| v2.31 `HCNA.LIB`, `HCLOC.LIB`; v3.03 `HCNA.LIB` | 0 | 1–83 |

⚠️ **A real bug this exposed, and it is not MetaWare-specific.** These libraries mix 16-bit and
32-bit modules. `fid-build` pins the library's language from **whichever module comes first** and
then skips every module that disagrees — so v3.03's main C runtime ingests **nothing** while
reporting only `ingested 0`, and the doc's health check ("symbols did not survive extraction")
mis-diagnoses it. The `one library, one language` invariant is right and must stay; what is wrong
is inferring the language implicitly. Fix: an explicit `--language` pin on `fid-build`, plus a
summarised skip count instead of one identical line per module (259 lines of noise here).

## Calling convention — measured, and it corrects an earlier claim

⚠️ **Correction.** An earlier version of this plan stated High C 386 "is a register-convention
compiler" and that the `gcc` placeholder would therefore be badly wrong. **That was an assumption,
and the compiler's own output contradicts it.** Default v3.03 codegen (`-O1 -386`, no pragmas) is
ordinary **32-bit cdecl**:

```
i6(a,b,c,d,e,f):     push ebp; mov ebp,esp
                     mov eax,[ebp+8]; add eax,[ebp+0xc] ... add eax,[ebp+0x1c]
                     leave; ret                      <- args on the stack, left to right
caller:              push 3; push 2; push 1; call add3; add esp,0xc   <- caller cleans up
clobber:             push edi; push esi; push ebx ... pop ebx; pop esi; pop edi
                                                     <- EBX/ESI/EDI callee-saved
dmix(int,double,int): fildl 0x8(ebp); faddl 0xc(ebp)  <- doubles on the stack, result in ST(0)
```

Cross-check on the real samples: `call <fn>; add esp,0x4` and `push`-ed arguments appear
throughout, consistent with the same convention.

**The one divergence found that matters**, and it is decompilation-visible:

```
sret(int a) -> struct S {int a; int b;}:
      mov eax,-0x8(ebp); mov edx,-0x4(ebp); leave; ret
```

An 8-byte struct comes back in **EAX:EDX**, where gcc/SysV i386 returns it through a hidden
pointer. Structs passed *by value* go on the stack (`pmix` reads `[esp+0xc]`, `[esp+0x10]`).

**So #2 is smaller and lower-risk than planned, and no longer a blocker:** start from Ghidra's
x86-32 gcc cspec, change the struct-return rule, validate against probe output — rather than
deriving a register convention from nothing. It is still worth doing, because a function returning
a small struct decompiles wrongly without it.

**Still unmeasured, do not assume:** High C's pragmas/options that can change the convention (none
were used here); varargs beyond the trivial case (`_mwargstack` is an interesting extern); `long
long`/float returns; and which version built the real samples — answered by #3, not by guessing.

## 1. Detection (`loader/metaware.rs`, mirroring `loader/watcom.rs`)

Same shape as `watcom.rs`: scan for the C run-time's own strings, return vendor + era, expose
`compiler_label()` and a `compiler_spec_id()`.

**The container hands us a clean place to look** — verified on both samples: strings in the
stub/16-bit region belong to the *extender*, strings in the 32-bit flat image belong to the
*compiler runtime*.

- extender (16-bit region): `DOS extender Copyright 1991-1994 by Doug Huffman`,
  `A PAGE FAULT HAS OCCURRED …`, `__X386_VM_DISABLED`, `DGROUP relative address`
- compiler runtime (32-bit image): `NULL code pointer called`, `Not enough memory`,
  `Bad stack size parameter`, `Stack Overflow`

Scan the **32-bit image**, not the whole file — otherwise it identifies the extender, which says
nothing about the compiler.

⚠️ Those four strings are a **candidate** tell. That they are High C's is what #1 must prove, by
linking a program with the real runtime and checking the same strings appear — the standard
`watcom.rs` already sets (grounded in source *and* verified against a real toolchain). The
`LIB/SRC/*.ASM` sources shipped with v2.31 are the corroborating source-level grounding.

Tests, independent of user-provided binaries (the `watcom_detection` + `compiler_version` pattern):
committed **marker fragments** so the gate runs without the toolchain; **no-false-positive** against
the corpus's Watcom, Borland and DJGPP binaries; era discrimination across the versions that
install, at the honest banner granularity `watcom.rs` documents.

## 3. FID databases

Per [`fid-building-databases.md`](fid-building-databases.md) §"Versions: one database per toolchain
build", into `oracle/fid/db/` (already searched by `paths::fid_db_dirs`). The format question is
settled — OMF, ingesting today. Remaining work per version: the `--language` pin above, a
common-symbols exclusion list, verification by identifying functions in a binary **we compiled
ourselves** (the `fid_watcom_identify` pattern), and a `fid_database_drift` entry.

Useful side effect: with several version databases attached, the match profile **dates** an unknown
image ([`fid-building-databases.md`](fid-building-databases.md) §"Using the databases to date a
binary") — which is how "which High C built this?" gets answered by evidence.

## Revised sequencing

Step 0 changed the order: the cspec shrank, and FID/detection carry more of the value.

1. **Loader** ([`x32-loader-notes.md`](x32-loader-notes.md)) — independent of all of this; synthetic tests.
2. **`fid-build --language` pin** — small, unblocks ~250 discarded modules, and fixes a general bug.
3. **FID databases** for v2.31 + v3.03 — ≈508 named functions already reachable, plus whatever the
   pin recovers.
4. **Detection** (#1) — validated against a self-linked binary; also tells us whether the samples
   are High C at all.
5. **cspec** (#2) — gcc x86-32 as the base, struct-return-in-EAX:EDX as the delta, probes as the gate.
6. *(optional)* v3.04/v3.31 installer under dosemu2 for more FID columns; v3.2 (ZOO/OS-2) last.

A staging script `scripts/setup-metaware-dosemu.sh` mirroring `setup-watcom-dosemu.sh` (env-located
archives, `mktemp` work dir, stage into `DOSEMU_C`, optional `--compile`) makes steps 3–5
repeatable; it is the natural first commit of this track.
