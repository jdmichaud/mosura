# The WAR2 compiler — synthesis of the "custom compiler" question

*2026-08-18. This closes out a question several investigation generations have circled:
which compiler produced WAR2.EXE's bytes, and why does no compiler we own reproduce them?
Prior conclusions invariably retreated to "a mysterious custom compiler". This document
assembles both projects' evidence (mosura `docs/watcom-codegen-fingerprint.md`,
warcraft2-re `analysis/toolchain.md` + `analysis/openwatcom-investigation/`), adds the
measurements that were missing, and states what is now known, what is newly fixed, and
what genuinely remains.*

## The two piles, and why "custom compiler" kept regenerating

WAR2's application code (not its CRT — Blizzard's own functions) simultaneously exhibits:

**Pile A — 10.0a-and-later markers.**
- The byte-compare **promotion** (`MOV AL,[mem]; AND EAX,0xff; CMP EAX,imm`), verified at
  the instruction level on **103 sites** with a byte-load writer (5 programmer-mask
  lookalikes, 10 unattributed — `dumpfp` over the sb43 manifest). Among every measured
  shipped revision (7.0…11.0, OW2) only **10.0a** promotes — and see below: the promotion
  is a *documented a-level fix*.

**Pile B — behaviors 10.0a does not produce under any accepted flag.**
- **No `LEA reg,[reg+imm]` copy+add folds** — zero in 380 KB — where every shipped
  revision measured (9.5b, 10.0-LA beta, 10.0a `wcc386` *and* `wpp386`, 10.6, 11.0, OW2)
  folds the probe `x % 4 + 0x12` into `LEA EAX,[EDX+0x12]` under `-onatx`, `-onasx`,
  `-os`, `-ot`, `-or`, `-3r/-4r/-5r`, and bare flags. Only `-od` (no optimizer, spills
  everything) avoids it.
- The **register-allocation order** divergence (warcraft2-re's `ecx-allocator-mystery`:
  `DoubleRegs[]` picks EDX where the target picks ECX/EBX — 13-byte pure-register diffs
  on otherwise identical 43-byte bodies).
- **Callee-saves of unmodified registers** (`bxsidi-save-no-modify`; corpus-wide:
  missing prologue saves outnumber extra ones 1231 : 150).
- Opposite **load scheduling** (`scheduler-loadv-vs-loadold`).

No shipped binary has both piles, so every investigation ended at "custom".

## What the A_LEVEL discovery settles

The 10.0a CD (`WATCOM_C10A.ISO` — mastered 1994-09-23) carries **`A_LEVEL/`**: 1,266
`PTCH*.A` bpatch deltas + `APPLYA.BAT` + `README.A` — the patch set that turns a 10.0 GA
install into 10.0a. Findings:

1. **`README.A`'s Code Generator section documents the promotion as an a-level FIX**:
   *"A compare of an unsigned type shorter than an int and a constant which could be
   represented in that type would be done as the original type instead of being promoted
   to an integer."* This is vendor documentation for the fingerprint doc's measured
   "one-release excursion", and it means **WAR2's compiler is at or after a-level** —
   the 10.0-GA hypothesis for WAR2 is dead.
2. The a-level codegen changelog contains **no LEA-fold or allocator changes** — pile B
   is not the GA↔a delta.
3. `ptch23.a` patches `binb\wcc386.exe`, but the bpatch format (OW `bld/bdiff`) writes
   only `CMD_SAMES` (copy-from-old) and `CMD_DIFFS` (literal *new* bytes): the old
   content of exactly the changed regions is absent, so **GA's wcc386 cannot be
   reconstructed from the patch**.
4. The CD's plain tree and its 384 install payloads are all stamped 1994-09-01 —
   post-patch vintage. No GA bytes on the disc.
5. The harness compiler is byte-identical (sha256) to the CD's `BINB/WCC386.EXE` —
   every measurement in both projects really is "10.0a, the disc".

**GA media is extinct publicly**: WinWorld's "10.0" page carries only the LA beta and the
10.0a CD; both archive.org "10.0" items are the same `WATCOM_C10A` disc; the OpenWatcom
FTP archive starts at 11.0c; no 10.0**b** is attested anywhere searched. (Sources:
[WinWorld](https://winworldpc.com/product/watcom-c-c/100),
[archive.org watcomcc10.0cd-rom](https://archive.org/details/watcomcc10.0cd-rom),
[archive.org Watcom_C_10.0](https://archive.org/details/Watcom_C_10.0),
[openwatcom.org/ftp/archive](http://openwatcom.org/ftp/archive/),
[Hsieh's Watcom FAQ](https://www.azillionmonkeys.com/qed/watfaq.txt) — "WATCOM had
patches available in a couple months" after the troubled 10.0 GA.)

## The `-5r` discovery — one pile-B member was ours all along

Reading the LEA selection in the Open Watcom source (`bld/cg/intel/c/i86ver.c`,
`V_LEA_GOOD`) exposed CPU/size gates on these transforms. One is live in 10.0a:
**`-5r` (Pentium tuning) suppresses the in-place scaled LEA** — `SHL EAX,2` instead of
`LEA EAX,[EAX*4]` — exactly WAR2's shape (the gate survives in OW source as
`op1 == result && _CPULevel( CPU_586 )`). The CPU digit is tuning, not a convention
change, and WAR2 is a Pentium-era title; the profile had been `-4r` since the
byte-zero-store finding (itself a `-3r`→`-4r` correction of the same kind).

Corpus-wide on sb43 sources (`/data/be2/sb43-5r.tsv`):

| | `-4r` profile | `-5r` profile |
| --- | --- | --- |
| EXACT | 586 | **591** (+6, −1) → **592** with the per-function digit (below) |
| SHL>LEA divergence rows | 157 | **12** |
| candidate in-place scaled LEAs | 470 | **76** |
| global similarity | 0.3841 | 0.3858 |

The profile base is now `-5r` (`recompile::buildconfig::watcom_10_0a`). The
`selection SHL>LEA` family in `byte-exact-families.md` was a **flags** family, not a
compiler one.

The lone `-5r` regression exposed one more real fact: **WAR2's own build mixed tuning
levels.** Exactly one contiguous module — 9 functions, 0x69fb0..0x6e6e0, 18 sites —
contains in-place scaled LEAs, the form `-5r` can never emit, and measurably improves
under `-4r` (its EXACT function returns, neighbors gain similarity). A per-module CFLAGS
difference in Blizzard's Makefile. The CPU digit is therefore recovered **per function**
(`buildconfig::Evidence::in_place_scaled_lea`): presence of the form proves pre-Pentium
tuning and downgrades that function to `-4r`; the evidence is one-sided, so absence
keeps `-5r`. EXACT 591 → **592**; the only verdict change is that function.

## Watcom 10.5 measured (2026-08-19) — a release the fingerprint work never covered

The store held `Watcom CPP 10.5 (ISO).7z` (files stamped July 1995 — exactly WAR2's build
window) and it was absent from the measured list. Its DOS-hosted `wcc386.exe` was extracted
by building OW 1.0's own `wpack` unpacker natively and unpacking the installer's spanned
`PCK00017` archive; the compiler runs in the harness via a tree swap.

Results, all three quick discriminators plus the runtime:

- **Codegen: indistinguishable from 10.0a on our dials.** The reg+imm LEA fold probe folds
  (`LEA EAX,[EDX+0x12]`), the byte-compare promotion promotes, `-5r` selects `SHL` over the
  in-place scaled LEA — byte-for-byte the same probe outputs as 10.0a.
- **Runtime: decisively NOT WAR2's.** Against WAR2's 130 name-matched library functions
  (OMF-paged module extraction, relocation-masked byte compare): **10.0a CLIB3R = 50
  byte-identical / 80 differing; 10.5 CLIB3R = 19 / 111.** WAR2 links the 10.0a-era runtime.

Consequences: 10.5 is eliminated as WAR2's toolchain; the interim-build hypothesis SURVIVES
and narrows — the no-fold code generator is not 10.5 any more than it was 10.0a or 10.6, and
the runtime pins Blizzard's tree to 10.0a-era libraries with a codegen between shipped
snapshots. Also closed: the second 10.0 ISO in the store (`Watcom_C++_10.0.iso`) differs by
hash from `WATCOM_C10A.ISO` but carries the same `A_LEVEL/` patch set and 1994-09-01
payloads — another a-level pressing; GA media remains extinct.

Next per JD: OW 1.0 source reconnaissance (`open_watcom_1.0.0-src.zip`, already in store —
and the oldest OW source in existence) for the four pile-B decision procedures.

## OW 1.0 source reconnaissance (2026-08-19) — the pile-B dials located

Level-1 recon over `open_watcom_1.0.0-src.zip` (the oldest OW source in existence), read
against empirical probes of the store's compilers:

- **The add-fold is one decision point**: `bld/cg/intel/c/i86ver.c`, `V_LEA_GOOD` /
  `V_LEA` — the `OP_ADD`/`OP_SUB` arm returns TRUE (fold to LEA) on any CPU ≥ 286. OW 1.0
  carries a size gate (`OptForSize > 50 → FALSE`) that MEASURABLY DOES NOT EXIST in 10.0a
  or 10.5 (both fold under `-os` — probed): the gate postdates 10.5, proving this exact
  dial was being worked on in WAR2's era. An interim build with the fold disabled (the
  gate's ancestor, or a development state returning FALSE) is textually plausible in a way
  it never was before.
- **The allocation order is one table**: `386rgtbl.c`'s `DoubleRegs[] = EAX, EDX, ECX,
  EBX, ESI, EDI` — matching 10.0a's observed behavior; WAR2's allocator prefers ECX/EBX
  where 10.0a picks EDX (warcraft2-re's `ecx-allocator-mystery`), i.e. the interim build's
  table was ORDERED DIFFERENTLY.
- Both dials are DATA or SMALL CODE in the compiled compiler: the verifier's `OP_MUL` arm
  carries a searchable signature (the 3/5/9 constant triple beside the `OP_ADD` arm), and
  the register table is a byte sequence of hw_reg_set masks.

**The level-2 experiment this enables — the dial-patched verifier**: locate `V_LEA`'s
`OP_ADD` arm in 10.0a's own `wcc386.exe` (via the 3/5/9 signature; the binary is a DOS/4GW
LE image, which mosura can load and decompile — dogfood), patch it to refuse the fold,
re-run the corpus. If the add-fold rows convert, repeat for the `DoubleRegs` order. Each
patch is falsifiable against the four discriminators before a corpus run. This is compiler
binary surgery and a new phase — awaiting JD's go.

## What genuinely remains, stated precisely

After `-5r`, WAR2's compiler still differs from the shipped 10.0a in:

1. the reg+imm LEA fold (188 MOV>LEA divergence rows remain; the add-fold is
   flag-unreachable in every shipped revision measured),
2. `DoubleRegs[]` allocation order,
3. callee-save policy (saves unmodified registers),
4. load scheduling order.

These are all **instruction-selection/allocation dials that demonstrably exist in the
lineage's own codebase** — the OW source carries size- and CPU-gates on the very same
transforms, set differently. The sharpened conclusion is therefore not "a mysterious
custom compiler" but: **an interim 10.0-line code-generator build — a-level front end
with selection/allocation settings between the shipped snapshots.** Watcom shipped
rolling interim patch builds routinely in that era (a-level itself is a dated snapshot,
1994-09-22, on a disc mastered the next day); nothing requires Blizzard modification.
No such interim build survives in any public archive found.

Practical consequences:

- The remaining pile-B divergences are a **bounded, named residual** of the byte-exact
  campaign — compiler-policy families (`byte-exact-families.md`: F2's add-fold part, F3,
  the scheduling and pure-regalloc clusters) that no source or flag change can close,
  and that should not be chased per-function.
- Compiler-invariant work (structure, typing, block layout, call recovery — most of the
  `missing` mass) is unaffected and remains the live frontier.
- If 10.0-GA or any interim 10.0 build ever surfaces, the discriminators are committed
  and cheap: the fold probe (`x % 4 + 0x12`), the promotion probe, `clear_strip`'s
  allocation order, and the full recompile harness.

## Reproduction

- Promotion site classification: `cargo run --release --example dumpfp -- /data/be2/sb43/manifest.tsv`
  (gitignored `dump*`; logic documented in its header).
- Fold table: `FOLD.C` = the two probe functions above; compiled per revision via the
  staged dosemu trees (`~/.dosemu/drive_c/WAT100A|WAT106|W110|wat95b`, flags
  `-4r -fpi87 -s -onatx`), the LA beta under wine (`C:\WBETA\BINNT\WCC386.EXE`), OW2
  natively; `scripts/extract-omf-code.py` + `objdump -D -b binary -m i386`.
- A_LEVEL: `7z x WATCOM_C10A.ISO "A_LEVEL/README.A" "A_LEVEL/APPLYA.BAT"`.
- `-5r` corpus: the standard remeasure runbook — the profile now carries the flag.
