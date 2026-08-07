# Watcom codegen fingerprinting — pinning the exact revision

Watcom's runtime banner is an **era** stamp (copyright year range) and no header field
carries the exact release for **DOS/4GW LE** output (the WAR2 case) — see
[`watcom-detection.md`](watcom-detection.md). The exact revision is recoverable only from the
**code the compiler generates**: different `wcc386` revisions make different instruction /
register-allocation choices for the same source. This is the signal that pins WAR2's exact
Watcom revision and feeds byte-exact recompilation (the `D1` north star).

## Reproducible setup — running a historical `wcc386` under dosemu2

**One command** (`scripts/setup-watcom-dosemu.sh`) stages any ISO-based revision from its archive
into the dosemu C: drive and optionally compiles a probe — the codified, disk-cleanup-proof form of
the manual recipe below. The extracted toolchains keep getting deleted, but the archives under
`$WATCOM_ARCHIVES` (default `/data/tools/watcom`) survive, and this rebuilds from them:

```sh
# stage 11.0 and compile the probe → C:\watcom_c.obj
scripts/setup-watcom-dosemu.sh 11.0 --compile oracle/codegen-probes/watcom_cg.c
python3 scripts/extract-omf-code.py ~/.dosemu/drive_c/watcom_c.obj \
    | cmp - oracle/codegen-probes/watcom/11.0.code    # byte-identical
```

It auto-finds the archive by version, extracts the nested ISO, locates the DOS-extender host
(`BINW`/`BINB`, never the NT/`BIN95` stubs), normalises it to `C:\WAT<ver>\BIN` + `H` + `LIB386`,
and emits the compile BAT. Verified end-to-end on 10.6 and 11.0 (each reproduces its committed
`<rev>.code`). Scope: the ISO revisions (10.0/10.0a/10.5/10.6/11.0); the floppy sets
(7.0/8.5a/9.01/9.5b) ship everything packed in `.WPK` and need `INSTALL.EXE` first — see the next
section, which is now a *worked* procedure rather than a task note.

### Floppy-set revisions (7.0 / 8.5a / 9.01 / 9.5b) — run the vendor installer

Everything on these disks is Watcom-packed, **including the files whose extension suggests
otherwise**: `WCC386.DOS` starts `03 24 01 01`, not `MZ`. There is no unpacker on this machine
(`bld/wpack` in the OW2 tree does not build against glibc — `dos.h`, `direct.h`, `sys/utime.h`), so
the only route is the vendor's own `INSTALL.EXE`, driven from a stdin answer file. Verified on 9.01
2026-08-06; it produced `bin/wcc386.exe` (181,192 bytes, 28 May 1992) plus `wcc386p.exe` and
`dos4gw.exe`.

```sh
DC=~/.dosemu/drive_c
rm -rf /tmp/w901src && mkdir -p /tmp/w901src            # all six floppies flattened into one dir
for d in /data/w901/d0*/; do cp -n "$d"* /tmp/w901src/; done
# continue=y | doshost=y os2host=n dosx=y | pls=n ecs=n dos4g=y ads=n | win3tgt=n os2tgt=n
#            help=n nlm=n wprof=n pen=n     (CRLF, one per line, pad with extra n)
printf 'y\r\ny\r\nn\r\ny\r\nn\r\nn\r\ny\r\nn\r\nn\r\nn\r\nn\r\nn\r\nn\r\nn\r\n' > "$DC/ANS.TXT"
printf '@echo off\r\nlredir M: /tmp/w901src >C:\\LRED.TXT\r\nM:\\INSTALL M: C:\\WAT901 <C:\\ANS.TXT >C:\\INSOUT.TXT\r\n' \
    > "$DC/MKW901.BAT"
( cd "$DC" && timeout 400 dosemu -dumb -quiet -E MKW901.BAT </dev/null )
```

**Three traps, each of which silently produces a wrong or absent toolchain:**

1. **`INSTALL.EXE` demands a drive ROOT** — `INSTALL C:\W901SRC ...` is rejected as *"invalid"*.
   `lredir` must map the staging dir to its own letter. Its syntax here is a **plain unix path**
   (`lredir M: /tmp/w901src`), not the `LINUX\FS\...` form; `D:` and `E:` are already taken by
   dosemu2 itself. dosemu2 also gates which paths may be mapped — hence the one-line `~/.dosemurc`
   carrying `$_lredir_paths`. The path must have no dot components: `~/.dosemu/...` is refused
   outright, which is why the staging dir lives in `/tmp`.
2. **An undocumented `Do you wish to continue (y/n)?` precedes the 17 questions in `INSTALL.SCR`.**
   It eats answer #1 and shifts the whole file by one. The first attempt here silently installed the
   **OS/2-hosted** compiler (`NE` header, `DOSCALLS`/`VIOCALLS` imports) — which fails with *"This
   program cannot be run in DOS mode"*, an error that reads like a missing extender and is not.
   **Always confirm the host from the binary** (`xxd -s 0x3c`), never from the answers you intended.
3. **`if %dosx ask ...` means four questions appear only when DOS-extender support is accepted**, so
   a wrong answer earlier changes *how many* questions follow. Read `C:\INSOUT.TXT` back and check
   which questions were actually asked — the installer echoes them.

The manual recipe it replaces: the historical DOS-hosted compilers run under dosemu2. The one
non-obvious gotcha is that the `BINB/WCC386.EXE` build is **W32RUN-hosted**, so
`WATCOM/BIN/W32RUN.EXE` must be on the DOS `PATH` (without it: *"This program requires W32RUN.EXE
to be in your PATH"*).

```sh
# 1. extract the toolchain into the dosemu C: drive
7z e "Watcom CPP 10.0a.7z" "Watcom CPP 10.0a/WATCOM_C10A.ISO" -o/data/w10a
DC=~/.dosemu/drive_c
7z x /data/w10a/WATCOM_C10A.ISO -o"$DC" \
   "WATCOM/BINB/*" "WATCOM/BIN/*" "WATCOM/H/*" "WATCOM/LIB386/*"   # BIN/* pulls W32RUN.EXE too

# 2. C:\CG.BAT   (DOS command.com — single '>' redirect only, no 2>&1)
#    set WATCOM=C:\WATCOM
#    set INCLUDE=C:\WATCOM\H
#    set PATH=C:\WATCOM\BINB;C:\WATCOM\BIN
#    wcc386 CG.C >WCCOUT.TXT

# 3. run headless; object lands as C:\cg.obj
dosemu -dumb -quiet -E "CG.BAT"

# 4. disassemble with native Open Watcom's wdis (reads OMF .obj)
wdis -a cg.obj
```

Native Open Watcom 2.0 (Linux-hosted) compiles the same probe directly for the modern end of
the lineage — the built native compiler lives in the OW2 source tree at
`/data/open-watcom-v2/bld/cc/386/linuxx64/binbuild/wcc386.exe` (an x86-64 ELF despite the `.exe`
name; `WATCOM=/data/open-watcom-v2 wcc386.exe cg.c` → `cg.o`, which `extract-omf-code.py` reads).

**Full corpus reproducibility — verified.** Every committed `oracle/codegen-probes/watcom/<rev>.code`
is reproducible from its compiler: **10.0a / 10.6 / 11.0** via `scripts/setup-watcom-dosemu.sh`
(dosemu) and **ow2** via the native compiler above — each byte-identical to the committed bytes.
**9.01** comes from the floppy-set `INSTALL.EXE` recipe in the previous section rather than from
`setup-watcom-dosemu.sh` (the disks ship everything Watcom-packed); the object → code-bytes half of
its chain is checked the same way as the others,
`extract-omf-code.py 9.01.obj | cmp - 9.01.code` — byte-identical.

## The probe (`oracle/codegen-probes/watcom_cg.c`)

Five constructs. Three expose revision-specific **classification** boundaries: a **byte
comparison** (promotion), a **counted loop** (register allocation + loop shape), and a small
**switch**. Two more — **signed** and **unsigned division by a constant** (`x/7`, `x/10u`) — add
no classification power (see the div/mod/mul note below) but contribute a whole-binary **robustness
anchor**: division is far more common in a real binary than the setcc-int construct, so it is a
more reliably-present way to find the `cdq`/`movzx` fingerprint when scanning an arbitrary program.
(That fingerprint marks the lineage's outer ends — 9.01 or Open Watcom — not Open Watcom alone;
see the correction at the end of this file.)

## The `version → fingerprint` table (measured across the lineage)

Each revision compiled the probe under dosemu (native OW 2.0 directly); `cmpbyte` disassembled
with `wdis`. The **byte-compare-promotion** — the divergence the `warcraft2-re` A-level-patch
note tied to WAR2 — pins the boundary:

`cmpbyte(unsigned char c){ return c == 5; }`

Verbatim from `wdis -a <rev>.obj` on the committed objects (the `push N ; call __CHK` stack-probe
prologue every revision emits is elided from each row):

| Watcom revision | codegen | class |
| --- | --- | --- |
| **9.01** (1992, WATCOM Intl) | `cmp al,5 ; sete al ; movzx eax,al` | byte compare + zero-extend |
| **10.0a** (1994, WATCOM Intl) | `and eax,0ffH ; cmp eax,5 ; sete al ; and eax,0ffH` | **promote** to 32-bit compare |
| **10.6** (1995) | `cmp al,5 ; sete al ; and eax,0ffH` | byte compare, `AND`-masked |
| **11.0** (1997, Sybase) | `cmp al,5 ; jne L$1 ; mov eax,1` | byte compare, **branch — no `setcc` at all** |
| **Open Watcom 2.0** (2002+) | `cmp al,5 ; sete al ; movzx eax,al` | byte compare + zero-extend |

⚠️ **11.0's row was previously written `cmp al,5 ; sete al`, which its object does not contain** —
it branches instead of using `setcc`. Corrected here from `wdis` on `11.0.obj` (2026-08-06). The
consequence is live: `extract_signals` reports `result_zero_extended: None` for 11.0, because there
is no `SETcc` site to ask about, so 11.0 is classified purely by its `ECX` loop bound and ascending
switch. The matcher's `TABLE` row still records `zero_extended: Some(false)` for 11.0; that is
`consistent` with the observed `None` and nothing today contradicts it, **but it is an unevidenced
claim** — no 11.0 artefact shows a `SETcc` either way — and it would exclude 11.0 from any binary
that does show `SETcc ; MOVZX`. Left as-is deliberately rather than changed on a guess; flagged so
the next person to add a construct probes `setcc` on 11.0 first.

**Four** distinguishable signatures across five revisions — 9.01 and OW 2.0 are byte-identical on
this construct, and everything else differs. (It read "three" while 11.0's row was miswritten as a
`setcc` form.) But **9.01 changes what the boundaries mean**, and the earlier reading of this table
was wrong in one direction:

- **`cmp eax,5` (promote) is unique to 10.0a**, and 9.01 makes that claim *stronger*, not weaker:
  the promotion is a one-revision anomaly with plain byte compares on both sides of it, not the
  "early Watcom" behaviour it looked like when 10.0a was the oldest column. This is exactly the
  WAR2 base the `warcraft2-re` codegen investigation identified, now confirmed through mosura's
  tooling.
- **`+movzx` is NOT a "classic → Open Watcom" marker.** 9.01 emits it, 10.0a/10.6/11.0 do not, and
  Open Watcom does again. It brackets the lineage's **outer ends**; the classic 10.0a-11.0
  interior is what is unusual. Anything that read `SETcc ; MOVZX` as Open-Watcom evidence — the
  whole-binary matcher did — is corrected below.

### Combined fingerprint — three constructs uniquely identify each revision

No single probe separates all five revisions, but each construct draws its boundary at a
*different* point, so the tuple is unique. All four signal columns are **implemented** in the
matcher (`analysis::codegen_fingerprint::Signals`) and gated against the committed artefacts:

| revision | `cmpbyte` (promotion / zero-ext) | `loop` (bound reg) | `sw` (compare order) |
| --- | --- | --- | --- |
| **9.01** | `cmp al,5 ; movzx` | `ebx` | `1,2` ascending |
| **10.0a** | `cmp eax,5` (promote), no `movzx` | `ebx` | `1,2` ascending |
| **10.6** | `cmp al,5`, no `movzx` (`and` instead) | `ebx` | `1,2` ascending |
| **11.0** | `cmp al,5`, **no `setcc` — signal is `None`** | `ecx` | `1,2` ascending |
| **OW 2.0** | `cmp al,5 ; movzx` | `ecx` | `2,1` descending |

Boundaries, per construct: the `movzx` (**9.01 → 10.0a** *and* **11.0 → OW**, i.e. twice, at the
two ends), byte-compare-promotion (**10.0a → 10.6**, a one-revision anomaly), `loop` bound register
`ebx→ecx` (**10.6 → 11.0**), and `sw` compare-order (**classic → Open Watcom**). The matcher
classifies each committed probe **uniquely** (`matches_committed_self_compiled_probes`) — and
10.0a's `(promote, ebx, ascending)` tuple is the WAR2 base fingerprint.

**9.01 required a new `TABLE` row, not a new `Signals` variant.** Its tuple
`(byte compare, movzx, ebx, ascending)` is expressible in the four existing signal columns; what it
did not have was a row to match, so before this it classified as the **empty set** — "no known
Watcom revision", which reads as "not Watcom at all". Uniqueness survives, but only just: 9.01 is
separated from OW 2.0 by the loop register *and* the switch order, and from 10.6 by the `movzx`
alone. That narrowness is why the probe artefacts, not the table, are the gate.

**What this does NOT license.** These tables classify **body codegen**, and that is the only axis
they speak to. On this probe 9.01 is amply distinguishable from 10.0a — `9.01.code` is 150 bytes to
10.0a's 162, differing from offset 11 onward (`cmp -l`: 125 differing positions), because the two
disagree on `cmpbyte`'s promotion, on `cmpbyte`'s `movzx`, and on `divc`'s sign-extension idiom.
That says **nothing** about whether the two revisions' *prologues* differ, which is the separate
entry-shape question the function-start work asks and which is closed on its own measurement. Do
not carry a conclusion across: a revision pair can be trivially separable by body codegen and
byte-identical in every prologue.

### The committed ground-truth chain (fully in-repo)

`oracle/codegen-probes/watcom/` holds, per revision, the compiler's **OMF object**
(`<rev>.obj`, our probe compiled by the known toolchain) and the **flat code bytes**
(`<rev>.code`) the matcher is gated on. The transformation between them is
`scripts/extract-omf-code.py` (concatenates the LEDATA/LEDATA32 payloads; fixups deliberately
unapplied — `call` targets read `e8 00 00 00 00`, which the shape signals never depend on).
Regenerate and verify any artefact with:

```sh
python3 scripts/extract-omf-code.py oracle/codegen-probes/watcom/10.0a.obj \
    | cmp - oracle/codegen-probes/watcom/10.0a.code   # byte-identical
```

So every link is committed: probe source → known-compiler object → extractor script → code
bytes → gated test. Only *producing a new* `<rev>.obj` needs the historical toolchain (the
dosemu recipe above, or the wine one for [10.5](#getting-the-105-compiler-to-run)).

Revisions currently covered: `9.01`, `10.0a`, `10.5`, `10.6`, `11.0`, `ow2`. Every row in the
`TABLE` has an artefact behind it — a row without one is an inference, which is what 10.5 was.

### Two matchers — isolated probe vs whole binary

`analysis::codegen_fingerprint` exposes both scales, because the signals behave differently:

- **Isolated region** (`identify_watcom` / `extract_signals`) — the committed probe artefacts. You
  *know* the region is the discriminating construct, so all four signals are two-sided and the
  five revisions classify **uniquely** (`matches_committed_self_compiled_probes`).

- **Whole binary** (`identify_watcom_program`) — locates the constructs across an analyzed
  program's functions and aggregates. Two hard facts, both instrumented (not assumed):

  1. **Anchoring.** A byte-compare site is counted only with a byte anchor — a byte register, or a
     preceding `AND reg,0xff` / `MOVZX` — so a switch's `CMP EAX,1` or any integer compare is *not*
     misread as a promoted byte compare. Loops are located by a *backward* branch (either the
     test's own `Jcc`, or the compare being a back-edge target), covering both bottom-test (10.x)
     and top-test (11.0/OW) shapes.
  2. **One-sided evidence.** The quirks are *construct*-specific, not compiler-wide — real 10.0a
     code (`watcom_hello`) is full of plain `CMP AL,imm` byte compares even though 10.0a *promotes*
     the `unsigned char == const` shape. So a byte-form compare is non-diagnostic and must not
     exclude the promoting line; only the **presence** of a diagnostic pattern is evidence
     (`AND EAX,0xff ; CMP EAX,imm` → 10.0 line; `SETcc ; MOVZX` **or** inline signed constant
     division `MOV r,imm ; CDQ ; IDIV r` → **outside** the classic 10.0a-11.0 interior, i.e.
     `{9.01, open}` — two independent, mutually-corroborating anchors, either sufficient). Absence
     is inconclusive. The register/loop/switch artifacts are dropped at this scale (register choice
     varies per site), which is exactly why 9.01 and Open Watcom cannot be separated here — those
     two artifacts are the only things that separate them. Result: a class (the era — what WAR2
     needs), never a wrong exclusion.

The remaining depth (turning a class into an exact minor revision on an arbitrary binary) needs
matching the *same source construct* across binaries — a harder problem than pattern scanning.

Notes: 11.0's DOS host lives in `BINW` (with its own `W32RUN.EXE`), 10.0a's in `BINB` (loader
`W32RUN.EXE` in `BIN`). 10.5 is now measured too — see [10.5](#105-measured-not-inferred).

## Direction

- **Fingerprint table**: compile the probe with each Watcom revision (10.0/10.0a/10.5/10.6/11.0
  via dosemu; 9.01 done via the floppy `INSTALL.EXE` recipe, 8.5a/9.5b/7.0 still to do the same
  way; OW 1.x/2.0 native) and record the per-construct codegen. That is the
  `version → fingerprint` map. 9.01 is the standing warning that a missing column can invert a
  boundary's meaning, not just leave a gap — see the correction at the end of this file.
- **Matcher**: mosura disassembles an unknown binary (dogfooding its own engine), locates the
  equivalent constructs, and matches against the table to report the revision — the codegen
  counterpart to the header-field `compiler_version` detector.
- **WAR2**: its banner era (`1988-1994`) + DOS/4GW Professional pin the **10.0 family**; the
  byte-compare-promotion shape then selects the exact base revision, which is what a byte-exact
  recompile needs. This reproduces the `warcraft2-re` result through mosura's own tooling.

### Measured: div/mod/mul does NOT add classification power, but division IS a robustness anchor (2026-07-23)

With all four columns recoverable (dosemu 10.0a/10.6/11.0 + native ow2), a candidate probe
(`x/7`, `x%10`, `x*25`, `<<5`) was compiled across the lineage to test whether it discriminates
further. It does **not**: Watcom emits a real `idiv` (not a magic-number multiply), and the
divisor register draws the **same** `EBX`(10.x)→`ECX`(11.0/ow) boundary as the existing
`loop_bound_reg` signal. For this probe **10.0a ≡ 10.6** byte-for-byte. So the 3-construct probe
already extracts the maximum *classification* the **available** version set supports; further
classification gain needs the missing versions (10.0-beta ISO-layout / 9.01 floppy-`INSTALL.EXE`),
not more constructs.

## 10.5: measured, not inferred

`watcom:10.5/10.6` was for a long time a **one-measurement row wearing two labels**: only 10.6 was
compiled, and 10.5 was folded in because it sits between the measured 10.0a and 10.6 and nothing
was expected to change across it. That is precisely the reasoning the CORRECTION at the end of this
file calls a boundary of your corpus rather than of the compiler, so it was settled by measurement.

The result: **10.5 and 10.6 emit byte-identical code for the probe** — the same 156 bytes, against
162 for 10.0a, 158 for 11.0 and 150 for 9.01. The inference was right, and the combined row is now
a measured fact. The OBJ *containers* differ (version records), so `10.5.obj` is a genuine second
artefact and not a copy — `watcom_10_5_and_10_6_emit_identical_probe_code` asserts both halves,
so a future revision that wants to split the row has to produce a probe whose code actually
differs.

### Getting the 10.5 compiler to run

Two obstacles, neither of them dosemu's fault (the old "Loader read error" note blamed the
emulator; the file was simply truncated):

1. **The CD's C compiler is damaged.** `BINW/WCC386.EXE` is a 65,536-byte stub — and is dated a day
   later than every other file on the disc. The real 567,558-byte binary exists only inside the
   installer archives, as `DISKIMGS/DISK02+03/PCK00017.{1,2}`. Unpacking those needed a `wpack`
   decoder: see [`oracle/wpack/`](../oracle/wpack/README.md).
2. **This media is Windows-hosted, so there is no DOS compiler to run.** The unpacked binary is a
   W32RUN (LX) image that answers `This program requires W32RUN.EXE to be in your PATH` under
   dosemu. The way through is not DOS at all: `BINNT/WCC386.EXE` is a small **PE32 launcher** that
   runs under **wine** and loads its sibling `BINW\WCC386.EXE` — so dropping the unpacked binary in
   as that sibling gives a working compiler.

```sh
# 1. unpack the real compiler (see oracle/wpack/README.md for the archive-directory scan)
cat DISKIMGS/DISK02/PCK00017.1 DISKIMGS/DISK03/PCK00017.2 > pck00017.bin
python3 oracle/wpack/wunpack.py pck00017.bin /tmp/w105

# 2. lay out BINNT (launcher) + BINW (real compiler) + H, then compile under wine.
#    The source must be C:\WATCOM_C.C so the OBJ's THEADR matches the other revisions'.
cp /tmp/w105/wcc386.exe  <tree>/BINW/WCC386.EXE
cp oracle/codegen-probes/watcom_cg.c "$WINEPREFIX/drive_c/WATCOM_C.C"
cd "$WINEPREFIX/drive_c" && INCLUDE='C:\W105\H' wine 'C:\W105\BINNT\WCC386.EXE' WATCOM_C.C
#    -> WATCOM C32 Optimizing Compiler  Version 10.5 ... Code size: 156

python3 scripts/extract-omf-code.py WATCOM_C.obj > oracle/codegen-probes/watcom/10.5.code
```

Worth keeping in mind for the other absent revisions: **the compiler being unrunnable was a
property of the media and the host, not of the emulator.** Both blockers here were mechanical.

**Precise re-measurement of the codegen (append-only probe, both signs, disassembled with
mosura's own engine).** The exact per-revision codegen for `int divc(int x){return x/7;}` and
`unsigned udivc(unsigned x){return x/10u;}`:

| revision | `divc` (signed / 7) | `udivc` (unsigned / 10) |
| --- | --- | --- |
| **9.01** | `MOV EBX,7 ; CDQ ; IDIV EBX` | `MOV EBX,0xa ; XOR EDX,EDX ; DIV EBX` |
| **10.0a** | `MOV EDX,EAX ; MOV EBX,7 ; SAR EDX,0x1f ; IDIV EBX` | `MOV EBX,0xa ; XOR EDX,EDX ; DIV EBX` |
| **10.6** | `MOV EDX,EAX ; MOV EBX,7 ; SAR EDX,0x1f ; IDIV EBX` | `MOV EBX,0xa ; XOR EDX,EDX ; DIV EBX` |
| **11.0** | `MOV EDX,EAX ; MOV ECX,7 ; SAR EDX,0x1f ; IDIV ECX` | `MOV ECX,0xa ; XOR EDX,EDX ; DIV ECX` |
| **OW 2.0** | `MOV ECX,7 ; CDQ ; IDIV ECX` | `MOV ECX,0xa ; XOR EDX,EDX ; DIV ECX` |

Two corrections to earlier assumptions, both now measured (variable `x/y` and `x%7` compiled too,
same shapes):

1. **Every revision INLINES division by a constant** — none calls a `__iXD`/`__uXD` helper. (The
   only `call` in each function body is the ubiquitous fixup-blanked stack-probe in *every*
   prologue, `push N ; call __STK`, not a division helper — it is present in `cmpbyte`/`loop`/`sw`
   too.) So an "inline-vs-helper" anchor is **unsound**: it would false-positive on the whole
   classic line.
2. The divergence is the **sign-extension idiom**: the classic **10.0a/10.6/11.0 interior** uses
   `MOV EDX,EAX ; … ; SAR EDX,0x1f` and **never emits `CDQ`** (confirmed for variable, constant,
   and modulo division). The commonly-assumed "`cdq ; idiv` is universal for variable division"
   does **not** hold for Watcom classic.

So the sound, non-redundant **whole-binary anchor** is the inline *signed* constant division
`MOV r,imm ; CDQ ; IDIV r`, wired one-sided into `identify_watcom_program` (folded into
`result_zero_extended`, composing with `SETcc ; MOVZX`). Guards, each measured
(`inline_const_div_anchor_rejects_lookalikes`):

- **variable** signed division is `MOV r,<reg> ; CDQ ; IDIV r` — the pre-`CDQ` move is
  register-to-register, so the immediate-load requirement rejects it (this is what makes the
  anchor "*constant* division", not bare `cdq;idiv`);
- **unsigned** constant division is `MOV r,imm ; XOR EDX,EDX ; DIV r` — emitted **identically by
  every revision**, so it is non-diagnostic and deliberately not matched (`DIV`/`XOR`, not
  `IDIV`/`CDQ`);
- the classic signed constant form uses `SAR`, not `CDQ`, so it cannot match the window.

This is explicitly a **robustness / coverage** add (division is common in real binaries), **not**
new classification power — it draws the same boundary the `movzx` signal already draws.

### CORRECTION (2026-08-06, 9.01): `CDQ` and `MOVZX` are not Open-Watcom anchors

Measured on `oracle/codegen-probes/watcom/9.01.obj`: 9.01 emits **both** shapes this document
previously called Open-Watcom evidence — `cmp al,5 ; sete al ; movzx eax,al` and
`mov ebx,7 ; cdq ; idiv ebx`. Both anchors therefore mark *the lineage's outer ends*
(9.01 **or** Open Watcom), not Open Watcom alone, and the surviving fact is the narrower one:
**the classic 10.0a/10.6/11.0 interior emits neither.**

Consequences, all landed:

- `identify_watcom_program` now reports the pair `{watcom:9.01, watcom:open}` where it used to
  report `watcom:open`. That is a *loss of precision and a gain of correctness*: what separates
  9.01 from Open Watcom is the loop-bound register and the switch compare order, and those are
  exactly the register-allocation artifacts the whole-binary scale drops by design. Narrowing to
  `watcom:open` was a wrong exclusion of the kind that matcher exists to avoid.
- `inline_const_div_anchor_fires_on_ow2_not_classic` is renamed
  `inline_const_div_anchor_fires_on_the_cdq_revisions` and now asserts the anchor on 9.01 too.
- **WAR2 is unaffected.** Its fingerprint is the *promoting* `cmp eax,5`, which is 10.0a's alone
  and is a positive 10.0-line anchor, not a `movzx`/`cdq` one. Nothing about the 10.0a base
  identification rests on the corrected claim.

The general lesson: a boundary inferred from the **ends of the version set you happen to have** is a
boundary of your corpus, not of the compiler. `movzx` looked like a clean classic→Open-Watcom
transition for as long as 10.0a was the oldest column.

`10.5` was the other instance of the same shape, and it has since been
[measured](#105-measured-not-inferred) rather than argued: its row was one measurement (10.6)
wearing two labels. Note how the two resolved differently — filling in 9.01 **inverted** a boundary's
meaning, filling in 10.5 **confirmed** the guess. That is the point: which way an inference falls is
not predictable from the inference, so the only way to know is to go and measure it. Both remaining
gaps (10.0-beta, and the 7.0/8.5a/9.5b floppy sets) are still inferences of exactly this kind.
