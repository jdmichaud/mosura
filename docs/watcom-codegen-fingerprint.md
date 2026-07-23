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
(7.0/8.5a/9.01) ship the runtime packed in `.WPK` and need `INSTALL.EXE` first (A4 Stage 2).

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

## The probe (`oracle/codegen-probes/watcom_cg.c`)

Five constructs. Three expose revision-specific **classification** boundaries: a **byte
comparison** (promotion), a **counted loop** (register allocation + loop shape), and a small
**switch**. Two more — **signed** and **unsigned division by a constant** (`x/7`, `x/10u`) — add
no classification power (see the div/mod/mul note below) but contribute a whole-binary **robustness
anchor**: division is far more common in a real binary than the setcc-int construct, so it is a
more reliably-present way to find Open Watcom's fingerprint when scanning an arbitrary program.

## The `version → fingerprint` table (measured across the lineage)

Each revision compiled the probe under dosemu (native OW 2.0 directly); `cmpbyte` disassembled
with `wdis`. The **byte-compare-promotion** — the divergence the `warcraft2-re` A-level-patch
note tied to WAR2 — pins the boundary:

`cmpbyte(unsigned char c){ return c == 5; }`

| Watcom revision | codegen | class |
| --- | --- | --- |
| **10.0a** (1994, WATCOM Intl) | `cmp eax,5 ; sete al` | **promote** to 32-bit compare |
| **10.6** (1995) | `cmp al,5 ; sete al` | byte compare |
| **11.0** (1997, Sybase) | `cmp al,5 ; sete al` | byte compare |
| **Open Watcom 2.0** (2002+) | `cmp al,5 ; sete al ; movzx eax,al` | byte compare + zero-extend |

Three distinguishable signatures, with two boundaries: **promote → byte** between 10.0a and
10.6, and **+movzx** at the classic → Open Watcom transition. Crucially the promoting form
(`cmp eax,5`) is **unique to the early 10.0 line** — which is exactly the WAR2 base the
`warcraft2-re` codegen investigation identified, now confirmed through mosura's tooling.

### Combined fingerprint — three constructs uniquely identify each revision

No single probe separates all four revisions, but each construct draws its boundary at a
*different* point, so the tuple is unique. All four signal columns are **implemented** in the
matcher (`analysis::codegen_fingerprint::Signals`) and gated against the committed artefacts:

| revision | `cmpbyte` (promotion / zero-ext) | `loop` (bound reg) | `sw` (compare order) |
| --- | --- | --- | --- |
| **10.0a** | `cmp eax,5` (promote), no `movzx` | `ebx` | `1,2` ascending |
| **10.6** | `cmp al,5`, no `movzx` | `ebx` | `1,2` ascending |
| **11.0** | `cmp al,5` | `ecx` | `1,2` ascending |
| **OW 2.0** | `cmp al,5 ; movzx` | `ecx` | `2,1` descending |

Three independent boundaries at different revisions: byte-compare-promotion (**10.0a → 10.6**),
`loop` bound register `ebx→ecx` (**10.6 → 11.0**), and `sw` compare-order + the `movzx`
(**classic → Open Watcom**). The matcher classifies each committed probe **uniquely**
(`matches_committed_self_compiled_probes`) — and 10.0a's `(promote, ebx, ascending)` tuple is
the WAR2 base fingerprint.

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
dosemu recipe above).

### Two matchers — isolated probe vs whole binary

`analysis::codegen_fingerprint` exposes both scales, because the signals behave differently:

- **Isolated region** (`identify_watcom` / `extract_signals`) — the committed probe artefacts. You
  *know* the region is the discriminating construct, so all four signals are two-sided and the
  four revisions classify **uniquely** (`matches_committed_self_compiled_probes`).

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
     division `MOV r,imm ; CDQ ; IDIV r` → Open Watcom — two independent, mutually-corroborating
     ow2 anchors, either sufficient). Absence is inconclusive. The register/loop/switch artifacts
     are dropped at this scale (register choice varies per site). Result: a class (the era — what
     WAR2 needs), never a wrong exclusion.

The remaining depth (turning a class into an exact minor revision on an arbitrary binary) needs
matching the *same source construct* across binaries — a harder problem than pattern scanning.

Notes: 10.5 didn't run under dosemu2 here (its `W32RUN`/`DOS4GW` loader hit a "Loader read
error"); the four points above already bracket the transition. 11.0's DOS host lives in `BINW`
(with its own `W32RUN.EXE`), 10.0a's in `BINB` (loader `W32RUN.EXE` in `BIN`).

## Direction

- **Fingerprint table**: compile the probe with each Watcom revision (10.0/10.0a/10.5/10.6/11.0
  via dosemu; 9.x/8.x floppies once unpacked; OW 1.x/2.0 native) and record the per-construct
  codegen. That is the `version → fingerprint` map.
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
classification gain needs the missing versions (10.0-beta ISO-layout / 10.5 dosemu "Loader read
error" / 9.01 floppy-`INSTALL.EXE`), not more constructs.

**Precise re-measurement of the codegen (append-only probe, both signs, disassembled with
mosura's own engine).** The exact per-revision codegen for `int divc(int x){return x/7;}` and
`unsigned udivc(unsigned x){return x/10u;}`:

| revision | `divc` (signed / 7) | `udivc` (unsigned / 10) |
| --- | --- | --- |
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
2. The real classic→ow2 divergence is the **sign-extension idiom**: ow2 uses `CDQ`; the classic
   10.x/11.0 line uses `MOV EDX,EAX ; … ; SAR EDX,0x1f` and **never emits `CDQ`** (confirmed for
   variable, constant, and modulo division). The commonly-assumed "`cdq ; idiv` is universal for
   variable division" does **not** hold for Watcom classic.

So the sound, non-redundant **whole-binary anchor** is Open Watcom's inline *signed* constant
division `MOV r,imm ; CDQ ; IDIV r` → Open-Watcom evidence, wired one-sided into
`identify_watcom_program` (folded into the table's ow2 discriminator, composing with `SETcc ;
MOVZX`). Guards, each measured (`inline_const_div_anchor_rejects_lookalikes`):

- **variable** signed division is `MOV r,<reg> ; CDQ ; IDIV r` — the pre-`CDQ` move is
  register-to-register, so the immediate-load requirement rejects it (this is what makes the
  anchor "*constant* division", not bare `cdq;idiv`);
- **unsigned** constant division is `MOV r,imm ; XOR EDX,EDX ; DIV r` — emitted **identically by
  every revision**, so it is non-diagnostic and deliberately not matched (`DIV`/`XOR`, not
  `IDIV`/`CDQ`);
- the classic signed constant form uses `SAR`, not `CDQ`, so it cannot match the window.

This is explicitly a **robustness / coverage** add (division is common in real binaries), **not**
new classification power — it draws the same classic→ow2 boundary the `movzx` signal already draws.
