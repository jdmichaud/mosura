# Watcom codegen fingerprinting — pinning the exact revision

Watcom's runtime banner is an **era** stamp (copyright year range) and no header field
carries the exact release for **DOS/4GW LE** output (the WAR2 case) — see
[`watcom-detection.md`](watcom-detection.md). The exact revision is recoverable only from the
**code the compiler generates**: different `wcc386` revisions make different instruction /
register-allocation choices for the same source. This is the signal that pins WAR2's exact
Watcom revision and feeds byte-exact recompilation (the `D1` north star).

## Reproducible setup — running a historical `wcc386` under dosemu2

The historical DOS-hosted compilers run under dosemu2. The one non-obvious gotcha: the
`BINB/WCC386.EXE` build is **W32RUN-hosted**, so `WATCOM/BIN/W32RUN.EXE` must be on the DOS
`PATH` (without it: *"This program requires W32RUN.EXE to be in your PATH"*).

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

Native Open Watcom 2.0 (`$GT_WATCOM/binl/wcc386`, Linux-hosted) compiles the same probe
directly for the modern end of the lineage.

## The probe (`oracle/codegen-probes/watcom_cg.c`)

Three constructs chosen to expose revision-specific choices: a **byte comparison** (promotion),
a **counted loop** (register allocation + loop shape), and a small **switch**.

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

### Scope caveat — signals are probe-shaped

`extract_signals` uses first-match heuristics that are sound only when the scanned region is
the probe's constructs (on arbitrary code, a switch's `cmp eax,0x1` would read as a promoted
byte-compare). Pointing the matcher at an unknown binary (WAR2) requires locating the
equivalent constructs first — that construct-location pass is the open next step.

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
