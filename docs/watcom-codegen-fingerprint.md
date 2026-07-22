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

## Measured divergence — Watcom 10.0a vs Open Watcom 2.0 (verified)

`cmpbyte(unsigned char c){ return c == 5; }` — the **byte-compare-promotion** divergence
(the same one the `warcraft2-re` A-level-patch note identified as correlating with WAR2):

| | 10.0a | Open Watcom 2.0 |
| --- | --- | --- |
| compare | `cmp eax,5` (promotes byte → 32-bit) | `cmp al,5` (byte compare) |
| result | `sete al` | `sete al ; movzx eax,al` |

`loop(int n){ int s=0,i; for(i=0;i<n;i++) s+=i; return s; }`:

| | 10.0a | Open Watcom 2.0 |
| --- | --- | --- |
| `n` register | `ebx` | `ecx` |
| loop shape | body-then-test (bottom test, `jl` back) | test-first |

So three independent discriminators (compare width, register allocation, loop structure)
separate two revisions the banner era cannot. Each is a bit of a codegen fingerprint.

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
