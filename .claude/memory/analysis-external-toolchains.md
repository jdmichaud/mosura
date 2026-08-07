---
name: analysis-external-toolchains
description: Where the historical compilers + Ghidra golden-gen live and how to use them for A2/A3/A4 compiler-detection fixtures; the /data partition that holds build caches + tools.
metadata: 
  node_type: memory
  type: reference
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-07-22T19:31:38.137Z
---

External-tool setup for the analysis-track compiler-detection work (A2 ELF, A3 PE, A4
Watcom), discovered/built 2026-07-22. All on the analysis-port worktree.

**Disk — `/data` partition (sda4, 30G).** Root (sda2, 18G) hit 100%; created a new GPT
partition `/dev/sda4` in freed qcow space, ext4, mounted `/data` (fstab by UUID + `nofail`).
Relocated the space hogs there via **symlinks**: `mosura-analysis/target` → `/data/analysis-target`,
`~/tools` → `/data/tools` (Ghidra 5.3G + Open Watcom). So `GT_WATCOM=~/tools/open-watcom` and
`cargo` resolve through symlinks — **if `/data` ever fails to mount, builds + GT_WATCOM break**
(nofail means the box still boots). `mosura/target` (11G, the DECOMPILER agent's worktree) was
left on root — not mine to move.

**Historical compiler archives** live in `~/projects/tools/{watcom,visual_studio,borland_turbo_c}`
(user-restored; ISOs/7z/floppy-img). Key finding: **BC++ 4.5 and MSVC 6.0 have their compiler
trees DIRECTLY on the CD ISOs — no installer.** Extract + run under wine:
- **Borland**: `7z x "Borland C++ 4.5 (CD).7z"` → `BORLANDC_45.ISO` → extract `BC45/{BIN,INCLUDE,LIB}`;
  run `bcc32.exe` from `BIN` (so `tlink32.exe` is in CWD), `-I..\INCLUDE -L..\LIB`. → 32-bit PE.
  Extracted to `/data/borland`; a built PE at `/data/borland/bc45_hello.exe`.
- **MSVC 6.0**: VC6 ISO `VCP600ENU1.iso` → extract `VC98/{BIN,INCLUDE,LIB}` **plus**
  `COMMON/MSDEV98/BIN/MSPDB60.DLL` into `VC98/BIN` (cl.exe needs it); run
  `INCLUDE=Z:\...\INCLUDE LIB=Z:\...\LIB wine CL.EXE /Fe... hello.c`. → 32-bit PE with a DanS
  Rich header. Extracted to `/data/msvc`; a built PE at `/data/msvc/vc6_hello.exe`.
- MSVC/Borland runtimes are proprietary → built binaries NOT committed (like cnv.exe); tests
  read `MOSURA_VC6_EXE` / `MOSURA_BC45_EXE`, skip-if-absent; the Ghidra goldens ARE committed.
- mingw-w64 (both arches) + clang are native (`/usr/bin`) → their PEs ARE committed (permissive).
  Watcom ISOs: banners stream out with `7z x -so <7z> <inner.iso> | strings` (libs plain on ISO,
  no dosemu). Pre-10 Watcom floppies have PACKED `.wpk` libs (need a dosemu install to unpack).
- **Historical Watcom `wcc386` under dosemu2 WORKS** (for codegen fingerprinting): extract
  `WATCOM/{BINB,BIN,H,LIB386}` into `~/.dosemu/drive_c/WATCOM`; **gotcha: `BINB/WCC386.EXE` is
  W32RUN-hosted → `WATCOM/BIN/W32RUN.EXE` must be on the DOS PATH** ("requires W32RUN.EXE").
  Run `dosemu -dumb -quiet -E "CG.BAT"` (DOS `command.com`: single `>` only, no `2>&1`); object
  lands as `cg.obj`; disassemble with native OW `wdis -a`. Full recipe + the reproduced
  byte-compare-promotion divergence (10.0a `cmp eax,5` vs OW2 `cmp al,5`+movzx) in
  `docs/watcom-codegen-fingerprint.md` + probe `oracle/codegen-probes/watcom_cg.c`.

**Ghidra golden-gen** (analyzeHeadless snapshots): the built DEV dist is at
`/data/tools/ghidra_12.0.3_PUBLIC/build/dist/ghidra_12.0.3_DEV` + JDK 21. One-off capture mirrors
`scripts/capture-analysis.sh`: `$DIST/support/analyzeHeadless $(mktemp -d) cap -import <exe>
-noanalysis -scriptPath oracle/ghidra_scripts -postScript DumpAnalysisSnapshot.java
goldens/analysis/<name>.loaded.snapshot -deleteProject`. The snapshot header carries
`compiler=`/`compilerinfo=` — what the opinion tests assert against.

Status (analysis-port, see `docs/analysis-tasklist.md`): **A3 COMPLETE** — all PE compiler
branches golden-validated (Clang/Gcc-64/Gcc-32/VisualStudio/Borland). **A4 Stage 1 DONE** —
Watcom 10.0–11.0 runtime-banner lineage measured. Relates: [[war2-issues-become-source-tests]],
[[direction-analysis-port]].
