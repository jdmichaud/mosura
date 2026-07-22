# Analysis-track task list

> Stopgap while the task-tracker MCP server is disconnected (the UI task panel
> can't be written to). This file mirrors what would be in the tracker; it will
> be moved back into the panel once that server reconnects.
> Last updated: 2026-07-20.

## Status snapshot
- `master` @ `9b9dd7e`; `analysis-port` @ `ce1b1a4` (1 commit ahead — the #3 bootstrap).
- Landed & in master: A0–A7, multi-arch listing (x86/ARM64/RISC-V/68k/Z80), PE
  CompilerOpinion, Watcom detect + watcall, **WAR2 native-LE switch win**, the full
  dependency-hardening line (manifest, Ghidra pin, CI clean-clone split, portable
  path-vars). cspec decompiler-side (task #11) done by the decompiler agent.

## Active (analysis lane — mine)
- **A1 — #3 ground-truth oracle SCALE-OUT** ✅ DONE `9d9c43f` (verified: re-derived
  a cross-arch truth from the compiler myself, exact; EM_386 mapping faithful). 20
  source-owned binaries across x86-64/ARM64/RISC-V/68k/Z80/Watcom-x86-32, all
  build-derived + stripped-tested + 0-spurious. Phase-1 bootstrap `ce1b1a4`.
- **A5 — m68k register-indirect call resolution** ✅ DONE `b43d068` (verified:
  no analysis golden changed = other arches byte-identical; m68k fnptr 6/6 +
  strdata 4/4, 0-spurious). Root cause was NOT const-prop (that already fired) but
  a missing "COMPUTED_CALL destination → function" seed; faithful port of Ghidra
  ConstantPropagationAnalyzer.findFunctionLocations, guarded to exec-memory call
  refs (x86-64 PLT terminators unaffected). m68k carve-out removed; gate now 22 cells.
- **A6 — static function-pointer-table resolution** ✅ CLOSED as a NON-GAP (scope-first
  + I ran Ghidra myself): on a RUNTIME-dispatched pointer table Ghidra also recovers
  0/4 targets — mosura is at exact parity; pursuing it would EXCEED Ghidra (violates
  the faithful-port mandate). The only faithful divergence is CONST-index tables
  (Ghidra 2/4 via stack-value tracking + scaled-index folding; mosura 0/4) → filed
  as optional B below, narrow ROI.
- **B (optional, narrow) — SymbolicPropogator: stack-relative value tracking +
  INT_MULT/INT_LEFT scaled-index folding** — recovers exactly Ghidra's const-index
  pointer-table set; medium effort (stack-value tracking is the foundation), narrow
  value (const-index-through-a-table is uncommon; real tables are runtime = non-gap).
  USER ROI CALL — do NOT start autonomously.

## Active — bug-hunt (analysis lane)
- **A7 — ground-truth bug-hunt** ✅ DONE (`a8081f7` corpus + `b1a9641` handoffs):
  analysis-lane CLEAN across 8 stress constructs (54-cell gate); found 3 real
  decompiler MIS-PORTS (verified vs Ghidra's own C: D3 OR-drop, D4 tail-call empty
  loop, D5 func_0x/extraout naming) + reconfirmed D2 panic. All filed as
  docs/decompiler-bug-{d3,d4,d5,tm-clones}*.md for the decompiler agent. Ball now
  in the decompiler agent's court; analysis-lane has nothing to fix.
- **A8 — bug-hunt round 2 (HARD constructs)** ✅ DONE (`e020ff4`+`19f1f6b`): analysis
  CLEAN again (75 cells, 2 rounds → ZERO analysis bugs = port comprehensively
  validated). Found new mis-port D6 (int64 div over-widened to 128-bit) + broadened D3
  (value-drop is switch-block structure, not OR-specific); SHARED cases (irreducible
  CFG, nested loops) correctly NOT filed (mosura==Ghidra = faithful).

## ✅ ANALYSIS-TRACK AUTONOMOUS WORK — CONSOLIDATED (2026-07-21)
Two clean bug-hunt rounds prove the analysis port is comprehensively validated; bounded
analysis-lane work is EXHAUSTED (per [[bounded-levers-exhausted]] pattern). Leverage now
is decompiler-lane (D2–D6) or deep foundations — user's investment call, do NOT force.

## Follow-ups (analysis lane) — TOOLCHAINS NOW AVAILABLE (2026-07-22)
External toolchains restored by user under `/home/jd/projects/tools` (watcom/,
visual_studio/, borland_turbo_c/) + installed: wine 10.0 (+i386), mingw-w64 (both
arches), clang, dosemu2, native Open Watcom. Go dropped (user). Disk: build caches +
`~/tools` relocated to `/data` (sda4, new 30G partition); root off 100%.
- **A2** — ELF32-dynamic hardening (m68k 32-bit dynamic validation + `coverage_68k`
  variant alignment to Coldfire). UNBLOCKED (gcc-multilib installed).
- **A3** — PE CompilerOpinion: golden-validate the non-Clang branches. ✅ **COMPLETE.**
  All real-world PE compiler branches now golden-validated vs Ghidra 12.0.3 (DEV dist at
  `/data/tools/ghidra_12.0.3_PUBLIC/build/dist/ghidra_12.0.3_DEV` + JDK 21):
  - **Clang** — cnv.exe (pre-existing).
  - **Gcc** — mingw_hello.exe (64-bit, committed) `34596d1` + mingw_hello32.exe (32-bit,
    committed) `5bbabb3`; both `windows`/`gcc:unknown`.
  - **PeFile32 enabler** `5bbabb3`: get_opinion + helpers generic over `ImageNtHeaders`;
    load_pe dispatches Pe32→x86:LE:32 / Pe64→x86:LE:64 into a shared generic builder;
    `cspec_x86()` = the faithful i386 opinion block (borlandcpp/borlanddelphi/clang/golang,
    else windows). 64-bit path byte-identical (cnv memory-map regression green).
  - **Borland** — BC++ 4.5 (`bcc32`/`tlink32` under wine) `87b5a78`; Ghidra labels it
    `borlanddelphi`/`borland:pascal` (e_lfanew=0x100, not source language), mosura matches.
  - **VisualStudio** — MSVC 6.0 (`CL`/`LINK`+MSPDB60 under wine); `windows`/
    `visualstudio:unknown` via the DanS Rich header (e_lfanew=0xd0).
  MSVC/Borland runtimes are proprietary → binaries not committed (like cnv), goldens
  committed, tests skip-if-absent via `MOSURA_VC6_EXE`/`MOSURA_BC45_EXE`. Extracted
  toolchains live in `/data/{borland,msvc}` (the compiler trees are directly on the CDs —
  no installer). Follow-up (optional): CLI/managed (.NET), Rust, Go, Swift branches.
- **A4** — Watcom per-version banner→era table. ✅ **Stage 1 DONE `1a2e83a`**: the full
  10.0–11.0 lineage measured against 8 real install ISOs (concatenated runtime banners
  via strings; `detects_watcom_lineage_eras` test + empirical table in
  `docs/watcom-detection.md`). Findings: max era 10.0→1994, 10.5..11.0B→1995 (all
  indistinguishable by runtime banner); regex already covers the whole range.
  **Stage 2 (filed, heavier)**: pre-10.0 (7.0/8.5a/9.01/9.5b) are floppy sets with
  PACKED (`.wpk`) runtime libs → need a dosemu install to unpack; 9.01 leaks an earlier
  `WATCOM Systems Inc. 1990-1991` vendor wording the regex would miss — confirm whether
  compiled binaries embed it, extend the vendor alternation + add a fixture if so.

## Cross-lane
- **X1** — Faithful space-qualified default names (`FUN_ram_0104`/`EXT_ram_`,
  `showSpaceName`). Needs a `Space`-struct change in the SHARED sleigh engine —
  coordinate with the decompiler agent.

## Decompiler-lane handoffs (other agent; do NOT implement on analysis-port)
- **D1** — Recompilation-equivalence NORTH STAR: a compilable-C emitter (types
  prelude + intrinsics lib + real prototypes/structs) so decompile→recompile→same
  binary becomes gradeable. The big foundation; the `#3` recompile probe measures
  distance to it today. Brief in `docs/self-compiled-ground-truth` (memory) + this
  file.
- **D2** — `resolve_call_output` OOB panic on the `tm_clones` idiom
  (`docs/decompiler-bug-tm-clones-panic.md`); verify still reproduces on current master.
- **D3** — Switch case returning an OR-expr drops its value (`classify` case-5
  `return y | 256` → `return;`). Repro: fn 0x401030 in
  `oracle/ground-truth/dispatch.gcc-x86-64`. NARROWED by A7: triggers on OR with a
  HIGH-bit constant (`y|256` drops it; `y|6` in tables.dense is correct).
- **D4** — mutual-tail-recursion loop body dropped (A7, NEW wrong-code): gcc -O2
  merges is_even/is_odd into a decrement-by-2 loop; mosura emits an EMPTY
  `do{}while(n!=0)` — the `n-=2` body + cross-fn tail-jmp dropped → empty infinite
  loop. Repro fn 0x401000 in `oracle/ground-truth/tailcall.gcc-x86-64`. Analysis
  recovered all 3 fns; purely emission/structuring.
- **D-emission set** (feeds D1): `func_0x<addr>()` for calls to KNOWN fns (should be
  `FUN_<addr>`), `xunknown*`/`float4`/`float8` placeholders, `extraout_RAX`, `fRam<addr>`
  float constants. Block recompilation; func_0x→FUN_ is the most concrete sub-fix.
- **‼ CLASSIFY-vs-Ghidra caveat** (applies to D3/D4): mosura is a faithful PORT. Each
  wrong-code finding must be checked against GHIDRA's own C (`oracle/capture --c`): if
  Ghidra ALSO drops it → mosura is faithful, "fixing" it EXCEEDS Ghidra = the D1 north
  star (user's call), NOT a port bug. Only mosura≠Ghidra = a real mis-port to fix.

## Housekeeping
- **H1** — Sync master: the `#3` bootstrap (`ce1b1a4`) + whatever the scale-out adds
  sit on `analysis-port`, not yet in master. Fast-forward on the user's go.
