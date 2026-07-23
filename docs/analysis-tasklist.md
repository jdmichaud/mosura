# Analysis-track task list

> Stopgap while the task-tracker MCP server is disconnected (the UI task panel
> can't be written to). This file mirrors what would be in the tracker; it will
> be moved back into the panel once that server reconnects.
> Last updated: 2026-07-23 (`analysis-port` @ `c86bd51`).

## Status snapshot
- `analysis-port` @ `c86bd51`; **not merged to master** (H1) — 35+ commits ahead since the
  compiler-detection arc began. Suite: 489 lib + 25 analysis (+3 this session: marker fragments,
  m68k variant equivalence, m68k dynamic-link path), clippy clean.
- Landed & in master (older): A0–A8, multi-arch listing (x86/ARM64/RISC-V/68k/Z80), PE
  CompilerOpinion, Watcom detect + watcall, WAR2 native-LE switch win, dependency-hardening.

## ✅ LANDED THIS SESSION (on analysis-port, awaiting H1 merge)
- **Compiler VERSION + format detection arc — COMPLETE across the real-world set.**
  `loader::compiler_version` (family+version, beyond-Ghidra 2nd oracle) + `loader::pe_opinion`
  (faithful Ghidra family port) + `loader::pe` (new **PeFile32** path). Validated on real
  binaries: **GCC** (PE 32/64 + ELF `.comment`, exact) · **Clang** (PE + ELF, exact; clang-first
  ordering fix) · **MSVC** (Rich build exact VC6/VS2005; pre-Rich VC4/5 via linker version) ·
  **Borland** (BC++4.5, era + true c++/pascal) · **Watcom** (era banner + wlink-PE). Format
  matrix (PE/ELF/MZ/LE/COM) in `compiler_version.rs` module doc.
- **Watcom codegen fingerprinting + matcher** (`codegen_fingerprint.rs`, `docs/watcom-codegen-
  fingerprint.md`): dosemu-compiled 10.0a/10.6/11.0 + native OW2.0; measured version→fingerprint
  table; committed self-compiled `.code` ground truth + `scripts/extract-omf-code.py`;
  **construct-location matcher** (`identify_watcom_program`) — anchored, one-sided-at-scale
  (honest: class not always revision; never wrong-excludes).
- **Build self-containment**: `third_party/ghidra/` vendors the used language files + datatests
  (checkout→vendored fallback in `paths.rs`); `sleigh_canary` fails-loud (no silent skips);
  `verify-vendored-ghidra.sh`. Fixed a live incident (deleted checkout hollowed the suite).
- **Review cycle**: independent sub-agent review of the arc; findings verified + fixed (`e669740`).

## ⏩ UNBLOCKED — READY / next up (user said: work these)
- **A3-V Phase 3 — CI-runnable proprietary version fixtures** — ✅ `39a7356`+`6feca33`.
  Committed **marker fragments** (metadata, no runtime code): `msvc6_rich.bin` (VC6 → `msvc:6.0`),
  `msvc8_rich.bin` (genuine VS2005 msvcr80.dll from the VC8 ISO → `msvc:8.0`; wine's builtin is a
  gcc reimplementation, unusable), `borland45_banner.bin` (BC++4.5 → `borland:c++:1994`), gated by
  new `compiler_version_marker_fragments` — real-compiler-output version detection now runs in
  CI without the toolchain (robust to the disk-churn that keeps relocating it). Pre-Rich MSVC
  (VC4/5 linker-version + runtime-string) stays covered by synthetic unit tests. **Follow-on**:
  MSVC 2.0 (2nd pre-Rich datapoint), Borland 4.0/4.52 era-boundary fixtures.
- **A4 Stage 2 — pre-10 Watcom** (7.0/8.5a/9.01/9.5b) — ⏸ NEEDS FULL 9.01 INSTALL. Extracted the
  9.01 floppy set (`/data/w901/`, Disk01-06); the DOS compiler driver `WCC386.DOS` (116 KB) + the
  packed backend/runtime (`WCC386P.WPK`, `H.WPK`) are there. The only plaintext vendor string on the
  floppies is the "as is" *license* text (`WATCOM Systems Inc. 1990-1991`); the actual **runtime
  banner** a compiled binary would embed is **inside the packed `.WPK`** — invisible to `strings`,
  and 9.01 may not even use the 10.0+ `... Run-Time system. (c) Copyright by ...` banner format.
  Resolving the vendor-wording question (and enriching the codegen corpus with a 9.01 probe) needs a
  **full 9.01 install under dosemu** (run `INSTALL.EXE` to unpack the `.WPK`s, then compile+link). Real
  effort; deferred behind the tractable CI-fixture work above. NOTE: GT_WATCOM (`~/tools/open-watcom`)
  was deleted in the cleanup — regenerating any Watcom fixture needs it restored.
- **A2 — ELF32-dynamic hardening**: (1) `coverage_68k` variant "alignment" — ✅ RESOLVED `5cd9c50`:
  the premise was wrong. `coverage_68k` correctly uses `68040.sla` (= the `default` variant its
  golden was captured under); the loader's `Coldfire` pick is *faithful* (Ghidra collects the 4
  matching variants in a `HashSet` with no sort → stable iteration lands on Coldfire, verified from
  source — not alphabetical) AND **output-neutral** (coldfire≡default disasm proven byte-for-byte
  across the ground-truth m68k corpus, 742 insns, by new `m68k_coldfire_matches_default_variant`).
  (2) m68k 32-bit *dynamic* validation — ✅ DONE `b956c63` (user restored `gcc-14-m68k-linux-gnu`):
  added `m68k_dyn.elf` (dynamic analog of basic.elf, same source) + test `m68k_dynamic_link_path`.
  Exercises the BE/32 dynamic loader path — PT_INTERP, .dynamic/.dynsym, .rela.plt (RELA + m68k
  JMP_SLOT), the m68k memory-indirect `jmp ([disp,PC])` PLT thunks and the EXTERNAL block: mosura
  resolves the thunks through the GOT to named externals (`printf`, `__libc_start_main`), recovers
  every source fn, and seeds nothing in unmapped memory. Faithful Ghidra external/thunk model.
- **R2 — env scripting**: `setup-watcom-dosemu.sh` ✅ DONE `6d3f69a` — one command re-extracts any
  ISO-based Watcom (10.0/10.0a/10.5/10.6/11.0) from its surviving archive into the dosemu C: drive
  and compiles a probe; disk-cleanup-proof (archives survive, extracted trees don't). Tested
  end-to-end on 10.6 + 11.0 (each reproduces its committed `<rev>.code` byte-identically → the
  codegen-corpus enrichment path is UN-blocked). **Follow-on**: wine-toolchain setup script
  (BC45/VC6 direct-extract); floppy-set Watcom (7.0/8.5a/9.01) via `INSTALL.EXE` = A4-S2.

## Corpus note (user-flagged 2026-07-23)
Fixtures grow with features but the **core corpus is thin** — narrow single-purpose fixtures, not
construct-stressing programs. `ground-truth/` (~23 progs × 4–5 targets) is the real vehicle; the
codegen-fingerprint corpus is 1 construct × 4 versions. **Construct enrichment is now fully
UNBLOCKED** (2026-07-23): all four codegen columns reproduce their committed `<rev>.code`
byte-identically — 10.0a/10.6/11.0 via `setup-watcom-dosemu.sh`, ow2 via the native
`/data/open-watcom-v2` wcc386. So a new probe construct can be compiled across the whole lineage
and gated. NEXT enrichment step (ready): add construct(s) to `watcom_cg.c` that expose further
revision-specific codegen, recompile all 4 columns, extend the matcher `Signals`/`TABLE` +
committed artifacts + `matches_committed_self_compiled_probes`. Apply
`war2-issues-become-source-tests` (byte-compare promotion is construct-specific).

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
- **A2** — ELF32-dynamic hardening. Variant "alignment" ✅ RESOLVED (was a non-issue — see the
  UNBLOCKED section above; loader's Coldfire pick proven faithful + output-neutral). Dynamic
  validation ⏸ blocked on restoring the m68k gcc driver (`gcc-14-m68k-linux-gnu`, apt).
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

- **A3-V — compiler VERSION detection** (user-directed 2026-07-22: "handle all versions,
  recognize which is which, exact where possible"). Beyond-Ghidra second oracle refining the
  family opinion into a specific version. **Phase 1 (detector) `4b524c3` + Phase 2 (wired into
  loader→program→snapshot) `ccced8d` DONE.** `loader::compiler_version` reads each family's
  embedded marker; validated on real binaries:
  - **MSVC** → `msvc:6.0` EXACT (Rich-header @comp.id build 8168); build→product table.
  - **GCC** → `gcc:14-win32` EXACT (`.comment`, max across objects); **Clang** → `clang:19.1.7`.
  - **Borland** → `borland:c++:1994` ERA (startup banner) — reads the TRUE `c++` family from the
    binary, so the pascal/c++ question Ghidra's e_lfanew heuristic gets wrong is answered right,
    WITHOUT diverging from the faithful opinion (both coexist; `program.compiler` untouched).
  - **Watcom** → `watcom:1988-1994` ERA (adapts loader::watcom).
  Honest granularity: MSVC/GCC/Clang exact; Borland/Watcom era (copyright year), not minor
  release. **Phase 3 IN PROGRESS `39a7356`: CI-runnable marker fragments** — real VC6 Rich header +
  BC++4.5 banner committed (metadata only) + `compiler_version_marker_fragments`, so the detector's
  real-output path runs in CI without the proprietary toolchain. Remaining lineage points (VS2005
  Rich, MSVC 2.0, Borland 4.0/4.52 era boundaries, Watcom 10.0–11.0) extend the same fixture pattern.
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
- **X2 — vendored-ghidra fallback for decompile-lane paths (handoff).** `third_party/ghidra/`
  now vendors the used language files + datatests; `paths::processors_dir()`/`language_dir()`/
  `datatests_dir()` resolve checkout-first → vendored. Analysis-lane + all shared test files
  are repointed, but `crates/mosura/src/decompile/{build,printc,directwrite,pipeline}.rs`
  still hardcode `ghidra_src().join("Ghidra/Processors/...")` (decompiler lane — not touched).
  Switching those to `paths::language_dir("x86")` gives the decompile tests the same
  no-checkout fallback. Mechanical, zero behavior change with a checkout present.

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
