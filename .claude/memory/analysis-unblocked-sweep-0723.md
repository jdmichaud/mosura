---
name: analysis-unblocked-sweep-0723
description: "2026-07-23 analysis-port sweep of the \"unblocked\" tasks — what landed and what's user-blocked"
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-07-23T15:24:15.719Z
---

Session 2026-07-23 on `analysis-port` (worked the "unblocked/ready" tasks per user). HEAD `13221ea`.

**Landed (all committed, tested, clippy-clean):**
- **A3-V Phase 3 — CI-runnable version marker fragments** (`39a7356`+`6feca33`): committed
  `oracle/analysis-corpus/markers/{msvc6_rich,msvc8_rich,borland45_banner}.bin` (header/copyright
  metadata, NO runtime code) + test `compiler_version_marker_fragments`. Real-compiler version
  detection now runs in CI without the proprietary toolchain. VS2005 genuine bytes came from the
  VC8 ISO's msvcr80.dll — wine's `msvcr80.dll` is a gcc-compiled builtin (detects `gcc:14-win32`).
- **A2 alignment — RESOLVED as a non-issue** (`5cd9c50`): `coverage_68k` correctly uses `68040.sla`
  (= `default` variant, matching its golden). Loader's EM_68K→Coldfire pick is FAITHFUL (Ghidra
  collects the 4 matching 68000:BE:32 variants in a `HashSet`, no sort, `QueryResult` not
  Comparable → stable iteration lands on Coldfire — verified from checkout source, NOT alphabetical)
  AND output-neutral (coldfire≡68040 disasm proven byte-for-byte across the gcc-m68k ground-truth
  corpus, 742 insns, by new test `m68k_coldfire_matches_default_variant`).
- **R2 — `scripts/setup-watcom-dosemu.sh`** (`6d3f69a`+`0755ada`): one command re-extracts any
  ISO-based Watcom (10.0a/10.5/10.6/11.0) from its archive under `$WATCOM_ARCHIVES`
  (`/data/tools/watcom`, archives survived the cleanup) into the dosemu C: drive + compiles a probe.
  Tested end-to-end: 10.6 and 11.0 each reproduce their committed `<rev>.code` byte-identically.
  Gotchas baked in: nested-ISO path may have spaces (`-slt`), DOS host = largest BINW/BINB WCC386
  (never BINNT/BIN95 stubs), spool 7z listings to a file (early-close pipe → SIGPIPE 141 + set -e),
  dosemu names obj after the 8.3-truncated stem lowercased.

**Then user restored both toolchains → both landed (2026-07-23, same day):**
- **A2 dynamic m68k** ✅ `b956c63`: user installed `gcc-14-m68k-linux-gnu`. Added `m68k_dyn.elf`
  (dynamic analog of basic.elf, same src) + test `m68k_dynamic_link_path`. The BE/32 dynamic loader
  path (PT_INTERP/.dynamic/.dynsym/.rela.plt/PLT thunks/EXTERNAL block) works + is FAITHFUL: mosura
  resolves the m68k memory-indirect `jmp ([disp,PC])` PLT thunks through the GOT to named externals
  (printf, __libc_start_main). Instrument-first ruled out a false "spurious function" alarm (the
  0x80005xxx addrs are the faithful EXTERNAL block, not unmapped) and confirmed coldfire≡68040
  decode the memory-indirect PLT identically.
- **ow2 native + FULL codegen reproducibility** ✅ `a9ba099`+`44c23c6`: user put Open Watcom v2 at
  `/data/open-watcom-v2`. The built native compiler is
  `bld/cc/386/linuxx64/binbuild/wcc386.exe` (x86-64 ELF despite `.exe`; `WATCOM=/data/open-watcom-v2
  wcc386.exe cg.c`). All 4 committed codegen columns now reproduce their `<rev>.code`
  byte-identically: 10.0a/10.6/11.0 via setup-watcom-dosemu.sh, ow2 native. R2 script fix: pull
  W32RUN/DOS4GW when they live in a SEPARATE BIN dir (10.0a nested layout) + largest-BINW/BINB picker.
- **Codegen div/mod/mul CLASSIFICATION enrichment measured, NOT added** `c86bd51`: no NEW
  classification power (Watcom uses real idiv, not magic-multiply; boundaries redundant with
  loop_bound_reg/movzx; 10.0a≡10.6 for div). Finer classification needs the MISSING versions
  (10.0-beta ISO / 10.5 dosemu "Loader read error" / 9.01 floppy-INSTALL.EXE), not more constructs.
- **Division whole-binary ROBUSTNESS anchor LANDED** `78d0c8b`+`7e3646e`+`bcf56a6` (sub-agent,
  lead-verified independently): user said go, I delegated to a general-purpose sub-agent. It
  instrument-first FALSIFIED my mechanism hypothesis (I guessed "classic calls __i4D helper, ow2
  inlines" — WRONG: every revision inlines the divide; the shared `push;call` prefix is the prologue
  stack-probe, not a div helper). Real diagnostic: classic (10.x/11.0) sign-extends with
  `MOV EDX,EAX ; SAR EDX,0x1f`; ow2 uses `CDQ`. Sound one-sided ow2 anchor shipped =
  `MOV r,imm ; CDQ ; IDIV r` in `identify_watcom_program`/`scan_into`, folded into the ow2
  discriminator with `SETcc;MOVZX`. Guards (all unit-tested): immediate-load rejects variable div;
  IDIV+CDQ rejects the unsigned `XOR;DIV` form every revision shares; classic's SAR never matches.
  Probe extended append-only, 4 `<rev>.{obj,code}` regenerated (each obj→code byte-identical).
  Robustness only (same classic→ow2 boundary as movzx) — division is just far more common in a real
  binary; WAR2 is classic (SAR) so it does NOT fire there. Verified by me: git-isolated to
  analysis-port, 8/8 codegen + 24/24 parity + clippy 0, CDQ=1/SAR=0(ow2) vs CDQ=0/SAR=1(classic) in
  committed bytes, `whole_program_matcher_never_wrongly_excludes` green. Next construct should be
  war2-issues-become-source-tests-driven.

Recurring root cause across all blockers: an overnight disk cleanup keeps deleting EXTRACTED
toolchains (Ghidra checkout, open-watcom, m68k-gcc driver, dosemu Watcom trees) while the source
archives under `/data/tools` survive. The marker-fragments + vendored-ghidra + R2 work all move
coverage toward being self-contained/reproducible against exactly this churn. See
[[analysis-external-toolchains]], [[war2-issues-become-source-tests]].
