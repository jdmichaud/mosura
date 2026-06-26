# Multi-architecture support — plan & ownership

mosura's auto-analysis lists functions for **x86 only** today (x86-64 ELF/PE, x86-16 MZ,
x86-32 LE). This doc is the standing plan for extending to other CPUs (ARM64, RISC-V, 68k,
Z80, …) and the **ownership split** between the auto-analysis agent (`analysis-port`) and
the main/decompiler agent (`master`).

## The two orthogonal axes

- **Container format** (ELF / PE / MZ / LE / raw) — handled by `analysis/loader/*` (auto-analysis agent).
- **CPU architecture** (x86 / ARM / RISC-V / 68k / Z80 …) — the SLEIGH `.sla` (shared engine,
  validated per-arch on the main side) + an architecture-neutral analysis pipeline (p-code).

A format can hold any arch; "can it list functions" needs **both** a loader that accepts the
arch *and* a SLEIGH spec the engine is proven on. Today every loader hardcodes/gates to x86
(`elf.rs` rejects `e_machine != EM_X86_64`; all loaders emit `x86:LE:*`).

## What's already arch-neutral (no rebuild needed)

- The **SLEIGH engine** is a general `.sla` interpreter, validated on **x86-64, AArch64, 6502**
  (`tests/coverage_*.rs`, `tests/disasm_*.rs`). Ghidra ships `.sla`/`.pspec`/`.cspec` for
  AARCH64, ARM, RISCV, MIPS, PowerPC, Sparc, 68000, Z80, … and `lang::load` resolves any of them.
- The **analysis pipeline** runs on p-code (Branch/Call/Return, `getDynamicOperandRefType`, …).
- The **calling-convention layer** (`analysis/cspec.rs`) loads *any* `.cspec`.

So adding an arch is **"un-gate the loader + validate against Ghidra goldens"**, not a rebuild —
modulo the per-arch caveats below.

## The hard rule: no arch ships unvalidated

mosura's whole guarantee is parity with Ghidra. A new arch needs a **corpus + Ghidra goldens**
(captured via `scripts/capture-analysis.sh` / `analyzeHeadless`) before its function listing is
trusted. x86 stays validated throughout; a new arch's tests are skip-if-no-golden until its
corpus exists. **Toolchains** (decided: user-installed): `gcc-aarch64-linux-gnu`,
`gcc-riscv64-linux-gnu`, `gcc-m68k-linux-gnu`, `sdcc` (Z80).

## Per-arch status, blockers, and ownership

| Arch | SLEIGH (engine) | Distinctive blocker | Auto-analysis agent (me) | Main/decompiler agent |
| --- | --- | --- | --- | --- |
| **ARM64 (AArch64)** | ✅ validated | none | un-gate ELF loader (`EM_AARCH64`→`AARCH64:LE:64:v8A`) + corpus + validate pipeline | — (engine ready); optional: decompiler-driven switch recovery on ARM |
| **RISC-V** | ⚠️ `.sla` present, **not** in validated set | none (LE) | un-gate loader (`EM_RISCV`) + corpus + validate | **SLEIGH validation pass** (`coverage_riscv.rs`); fix any unimplemented construct |
| **68k (m68000)** | ⚠️ present, not validated | **big-endian** — analysis read paths are LE-hardcoded (`read_mem_const`, the data markup, the `big_endian` reject) | thread endianness through the analysis read paths + un-gate/build loader + corpus | **SLEIGH validation pass** (`coverage_68k.rs`) |
| **Z80** | ⚠️ present, not validated (6502 is, so likely small) | **no loader** — Z80 binaries aren't ELF/PE/MZ | **new flat/platform loader** + corpus | **SLEIGH validation pass** (`coverage_z80.rs`) |

**Decompiler-driven analyzers** (A6 switch/param recovery via the decompiler bridge) on any new
arch need the *decompiler* to handle that arch's p-code — main agent's domain — but they are a
refinement; **basic function listing does not depend on them.**

## Format choices for 68k / Z80 (decided: both, easy path first)

- **68k:** start with **m68k Linux ELF** (reuses the ELF pipeline; just needs the big-endian
  work) → then **retro platforms** (Amiga Hunk, Sega Genesis ROM) as bespoke loaders.
- **Z80:** start with **CP/M `.COM`** (simplest flat loader — load image at `0x100`, entry `0x100`)
  → then **retro platforms** (ZX Spectrum `.sna`/`.z80`/`.tap`, MSX ROM). Each retro format gets
  its own loader + a Ghidra-setup note (processor + base must be set manually, as for war2).

## Current scope

**ARM64 is being implemented now** (the quick win). RISC-V / 68k / Z80 are documented + tasked
for later, each gated on its corpus + (for RISC-V/68k/Z80) a main-side SLEIGH validation pass.
