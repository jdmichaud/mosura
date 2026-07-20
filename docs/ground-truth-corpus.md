# Cross-compiler self-compiled ground-truth corpus

**Status: phase-1 bootstrap landed** (x86-64 gcc slice). The oracle strategy behind the
multi-arch / compiler-detection line, made explicit: validate mosura against programs **whose
source we own**, compiled by real compilers — *not* against Ghidra, which is often wrong (it
invented ~20 fake switches in WAR2 that were really loops/searches — see
[`le-loader-notes.md`](le-loader-notes.md) / [[war2-dos4gw-le]]).

## Why source-owned truth

The strongest oracle is a program whose behaviour we already know. Compiling it ourselves gives
an **exact, Ghidra-independent** ground truth, and it directly serves the project's purpose —
*do better than Ghidra*. Two correctness levels, phased:

- **Analysis level (phase 1, implemented).** The known source + build gives exact function
  boundaries, switch/computed-jump locations, the call graph, and compiler identity. Validated
  by `tests/ground_truth_parity.rs`.
- **Decompiler level (later).** *Recompilation equivalence* — decompile → recompile with the
  **same** compiler → the **same** binary. The compiler is the objective judge (it ignores
  names/structure); closeness (byte-identical → functionally-equivalent) is the quality metric.
  This is precisely where mosura can beat Ghidra, whose C usually won't even recompile. Measured
  (not yet gated) by `examples/gt_recompile_probe.rs`; see [Decompiler level](#decompiler-level).

## Layout

```
oracle/ground-truth/
  src/<program>.c                     source we own (portable helpers + an arch entry shim)
  build.sh                            compile → DERIVE truth → strip   (dev-oracle; regen only)
  <program>.<compiler>-<arch>         the analyzed artifact: STRIPPED binary   (committed)
  <program>.<compiler>-<arch>.truth   build-derived ground truth               (committed)
```

Consistent with [`dependencies.md`](dependencies.md) tiering: **building** the corpus is
DEV-ORACLE (needs the toolchains); the **committed stripped binary + `.truth`** are the
BUILD/TEST surface — `cargo test` runs the gate offline, no toolchain required.

## Ground truth is DERIVED from the build, never hand-authored

`build.sh` compiles an **unstripped** binary, derives the truth from the artifact itself, then
strips the binary to the analyzed form (a realistic RE target — no symbols). Derivation:

- **functions** — `nm -S --defined-only` (text symbols): entry address, size, name;
- **switch dispatches** — `objdump -d` indirect jumps (`jmp *reg` / `jmp *mem`);
- **compiler** — the known toolchain of the build recipe.

The `.truth` format is a simple diffable line format (mirrors the snapshot goldens):

```
# mosura-ground-truth v1 program=dispatch compiler=gcc arch=x86-64 lang=x86:LE:64:default
# derived-from=dispatch.gcc-x86-64.unstripped via=nm+objdump (build artifact, NOT Ghidra)
compiler gcc
entry 00000000004010a0
func 0000000000401030 0000000000000068 classify
switch 401049
```

## Compile matrix

Programs × compilers × arches. Phase-1 ships the **x86-64 gcc** column; the rest are one
`build_one` row each in `build.sh` (commented, ready to enable after review).

| toolchain | arch | mosura lang | status |
| --- | --- | --- | --- |
| gcc | x86-64 | `x86:LE:64:default` | **live (phase 1)** |
| gcc | aarch64 | `AARCH64:LE:64:v8A` | ready to enable |
| gcc | riscv64 | `RISCV:LE:64:default` | ready to enable |
| gcc | m68k | `68000:BE:32:default` | ready to enable |
| sdcc | z80 | `z80:LE:16:default` | ready to enable |
| Open Watcom `wcc386` | x86-32 | `x86:LE:32:default` | ready to enable |
| clang | * | — | **ABSENT toolchain** (gap, not faked) |
| MSVC | x86/x64 | — | **ABSENT toolchain** (gap, not faked) |

Absent toolchains are documented gaps — never fabricated binaries. Scaling to other arches
uses a per-arch entry shim (the x86-64 `_start`/syscall stub in `src/*.c` is the shim; the
arithmetic/switch helpers are portable), or a portable-`main` + CRT variant (more functions in
the truth, but still exact).

## Analysis level (phase 1, `tests/ground_truth_parity.rs`)

For each stripped binary, mosura's analysis must be a **clean subset** of the source truth:

1. **0 spurious** — every function mosura recovers is a real function in the truth;
2. **full recall of call-reachable functions** — with one honest carve-out: gcc splits cold
   paths into `<fn>.cold` symbols reached by a *jump*, not a *call*; on the stripped artifact
   flow-analysis correctly folds those into the parent, so they are not expected as separate
   functions (the truth marks them; the gate excludes `*.cold` from the recall set);
3. **every real switch dispatch recovered** (a `COMPUTED_JUMP` source or a `BRANCHIND` site).

Phase-1 result: `arith` 4/4 funcs (0 spurious); `dispatch` 4/4 + the `0x401049` jump-table
switch recovered exactly — validated against source, no Ghidra involved.

Note: compiler-ID from a stripped ELF is a follow-up — mosura reports the default `gcc` cspec
but does not yet *detect* it from `.comment`; the truth records the real compiler so the gate
can tighten once `.comment`-based detection lands.

## Decompiler level (recompilation equivalence — measured, not gated)

`examples/gt_recompile_probe.rs` decompiles functions from a ground-truth binary (read-only via
the decompiler's public API — it does **not** modify the decompiler) and tries to compile the C.
Phase-1 measurement (x86-64 gcc):

- **Simple leaf functions already recompile** with only a sized-int prelude: `square`/`op_add`
  (`int4 f(int4 a,int4 b){return a+b;}`) → `gcc -c` **COMPILES**. mosura is already ahead of
  Ghidra's "won't compile at all" here.
- **Blockers (all in decompiler C-emission — a decompiler-track handoff, not this task):**
  - no sized-int / `undefined` typedef prelude (`int4`/`uint4`/`undefined*`) — trivial;
  - `xunknown*` placeholder types (e.g. `xunknown4` for an unresolved switch selector);
  - `func_0x<addr>()` unprototyped call targets + `extraout_RAX`/`extraout_RDX` register-return
    placeholders;
  - a correctness bug surfaced by the probe: `classify` case 5 (`y | 256`) emitted as a bare
    `return;` — filed for the decompiler track.

**Recompilation-equivalence loop (when the decompiler grows a compilable-emission mode):**
decompile every function → emit the prelude + prototypes → recompile with the same toolchain/
flags → strip → **diff the bytes** against the original stripped artifact; the byte-distance is
the decompiler-quality metric. The probe already scaffolds the single-function measurement.

## Scale-out plan (after review)

1. Enable the matrix rows in `build.sh` (aarch64/riscv64/m68k gcc, z80 sdcc, x86-32 Watcom),
   committing each stripped binary + `.truth`; the gate iterates them automatically.
2. Grow the program set (indirect calls via function-pointer tables, nested switches, string
   data) — each a new `src/*.c`, truth auto-derived.
3. Decompiler track (separate, handoff): compilable-emission mode → wire the recompilation-
   equivalence loop into a scored gate.
