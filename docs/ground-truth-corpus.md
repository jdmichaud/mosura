# Cross-compiler self-compiled ground-truth corpus

**Status: phase-2 matrix landed** — the installed compiler×arch matrix (gcc x86-64 / aarch64 /
riscv64 / m68k, sdcc z80, Open Watcom x86-32) × a grown program set, all build-derived +
stripped-tested + green. The oracle strategy behind the multi-arch / compiler-detection line,
made explicit: validate mosura against programs **whose source we own**, compiled by real
compilers — *not* against Ghidra, which is often wrong (it invented ~20 fake switches in the subject
that were really loops/searches — see [`le-loader-notes.md`](le-loader-notes.md) /
(subject-profile note `dos4gw-le`)).

## Why source-owned truth

The strongest oracle is a program whose behaviour we already know. Compiling it ourselves gives
an **exact, Ghidra-independent** ground truth, and it directly serves the project's purpose —
*do better than Ghidra*. Two correctness levels, phased:

- **Analysis level (phase 1, implemented).** The known source + build gives exact function
  boundaries, switch/computed-jump locations, the call graph, and compiler identity. Validated
  by `tests/ground_truth_parity.rs`.
- **Decompiler level (phase 2, GATED 2026-08-22).** *Recompilation equivalence* — decompile →
  recompile with the **same** compiler → the **same** binary. `recompile::groundtruth` runs it
  for the host gcc column: each program is built with the LOCAL gcc (`GCC_FLAGS`), every
  function decompiled, the emitted C assembled into a TU (LP64 prelude, callee prototypes from
  the callees' own decompiled signatures, globals declared from their `<prefix>Ram<hex>` stem
  at the varnode's width) and compiled with the same gcc, and `recompile::verify` attributes
  the difference (the ELF-relocatable candidate loader in `candidate.rs`). gcc is a
  development-environment requirement and its version floats, so
  `tests/ground_truth_recompile.rs` gates against a PER-MACHINE baseline
  (`build/gt-recompile/baseline.tsv`: first run writes it; later runs fail on a verdict
  regression or a WGSS drop over 0.01; `MOSURA_GT_BASELINE=update` accepts a change).
  `cargo run --release --example gt_recompile [prog…]` prints the per-function table and
  writes `build/gt-recompile/report.tsv`; the TUs and objects stay in `build/gt-recompile/<prog>/`
  for the three-way read (source / our C / divergence).
  **First measurement (2026-08-22, gcc 14, -O2): 20 programs, 70 functions, 1,412 instructions,
  WGSS 0.29, 17 EXACT — with the compiler known and fixed.** The divergence-class profile is
  the subject's (extra 25 % / selection 20 % / regalloc 15 % / missing 14 % / operand-form 11 %), which
  settles the compiler question for the subject: the gap is the decompiler's source shape. First
  named finding: gcc's `-fipa-ra` keeps a caller's value in a register the callee is known not
  to clobber (`cube` reads `extraout_EDX` after calling `square`) — the same callee-clobber
  recovery the subject survey does with recovered `modify` lists, needed here as a decompiler
  feature. The compiler is the objective judge (it ignores
  names/structure); closeness (byte-identical → functionally-equivalent) is the quality metric.
  This is precisely where mosura can beat Ghidra, whose C usually won't even recompile. Measured
  (not yet gated) by `examples/gt_recompile_probe.rs`; see [Decompiler level](#decompiler-level).

## Layout

```
oracle/ground-truth/
  src/<program>.c                     source we own (arch-neutral helpers)
  src/shim.h                          per-arch process-exit shim (gcc ELF columns)
  src/z80prog.c + z80_crt0.s          the z80/CP/M program + its .COM entry crt0
  src/watprog.c + watprog_cstart.asm  the Watcom program + its freestanding _cstart_ entry stub
  build.sh                            compile → DERIVE truth → strip   (dev-oracle; regen only)
  <program>.<compiler>-<arch>         the analyzed artifact: STRIPPED binary   (committed)
  <program>.<compiler>-<arch>.truth   build-derived ground truth               (committed)
  z80prog.sdcc-z80.com[.truth]        the z80 column: a raw CP/M .COM (the .com suffix selects
                                      mosura's load_com by extension) + its truth
```

## Programs (arch-neutral source, one per feature)

| program    | exercises                                   | columns |
| ---        | ---                                         | --- |
| `arith`    | a call graph + a counted loop with a nested call | all |
| `dispatch` | a 7-case switch (jump table on x86-64/riscv/m68k; a branch tree on aarch64) | all |
| `tables`   | a dense 12-case switch (jump table on **every** arch) + a nested switch | all |
| `strdata`  | `.rodata` string constants referenced from code (data-not-code) | gcc x86-64/aarch64/riscv64 |
| `fnptr`    | a const function-pointer table + an indirect call site | gcc x86-64/aarch64/riscv64 |
| `z80prog`  | z80 call graph + a `jp (hl)` jump-table switch | sdcc z80 |
| `watprog`  | Watcom call graph + a jump-table switch | wcc386 x86-32 |

The gcc-ELF programs share one arch-neutral source; only the process-exit syscall is
arch-specific, isolated in `src/shim.h` (the "arch entry shim"). `_start` passes each result to
`sys_exit` so no call is a tail-jump — a tail-jump target has no direct call site, so flow
analysis folds it into the caller (correct for a symbol-free binary, but it would read as a
missed function). The z80 (CP/M crt0) and Watcom (wasm `_cstart_` stub) columns have their own
entry conventions.

Consistent with [`dependencies.md`](dependencies.md) tiering: **building** the corpus is
DEV-ORACLE (needs the toolchains); the **committed stripped binary + `.truth`** are the
BUILD/TEST surface — `cargo test` runs the gate offline, no toolchain required.

## Ground truth is DERIVED from the build, never hand-authored

`build.sh` compiles an **unstripped** binary, derives the truth from the artifact itself, then
strips the binary to the analyzed form (a realistic RE target — no symbols). There are two
derivation paths, both from the toolchain's OWN output (never Ghidra, never hand-authored):

**ELF columns (gcc x86-64/aarch64/riscv64/m68k + Watcom x86-32):**

- **functions** — `nm -S --defined-only` text symbols (t/T/w/W) that lie **inside an executable
  section** (the in-section test — exec ranges from `objdump -h` — drops ld boundary markers like
  `__bss_start`/`_edata`/`_end`, which ld binds to the .text index so nm mistypes them `T`). The
  `nm -S` size column is present (gcc) or absent (Watcom emits no sizes); the type field is found
  by position so both parse;
- **switch dispatches** — `objdump -d` indirect jumps, the union of every arch's mnemonic: x86
  `jmp *`, RISC-V `jr`, AArch64 `br`, m68k register-indexed/indirect `jmp` (a plain/PC-relative
  `jmp` with no address/data-register operand is a direct jump and excluded);
- **compiler** — the known toolchain of the build recipe.

**z80 column (a raw CP/M `.COM` — nm/objdump don't apply to a flat z80 image):** truth comes
from **sdcc's own linker output** — functions from the `_CODE` area of the map (`.map`, `-w`
wide), the switch dispatch from the relocated listing (`.rst`: a `jp (hl)` **followed by a `.dw`
jump table**; z80 also lowers a function *return* to `jp (hl)`, which is excluded). The entry is
the CP/M TPA (`0x100`), labeled in the crt0 so it appears in the map.

The `.truth` format is a simple diffable line format (mirrors the snapshot goldens):

```
# mosura-ground-truth v1 program=dispatch compiler=gcc arch=x86-64 lang=x86:LE:64:default
# derived-from=dispatch.gcc-x86-64.unstripped via=nm+objdump (build artifact, NOT Ghidra)
compiler gcc
entry 00000000004010a0
func 0000000000401030 0000000000000068 classify
switch 401049
```

**Watcom column (`wcc386` → freestanding ELF32 i386):** `wcc386 -bt=linux -s` compiles to an OMF
object; a hand-written `wasm` `_cstart_` stub (`src/watprog_cstart.asm`, declared the entry via
its `end _cstart_` MODEND record) provides the entry so **no Watcom C run-time is linked** (the
full CRT is a fragile ~40-function recall surface); `wlink system linux option nodefaultlib`
emits an ELF32. Watcom writes non-standard ELF section headers that mosura's `object`-crate ELF
parser rejects, so host `objcopy` normalizes it into a clean GNU ELF (also the source of the
truth). mosura's ELF loader maps `EM_386` → `x86:LE:32:default` (Ghidra's x86 ELF opinion; the
Watcom-ness lives in the code, not the container). Truth then follows the ELF path above.

## Compile matrix

Programs × compilers × arches — **all installed rows live** (build-derived, stripped-tested,
green in `tests/ground_truth_parity.rs`). clang and MSVC are not installed (documented gaps,
never faked).

| toolchain | arch | mosura lang | status |
| --- | --- | --- | --- |
| gcc | x86-64 | `x86:LE:64:default` | **live** — arith, dispatch, tables, strdata, fnptr |
| gcc | aarch64 | `AARCH64:LE:64:v8A` | **live** — arith, dispatch, tables, strdata, fnptr |
| gcc | riscv64 | `RISCV:LE:64:default` | **live** — arith, dispatch, tables, strdata, fnptr |
| gcc | m68k (BE) | `68000:BE:32:Coldfire` | **live** — arith, dispatch, tables, strdata, fnptr |
| sdcc | z80 | `z80:LE:16:default` | **live** — z80prog (CP/M .COM via load_com) |
| Open Watcom `wcc386` | x86-32 | `x86:LE:32:default` | **live** — watprog (freestanding ELF32) |
| clang | * | — | **ABSENT toolchain** (gap, not faked) |
| MSVC | x86/x64 | — | **ABSENT toolchain** (gap, not faked) |

### m68k register-indirect calls — gap surfaced then CLOSED

The corpus first surfaced a real recall gap: gcc `-O2` on m68k hoists a repeated/loop call
target's address into an address register and calls it register-indirect
(`lea %pc@(fn),%aN; jsr %aN@`) — so a target reached ONLY that way (`apply` in fnptr, called
twice; `slen`/`checksum` in strdata's loop) had no direct call site. Instrumenting showed the
constant propagator already folded the PC-relative `lea` to the constant target and emitted the
`COMPUTED_CALL` reference, but **no function was created at the destination**. The fix (a faithful
Ghidra `ConstantPropagationAnalyzer` port — `symbolic.rs` now seeds a function at each resolved
COMPUTED_CALL destination in executable memory, the same treatment the disassembler gives a
direct-call target) closed it: m68k `strdata`/`fnptr` now recover fully (0 spurious). **Note:** a
function-pointer *target reached only through the runtime table* is still not recovered as a
function on any arch (static pointer-table resolution is a separate capability) — `fnptr` keeps
every target directly call-reachable so recall stays exact while the indirect dispatch is present.

## Analysis level (phase 1, `tests/ground_truth_parity.rs`)

For each stripped binary, mosura's analysis must be a **clean subset** of the source truth:

1. **0 spurious** — every function mosura recovers is a real function in the truth;
2. **full recall of call-reachable functions** — with one honest carve-out: gcc splits cold
   paths into `<fn>.cold` symbols reached by a *jump*, not a *call*; on the stripped artifact
   flow-analysis correctly folds those into the parent, so they are not expected as separate
   functions (the truth marks them; the gate excludes `*.cold` from the recall set);
3. **every real switch dispatch recovered** (a `COMPUTED_JUMP` source or a `BRANCHIND` site).

Phase-2 result: **20 committed binaries green** across the matrix — every one 0 spurious with
full recall of its call-reachable functions, and every real switch dispatch recovered (as a
`COMPUTED_JUMP` source or a `BRANCHIND` site). E.g. `tables` 3/3 funcs + the dense-switch jump
table on all four gcc arches (`jmp *`/`br`/`jr`/`jmp %pc@(…,%dN:w)`); `watprog` 5/5 + its switch;
`z80prog` 5/5 + its `jp (hl)` switch — validated against source, no Ghidra involved.

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

## Scale-out status

1. ✅ **Matrix rows enabled** (aarch64/riscv64/m68k gcc, z80 sdcc, x86-32 Watcom) — each commits
   a stripped binary + `.truth`; the gate iterates them automatically. Adding EM_386 to the ELF
   loader (`x86:LE:32:default`) unlocked the Watcom column.
2. ✅ **Program set grown** — function-pointer indirect calls (`fnptr`), dense + nested switches
   (`tables`), string/data references (`strdata`), each an arch-neutral `src/*.c` with
   auto-derived truth, on every applicable arch.
3. ✅ **m68k register-indirect-call resolution** — the analyzer now creates a function at each
   resolved COMPUTED_CALL destination (Ghidra `ConstantPropagationAnalyzer` parity), closing the
   m68k `strdata`/`fnptr` gap the corpus surfaced.
4. **Open follow-ons (not this task):**
   - clang / MSVC columns once those toolchains are installed.
   - Decompiler track (separate, handoff): compilable-emission mode → wire the recompilation-
     equivalence loop (`examples/gt_recompile_probe.rs`) into a scored gate.
