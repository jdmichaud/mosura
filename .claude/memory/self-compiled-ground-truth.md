---
name: self-compiled-ground-truth
description: "Strategic idea (user, keep-in-mind): use self-authored programs compiled by each supported compiler as decompiler/analysis ground truth instead of relying on Ghidra (often wrong). Build a cross-compiler test-program set."
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-07-20T18:08:33.444Z
---

**User idea, 2026-07-18 — "an idea to keep in mind" (NOT yet actioned).** The strongest ground
truth is a program whose source you already know: author test programs, compile them with each
supported compiler (gcc / clang / Watcom / MSVC / …) across each supported arch (x86 / ARM64 /
RISC-V / 68k / Z80), decompile with mosura, and compare against the known original source.
Proposed concretely: a curated **test set of programs compiled by all supported compilers**,
used as the ground truth.

**Why it's strong (and why the user raised it):** the source IS the truth, so it does not
depend on Ghidra being correct — and Ghidra is often wrong (it invented ~20 false switches in
WAR2 that were really loops/searches; see [[war2-dos4gw-le]]). Reproducible + portable (compile
anywhere, no external oracle checkout). It directly serves the project's stated purpose — **do
better than Ghidra**: Ghidra-parity goldens only measure "matches Ghidra"; source-recovery
measures "recovers the actual program."

**The correctness criterion (user, clarified 2026-07-18): RECOMPILATION EQUIVALENCE, not
source resemblance.** The target is NOT "decompiled C looks like the original source" (fuzzy;
names/structure differ and that is explicitly not what we're after). It is: mosura's decompiled
C, **recompiled with the same compiler, produces the same binary.** That makes the compiler
itself the objective, automatable judge — it ignores naming/structure entirely and gives a
provable pass/fail. It is also precisely where mosura can beat Ghidra: Ghidra's decompiled C
frequently won't recompile at all, let alone reproduce the bytes. Practical spectrum:
byte-identical recompilation (strongest; achievable for a deterministic compiler on clean
output) → functionally-equivalent binary; how close mosura gets to byte-identical IS the
decompiler-quality metric.

For the **analysis track** (function boundaries, reference targets, switch locations, compiler
ID), the self-compiled source ALSO gives an exact, clean oracle for those properties — better
than Ghidra, and it's what this whole multi-arch/compiler-detection line has been validating.

Relates to [[direction-analysis-port]] and the two-oracle policy. For-the-record correction:
the warcraft2-re WAR2 ground truth was corrected by the AGENT, not hand-authored by the user.

**SCOPED 2026-07-20 (task #3; build deferred, keep-in-mind).** Grounded feasibility:
- **The self-compiled SET already exists** — `oracle/analysis-corpus/src/` (10 sources across
  gcc/g++/aarch64/riscv/m68k-gcc/sdcc/Watcom, binaries committed). The gap is the ORACLE SWAP:
  `goldens/analysis/*.snapshot` are still Ghidra-captured (analyzeHeadless), not source-derived.
- **(A) ANALYSIS source-derived oracle = TRACTABLE (my lane, incremental).** Assert source
  invariants (compiler-ID + function/switch-computed-jump/ref *presence* + 0-spurious) — a 2nd
  oracle alongside the byte-exact Ghidra golden (WAR2 two-oracle pattern). Caveat: source gives
  invariants not addresses (compile-dependent), so it complements, not replaces. Brick-1 = a
  source-oracle harness over the existing corpus.
- **(B) DECOMPILER recompilation-equivalence = DEEP, BLOCKED.** `dumpc` emits Ghidra-pseudo-C
  (`uint8`/`int4`/`CONCAT44`/intrinsics/`undefined*`) — NOT compilable. Needs a compilable-C
  emitter foundation (types prelude + intrinsics lib + proto/struct emission); decompiler-agent
  lane; multi-session. Even Ghidra's C usually won't recompile (= the beat-Ghidra opening).
  Not startable until the compilable-C emitter lands.
- Reported to the executive with a Brick-1 recommendation; not started autonomously (foundation
  = user's ROI call).

**PHASE-1 BOOTSTRAP LANDED `ce1b1a4` (2026-07-20).** `oracle/ground-truth/` (NEW, distinct from
analysis-corpus): src/{arith,dispatch}.c → `build.sh` compiles unstripped, DERIVES truth via
nm+objdump (NOT hand-authored, NOT Ghidra) → `.truth`, then STRIPS the analyzed binary. Committed:
stripped binary + `.truth` (test surface); toolchains = dev-oracle. **Analysis gate**
`tests/ground_truth_parity.rs`: mosura vs source truth = 0-spurious + full recall of
call-reachable funcs (gcc `*.cold` split-sections folded by flow-analysis, excluded) + switch
recovery. Result: arith 4/4, dispatch 4/4 + switch@0x401049. **Recompile probe**
`examples/gt_recompile_probe.rs` (measured, not gated): leaf funcs (square/op_add) COMPILE with a
sized-int prelude (ahead of Ghidra); blockers all C-emission (`xunknown*`, `func_0x`/`extraout`,
prelude, + a `classify` case-5 correctness bug) → decompiler-track handoff. Design:
`docs/ground-truth-corpus.md` (matrix incl. clang/MSVC ABSENT-gaps; both levels; scale plan).
**STOPPED for executive review before scaling the matrix** (per instruction). Installed
toolchains: gcc x86-64/aarch64/riscv64/m68k, sdcc, wcc386; clang+MSVC absent.
