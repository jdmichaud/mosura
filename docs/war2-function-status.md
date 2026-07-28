# WAR2.EXE — per-function decompilation status (recompilation parity)

**The bar:** a function counts as *properly decompiled* only if its emitted C, recompiled with the same compiler the game was built with, reproduces the original machine code **byte for byte**.

## Provenance

| | |
|---|---|
| Binary | `/home/jd/WAR2.EXE` (DOS/4GW Linear Executable) |
| SHA-256 | `4789987d1c4f4c3d02ad28cd20377d58d54f51c1fd2976d842ac33861eed0f63` |
| mosura | master `b0fb75b` (decompiler unchanged — read-only survey) |
| Loader | `analysis::analyze_le_file` (`--le` path, LE fixups applied; obj1 code rebased at 0x10000) |
| Compiler | Watcom C/386 10.0a `wcc386` under dosemu2, register calling convention |
| Flags | frame fns (`55 8b ec`): `-4r -fpi87 -s -of+ -onatx`; frameless: `-4r -fpi87 -s -onat`; post-link strip of the redundant `89 ec` epilogue (matches the original build) |
| Comparison | OMF `.OBJ` code bytes vs original `[entry, next-entry)` (trailing `00/90/cc` padding trimmed), relocation/fixup operand sites masked for the RELOC_EXACT class |
| Functions measured | **1286 of 1286** recovered functions (100%) |
| Date | 2026-07-23 |
| Harness | `crates/mosura/examples/war2_survey.rs` + `war2-survey/` driver scripts (compile.sh, compare.py) |

## Update — 2026-07-28: VariablePiece split (`be13a04`) — 505 value drops fixed, +18 COMPILE_FAIL

Full re-measure, both sides through the same harness with `obj/` cleaned each time, sides
state-asserted by the presence of the partial-symbol render (0 files before, 20 after). Saved as
`war2-survey/results.copymark-8c9c6bb.tsv` and `results.varpiece-be13a04.tsv`.

| status | `8c9c6bb` (before) | `be13a04` (after) |
| --- | --- | --- |
| EXACT | 1 | 1 |
| MISMATCH | 1214 | 1196 |
| **COMPILE_FAIL** | **71** | **89** |
| DECOMPILE_FAIL | 0 | 0 |

**Every transition is `MISMATCH → COMPILE_FAIL`, 18 of them, and nothing moves the other way.**
All 18 are one new error class, `E1032: Expression for '.' must be a 'structure' or 'union'` — the
partial-symbol accessor. Total E1032 = 20 = exactly the 20 files carrying the render (2 were already
COMPILE_FAIL under `E1052`, which drops 37 → 35 correspondingly). Every other class is unchanged:
E1079 11, E1010 11, E1018 7, and the six singletons.

**What was traded.** Those 18 functions compiled before, to the wrong bytes: 17 of the 18 matched
the original at **0-3%**, the last at 12%. Against that, the change fixed **505 narrow writes** that
were being emitted as full-width assignments (`uRam000000000008196c = (uint4)xVar12;` for a *1-byte*
store — three bytes claimed and not written). A function that compiles to the wrong semantics was
never a real pass; the byte-exact goal wants correct bytes, not compiling ones.

**This is the E1052-class ceiling again, and it splits a conflation worth naming.** `._<off>_<size>_`
is Ghidra's own artificial-field syntax (`PrintLanguage::unnamedField`, printlanguage.cc:719) — the
decompiler is faithful here and stays. But Ghidra's output was never meant to compile, and our
byte-exact goal needs it to. **Faithful and compilable are now separate axes.** Rendering the
accessor in compilable form — a width-correct write through the base address, or a union — is an
**emitter-level, beyond-Ghidra concern that belongs to the survey harness/emitter, never a reason to
put a wrong-code render back in the decompiler.** Filed as such; it is now the thing standing
between those 505 sites and compilability.

## Update — 2026-07-24: Brick 1 (pointer-in-integral-op cast) + clean-baseline correction

**Measurement correction (canonical going forward):** `war2-survey/compile.sh` does NOT clean `obj/`
between runs, so stale objects from a prior run were hiding new failures — the documented **137**
baseline was slightly stale-undercounted. Re-measured clean (`rm -f obj/*.OBJ` before compiling),
the **pre-fix baseline is 139** COMPILE_FAIL. All future numbers clean `obj/` first.

**Brick 1 (`8a86b73`)** — ported Ghidra's base `TypeOp::getInputCast` for the non-overriding
arithmetic/logical ops, so a pointer/float value fed to an integral op is cast (E1079/E1080/E1036).
See `docs/decompiler-bug-ptr-in-integral-op-cast.md`. Clean-vs-clean survey:

| Status | pre-fix (clean) | post-fix (clean) |
|---|---|---|
| EXACT | 1 | 1 |
| MISMATCH | 1140 | 1173 |
| COMPILE_FAIL | **139** | **112** |
| DECOMPILE_FAIL | 0* | 0 |

COMPILE_FAIL −27: E1079 33→11, E1080 12→5, E1036 3→0. Zero functions that compiled before now fail;
a few unmask a secondary type error and stay COMPILE_FAIL in a different bucket (honest accounting).

**E1052 (~35) reclassified — verified-faithful CEILING, not a defect** (see
`docs/decompiler-nonbug-e1052-void-indirect-call-faithful.md`): full-analysis Ghidra emits the
identical `iVar = (*(code *)p)();` for an opaque indirect call whose result is used, and that
construct fails to compile under gcc too. Not decompiler-reachable without beating Ghidra. **True
remaining actionable COMPILE_FAIL after Brick 1: 112 − 35 = 77.**

(*The clean pre-fix run showed 6 transient `returned None` — EMIT nondeterminism, decompiled fine in
the post-fix run; not attributable to the render-time cast change.)

## Update — 2026-07-23: Stage 0 (panic) landed

The **117 DECOMPILE_FAIL** functions below were all one bug — `Merge::trimOpInput` mis-port
(`merge.rs:1205` OOB on an INDIRECT in the entry block). Fixed in commit `b6ec467`
(docs/decompiler-bug-merge-indirect-trim-panic.md); re-running the survey EMIT stage now
decompiles **all 1286 functions (`fail=0`)**. Those 117 rows are stale — they now decompile and
will reclassify into MISMATCH/COMPILE_FAIL. Their exact recompile split is folded into the next
full re-measure (after Stage 1, the `__watcall` prototype wiring), rather than a separate dosemu
sweep now. The distribution table below is the pre-fix snapshot at `b0fb75b`.

## Update — 2026-07-23: Stage 1 (`__watcall` proto model) landed

Commit `e097ea8` threads the `Program`'s own `(language_id, compiler_spec_id)` into the
analysis-path proto-model resolution, so WAR2 decompiles under the Watcom `__watcall` register
convention (`specs/x86-32-watcom.cspec`: EAX,EDX,EBX,ECX integer args) instead of the datatest
x86-64 SysV default. Corpus stayed byte-identical (0.9513/57). This is the **first full
re-measure** after Stage 0 (the merge.rs panic fix), so it also folds in the 117 cleared
DECOMPILE_FAILs.

### New distribution (@ `e097ea8`)

| Status | Count | Share | Δ vs pre-fix (`b0fb75b`) |
|---|---:|---:|---|
| EXACT | 1 | 0.1% | 0 |
| RELOC_EXACT | 0 | 0.0% | 0 |
| MISMATCH | 1056 | 82.1% | +115 |
| COMPILE_FAIL | 229 | 17.8% | +2 |
| DECOMPILE_FAIL | 0 | 0.0% | −117 |
| **Total** | **1286** | 100% | |

### What moved and why

- **`void_proto` collapsed 1169 → 247** (compare.py smell): **922 functions gained parameters** —
  the `__watcall` model now recovers args/returns. This was the single biggest structural blocker
  in the pre-fix analysis, and it is retired. The 247 residual are genuinely parameter-less
  functions (leaves / no register args).
- **`extraout` dropped 626 → 93** (−533): modeling the EAX return retired most of the
  artifact-register reads that Stage 3 targets — a large chunk of the reg-artifact class was
  actually a *missing return*, fixed here as a side effect of proper return modeling.
- **DECOMPILE_FAIL 117 → 0**: Stage 0's `trimOpInput` fix, first shown in a full re-measure.

### Status transitions (pre-fix `b0fb75b` → `e097ea8`, joined by address)

| Transition | Count | Attribution |
|---|---:|---|
| DECOMPILE_FAIL → MISMATCH | 95 | Stage 0 (now decompiles; body differs) |
| DECOMPILE_FAIL → COMPILE_FAIL | 22 | Stage 0 (decompiles; C rejected) |
| COMPILE_FAIL → MISMATCH | 44 | **Stage 1** (param recovery let the void-proto body compile) |
| MISMATCH → COMPILE_FAIL | 24 | **Stage 1** regression (return modeling surfaced a type/render gap) |
| unchanged MISMATCH / COMPILE_FAIL / EXACT | 917 / 183 / 1 | — |

Net COMPILE_FAIL: −44 (fixed) +24 (regressed) +22 (from Stage 0) = **+2**.

The **24 MISMATCH → COMPILE_FAIL regressions** are all downstream type/render gaps, not proto-model
defects: 14 `E1052 Expression has void type`, 6 `E1010 Type mismatch`, 4 `E1045 Subscript on
non-array`. Root of the E1052 class: an indirect call is now modeled with an EAX return
(`uVar = (*(code *)p)();`) and its result assigned, but the `code` typedef is `void (*)()`, so
Watcom rejects the void expression as a value. That is Stage 2's scope (printc/type completeness
giving the call a concrete return type) — the `__watcall` resolution itself is correct (params
appear in EAX/EDX/EBX/ECX; unit test + empirical `wcc386` oracle confirm).

### MISMATCH cause shift

Param recovery no longer dominates: `param-recovery` 465 → 195, while `codegen/regalloc` is now
the dominant residual at **797** — the honest hard tail (correct-enough C, but `wcc386`'s register
allocation / instruction selection diverges from the original build). `reg-artifact` 61, `thunk` 3.
Byte similarity is essentially unchanged (best non-trivial: `FUN_0006a7d0` 75%, `FUN_00077f65`
64%): parameter recovery is a **necessary foundation, not sufficient** — crossing the byte-exact
bar needs codegen-level fidelity (Stage 2 compile-fail cleanup + Stage 3 reg-artifact + the codegen
tail).

### COMPILE_FAIL first-error classes (@ `e097ea8`)

| wcc386 error | Count | Was (pre-fix) |
|---|---:|---:|
| E1063 Missing operand | 113 | 100 |
| E1079 Expression must be integral | 31 | 37 |
| E1052 Expression has void type | 21 | 0 (new; return-modeling side effect) |
| E1029 Expression must be 'pointer to ...' | 17 | 52 |
| E1010 Type mismatch | 13 | 8 |
| E1080 Expression must be arithmetic | 11 | 10 |
| E1045 Subscript on non-array | 11 | 10 |
| E1081 Expression must be scalar type | 5 | 5 |
| E1036 Right operand of '-' is a pointer | 3 | 2 |
| E1090 / E1082 / E1018 | 1 each | — |

`E1063 Missing operand` (the `...`/CALLOTHER leak) remains the top COMPILE_FAIL feeder — Stage 2's
primary target.

## Update — 2026-07-23: Stage 2 (printc completeness — `...`/CALLOTHER leak) landed

Commit `b4ac8f4` retires the `NAME(...)` catch-all leak from the emitted C: `CPUI_CALLOTHER`
renders as its SLEIGH user-op name (`in`/`cpuid`/`rdtsc`/`swi`; Ghidra `PrintC::opCallother`),
`CPUI_INT_SBORROW` as `SBORROW<n>(a,b)`, `CPUI_POPCOUNT` as `POPCOUNT(x)`. The `.sla` user-op
index→name table (previously dropped) is threaded onto the `Funcdata`. Corpus byte-identical
(0.9513/57). Details in docs/decompiler-bug-callother-ellipsis-leak.md.

### New distribution (@ `b4ac8f4`)

| Status | Count | Share | Δ vs Stage 1 (`e097ea8`) |
|---|---:|---:|---|
| EXACT | 1 | 0.1% | 0 |
| RELOC_EXACT | 0 | 0.0% | 0 |
| MISMATCH | 1148 | 89.3% | +92 |
| COMPILE_FAIL | 137 | 10.7% | −92 |
| DECOMPILE_FAIL | 0 | 0.0% | 0 |
| **Total** | **1286** | 100% | |

### What moved and why

- **COMPILE_FAIL 229 → 137 (−92)**: every mover is `COMPILE_FAIL → MISMATCH` (now compiles);
  **zero regressions** (no function that compiled at Stage 1 fails now).
- **`E1063 Missing operand` 113 → 4**: the top COMPILE_FAIL class is essentially gone. The 4
  residual are `MULTIEQUAL(...)`/`INDIRECT(...)` raw p-code that leaked past structuring — a
  distinct `raw_marker` upstream class (5 functions), not CALLOTHER.
- Smells: `callother` 66 → 0, `ellipsis` 118 → 5 (the 5 = the raw-marker residual).
- Byte-exact bar unmoved (1/0): Stage 2 is a *compilability* fix, not codegen fidelity. MISMATCH
  cause split essentially unchanged (codegen/regalloc 872, param-recovery 202, reg-artifact 68).

### Remaining COMPILE_FAIL (137) — all upstream type-inference / CAST, the deep C-cluster foundation

Instrumented the remaining first-error classes; none is a bounded printc miss — each is a value
mosura types as pointer-where-integer (or scalar-where-pointer), which Ghidra resolves with an
inserted CAST (`ActionSetCasts`) or a concrete `TypeCode`/`FuncProto`. Per the
faithful-type-of-wrong-ir rule the fix is upstream IR (the type system), i.e. the C-cluster
type-inference foundation (menu F), not the printer.

| wcc386 error | Count | Representative | Root |
|---|---:|---|---|
| E1052 Expression has void type | 34 | `iVar = (*(code *)p)();` | indirect-call result assigned, but the `code` cast is void-returning — needs `TypeCode` carrying the recovered return type |
| E1079 Expression must be integral | 33 | `uVar4 = pVar2 & -4;` | pointer-typed value in a bitwise op — needs an inserted `(uint)` cast |
| E1029 Expression must be 'pointer to ...' | 17 | `**param_4 = x;` / `*extraout_RCX` | under-pointered value dereferenced (some via `extraout_`, a Stage 3 artifact) |
| E1010 Type mismatch | 14 | — | mixed pointer/integer assignment |
| E1080 Expression must be arithmetic | 12 | `uVar6 = -param_4;` | negation/arith on a pointer-typed value |
| E1045 Subscript on non-array | 11 | `xVar1[-1] = param_4;` | a PTRADD-derived local typed scalar, then subscripted |
| E1081 / E1036 / E1063(raw) / others | 16 | — | scalar-type / pointer-subtract / raw-marker |

These are gated behind the type-inference foundation, consistent with the standing
bounded-levers-exhausted verdict (cast rules exhausted; remaining gaps are upstream). Stage 3
(the call-output trial lifecycle) addresses the `extraout_`-derived subset directly.

## Headline

**1 function of 1286 recompiles byte-identically** — `FUN_00070805`, a 1-byte `ret` stub (decompiled `void FUN_00070805(void) { return; }`). No function reaches RELOC_EXACT (identical modulo link-time fixups). Every non-trivial function currently falls short of the bar, for the reasons quantified below.

## Status distribution

| Status | Count | Share | Meaning |
|---|---:|---:|---|
| EXACT | 1 | 0.1% | recompiled bytes identical to the original |
| RELOC_EXACT | 0 | 0.0% | identical except at relocation/fixup operand sites |
| MISMATCH | 941 | 73.2% | compiles, but the machine code differs |
| COMPILE_FAIL | 227 | 17.7% | emitted C is rejected by wcc386 |
| DECOMPILE_FAIL | 117 | 9.1% | mosura panicked while decompiling the function |
| **Total** | **1286** | 100% | |

## Why functions miss the bar

### MISMATCH — 941 functions (73.2%)

The code compiles but does not reproduce the original bytes. Attributed causes:

| Cause | Count | Reading |
|---|---:|---|
| reg-artifact | 473 | `extraout_`/`unaff_`/`in_` artifact registers in the body — call/return trial-lifecycle gaps materialize phantom values the recompile can't reproduce |
| param-recovery | 465 | prototype recovered as `void(void)` — Watcom's register calling convention (`__watcall`: eax/edx/ebx/ecx) is not modeled, so parameters/returns are missing and the body reads uninitialized locals |
| thunk | 3 | 4-byte `jmp` thunks whose decompile re-expands into a full call sequence |

How close are they? Not close: **862 of 941** mismatching functions share fewer than 10% of their bytes with the original (rough sequence similarity). The best non-trivial approaches:

- `FUN_0006a7d0` @ 0x0006a7d0 — len cand=203 orig=223; 75%match; param-recovery
- `FUN_00077f65` @ 0x00077f65 — len cand=11 orig=218; 64%match; param-recovery
- `FUN_00034668` @ 0x00034668 — len cand=45 orig=48; 42%match; param-recovery

### COMPILE_FAIL — 227 functions (17.7%)

The emitted C is not valid Watcom C. First error per function:

| wcc386 error | Count |
|---|---:|
| E1063:Missing operand | 100 |
| E1029:Expression must be 'pointer to ...' | 52 |
| E1079:Expression must be integral | 37 |
| E1080:Expression must be arithmetic | 10 |
| E1045:Subscript on non-array | 10 |
| E1010:Type mismatch | 8 |
| E1081:Expression must be scalar type | 5 |
| E1036:Right operand of '-' is a pointer | 2 |
| E1018:Label 'LAB_00034f28' not defined in function | 1 |
| E1018:Label 'LAB_00043f3a' not defined in function | 1 |

`E1063: Missing operand` (the top class) is the compiler tripping over unrendered decompiler output — `...` ellipsis operands and raw `CALLOTHER` intrinsics that leak into the C. The pointer/arithmetic type errors are type-inference gaps at call and dereference sites.

### DECOMPILE_FAIL — 117 functions (9.1%)

Every one of the 117 failures is the **same panic**: `crates/mosura/src/decompile/merge.rs:1205 index out of bounds` — a single decompiler bug discovered by this survey. First affected functions: `0x00011954`, `0x000124ec`, `0x00012a78`. Per the WAR2 ground-truth rule, this reduces to a self-compiled source test before fixing.

## Structural blockers, ranked by blast radius

Smell markers across all 1286 emitted decompiles:

| Marker | Functions | Meaning |
|---|---:|---|
| void_proto | 1169 | prototype is `void FUN(void)` — no parameters or return recovered |
| indirect_call | 822 | `func_0x…` unresolved call target in the body |
| extraout | 626 | `extraout_` artifact register referenced |
| ellipsis | 108 | `...` unrendered operand in the output |
| callother | 61 | raw `CALLOTHER` intrinsic in the output |
| int64 | 10 | 64-bit `CONCAT44`/`int8` idiom present |
| raw_marker | 4 | raw p-code (`INDIRECT`/`MULTIEQUAL`) leaked into the C |

1. **Watcom register-convention prototype recovery** — `void_proto` on 1169 of 1286 functions (91%). Without `__watcall` parameter/return modeling on the LE path, essentially no function can produce matching code. Biggest single lever.
2. **Call/return artifact registers** (`extraout_`, 626 functions) — the persistent output-trial lifecycle foundation already on the menu as pick (E).
3. **Unresolved indirect calls** (`func_0x…`, 822 functions) — needs global data-flow/symbol propagation for call targets through the jump/vtable tables.
4. **Unrendered operands** (`...`/`CALLOTHER`, ~169 functions) — printc completeness; also the top COMPILE_FAIL feeder.
5. **merge.rs:1205 panic** — 117 functions, one bug.

## Reproducing

```
cargo run --release --example war2_survey   # decompile + emit C for every function
war2-survey/compile.sh                      # batch wcc386 under dosemu2
python3 war2-survey/compare.py              # classify -> results.tsv
```

## Per-function status — all 1286 functions

Sorted by address. *Detail* is length/similarity for MISMATCH, the first compiler error for COMPILE_FAIL, the panic for DECOMPILE_FAIL.

| # | VA | Function | Status | Detail | Markers |
|---:|---|---|---|---|---|
| 0 | 0x0001011e | FUN_0001011e | MISMATCH | len cand=312 orig=246; 3%match; codegen/regalloc |  |
| 1 | 0x00010214 | FUN_00010214 | COMPILE_FAIL | E1079:Expression must be integral |  |
| 2 | 0x0001081c | FUN_0001081c | COMPILE_FAIL | E1080:Expression must be arithmetic |  |
| 3 | 0x00010b65 | FUN_00010b65 | MISMATCH | len cand=32 orig=39; 6%match; codegen/regalloc |  |
| 4 | 0x00010b8c | FUN_00010b8c | MISMATCH | len cand=76 orig=58; 2%match; codegen/regalloc |  |
| 5 | 0x00010bd0 | FUN_00010bd0 | MISMATCH | len cand=53 orig=79; 2%match; codegen/regalloc | indirect_call |
| 6 | 0x00010c20 | FUN_00010c20 | MISMATCH | len cand=203 orig=252; 1%match; codegen/regalloc | indirect_call |
| 7 | 0x00010d1c | FUN_00010d1c | MISMATCH | len cand=18 orig=15; 7%match; param-recovery | indirect_call,void_proto |
| 8 | 0x00010d2c | FUN_00010d2c | MISMATCH | len cand=18 orig=712; 6%match; param-recovery | indirect_call,void_proto |
| 9 | 0x00010ff4 | FUN_00010ff4 | MISMATCH | len cand=132 orig=191; 2%match; codegen/regalloc |  |
| 10 | 0x000110b4 | FUN_000110b4 | MISMATCH | len cand=128 orig=144; 5%match; codegen/regalloc | indirect_call |
| 11 | 0x00011144 | FUN_00011144 | MISMATCH | len cand=194 orig=119; 1%match; codegen/regalloc | indirect_call |
| 12 | 0x000111bc | FUN_000111bc | MISMATCH | len cand=220 orig=280; 4%match; codegen/regalloc | indirect_call |
| 13 | 0x000112d4 | FUN_000112d4 | MISMATCH | len cand=46 orig=124; 2%match; codegen/regalloc | indirect_call |
| 14 | 0x00011350 | FUN_00011350 | MISMATCH | len cand=315 orig=255; 2%match; codegen/regalloc | indirect_call |
| 15 | 0x00011450 | FUN_00011450 | MISMATCH | len cand=612 orig=392; 4%match; codegen/regalloc | indirect_call |
| 16 | 0x000115d8 | FUN_000115d8 | COMPILE_FAIL | E1052:Expression has void type |  |
| 17 | 0x0001163c | FUN_0001163c | COMPILE_FAIL | E1010:Type mismatch | indirect_call |
| 18 | 0x00011838 | FUN_00011838 | COMPILE_FAIL | E1052:Expression has void type |  |
| 19 | 0x0001193c | FUN_0001193c | MISMATCH | len cand=14 orig=24; 6%match; codegen/regalloc | indirect_call |
| 20 | 0x00011954 | FUN_00011954 | MISMATCH | len cand=53 orig=1736; 0%match; codegen/regalloc | indirect_call |
| 21 | 0x0001201c | FUN_0001201c | MISMATCH | len cand=317 orig=295; 1%match; codegen/regalloc | indirect_call |
| 22 | 0x00012144 | FUN_00012144 | MISMATCH | len cand=102 orig=664; 6%match; codegen/regalloc | indirect_call |
| 23 | 0x000123dc | FUN_000123dc | MISMATCH | len cand=257 orig=227; 2%match; reg-artifact | extraout,indirect_call |
| 24 | 0x000124c0 | FUN_000124c0 | MISMATCH | len cand=47 orig=44; 7%match; codegen/regalloc |  |
| 25 | 0x000124ec | FUN_000124ec | MISMATCH | len cand=142 orig=168; 12%match; codegen/regalloc | indirect_call |
| 26 | 0x00012594 | FUN_00012594 | MISMATCH | len cand=43 orig=40; 2%match; codegen/regalloc |  |
| 27 | 0x000125bc | FUN_000125bc | MISMATCH | len cand=110 orig=87; 1%match; codegen/regalloc | indirect_call |
| 28 | 0x00012614 | FUN_00012614 | MISMATCH | len cand=157 orig=216; 2%match; codegen/regalloc | indirect_call |
| 29 | 0x000126ec | FUN_000126ec | MISMATCH | len cand=346 orig=239; 2%match; codegen/regalloc | indirect_call |
| 30 | 0x000127dc | FUN_000127dc | MISMATCH | len cand=95 orig=136; 3%match; codegen/regalloc | indirect_call |
| 31 | 0x00012864 | FUN_00012864 | MISMATCH | len cand=148 orig=124; 7%match; codegen/regalloc | indirect_call |
| 32 | 0x000128e0 | FUN_000128e0 | MISMATCH | len cand=62 orig=88; 3%match; codegen/regalloc | indirect_call |
| 33 | 0x00012938 | FUN_00012938 | MISMATCH | len cand=41 orig=87; 2%match; codegen/regalloc |  |
| 34 | 0x00012990 | FUN_00012990 | MISMATCH | len cand=152 orig=127; 11%match; codegen/regalloc | indirect_call |
| 35 | 0x00012a10 | FUN_00012a10 | MISMATCH | len cand=15 orig=104; 0%match; codegen/regalloc |  |
| 36 | 0x00012a78 | FUN_00012a78 | MISMATCH | len cand=327 orig=143; 3%match; codegen/regalloc | indirect_call |
| 37 | 0x00012b08 | FUN_00012b08 | MISMATCH | len cand=52 orig=51; 2%match; codegen/regalloc |  |
| 38 | 0x00012b3c | FUN_00012b3c | MISMATCH | len cand=121 orig=195; 2%match; codegen/regalloc | indirect_call |
| 39 | 0x00012c00 | FUN_00012c00 | MISMATCH | len cand=132 orig=88; 3%match; codegen/regalloc | indirect_call |
| 40 | 0x00012c58 | FUN_00012c58 | MISMATCH | len cand=81 orig=51; 2%match; codegen/regalloc | indirect_call |
| 41 | 0x00012c90 | FUN_00012c90 | MISMATCH | len cand=24 orig=16; 6%match; param-recovery | indirect_call,void_proto |
| 42 | 0x00012ca0 | FUN_00012ca0 | MISMATCH | len cand=58 orig=291; 3%match; codegen/regalloc | indirect_call |
| 43 | 0x00012dc4 | FUN_00012dc4 | MISMATCH | len cand=43 orig=215; 0%match; reg-artifact | extraout,indirect_call |
| 44 | 0x00012e9c | FUN_00012e9c | MISMATCH | len cand=34 orig=591; 12%match; codegen/regalloc | indirect_call |
| 45 | 0x000130ec | FUN_000130ec | MISMATCH | len cand=85 orig=116; 5%match; codegen/regalloc |  |
| 46 | 0x00013160 | FUN_00013160 | MISMATCH | len cand=14 orig=319; 6%match; codegen/regalloc | indirect_call |
| 47 | 0x000132a0 | FUN_000132a0 | MISMATCH | len cand=88 orig=132; 3%match; codegen/regalloc | indirect_call |
| 48 | 0x00013324 | FUN_00013324 | MISMATCH | len cand=515 orig=567; 2%match; codegen/regalloc | indirect_call |
| 49 | 0x0001355c | FUN_0001355c | MISMATCH | len cand=197 orig=171; 5%match; codegen/regalloc | indirect_call |
| 50 | 0x00013608 | FUN_00013608 | MISMATCH | len cand=113 orig=132; 3%match; codegen/regalloc | indirect_call |
| 51 | 0x0001368c | FUN_0001368c | MISMATCH | len cand=116 orig=128; 3%match; codegen/regalloc |  |
| 52 | 0x0001370c | FUN_0001370c | MISMATCH | len cand=261 orig=1347; 3%match; codegen/regalloc | indirect_call |
| 53 | 0x00013c50 | FUN_00013c50 | MISMATCH | len cand=43 orig=35; 3%match; codegen/regalloc | indirect_call |
| 54 | 0x00013c74 | FUN_00013c74 | MISMATCH | len cand=92 orig=336; 13%match; codegen/regalloc | indirect_call |
| 55 | 0x00013dc4 | FUN_00013dc4 | MISMATCH | len cand=92 orig=192; 13%match; codegen/regalloc | indirect_call |
| 56 | 0x00013e84 | FUN_00013e84 | MISMATCH | len cand=91 orig=87; 6%match; codegen/regalloc | indirect_call |
| 57 | 0x00013edc | FUN_00013edc | MISMATCH | len cand=86 orig=100; 5%match; codegen/regalloc | indirect_call |
| 58 | 0x00013f40 | FUN_00013f40 | MISMATCH | len cand=61 orig=60; 3%match; codegen/regalloc | indirect_call |
| 59 | 0x00013f7c | FUN_00013f7c | MISMATCH | len cand=324 orig=1083; 5%match; codegen/regalloc | indirect_call |
| 60 | 0x000143b8 | FUN_000143b8 | MISMATCH | len cand=349 orig=175; 5%match; codegen/regalloc | indirect_call |
| 61 | 0x00014468 | FUN_00014468 | MISMATCH | len cand=48 orig=6384; 2%match; codegen/regalloc | indirect_call |
| 62 | 0x00015d58 | FUN_00015d58 | MISMATCH | len cand=241 orig=319; 2%match; codegen/regalloc | indirect_call |
| 63 | 0x00015e98 | FUN_00015e98 | MISMATCH | len cand=280 orig=147; 3%match; codegen/regalloc | indirect_call |
| 64 | 0x00015f2c | FUN_00015f2c | MISMATCH | len cand=322 orig=223; 4%match; codegen/regalloc | indirect_call |
| 65 | 0x0001600c | FUN_0001600c | MISMATCH | len cand=83 orig=92; 6%match; codegen/regalloc | indirect_call |
| 66 | 0x00016068 | FUN_00016068 | MISMATCH | len cand=53 orig=175; 6%match; codegen/regalloc | indirect_call |
| 67 | 0x00016118 | FUN_00016118 | MISMATCH | len cand=253 orig=256; 1%match; codegen/regalloc | indirect_call |
| 68 | 0x00016218 | FUN_00016218 | MISMATCH | len cand=111 orig=895; 0%match; codegen/regalloc | indirect_call |
| 69 | 0x00016598 | FUN_00016598 | COMPILE_FAIL | E1010:Type mismatch | indirect_call |
| 70 | 0x00016610 | FUN_00016610 | MISMATCH | len cand=33 orig=88; 9%match; codegen/regalloc | indirect_call |
| 71 | 0x00016668 | FUN_00016668 | COMPILE_FAIL | E1010:Type mismatch | indirect_call |
| 72 | 0x000166f0 | FUN_000166f0 | MISMATCH | len cand=39 orig=32; 6%match; codegen/regalloc | indirect_call |
| 73 | 0x00016710 | FUN_00016710 | MISMATCH | len cand=85 orig=83; 0%match; codegen/regalloc |  |
| 74 | 0x00016764 | FUN_00016764 | MISMATCH | len cand=97 orig=132; 2%match; codegen/regalloc |  |
| 75 | 0x000167e8 | FUN_000167e8 | MISMATCH | len cand=84 orig=127; 5%match; codegen/regalloc | indirect_call |
| 76 | 0x00016868 | FUN_00016868 | MISMATCH | len cand=54 orig=59; 6%match; codegen/regalloc | indirect_call |
| 77 | 0x000168a4 | FUN_000168a4 | MISMATCH | len cand=103 orig=144; 1%match; reg-artifact | extraout,indirect_call |
| 78 | 0x00016934 | FUN_00016934 | MISMATCH | len cand=70 orig=84; 7%match; reg-artifact | extraout,indirect_call |
| 79 | 0x00016988 | FUN_00016988 | MISMATCH | len cand=56 orig=74; 0%match; reg-artifact | extraout,indirect_call |
| 80 | 0x000169e0 | FUN_000169e0 | MISMATCH | len cand=43 orig=76; 2%match; codegen/regalloc | indirect_call |
| 81 | 0x00016a2c | FUN_00016a2c | MISMATCH | len cand=71 orig=127; 3%match; codegen/regalloc | indirect_call |
| 82 | 0x00016aac | FUN_00016aac | MISMATCH | len cand=83 orig=140; 7%match; codegen/regalloc | indirect_call |
| 83 | 0x00016b38 | FUN_00016b38 | MISMATCH | len cand=14 orig=27; 0%match; codegen/regalloc | indirect_call |
| 84 | 0x00016b54 | FUN_00016b54 | MISMATCH | len cand=111 orig=135; 4%match; codegen/regalloc | indirect_call |
| 85 | 0x00016bdc | FUN_00016bdc | MISMATCH | len cand=162 orig=243; 2%match; reg-artifact | extraout,indirect_call |
| 86 | 0x00016cd0 | FUN_00016cd0 | MISMATCH | len cand=92 orig=3313; 7%match; codegen/regalloc | indirect_call |
| 87 | 0x000179d0 | FUN_000179d0 | MISMATCH | len cand=38 orig=48; 0%match; codegen/regalloc |  |
| 88 | 0x00017a00 | FUN_00017a00 | MISMATCH | len cand=689 orig=587; 2%match; codegen/regalloc |  |
| 89 | 0x00017c4c | FUN_00017c4c | MISMATCH | len cand=91 orig=319; 1%match; codegen/regalloc | indirect_call |
| 90 | 0x00017d8c | FUN_00017d8c | MISMATCH | len cand=19 orig=115; 5%match; codegen/regalloc |  |
| 91 | 0x00017e00 | FUN_00017e00 | MISMATCH | len cand=1551 orig=548; 1%match; codegen/regalloc | indirect_call |
| 92 | 0x00018024 | FUN_00018024 | COMPILE_FAIL | E1080:Expression must be arithmetic | extraout,indirect_call |
| 93 | 0x0001812c | FUN_0001812c | MISMATCH | len cand=80 orig=899; 4%match; codegen/regalloc | indirect_call |
| 94 | 0x000184b0 | FUN_000184b0 | MISMATCH | len cand=488 orig=208; 2%match; codegen/regalloc | indirect_call |
| 95 | 0x00018580 | FUN_00018580 | MISMATCH | len cand=430 orig=1079; 2%match; codegen/regalloc | indirect_call |
| 96 | 0x000189b8 | FUN_000189b8 | MISMATCH | len cand=48 orig=2167; 6%match; codegen/regalloc | indirect_call |
| 97 | 0x00019230 | FUN_00019230 | MISMATCH | len cand=84 orig=79; 4%match; codegen/regalloc |  |
| 98 | 0x00019280 | FUN_00019280 | MISMATCH | len cand=98 orig=196; 2%match; codegen/regalloc | indirect_call |
| 99 | 0x00019344 | FUN_00019344 | MISMATCH | len cand=35 orig=1160; 3%match; codegen/regalloc | indirect_call |
| 100 | 0x000197cc | FUN_000197cc | MISMATCH | @+0; 4%comparable-match; codegen/regalloc |  |
| 101 | 0x000197e8 | FUN_000197e8 | MISMATCH | len cand=191 orig=235; 3%match; codegen/regalloc | indirect_call |
| 102 | 0x000198d4 | FUN_000198d4 | COMPILE_FAIL | E1052:Expression has void type | indirect_call |
| 103 | 0x0001b750 | FUN_0001b750 | MISMATCH | len cand=27 orig=20; 15%match; codegen/regalloc |  |
| 104 | 0x0001b764 | FUN_0001b764 | MISMATCH | len cand=167 orig=196; 1%match; codegen/regalloc |  |
| 105 | 0x0001b828 | FUN_0001b828 | MISMATCH | len cand=99 orig=143; 6%match; codegen/regalloc |  |
| 106 | 0x0001b8b8 | FUN_0001b8b8 | MISMATCH | len cand=340 orig=384; 2%match; codegen/regalloc | indirect_call |
| 107 | 0x0001ba38 | FUN_0001ba38 | MISMATCH | len cand=184 orig=332; 2%match; codegen/regalloc | indirect_call |
| 108 | 0x0001bb84 | FUN_0001bb84 | MISMATCH | len cand=124 orig=267; 2%match; reg-artifact | extraout,indirect_call |
| 109 | 0x0001bc90 | FUN_0001bc90 | MISMATCH | len cand=75 orig=160; 3%match; codegen/regalloc |  |
| 110 | 0x0001bd30 | FUN_0001bd30 | MISMATCH | len cand=81 orig=952; 5%match; codegen/regalloc | indirect_call |
| 111 | 0x0001c0e8 | FUN_0001c0e8 | COMPILE_FAIL | E1079:Expression must be integral |  |
| 112 | 0x0001c154 | FUN_0001c154 | MISMATCH | len cand=165 orig=179; 3%match; codegen/regalloc |  |
| 113 | 0x0001c208 | FUN_0001c208 | MISMATCH | len cand=275 orig=287; 2%match; codegen/regalloc |  |
| 114 | 0x0001c328 | FUN_0001c328 | MISMATCH | len cand=112 orig=103; 3%match; codegen/regalloc | indirect_call |
| 115 | 0x0001c390 | FUN_0001c390 | MISMATCH | len cand=84 orig=139; 11%match; codegen/regalloc | indirect_call |
| 116 | 0x0001c41c | FUN_0001c41c | MISMATCH | len cand=78 orig=187; 5%match; codegen/regalloc | indirect_call |
| 117 | 0x0001c4d8 | FUN_0001c4d8 | MISMATCH | len cand=49 orig=891; 0%match; codegen/regalloc | indirect_call |
| 118 | 0x0001c854 | FUN_0001c854 | MISMATCH | len cand=95 orig=112; 0%match; codegen/regalloc | indirect_call |
| 119 | 0x0001c8c4 | FUN_0001c8c4 | MISMATCH | len cand=78 orig=167; 0%match; reg-artifact | extraout,indirect_call |
| 120 | 0x0001c96c | FUN_0001c96c | MISMATCH | len cand=58 orig=4164; 5%match; reg-artifact | extraout,indirect_call |
| 121 | 0x0001d9b0 | FUN_0001d9b0 | MISMATCH | len cand=53 orig=79; 4%match; codegen/regalloc |  |
| 122 | 0x0001da00 | FUN_0001da00 | MISMATCH | len cand=29 orig=43; 3%match; codegen/regalloc | indirect_call |
| 123 | 0x0001da2c | FUN_0001da2c | MISMATCH | len cand=29 orig=51; 3%match; codegen/regalloc | indirect_call |
| 124 | 0x0001da60 | FUN_0001da60 | MISMATCH | len cand=201 orig=728; 1%match; param-recovery | indirect_call,void_proto |
| 125 | 0x0001dd38 | FUN_0001dd38 | MISMATCH | len cand=239 orig=1043; 4%match; codegen/regalloc | indirect_call |
| 126 | 0x0001e14c | FUN_0001e14c | MISMATCH | len cand=228 orig=424; 4%match; codegen/regalloc | indirect_call |
| 127 | 0x0001e2f4 | FUN_0001e2f4 | MISMATCH | len cand=54 orig=99; 4%match; codegen/regalloc | indirect_call |
| 128 | 0x0001e358 | FUN_0001e358 | MISMATCH | len cand=2386 orig=664; 1%match; codegen/regalloc | indirect_call |
| 129 | 0x0001e5f0 | FUN_0001e5f0 | MISMATCH | len cand=214 orig=260; 6%match; codegen/regalloc | indirect_call |
| 130 | 0x0001e6f4 | FUN_0001e6f4 | MISMATCH | len cand=283 orig=327; 4%match; codegen/regalloc | indirect_call |
| 131 | 0x0001e83c | FUN_0001e83c | MISMATCH | len cand=402 orig=528; 3%match; codegen/regalloc | indirect_call |
| 132 | 0x0001ea4c | FUN_0001ea4c | MISMATCH | len cand=54 orig=71; 4%match; codegen/regalloc | indirect_call |
| 133 | 0x0001ea94 | FUN_0001ea94 | MISMATCH | len cand=162 orig=324; 0%match; codegen/regalloc |  |
| 134 | 0x0001ebd8 | FUN_0001ebd8 | MISMATCH | len cand=105 orig=119; 5%match; codegen/regalloc | indirect_call |
| 135 | 0x0001ec50 | FUN_0001ec50 | MISMATCH | len cand=163 orig=216; 2%match; codegen/regalloc |  |
| 136 | 0x0001ed28 | FUN_0001ed28 | MISMATCH | len cand=9 orig=48; 0%match; param-recovery | void_proto |
| 137 | 0x0001ed58 | FUN_0001ed58 | MISMATCH | len cand=26 orig=55; 4%match; codegen/regalloc |  |
| 138 | 0x0001ed90 | FUN_0001ed90 | MISMATCH | len cand=277 orig=264; 3%match; codegen/regalloc |  |
| 139 | 0x0001ee98 | FUN_0001ee98 | MISMATCH | len cand=623 orig=792; 3%match; codegen/regalloc | indirect_call |
| 140 | 0x0001f1b0 | FUN_0001f1b0 | MISMATCH | len cand=269 orig=423; 1%match; codegen/regalloc |  |
| 141 | 0x0001f358 | FUN_0001f358 | MISMATCH | len cand=120 orig=127; 3%match; codegen/regalloc |  |
| 142 | 0x0001f3d8 | FUN_0001f3d8 | COMPILE_FAIL | E1079:Expression must be integral |  |
| 143 | 0x0001f47c | FUN_0001f47c | MISMATCH | len cand=410 orig=1499; 2%match; codegen/regalloc |  |
| 144 | 0x0001fa58 | FUN_0001fa58 | MISMATCH | len cand=251 orig=268; 5%match; codegen/regalloc |  |
| 145 | 0x0001fb64 | FUN_0001fb64 | MISMATCH | len cand=32 orig=87; 0%match; codegen/regalloc |  |
| 146 | 0x0001fbbc | FUN_0001fbbc | MISMATCH | len cand=55 orig=232; 0%match; codegen/regalloc | indirect_call |
| 147 | 0x0001fca4 | FUN_0001fca4 | MISMATCH | len cand=55 orig=280; 0%match; codegen/regalloc | indirect_call |
| 148 | 0x0001fdbc | FUN_0001fdbc | MISMATCH | len cand=894 orig=1110; 4%match; codegen/regalloc | indirect_call |
| 149 | 0x00020220 | FUN_00020220 | MISMATCH | len cand=52 orig=56; 0%match; codegen/regalloc | indirect_call |
| 150 | 0x00020258 | FUN_00020258 | MISMATCH | len cand=161 orig=1144; 3%match; codegen/regalloc | indirect_call |
| 151 | 0x000206d0 | FUN_000206d0 | MISMATCH | len cand=49 orig=51; 4%match; codegen/regalloc |  |
| 152 | 0x00020704 | FUN_00020704 | COMPILE_FAIL | E1052:Expression has void type |  |
| 153 | 0x000214ec | FUN_000214ec | MISMATCH | len cand=62 orig=87; 3%match; codegen/regalloc | indirect_call |
| 154 | 0x00021544 | FUN_00021544 | MISMATCH | len cand=126 orig=1284; 2%match; codegen/regalloc | indirect_call |
| 155 | 0x00021a48 | FUN_00021a48 | MISMATCH | len cand=51 orig=64; 7%match; codegen/regalloc | indirect_call |
| 156 | 0x00021a90 | FUN_00021a90 | MISMATCH | len cand=267 orig=243; 10%match; codegen/regalloc | indirect_call |
| 157 | 0x00021b84 | FUN_00021b84 | MISMATCH | len cand=2884 orig=711; 2%match; codegen/regalloc | indirect_call |
| 158 | 0x00021e4c | FUN_00021e4c | MISMATCH | len cand=244 orig=1348; 4%match; codegen/regalloc | indirect_call |
| 159 | 0x00022390 | FUN_00022390 | MISMATCH | len cand=229 orig=235; 8%match; codegen/regalloc | indirect_call |
| 160 | 0x0002247c | FUN_0002247c | MISMATCH | len cand=88 orig=117; 3%match; param-recovery | indirect_call,void_proto |
| 161 | 0x00022500 | FUN_00022500 | MISMATCH | len cand=77 orig=83; 5%match; codegen/regalloc |  |
| 162 | 0x00022554 | FUN_00022554 | MISMATCH | len cand=41 orig=56; 10%match; codegen/regalloc |  |
| 163 | 0x0002258c | FUN_0002258c | MISMATCH | len cand=71 orig=83; 7%match; codegen/regalloc |  |
| 164 | 0x000225e0 | FUN_000225e0 | MISMATCH | len cand=184 orig=139; 1%match; codegen/regalloc | indirect_call |
| 165 | 0x0002266c | FUN_0002266c | MISMATCH | len cand=47 orig=907; 11%match; codegen/regalloc | indirect_call |
| 166 | 0x000229f8 | FUN_000229f8 | MISMATCH | len cand=179 orig=300; 2%match; param-recovery | indirect_call,void_proto |
| 167 | 0x00022b24 | FUN_00022b24 | MISMATCH | len cand=252 orig=232; 0%match; codegen/regalloc | indirect_call |
| 168 | 0x00022c0c | FUN_00022c0c | MISMATCH | len cand=73 orig=119; 0%match; codegen/regalloc | indirect_call |
| 169 | 0x00022c84 | FUN_00022c84 | MISMATCH | len cand=203 orig=267; 0%match; codegen/regalloc | indirect_call |
| 170 | 0x00022d90 | FUN_00022d90 | MISMATCH | len cand=747 orig=2591; 3%match; codegen/regalloc | indirect_call |
| 171 | 0x000237b0 | FUN_000237b0 | MISMATCH | len cand=25 orig=171; 7%match; codegen/regalloc | indirect_call |
| 172 | 0x0002385c | FUN_0002385c | MISMATCH | len cand=208 orig=300; 3%match; codegen/regalloc | indirect_call |
| 173 | 0x00023988 | FUN_00023988 | MISMATCH | len cand=210 orig=255; 2%match; codegen/regalloc | indirect_call |
| 174 | 0x00023a88 | FUN_00023a88 | MISMATCH | len cand=62 orig=79; 0%match; codegen/regalloc | indirect_call |
| 175 | 0x00023ad8 | FUN_00023ad8 | MISMATCH | len cand=35 orig=59; 5%match; codegen/regalloc | indirect_call |
| 176 | 0x00023b14 | FUN_00023b14 | MISMATCH | len cand=20 orig=155; 12%match; codegen/regalloc | indirect_call |
| 177 | 0x00023bb0 | FUN_00023bb0 | MISMATCH | len cand=79 orig=143; 8%match; codegen/regalloc | indirect_call |
| 178 | 0x00023c40 | FUN_00023c40 | MISMATCH | len cand=193 orig=951; 1%match; codegen/regalloc | indirect_call |
| 179 | 0x00023ff8 | FUN_00023ff8 | MISMATCH | len cand=44 orig=64; 7%match; codegen/regalloc | indirect_call |
| 180 | 0x00024038 | FUN_00024038 | MISMATCH | len cand=37 orig=451; 0%match; codegen/regalloc | indirect_call |
| 181 | 0x000241fc | FUN_000241fc | MISMATCH | len cand=20 orig=32; 4%match; codegen/regalloc | indirect_call |
| 182 | 0x0002421c | FUN_0002421c | MISMATCH | len cand=20 orig=60; 4%match; codegen/regalloc | indirect_call |
| 183 | 0x00024258 | FUN_00024258 | MISMATCH | len cand=20 orig=147; 4%match; codegen/regalloc | indirect_call |
| 184 | 0x000242ec | FUN_000242ec | MISMATCH | len cand=20 orig=208; 4%match; codegen/regalloc | indirect_call |
| 185 | 0x000243bc | FUN_000243bc | MISMATCH | len cand=156 orig=635; 3%match; codegen/regalloc | indirect_call |
| 186 | 0x00024640 | FUN_00024640 | MISMATCH | len cand=137 orig=215; 4%match; codegen/regalloc |  |
| 187 | 0x00024718 | FUN_00024718 | MISMATCH | len cand=52 orig=147; 0%match; codegen/regalloc | indirect_call |
| 188 | 0x000247ac | FUN_000247ac | MISMATCH | len cand=55 orig=183; 4%match; codegen/regalloc | indirect_call |
| 189 | 0x00024864 | FUN_00024864 | MISMATCH | len cand=41 orig=75; 2%match; codegen/regalloc | indirect_call |
| 190 | 0x000248b0 | FUN_000248b0 | MISMATCH | len cand=129 orig=123; 1%match; codegen/regalloc | indirect_call |
| 191 | 0x0002492c | FUN_0002492c | MISMATCH | len cand=102 orig=1047; 0%match; codegen/regalloc | indirect_call |
| 192 | 0x00024d44 | FUN_00024d44 | MISMATCH | len cand=222 orig=1848; 2%match; codegen/regalloc | indirect_call |
| 193 | 0x0002547c | FUN_0002547c | MISMATCH | len cand=94 orig=92; 2%match; codegen/regalloc |  |
| 194 | 0x000254d8 | FUN_000254d8 | MISMATCH | @+0; 6%comparable-match; codegen/regalloc | indirect_call |
| 195 | 0x000254f0 | FUN_000254f0 | MISMATCH | len cand=14 orig=27; 0%match; codegen/regalloc | indirect_call |
| 196 | 0x0002550c | FUN_0002550c | MISMATCH | len cand=110 orig=131; 4%match; codegen/regalloc | indirect_call |
| 197 | 0x00025590 | FUN_00025590 | MISMATCH | len cand=8 orig=58; 0%match; codegen/regalloc |  |
| 198 | 0x000255d0 | FUN_000255d0 | MISMATCH | len cand=57 orig=151; 2%match; codegen/regalloc |  |
| 199 | 0x00025668 | FUN_00025668 | COMPILE_FAIL | E1079:Expression must be integral | extraout,indirect_call,int64 |
| 200 | 0x00025804 | FUN_00025804 | MISMATCH | len cand=74 orig=116; 5%match; codegen/regalloc | indirect_call |
| 201 | 0x00025878 | FUN_00025878 | MISMATCH | len cand=65 orig=132; 3%match; codegen/regalloc | indirect_call |
| 202 | 0x000258fc | FUN_000258fc | MISMATCH | len cand=65 orig=132; 3%match; codegen/regalloc | indirect_call |
| 203 | 0x00025980 | FUN_00025980 | COMPILE_FAIL | E1052:Expression has void type | indirect_call |
| 204 | 0x00026130 | FUN_00026130 | MISMATCH | len cand=20 orig=183; 8%match; codegen/regalloc | indirect_call |
| 205 | 0x000261e8 | FUN_000261e8 | MISMATCH | len cand=13 orig=964; 8%match; codegen/regalloc |  |
| 206 | 0x000265ac | FUN_000265ac | MISMATCH | len cand=27 orig=152; 4%match; codegen/regalloc |  |
| 207 | 0x00026644 | FUN_00026644 | MISMATCH | len cand=117 orig=140; 3%match; codegen/regalloc | indirect_call |
| 208 | 0x000266d0 | FUN_000266d0 | MISMATCH | len cand=85 orig=163; 2%match; codegen/regalloc | indirect_call |
| 209 | 0x00026774 | FUN_00026774 | MISMATCH | len cand=386 orig=440; 3%match; codegen/regalloc | indirect_call |
| 210 | 0x0002692c | FUN_0002692c | MISMATCH | len cand=439 orig=492; 3%match; codegen/regalloc | indirect_call |
| 211 | 0x00026b18 | FUN_00026b18 | MISMATCH | len cand=7 orig=66; 0%match; codegen/regalloc |  |
| 212 | 0x00026b60 | FUN_00026b60 | MISMATCH | len cand=10 orig=272; 10%match; codegen/regalloc |  |
| 213 | 0x00026c70 | FUN_00026c70 | MISMATCH | len cand=46 orig=116; 2%match; codegen/regalloc |  |
| 214 | 0x00026ce4 | FUN_00026ce4 | COMPILE_FAIL | E1079:Expression must be integral |  |
| 215 | 0x00026da8 | FUN_00026da8 | MISMATCH | len cand=104 orig=208; 1%match; param-recovery | indirect_call,void_proto |
| 216 | 0x00026e78 | FUN_00026e78 | MISMATCH | len cand=70 orig=120; 0%match; codegen/regalloc | indirect_call |
| 217 | 0x00026ef0 | FUN_00026ef0 | MISMATCH | len cand=43 orig=156; 2%match; codegen/regalloc |  |
| 218 | 0x00026f8c | FUN_00026f8c | MISMATCH | len cand=74 orig=176; 1%match; codegen/regalloc | indirect_call |
| 219 | 0x0002703c | FUN_0002703c | MISMATCH | len cand=49 orig=112; 4%match; codegen/regalloc |  |
| 220 | 0x000270ac | FUN_000270ac | MISMATCH | len cand=29 orig=415; 3%match; codegen/regalloc | indirect_call |
| 221 | 0x0002724c | FUN_0002724c | MISMATCH | len cand=51 orig=76; 2%match; codegen/regalloc | indirect_call |
| 222 | 0x00027298 | FUN_00027298 | MISMATCH | len cand=134 orig=935; 4%match; reg-artifact | extraout,indirect_call |
| 223 | 0x00027640 | FUN_00027640 | COMPILE_FAIL | E1052:Expression has void type |  |
| 224 | 0x000276e8 | FUN_000276e8 | MISMATCH | len cand=149 orig=191; 3%match; codegen/regalloc | indirect_call |
| 225 | 0x000277a8 | FUN_000277a8 | MISMATCH | len cand=20 orig=168; 8%match; codegen/regalloc | indirect_call |
| 226 | 0x00027850 | FUN_00027850 | MISMATCH | len cand=562 orig=340; 1%match; codegen/regalloc | indirect_call |
| 227 | 0x000279a4 | FUN_000279a4 | MISMATCH | len cand=14 orig=171; 7%match; codegen/regalloc |  |
| 228 | 0x00027a50 | FUN_00027a50 | MISMATCH | len cand=110 orig=224; 4%match; codegen/regalloc | indirect_call |
| 229 | 0x00027b30 | FUN_00027b30 | MISMATCH | len cand=105 orig=300; 4%match; codegen/regalloc | indirect_call |
| 230 | 0x00027c5c | FUN_00027c5c | MISMATCH | len cand=66 orig=116; 8%match; codegen/regalloc |  |
| 231 | 0x00027cd0 | FUN_00027cd0 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call,int64 |
| 232 | 0x00027d60 | FUN_00027d60 | MISMATCH | len cand=282 orig=311; 3%match; reg-artifact | extraout,indirect_call |
| 233 | 0x00027e98 | FUN_00027e98 | MISMATCH | len cand=123 orig=132; 2%match; reg-artifact | extraout,indirect_call |
| 234 | 0x00027f1c | FUN_00027f1c | MISMATCH | len cand=138 orig=3531; 4%match; reg-artifact | extraout,indirect_call |
| 235 | 0x00028ce8 | FUN_00028ce8 | MISMATCH | len cand=189 orig=175; 2%match; codegen/regalloc | indirect_call |
| 236 | 0x00028d98 | FUN_00028d98 | MISMATCH | len cand=364 orig=467; 4%match; codegen/regalloc | indirect_call |
| 237 | 0x00028f6c | FUN_00028f6c | MISMATCH | len cand=193 orig=464; 3%match; codegen/regalloc | indirect_call |
| 238 | 0x0002913c | FUN_0002913c | COMPILE_FAIL | E1036:Right operand of '-' is a pointer | indirect_call |
| 239 | 0x000293d0 | FUN_000293d0 | MISMATCH | len cand=16 orig=143; 6%match; codegen/regalloc |  |
| 240 | 0x00029460 | FUN_00029460 | MISMATCH | len cand=76 orig=160; 6%match; codegen/regalloc | indirect_call |
| 241 | 0x00029500 | FUN_00029500 | MISMATCH | len cand=81 orig=160; 2%match; codegen/regalloc |  |
| 242 | 0x000295a0 | FUN_000295a0 | COMPILE_FAIL | E1079:Expression must be integral |  |
| 243 | 0x00029630 | FUN_00029630 | MISMATCH | len cand=139 orig=151; 1%match; codegen/regalloc | indirect_call |
| 244 | 0x000296c8 | FUN_000296c8 | MISMATCH | @+0; 1%comparable-match; codegen/regalloc | indirect_call |
| 245 | 0x00029794 | FUN_00029794 | MISMATCH | len cand=115 orig=219; 1%match; codegen/regalloc | indirect_call |
| 246 | 0x00029870 | FUN_00029870 | MISMATCH | len cand=511 orig=352; 3%match; codegen/regalloc | indirect_call |
| 247 | 0x000299d0 | FUN_000299d0 | MISMATCH | len cand=38 orig=35; 0%match; param-recovery | indirect_call,void_proto |
| 248 | 0x000299f4 | FUN_000299f4 | MISMATCH | len cand=41 orig=984; 2%match; codegen/regalloc | indirect_call |
| 249 | 0x00029dcc | FUN_00029dcc | MISMATCH | len cand=415 orig=624; 12%match; codegen/regalloc | indirect_call |
| 250 | 0x0002a03c | FUN_0002a03c | MISMATCH | len cand=112 orig=120; 4%match; codegen/regalloc | indirect_call |
| 251 | 0x0002a0b4 | FUN_0002a0b4 | MISMATCH | len cand=34 orig=56; 9%match; codegen/regalloc | indirect_call |
| 252 | 0x0002a0ec | FUN_0002a0ec | MISMATCH | len cand=179 orig=127; 6%match; codegen/regalloc | indirect_call |
| 253 | 0x0002a16c | FUN_0002a16c | MISMATCH | len cand=56 orig=2003; 2%match; codegen/regalloc | indirect_call |
| 254 | 0x0002a940 | FUN_0002a940 | COMPILE_FAIL | E1052:Expression has void type | indirect_call |
| 255 | 0x0002ab58 | FUN_0002ab58 | MISMATCH | len cand=278 orig=280; 4%match; codegen/regalloc | indirect_call |
| 256 | 0x0002ac70 | FUN_0002ac70 | MISMATCH | len cand=45 orig=1299; 2%match; codegen/regalloc | indirect_call |
| 257 | 0x0002b184 | FUN_0002b184 | MISMATCH | len cand=155 orig=128; 3%match; codegen/regalloc | indirect_call |
| 258 | 0x0002b204 | FUN_0002b204 | COMPILE_FAIL | E1081:Expression must be scalar type | indirect_call |
| 259 | 0x0002b310 | FUN_0002b310 | MISMATCH | len cand=18 orig=15; 7%match; param-recovery | indirect_call,void_proto |
| 260 | 0x0002b320 | FUN_0002b320 | MISMATCH | len cand=85 orig=200; 1%match; codegen/regalloc | indirect_call |
| 261 | 0x0002b3e8 | FUN_0002b3e8 | MISMATCH | len cand=419 orig=387; 3%match; codegen/regalloc |  |
| 262 | 0x0002b56c | FUN_0002b56c | MISMATCH | len cand=529 orig=424; 0%match; codegen/regalloc | indirect_call |
| 263 | 0x0002b714 | FUN_0002b714 | MISMATCH | len cand=14 orig=16; 14%match; param-recovery | void_proto |
| 264 | 0x0002b724 | FUN_0002b724 | MISMATCH | len cand=338 orig=1519; 3%match; codegen/regalloc | indirect_call |
| 265 | 0x0002bd14 | FUN_0002bd14 | COMPILE_FAIL | E1063:Missing operand | ellipsis,indirect_call,raw_marker |
| 266 | 0x0002c08c | FUN_0002c08c | MISMATCH | len cand=57 orig=376; 7%match; codegen/regalloc |  |
| 267 | 0x0002c204 | FUN_0002c204 | MISMATCH | len cand=80 orig=2739; 1%match; codegen/regalloc | indirect_call |
| 268 | 0x0002ccb8 | FUN_0002ccb8 | COMPILE_FAIL | E1010:Type mismatch |  |
| 269 | 0x0002cd9c | FUN_0002cd9c | MISMATCH | len cand=117 orig=112; 1%match; codegen/regalloc | indirect_call |
| 270 | 0x0002ce0c | FUN_0002ce0c | MISMATCH | len cand=107 orig=216; 4%match; codegen/regalloc | indirect_call |
| 271 | 0x0002cee4 | FUN_0002cee4 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call |
| 272 | 0x0002d06c | FUN_0002d06c | MISMATCH | len cand=160 orig=152; 6%match; codegen/regalloc |  |
| 273 | 0x0002d104 | FUN_0002d104 | MISMATCH | len cand=46 orig=44; 2%match; codegen/regalloc | indirect_call |
| 274 | 0x0002d130 | FUN_0002d130 | MISMATCH | len cand=9 orig=8; 12%match; codegen/regalloc |  |
| 275 | 0x0002d138 | FUN_0002d138 | MISMATCH | len cand=102 orig=743; 1%match; codegen/regalloc | indirect_call |
| 276 | 0x0002d420 | FUN_0002d420 | MISMATCH | len cand=14 orig=15; 36%match; param-recovery | void_proto |
| 277 | 0x0002d430 | FUN_0002d430 | MISMATCH | len cand=17 orig=15; 7%match; codegen/regalloc |  |
| 278 | 0x0002d440 | FUN_0002d440 | MISMATCH | len cand=95 orig=171; 2%match; codegen/regalloc | indirect_call |
| 279 | 0x0002d4ec | FUN_0002d4ec | MISMATCH | len cand=55 orig=52; 2%match; param-recovery | indirect_call,void_proto |
| 280 | 0x0002d520 | FUN_0002d520 | MISMATCH | len cand=94 orig=196; 2%match; codegen/regalloc | indirect_call |
| 281 | 0x0002d5e4 | FUN_0002d5e4 | MISMATCH | len cand=59 orig=40; 5%match; codegen/regalloc | indirect_call |
| 282 | 0x0002d60c | FUN_0002d60c | MISMATCH | len cand=75 orig=66; 5%match; codegen/regalloc | indirect_call |
| 283 | 0x0002d650 | FUN_0002d650 | MISMATCH | len cand=62 orig=84; 2%match; codegen/regalloc | indirect_call |
| 284 | 0x0002d6a4 | FUN_0002d6a4 | MISMATCH | len cand=62 orig=84; 2%match; codegen/regalloc | indirect_call |
| 285 | 0x0002d6f8 | FUN_0002d6f8 | MISMATCH | len cand=61 orig=84; 7%match; codegen/regalloc | indirect_call |
| 286 | 0x0002d74c | FUN_0002d74c | MISMATCH | len cand=121 orig=176; 3%match; codegen/regalloc | indirect_call |
| 287 | 0x0002d7fc | FUN_0002d7fc | MISMATCH | len cand=740 orig=1092; 1%match; codegen/regalloc | indirect_call |
| 288 | 0x0002dc40 | FUN_0002dc40 | MISMATCH | len cand=39 orig=52; 10%match; codegen/regalloc | indirect_call |
| 289 | 0x0002dc74 | FUN_0002dc74 | MISMATCH | len cand=117 orig=783; 2%match; codegen/regalloc | indirect_call |
| 290 | 0x0002df90 | FUN_0002df90 | MISMATCH | len cand=35 orig=32; 3%match; codegen/regalloc | indirect_call |
| 291 | 0x0002dfb0 | FUN_0002dfb0 | MISMATCH | len cand=122 orig=227; 4%match; codegen/regalloc | indirect_call |
| 292 | 0x0002e094 | FUN_0002e094 | MISMATCH | len cand=16 orig=128; 6%match; codegen/regalloc |  |
| 293 | 0x0002e114 | FUN_0002e114 | MISMATCH | len cand=20 orig=108; 20%match; codegen/regalloc |  |
| 294 | 0x0002e180 | FUN_0002e180 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call |
| 295 | 0x0002e290 | FUN_0002e290 | MISMATCH | len cand=23 orig=100; 4%match; codegen/regalloc | indirect_call |
| 296 | 0x0002e2f4 | FUN_0002e2f4 | MISMATCH | len cand=142 orig=296; 2%match; codegen/regalloc | indirect_call |
| 297 | 0x0002e41c | FUN_0002e41c | MISMATCH | len cand=99 orig=131; 3%match; codegen/regalloc | indirect_call |
| 298 | 0x0002e4a0 | FUN_0002e4a0 | MISMATCH | len cand=87 orig=128; 3%match; codegen/regalloc |  |
| 299 | 0x0002e520 | FUN_0002e520 | MISMATCH | len cand=72 orig=63; 5%match; codegen/regalloc | indirect_call |
| 300 | 0x0002e560 | FUN_0002e560 | MISMATCH | len cand=133 orig=323; 2%match; codegen/regalloc | indirect_call |
| 301 | 0x0002e6a4 | FUN_0002e6a4 | MISMATCH | len cand=14 orig=184; 0%match; codegen/regalloc | indirect_call |
| 302 | 0x0002e75c | FUN_0002e75c | MISMATCH | len cand=16 orig=175; 6%match; codegen/regalloc |  |
| 303 | 0x0002e80c | FUN_0002e80c | MISMATCH | len cand=377 orig=1704; 3%match; codegen/regalloc | indirect_call |
| 304 | 0x0002eeb4 | FUN_0002eeb4 | MISMATCH | len cand=230 orig=295; 3%match; codegen/regalloc | indirect_call |
| 305 | 0x0002efdc | FUN_0002efdc | MISMATCH | len cand=152 orig=256; 5%match; codegen/regalloc | indirect_call |
| 306 | 0x0002f0dc | FUN_0002f0dc | MISMATCH | len cand=83 orig=108; 2%match; codegen/regalloc | indirect_call |
| 307 | 0x0002f148 | FUN_0002f148 | MISMATCH | len cand=83 orig=228; 0%match; codegen/regalloc |  |
| 308 | 0x0002f22c | FUN_0002f22c | MISMATCH | len cand=45 orig=55; 4%match; codegen/regalloc | indirect_call |
| 309 | 0x0002f264 | FUN_0002f264 | MISMATCH | len cand=13 orig=132; 0%match; codegen/regalloc |  |
| 310 | 0x0002f2e8 | FUN_0002f2e8 | MISMATCH | len cand=180 orig=187; 4%match; codegen/regalloc |  |
| 311 | 0x0002f3a4 | FUN_0002f3a4 | MISMATCH | len cand=64 orig=80; 0%match; codegen/regalloc | indirect_call |
| 312 | 0x0002f3f4 | FUN_0002f3f4 | MISMATCH | len cand=116 orig=127; 0%match; codegen/regalloc |  |
| 313 | 0x0002f474 | FUN_0002f474 | MISMATCH | len cand=129 orig=160; 2%match; codegen/regalloc | indirect_call |
| 314 | 0x0002f514 | FUN_0002f514 | MISMATCH | len cand=79 orig=208; 5%match; codegen/regalloc |  |
| 315 | 0x0002f5e4 | FUN_0002f5e4 | MISMATCH | len cand=111 orig=107; 1%match; codegen/regalloc | indirect_call |
| 316 | 0x0002f650 | FUN_0002f650 | MISMATCH | len cand=106 orig=164; 1%match; codegen/regalloc | indirect_call |
| 317 | 0x0002f6f4 | FUN_0002f6f4 | MISMATCH | len cand=138 orig=363; 1%match; codegen/regalloc | indirect_call |
| 318 | 0x0002f860 | FUN_0002f860 | MISMATCH | len cand=75 orig=99; 3%match; codegen/regalloc | indirect_call |
| 319 | 0x0002f8c4 | FUN_0002f8c4 | COMPILE_FAIL | E1052:Expression has void type | extraout,indirect_call |
| 320 | 0x0002fa30 | FUN_0002fa30 | MISMATCH | len cand=140 orig=216; 3%match; codegen/regalloc | indirect_call |
| 321 | 0x0002fb08 | FUN_0002fb08 | MISMATCH | len cand=182 orig=215; 3%match; codegen/regalloc | indirect_call |
| 322 | 0x0002fbe0 | FUN_0002fbe0 | MISMATCH | len cand=306 orig=284; 3%match; codegen/regalloc |  |
| 323 | 0x0002fcfc | FUN_0002fcfc | MISMATCH | len cand=195 orig=387; 3%match; codegen/regalloc |  |
| 324 | 0x0002fe80 | FUN_0002fe80 | MISMATCH | len cand=75 orig=124; 0%match; codegen/regalloc | indirect_call |
| 325 | 0x0002fefc | FUN_0002fefc | MISMATCH | len cand=65 orig=96; 1%match; codegen/regalloc | indirect_call |
| 326 | 0x0002ff5c | FUN_0002ff5c | MISMATCH | len cand=18 orig=12; 8%match; param-recovery | indirect_call,void_proto |
| 327 | 0x0002ff68 | FUN_0002ff68 | MISMATCH | len cand=97 orig=263; 9%match; codegen/regalloc | indirect_call |
| 328 | 0x00030070 | FUN_00030070 | MISMATCH | len cand=142 orig=176; 1%match; codegen/regalloc | indirect_call |
| 329 | 0x00030120 | FUN_00030120 | COMPILE_FAIL | E1052:Expression has void type | indirect_call |
| 330 | 0x00030270 | FUN_00030270 | COMPILE_FAIL | E1052:Expression has void type | indirect_call |
| 331 | 0x000303d8 | FUN_000303d8 | MISMATCH | len cand=219 orig=251; 2%match; codegen/regalloc | indirect_call |
| 332 | 0x000304d4 | FUN_000304d4 | MISMATCH | len cand=44 orig=324; 5%match; codegen/regalloc | indirect_call |
| 333 | 0x00030618 | FUN_00030618 | MISMATCH | len cand=155 orig=135; 1%match; codegen/regalloc | indirect_call |
| 334 | 0x000306a0 | FUN_000306a0 | MISMATCH | len cand=117 orig=123; 7%match; reg-artifact | extraout,indirect_call |
| 335 | 0x0003071c | FUN_0003071c | MISMATCH | len cand=41 orig=35; 6%match; codegen/regalloc | indirect_call |
| 336 | 0x00030740 | FUN_00030740 | MISMATCH | len cand=70 orig=100; 11%match; codegen/regalloc | indirect_call |
| 337 | 0x000307a4 | FUN_000307a4 | MISMATCH | len cand=4 orig=12; 0%match; param-recovery | void_proto |
| 338 | 0x000307b0 | FUN_000307b0 | MISMATCH | len cand=118 orig=176; 5%match; codegen/regalloc | indirect_call |
| 339 | 0x00030860 | FUN_00030860 | MISMATCH | len cand=606 orig=287; 1%match; codegen/regalloc |  |
| 340 | 0x00030980 | FUN_00030980 | MISMATCH | len cand=205 orig=628; 3%match; codegen/regalloc | indirect_call |
| 341 | 0x00030bf4 | FUN_00030bf4 | MISMATCH | len cand=155 orig=172; 3%match; codegen/regalloc | indirect_call |
| 342 | 0x00030ca0 | FUN_00030ca0 | MISMATCH | len cand=184 orig=264; 0%match; codegen/regalloc | indirect_call |
| 343 | 0x00030da8 | FUN_00030da8 | MISMATCH | len cand=18 orig=14; 14%match; param-recovery | indirect_call,void_proto |
| 344 | 0x00030db8 | FUN_00030db8 | MISMATCH | len cand=18 orig=14; 14%match; param-recovery | indirect_call,void_proto |
| 345 | 0x00030dc8 | FUN_00030dc8 | MISMATCH | len cand=27 orig=112; 3%match; codegen/regalloc | indirect_call |
| 346 | 0x00030e38 | FUN_00030e38 | COMPILE_FAIL | E1045:Subscript on non-array | indirect_call |
| 347 | 0x00030fb8 | FUN_00030fb8 | MISMATCH | len cand=86 orig=140; 2%match; codegen/regalloc | indirect_call |
| 348 | 0x00031044 | FUN_00031044 | MISMATCH | len cand=101 orig=75; 7%match; codegen/regalloc | indirect_call |
| 349 | 0x00031090 | FUN_00031090 | MISMATCH | len cand=155 orig=110; 2%match; codegen/regalloc | indirect_call |
| 350 | 0x00031100 | FUN_00031100 | MISMATCH | len cand=45 orig=728; 0%match; codegen/regalloc |  |
| 351 | 0x000313d8 | FUN_000313d8 | MISMATCH | len cand=175 orig=806; 2%match; codegen/regalloc | indirect_call |
| 352 | 0x00031700 | FUN_00031700 | MISMATCH | len cand=72 orig=107; 3%match; codegen/regalloc | indirect_call |
| 353 | 0x0003176c | FUN_0003176c | MISMATCH | len cand=47 orig=80; 4%match; codegen/regalloc | indirect_call |
| 354 | 0x000317bc | FUN_000317bc | MISMATCH | len cand=137 orig=111; 3%match; codegen/regalloc | indirect_call |
| 355 | 0x0003182c | FUN_0003182c | MISMATCH | len cand=33 orig=7960; 9%match; codegen/regalloc | indirect_call |
| 356 | 0x00033744 | FUN_00033744 | MISMATCH | len cand=543 orig=403; 2%match; codegen/regalloc | indirect_call |
| 357 | 0x000338d8 | FUN_000338d8 | COMPILE_FAIL | E1080:Expression must be arithmetic |  |
| 358 | 0x00033a10 | FUN_00033a10 | MISMATCH | len cand=181 orig=179; 6%match; codegen/regalloc | indirect_call |
| 359 | 0x00033ac4 | FUN_00033ac4 | MISMATCH | len cand=14 orig=12; 17%match; param-recovery | void_proto |
| 360 | 0x00033ad0 | FUN_00033ad0 | MISMATCH | len cand=76 orig=155; 6%match; codegen/regalloc | indirect_call |
| 361 | 0x00033b6c | FUN_00033b6c | MISMATCH | len cand=109 orig=116; 12%match; codegen/regalloc | indirect_call |
| 362 | 0x00033be0 | FUN_00033be0 | MISMATCH | len cand=46 orig=56; 4%match; codegen/regalloc | indirect_call |
| 363 | 0x00033c18 | FUN_00033c18 | MISMATCH | len cand=13 orig=63; 15%match; codegen/regalloc |  |
| 364 | 0x00033c58 | FUN_00033c58 | MISMATCH | len cand=181 orig=224; 2%match; codegen/regalloc | indirect_call |
| 365 | 0x00033d38 | FUN_00033d38 | MISMATCH | len cand=62 orig=76; 2%match; codegen/regalloc | indirect_call |
| 366 | 0x00033d84 | FUN_00033d84 | MISMATCH | len cand=4 orig=43; 0%match; codegen/regalloc |  |
| 367 | 0x00033db0 | FUN_00033db0 | MISMATCH | len cand=77 orig=95; 1%match; codegen/regalloc | indirect_call |
| 368 | 0x00033e10 | FUN_00033e10 | MISMATCH | len cand=229 orig=235; 2%match; codegen/regalloc | indirect_call |
| 369 | 0x00033efc | FUN_00033efc | MISMATCH | len cand=1561 orig=1139; 5%match; reg-artifact | extraout,indirect_call |
| 370 | 0x00034370 | FUN_00034370 | MISMATCH | len cand=141 orig=179; 2%match; reg-artifact | extraout,indirect_call |
| 371 | 0x00034424 | FUN_00034424 | MISMATCH | len cand=32 orig=283; 3%match; param-recovery | indirect_call,void_proto |
| 372 | 0x00034540 | FUN_00034540 | MISMATCH | len cand=111 orig=52; 6%match; codegen/regalloc |  |
| 373 | 0x00034574 | FUN_00034574 | MISMATCH | len cand=14 orig=59; 0%match; codegen/regalloc | indirect_call |
| 374 | 0x000345b0 | FUN_000345b0 | MISMATCH | len cand=94 orig=87; 2%match; reg-artifact | extraout,indirect_call |
| 375 | 0x00034608 | FUN_00034608 | MISMATCH | len cand=14 orig=96; 0%match; codegen/regalloc | indirect_call |
| 376 | 0x00034668 | FUN_00034668 | MISMATCH | len cand=45 orig=48; 42%match; param-recovery | void_proto |
| 377 | 0x00034698 | FUN_00034698 | MISMATCH | len cand=60 orig=176; 0%match; codegen/regalloc | indirect_call |
| 378 | 0x00034748 | FUN_00034748 | MISMATCH | len cand=64 orig=900; 5%match; codegen/regalloc |  |
| 379 | 0x00034ad0 | FUN_00034ad0 | MISMATCH | len cand=65 orig=104; 9%match; codegen/regalloc |  |
| 380 | 0x00034b38 | FUN_00034b38 | MISMATCH | len cand=26 orig=20; 5%match; param-recovery | indirect_call,void_proto |
| 381 | 0x00034b4c | FUN_00034b4c | MISMATCH | len cand=107 orig=123; 1%match; codegen/regalloc | indirect_call |
| 382 | 0x00034bc8 | FUN_00034bc8 | MISMATCH | len cand=232 orig=196; 1%match; codegen/regalloc | indirect_call |
| 383 | 0x00034c8c | FUN_00034c8c | MISMATCH | len cand=312 orig=335; 3%match; codegen/regalloc | indirect_call |
| 384 | 0x00034ddc | FUN_00034ddc | MISMATCH | len cand=117 orig=147; 3%match; codegen/regalloc |  |
| 385 | 0x00034e70 | FUN_00034e70 | MISMATCH | len cand=161 orig=260; 3%match; codegen/regalloc | indirect_call |
| 386 | 0x00034f74 | FUN_00034f74 | MISMATCH | len cand=95 orig=107; 4%match; codegen/regalloc |  |
| 387 | 0x00034fe0 | FUN_00034fe0 | COMPILE_FAIL | E1029:Expression must be 'pointer to ...' | extraout,indirect_call |
| 388 | 0x00035030 | FUN_00035030 | MISMATCH | len cand=116 orig=199; 3%match; codegen/regalloc | indirect_call |
| 389 | 0x000350f8 | FUN_000350f8 | MISMATCH | len cand=61 orig=83; 5%match; codegen/regalloc | indirect_call |
| 390 | 0x0003514c | FUN_0003514c | MISMATCH | len cand=14 orig=27; 0%match; codegen/regalloc | indirect_call |
| 391 | 0x00035168 | FUN_00035168 | MISMATCH | len cand=46 orig=67; 2%match; codegen/regalloc |  |
| 392 | 0x000351ac | FUN_000351ac | MISMATCH | len cand=55 orig=69; 4%match; codegen/regalloc |  |
| 393 | 0x00035200 | FUN_00035200 | MISMATCH | len cand=163 orig=187; 5%match; codegen/regalloc | indirect_call |
| 394 | 0x000352bc | FUN_000352bc | MISMATCH | len cand=14 orig=48; 0%match; codegen/regalloc | indirect_call |
| 395 | 0x000352ec | FUN_000352ec | MISMATCH | len cand=132 orig=163; 2%match; codegen/regalloc | indirect_call |
| 396 | 0x00035390 | FUN_00035390 | MISMATCH | len cand=419 orig=367; 4%match; codegen/regalloc | indirect_call |
| 397 | 0x00035500 | FUN_00035500 | MISMATCH | len cand=27 orig=31; 4%match; param-recovery | indirect_call,void_proto |
| 398 | 0x00035520 | FUN_00035520 | MISMATCH | len cand=667 orig=272; 3%match; codegen/regalloc | indirect_call |
| 399 | 0x00035630 | FUN_00035630 | MISMATCH | len cand=256 orig=248; 2%match; codegen/regalloc | indirect_call |
| 400 | 0x00035728 | FUN_00035728 | MISMATCH | len cand=267 orig=204; 2%match; codegen/regalloc | indirect_call |
| 401 | 0x000357f4 | FUN_000357f4 | MISMATCH | len cand=27 orig=412; 4%match; param-recovery | indirect_call,void_proto |
| 402 | 0x00035990 | FUN_00035990 | MISMATCH | len cand=72 orig=84; 1%match; codegen/regalloc | indirect_call |
| 403 | 0x000359e4 | FUN_000359e4 | MISMATCH | len cand=70 orig=64; 3%match; codegen/regalloc | indirect_call |
| 404 | 0x00035a24 | FUN_00035a24 | MISMATCH | len cand=197 orig=283; 5%match; codegen/regalloc | indirect_call |
| 405 | 0x00035b40 | FUN_00035b40 | MISMATCH | @+0; 10%comparable-match; codegen/regalloc | indirect_call |
| 406 | 0x00035bd4 | FUN_00035bd4 | MISMATCH | len cand=107 orig=132; 1%match; codegen/regalloc | indirect_call |
| 407 | 0x00035c58 | FUN_00035c58 | MISMATCH | len cand=167 orig=235; 2%match; codegen/regalloc | indirect_call |
| 408 | 0x00035d44 | FUN_00035d44 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call |
| 409 | 0x00035e84 | FUN_00035e84 | MISMATCH | len cand=72 orig=96; 3%match; codegen/regalloc | indirect_call |
| 410 | 0x00035ee4 | FUN_00035ee4 | MISMATCH | len cand=72 orig=431; 3%match; codegen/regalloc | indirect_call |
| 411 | 0x000360a0 | FUN_000360a0 | MISMATCH | len cand=519 orig=347; 7%match; codegen/regalloc | indirect_call |
| 412 | 0x000361fc | FUN_000361fc | MISMATCH | len cand=435 orig=272; 4%match; codegen/regalloc | indirect_call |
| 413 | 0x0003630c | FUN_0003630c | MISMATCH | len cand=182 orig=164; 2%match; codegen/regalloc | indirect_call |
| 414 | 0x000363b0 | FUN_000363b0 | MISMATCH | len cand=90 orig=76; 1%match; codegen/regalloc | indirect_call |
| 415 | 0x000363fc | FUN_000363fc | MISMATCH | len cand=51 orig=63; 2%match; codegen/regalloc | indirect_call |
| 416 | 0x0003643c | FUN_0003643c | MISMATCH | len cand=84 orig=51; 8%match; codegen/regalloc | indirect_call |
| 417 | 0x00036470 | FUN_00036470 | MISMATCH | len cand=155 orig=124; 4%match; codegen/regalloc | indirect_call |
| 418 | 0x000364ec | FUN_000364ec | MISMATCH | len cand=119 orig=568; 10%match; codegen/regalloc | indirect_call |
| 419 | 0x00036724 | FUN_00036724 | MISMATCH | @+0; 4%comparable-match; codegen/regalloc | indirect_call |
| 420 | 0x000367a8 | FUN_000367a8 | MISMATCH | len cand=70 orig=92; 3%match; codegen/regalloc | indirect_call |
| 421 | 0x00036804 | FUN_00036804 | COMPILE_FAIL | E1045:Subscript on non-array | extraout,indirect_call |
| 422 | 0x0003693c | FUN_0003693c | MISMATCH | len cand=17 orig=23; 5%match; codegen/regalloc | indirect_call |
| 423 | 0x00036954 | FUN_00036954 | MISMATCH | len cand=23 orig=72; 4%match; codegen/regalloc | indirect_call |
| 424 | 0x0003699c | FUN_0003699c | MISMATCH | len cand=154 orig=284; 3%match; codegen/regalloc | indirect_call |
| 425 | 0x00036ab8 | FUN_00036ab8 | MISMATCH | len cand=153 orig=119; 3%match; codegen/regalloc | indirect_call |
| 426 | 0x00036b30 | FUN_00036b30 | MISMATCH | len cand=303 orig=255; 4%match; codegen/regalloc | indirect_call |
| 427 | 0x00036c30 | FUN_00036c30 | MISMATCH | len cand=335 orig=379; 3%match; codegen/regalloc | indirect_call |
| 428 | 0x00036dac | FUN_00036dac | MISMATCH | len cand=136 orig=124; 5%match; codegen/regalloc | indirect_call |
| 429 | 0x00036e28 | FUN_00036e28 | MISMATCH | len cand=211 orig=159; 3%match; codegen/regalloc | indirect_call |
| 430 | 0x00036ec8 | FUN_00036ec8 | MISMATCH | len cand=31 orig=63; 3%match; codegen/regalloc | indirect_call |
| 431 | 0x00036f08 | FUN_00036f08 | MISMATCH | len cand=31 orig=409; 3%match; codegen/regalloc | indirect_call |
| 432 | 0x000370b0 | FUN_000370b0 | MISMATCH | len cand=41 orig=1291; 2%match; codegen/regalloc | indirect_call |
| 433 | 0x000375bc | FUN_000375bc | MISMATCH | len cand=200 orig=7184; 2%match; codegen/regalloc | indirect_call |
| 434 | 0x000391cc | FUN_000391cc | MISMATCH | len cand=4 orig=72; 0%match; param-recovery | void_proto |
| 435 | 0x00039214 | FUN_00039214 | MISMATCH | len cand=4 orig=1664; 0%match; param-recovery | void_proto |
| 436 | 0x000398a0 | FUN_000398a0 | MISMATCH | len cand=17 orig=715; 0%match; codegen/regalloc |  |
| 437 | 0x00039b6c | FUN_00039b6c | MISMATCH | len cand=131 orig=8191; 3%match; codegen/regalloc | indirect_call |
| 438 | 0x0003ca30 | FUN_0003ca30 | MISMATCH | len cand=14 orig=24; 6%match; codegen/regalloc | indirect_call |
| 439 | 0x0003ca48 | FUN_0003ca48 | MISMATCH | len cand=16 orig=180; 6%match; codegen/regalloc |  |
| 440 | 0x0003cafc | FUN_0003cafc | MISMATCH | len cand=292 orig=256; 2%match; codegen/regalloc | indirect_call |
| 441 | 0x0003cbfc | FUN_0003cbfc | COMPILE_FAIL | E1052:Expression has void type | indirect_call |
| 442 | 0x0003cccc | FUN_0003cccc | MISMATCH | len cand=58 orig=603; 2%match; codegen/regalloc | indirect_call |
| 443 | 0x0003cf28 | FUN_0003cf28 | MISMATCH | len cand=189 orig=423; 3%match; codegen/regalloc | indirect_call |
| 444 | 0x0003d0d0 | FUN_0003d0d0 | MISMATCH | len cand=108 orig=264; 6%match; codegen/regalloc | indirect_call |
| 445 | 0x0003d1d8 | FUN_0003d1d8 | MISMATCH | len cand=87 orig=480; 0%match; codegen/regalloc | indirect_call |
| 446 | 0x0003d3b8 | FUN_0003d3b8 | MISMATCH | len cand=50 orig=511; 2%match; codegen/regalloc | indirect_call |
| 447 | 0x0003d5b8 | FUN_0003d5b8 | MISMATCH | len cand=14 orig=12; 17%match; param-recovery | void_proto |
| 448 | 0x0003d5c4 | FUN_0003d5c4 | MISMATCH | len cand=14 orig=12; 17%match; param-recovery | void_proto |
| 449 | 0x0003d5d0 | FUN_0003d5d0 | MISMATCH | len cand=98 orig=127; 0%match; codegen/regalloc |  |
| 450 | 0x0003d650 | FUN_0003d650 | MISMATCH | len cand=59 orig=100; 3%match; codegen/regalloc |  |
| 451 | 0x0003d6b4 | FUN_0003d6b4 | MISMATCH | len cand=121 orig=235; 2%match; codegen/regalloc | indirect_call |
| 452 | 0x0003d7a0 | FUN_0003d7a0 | MISMATCH | len cand=120 orig=79; 0%match; codegen/regalloc | indirect_call |
| 453 | 0x0003d7f0 | FUN_0003d7f0 | MISMATCH | len cand=68 orig=107; 0%match; codegen/regalloc |  |
| 454 | 0x0003d85c | FUN_0003d85c | COMPILE_FAIL | E1045:Subscript on non-array | indirect_call |
| 455 | 0x0003da18 | FUN_0003da18 | MISMATCH | len cand=202 orig=280; 3%match; codegen/regalloc | indirect_call |
| 456 | 0x0003db30 | FUN_0003db30 | MISMATCH | len cand=74 orig=75; 5%match; codegen/regalloc | indirect_call |
| 457 | 0x0003db7c | FUN_0003db7c | MISMATCH | len cand=444 orig=401; 3%match; codegen/regalloc | indirect_call |
| 458 | 0x0003dd10 | FUN_0003dd10 | MISMATCH | len cand=64 orig=80; 25%match; codegen/regalloc |  |
| 459 | 0x0003dd60 | FUN_0003dd60 | MISMATCH | len cand=18 orig=728; 6%match; codegen/regalloc |  |
| 460 | 0x0003e038 | FUN_0003e038 | MISMATCH | len cand=74 orig=92; 1%match; codegen/regalloc |  |
| 461 | 0x0003e094 | FUN_0003e094 | MISMATCH | len cand=24 orig=191; 21%match; codegen/regalloc |  |
| 462 | 0x0003e154 | FUN_0003e154 | MISMATCH | len cand=145 orig=140; 4%match; codegen/regalloc | indirect_call |
| 463 | 0x0003e1e0 | FUN_0003e1e0 | MISMATCH | len cand=18 orig=12; 8%match; param-recovery | indirect_call,void_proto |
| 464 | 0x0003e1ec | FUN_0003e1ec | MISMATCH | len cand=18 orig=12; 8%match; param-recovery | indirect_call,void_proto |
| 465 | 0x0003e1f8 | FUN_0003e1f8 | MISMATCH | len cand=19 orig=136; 5%match; codegen/regalloc |  |
| 466 | 0x0003e280 | FUN_0003e280 | MISMATCH | len cand=11 orig=64; 9%match; codegen/regalloc |  |
| 467 | 0x0003e2c0 | FUN_0003e2c0 | MISMATCH | len cand=125 orig=83; 2%match; codegen/regalloc | indirect_call |
| 468 | 0x0003e314 | FUN_0003e314 | MISMATCH | len cand=23 orig=159; 4%match; codegen/regalloc | indirect_call |
| 469 | 0x0003e3b4 | FUN_0003e3b4 | MISMATCH | len cand=16 orig=702; 6%match; codegen/regalloc |  |
| 470 | 0x0003e680 | FUN_0003e680 | MISMATCH | len cand=14 orig=15; 7%match; param-recovery | void_proto |
| 471 | 0x0003e690 | FUN_0003e690 | MISMATCH | len cand=4 orig=79; 0%match; param-recovery | void_proto |
| 472 | 0x0003e6e0 | FUN_0003e6e0 | MISMATCH | len cand=74 orig=192; 1%match; reg-artifact | extraout,indirect_call |
| 473 | 0x0003e7a0 | FUN_0003e7a0 | MISMATCH | len cand=103 orig=76; 5%match; reg-artifact | extraout,indirect_call |
| 474 | 0x0003e7ec | FUN_0003e7ec | MISMATCH | len cand=60 orig=47; 4%match; codegen/regalloc | indirect_call |
| 475 | 0x0003e81c | FUN_0003e81c | MISMATCH | len cand=36 orig=59; 2%match; codegen/regalloc | indirect_call |
| 476 | 0x0003e858 | FUN_0003e858 | MISMATCH | len cand=83 orig=63; 3%match; codegen/regalloc | indirect_call |
| 477 | 0x0003e898 | FUN_0003e898 | MISMATCH | len cand=101 orig=524; 3%match; codegen/regalloc | indirect_call |
| 478 | 0x0003eaa4 | FUN_0003eaa4 | MISMATCH | len cand=128 orig=83; 4%match; codegen/regalloc | indirect_call |
| 479 | 0x0003eaf8 | FUN_0003eaf8 | MISMATCH | len cand=55 orig=984; 2%match; codegen/regalloc | indirect_call |
| 480 | 0x0003eed0 | FUN_0003eed0 | MISMATCH | len cand=101 orig=88; 6%match; codegen/regalloc | indirect_call |
| 481 | 0x0003ef28 | FUN_0003ef28 | MISMATCH | len cand=68 orig=56; 4%match; codegen/regalloc | indirect_call |
| 482 | 0x0003ef60 | FUN_0003ef60 | MISMATCH | len cand=52 orig=48; 0%match; codegen/regalloc | indirect_call |
| 483 | 0x0003ef90 | FUN_0003ef90 | COMPILE_FAIL | E1029:Expression must be 'pointer to ...' | indirect_call |
| 484 | 0x0003f0c0 | FUN_0003f0c0 | MISMATCH | len cand=243 orig=299; 3%match; codegen/regalloc | indirect_call |
| 485 | 0x0003f1ec | FUN_0003f1ec | MISMATCH | len cand=53 orig=1527; 4%match; codegen/regalloc | indirect_call |
| 486 | 0x0003f7e4 | FUN_0003f7e4 | MISMATCH | len cand=93 orig=543; 14%match; codegen/regalloc |  |
| 487 | 0x0003fa04 | FUN_0003fa04 | MISMATCH | len cand=46 orig=96; 10%match; codegen/regalloc | indirect_call |
| 488 | 0x0003fa64 | FUN_0003fa64 | MISMATCH | len cand=41 orig=1851; 4%match; codegen/regalloc | indirect_call |
| 489 | 0x000401a0 | FUN_000401a0 | MISMATCH | len cand=16 orig=523; 6%match; codegen/regalloc |  |
| 490 | 0x000403ac | FUN_000403ac | MISMATCH | len cand=147 orig=311; 2%match; codegen/regalloc | indirect_call |
| 491 | 0x000404e4 | FUN_000404e4 | MISMATCH | len cand=199 orig=268; 3%match; codegen/regalloc | indirect_call |
| 492 | 0x000405f0 | FUN_000405f0 | MISMATCH | len cand=149 orig=171; 3%match; codegen/regalloc | indirect_call |
| 493 | 0x0004069c | FUN_0004069c | MISMATCH | len cand=172 orig=123; 2%match; codegen/regalloc | indirect_call |
| 494 | 0x00040718 | FUN_00040718 | MISMATCH | len cand=77 orig=152; 4%match; codegen/regalloc | indirect_call |
| 495 | 0x000407b8 | FUN_000407b8 | MISMATCH | len cand=198 orig=184; 16%match; codegen/regalloc |  |
| 496 | 0x00040870 | FUN_00040870 | MISMATCH | len cand=50 orig=176; 2%match; codegen/regalloc | indirect_call |
| 497 | 0x00040920 | FUN_00040920 | MISMATCH | len cand=45 orig=123; 4%match; codegen/regalloc |  |
| 498 | 0x0004099c | FUN_0004099c | MISMATCH | len cand=496 orig=599; 1%match; codegen/regalloc |  |
| 499 | 0x00040bf4 | FUN_00040bf4 | COMPILE_FAIL | E1010:Type mismatch |  |
| 500 | 0x00040e6c | FUN_00040e6c | COMPILE_FAIL | E1063:Missing operand | ellipsis,raw_marker |
| 501 | 0x00040f40 | FUN_00040f40 | MISMATCH | len cand=785 orig=543; 1%match; codegen/regalloc | indirect_call |
| 502 | 0x00041160 | FUN_00041160 | MISMATCH | len cand=622 orig=239; 1%match; codegen/regalloc |  |
| 503 | 0x00041250 | FUN_00041250 | MISMATCH | len cand=57 orig=63; 19%match; codegen/regalloc |  |
| 504 | 0x00041290 | FUN_00041290 | MISMATCH | len cand=102 orig=211; 4%match; codegen/regalloc | indirect_call |
| 505 | 0x00041364 | FUN_00041364 | COMPILE_FAIL | E1081:Expression must be scalar type | indirect_call |
| 506 | 0x00041808 | FUN_00041808 | MISMATCH | len cand=263 orig=503; 1%match; codegen/regalloc | indirect_call |
| 507 | 0x00041a00 | FUN_00041a00 | MISMATCH | len cand=10 orig=19; 10%match; codegen/regalloc |  |
| 508 | 0x00041a14 | FUN_00041a14 | MISMATCH | len cand=70 orig=88; 1%match; codegen/regalloc | indirect_call |
| 509 | 0x00041a6c | FUN_00041a6c | MISMATCH | len cand=30 orig=79; 7%match; codegen/regalloc |  |
| 510 | 0x00041abc | FUN_00041abc | MISMATCH | len cand=432 orig=623; 2%match; codegen/regalloc | indirect_call |
| 511 | 0x00041d2c | FUN_00041d2c | MISMATCH | len cand=154 orig=276; 1%match; codegen/regalloc | indirect_call |
| 512 | 0x00041e40 | FUN_00041e40 | MISMATCH | len cand=291 orig=435; 2%match; codegen/regalloc | indirect_call |
| 513 | 0x00041ff4 | FUN_00041ff4 | MISMATCH | len cand=266 orig=251; 1%match; codegen/regalloc | indirect_call |
| 514 | 0x000420f0 | FUN_000420f0 | MISMATCH | len cand=70 orig=272; 1%match; codegen/regalloc | indirect_call |
| 515 | 0x00042200 | FUN_00042200 | MISMATCH | len cand=90 orig=107; 3%match; codegen/regalloc | indirect_call |
| 516 | 0x0004226c | FUN_0004226c | MISMATCH | len cand=7 orig=76; 0%match; codegen/regalloc |  |
| 517 | 0x000422b8 | FUN_000422b8 | MISMATCH | len cand=7 orig=71; 0%match; codegen/regalloc |  |
| 518 | 0x00042300 | FUN_00042300 | MISMATCH | len cand=27 orig=347; 4%match; codegen/regalloc |  |
| 519 | 0x0004245c | FUN_0004245c | MISMATCH | len cand=190 orig=212; 11%match; codegen/regalloc | indirect_call |
| 520 | 0x00042530 | FUN_00042530 | MISMATCH | len cand=24 orig=107; 8%match; codegen/regalloc |  |
| 521 | 0x0004259c | FUN_0004259c | MISMATCH | len cand=384 orig=435; 2%match; codegen/regalloc | indirect_call |
| 522 | 0x00042750 | FUN_00042750 | MISMATCH | len cand=56 orig=343; 7%match; codegen/regalloc | indirect_call |
| 523 | 0x000428a8 | FUN_000428a8 | MISMATCH | len cand=123 orig=295; 2%match; codegen/regalloc | indirect_call |
| 524 | 0x000429d0 | FUN_000429d0 | MISMATCH | len cand=827 orig=1195; 2%match; reg-artifact | extraout,indirect_call |
| 525 | 0x00042e7c | FUN_00042e7c | MISMATCH | len cand=52 orig=103; 4%match; codegen/regalloc | indirect_call |
| 526 | 0x00042ee4 | FUN_00042ee4 | MISMATCH | len cand=33 orig=156; 0%match; codegen/regalloc | indirect_call |
| 527 | 0x00042f80 | FUN_00042f80 | MISMATCH | len cand=164 orig=196; 1%match; codegen/regalloc | indirect_call |
| 528 | 0x00043044 | FUN_00043044 | MISMATCH | len cand=365 orig=511; 2%match; codegen/regalloc | indirect_call |
| 529 | 0x00043244 | FUN_00043244 | COMPILE_FAIL | E1052:Expression has void type | indirect_call |
| 530 | 0x00043514 | FUN_00043514 | MISMATCH | len cand=13 orig=99; 15%match; codegen/regalloc |  |
| 531 | 0x00043578 | FUN_00043578 | MISMATCH | len cand=105 orig=296; 2%match; codegen/regalloc | indirect_call |
| 532 | 0x000436a0 | FUN_000436a0 | MISMATCH | len cand=140 orig=155; 3%match; reg-artifact | extraout,indirect_call |
| 533 | 0x0004373c | FUN_0004373c | MISMATCH | len cand=36 orig=35; 0%match; codegen/regalloc |  |
| 534 | 0x00043760 | FUN_00043760 | MISMATCH | len cand=90 orig=116; 1%match; codegen/regalloc | indirect_call |
| 535 | 0x000437d4 | FUN_000437d4 | MISMATCH | len cand=123 orig=219; 2%match; codegen/regalloc | indirect_call |
| 536 | 0x000438b0 | FUN_000438b0 | MISMATCH | len cand=29 orig=99; 7%match; codegen/regalloc |  |
| 537 | 0x00043914 | FUN_00043914 | MISMATCH | len cand=7 orig=83; 0%match; codegen/regalloc |  |
| 538 | 0x00043968 | FUN_00043968 | MISMATCH | len cand=96 orig=1139; 10%match; codegen/regalloc |  |
| 539 | 0x00043ddc | FUN_00043ddc | MISMATCH | len cand=7 orig=36; 0%match; codegen/regalloc |  |
| 540 | 0x00043e00 | FUN_00043e00 | MISMATCH | len cand=145 orig=260; 4%match; reg-artifact | extraout,indirect_call |
| 541 | 0x00043f04 | FUN_00043f04 | COMPILE_FAIL | E1018:Label 'LAB_00043f3a' not defined in function | indirect_call |
| 542 | 0x00043f74 | FUN_00043f74 | MISMATCH | len cand=94 orig=112; 1%match; codegen/regalloc |  |
| 543 | 0x00043fe4 | FUN_00043fe4 | MISMATCH | len cand=114 orig=115; 2%match; codegen/regalloc |  |
| 544 | 0x00044058 | FUN_00044058 | MISMATCH | len cand=54 orig=67; 3%match; codegen/regalloc | indirect_call |
| 545 | 0x0004409c | FUN_0004409c | MISMATCH | len cand=174 orig=248; 3%match; codegen/regalloc | indirect_call |
| 546 | 0x00044194 | FUN_00044194 | MISMATCH | len cand=90 orig=87; 2%match; codegen/regalloc | indirect_call |
| 547 | 0x000441ec | FUN_000441ec | MISMATCH | len cand=123 orig=315; 0%match; codegen/regalloc | indirect_call |
| 548 | 0x00044328 | FUN_00044328 | MISMATCH | len cand=619 orig=815; 1%match; codegen/regalloc | indirect_call |
| 549 | 0x00044658 | FUN_00044658 | MISMATCH | len cand=32 orig=103; 9%match; codegen/regalloc |  |
| 550 | 0x000446c0 | FUN_000446c0 | MISMATCH | len cand=111 orig=186; 1%match; codegen/regalloc | indirect_call |
| 551 | 0x0004477c | FUN_0004477c | MISMATCH | len cand=133 orig=275; 3%match; codegen/regalloc | indirect_call |
| 552 | 0x00044890 | FUN_00044890 | MISMATCH | len cand=9 orig=35; 0%match; param-recovery | void_proto |
| 553 | 0x000448b4 | FUN_000448b4 | MISMATCH | len cand=65 orig=180; 3%match; codegen/regalloc |  |
| 554 | 0x00044968 | FUN_00044968 | MISMATCH | len cand=117 orig=111; 0%match; codegen/regalloc | indirect_call |
| 555 | 0x000449d8 | FUN_000449d8 | MISMATCH | len cand=4 orig=44; 0%match; codegen/regalloc |  |
| 556 | 0x00044a04 | FUN_00044a04 | COMPILE_FAIL | E1010:Type mismatch | indirect_call |
| 557 | 0x0004501c | FUN_0004501c | MISMATCH | len cand=68 orig=272; 0%match; codegen/regalloc |  |
| 558 | 0x0004512c | FUN_0004512c | MISMATCH | len cand=169 orig=236; 4%match; codegen/regalloc | indirect_call |
| 559 | 0x00045218 | FUN_00045218 | MISMATCH | len cand=39 orig=143; 3%match; param-recovery | indirect_call,void_proto |
| 560 | 0x000452a8 | FUN_000452a8 | MISMATCH | len cand=50 orig=83; 0%match; codegen/regalloc | indirect_call |
| 561 | 0x000452fc | FUN_000452fc | MISMATCH | len cand=372 orig=343; 2%match; codegen/regalloc | indirect_call |
| 562 | 0x00045454 | FUN_00045454 | MISMATCH | len cand=10 orig=111; 10%match; codegen/regalloc |  |
| 563 | 0x000454c4 | FUN_000454c4 | MISMATCH | len cand=60 orig=224; 2%match; codegen/regalloc | indirect_call |
| 564 | 0x000455a4 | FUN_000455a4 | MISMATCH | len cand=194 orig=191; 2%match; codegen/regalloc | indirect_call |
| 565 | 0x00045664 | FUN_00045664 | MISMATCH | len cand=136 orig=164; 0%match; reg-artifact | extraout,indirect_call |
| 566 | 0x00045708 | FUN_00045708 | MISMATCH | len cand=31 orig=368; 3%match; codegen/regalloc | indirect_call |
| 567 | 0x00045878 | FUN_00045878 | MISMATCH | len cand=110 orig=3027; 5%match; codegen/regalloc |  |
| 568 | 0x0004644c | FUN_0004644c | MISMATCH | len cand=40 orig=464; 0%match; codegen/regalloc |  |
| 569 | 0x0004661c | FUN_0004661c | MISMATCH | len cand=194 orig=392; 4%match; codegen/regalloc | indirect_call |
| 570 | 0x000467a4 | FUN_000467a4 | MISMATCH | len cand=91 orig=927; 1%match; codegen/regalloc |  |
| 571 | 0x00046b44 | FUN_00046b44 | MISMATCH | len cand=31 orig=24; 4%match; codegen/regalloc |  |
| 572 | 0x00046b5c | FUN_00046b5c | MISMATCH | len cand=73 orig=88; 5%match; codegen/regalloc |  |
| 573 | 0x00046bb4 | FUN_00046bb4 | MISMATCH | len cand=161 orig=200; 3%match; codegen/regalloc | indirect_call |
| 574 | 0x00046c7c | FUN_00046c7c | MISMATCH | len cand=86 orig=95; 4%match; reg-artifact | extraout,indirect_call |
| 575 | 0x00046cdc | FUN_00046cdc | MISMATCH | len cand=125 orig=275; 6%match; codegen/regalloc | indirect_call |
| 576 | 0x00046df0 | FUN_00046df0 | MISMATCH | len cand=67 orig=51; 6%match; codegen/regalloc | indirect_call |
| 577 | 0x00046e24 | FUN_00046e24 | MISMATCH | len cand=35 orig=5364; 3%match; codegen/regalloc |  |
| 578 | 0x00048318 | FUN_00048318 | MISMATCH | len cand=129 orig=145; 4%match; codegen/regalloc | indirect_call |
| 579 | 0x000483b0 | FUN_000483b0 | MISMATCH | len cand=114 orig=200; 1%match; codegen/regalloc | indirect_call |
| 580 | 0x00048478 | FUN_00048478 | MISMATCH | len cand=18 orig=4903; 6%match; param-recovery | indirect_call,void_proto |
| 581 | 0x000497a0 | FUN_000497a0 | MISMATCH | len cand=139 orig=2480; 2%match; codegen/regalloc | indirect_call |
| 582 | 0x0004a150 | FUN_0004a150 | MISMATCH | len cand=103 orig=68; 3%match; codegen/regalloc | indirect_call |
| 583 | 0x0004a194 | FUN_0004a194 | MISMATCH | len cand=82 orig=520; 2%match; codegen/regalloc | indirect_call |
| 584 | 0x0004a39c | FUN_0004a39c | MISMATCH | len cand=96 orig=111; 2%match; codegen/regalloc | indirect_call |
| 585 | 0x0004a40c | FUN_0004a40c | MISMATCH | len cand=135 orig=124; 2%match; codegen/regalloc | indirect_call |
| 586 | 0x0004a488 | FUN_0004a488 | MISMATCH | len cand=29 orig=132; 3%match; codegen/regalloc | indirect_call |
| 587 | 0x0004a50c | FUN_0004a50c | MISMATCH | len cand=69 orig=79; 4%match; reg-artifact | extraout,indirect_call |
| 588 | 0x0004a55c | FUN_0004a55c | MISMATCH | len cand=72 orig=5791; 4%match; reg-artifact | extraout,indirect_call |
| 589 | 0x0004bbfc | FUN_0004bbfc | MISMATCH | len cand=14 orig=1896; 6%match; codegen/regalloc | indirect_call |
| 590 | 0x0004c364 | FUN_0004c364 | MISMATCH | len cand=51 orig=524; 4%match; codegen/regalloc | indirect_call |
| 591 | 0x0004c570 | FUN_0004c570 | MISMATCH | len cand=29 orig=282; 3%match; codegen/regalloc | indirect_call |
| 592 | 0x0004c690 | FUN_0004c690 | MISMATCH | len cand=14 orig=682; 7%match; param-recovery | void_proto |
| 593 | 0x0004c940 | FUN_0004c940 | MISMATCH | len cand=61 orig=56; 2%match; codegen/regalloc | indirect_call |
| 594 | 0x0004c978 | FUN_0004c978 | MISMATCH | len cand=274 orig=273; 3%match; codegen/regalloc | indirect_call |
| 595 | 0x0004ca90 | FUN_0004ca90 | MISMATCH | len cand=84 orig=251; 0%match; codegen/regalloc | indirect_call |
| 596 | 0x0004cb8c | FUN_0004cb8c | MISMATCH | len cand=168 orig=311; 3%match; codegen/regalloc | indirect_call |
| 597 | 0x0004ccc4 | FUN_0004ccc4 | MISMATCH | len cand=210 orig=359; 2%match; codegen/regalloc | indirect_call |
| 598 | 0x0004ce2c | FUN_0004ce2c | MISMATCH | len cand=39 orig=716; 8%match; codegen/regalloc | indirect_call |
| 599 | 0x0004d0f8 | FUN_0004d0f8 | COMPILE_FAIL | E1052:Expression has void type | indirect_call |
| 600 | 0x0004d1f0 | FUN_0004d1f0 | MISMATCH | @+0; 7%comparable-match; codegen/regalloc | indirect_call |
| 601 | 0x0004d270 | FUN_0004d270 | MISMATCH | len cand=283 orig=267; 6%match; codegen/regalloc | indirect_call |
| 602 | 0x0004d37c | FUN_0004d37c | MISMATCH | len cand=4 orig=259; 0%match; param-recovery | void_proto |
| 603 | 0x0004d480 | FUN_0004d480 | COMPILE_FAIL | E1029:Expression must be 'pointer to ...' | indirect_call |
| 604 | 0x0004d4c0 | FUN_0004d4c0 | COMPILE_FAIL | E1029:Expression must be 'pointer to ...' | indirect_call |
| 605 | 0x0004d4e8 | FUN_0004d4e8 | COMPILE_FAIL | E1029:Expression must be 'pointer to ...' | indirect_call |
| 606 | 0x0004d508 | FUN_0004d508 | MISMATCH | len cand=31 orig=32; 3%match; codegen/regalloc | indirect_call |
| 607 | 0x0004d528 | FUN_0004d528 | MISMATCH | len cand=4 orig=28; 0%match; param-recovery | void_proto |
| 608 | 0x0004d544 | FUN_0004d544 | COMPILE_FAIL | E1079:Expression must be integral | extraout,indirect_call |
| 609 | 0x0004d6e0 | FUN_0004d6e0 | MISMATCH | len cand=71 orig=51; 6%match; codegen/regalloc | indirect_call |
| 610 | 0x0004d714 | FUN_0004d714 | MISMATCH | len cand=40 orig=127; 2%match; codegen/regalloc | indirect_call |
| 611 | 0x0004d794 | FUN_0004d794 | MISMATCH | len cand=360 orig=329; 4%match; codegen/regalloc | indirect_call |
| 612 | 0x0004d8e0 | FUN_0004d8e0 | MISMATCH | len cand=12 orig=399; 8%match; param-recovery | void_proto |
| 613 | 0x0004da70 | FUN_0004da70 | MISMATCH | len cand=45 orig=139; 4%match; codegen/regalloc | indirect_call |
| 614 | 0x0004dafc | FUN_0004dafc | MISMATCH | len cand=81 orig=151; 5%match; codegen/regalloc | indirect_call |
| 615 | 0x0004db94 | FUN_0004db94 | MISMATCH | len cand=54 orig=119; 5%match; codegen/regalloc | indirect_call |
| 616 | 0x0004dc0c | FUN_0004dc0c | MISMATCH | len cand=49 orig=87; 6%match; codegen/regalloc | indirect_call |
| 617 | 0x0004dc64 | FUN_0004dc64 | MISMATCH | len cand=43 orig=111; 4%match; codegen/regalloc | indirect_call |
| 618 | 0x0004dcd4 | FUN_0004dcd4 | MISMATCH | len cand=54 orig=99; 5%match; codegen/regalloc | indirect_call |
| 619 | 0x0004dd38 | FUN_0004dd38 | MISMATCH | len cand=71 orig=152; 11%match; codegen/regalloc | indirect_call |
| 620 | 0x0004ddd0 | FUN_0004ddd0 | MISMATCH | len cand=112 orig=239; 6%match; codegen/regalloc | indirect_call |
| 621 | 0x0004debf | FUN_0004debf | COMPILE_FAIL | E1052:Expression has void type | extraout,indirect_call,void_proto |
| 622 | 0x0004dee0 | FUN_0004dee0 | MISMATCH | len cand=49 orig=33; 0%match; param-recovery | indirect_call,void_proto |
| 623 | 0x0004df01 | FUN_0004df01 | COMPILE_FAIL | E1029:Expression must be 'pointer to ...' | indirect_call,void_proto |
| 624 | 0x0004df86 | FUN_0004df86 | MISMATCH | len cand=26 orig=44; 0%match; param-recovery | indirect_call,void_proto |
| 625 | 0x0004dfb2 | FUN_0004dfb2 | MISMATCH | len cand=78 orig=105; 1%match; param-recovery | indirect_call,void_proto |
| 626 | 0x0004e01b | FUN_0004e01b | MISMATCH | len cand=78 orig=37; 0%match; param-recovery | indirect_call,void_proto |
| 627 | 0x0004e040 | FUN_0004e040 | MISMATCH | len cand=34 orig=23; 4%match; param-recovery | indirect_call,void_proto |
| 628 | 0x0004e057 | FUN_0004e057 | MISMATCH | len cand=34 orig=1492; 3%match; param-recovery | indirect_call,void_proto |
| 629 | 0x0004e62b | FUN_0004e62b | MISMATCH | len cand=92 orig=76; 4%match; param-recovery | indirect_call,void_proto |
| 630 | 0x0004e677 | FUN_0004e677 | COMPILE_FAIL | E1052:Expression has void type | indirect_call,void_proto |
| 631 | 0x0004e820 | FUN_0004e820 | MISMATCH | len cand=1 orig=4; 0%match; param-recovery | void_proto |
| 632 | 0x0004e830 | FUN_0004e830 | MISMATCH | len cand=35 orig=30; 7%match; param-recovery | indirect_call,void_proto |
| 633 | 0x0004e850 | FUN_0004e850 | MISMATCH | len cand=138 orig=98; 5%match; codegen/regalloc | indirect_call |
| 634 | 0x0004e8c0 | FUN_0004e8c0 | MISMATCH | len cand=215 orig=173; 2%match; codegen/regalloc | indirect_call |
| 635 | 0x0004e970 | FUN_0004e970 | MISMATCH | len cand=25 orig=108; 3%match; codegen/regalloc |  |
| 636 | 0x0004e9e0 | FUN_0004e9e0 | MISMATCH | len cand=172 orig=145; 4%match; param-recovery | indirect_call,void_proto |
| 637 | 0x0004ea80 | FUN_0004ea80 | MISMATCH | len cand=100 orig=88; 3%match; param-recovery | indirect_call,void_proto |
| 638 | 0x0004eae0 | FUN_0004eae0 | MISMATCH | len cand=783 orig=656; 7%match; param-recovery | indirect_call,void_proto |
| 639 | 0x0004ed70 | FUN_0004ed70 | MISMATCH | len cand=292 orig=280; 8%match; param-recovery | indirect_call,void_proto |
| 640 | 0x0004ee90 | FUN_0004ee90 | MISMATCH | len cand=212 orig=168; 10%match; codegen/regalloc | indirect_call |
| 641 | 0x0004ef40 | FUN_0004ef40 | MISMATCH | len cand=44 orig=165; 7%match; param-recovery | indirect_call,void_proto |
| 642 | 0x0004eff0 | FUN_0004eff0 | MISMATCH | len cand=80 orig=64; 3%match; param-recovery | indirect_call,void_proto |
| 643 | 0x0004f030 | FUN_0004f030 | MISMATCH | len cand=236 orig=173; 1%match; param-recovery | indirect_call,void_proto |
| 644 | 0x0004f0e0 | FUN_0004f0e0 | MISMATCH | len cand=1 orig=16; 0%match; param-recovery | void_proto |
| 645 | 0x0004f0f0 | FUN_0004f0f0 | MISMATCH | len cand=62 orig=58; 14%match; codegen/regalloc |  |
| 646 | 0x0004f130 | FUN_0004f130 | MISMATCH | len cand=172 orig=183; 4%match; codegen/regalloc | indirect_call |
| 647 | 0x0004f1e8 | FUN_0004f1e8 | MISMATCH | len cand=300 orig=240; 5%match; codegen/regalloc | indirect_call |
| 648 | 0x0004f2d8 | FUN_0004f2d8 | MISMATCH | len cand=20 orig=36; 4%match; codegen/regalloc | indirect_call |
| 649 | 0x0004f2fc | FUN_0004f2fc | MISMATCH | len cand=30 orig=80; 3%match; codegen/regalloc | indirect_call |
| 650 | 0x0004f34c | FUN_0004f34c | MISMATCH | len cand=28 orig=39; 4%match; codegen/regalloc | indirect_call |
| 651 | 0x0004f374 | FUN_0004f374 | MISMATCH | len cand=81 orig=92; 9%match; codegen/regalloc | indirect_call |
| 652 | 0x0004f3d0 | FUN_0004f3d0 | MISMATCH | len cand=36 orig=55; 8%match; codegen/regalloc |  |
| 653 | 0x0004f408 | FUN_0004f408 | MISMATCH | len cand=248 orig=219; 3%match; codegen/regalloc | indirect_call |
| 654 | 0x0004f4e4 | FUN_0004f4e4 | MISMATCH | len cand=115 orig=155; 3%match; codegen/regalloc | indirect_call |
| 655 | 0x0004f580 | FUN_0004f580 | MISMATCH | len cand=93 orig=96; 3%match; codegen/regalloc | indirect_call |
| 656 | 0x0004f5e0 | FUN_0004f5e0 | COMPILE_FAIL | E1079:Expression must be integral |  |
| 657 | 0x0004f6d4 | FUN_0004f6d4 | MISMATCH | len cand=436 orig=396; 2%match; codegen/regalloc | indirect_call |
| 658 | 0x0004f860 | FUN_0004f860 | MISMATCH | len cand=95 orig=135; 5%match; codegen/regalloc | indirect_call |
| 659 | 0x0004f8e8 | FUN_0004f8e8 | MISMATCH | len cand=85 orig=144; 4%match; codegen/regalloc | indirect_call |
| 660 | 0x0004f978 | FUN_0004f978 | MISMATCH | len cand=156 orig=171; 4%match; codegen/regalloc | indirect_call |
| 661 | 0x0004fa24 | FUN_0004fa24 | MISMATCH | len cand=129 orig=163; 5%match; codegen/regalloc | indirect_call |
| 662 | 0x0004fac8 | FUN_0004fac8 | MISMATCH | len cand=156 orig=165; 2%match; codegen/regalloc | indirect_call |
| 663 | 0x0004fb70 | FUN_0004fb70 | MISMATCH | len cand=18 orig=12; 8%match; param-recovery | indirect_call,void_proto |
| 664 | 0x0004fb7c | FUN_0004fb7c | MISMATCH | len cand=56 orig=79; 4%match; codegen/regalloc | indirect_call |
| 665 | 0x0004fbcc | FUN_0004fbcc | MISMATCH | len cand=171 orig=252; 2%match; codegen/regalloc | indirect_call |
| 666 | 0x0004fcc8 | FUN_0004fcc8 | MISMATCH | len cand=105 orig=151; 1%match; codegen/regalloc | indirect_call |
| 667 | 0x0004fd60 | FUN_0004fd60 | MISMATCH | len cand=4 orig=136; 0%match; param-recovery | void_proto |
| 668 | 0x0004fde8 | FUN_0004fde8 | MISMATCH | len cand=130 orig=123; 1%match; codegen/regalloc |  |
| 669 | 0x0004fe64 | FUN_0004fe64 | MISMATCH | len cand=103 orig=131; 1%match; codegen/regalloc |  |
| 670 | 0x0004fee8 | FUN_0004fee8 | MISMATCH | len cand=181 orig=300; 3%match; reg-artifact | extraout,indirect_call |
| 671 | 0x00050014 | FUN_00050014 | MISMATCH | len cand=31 orig=243; 3%match; codegen/regalloc | indirect_call |
| 672 | 0x00050108 | FUN_00050108 | MISMATCH | len cand=444 orig=882; 2%match; codegen/regalloc | indirect_call |
| 673 | 0x00050480 | FUN_00050480 | MISMATCH | len cand=14 orig=43; 0%match; codegen/regalloc | indirect_call |
| 674 | 0x000504ac | FUN_000504ac | MISMATCH | len cand=59 orig=63; 2%match; codegen/regalloc |  |
| 675 | 0x000504ec | FUN_000504ec | COMPILE_FAIL | E1029:Expression must be 'pointer to ...' |  |
| 676 | 0x00050564 | FUN_00050564 | MISMATCH | len cand=64 orig=75; 0%match; codegen/regalloc | indirect_call |
| 677 | 0x000505b0 | FUN_000505b0 | MISMATCH | len cand=16 orig=84; 19%match; codegen/regalloc |  |
| 678 | 0x00050604 | FUN_00050604 | COMPILE_FAIL | E1029:Expression must be 'pointer to ...' | indirect_call |
| 679 | 0x00050704 | FUN_00050704 | MISMATCH | @+0; 4%comparable-match; codegen/regalloc | indirect_call |
| 680 | 0x000507d4 | FUN_000507d4 | COMPILE_FAIL | E1029:Expression must be 'pointer to ...' | indirect_call |
| 681 | 0x00050874 | FUN_00050874 | MISMATCH | len cand=153 orig=156; 5%match; codegen/regalloc | indirect_call |
| 682 | 0x00050910 | FUN_00050910 | MISMATCH | len cand=232 orig=280; 0%match; codegen/regalloc | indirect_call |
| 683 | 0x00050a28 | FUN_00050a28 | MISMATCH | len cand=138 orig=104; 0%match; codegen/regalloc | indirect_call |
| 684 | 0x00050a90 | FUN_00050a90 | MISMATCH | len cand=56 orig=71; 7%match; codegen/regalloc | indirect_call |
| 685 | 0x00050ad8 | FUN_00050ad8 | MISMATCH | len cand=47 orig=767; 2%match; param-recovery | indirect_call,void_proto |
| 686 | 0x00050dd8 | FUN_00050dd8 | MISMATCH | len cand=79 orig=84; 1%match; codegen/regalloc | indirect_call |
| 687 | 0x00050e2c | FUN_00050e2c | MISMATCH | len cand=79 orig=84; 1%match; codegen/regalloc | indirect_call |
| 688 | 0x00050e80 | FUN_00050e80 | MISMATCH | len cand=91 orig=348; 1%match; reg-artifact | extraout,indirect_call |
| 689 | 0x00050fdc | FUN_00050fdc | MISMATCH | len cand=160 orig=215; 2%match; reg-artifact | extraout,indirect_call |
| 690 | 0x000510b4 | FUN_000510b4 | MISMATCH | len cand=93 orig=215; 1%match; codegen/regalloc | indirect_call |
| 691 | 0x0005118c | FUN_0005118c | MISMATCH | len cand=46 orig=32; 3%match; param-recovery | indirect_call,void_proto |
| 692 | 0x000511ac | FUN_000511ac | MISMATCH | len cand=207 orig=235; 1%match; codegen/regalloc | indirect_call |
| 693 | 0x00051298 | FUN_00051298 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call |
| 694 | 0x0005159c | FUN_0005159c | MISMATCH | len cand=158 orig=191; 4%match; codegen/regalloc | indirect_call |
| 695 | 0x0005165c | FUN_0005165c | MISMATCH | len cand=73 orig=84; 3%match; codegen/regalloc | indirect_call |
| 696 | 0x000516b0 | FUN_000516b0 | MISMATCH | len cand=175 orig=180; 7%match; codegen/regalloc | indirect_call |
| 697 | 0x00051764 | FUN_00051764 | MISMATCH | len cand=267 orig=276; 3%match; codegen/regalloc | indirect_call |
| 698 | 0x00051878 | FUN_00051878 | MISMATCH | len cand=219 orig=166; 2%match; codegen/regalloc | indirect_call |
| 699 | 0x0005191e | FUN_0005191e | MISMATCH | len cand=507 orig=380; 2%match; param-recovery | indirect_call,void_proto |
| 700 | 0x00051a9a | FUN_00051a9a | MISMATCH | len cand=177 orig=147; 0%match; param-recovery | indirect_call,void_proto |
| 701 | 0x00051b2d | FUN_00051b2d | MISMATCH | len cand=334 orig=248; 2%match; reg-artifact | extraout,indirect_call,void_proto |
| 702 | 0x00051c27 | FUN_00051c27 | MISMATCH | len cand=16 orig=4; 0%match; thunk |  |
| 703 | 0x00051c2c | FUN_00051c2c | MISMATCH | len cand=16 orig=4; 0%match; thunk |  |
| 704 | 0x00051c31 | FUN_00051c31 | MISMATCH | len cand=322 orig=233; 2%match; reg-artifact | extraout,indirect_call,void_proto |
| 705 | 0x00051d1c | FUN_00051d1c | MISMATCH | len cand=167 orig=259; 1%match; param-recovery | indirect_call,void_proto |
| 706 | 0x00051e1f | FUN_00051e1f | MISMATCH | len cand=155 orig=135; 1%match; param-recovery | indirect_call,void_proto |
| 707 | 0x00051ea6 | FUN_00051ea6 | MISMATCH | len cand=358 orig=278; 3%match; reg-artifact | extraout,indirect_call,void_proto |
| 708 | 0x00051fbc | FUN_00051fbc | MISMATCH | len cand=155 orig=109; 1%match; param-recovery | indirect_call,void_proto |
| 709 | 0x00052029 | FUN_00052029 | MISMATCH | len cand=10 orig=4; 0%match; thunk |  |
| 710 | 0x0005202e | FUN_0005202e | MISMATCH | len cand=1166 orig=857; 2%match; reg-artifact | extraout,indirect_call,void_proto |
| 711 | 0x00052387 | FUN_00052387 | MISMATCH | len cand=322 orig=233; 2%match; reg-artifact | extraout,indirect_call,void_proto |
| 712 | 0x00052472 | FUN_00052472 | MISMATCH | len cand=334 orig=243; 2%match; reg-artifact | extraout,indirect_call,void_proto |
| 713 | 0x00052565 | FUN_00052565 | MISMATCH | len cand=167 orig=118; 1%match; param-recovery | indirect_call,void_proto |
| 714 | 0x000525db | FUN_000525db | MISMATCH | len cand=167 orig=236; 2%match; param-recovery | indirect_call,void_proto |
| 715 | 0x000526c7 | FUN_000526c7 | MISMATCH | len cand=310 orig=220; 1%match; reg-artifact | extraout,indirect_call,void_proto |
| 716 | 0x000527a5 | FUN_000527a5 | MISMATCH | len cand=155 orig=207; 1%match; param-recovery | indirect_call,void_proto |
| 717 | 0x00052874 | FUN_00052874 | MISMATCH | len cand=155 orig=207; 1%match; param-recovery | indirect_call,void_proto |
| 718 | 0x00052943 | FUN_00052943 | MISMATCH | len cand=155 orig=109; 1%match; param-recovery | indirect_call,void_proto |
| 719 | 0x000529b0 | FUN_000529b0 | MISMATCH | len cand=140 orig=98; 0%match; param-recovery | indirect_call,void_proto |
| 720 | 0x00052a12 | FUN_00052a12 | MISMATCH | len cand=322 orig=229; 2%match; reg-artifact | extraout,indirect_call,void_proto |
| 721 | 0x00052af7 | FUN_00052af7 | MISMATCH | len cand=334 orig=243; 2%match; reg-artifact | extraout,indirect_call,void_proto |
| 722 | 0x00052bea | FUN_00052bea | MISMATCH | len cand=155 orig=109; 1%match; param-recovery | indirect_call,void_proto |
| 723 | 0x00052c57 | FUN_00052c57 | MISMATCH | len cand=322 orig=241; 2%match; reg-artifact | extraout,indirect_call,void_proto |
| 724 | 0x00052d48 | FUN_00052d48 | MISMATCH | len cand=334 orig=346; 3%match; reg-artifact | extraout,indirect_call,void_proto |
| 725 | 0x00052ea2 | FUN_00052ea2 | MISMATCH | len cand=322 orig=229; 2%match; reg-artifact | extraout,indirect_call,void_proto |
| 726 | 0x00052f87 | FUN_00052f87 | MISMATCH | len cand=346 orig=253; 3%match; reg-artifact | extraout,indirect_call,void_proto |
| 727 | 0x00053086 | FUN_00053086 | MISMATCH | len cand=155 orig=109; 1%match; param-recovery | indirect_call,void_proto |
| 728 | 0x000530f3 | FUN_000530f3 | MISMATCH | len cand=155 orig=371; 2%match; param-recovery | indirect_call,void_proto |
| 729 | 0x00053266 | FUN_00053266 | MISMATCH | len cand=182 orig=130; 0%match; param-recovery | indirect_call,void_proto |
| 730 | 0x000532e8 | FUN_000532e8 | MISMATCH | len cand=182 orig=130; 0%match; param-recovery | indirect_call,void_proto |
| 731 | 0x0005336a | FUN_0005336a | MISMATCH | len cand=155 orig=327; 1%match; param-recovery | indirect_call,void_proto |
| 732 | 0x000534b1 | FUN_000534b1 | MISMATCH | len cand=155 orig=109; 1%match; param-recovery | indirect_call,void_proto |
| 733 | 0x0005351e | FUN_0005351e | MISMATCH | len cand=167 orig=118; 1%match; param-recovery | indirect_call,void_proto |
| 734 | 0x00053594 | FUN_00053594 | MISMATCH | len cand=167 orig=236; 2%match; param-recovery | indirect_call,void_proto |
| 735 | 0x00053680 | FUN_00053680 | MISMATCH | len cand=167 orig=1859; 1%match; param-recovery | indirect_call,void_proto |
| 736 | 0x00053dc3 | FUN_00053dc3 | MISMATCH | len cand=346 orig=249; 3%match; reg-artifact | extraout,indirect_call,void_proto |
| 737 | 0x00053ebc | FUN_00053ebc | MISMATCH | len cand=322 orig=229; 2%match; reg-artifact | extraout,indirect_call,void_proto |
| 738 | 0x00053fa1 | FUN_00053fa1 | MISMATCH | len cand=196 orig=964; 2%match; param-recovery | indirect_call,void_proto |
| 739 | 0x00054365 | FUN_00054365 | MISMATCH | len cand=334 orig=237; 3%match; reg-artifact | extraout,indirect_call,void_proto |
| 740 | 0x00054452 | FUN_00054452 | MISMATCH | len cand=334 orig=237; 3%match; reg-artifact | extraout,indirect_call,void_proto |
| 741 | 0x0005453f | FUN_0005453f | MISMATCH | len cand=182 orig=367; 1%match; param-recovery | indirect_call,void_proto |
| 742 | 0x000546ae | FUN_000546ae | MISMATCH | len cand=322 orig=229; 2%match; reg-artifact | extraout,indirect_call,void_proto |
| 743 | 0x00054793 | FUN_00054793 | MISMATCH | len cand=322 orig=229; 2%match; reg-artifact | extraout,indirect_call,void_proto |
| 744 | 0x00054878 | FUN_00054878 | MISMATCH | len cand=334 orig=346; 2%match; reg-artifact | extraout,indirect_call,void_proto |
| 745 | 0x000549d2 | FUN_000549d2 | MISMATCH | len cand=322 orig=338; 2%match; reg-artifact | extraout,indirect_call,void_proto |
| 746 | 0x00054b24 | FUN_00054b24 | MISMATCH | len cand=346 orig=249; 3%match; reg-artifact | extraout,indirect_call,void_proto |
| 747 | 0x00054c1d | FUN_00054c1d | MISMATCH | len cand=155 orig=109; 1%match; param-recovery | indirect_call,void_proto |
| 748 | 0x00054c8a | FUN_00054c8a | MISMATCH | len cand=155 orig=218; 1%match; param-recovery | indirect_call,void_proto |
| 749 | 0x00054d64 | FUN_00054d64 | MISMATCH | len cand=155 orig=239; 2%match; param-recovery | indirect_call,void_proto |
| 750 | 0x00054e53 | FUN_00054e53 | MISMATCH | len cand=182 orig=248; 1%match; param-recovery | indirect_call,void_proto |
| 751 | 0x00054f4b | FUN_00054f4b | MISMATCH | len cand=322 orig=1512; 2%match; reg-artifact | extraout,indirect_call,void_proto |
| 752 | 0x00055533 | FUN_00055533 | MISMATCH | len cand=316 orig=249; 2%match; reg-artifact | extraout,indirect_call,void_proto |
| 753 | 0x0005562c | FUN_0005562c | MISMATCH | len cand=155 orig=1846; 2%match; param-recovery | indirect_call,void_proto |
| 754 | 0x00055d62 | FUN_00055d62 | MISMATCH | len cand=167 orig=2025; 1%match; param-recovery | indirect_call,void_proto |
| 755 | 0x0005654b | FUN_0005654b | MISMATCH | len cand=322 orig=229; 2%match; reg-artifact | extraout,indirect_call,void_proto |
| 756 | 0x00056630 | FUN_00056630 | MISMATCH | len cand=167 orig=118; 1%match; param-recovery | indirect_call,void_proto |
| 757 | 0x000566a6 | FUN_000566a6 | MISMATCH | len cand=182 orig=367; 0%match; param-recovery | indirect_call,void_proto |
| 758 | 0x00056815 | FUN_00056815 | MISMATCH | len cand=206 orig=686; 0%match; param-recovery | indirect_call,void_proto |
| 759 | 0x00056ad0 | FUN_00056ad0 | MISMATCH | len cand=26 orig=43; 4%match; codegen/regalloc |  |
| 760 | 0x00056afc | FUN_00056afc | MISMATCH | len cand=105 orig=59; 5%match; codegen/regalloc |  |
| 761 | 0x00056b38 | FUN_00056b38 | MISMATCH | len cand=10 orig=55; 10%match; codegen/regalloc |  |
| 762 | 0x00056b70 | FUN_00056b70 | MISMATCH | len cand=182 orig=123; 2%match; codegen/regalloc |  |
| 763 | 0x00056bec | FUN_00056bec | MISMATCH | len cand=34 orig=79; 0%match; codegen/regalloc |  |
| 764 | 0x00056c3c | FUN_00056c3c | MISMATCH | len cand=41 orig=79; 2%match; codegen/regalloc | indirect_call |
| 765 | 0x00056c8c | FUN_00056c8c | MISMATCH | len cand=24 orig=64; 4%match; param-recovery | void_proto |
| 766 | 0x00056ccc | FUN_00056ccc | COMPILE_FAIL | E1052:Expression has void type | indirect_call |
| 767 | 0x00056db4 | FUN_00056db4 | MISMATCH | len cand=54 orig=103; 4%match; codegen/regalloc | indirect_call |
| 768 | 0x00056e1c | FUN_00056e1c | MISMATCH | len cand=171 orig=99; 2%match; codegen/regalloc | indirect_call |
| 769 | 0x00056e80 | FUN_00056e80 | MISMATCH | len cand=14 orig=20; 0%match; codegen/regalloc | indirect_call |
| 770 | 0x00056e94 | FUN_00056e94 | MISMATCH | len cand=141 orig=83; 8%match; codegen/regalloc | indirect_call |
| 771 | 0x00056ee8 | FUN_00056ee8 | MISMATCH | len cand=300 orig=196; 3%match; codegen/regalloc | indirect_call |
| 772 | 0x00056fac | FUN_00056fac | MISMATCH | len cand=137 orig=136; 4%match; codegen/regalloc |  |
| 773 | 0x00057034 | FUN_00057034 | COMPILE_FAIL | E1052:Expression has void type |  |
| 774 | 0x000570e4 | FUN_000570e4 | MISMATCH | len cand=233 orig=228; 4%match; codegen/regalloc | indirect_call |
| 775 | 0x000571c8 | FUN_000571c8 | MISMATCH | len cand=7 orig=88; 0%match; codegen/regalloc |  |
| 776 | 0x00057220 | FUN_00057220 | MISMATCH | len cand=180 orig=119; 1%match; codegen/regalloc | indirect_call |
| 777 | 0x00057298 | FUN_00057298 | MISMATCH | len cand=149 orig=184; 3%match; codegen/regalloc | indirect_call |
| 778 | 0x00057350 | FUN_00057350 | MISMATCH | len cand=7 orig=144; 0%match; codegen/regalloc |  |
| 779 | 0x000573e0 | FUN_000573e0 | MISMATCH | len cand=329 orig=291; 3%match; codegen/regalloc | indirect_call |
| 780 | 0x00057504 | FUN_00057504 | MISMATCH | len cand=44 orig=152; 2%match; codegen/regalloc |  |
| 781 | 0x0005759c | FUN_0005759c | MISMATCH | len cand=75 orig=128; 4%match; codegen/regalloc |  |
| 782 | 0x0005761c | FUN_0005761c | MISMATCH | len cand=158 orig=187; 1%match; codegen/regalloc | indirect_call |
| 783 | 0x000576d8 | FUN_000576d8 | COMPILE_FAIL | E1052:Expression has void type | indirect_call |
| 784 | 0x00057858 | FUN_00057858 | COMPILE_FAIL | E1079:Expression must be integral | extraout,indirect_call |
| 785 | 0x000578e8 | FUN_000578e8 | MISMATCH | len cand=17 orig=231; 5%match; codegen/regalloc | indirect_call |
| 786 | 0x000579d0 | FUN_000579d0 | MISMATCH | len cand=14 orig=151; 7%match; codegen/regalloc |  |
| 787 | 0x00057a68 | FUN_00057a68 | MISMATCH | len cand=100 orig=208; 2%match; codegen/regalloc | indirect_call |
| 788 | 0x00057b38 | FUN_00057b38 | MISMATCH | len cand=169 orig=124; 6%match; codegen/regalloc | indirect_call |
| 789 | 0x00057bb4 | FUN_00057bb4 | MISMATCH | len cand=170 orig=260; 2%match; codegen/regalloc | indirect_call |
| 790 | 0x00057cb8 | FUN_00057cb8 | MISMATCH | len cand=407 orig=403; 3%match; codegen/regalloc | indirect_call |
| 791 | 0x00057e4c | FUN_00057e4c | MISMATCH | len cand=122 orig=140; 1%match; codegen/regalloc | indirect_call |
| 792 | 0x00057ed8 | FUN_00057ed8 | MISMATCH | len cand=144 orig=179; 5%match; codegen/regalloc | indirect_call |
| 793 | 0x00057f90 | FUN_00057f90 | MISMATCH | len cand=17 orig=28; 5%match; codegen/regalloc | indirect_call |
| 794 | 0x00057fac | FUN_00057fac | MISMATCH | len cand=21 orig=32; 0%match; codegen/regalloc |  |
| 795 | 0x00057fcc | FUN_00057fcc | MISMATCH | len cand=21 orig=35; 0%match; codegen/regalloc |  |
| 796 | 0x00057ff0 | FUN_00057ff0 | MISMATCH | len cand=69 orig=88; 9%match; codegen/regalloc |  |
| 797 | 0x00058048 | FUN_00058048 | MISMATCH | len cand=159 orig=187; 4%match; codegen/regalloc |  |
| 798 | 0x00058104 | FUN_00058104 | MISMATCH | len cand=86 orig=155; 2%match; codegen/regalloc | indirect_call |
| 799 | 0x000581a0 | FUN_000581a0 | MISMATCH | len cand=124 orig=155; 5%match; codegen/regalloc | indirect_call |
| 800 | 0x0005823c | FUN_0005823c | MISMATCH | len cand=260 orig=112; 3%match; codegen/regalloc |  |
| 801 | 0x000582ac | FUN_000582ac | MISMATCH | len cand=78 orig=128; 1%match; codegen/regalloc | indirect_call,int64 |
| 802 | 0x0005832c | FUN_0005832c | MISMATCH | len cand=41 orig=44; 5%match; codegen/regalloc | indirect_call |
| 803 | 0x00058358 | FUN_00058358 | MISMATCH | len cand=95 orig=108; 4%match; codegen/regalloc | indirect_call |
| 804 | 0x000583c4 | FUN_000583c4 | MISMATCH | len cand=197 orig=1135; 4%match; codegen/regalloc | indirect_call |
| 805 | 0x00058834 | FUN_00058834 | MISMATCH | len cand=20 orig=56; 0%match; param-recovery | void_proto |
| 806 | 0x0005886c | FUN_0005886c | MISMATCH | len cand=64 orig=76; 2%match; codegen/regalloc | indirect_call |
| 807 | 0x000588b8 | FUN_000588b8 | MISMATCH | len cand=14 orig=23; 0%match; codegen/regalloc | indirect_call |
| 808 | 0x000588d0 | FUN_000588d0 | MISMATCH | len cand=14 orig=23; 0%match; codegen/regalloc | indirect_call |
| 809 | 0x000588f0 | FUN_000588f0 | MISMATCH | len cand=95 orig=483; 3%match; codegen/regalloc | indirect_call |
| 810 | 0x00058ad4 | FUN_00058ad4 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call |
| 811 | 0x00058bec | FUN_00058bec | MISMATCH | len cand=82 orig=544; 1%match; codegen/regalloc | indirect_call |
| 812 | 0x00058e0c | FUN_00058e0c | MISMATCH | len cand=56 orig=112; 2%match; codegen/regalloc |  |
| 813 | 0x00058e7c | FUN_00058e7c | MISMATCH | len cand=18 orig=15; 7%match; param-recovery | indirect_call,void_proto |
| 814 | 0x00058e8c | FUN_00058e8c | MISMATCH | len cand=183 orig=168; 3%match; codegen/regalloc | indirect_call |
| 815 | 0x00058f34 | FUN_00058f34 | MISMATCH | len cand=179 orig=196; 3%match; codegen/regalloc | indirect_call |
| 816 | 0x00058ff8 | FUN_00058ff8 | MISMATCH | len cand=18 orig=23; 5%match; codegen/regalloc | indirect_call |
| 817 | 0x00059010 | FUN_00059010 | COMPILE_FAIL | E1052:Expression has void type | indirect_call |
| 818 | 0x00059060 | FUN_00059060 | MISMATCH | len cand=195 orig=172; 2%match; codegen/regalloc | indirect_call |
| 819 | 0x0005910c | FUN_0005910c | MISMATCH | len cand=336 orig=427; 2%match; codegen/regalloc | indirect_call |
| 820 | 0x000592c0 | FUN_000592c0 | MISMATCH | len cand=27 orig=132; 3%match; codegen/regalloc | indirect_call |
| 821 | 0x00059344 | FUN_00059344 | MISMATCH | len cand=360 orig=191; 3%match; codegen/regalloc | indirect_call |
| 822 | 0x00059404 | FUN_00059404 | MISMATCH | len cand=299 orig=162; 2%match; codegen/regalloc | indirect_call |
| 823 | 0x000594b0 | FUN_000594b0 | MISMATCH | len cand=26 orig=28; 4%match; codegen/regalloc | indirect_call |
| 824 | 0x000594cc | FUN_000594cc | MISMATCH | len cand=63 orig=81; 5%match; codegen/regalloc | indirect_call |
| 825 | 0x00059520 | FUN_00059520 | MISMATCH | len cand=195 orig=399; 2%match; codegen/regalloc | indirect_call |
| 826 | 0x000596b0 | FUN_000596b0 | MISMATCH | len cand=35 orig=351; 6%match; codegen/regalloc |  |
| 827 | 0x00059810 | FUN_00059810 | MISMATCH | len cand=82 orig=135; 10%match; codegen/regalloc | indirect_call |
| 828 | 0x00059898 | FUN_00059898 | MISMATCH | len cand=172 orig=604; 3%match; codegen/regalloc | indirect_call |
| 829 | 0x00059af4 | FUN_00059af4 | MISMATCH | len cand=253 orig=263; 4%match; reg-artifact | extraout |
| 830 | 0x00059bfc | FUN_00059bfc | MISMATCH | len cand=57 orig=48; 8%match; codegen/regalloc |  |
| 831 | 0x00059c2c | FUN_00059c2c | COMPILE_FAIL | E1052:Expression has void type |  |
| 832 | 0x00059c6c | FUN_00059c6c | MISMATCH | len cand=51 orig=52; 0%match; codegen/regalloc |  |
| 833 | 0x00059ca0 | FUN_00059ca0 | MISMATCH | len cand=34 orig=2027; 0%match; codegen/regalloc |  |
| 834 | 0x0005a48c | FUN_0005a48c | MISMATCH | len cand=26 orig=128; 4%match; codegen/regalloc |  |
| 835 | 0x0005a50c | FUN_0005a50c | MISMATCH | len cand=87 orig=92; 2%match; codegen/regalloc | indirect_call |
| 836 | 0x0005a568 | FUN_0005a568 | MISMATCH | len cand=138 orig=171; 2%match; codegen/regalloc | indirect_call |
| 837 | 0x0005a614 | FUN_0005a614 | MISMATCH | len cand=44 orig=55; 0%match; codegen/regalloc |  |
| 838 | 0x0005a64c | FUN_0005a64c | MISMATCH | len cand=34 orig=88; 12%match; codegen/regalloc | indirect_call |
| 839 | 0x0005a6a4 | FUN_0005a6a4 | MISMATCH | len cand=96 orig=123; 6%match; codegen/regalloc |  |
| 840 | 0x0005a720 | FUN_0005a720 | MISMATCH | len cand=48 orig=260; 6%match; codegen/regalloc |  |
| 841 | 0x0005a824 | FUN_0005a824 | MISMATCH | len cand=33 orig=167; 3%match; codegen/regalloc | indirect_call |
| 842 | 0x0005a8cc | FUN_0005a8cc | MISMATCH | len cand=192 orig=244; 2%match; codegen/regalloc | indirect_call |
| 843 | 0x0005a9c0 | FUN_0005a9c0 | MISMATCH | len cand=34 orig=476; 3%match; codegen/regalloc | indirect_call |
| 844 | 0x0005ab9c | FUN_0005ab9c | MISMATCH | len cand=65 orig=376; 2%match; codegen/regalloc | indirect_call |
| 845 | 0x0005ad14 | FUN_0005ad14 | MISMATCH | len cand=132 orig=135; 3%match; codegen/regalloc | indirect_call |
| 846 | 0x0005ad9c | FUN_0005ad9c | MISMATCH | len cand=86 orig=2666; 5%match; codegen/regalloc | indirect_call |
| 847 | 0x0005b810 | FUN_0005b810 | MISMATCH | len cand=46 orig=1696; 4%match; param-recovery | indirect_call,void_proto |
| 848 | 0x0005beb0 | FUN_0005beb0 | MISMATCH | len cand=69 orig=100; 4%match; codegen/regalloc |  |
| 849 | 0x0005bf14 | FUN_0005bf14 | MISMATCH | len cand=212 orig=4212; 3%match; codegen/regalloc | indirect_call |
| 850 | 0x0005cf88 | FUN_0005cf88 | MISMATCH | len cand=16 orig=84; 0%match; param-recovery | void_proto |
| 851 | 0x0005cfdc | FUN_0005cfdc | MISMATCH | len cand=52 orig=45; 4%match; codegen/regalloc | indirect_call |
| 852 | 0x0005d00a | FUN_0005d00a | MISMATCH | len cand=14 orig=301; 0%match; codegen/regalloc | indirect_call |
| 853 | 0x0005d138 | FUN_0005d138 | MISMATCH | len cand=181 orig=364; 2%match; reg-artifact | extraout,indirect_call |
| 854 | 0x0005d2a4 | FUN_0005d2a4 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call |
| 855 | 0x0005d314 | FUN_0005d314 | MISMATCH | len cand=112 orig=492; 3%match; codegen/regalloc | indirect_call |
| 856 | 0x0005d500 | FUN_0005d500 | MISMATCH | len cand=80 orig=56; 5%match; codegen/regalloc | indirect_call |
| 857 | 0x0005d538 | FUN_0005d538 | MISMATCH | len cand=76 orig=68; 3%match; codegen/regalloc | indirect_call |
| 858 | 0x0005d57c | FUN_0005d57c | MISMATCH | len cand=68 orig=200; 3%match; codegen/regalloc | indirect_call |
| 859 | 0x0005d644 | FUN_0005d644 | MISMATCH | len cand=83 orig=59; 3%match; param-recovery | indirect_call,void_proto |
| 860 | 0x0005d680 | FUN_0005d680 | MISMATCH | len cand=202 orig=164; 5%match; codegen/regalloc | indirect_call |
| 861 | 0x0005d724 | FUN_0005d724 | MISMATCH | len cand=202 orig=571; 4%match; codegen/regalloc | indirect_call |
| 862 | 0x0005d960 | FUN_0005d960 | MISMATCH | len cand=217 orig=1387; 4%match; codegen/regalloc | indirect_call |
| 863 | 0x0005decc | FUN_0005decc | MISMATCH | len cand=121 orig=3995; 3%match; codegen/regalloc | indirect_call |
| 864 | 0x0005ee67 | FUN_0005ee67 | MISMATCH | len cand=217 orig=76; 4%match; codegen/regalloc |  |
| 865 | 0x0005eec0 | FUN_0005eec0 | MISMATCH | len cand=60 orig=95; 10%match; codegen/regalloc | indirect_call |
| 866 | 0x0005ef20 | FUN_0005ef20 | MISMATCH | len cand=46 orig=64; 8%match; codegen/regalloc | indirect_call |
| 867 | 0x0005ef60 | FUN_0005ef60 | MISMATCH | len cand=68 orig=184; 3%match; reg-artifact | extraout,indirect_call |
| 868 | 0x0005f018 | FUN_0005f018 | MISMATCH | len cand=1 orig=14; 0%match; param-recovery | void_proto |
| 869 | 0x0005f030 | FUN_0005f030 | COMPILE_FAIL | E1010:Type mismatch |  |
| 870 | 0x0005f0d1 | FUN_0005f0d1 | MISMATCH | len cand=37 orig=161; 0%match; codegen/regalloc |  |
| 871 | 0x0005f172 | FUN_0005f172 | MISMATCH | len cand=42 orig=57; 0%match; codegen/regalloc |  |
| 872 | 0x0005f1ab | FUN_0005f1ab | COMPILE_FAIL | E1045:Subscript on non-array |  |
| 873 | 0x0005f202 | FUN_0005f202 | COMPILE_FAIL | E1079:Expression must be integral | extraout,indirect_call |
| 874 | 0x0005f33b | FUN_0005f33b | MISMATCH | @+0; 0%comparable-match; param-recovery | indirect_call,void_proto |
| 875 | 0x0005f34d | FUN_0005f34d | MISMATCH | len cand=30 orig=85; 0%match; codegen/regalloc | indirect_call |
| 876 | 0x0005f3b0 | FUN_0005f3b0 | MISMATCH | len cand=305 orig=143; 1%match; codegen/regalloc | indirect_call |
| 877 | 0x0005f440 | FUN_0005f440 | MISMATCH | len cand=75 orig=69; 1%match; reg-artifact | extraout,indirect_call |
| 878 | 0x0005f490 | FUN_0005f490 | MISMATCH | len cand=46 orig=675; 4%match; param-recovery | indirect_call,void_proto |
| 879 | 0x0005f734 | FUN_0005f734 | MISMATCH | len cand=4 orig=5; 0%match; param-recovery | void_proto |
| 880 | 0x0005f740 | FUN_0005f740 | MISMATCH | len cand=60 orig=71; 2%match; codegen/regalloc | indirect_call |
| 881 | 0x0005f788 | FUN_0005f788 | MISMATCH | len cand=44 orig=59; 5%match; codegen/regalloc | indirect_call |
| 882 | 0x0005f7d0 | FUN_0005f7d0 | COMPILE_FAIL | E1029:Expression must be 'pointer to ...' | extraout,indirect_call |
| 883 | 0x0005f84c | FUN_0005f84c | MISMATCH | len cand=1 orig=6; 0%match; param-recovery | void_proto |
| 884 | 0x0005f852 | FUN_0005f852 | MISMATCH | len cand=36 orig=287; 8%match; codegen/regalloc | indirect_call |
| 885 | 0x0005f971 | FUN_0005f971 | MISMATCH | len cand=1 orig=199; 0%match; param-recovery | void_proto |
| 886 | 0x0005fa38 | FUN_0005fa38 | MISMATCH | len cand=252 orig=235; 2%match; reg-artifact | extraout,indirect_call |
| 887 | 0x0005fb24 | FUN_0005fb24 | MISMATCH | len cand=124 orig=140; 2%match; codegen/regalloc | indirect_call |
| 888 | 0x0005fbb0 | FUN_0005fbb0 | MISMATCH | len cand=20 orig=34; 0%match; codegen/regalloc | indirect_call |
| 889 | 0x0005fbd2 | FUN_0005fbd2 | COMPILE_FAIL | E1029:Expression must be 'pointer to ...' | indirect_call |
| 890 | 0x0005fc80 | FUN_0005fc80 | MISMATCH | len cand=54 orig=72; 11%match; codegen/regalloc | indirect_call |
| 891 | 0x0005fcc8 | FUN_0005fcc8 | MISMATCH | len cand=54 orig=134; 11%match; codegen/regalloc | indirect_call |
| 892 | 0x0005fd4e | FUN_0005fd4e | MISMATCH | len cand=189 orig=376; 4%match; codegen/regalloc | indirect_call |
| 893 | 0x0005fed0 | FUN_0005fed0 | MISMATCH | len cand=23 orig=608; 7%match; param-recovery | indirect_call,void_proto |
| 894 | 0x00060130 | FUN_00060130 | MISMATCH | len cand=128 orig=49; 2%match; codegen/regalloc | indirect_call |
| 895 | 0x00060170 | FUN_00060170 | COMPILE_FAIL | E1080:Expression must be arithmetic | indirect_call |
| 896 | 0x000601dc | FUN_000601dc | MISMATCH | len cand=26 orig=25; 0%match; codegen/regalloc | indirect_call |
| 897 | 0x000601f8 | entry | COMPILE_FAIL | E1052:Expression has void type | extraout,indirect_call,void_proto |
| 898 | 0x00060489 | FUN_00060489 | MISMATCH | len cand=64 orig=68; 3%match; codegen/regalloc | indirect_call |
| 899 | 0x000604cf | FUN_000604cf | MISMATCH | len cand=17 orig=48; 10%match; codegen/regalloc | indirect_call |
| 900 | 0x00060500 | FUN_00060500 | MISMATCH | len cand=237 orig=225; 2%match; codegen/regalloc | indirect_call |
| 901 | 0x000605f0 | FUN_000605f0 | MISMATCH | len cand=59 orig=66; 3%match; codegen/regalloc | indirect_call |
| 902 | 0x00060640 | FUN_00060640 | MISMATCH | len cand=74 orig=109; 0%match; codegen/regalloc | indirect_call |
| 903 | 0x000606b0 | FUN_000606b0 | MISMATCH | len cand=1 orig=6; 0%match; param-recovery | void_proto |
| 904 | 0x000606c0 | FUN_000606c0 | MISMATCH | len cand=1 orig=6; 0%match; param-recovery | void_proto |
| 905 | 0x000606d0 | FUN_000606d0 | MISMATCH | len cand=1 orig=184; 0%match; param-recovery | void_proto |
| 906 | 0x00060790 | FUN_00060790 | MISMATCH | len cand=78 orig=203; 4%match; param-recovery | void_proto |
| 907 | 0x00060860 | FUN_00060860 | MISMATCH | len cand=58 orig=62; 3%match; param-recovery | indirect_call,void_proto |
| 908 | 0x000608a0 | FUN_000608a0 | COMPILE_FAIL | E1052:Expression has void type |  |
| 909 | 0x00060ad0 | FUN_00060ad0 | MISMATCH | len cand=176 orig=226; 2%match; codegen/regalloc | indirect_call |
| 910 | 0x00060bc0 | FUN_00060bc0 | COMPILE_FAIL | E1045:Subscript on non-array | extraout,indirect_call |
| 911 | 0x00060ec5 | FUN_00060ec5 | COMPILE_FAIL | E1052:Expression has void type | extraout,indirect_call |
| 912 | 0x00060f10 | FUN_00060f10 | MISMATCH | len cand=259 orig=2533; 8%match; param-recovery | indirect_call,void_proto |
| 913 | 0x00061900 | FUN_00061900 | COMPILE_FAIL | E1080:Expression must be arithmetic | extraout,indirect_call |
| 914 | 0x00061e40 | FUN_00061e40 | MISMATCH | len cand=45 orig=55; 4%match; codegen/regalloc |  |
| 915 | 0x00061e80 | FUN_00061e80 | MISMATCH | len cand=182 orig=355; 5%match; param-recovery | indirect_call,void_proto |
| 916 | 0x00061ff0 | FUN_00061ff0 | MISMATCH | len cand=280 orig=271; 4%match; codegen/regalloc | indirect_call |
| 917 | 0x00062100 | FUN_00062100 | MISMATCH | len cand=247 orig=210; 5%match; param-recovery | indirect_call,void_proto |
| 918 | 0x000621e0 | FUN_000621e0 | MISMATCH | len cand=123 orig=120; 6%match; codegen/regalloc | indirect_call |
| 919 | 0x00062260 | FUN_00062260 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call |
| 920 | 0x000624e0 | FUN_000624e0 | COMPILE_FAIL | E1029:Expression must be 'pointer to ...' | indirect_call |
| 921 | 0x000626c0 | FUN_000626c0 | COMPILE_FAIL | E1010:Type mismatch | indirect_call,void_proto |
| 922 | 0x000628d0 | FUN_000628d0 | COMPILE_FAIL | E1045:Subscript on non-array | indirect_call,void_proto |
| 923 | 0x00062f10 | FUN_00062f10 | MISMATCH | len cand=596 orig=673; 4%match; codegen/regalloc | indirect_call |
| 924 | 0x000631c0 | FUN_000631c0 | COMPILE_FAIL | E1080:Expression must be arithmetic |  |
| 925 | 0x00063410 | FUN_00063410 | COMPILE_FAIL | E1036:Right operand of '-' is a pointer | indirect_call |
| 926 | 0x000636f0 | FUN_000636f0 | COMPILE_FAIL | E1080:Expression must be arithmetic | indirect_call |
| 927 | 0x00063930 | FUN_00063930 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call |
| 928 | 0x00063b80 | FUN_00063b80 | MISMATCH | len cand=45 orig=41; 0%match; codegen/regalloc | indirect_call |
| 929 | 0x00063bb0 | FUN_00063bb0 | MISMATCH | len cand=168 orig=53; 0%match; codegen/regalloc |  |
| 930 | 0x00063be5 | FUN_00063be5 | MISMATCH | len cand=20 orig=33; 0%match; codegen/regalloc | indirect_call |
| 931 | 0x00063c06 | FUN_00063c06 | MISMATCH | len cand=41 orig=47; 0%match; codegen/regalloc | indirect_call |
| 932 | 0x00063c35 | FUN_00063c35 | MISMATCH | len cand=23 orig=21; 0%match; codegen/regalloc | indirect_call |
| 933 | 0x00063c4a | FUN_00063c4a | MISMATCH | len cand=1 orig=12; 0%match; param-recovery | void_proto |
| 934 | 0x00063c56 | FUN_00063c56 | COMPILE_FAIL | E1029:Expression must be 'pointer to ...' | extraout,indirect_call |
| 935 | 0x00063cbf | FUN_00063cbf | MISMATCH | len cand=183 orig=137; 1%match; codegen/regalloc | indirect_call |
| 936 | 0x00063d48 | FUN_00063d48 | MISMATCH | len cand=55 orig=180; 5%match; codegen/regalloc | indirect_call |
| 937 | 0x00063dfc | FUN_00063dfc | MISMATCH | len cand=210 orig=200; 6%match; reg-artifact | extraout,indirect_call |
| 938 | 0x00063ec4 | FUN_00063ec4 | MISMATCH | len cand=35 orig=27; 0%match; param-recovery | indirect_call,void_proto |
| 939 | 0x00063edf | FUN_00063edf | MISMATCH | len cand=11 orig=150; 0%match; codegen/regalloc | indirect_call |
| 940 | 0x00063f76 | FUN_00063f76 | MISMATCH | len cand=77 orig=3; 0%match; thunk |  |
| 941 | 0x00063f7b | FUN_00063f7b | MISMATCH | len cand=23 orig=18; 0%match; codegen/regalloc |  |
| 942 | 0x00063f8d | FUN_00063f8d | MISMATCH | len cand=233 orig=202; 3%match; codegen/regalloc | indirect_call |
| 943 | 0x00064058 | FUN_00064058 | MISMATCH | len cand=37 orig=31; 3%match; codegen/regalloc | indirect_call |
| 944 | 0x00064077 | FUN_00064077 | MISMATCH | len cand=1 orig=6; 0%match; param-recovery | void_proto |
| 945 | 0x0006407d | FUN_0006407d | MISMATCH | len cand=1 orig=6; 0%match; param-recovery | void_proto |
| 946 | 0x00064090 | FUN_00064090 | MISMATCH | len cand=105 orig=49; 0%match; reg-artifact | extraout,indirect_call |
| 947 | 0x000640c7 | FUN_000640c7 | MISMATCH | len cand=171 orig=108; 4%match; codegen/regalloc |  |
| 948 | 0x00064133 | FUN_00064133 | MISMATCH | len cand=95 orig=129; 0%match; codegen/regalloc | indirect_call |
| 949 | 0x000641b4 | FUN_000641b4 | MISMATCH | len cand=37 orig=31; 3%match; codegen/regalloc | indirect_call |
| 950 | 0x000641d3 | FUN_000641d3 | MISMATCH | len cand=27 orig=41; 4%match; codegen/regalloc |  |
| 951 | 0x000641fc | FUN_000641fc | MISMATCH | len cand=33 orig=105; 6%match; codegen/regalloc |  |
| 952 | 0x00064270 | FUN_00064270 | MISMATCH | len cand=56 orig=79; 7%match; codegen/regalloc |  |
| 953 | 0x000642c0 | FUN_000642c0 | MISMATCH | len cand=98 orig=121; 8%match; codegen/regalloc |  |
| 954 | 0x00064340 | FUN_00064340 | MISMATCH | len cand=75 orig=88; 5%match; codegen/regalloc |  |
| 955 | 0x000643a0 | FUN_000643a0 | MISMATCH | len cand=108 orig=58; 7%match; codegen/regalloc |  |
| 956 | 0x000643e0 | FUN_000643e0 | MISMATCH | len cand=61 orig=85; 16%match; codegen/regalloc | indirect_call |
| 957 | 0x00064435 | FUN_00064435 | MISMATCH | len cand=141 orig=157; 4%match; codegen/regalloc |  |
| 958 | 0x000644e0 | FUN_000644e0 | MISMATCH | len cand=9 orig=288; 11%match; codegen/regalloc |  |
| 959 | 0x00064600 | FUN_00064600 | MISMATCH | len cand=64 orig=75; 3%match; codegen/regalloc | indirect_call |
| 960 | 0x0006464c | FUN_0006464c | MISMATCH | len cand=79 orig=1794; 5%match; codegen/regalloc | indirect_call |
| 961 | 0x00064d50 | FUN_00064d50 | MISMATCH | len cand=20 orig=43; 4%match; codegen/regalloc | indirect_call |
| 962 | 0x00064d7b | FUN_00064d7b | COMPILE_FAIL | E1018:Label 'LAB_00064e45' not defined in function | indirect_call |
| 963 | 0x00064e5e | FUN_00064e5e | MISMATCH | len cand=87 orig=131; 1%match; codegen/regalloc | indirect_call |
| 964 | 0x00064ee1 | FUN_00064ee1 | COMPILE_FAIL | E1052:Expression has void type | extraout,indirect_call |
| 965 | 0x00064ff4 | FUN_00064ff4 | MISMATCH | len cand=23 orig=27; 7%match; param-recovery | indirect_call,void_proto |
| 966 | 0x0006500f | FUN_0006500f | MISMATCH | len cand=39 orig=36; 0%match; codegen/regalloc | indirect_call |
| 967 | 0x00065033 | FUN_00065033 | COMPILE_FAIL | E1045:Subscript on non-array | indirect_call |
| 968 | 0x0006525d | FUN_0006525d | MISMATCH | len cand=47 orig=3; 0%match; thunk | indirect_call |
| 969 | 0x00065262 | FUN_00065262 | MISMATCH | len cand=57 orig=61; 2%match; codegen/regalloc | indirect_call |
| 970 | 0x0006529f | FUN_0006529f | COMPILE_FAIL | E1052:Expression has void type | extraout,indirect_call |
| 971 | 0x00065470 | FUN_00065470 | COMPILE_FAIL | E1079:Expression must be integral |  |
| 972 | 0x000655c0 | FUN_000655c0 | MISMATCH | len cand=59 orig=56; 2%match; codegen/regalloc | indirect_call |
| 973 | 0x000655f8 | FUN_000655f8 | MISMATCH | len cand=522 orig=148; 2%match; codegen/regalloc | indirect_call |
| 974 | 0x0006568c | FUN_0006568c | MISMATCH | len cand=44 orig=399; 4%match; codegen/regalloc | indirect_call |
| 975 | 0x0006581c | FUN_0006581c | MISMATCH | len cand=41 orig=224; 4%match; codegen/regalloc | indirect_call |
| 976 | 0x000658fc | FUN_000658fc | MISMATCH | len cand=172 orig=125; 4%match; param-recovery | indirect_call,void_proto |
| 977 | 0x0006597c | FUN_0006597c | MISMATCH | len cand=46 orig=136; 0%match; codegen/regalloc | indirect_call |
| 978 | 0x00065a04 | FUN_00065a04 | COMPILE_FAIL | E1082:Statement required after label |  |
| 979 | 0x00065a68 | FUN_00065a68 | MISMATCH | len cand=3214 orig=1127; 3%match; param-recovery | indirect_call,void_proto |
| 980 | 0x00065ed0 | FUN_00065ed0 | MISMATCH | len cand=1 orig=8; 0%match; param-recovery | void_proto |
| 981 | 0x00065ed8 | FUN_00065ed8 | MISMATCH | len cand=1 orig=8; 0%match; param-recovery | void_proto |
| 982 | 0x00065ee0 | FUN_00065ee0 | MISMATCH | len cand=1 orig=8; 0%match; param-recovery | void_proto |
| 983 | 0x00065ee8 | FUN_00065ee8 | MISMATCH | len cand=1 orig=6; 0%match; param-recovery | void_proto |
| 984 | 0x00065eee | FUN_00065eee | MISMATCH | len cand=28 orig=97; 4%match; codegen/regalloc |  |
| 985 | 0x00065f50 | FUN_00065f50 | MISMATCH | len cand=100 orig=79; 4%match; codegen/regalloc | indirect_call |
| 986 | 0x00065fa0 | FUN_00065fa0 | COMPILE_FAIL | E1081:Expression must be scalar type | extraout,indirect_call |
| 987 | 0x00066100 | FUN_00066100 | COMPILE_FAIL | E1063:Missing operand | ellipsis,extraout,indirect_call,raw_marker |
| 988 | 0x00066874 | FUN_00066874 | MISMATCH | len cand=94 orig=280; 4%match; codegen/regalloc | indirect_call |
| 989 | 0x0006698c | FUN_0006698c | MISMATCH | len cand=202 orig=168; 6%match; codegen/regalloc | indirect_call |
| 990 | 0x00066a34 | FUN_00066a34 | MISMATCH | len cand=9 orig=599; 0%match; param-recovery | void_proto |
| 991 | 0x00066c90 | FUN_00066c90 | MISMATCH | len cand=175 orig=108; 3%match; reg-artifact | extraout,indirect_call |
| 992 | 0x00066cfc | FUN_00066cfc | MISMATCH | len cand=99 orig=83; 1%match; codegen/regalloc | indirect_call |
| 993 | 0x00066d50 | FUN_00066d50 | MISMATCH | len cand=110 orig=88; 0%match; codegen/regalloc | indirect_call |
| 994 | 0x00066da8 | FUN_00066da8 | MISMATCH | len cand=250 orig=255; 13%match; codegen/regalloc | indirect_call |
| 995 | 0x00066ea8 | FUN_00066ea8 | MISMATCH | len cand=97 orig=300; 3%match; codegen/regalloc | indirect_call |
| 996 | 0x00066fd4 | FUN_00066fd4 | MISMATCH | len cand=7 orig=87; 0%match; codegen/regalloc |  |
| 997 | 0x0006702c | FUN_0006702c | MISMATCH | len cand=118 orig=100; 3%match; codegen/regalloc | indirect_call |
| 998 | 0x00067090 | FUN_00067090 | MISMATCH | len cand=36 orig=820; 0%match; codegen/regalloc | indirect_call |
| 999 | 0x000673c4 | FUN_000673c4 | MISMATCH | len cand=45 orig=75; 0%match; codegen/regalloc | indirect_call |
| 1000 | 0x00067410 | FUN_00067410 | MISMATCH | len cand=51 orig=52; 0%match; codegen/regalloc | indirect_call |
| 1001 | 0x00067444 | FUN_00067444 | MISMATCH | len cand=49 orig=43; 5%match; codegen/regalloc | indirect_call |
| 1002 | 0x00067470 | FUN_00067470 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call |
| 1003 | 0x00067580 | FUN_00067580 | MISMATCH | len cand=31 orig=43; 3%match; codegen/regalloc | indirect_call |
| 1004 | 0x000675ac | FUN_000675ac | MISMATCH | len cand=31 orig=47; 3%match; codegen/regalloc | indirect_call |
| 1005 | 0x000675dc | FUN_000675dc | MISMATCH | len cand=31 orig=48; 3%match; codegen/regalloc | indirect_call |
| 1006 | 0x0006760c | FUN_0006760c | MISMATCH | len cand=38 orig=32; 3%match; codegen/regalloc | indirect_call |
| 1007 | 0x0006762c | FUN_0006762c | MISMATCH | len cand=461 orig=248; 2%match; codegen/regalloc | indirect_call |
| 1008 | 0x00067730 | FUN_00067730 | MISMATCH | len cand=29 orig=56; 3%match; codegen/regalloc | indirect_call |
| 1009 | 0x00067768 | FUN_00067768 | MISMATCH | len cand=153 orig=128; 1%match; codegen/regalloc |  |
| 1010 | 0x000677e8 | FUN_000677e8 | COMPILE_FAIL | E1029:Expression must be 'pointer to ...' | extraout,indirect_call |
| 1011 | 0x00067850 | FUN_00067850 | MISMATCH | len cand=4 orig=7; 0%match; param-recovery | void_proto |
| 1012 | 0x00067858 | FUN_00067858 | MISMATCH | len cand=49 orig=45; 2%match; codegen/regalloc |  |
| 1013 | 0x00067885 | FUN_00067885 | MISMATCH | len cand=104 orig=103; 7%match; codegen/regalloc | indirect_call |
| 1014 | 0x000678ec | FUN_000678ec | MISMATCH | len cand=14 orig=26; 7%match; codegen/regalloc |  |
| 1015 | 0x00067906 | FUN_00067906 | MISMATCH | len cand=27 orig=40; 15%match; codegen/regalloc |  |
| 1016 | 0x0006792e | FUN_0006792e | MISMATCH | len cand=24 orig=1032; 8%match; param-recovery | indirect_call,void_proto |
| 1017 | 0x00067d38 | FUN_00067d38 | MISMATCH | len cand=16 orig=13; 0%match; codegen/regalloc |  |
| 1018 | 0x00067d45 | FUN_00067d45 | MISMATCH | len cand=16 orig=307; 0%match; codegen/regalloc |  |
| 1019 | 0x00067e78 | FUN_00067e78 | MISMATCH | len cand=212 orig=48; 2%match; codegen/regalloc |  |
| 1020 | 0x00067ea8 | FUN_00067ea8 | MISMATCH | len cand=89 orig=51; 4%match; codegen/regalloc | indirect_call |
| 1021 | 0x00067edb | FUN_00067edb | MISMATCH | len cand=142 orig=339; 3%match; codegen/regalloc | indirect_call |
| 1022 | 0x0006802e | FUN_0006802e | MISMATCH | len cand=236 orig=59; 5%match; codegen/regalloc | indirect_call |
| 1023 | 0x00068069 | FUN_00068069 | MISMATCH | len cand=55 orig=44; 0%match; codegen/regalloc |  |
| 1024 | 0x00068095 | FUN_00068095 | MISMATCH | len cand=27 orig=658; 0%match; codegen/regalloc |  |
| 1025 | 0x00068327 | FUN_00068327 | MISMATCH | len cand=57 orig=176; 2%match; codegen/regalloc |  |
| 1026 | 0x000683d7 | FUN_000683d7 | MISMATCH | len cand=330 orig=218; 3%match; codegen/regalloc | indirect_call |
| 1027 | 0x000684b1 | FUN_000684b1 | MISMATCH | len cand=85 orig=61; 0%match; codegen/regalloc |  |
| 1028 | 0x000684ee | FUN_000684ee | MISMATCH | len cand=10 orig=12; 0%match; codegen/regalloc |  |
| 1029 | 0x000684fa | FUN_000684fa | MISMATCH | len cand=107 orig=71; 23%match; codegen/regalloc | indirect_call |
| 1030 | 0x00068541 | FUN_00068541 | MISMATCH | len cand=73 orig=40; 5%match; codegen/regalloc | indirect_call |
| 1031 | 0x00068569 | FUN_00068569 | MISMATCH | len cand=64 orig=39; 8%match; codegen/regalloc | indirect_call |
| 1032 | 0x00068590 | FUN_00068590 | MISMATCH | len cand=81 orig=36; 3%match; codegen/regalloc | indirect_call |
| 1033 | 0x000685b4 | FUN_000685b4 | MISMATCH | len cand=73 orig=84; 4%match; codegen/regalloc | indirect_call |
| 1034 | 0x00068608 | FUN_00068608 | MISMATCH | len cand=73 orig=84; 4%match; codegen/regalloc | indirect_call |
| 1035 | 0x0006865c | FUN_0006865c | MISMATCH | len cand=80 orig=48; 6%match; codegen/regalloc | indirect_call |
| 1036 | 0x0006868c | FUN_0006868c | MISMATCH | len cand=81 orig=114; 2%match; codegen/regalloc | indirect_call |
| 1037 | 0x000686fe | FUN_000686fe | MISMATCH | len cand=10 orig=12; 0%match; codegen/regalloc |  |
| 1038 | 0x0006870a | FUN_0006870a | MISMATCH | len cand=48 orig=37; 0%match; param-recovery | indirect_call,void_proto |
| 1039 | 0x0006872f | FUN_0006872f | COMPILE_FAIL | E1010:Type mismatch | indirect_call |
| 1040 | 0x00068789 | FUN_00068789 | MISMATCH | len cand=215 orig=216; 5%match; codegen/regalloc | indirect_call |
| 1041 | 0x00068861 | FUN_00068861 | COMPILE_FAIL | E1080:Expression must be arithmetic | extraout,indirect_call,void_proto |
| 1042 | 0x00068902 | FUN_00068902 | COMPILE_FAIL | E1029:Expression must be 'pointer to ...' | extraout,indirect_call,void_proto |
| 1043 | 0x00068bca | FUN_00068bca | MISMATCH | len cand=16 orig=25; 12%match; param-recovery | void_proto |
| 1044 | 0x00068be3 | FUN_00068be3 | MISMATCH | len cand=965 orig=558; 3%match; param-recovery | indirect_call,void_proto |
| 1045 | 0x00068e11 | FUN_00068e11 | MISMATCH | len cand=262 orig=163; 1%match; param-recovery | indirect_call,void_proto |
| 1046 | 0x00068eb4 | FUN_00068eb4 | MISMATCH | len cand=152 orig=113; 4%match; param-recovery | indirect_call,void_proto |
| 1047 | 0x00068f25 | FUN_00068f25 | MISMATCH | len cand=932 orig=274; 2%match; codegen/regalloc | indirect_call |
| 1048 | 0x00069037 | FUN_00069037 | MISMATCH | len cand=83 orig=180; 2%match; param-recovery | indirect_call,void_proto |
| 1049 | 0x000690eb | FUN_000690eb | MISMATCH | len cand=22 orig=30; 14%match; codegen/regalloc |  |
| 1050 | 0x00069109 | FUN_00069109 | MISMATCH | len cand=14 orig=29; 6%match; codegen/regalloc | indirect_call |
| 1051 | 0x00069126 | FUN_00069126 | MISMATCH | len cand=65 orig=81; 2%match; codegen/regalloc | indirect_call |
| 1052 | 0x00069177 | FUN_00069177 | MISMATCH | len cand=11 orig=13; 0%match; codegen/regalloc | indirect_call |
| 1053 | 0x00069184 | FUN_00069184 | COMPILE_FAIL | E1045:Subscript on non-array |  |
| 1054 | 0x000691b7 | FUN_000691b7 | MISMATCH | len cand=226 orig=263; 2%match; codegen/regalloc | indirect_call |
| 1055 | 0x000692be | FUN_000692be | MISMATCH | len cand=11 orig=13; 0%match; codegen/regalloc | indirect_call |
| 1056 | 0x000692cb | FUN_000692cb | MISMATCH | @+0; 16%comparable-match; codegen/regalloc |  |
| 1057 | 0x000692f0 | FUN_000692f0 | MISMATCH | len cand=305 orig=320; 4%match; codegen/regalloc | indirect_call |
| 1058 | 0x00069430 | FUN_00069430 | COMPILE_FAIL | E1079:Expression must be integral | int64,void_proto |
| 1059 | 0x00069980 | FUN_00069980 | COMPILE_FAIL | E1081:Expression must be scalar type | indirect_call,int64,void_proto |
| 1060 | 0x00069e00 | FUN_00069e00 | COMPILE_FAIL | E1045:Subscript on non-array | indirect_call,void_proto |
| 1061 | 0x00069fb0 | FUN_00069fb0 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call,void_proto |
| 1062 | 0x0006a5d0 | FUN_0006a5d0 | MISMATCH | len cand=222 orig=191; 2%match; param-recovery | indirect_call,void_proto |
| 1063 | 0x0006a690 | FUN_0006a690 | MISMATCH | len cand=145 orig=144; 1%match; param-recovery | indirect_call,void_proto |
| 1064 | 0x0006a720 | FUN_0006a720 | MISMATCH | len cand=23 orig=47; 0%match; param-recovery | void_proto |
| 1065 | 0x0006a750 | FUN_0006a750 | MISMATCH | len cand=179 orig=111; 2%match; param-recovery | indirect_call,void_proto |
| 1066 | 0x0006a7c0 | FUN_0006a7c0 | MISMATCH | len cand=15 orig=16; 20%match; param-recovery | void_proto |
| 1067 | 0x0006a7d0 | FUN_0006a7d0 | MISMATCH | len cand=203 orig=223; 75%match; param-recovery | indirect_call,void_proto |
| 1068 | 0x0006a8b0 | FUN_0006a8b0 | MISMATCH | len cand=38 orig=48; 18%match; param-recovery | void_proto |
| 1069 | 0x0006a8e0 | FUN_0006a8e0 | MISMATCH | len cand=49 orig=63; 4%match; param-recovery | indirect_call,void_proto |
| 1070 | 0x0006a920 | FUN_0006a920 | MISMATCH | len cand=16 orig=31; 38%match; param-recovery | void_proto |
| 1071 | 0x0006a940 | FUN_0006a940 | MISMATCH | len cand=36 orig=176; 6%match; param-recovery | indirect_call,void_proto |
| 1072 | 0x0006a9f0 | FUN_0006a9f0 | MISMATCH | @+0; 38%comparable-match; param-recovery | void_proto |
| 1073 | 0x0006aa00 | FUN_0006aa00 | MISMATCH | len cand=128 orig=255; 9%match; param-recovery | indirect_call,void_proto |
| 1074 | 0x0006ab00 | FUN_0006ab00 | MISMATCH | len cand=91 orig=143; 1%match; param-recovery | void_proto |
| 1075 | 0x0006ab90 | FUN_0006ab90 | MISMATCH | len cand=19 orig=31; 16%match; param-recovery | void_proto |
| 1076 | 0x0006abb0 | FUN_0006abb0 | MISMATCH | len cand=31 orig=160; 23%match; param-recovery | void_proto |
| 1077 | 0x0006ac50 | FUN_0006ac50 | MISMATCH | len cand=12 orig=160; 0%match; param-recovery | void_proto |
| 1078 | 0x0006acf0 | FUN_0006acf0 | MISMATCH | len cand=153 orig=140; 4%match; param-recovery | indirect_call,void_proto |
| 1079 | 0x0006ad80 | FUN_0006ad80 | MISMATCH | len cand=58 orig=280; 14%match; param-recovery | void_proto |
| 1080 | 0x0006ae98 | FUN_0006ae98 | MISMATCH | len cand=55 orig=44; 5%match; codegen/regalloc | indirect_call |
| 1081 | 0x0006aec4 | FUN_0006aec4 | MISMATCH | len cand=1 orig=103; 0%match; param-recovery | void_proto |
| 1082 | 0x0006af2c | FUN_0006af2c | COMPILE_FAIL | E1081:Expression must be scalar type | indirect_call |
| 1083 | 0x0006b1a9 | FUN_0006b1a9 | MISMATCH | len cand=288 orig=234; 0%match; param-recovery | indirect_call,void_proto |
| 1084 | 0x0006b293 | FUN_0006b293 | MISMATCH | len cand=427 orig=515; 7%match; param-recovery | indirect_call,void_proto |
| 1085 | 0x0006b496 | FUN_0006b496 | MISMATCH | len cand=19 orig=70; 16%match; param-recovery | void_proto |
| 1086 | 0x0006b4e0 | FUN_0006b4e0 | MISMATCH | len cand=423 orig=447; 5%match; codegen/regalloc | indirect_call |
| 1087 | 0x0006b6a0 | FUN_0006b6a0 | MISMATCH | len cand=318 orig=588; 14%match; param-recovery | indirect_call,void_proto |
| 1088 | 0x0006b8f0 | FUN_0006b8f0 | MISMATCH | len cand=241 orig=704; 0%match; param-recovery | indirect_call,void_proto |
| 1089 | 0x0006bbb0 | FUN_0006bbb0 | MISMATCH | len cand=443 orig=463; 7%match; param-recovery | void_proto |
| 1090 | 0x0006bd80 | FUN_0006bd80 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call,int64,void_proto |
| 1091 | 0x0006c210 | FUN_0006c210 | MISMATCH | len cand=241 orig=207; 3%match; param-recovery | indirect_call,void_proto |
| 1092 | 0x0006c2e0 | FUN_0006c2e0 | MISMATCH | len cand=184 orig=176; 9%match; param-recovery | indirect_call,void_proto |
| 1093 | 0x0006c390 | FUN_0006c390 | MISMATCH | len cand=736 orig=575; 5%match; param-recovery | indirect_call,void_proto |
| 1094 | 0x0006c5d0 | FUN_0006c5d0 | MISMATCH | len cand=156 orig=219; 12%match; param-recovery | indirect_call,void_proto |
| 1095 | 0x0006c6b0 | FUN_0006c6b0 | MISMATCH | len cand=85 orig=2032; 1%match; param-recovery | indirect_call,void_proto |
| 1096 | 0x0006cea0 | FUN_0006cea0 | COMPILE_FAIL | E1045:Subscript on non-array | indirect_call,void_proto |
| 1097 | 0x0006cfd0 | FUN_0006cfd0 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call,int64,void_proto |
| 1098 | 0x0006d680 | FUN_0006d680 | MISMATCH | len cand=222 orig=191; 2%match; param-recovery | indirect_call,void_proto |
| 1099 | 0x0006d740 | FUN_0006d740 | MISMATCH | len cand=145 orig=144; 1%match; param-recovery | indirect_call,void_proto |
| 1100 | 0x0006d7d0 | FUN_0006d7d0 | MISMATCH | len cand=115 orig=159; 3%match; param-recovery | indirect_call,void_proto |
| 1101 | 0x0006d870 | FUN_0006d870 | MISMATCH | len cand=96 orig=128; 1%match; param-recovery | void_proto |
| 1102 | 0x0006d8f0 | FUN_0006d8f0 | MISMATCH | len cand=169 orig=160; 4%match; param-recovery | indirect_call,void_proto |
| 1103 | 0x0006d990 | FUN_0006d990 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call,void_proto |
| 1104 | 0x0006dd50 | FUN_0006dd50 | MISMATCH | len cand=67 orig=59; 3%match; param-recovery | indirect_call,void_proto |
| 1105 | 0x0006dd90 | FUN_0006dd90 | MISMATCH | len cand=223 orig=352; 4%match; param-recovery | indirect_call,void_proto |
| 1106 | 0x0006def0 | FUN_0006def0 | MISMATCH | len cand=62 orig=171; 2%match; param-recovery | indirect_call,void_proto |
| 1107 | 0x0006dfa0 | FUN_0006dfa0 | MISMATCH | len cand=147 orig=128; 9%match; param-recovery | indirect_call,void_proto |
| 1108 | 0x0006e020 | FUN_0006e020 | MISMATCH | len cand=1 orig=896; 0%match; param-recovery | void_proto |
| 1109 | 0x0006e3a0 | FUN_0006e3a0 | MISMATCH | len cand=131 orig=416; 3%match; param-recovery | void_proto |
| 1110 | 0x0006e540 | FUN_0006e540 | MISMATCH | len cand=380 orig=415; 4%match; param-recovery | indirect_call,void_proto |
| 1111 | 0x0006e6e0 | FUN_0006e6e0 | MISMATCH | len cand=336 orig=303; 4%match; param-recovery | indirect_call,void_proto |
| 1112 | 0x0006e810 | FUN_0006e810 | MISMATCH | len cand=53 orig=96; 28%match; param-recovery | void_proto |
| 1113 | 0x0006e870 | FUN_0006e870 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call,int64,void_proto |
| 1114 | 0x0006faf8 | FUN_0006faf8 | MISMATCH | len cand=62 orig=221; 5%match; codegen/regalloc |  |
| 1115 | 0x0006fbd5 | FUN_0006fbd5 | MISMATCH | len cand=92 orig=99; 4%match; codegen/regalloc |  |
| 1116 | 0x0006fc38 | FUN_0006fc38 | MISMATCH | len cand=16 orig=71; 6%match; codegen/regalloc |  |
| 1117 | 0x0006fc7f | FUN_0006fc7f | MISMATCH | len cand=142 orig=209; 1%match; codegen/regalloc | indirect_call |
| 1118 | 0x0006fd50 | FUN_0006fd50 | COMPILE_FAIL | E1052:Expression has void type |  |
| 1119 | 0x0006fd88 | FUN_0006fd88 | COMPILE_FAIL | E1052:Expression has void type |  |
| 1120 | 0x0006fdaa | FUN_0006fdaa | COMPILE_FAIL | E1090:Invalid conversion | extraout,indirect_call |
| 1121 | 0x0007002b | FUN_0007002b | COMPILE_FAIL | E1080:Expression must be arithmetic | indirect_call |
| 1122 | 0x0007015e | FUN_0007015e | MISMATCH | len cand=104 orig=91; 2%match; codegen/regalloc |  |
| 1123 | 0x000701b9 | FUN_000701b9 | MISMATCH | len cand=33 orig=36; 27%match; codegen/regalloc |  |
| 1124 | 0x000701dd | FUN_000701dd | MISMATCH | @+0; 3%comparable-match; codegen/regalloc |  |
| 1125 | 0x00070200 | FUN_00070200 | COMPILE_FAIL | E1063:Missing operand | ellipsis,indirect_call,raw_marker |
| 1126 | 0x00070261 | FUN_00070261 | MISMATCH | len cand=244 orig=219; 3%match; reg-artifact | extraout,indirect_call |
| 1127 | 0x0007033c | FUN_0007033c | MISMATCH | len cand=15 orig=7; 0%match; param-recovery | void_proto |
| 1128 | 0x00070343 | FUN_00070343 | MISMATCH | len cand=1203 orig=1097; 3%match; codegen/regalloc | indirect_call |
| 1129 | 0x0007078c | FUN_0007078c | MISMATCH | len cand=44 orig=121; 0%match; codegen/regalloc | indirect_call |
| 1130 | 0x00070805 | FUN_00070805 | EXACT | 1b | void_proto |
| 1131 | 0x00070806 | FUN_00070806 | MISMATCH | len cand=50 orig=24; 0%match; codegen/regalloc | indirect_call |
| 1132 | 0x0007081e | FUN_0007081e | MISMATCH | len cand=66 orig=22; 0%match; codegen/regalloc | indirect_call |
| 1133 | 0x00070834 | FUN_00070834 | MISMATCH | len cand=150 orig=195; 1%match; codegen/regalloc |  |
| 1134 | 0x000708f7 | FUN_000708f7 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call,int64 |
| 1135 | 0x00070a4b | FUN_00070a4b | MISMATCH | len cand=15 orig=135; 0%match; codegen/regalloc | indirect_call |
| 1136 | 0x00070ad2 | FUN_00070ad2 | MISMATCH | len cand=170 orig=16; 6%match; codegen/regalloc | indirect_call |
| 1137 | 0x00070ae2 | FUN_00070ae2 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call |
| 1138 | 0x00070b6b | FUN_00070b6b | MISMATCH | len cand=35 orig=47; 3%match; codegen/regalloc | indirect_call |
| 1139 | 0x00070b9a | FUN_00070b9a | COMPILE_FAIL | E1029:Expression must be 'pointer to ...' | extraout,indirect_call |
| 1140 | 0x00070c45 | FUN_00070c45 | MISMATCH | len cand=53 orig=66; 8%match; codegen/regalloc |  |
| 1141 | 0x00070c87 | FUN_00070c87 | MISMATCH | len cand=263 orig=252; 2%match; codegen/regalloc | indirect_call |
| 1142 | 0x00070d83 | FUN_00070d83 | COMPILE_FAIL | E1080:Expression must be arithmetic | indirect_call |
| 1143 | 0x00070f4d | FUN_00070f4d | COMPILE_FAIL | E1036:Right operand of '-' is a pointer | indirect_call |
| 1144 | 0x0007114d | FUN_0007114d | MISMATCH | len cand=22 orig=35; 14%match; codegen/regalloc | indirect_call |
| 1145 | 0x00071170 | FUN_00071170 | MISMATCH | len cand=22 orig=19; 16%match; codegen/regalloc | indirect_call |
| 1146 | 0x00071190 | FUN_00071190 | MISMATCH | len cand=284 orig=342; 6%match; codegen/regalloc |  |
| 1147 | 0x000712e6 | FUN_000712e6 | MISMATCH | len cand=204 orig=157; 1%match; codegen/regalloc |  |
| 1148 | 0x00071383 | FUN_00071383 | MISMATCH | len cand=119 orig=555; 4%match; codegen/regalloc | indirect_call |
| 1149 | 0x000715ae | FUN_000715ae | MISMATCH | len cand=136 orig=119; 3%match; codegen/regalloc | indirect_call |
| 1150 | 0x00071625 | FUN_00071625 | MISMATCH | len cand=152 orig=481; 4%match; codegen/regalloc | indirect_call |
| 1151 | 0x00071806 | FUN_00071806 | COMPILE_FAIL | E1052:Expression has void type | extraout |
| 1152 | 0x00071891 | FUN_00071891 | MISMATCH | len cand=234 orig=436; 3%match; codegen/regalloc | indirect_call |
| 1153 | 0x00071a45 | FUN_00071a45 | MISMATCH | len cand=234 orig=56; 0%match; codegen/regalloc | indirect_call |
| 1154 | 0x00071a7d | FUN_00071a7d | MISMATCH | len cand=263 orig=281; 4%match; codegen/regalloc | indirect_call |
| 1155 | 0x00071b96 | FUN_00071b96 | MISMATCH | len cand=263 orig=281; 4%match; codegen/regalloc | indirect_call |
| 1156 | 0x00071caf | FUN_00071caf | MISMATCH | len cand=63 orig=82; 2%match; codegen/regalloc | indirect_call |
| 1157 | 0x00071d01 | FUN_00071d01 | COMPILE_FAIL | E1010:Type mismatch | indirect_call |
| 1158 | 0x00071d50 | FUN_00071d50 | MISMATCH | len cand=137 orig=75; 1%match; codegen/regalloc |  |
| 1159 | 0x00071d9b | FUN_00071d9b | MISMATCH | len cand=143 orig=79; 3%match; codegen/regalloc |  |
| 1160 | 0x00071dea | FUN_00071dea | MISMATCH | len cand=14 orig=174; 0%match; codegen/regalloc | indirect_call |
| 1161 | 0x00071ea0 | FUN_00071ea0 | MISMATCH | len cand=29 orig=153; 3%match; codegen/regalloc |  |
| 1162 | 0x00071f40 | FUN_00071f40 | COMPILE_FAIL | E1052:Expression has void type |  |
| 1163 | 0x00071fe0 | FUN_00071fe0 | MISMATCH | len cand=64 orig=56; 5%match; codegen/regalloc |  |
| 1164 | 0x00072018 | FUN_00072018 | MISMATCH | len cand=35 orig=5; 20%match; codegen/regalloc | indirect_call |
| 1165 | 0x0007201d | FUN_0007201d | MISMATCH | len cand=26 orig=102; 0%match; codegen/regalloc | indirect_call |
| 1166 | 0x00072090 | FUN_00072090 | MISMATCH | len cand=28 orig=89; 4%match; codegen/regalloc |  |
| 1167 | 0x000720e9 | FUN_000720e9 | COMPILE_FAIL | E1052:Expression has void type |  |
| 1168 | 0x00072181 | FUN_00072181 | MISMATCH | len cand=27 orig=36; 0%match; codegen/regalloc |  |
| 1169 | 0x000721a5 | FUN_000721a5 | MISMATCH | len cand=27 orig=12; 0%match; codegen/regalloc |  |
| 1170 | 0x000721b1 | FUN_000721b1 | MISMATCH | len cand=21 orig=111; 0%match; codegen/regalloc |  |
| 1171 | 0x00072220 | FUN_00072220 | MISMATCH | len cand=183 orig=168; 6%match; codegen/regalloc | indirect_call |
| 1172 | 0x000722c8 | FUN_000722c8 | MISMATCH | len cand=64 orig=87; 0%match; codegen/regalloc |  |
| 1173 | 0x0007231f | FUN_0007231f | MISMATCH | len cand=1 orig=6; 0%match; param-recovery | void_proto |
| 1174 | 0x00072325 | FUN_00072325 | MISMATCH | len cand=47 orig=50; 0%match; codegen/regalloc | indirect_call |
| 1175 | 0x00072357 | FUN_00072357 | MISMATCH | len cand=37 orig=5; 0%match; thunk | indirect_call |
| 1176 | 0x0007235c | FUN_0007235c | MISMATCH | len cand=64 orig=217; 2%match; codegen/regalloc | indirect_call |
| 1177 | 0x00072436 | FUN_00072436 | MISMATCH | len cand=209 orig=166; 3%match; codegen/regalloc |  |
| 1178 | 0x000724de | FUN_000724de | COMPILE_FAIL | E1079:Expression must be integral |  |
| 1179 | 0x000725e9 | FUN_000725e9 | MISMATCH | len cand=65 orig=63; 0%match; codegen/regalloc |  |
| 1180 | 0x00072628 | FUN_00072628 | COMPILE_FAIL | E1029:Expression must be 'pointer to ...' | indirect_call |
| 1181 | 0x00072789 | FUN_00072789 | MISMATCH | len cand=119 orig=116; 10%match; codegen/regalloc |  |
| 1182 | 0x000727fd | FUN_000727fd | MISMATCH | len cand=61 orig=78; 2%match; codegen/regalloc |  |
| 1183 | 0x0007284b | FUN_0007284b | COMPILE_FAIL | E1080:Expression must be arithmetic | indirect_call |
| 1184 | 0x0007291e | FUN_0007291e | COMPILE_FAIL | E1052:Expression has void type | indirect_call |
| 1185 | 0x000729cd | FUN_000729cd | MISMATCH | len cand=322 orig=324; 4%match; codegen/regalloc | indirect_call |
| 1186 | 0x00072b11 | FUN_00072b11 | MISMATCH | len cand=100 orig=119; 3%match; codegen/regalloc | indirect_call |
| 1187 | 0x00072b88 | FUN_00072b88 | MISMATCH | len cand=1 orig=3; 0%match; param-recovery | void_proto |
| 1188 | 0x00072b8b | FUN_00072b8b | MISMATCH | len cand=91 orig=85; 4%match; codegen/regalloc | indirect_call |
| 1189 | 0x00072be0 | FUN_00072be0 | MISMATCH | len cand=22 orig=21; 10%match; codegen/regalloc |  |
| 1190 | 0x00072bf5 | FUN_00072bf5 | MISMATCH | len cand=1 orig=66; 0%match; param-recovery | void_proto |
| 1191 | 0x00072c37 | FUN_00072c37 | MISMATCH | len cand=8 orig=21; 0%match; param-recovery | indirect_call,void_proto |
| 1192 | 0x00072c4c | FUN_00072c4c | MISMATCH | len cand=41 orig=180; 15%match; param-recovery | indirect_call,void_proto |
| 1193 | 0x00072d00 | FUN_00072d00 | MISMATCH | len cand=57 orig=39; 3%match; param-recovery | indirect_call,void_proto |
| 1194 | 0x00072d27 | FUN_00072d27 | MISMATCH | len cand=88 orig=58; 0%match; param-recovery | indirect_call,void_proto |
| 1195 | 0x00072d61 | FUN_00072d61 | MISMATCH | len cand=70 orig=57; 5%match; param-recovery | indirect_call,void_proto |
| 1196 | 0x00072d9a | FUN_00072d9a | MISMATCH | len cand=63 orig=83; 1%match; codegen/regalloc | indirect_call |
| 1197 | 0x00072ded | FUN_00072ded | MISMATCH | len cand=53 orig=57; 0%match; codegen/regalloc | indirect_call |
| 1198 | 0x00072e26 | FUN_00072e26 | MISMATCH | len cand=43 orig=48; 0%match; codegen/regalloc | indirect_call |
| 1199 | 0x00072e56 | FUN_00072e56 | MISMATCH | len cand=53 orig=33; 0%match; codegen/regalloc | indirect_call |
| 1200 | 0x00072e77 | FUN_00072e77 | MISMATCH | len cand=173 orig=480; 1%match; codegen/regalloc | indirect_call |
| 1201 | 0x00073057 | FUN_00073057 | MISMATCH | len cand=101 orig=102; 4%match; codegen/regalloc | indirect_call |
| 1202 | 0x000730bd | FUN_000730bd | MISMATCH | len cand=69 orig=60; 3%match; param-recovery | indirect_call,void_proto |
| 1203 | 0x000730f9 | FUN_000730f9 | MISMATCH | len cand=100 orig=126; 11%match; param-recovery | indirect_call,void_proto |
| 1204 | 0x00073177 | FUN_00073177 | MISMATCH | len cand=197 orig=193; 1%match; codegen/regalloc | indirect_call |
| 1205 | 0x00073238 | FUN_00073238 | MISMATCH | len cand=238 orig=240; 4%match; codegen/regalloc | indirect_call |
| 1206 | 0x00073328 | FUN_00073328 | MISMATCH | len cand=18 orig=114; 6%match; param-recovery | indirect_call,void_proto |
| 1207 | 0x0007339c | FUN_0007339c | MISMATCH | len cand=43 orig=1059; 2%match; codegen/regalloc |  |
| 1208 | 0x000737c0 | FUN_000737c0 | MISMATCH | len cand=25 orig=22; 0%match; codegen/regalloc |  |
| 1209 | 0x000737d6 | FUN_000737d6 | MISMATCH | len cand=406 orig=146; 1%match; reg-artifact | extraout,indirect_call |
| 1210 | 0x00073868 | FUN_00073868 | MISMATCH | len cand=10 orig=18; 10%match; param-recovery | void_proto |
| 1211 | 0x0007387a | FUN_0007387a | MISMATCH | len cand=10 orig=19; 10%match; param-recovery | void_proto |
| 1212 | 0x0007388d | FUN_0007388d | MISMATCH | len cand=10 orig=39; 10%match; param-recovery | void_proto |
| 1213 | 0x000738b4 | FUN_000738b4 | MISMATCH | len cand=20 orig=44; 5%match; param-recovery | void_proto |
| 1214 | 0x000738e0 | FUN_000738e0 | MISMATCH | len cand=133 orig=43; 2%match; codegen/regalloc |  |
| 1215 | 0x0007390b | FUN_0007390b | MISMATCH | len cand=133 orig=43; 2%match; codegen/regalloc |  |
| 1216 | 0x00073936 | FUN_00073936 | MISMATCH | len cand=11 orig=70; 9%match; param-recovery | void_proto |
| 1217 | 0x0007397c | FUN_0007397c | MISMATCH | len cand=47 orig=60; 2%match; codegen/regalloc |  |
| 1218 | 0x000739b8 | FUN_000739b8 | MISMATCH | len cand=18 orig=26; 6%match; param-recovery | indirect_call,void_proto |
| 1219 | 0x000739d2 | FUN_000739d2 | MISMATCH | len cand=74 orig=50; 6%match; param-recovery | indirect_call,void_proto |
| 1220 | 0x00073a04 | FUN_00073a04 | MISMATCH | len cand=282 orig=192; 6%match; codegen/regalloc | indirect_call |
| 1221 | 0x00073ac4 | FUN_00073ac4 | MISMATCH | len cand=44 orig=2822; 2%match; param-recovery | indirect_call,void_proto |
| 1222 | 0x000745ca | FUN_000745ca | MISMATCH | len cand=78 orig=311; 3%match; codegen/regalloc |  |
| 1223 | 0x00074701 | FUN_00074701 | MISMATCH | len cand=36 orig=1274; 6%match; codegen/regalloc |  |
| 1224 | 0x00074c00 | FUN_00074c00 | MISMATCH | len cand=101 orig=56; 2%match; codegen/regalloc | indirect_call |
| 1225 | 0x00074c38 | FUN_00074c38 | MISMATCH | len cand=20 orig=934; 0%match; param-recovery | void_proto |
| 1226 | 0x00074fde | FUN_00074fde | COMPILE_FAIL | E1010:Type mismatch |  |
| 1227 | 0x00074ff8 | FUN_00074ff8 | MISMATCH | len cand=183 orig=19; 0%match; reg-artifact | extraout,indirect_call |
| 1228 | 0x0007500b | FUN_0007500b | MISMATCH | len cand=58 orig=38; 3%match; codegen/regalloc |  |
| 1229 | 0x00075031 | FUN_00075031 | COMPILE_FAIL | E1080:Expression must be arithmetic | indirect_call |
| 1230 | 0x00075147 | FUN_00075147 | MISMATCH | len cand=258 orig=385; 4%match; codegen/regalloc | indirect_call |
| 1231 | 0x000752c8 | FUN_000752c8 | COMPILE_FAIL | E1079:Expression must be integral | ellipsis,indirect_call,int64,raw_marker |
| 1232 | 0x00075406 | FUN_00075406 | MISMATCH | len cand=17 orig=59; 18%match; codegen/regalloc |  |
| 1233 | 0x00075441 | FUN_00075441 | MISMATCH | len cand=89 orig=229; 3%match; reg-artifact | extraout,indirect_call |
| 1234 | 0x00075526 | FUN_00075526 | MISMATCH | len cand=36 orig=40; 0%match; param-recovery | indirect_call,void_proto |
| 1235 | 0x0007554e | FUN_0007554e | MISMATCH | len cand=848 orig=691; 2%match; reg-artifact | extraout,indirect_call |
| 1236 | 0x00075801 | FUN_00075801 | MISMATCH | len cand=13 orig=8192; 0%match; codegen/regalloc |  |
| 1237 | 0x0007787b | FUN_0007787b | MISMATCH | len cand=120 orig=147; 1%match; codegen/regalloc |  |
| 1238 | 0x0007790e | FUN_0007790e | MISMATCH | len cand=90 orig=44; 0%match; codegen/regalloc |  |
| 1239 | 0x0007793a | FUN_0007793a | MISMATCH | len cand=65 orig=587; 3%match; codegen/regalloc | indirect_call |
| 1240 | 0x00077b86 | FUN_00077b86 | MISMATCH | len cand=85 orig=74; 7%match; codegen/regalloc |  |
| 1241 | 0x00077bd0 | FUN_00077bd0 | MISMATCH | len cand=23 orig=27; 26%match; codegen/regalloc | indirect_call |
| 1242 | 0x00077beb | FUN_00077beb | MISMATCH | len cand=11 orig=54; 7%match; codegen/regalloc | indirect_call |
| 1243 | 0x00077c22 | FUN_00077c22 | MISMATCH | len cand=92 orig=73; 3%match; codegen/regalloc |  |
| 1244 | 0x00077c6b | FUN_00077c6b | MISMATCH | len cand=23 orig=27; 26%match; codegen/regalloc | indirect_call |
| 1245 | 0x00077c86 | FUN_00077c86 | COMPILE_FAIL | E1052:Expression has void type | indirect_call |
| 1246 | 0x00077cd2 | FUN_00077cd2 | MISMATCH | len cand=78 orig=5; 0%match; codegen/regalloc | indirect_call |
| 1247 | 0x00077cd7 | FUN_00077cd7 | MISMATCH | len cand=73 orig=47; 0%match; codegen/regalloc | indirect_call |
| 1248 | 0x00077d06 | FUN_00077d06 | MISMATCH | len cand=38 orig=29; 10%match; codegen/regalloc |  |
| 1249 | 0x00077d23 | FUN_00077d23 | MISMATCH | len cand=37 orig=151; 0%match; param-recovery | indirect_call,void_proto |
| 1250 | 0x00077dba | FUN_00077dba | MISMATCH | len cand=52 orig=14; 0%match; reg-artifact | extraout,indirect_call,void_proto |
| 1251 | 0x00077dcb | FUN_00077dcb | MISMATCH | len cand=89 orig=82; 2%match; codegen/regalloc | indirect_call |
| 1252 | 0x00077e1d | FUN_00077e1d | COMPILE_FAIL | E1052:Expression has void type | indirect_call |
| 1253 | 0x00077e9e | FUN_00077e9e | MISMATCH | len cand=35 orig=55; 3%match; codegen/regalloc | indirect_call |
| 1254 | 0x00077ed5 | FUN_00077ed5 | MISMATCH | len cand=36 orig=43; 3%match; codegen/regalloc |  |
| 1255 | 0x00077f00 | FUN_00077f00 | MISMATCH | len cand=23 orig=101; 0%match; codegen/regalloc |  |
| 1256 | 0x00077f65 | FUN_00077f65 | MISMATCH | len cand=11 orig=218; 64%match; param-recovery | void_proto |
| 1257 | 0x0007803f | FUN_0007803f | COMPILE_FAIL | E1010:Type mismatch | indirect_call |
| 1258 | 0x000782c0 | FUN_000782c0 | MISMATCH | len cand=145 orig=108; 2%match; codegen/regalloc |  |
| 1259 | 0x0007832c | FUN_0007832c | MISMATCH | len cand=71 orig=52; 4%match; codegen/regalloc |  |
| 1260 | 0x00078360 | FUN_00078360 | MISMATCH | len cand=67 orig=28; 0%match; codegen/regalloc |  |
| 1261 | 0x0007837c | FUN_0007837c | COMPILE_FAIL | E1052:Expression has void type |  |
| 1262 | 0x00078410 | FUN_00078410 | MISMATCH | len cand=61 orig=40; 2%match; codegen/regalloc | indirect_call |
| 1263 | 0x00078438 | FUN_00078438 | MISMATCH | len cand=15 orig=25; 0%match; codegen/regalloc |  |
| 1264 | 0x00078451 | FUN_00078451 | MISMATCH | len cand=17 orig=46; 0%match; codegen/regalloc | indirect_call |
| 1265 | 0x0007847f | FUN_0007847f | MISMATCH | len cand=97 orig=78; 1%match; codegen/regalloc | indirect_call |
| 1266 | 0x000784cd | FUN_000784cd | MISMATCH | len cand=206 orig=375; 4%match; codegen/regalloc | indirect_call |
| 1267 | 0x00078644 | FUN_00078644 | MISMATCH | len cand=34 orig=38; 26%match; codegen/regalloc |  |
| 1268 | 0x0007866a | FUN_0007866a | MISMATCH | len cand=152 orig=185; 4%match; codegen/regalloc | indirect_call |
| 1269 | 0x00078724 | FUN_00078724 | COMPILE_FAIL | E1045:Subscript on non-array | void_proto |
| 1270 | 0x00078984 | FUN_00078984 | MISMATCH | len cand=192 orig=240; 2%match; codegen/regalloc |  |
| 1271 | 0x00078a74 | FUN_00078a74 | MISMATCH | len cand=46 orig=70; 0%match; codegen/regalloc |  |
| 1272 | 0x00078aba | FUN_00078aba | MISMATCH | len cand=46 orig=87; 4%match; codegen/regalloc |  |
| 1273 | 0x00078b12 | FUN_00078b12 | MISMATCH | len cand=44 orig=263; 7%match; param-recovery | void_proto |
| 1274 | 0x00078c20 | FUN_00078c20 | COMPILE_FAIL | E1010:Type mismatch |  |
| 1275 | 0x00078cc0 | FUN_00078cc0 | MISMATCH | len cand=843 orig=767; 3%match; codegen/regalloc |  |
| 1276 | 0x00078fc0 | FUN_00078fc0 | MISMATCH | len cand=159 orig=112; 2%match; codegen/regalloc |  |
| 1277 | 0x00079030 | FUN_00079030 | MISMATCH | len cand=210 orig=144; 1%match; codegen/regalloc | indirect_call |
| 1278 | 0x000790c0 | FUN_000790c0 | MISMATCH | len cand=1 orig=16; 0%match; param-recovery | void_proto |
| 1279 | 0x000790d0 | FUN_000790d0 | MISMATCH | len cand=79 orig=48; 0%match; codegen/regalloc |  |
| 1280 | 0x00079100 | FUN_00079100 | MISMATCH | len cand=77 orig=48; 0%match; codegen/regalloc |  |
| 1281 | 0x00079130 | FUN_00079130 | MISMATCH | len cand=380 orig=688; 3%match; codegen/regalloc | indirect_call |
| 1282 | 0x000793e0 | FUN_000793e0 | MISMATCH | len cand=546 orig=4560; 2%match; codegen/regalloc |  |
| 1283 | 0x0007a5b0 | FUN_0007a5b0 | COMPILE_FAIL | E1079:Expression must be integral |  |
| 1284 | 0x0007b900 | FUN_0007b900 | COMPILE_FAIL | E1010:Type mismatch |  |
| 1285 | 0x0007baf0 | FUN_0007baf0 | COMPILE_FAIL | E1079:Expression must be integral | indirect_call |
