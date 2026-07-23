# Decompiler bug report: `CALLOTHER`/`SBORROW`/`POPCOUNT` leak the `NAME(...)` catch-all (FIXED)

**Owner: decompiler track (`master`). Status: FIXED** (this commit). Surfaced by the WAR2
recompilation-parity survey (docs/war2-function-status.md) as the top COMPILE_FAIL feeder:
`E1063 Missing operand` on an unrendered `...` operand.

## Symptom

The emitted C for many WAR2 functions contained tokens like `CALLOTHER(...)`, `INT_SBORROW(...)`,
and `POPCOUNT(...)`. Watcom `wcc386` rejects the `...` as a missing operand:

```
E1063: Missing operand
```

Across the 1286-function survey the leak affected **118 functions** (`ellipsis`/`callother`
smell). `E1063 Missing operand` was the single largest COMPILE_FAIL class (113 of 229).

## Root cause — an unported printer catch-all

`PrintC::render_op` (`src/decompile/printc.rs`) had a final catch-all arm

```rust
other => (format!("{}(...)", other.name()), 16),
```

that rendered any opcode without a dedicated arm as `<OPCODE_NAME>(...)` — a placeholder, not
Ghidra's actual rendering. Three faithful ops hit it:

| Op | Ghidra rendering | Ghidra ref |
|---|---|---|
| `CPUI_CALLOTHER` | `<userop-name>(in1,..,inN)` (input 0 is the userop index, skipped) | `PrintC::opCallother`, printc.cc:673 |
| `CPUI_INT_SBORROW` | `SBORROW<in0-size>(a,b)` | `TypeOpIntSborrow::getOperatorName`, typeop.cc:1372 |
| `CPUI_POPCOUNT` | `POPCOUNT(x)` | `TypeOpPopcount` (`TypeOpFunc`), typeop.cc:2558 |

For `CALLOTHER`, the printer additionally needs the SLEIGH user-op table to turn the input-0
index into the `define pcodeop` name (`TypeOpCallother::getOperatorName` → `UserOpSymbol` name).
mosura decoded the `.sla` USEROP symbols as `Symbol::Other`, discarding the index→name map, so
even a dedicated arm had nothing to resolve against.

## Fix — port the faithful renders + thread the user-op table

1. **`Spec::userops`** (`sleigh/engine.rs`): capture the `.sla` `<userop_head>` name +
   `<userop>` `index` (Ghidra `UserOpSymbol::decode`, slghsymbol.cc:377) into an index→name map
   (x86-64: 1756 userops; `in`=1, `cpuid`=44, `rdtsc`=74, `swi`=16).
2. **`Funcdata::userops`** (`funcdata.rs`): the analog of `Architecture::userops`, copied from the
   `Spec` by `build_from_instrs` (`build.rs`) — the same threading as `laned`/`proto_model`.
3. **printc arms** (`printc.rs`): `CALLOTHER` → `<userop>(args)` (Ghidra `opCallother`, functional
   display — the only form a `define pcodeop` takes); `INT_SBORROW` → `SBORROW<sz>(a,b)`;
   `POPCOUNT` → `POPCOUNT(x)`. All match Ghidra's compact functional comma (`spacing=0`,
   printc.cc:57), consistent with the existing `SUB`/`CONCAT` arms.

The `SBORROW<n>`/`POPCOUNT`/`SUB`/`CONCAT` macros are already in the survey prelude; the userop
pseudo-calls (`in`, `cpuid`, …) compile as C89 implicit-`int` functions (a warning, not an error).

## Verification

- **Regression test** `printc::tests::callother_renders_as_userop_name`: lifts `in eax,dx; ret`
  and `rdtsc; ret`, asserts the render is `in(...)`/`rdtsc()` and never `CALLOTHER(...)`. Fails on
  the pre-fix catch-all.
- **Corpus**: byte-identical (0.9513/57) — the new arms fire only on ops that previously hit the
  catch-all, none of which appear in the x86-64 corpus.
- **WAR2 re-measure**: `E1063 Missing operand` 113 → 4 (the 4 residual are `MULTIEQUAL`/`INDIRECT`
  raw-marker leaks — a distinct upstream class, not CALLOTHER); COMPILE_FAIL 229 → 137 (**92
  functions now compile**), zero regressions.

## Residual (not this fix)

`MULTIEQUAL(...)` (×4) and `INDIRECT(...)` (×1) still hit the catch-all — these are raw p-code ops
that should have been eliminated by SSA-out/structuring before printing (a `raw_marker`, upstream
IR gap), not functional ops with a faithful C rendering. Left for a separate investigation.
