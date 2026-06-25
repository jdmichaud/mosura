# Master plan — a faithful port of Ghidra's decompiler to Rust

> This supersedes the feature-by-feature approach in `decompiler-plan.md`,
> `floats-plan.md`, `switches-plan.md`, `type-system-plan.md` (kept for history).
> `TODO.md` tracks live status against the phases here.

## 0. The reframe (why this plan exists)

**The objective is to convert Ghidra's decompiler into Rust** — a *translation* of a known
C++ program (`../ghidra/Ghidra/Features/Decompiler/src/decompile/cpp`, ~100k LOC). It is
large but bounded and achievable. It is **not** "build a decompiler whose output looks
similar to Ghidra's."

The previous execution optimized a **proxy**: a token-skeleton *structural similarity*
score of mosura's final C against Ghidra's final C, over ~50 datatests
(`tests/datatest_score.rs`). That proxy **diverges from the objective** in two fatal ways:

1. **It rewards approximations and punishes faithfulness.** A hand-rolled heuristic whose
   output coincidentally shares tokens with Ghidra's scores *higher* than a faithful
   algorithm that produces correct-but-different output. Every "more correct but
   net-negative, reverted" result (GP varnode-overlap, call-arg recovery, MULTIEQUAL
   collapse) was this. We were optimizing *away* from Ghidra.
2. **Approximations don't compose.** Overlap needs heritage refinement needs the real
   SSA needs the real `Varnode` model. Each was approximated independently, so each new
   faithful piece collided with the hacks around it. That is the wall we hit.

**The fix:** a faithful **structural port** of Ghidra's architecture (its data model and
its `Action`/`Rule` pipeline), validated against Ghidra's **intermediate IR, exactly,
stage by stage**. Then faithfulness *is* the metric, a faithful change can never score
worse, and the pieces compose because it is the same architecture.

## 1. Keep vs. rebuild

- **Keep:** the SLEIGH engine (`src/sleigh/`) — bytes → instructions + raw p-code, at
  254/254 parity across 6 arches. The oracle infrastructure (`oracle/capture`,
  `scripts/setup-oracle.sh`, `goldens/`).
- **Rebuild (the work):** everything after raw p-code — the decompiler core — around
  Ghidra's model.
- The original `src/decomp/` prototype (a similarity-chasing approximation) has been
  **removed** — the faithful pipeline fully superseded it. All decompiler work now lives in
  `src/decompile/`, mirroring Ghidra's file layout.

## 2. The architecture to port (dependency order)

Ghidra's decompiler is a **generic `Action`/`Rule` pipeline that mutates a `Funcdata` to a
fixpoint**, then structures and prints. The spine — the framework — is the single most
important thing the current code lacks; with it, every rule is a self-contained,
testable, composable translation unit.

| # | Component | Ghidra source | Why it matters |
|---|---|---|---|
| **Data model** | `Varnode`, `PcodeOp`, `BlockBasic`/`BlockGraph`, `Funcdata`, `AddrSpace`/`Address` | `varnode.cc`, `op.cc`, `block.cc`, `funcdata*.cc`, `address.cc` | Ghidra's SSA **is** the Varnode graph (each Varnode = one SSA value, one def, many uses, with flags `input/written/addrtied/mapped/persist/…`). Fundamentally different from the current "uses-map over original ops". The foundation. |
| **Framework** | `Action`, `Rule`, `ActionGroup`, `ActionPool`, `ActionDatabase` | `action.cc`, `coreaction.cc` | The fixpoint driver. The keystone that makes everything compose. |
| **Heritage** | `Heritage`, `ActionHeritage` | `heritage.cc` | The real SSA: LocationMap, disjoint cover, `guard`/`refinement` (`normalizeReadSize`/`WriteSize`), INDIRECT/MULTIEQUAL placement, addrtied. **Overlap, CONCAT, phi-leaks all become consequences, not features.** |
| **Rules** | ~200 `Rule`s | `ruleaction.cc`, `coreaction.cc` | Constant fold, copy/algebraic propagation, the simplification fixpoint. |
| **Dead code** | `ActionDeadCode` | `coreaction.cc` | |
| **Types** | `TypeFactory`, `Datatype`, `ActionInferTypes` | `type.cc`, `coreaction.cc` | Widths, signedness, pointers, structs, arrays. |
| **Merge** | `Merge`, `HighVariable`, `Cover` | `merge.cc`, `cover.cc`, `variable.cc` | SSA varnodes → named C variables (the symbolic-vs-inlined decision). |
| **Prototypes** | `FuncProto`, `ParamActive`, `ParamList*`, `AncestorRealistic` | `fspec.cc`, `funcdata_varnode.cc` | Real call-argument and return recovery. |
| **Structuring** | `BlockGraph::collapse`, `ActionBlockStructure` | `block.cc`, `blockaction.cc` | CFG → if/else/while/for/switch (+`goto`). |
| **Print** | `PrintC`, `PrintLanguage` | `printc.cc`, `printlanguage.cc` | Structured blocks + folded expressions → C, with the explicit/implicit + cast model. |

## 3. Validation — IR-exact, per phase (the heart of this plan)

Ghidra's `decomp_dbg` console can dump the `Funcdata` after any action (`print raw` =
the SSA op tree; `print C` = the C; XML save = full state). So **every phase has its own
oracle**, exactly as disasm/p-code did.

- **Extend `oracle/capture`** to drive `decomp_dbg` to each named action breakpoint and
  emit Ghidra's IR there: raw p-code (have it), post-heritage SSA tree, post-typeinfer,
  post-merge, structured block tree, final C.
- **mosura emits the same IR** at each stage; a new test suite (`tests/ir_parity.rs`)
  diffs mosura's IR against Ghidra's **structurally exact** (the op/varnode graph, modulo
  deterministic varnode naming) — not fuzzy token similarity.
- This is the gate. **The structural-similarity score (`datatest_score`) is demoted to a
  coarse secondary gauge of overall progress — never again a gate that can block a
  faithful change.**

## 4. Phases (the to-do; live status in `TODO.md`)

Build the faithful pipeline **alongside** the prototype. The prototype keeps the corpus
measurable; the faithful path is gated by IR-parity; switch each stage over when its
IR-parity is green; the structural score should *jump* as faithfulness lands.

- **P0 — Foundation.** (a) Extend the oracle to dump Ghidra's per-phase IR. (b) The
  `Varnode`/`PcodeOp`/`BlockBasic`/`Funcdata` graph data model (with flags). (c) The
  `Action`/`Rule` framework skeleton + one trivial action, IR-diffed end-to-end. (d)
  `tests/ir_parity.rs` harness.
- **P1 — Heritage.** Port `Heritage` faithfully; gate on post-heritage IR-parity.
- **P2 — Rule pool.** Port `ActionPool` + the simplification `Rule`s; IR-parity.
- **P3 — Dead code.** `ActionDeadCode`; IR-parity.
- **P4 — Types.** `TypeFactory` + `ActionInferTypes`; IR-parity on inferred types.
- **P5 — Merge.** `Merge`/`HighVariable`/`Cover`; IR-parity on the variable grouping.
- **P6 — Prototypes.** `FuncProto`/`ParamActive`/`AncestorRealistic`; IR-parity on
  recovered params/returns.
- **P7 — Structuring.** `BlockGraph::collapse`; IR-parity on the structured block tree.
- **P8 — PrintC.** The real `PrintC`; **C-exact** parity (this is where the structural
  score should reach ~1.0 on covered functions).

Each phase: translate the C++ → IR-diff against Ghidra on the datatests → retire the
corresponding prototype code → record gotchas in memory.

## 5. Method & discipline

- **Translate, don't reinvent.** The C++ is the spec; when behavior is ambiguous, the
  C++ decides. (Same principle as before — but now enforced by IR-parity, not a fuzzy
  score, so it can't be gamed in either direction.)
- **Mirror Ghidra's structure** (file names, class/method names, the `Funcdata` contract)
  so a diff is always meaningful and the next file is always findable.
- **IR-parity is the gate.** Don't move to phase N+1 until phase N's IR matches Ghidra on
  the datatests.
- Keep the SLEIGH engine and its 254/254 parity untouched.

## 6. Honest scope

Large — Ghidra's decompiler is ~100k lines of C++ — and this is a multi-month effort. But
it is **bounded** (a finite codebase), **compounding** (every file ported is permanent
progress, not a revert-prone tweak), and **composing** (faithful pieces interact only
through the same `Funcdata` contract Ghidra uses). That is precisely what the
approximation approach was not.
