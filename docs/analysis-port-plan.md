# Plan — a faithful port of Ghidra's auto-analysis to Rust

> Sibling to [`port-plan.md`](port-plan.md). That plan ports Ghidra's **decompiler**
> (`decompile/cpp`, one function at a time). This one ports Ghidra's **auto-analysis** —
> the subsystem that takes a raw binary and decides *what to decompile in the first
> place*. `TODO.md` tracks live status against the phases here (the `A`-phase checklist).

## 0. The reframe (what auto-analysis is, and why it's a separate track)

mosura today decompiles **one function whose location and bytes are already known**: the
datatests hand it a memory image (`<bytechunk>`), the function entry as a named
`<symbol>`, and a script that says "decompile *this* address." `pipeline::decompile(&mut
Funcdata)` works on that single, pre-identified function.

**Auto-analysis is the layer above that** — it takes a binary *file* and produces the
facts the decompiler consumes: where code is, where functions start, what they reference,
what is data. In Ghidra this is a **different subsystem from the decompiler**, and it
lives almost entirely in **Java** (`Ghidra/Features/Base/.../app/plugin/core/analysis`
and analyzers scattered across the tree), *not* in the C++ `decompile/cpp` that
`port-plan.md` mirrors.

So this is a **second, largely orthogonal port**, not the next phase of the decompiler
port. The same discipline applies — translate Ghidra faithfully, validate against
Ghidra — but the reference source and the oracle are different (see §3).

## 1. Keep vs. rebuild — what mosura already has that helps

- **Keep / reuse:** the SLEIGH engine (`src/sleigh/`) is the disassembler the *disassembly
  analyzer* drives — bytes → instructions + raw p-code, 254/254. Usually the single
  hardest part of an analysis engine; already done. The p-code **interpreter**
  (`sleigh::emu`) is the concrete sibling of `SymbolicPropogator` (§2) — same p-code
  substrate, different value domain. The faithful **decompiler** (`src/decompile/`) is
  what the decompiler-driven analyzers (A6) call.
- **Reuse from the decompiler port:** `Address`/`AddrSpace`/`SpaceManager`
  (`src/decompile/space.rs`) — the Program model (A1) builds on these rather than
  redefining them.
- **Rebuild (the work):** the Program database, loaders, the analyzer framework, and the
  analyzers themselves — none of which exist today (fixtures fake the Program).
- The prototype `src/decomp/jumptable.rs` is a partial slice of switch recovery; it is
  retired by A6 (the decompiler-driven switch analyzer), not extended.

## 2. The architecture to port (dependency order)

Ghidra's auto-analysis is an **event-driven priority worklist that mutates a `Program` to
a fixpoint**: analyzers run in priority order, each consumes an address set of "facts that
appeared," and their Program mutations generate change events that schedule more work for
other analyzers. The framework is the keystone — the analog of the `Action`/`Rule` driver
in the decompiler port.

Reference source is now a real checkout at tag `Ghidra_12.0.3_build`, so these are loose
`.java` files at the canonical paths below.

| Component | Ghidra source | Why it matters |
|---|---|---|
| **Program model** | `program/model/{listing,mem,address,symbol}/*`, `program/database/*` (in `Framework/SoftwareModeling`) | `Program`/`Memory`/`MemoryBlock`/`Listing`/`CodeUnit`/`SymbolTable`/`ReferenceManager`/`FunctionManager`. The shared mutable state every analyzer reads/writes — the `Funcdata`-equivalent foundation, which mosura wholly lacks today. |
| **Framework** | `app/plugin/core/analysis/{AutoAnalysisManager,AnalysisScheduler}.java`, `app/services/{Analyzer,AbstractAnalyzer,AnalysisPriority}.java` (in `Features/Base`) | The fixpoint driver: priority queue + per-analyzer address-set accumulators + the change-event refeed. The keystone that makes every analyzer a composable unit. |
| **Loader** | `app/util/opinion/ElfLoader.java`, `app/util/bin/format/elf/*` (in `Features/Base`) | File → memory blocks (+perms), relocations, symbol import, entry points. Replaces the `<bytechunk>` fixture model with real files. Pure parsing; no oracle dependency. |
| **Disasm + functions** | the disassembler + `CreateFunctionCmd` / function-start (FID) analyzers | Recursive disassembly from entry points (drives the SLEIGH engine — mostly wiring) + function creation at call targets. |
| **Refs + value analysis** | `program/util/SymbolicPropogator.java`, `app/plugin/core/analysis/ConstantPropagationAnalyzer.java` (+ per-arch subclasses) | Abstract interpretation over p-code → data & code references. The one heavyweight new component; prerequisite for switch tables. |
| **Decompiler-driven** | `app/plugin/core/analysis/DecompilerSwitchAnalyzer.java` (in `Features/Decompiler`), `DecompilerFunctionAnalyzer`/parameter-ID | Run the decompiler per function and read back switch tables / recovered params. Depends on the decompiler port — the convergence point of the two tracks. |
| **The tail** | non-returning-function, shared-return, stack/purge, GNU/MS demangler, strings/data analyzers | Each a self-contained analyzer gated on Program-state parity. |

### 2a. The framework loop, precisely (the keystone)

- One global **`PriorityQueue<BackgroundCommand>`** keyed by an `int` priority — **lower
  runs first**.
- Each analyzer is wrapped in an **`AnalysisScheduler`** holding two accumulator
  `AddressSet`s (`addSet`/`removeSet`). Schedulers are grouped by **`AnalyzerType`** into
  task lists: `byte`, `instruction`, `function`, `functionModifierChanged`,
  `functionSignatureChanged`, `data`.
- **Cross-analyzer wiring is by *kind of fact discovered*, not direct calls.** The manager
  exposes `codeDefined(set)`, `functionDefined(set)`, `dataDefined(set)`,
  `blockAdded(set)`, `externalAdded`, `functionModifierChanged`,
  `functionSignatureChanged`. Each routes to the matching task list, which fans out to
  every scheduler in it: the scheduler ORs the set into its `addSet` and, if not already
  queued, pushes a task at the analyzer's priority.
- **The loop** (`AutoAnalysisManager.startAnalysis`): pop the lowest-priority task, run it.
  When an analyzer runs (`AnalysisScheduler.runAnalyzer`) it **atomically swaps out its
  accumulated sets** (resetting them, clearing `scheduled`) and calls `analyzer.added(
  program, savedSet, …)`. The analyzer mutates the Program; those mutations fire **change
  events** (`handleCodeAdded`, `handleFunctionAddedOrBodyChanged`) that call the `*Defined`
  notifiers → which enqueue more tasks. Repeat until the queue drains → `analysisEnded`.
- **Priorities** are a fixed ladder, 100 apart (`AnalysisPriority`): FORMAT 100 → BLOCK 200
  (entry-point disassembly) → DISASSEMBLY 300 → CODE 400 → FUNCTION 500 → REFERENCE 600 →
  DATA 700 → FUNCTION_ID 800 → DATA_TYPE_PROPAGATION 900 → LOW 10000, with `before()`/
  `after()` giving ±1 nudges. An analyzer declares where it sits relative to these.
- **`yield`**: an analyzer can recursively trigger higher-priority work mid-run (e.g.
  disassembly inside function analysis) and yield via a `yieldedTasks` stack bounded by a
  `limitPriority`.

**Rust translation:** a `BinaryHeap` keyed by `i32` + a `Scheduler` per analyzer holding
`AddressSet` accumulators + an `enum FactKind { Code, Function, Data, Block, … }` routing
layer + a `trait Analyzer { fn added(&self, prog, set) -> bool; fn priority(); fn ty(); }`.
The trickiest faithful part is the **change-event refeed**: Ghidra turns DB mutations into
new work via the `DomainObject` change-event queue (`flushPrivateEventQueue`). Replicate
it with an explicit "pending changes" channel that DB writes append to, drained between
tasks; port the `ignoreChanges` flag (suppresses refeed during certain ops). Single-
threaded is fine — the parallelism here is incidental.

### 2b. `SymbolicPropogator`, precisely (the heavyweight)

An **abstract interpreter over p-code** — the symbolic sibling of `sleigh::emu`:

- Constructed per run: `SymbolicPropogator(program, recordStartEndState)`.
- Driver: `flowConstants(startAddr, restrictSet, ContextEvaluator eval, saveContext,
  monitor) -> AddressSet`. Walks instructions following flow, maintaining a
  `VarnodeContext` (symbolic register/memory state), interpreting each instruction's
  p-code (`getInstructionPcode`). Overloads thread a `fromAddr` for per-function sub-flows.
- **Value domain** (`class Value`): a constant, *or* a **register-relative value**
  (`isRegisterRelativeValue` / `getRelativeRegister` / `getValue`), *or* unknown — exactly
  the lattice needed for stack/pointer reasoning. Query API: `getRegisterValue(addr,reg)`,
  `getEndRegisterValue`.
- **`ContextEvaluator`** is a caller-supplied callback: the *analyzer* implements it (e.g.
  `ConstantPropagationContextEvaluator`); the propagator calls back at decision points so
  the analyzer decides whether a resolved value becomes a reference, when to stop, etc.
- **`makeReference(...)`** (many overloads) — the side effect: it creates the actual
  program references when a value resolves to a pointer. Tuned via `setParamRefCheck`/
  `setReturnRefCheck`/`setStoredRefCheck`.

`ConstantPropagationAnalyzer.added()` is thin: per function, construct a propagator, set
ref-check flags, hand it a `ConstantPropagationContextEvaluator`, call `flowConstants`.
**Per-arch subclasses just override the evaluator** with architecture-specific heuristics
— so the abstract base ports once; arches are small deltas.

**Reuse insight:** this is the same p-code substrate mosura already lifts and interprets,
generalized over an abstract value lattice (constant / register-relative / unknown) with a
callback at reference sites. It is `emu` generalized — a real head start, not a from-
scratch engine. Still the largest new analysis component, but well-bounded.

### 2c. The decompiler-driven analyzers (the convergence point)

`DecompilerSwitchAnalyzer.added()` collects functions, builds a `DecompilerCallback` +
`SwitchAnalysisDecompileConfigurer`, runs `ParallelDecompiler.decompileFunctions(callback,
functions, monitor)`, and reads the jump table out of each `DecompileResults` (the
decompiler's `HighFunction`). So it **runs the ported decompiler per function and consumes
its switch recovery** — it depends on `DecompInterface` + the decompiler. Parameter-ID is
the same shape for call args/returns. This is what retires `decomp/jumptable.rs`, and what
gates A6 on decompiler-port progress.

## 3. Validation — Program-state parity (the oracle, and how it differs)

The decompiler port validates per-action IR via `decomp_dbg`. **Auto-analysis has no
`decomp_dbg` equivalent**, and it is a priority worklist run to a fixpoint, not a fixed
action sequence — so the faithful unit of comparison is the **converged Program-database
state for a given set of enabled analyzers**, not per-action.

- **Oracle:** Ghidra's `support/analyzeHeadless` runs the full loader + analysis pipeline
  and produces a `.gpr`. A headless script (or GhidraMCP) dumps the resulting Program:
  memory map, code units (instruction vs data + addresses), function boundaries + bodies,
  symbols, references. Ghidra lets you enable/disable individual analyzers, so you can run
  *just* disassembly, or disassembly + function-creation, and diff mosura's Program state
  at each increment — the same stage-by-stage discipline, with the Program snapshot as the
  "IR."
- **mosura emits the same snapshot**; a new `tests/analysis_parity.rs` diffs it
  structurally against Ghidra's. This is the gate.
- **Corpus:** the existing datatest fixtures are raw `<bytechunk>` images crafted for the
  decompiler, **not loadable files**. A0 needs a corpus of real object files (or tiny ELFs
  synthesized around the existing bytes).

## 4. Phases (the to-do; live status in `TODO.md`)

- **A0 — Oracle + corpus.** A script driving `analyzeHeadless` with a controllable
  analyzer set, dumping the converged Program (memory / code-units / functions / symbols /
  refs). A real-binary corpus. `tests/analysis_parity.rs` harness.
- **A1 — Program model.** `Program`/`Memory`/`MemoryBlock`/`AddressSet(View)`/`Listing`/
  `CodeUnit`/`SymbolTable`/`ReferenceManager`/`FunctionManager`, reusing the decompiler's
  `Address`/`AddrSpace`.
- **A2 — ELF loader.** File → memory blocks + relocations + symbols + entry points; gate
  on "memory map + symbol table match Ghidra." mosura starts ingesting real files.
- **A3 — Framework + one trivial analyzer.** `AutoAnalysisManager`/`AnalysisScheduler`/
  `Analyzer`/`AnalysisPriority` (§2a) + e.g. an entry-point marker analyzer, diffed
  end-to-end.
- **A4 — Disassembly + function discovery.** Wire SLEIGH into a disassembly analyzer from
  entry points; recursive descent following call/branch refs; function creation at call
  targets. Gate on code-unit + function-boundary parity.
- **A5 — References + `SymbolicPropogator`.** Port the abstract interpreter (§2b) + the
  reference analyzers. Gate on reference-set parity. The largest phase.
- **A6 — Decompiler-driven analyzers.** Switch recovery + parameter-ID via the decompiler
  (§2c). Retire `decomp/jumptable.rs`. Gate on jump-table + param parity. **Depends on the
  decompiler port.**
- **A7 — The tail.** Non-returning functions, shared-return, stack/purge, demanglers,
  strings/data, arch-specific propagation. Each gated on Program-state parity.

## 5. Method & discipline (same as the decompiler port)

- **Translate, don't reinvent.** The Java is the spec; when behavior is ambiguous, the
  Java decides. Enforced by Program-state parity, not a fuzzy score.
- **Mirror Ghidra's structure** (file/class/method names) so a diff is always meaningful.
  New work lives under `src/analysis/` (see §6), mirroring the Java tree's layout.
- **Program-state parity is the gate.** Don't advance to phase N+1 until phase N's Program
  snapshot matches Ghidra on the corpus (for that enabled-analyzer set).
- Keep the SLEIGH engine and its 254/254 parity, and the decompiler port, untouched.

## 6. Layout & relationship to the decompiler port

- New module tree **`src/analysis/`** (a sibling of `sleigh/`, `decomp/`, `decompile/`),
  same crate — the coupling makes a separate crate/repo pure friction (A1 reuses the
  decompiler's `Address`; A4 drives `sleigh`; A6 calls `decompile::pipeline`). Proposed
  submodules: `analysis/{program,loader,scheduler,manager,priority,analyzer}` +
  `analysis/symbolic/` + `analysis/analyzers/{constprop,switch,…}`. Tests in
  `tests/analysis_parity.rs`.
- **A1–A5 are independent of the decompiler port** and can proceed in parallel with its
  P-phases. **A6 gates on the decompiler** being far enough along to recover switches/
  params. Sequence A1–A5 so they don't block on it.

### File → module mapping

| Ghidra source | mosura home |
|---|---|
| `app/services/{Analyzer,AbstractAnalyzer}.java`, `AnalyzerType` | `analysis/analyzer.rs` (`trait Analyzer`) |
| `app/services/AnalysisPriority.java` | `analysis/priority.rs` |
| `app/plugin/core/analysis/AnalysisScheduler.java` | `analysis/scheduler.rs` |
| `app/plugin/core/analysis/AutoAnalysisManager.java` | `analysis/manager.rs` |
| `program/util/SymbolicPropogator.java` (+ `ContextEvaluator`, `VarnodeContext`) | `analysis/symbolic/` |
| `app/plugin/core/analysis/ConstantPropagationAnalyzer.java` | `analysis/analyzers/constprop.rs` |
| `app/plugin/core/analysis/DecompilerSwitchAnalyzer.java` | `analysis/analyzers/switch.rs` |
| `program/model/{listing,mem,address,symbol}/*`, `program/database/*` | `analysis/program/` |
| `app/util/opinion/ElfLoader.java`, `app/util/bin/format/elf/*` | `analysis/loader/elf.rs` |

## 7. Honest scope

Large — comparable to the decompiler port — but **bounded** and **compounding**, and
dominated by the Program model + loaders + the framework + `SymbolicPropogator`, **not** by
ISA decoding (the SLEIGH engine already nails that, which is usually the hardest part of an
analysis engine from scratch). The framework is small and fully understood (§2a);
`SymbolicPropogator` is the one heavyweight and it rides on infrastructure mosura already
has. It is a second track, not a continuation of the decompiler port — start it only as a
deliberate scope decision.
