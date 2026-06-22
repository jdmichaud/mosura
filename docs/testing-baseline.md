# Mosura — Test Baseline & Conformance Harness Design

**Status:** Draft for review
**Scope:** How we establish a test baseline to *guide* the port of Ghidra's logic into Rust (mosura), before writing port code.
**Reference tree:** `../ghidra` — pinned to **Ghidra 12.0.3** (git tag `Ghidra_12.0.3_build`) so the code we read == the code the oracle runs.
**Primary oracle (offline, self-contained):** Ghidra's standalone C++ tools — `sleigh_opt` (SLEIGH compiler), `decomp_dbg` (decompiler console; `print raw` = p-code), `decomp_test_dbg` (native datatest runner) — built from the pinned tree by `scripts/setup-oracle.sh`, which also compiles all `.sla` **from source**. **No external Ghidra install required.** Verified: the datatest suite runs **599/599** against source-compiled specs (see §10, README).
**Secondary oracle (optional):** the GhidraMCP headless server (v4.3.0) over a Ghidra 12.0.3 install, via the `mcp__ghidra__*` tools. Used to cross-check and to cover Java-side stages (loaders/analysis) the C++ tools don't. Its install path is environment-specific and **not a mosura dependency**.

---

## 1. Core principle: Ghidra is the oracle, not a source of unit tests

Ghidra ships ~1,712 `*Test.java` JUnit files plus a C++ suite. **We do not port them.** They assert against Java/C++ internal APIs (`DB`, `Docking`, class contracts, GUI) that will not exist in mosura. Porting them would mean porting Ghidra's architecture, which is the opposite of the goal.

Instead we use **characterization / golden-master testing** (a.k.a. approval testing): feed identical input bytes to Ghidra and to mosura, capture Ghidra's output as the *golden reference*, and require mosura to reproduce it. Behavior — what disassembly / p-code / decompiled C Ghidra produces — is the spec. This is the standard discipline for re-implementing a legacy system whose *behavior* matters more than its *structure*.

Two things make this tractable here:

1. Ghidra already contains **language-agnostic, output-based corpora** we can adopt almost verbatim (§4, Layer 0).
2. The **GhidraMCP headless oracle** lets us generate unlimited golden data programmatically (§5, Layer 1).

---

## 2. The pipeline and the port order

Ghidra's logic pipeline, bottom-up, with the module that owns each stage:

| # | Stage | Ghidra location (reference) | Determinism |
|---|-------|------------------------------|-------------|
| 0 | **Loader** (ELF/PE/Mach-O → memory image + symbols) | `Ghidra/Features/Base/.../app/util/opinion/*Loader.java` | High |
| **1a** | **SLEIGH compiler** (`.slaspec`/`.sinc` → internal tables) | standalone `Features/Decompiler/src/decompile/cpp/slgh_compile.*`, `slghparse.y`, `slghscan.l`, `slghsymbol.*`, `slghpatexpress.*` | **Deterministic** |
| **1b** | **SLEIGH runtime** (tables + bytes → instructions + raw p-code) | `Framework/SoftwareModeling/.../processors/sleigh/*`; standalone `sleigh.cc`, `sleighbase.cc` | **Highest** |
| 3 | **Analysis** (function ID, switch recovery, data types, refs) | `Features/Base/.../app/plugin/core/analysis/*` | Heuristic / lower |
| 4 | **Decompiler** (p-code → high p-code → C) | `Features/Decompiler/src/decompile/cpp/*` | Medium-high |

**First port target (DECIDED): the SLEIGH engine — stages 1a + 1b.**
We will port the SLEIGH *compiler/interpreter* and consume Ghidra's `.slaspec`/`.sinc` specs directly (~350 specs → every architecture for free), matching Ghidra's own design rather than hand-writing per-arch disassemblers. Rationale: most self-contained, *fully deterministic* (pure function of bytes + language spec, no heuristics), the densest existing test coverage (the `.slaspec` specs themselves + per-processor emulator tests + the `pcodetest` semantic suite), and the foundation every higher stage depends on. A bug here is unambiguous; a bug in the decompiler could be anywhere below it.

The engine splits into two sub-stages that need **separate oracles** — see §3.5. Briefly: don't golden-compare compiled `.sla` (it is a *packed binary* table format, version-coupled — §3.5); validate the **compiler (1a) indirectly through runtime behavior (1b)**.

**Stage boundaries are oracle cut-points.** We pin a golden snapshot at *each* boundary, not just end-to-end, so a regression localizes to one stage instead of "the decompiled C changed."

---

## 3. Three-layer baseline

### Layer 0 — Adopt Ghidra's in-tree golden corpora *as-is*
Zero re-derivation; these are already input-bytes → expected-output and free of Java internals.

- **Decompiler datatests** — `Features/Decompiler/src/decompile/datatests/*.xml` (**79 files** in 12.0.3). Each is self-contained:
  - `<binaryimage arch="x86:LE:64:default:gcc">` with raw `<bytechunk>` hex at fixed addresses,
  - `<symbol>` definitions,
  - a `<script>` of console commands (`map fun`, `parse line …`, `lo fu <name>`, `decompile`, `print C`),
  - `<stringmatch name=… min=… max=…>REGEX</stringmatch>` assertions on the emitted C.

  Run today by the standalone C++ harness in `testfunction.cc` (`loadTest` → `buildProgram` → `startTests` → `runTests`) — **no Java, no GUI**. mosura reuses the *same XML schema and command grammar*, giving a ready-made decompiler conformance suite on day one.

  Arch coverage (12.0.3): x86-64 gcc ×59, x86-64 windows ×3, AARCH64 ×3, x86-32 ×3 (gcc/win/windows), MIPS ×4 (LE ×2, BE ×2), PowerPC ×2, ARMv8 ×2, 68000 ×1, 8051 ×1, Toy ×1. This count drives the **arch order (decision #4)**: x86-64-gcc → {x86-64-win, AARCH64} → {MIPS, PowerPC, ARM} → the singletons.

- **Processor emulator tests** — `Ghidra/Processors/*/src/test.processors/`. Assemble a program, run it through the p-code emulator, assert a register holds a pass value. These encode **SLEIGH semantics** per architecture — directly relevant to the first target (stages 1a+1b).

- **The `pcodetest` semantic suite (primary asset for the first target)** — `Ghidra/Extensions/SleighDevTools/pcodetest/c_src/` + `Features/Base/{data,src/main/resources}/pcodetest`. Ghidra's canonical SLEIGH-semantics conformance corpus: a set of C programs by feature — `BIOPS*` (binary ops over int/float/double/longlong), `BitManipulation`, `DecisionMaking`, `IterativeProcessing{For,While,DoWhile}`, `ParameterPassing{1,2,3}`, `PointerManipulation`, `StructUnionManipulation`, `GlobalVariables` — compiled per-toolchain into test binaries and *executed under the p-code emulator*, asserting computed results. This is exactly stages 1a+1b under test: if mosura's compiled tables + runtime produce the same emulated results, the SLEIGH engine is correct. We reuse the C sources and the `pcode_defs.py` build matrix; the emulator is mosura's (a thin p-code interpreter is a prerequisite for this suite).

### Layer 1 — Differential capture via the GhidraMCP oracle (the workhorse)
A capture harness drives the live headless server to dump structured golden output over a corpus, per stage. MCP endpoint → stage mapping:

| Stage | Golden-capture MCP endpoint(s) |
|-------|-------------------------------|
| Loader | `load_program`, `list_segments`, `list_imports`/`list_exports`, `get_entry_points`, `read_memory` |
| Disasm | `disassemble_bytes` (raw range, no analysis), `disassemble_function` |
| P-code | `get_assembly_context`, decompiler raw-pcode (via `decompile_function` low stages) / script endpoint |
| Analysis | `list_functions`, `get_function_metrics`, `analyze_control_flow`, `get_function_call_graph`, `list_data_items` |
| Decompiler | `decompile_function` |

The oracle is confirmed live (`check_connection` → OK; `list_language_ids` returns the full SLEIGH set incl. `x86:LE:64:default` with gcc/windows/golang/swift cspecs). The capture path: `load_program` from a corpus binary → call the stage endpoint → normalize → write golden file.

### Layer 2 — Stage-pinned snapshots (regression net)
Each stage gets its own golden snapshot directory; mosura's per-stage output is compared independently. End-to-end decompiler match is the *headline* metric but never the *only* one.

---

## 3.5 SLEIGH-engine testing strategy (first target)

Porting the SLEIGH engine splits the first target into two sub-stages with **different** oracles.

**Critical caveat — do *not* golden-compare `.sla` byte-for-byte.** In 12.0.3 the compiled `.sla` is a *packed binary* table format (`sla::FORMAT_VERSION`, `Encoder`/`Decoder` in `slaformat.cc`), not the old XML — byte-equality is coupled to a format version we don't control and to internal table-ordering that is an implementation detail, not behavior. (The source tree ships 0 compiled `.sla`; `scripts/setup-oracle.sh` compiles them **from source** with `sleigh_opt` — 146 `.sla` — so reference tables are reproducible with no external install.) **Conclusion:** treat compiled tables as an internal representation, validated through behavior.

**Stage 1a — SLEIGH compiler (`.slaspec`/`.sinc` → tables).** Validated three ways, in priority order:
1. **Indirectly, through runtime behavior (primary).** If mosura's tables drive disassembly + p-code that match the oracle (1b below) across the corpus, the compiler is correct *where it matters*. This is the main signal.
2. **Interop round-trip (DECIDED: do it).** mosura's Rust `.sla` decoder reads a `.sla` produced by the reference C++ `sleigh_opt` (from `setup-oracle.sh`) and confirms it yields the same disassembly as mosura's own compile of the matching `.slaspec`. Tests the decoder + semantic equivalence against the reference encoder without asserting byte layout — and needs no external install.
3. **Front-end unit goldens.** The preprocessor / lexer / parser (`slghscan.l`, `slghparse.y`) get small hand-authored spec fragments with expected token/AST/diagnostic output. Mirrors Ghidra's own `SleighPreprocessorTest` and `slgh_compile/regression/SleighCompileRegressionTest` (used as conceptual references, not ported).

**Stage 1b — SLEIGH runtime (tables + bytes → instructions + raw p-code).** This is the byte-exact heart of the baseline:
- **Oracle:** instruction text + raw p-code from *either* the standalone `decomp_dbg` (`print raw`, fully offline) or the MCP (`disassemble_bytes` + a Ghidra script calling `Instruction.getPcode()`), over (i) the byte-chunks extracted from the 79 datatests, (ii) Tier-A synthetic fixtures, (iii) the `pcodetest` binaries.
- **Semantic oracle:** the `pcodetest` suite + processor emulator tests — run the same binaries through mosura's p-code interpreter and assert identical computed results. This catches semantic errors that disassembly-text matching misses (e.g. a wrong flag computation that still prints the right mnemonic).
- **Match mode:** exact (after varnode/temp normalization, §5).

**Prerequisite:** stage 1b's semantic suite needs a minimal **p-code interpreter** in mosura. That interpreter is small, is needed eventually anyway, and is itself validated by the `pcodetest` expected-results — so it is in-scope for the first milestone.

---

## 4. Corpus design

Grow deterministically, smallest first:

1. **Tier A — synthetic micro-inputs (start here).** Hand-written `.o`/`.bin` with known semantics, *plus the byte-chunks already embedded in the 79 datatests* (extract them as standalone disasm/p-code fixtures). Tiny, fully deterministic, one feature each (a `for` loop, a switch, a bitfield, a float cast…).
2. **Tier B — single-compiler, single-arch real objects.** A handful of small C programs compiled at `-O0` and `-O3` for `x86:LE:64:gcc`. Mirrors Ghidra's own `*_O0`/`*_O3` processor-test naming.
3. **Tier C — cross-arch + cross-compiler.** Extend Tier B across the arches already present in Layer 0 (AARCH64, MIPS, PowerPC, ARM, 68000) and compilers (gcc/windows).
4. **Tier D — real-world binaries.** Stripped/optimized system binaries for stress + analysis-stage coverage. Used for *trend* tracking, not byte-exact gating (analysis is heuristic).

Corpus binaries and their goldens live **in-repo** (decision #2: no Git-LFS unless the total exceeds a few hundred MB — disasm/p-code goldens are small text; the `pcodetest` binaries are modest) so the baseline is reproducible offline.

---

## 5. Snapshot / dump format

**Requirements:** deterministic, normalized, diff-friendly, stage-specific, machine- and human-readable. One canonical text form per stage (JSON-lines or a stable pretty text). Example for the **disasm+pcode** stage (first target):

```
# lang=x86:LE:64:default cspec=gcc  oracle=ghidra-12.0.3  capture=v1
0010027f  89 f0              MOV  EAX, ESI
          pcode: (register,0x0,4) = COPY (register,0x30,4)
00100281  83 e0 0f           AND  EAX, 0xf
          pcode: CF = INT_... ; (register,0x0,4) = INT_AND (register,0x0,4) (const,0xf,4)
...
```

**Normalization rules (so diffs mean something):**
- Addresses: keep absolute (deterministic for a fixed image); for relocatable fixtures, express relative to function start.
- Varnodes: canonical `(space,offset,size)` notation; never rely on temp-register numbering that can shift — sort/normalize unique temporaries.
- Strip volatile fields: capture timestamps, absolute host paths, Ghidra build hash (recorded once in the header, not per line).
- Stable ordering: instructions by address; p-code ops in emission order; lists (functions, symbols) sorted by a documented key.
- Comparison strength is per-stage (see §6, decision #5): loader/disasm/p-code use **exact** match after normalization; the decompiler uses **structural (AST) equivalence**, with Ghidra's `<stringmatch>` regexes kept only as a cheap smoke check.

Every golden file header records: language id, compiler spec, **oracle Ghidra version**, and a capture-format version — so a baseline is self-describing and regenerable.

---

## 6. Diff tooling & harness shape

- **Comparison modes (decision #5 — go beyond regex):**
  - *exact* (after normalization) for loader, disasm, p-code;
  - *structural equivalence* for the decompiler — parse both C outputs to an AST, α-rename variables, canonicalize, compare structure (ignores naming/formatting/benign reordering). Ghidra's `<stringmatch>` regexes are a first-pass smoke check, not the bar;
  - *behavioral equivalence (strongest, optional)* — recompile both C outputs and compare emulated I/O on sample inputs; catches semantically-equal-but-structurally-different output. Heavier; reserved for the decompiler milestone.
  - Analysis-stage metrics use *tolerances* (function-count within N, set-equality on recovered boundaries).
- **Harness location:** `mosura/tests/conformance/` — a Rust integration-test harness that (a) loads a fixture, (b) runs the mosura stage, (c) loads the golden, (d) diffs per the stage's mode. Datatest XML is parsed by a small reader mirroring `testfunction.cc`.
- **Golden regeneration:** an env-gated path (`MOSURA_UPDATE_GOLDEN=1`) re-captures from the oracle and rewrites goldens; default runs are read-only and must not touch the network.
- **Capture script:** a separate tool produces/refreshes Layer-1 goldens from **two cross-checkable oracles** — the MCP (Java 12.0.3) and the standalone C++ tools (`decomp_dbg`/`decomp_test_dbg`, fully offline) — plus `sleigh_opt` for stage-1a `.sla` references. It is *not* part of the normal `cargo test` run (goldens are captured ahead of time; tests run with both oracles offline).
- **CI gate:** all three layers run on every change; a stage is "ported" only when its layer is green.

---

## 7. Version pinning & determinism

- **Pinned to Ghidra 12.0.3 (DECIDED).** The source tree is checked out at git tag `Ghidra_12.0.3_build` (enforced by `scripts/setup-oracle.sh`); the offline oracle is built from this same tree, and the optional MCP runs the matching 12.0.3. Every golden header records `oracle=ghidra-12.0.3`. Regenerate goldens only via a deliberate, reviewed "bump oracle" change — never silently.
- **Corpus is *not* frozen to 12.0.3.** Pinning fixes the *behavioral target*, not the breadth of inputs — we can pull additional/newer datatests and test data from later tags at will (the tree is a git checkout: `git show <tag>:<path>`). Caveat: a datatest's committed `<stringmatch>` golden is version-coupled, so when importing a newer fixture, re-anchor its expected output to the pinned 12.0.3 oracle (Layer-1 capture) rather than trusting the cross-version assertion.
- **Neutralize known non-determinism** before it pollutes goldens: analysis heuristics (run with a fixed analyzer set / fixed options), auto-generated names (`DAT_…`, `FUN_…`, `uVar1`) normalized or matched by structure not literal name, and any iteration-order-dependent output sorted.
- Disasm/p-code have *no* heuristic inputs → expect byte-exact stability; treat any nondeterminism there as a harness bug.

---

## 8. First milestone — status

Goal: a live, localized baseline for the **SLEIGH engine (1a+1b)**. Implemented in
`crates/mosura` (the harness) + `oracle/` (the offline capture tool); `cargo test`
is green and the ratchets sit at their red baseline.

- ✅ **Harness skeleton** — `crates/mosura`: `datatest` (reader), `conformance`
  (exact / `stringmatch` / Tally modes), `golden` (disasm/p-code parser), `sleigh`
  (stub engine returning `Unimplemented`). Unit-tested.
- ✅ **Datatest baseline** — `tests/conformance_datatests.rs` ingests all **79**
  datatests and counts **599** stringmatch assertions (independently matching the
  oracle's 599/599). Decompiler-parity ratchet `EXPECTED_DATATEST_PASS = 0`.
- ✅ **Runtime golden (1b) — DONE, 6 architectures at 100% (254/254).** The SLEIGH
  engine (`sleigh::engine`), driven through the public `sleigh::disassemble` via the
  `lang` registry (id → `.sla` + context), reproduces every golden instruction —
  disasm **and** raw p-code — across **x86-64, AARCH64, 6502, ARM, MIPS (BE+LE), and
  PowerPC (BE)**. `tests/disasm_golden.rs` ratchets at `EXPECTED_DISASM_PASS = 254`
  (was 0). Cross-arch reached 100% via generic engine features only (delay slots,
  full op-name table, const masking, chunk-boundary loader semantics).
- ✅ **Semantic golden (1b) — p-code interpreter** (`sleigh::emu`): executes lifted
  raw p-code over a byte-addressable machine, **following branches/loops**.
  `tests/semantic_x86_64.rs` runs `f(a,b)=a*3+(b>>2)-5` and a real loop
  `sumto(n)=n*(n+1)/2` (1000+ iterations) and asserts the **computed result** vs the
  C semantics. The full `pcodetest` C suite (needs per-arch cross-compilers) is a
  later broadening, not a blocker.
- ✅ **Regen entry point** — `cargo xtask baseline` rebuilds the goldens from
  fixtures via the offline capture tool (idempotent, no network, no external install).

**Milestone reached.** The stage-1a+1b baseline is live and *green at 100%* across
six architectures. Next phase (beyond this milestone): the `pcodetest` semantic
corpus, SSE/AVX breadth, and the **decompiler** stage — bumping the still-red
`EXPECTED_DATATEST_PASS` toward the oracle's 599/599. The decompiler stage is
planned in [`decompiler-plan.md`](decompiler-plan.md).

---

## 9. Decisions & remaining work

**All resolved:**
- ✅ **First target** — the SLEIGH engine (stages 1a+1b).
- ✅ **SLEIGH spec strategy** — port the SLEIGH compiler/interpreter; consume `.slaspec`/`.sinc` directly (~350 specs → all arches). **Sequencing (approved 2026-06-21):** build the *runtime* (stage 1b) now against tables decoded from Ghidra-compiled `.sla` (the `.sla` reader doubles as the planned interop check); **port the `.slaspec` compiler (stage 1a) later** so mosura becomes self-contained. End goal — consume `.slaspec` directly — is unchanged.
- ✅ **Oracle pinning (#1)** — pin to **12.0.3** to match the MCP; source tree checked out at `Ghidra_12.0.3_build`. Corpus stays extensible (§7).
- ✅ **Golden storage (#2)** — **in-repo**; no Git-LFS unless the total grows past a few hundred MB.
- ✅ **`.sla` interop + offline oracle (#3)** — done & self-contained: `setup-oracle.sh` builds the tools and compiles all `.sla` **from source** (no external install), and the native `decomp_test_dbg` runs the full datatest suite **fully offline at 599/599**. Two oracles: standalone C++ tools (primary) + optional MCP (secondary).
- ✅ **Arch order (#4)** — by dataset count: x86-64-gcc (59) first, then {x86-64-win, AARCH64} (3), then {MIPS, PowerPC, ARM} (2), then the singletons. *All* arches in scope eventually.
- ✅ **Decompiler parity (#5)** — neither plain regex nor exact text; use **structural (AST) equivalence**, with **behavioral (recompile-and-emulate) equivalence** as the strongest optional tier. Regex `<stringmatch>` is kept only as a smoke check.

**To pin down during milestone 1 (implementation details, not blocking):**
- The exact on-the-wire schema for the disasm+p-code snapshot (field set; normalization of temp varnodes).
- Whether mosura's minimal p-code interpreter (needed for the `pcodetest` semantic layer) lands in milestone 1 or 2.
- The AST/behavioral comparator is only needed at the decompiler stage — design it then, not now.

---

## 10. Environment setup & portability

The offline baseline is **self-contained and scripted** — see `README.md` and `scripts/setup-oracle.sh`. Given a C++ toolchain + libbfd and the pinned `ghidra/` checkout, one command builds the standalone tools, compiles all `.sla` from source, and verifies **599/599** — with **no dependency on any external Ghidra install**. Specifics:

- Paths derive from the script's own location (override the Ghidra tree with `GHIDRA_SRC`); nothing is hard-coded to a home directory.
- The script enforces the pinned tag, builds `sleigh_opt`/`decomp_dbg`/`decomp_test_dbg`, runs `sleigh_opt -a` to compile every processor spec, then runs the datatest suite as a gate.
- It writes `build/oracle.env` (exported tool paths) for the capture harness to source.
- All artifacts — `*.sla`, the tool binaries, object dirs, `build/` — are regenerated and git-ignored; the reference checkout stays clean (the script adds local excludes for the few binaries Ghidra's `.gitignore` misses).
- **Moving machines:** copy or re-create the workspace (`ghidra/` at tag `Ghidra_12.0.3_build` + `mosura/`), `apt-get` the prerequisites, run the script. The optional MCP oracle is the only component needing separate, environment-specific setup, and only for Java-side stages beyond the first target.
