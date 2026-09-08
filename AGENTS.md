# Working on mosura

mosura is a **port of Ghidra's logic** (not its UI) in Rust — a SLEIGH disassembler and p-code
lifter, a p-code interpreter, and the decompiler — shipped as a library with a C API and a
command line, and extended with a recompilation pipeline that emits compilable C and judges it
against the original bytes. Ghidra is the golden oracle for the port; the binary is the target.

**Read to start work:** this file. **Before quoting a number, retiring a claim, or trusting an
instrument:** [`docs/measurement-rules.md`](docs/measurement-rules.md). **Setup, layout, tests,
the developer tier:** [`docs/development.md`](docs/development.md). **The plans:**
[`docs/port-plan.md`](docs/port-plan.md) (the faithful decompiler port),
[`docs/roadmap-100.md`](docs/roadmap-100.md) (the road to a complete port),
[`docs/product/architecture.md`](docs/product/architecture.md) (the library, C API, store and CLI).
The owner's backlog is [`TODO.md`](TODO.md).

## Operating directives

These come from the project owner and outrank convenience.

1. **Exactness with the BINARY is the goal, not agreement with Ghidra's output.** Ghidra
   faithfulness is the *method*; the original binary's bytes are the target. The corpus is a
   diagnostic, never the objective.
2. **Don't stop. If you want to stop, don't.** Work continues until the task is done or the
   owner redirects.
3. **Don't block on questions — take the first option you would have proposed and keep going.**
   Report status, not choices.
4. **An issue found on a survey binary becomes an MVE first — then you solve the MVE.**
   When decompiling a real binary surfaces a defect, do not fix it against that binary. Write a
   minimal self-compiled program in `oracle/ground-truth/src/` that surfaces the same defect,
   gate it in `crates/mosura-core/tests/ground_truth_parity.rs`, and fix *that*. The survey
   binary is temporary and cannot be shipped; a gate built on it dies with it, and until then it
   is unreproducible by anyone who lacks the binary. The MVE must be shown to FAIL before the
   fix and pass after — a gate that never caught the bug is decoration. Record the properties
   the program depends on in its own source, so it is not later "simplified" into something
   that no longer reproduces.
5. **Compiler quirks go through the cspec, never an `if (target)` in the decompiler core.**
   Reduce a suspected quirk to a minimal example, compile it with several compilers, and if the
   behaviour is compiler-specific, scope it behind the existing compiler/version detection so one
   compiler's specifics are not generalised. If the cspec route becomes limiting: shoehorn it in
   without regression, or come back and discuss it.

## The one principle: port, don't reinvent — and validate on the IR

This is a **translation** of Ghidra's decompiler (C++ → Rust), not "build something whose
output merely looks similar." Ghidra's C++ is the reference and it is correct (it passes
its own datatests 599/599). When something is wrong or missing, **read Ghidra's source
and reimplement the algorithm faithfully** — do not invent heuristics or approximations.
Cases that feel "ambiguous" (is a function void? what width is an argument? hex or
decimal?) are decided by concrete code in Ghidra; find it and port it.

**Validate against Ghidra's intermediate IR, exactly, stage by stage** — not a fuzzy
final-C similarity score. Optimizing a token-skeleton similarity score rewards approximations
that coincidentally match Ghidra's tokens and *punishes* faithful algorithms that produce
correct-but-different output: it optimizes *away* from Ghidra, and approximations don't compose.
Mirror Ghidra's data model and `Action`/`Rule` pipeline so faithfulness *is* the metric.

**No adaptation is grandfathered.** Any deviation from Ghidra's actual logic — however it was
justified earlier — is cancelled the moment it stands between us and a faithful port. A past
decision to approximate never protects the approximation. (Faithful cross-language translations
are not deviations; they *are* the port.)

**Instrument first, hypothesise second.** When the question is "which Ghidra mechanism produces
X?", do not chain source-reading guesses — run the rule-trace diff (`scripts/trace-diff.sh
<fixture>`, `oracle/capture_trace`) or an oracle IR dump so the firing evidence *names* the
mechanism, then read the source to understand what was named. One trace beats five
plausible-but-wrong premise checks.

**Where the printer and the emitter part ways.** The C printer (`decompile/printc.rs`) is the
faithful port and stays one; when its output is not *compilable* C, the fix lives in the emit arms
and the translation-unit synthesis (`decompile/emit/`, `recompile/tu.rs`), each arm witnessed by
the bytes and switchable, never in a printer "improvement". `docs/exact-arms.md` is the record.

The Ghidra source is pinned to tag `Ghidra_12.0.3_build` (commit `09f14c92`): `scripts/setup-ghidra.sh`
fetches it beside this repository (or at `ghidra_src` in `dev-config.toml`), verifies the commit and
compiles the `.sla`. The decompiler to port is `Ghidra/Features/Decompiler/src/decompile/cpp` in that
tree (`coreaction.cc`, `printc.cc`, `printlanguage.cc`, `funcdata*.cc`, `type.cc`, `jumptable.cc`, …);
`crates/mosura-core/src/decompile/` mirrors its file and class names. Nothing at run time needs that
checkout: the processor tables are vendored in `third_party/ghidra/` and embedded.

## The decision rule (read this before you revert anything)

The C-similarity (`ccompare`) is a **coarse gauge, never the gate.** It erases names,
types, and numbers, and it *rewards* a missing/empty rendering over a correct-but-verbose
one. Do not let it drive decisions. Concretely:

1. **A change that passes `ir_parity` + `disasm_golden` and matches Ghidra's IR is correct.
   KEEP it — even if the similarity score drops.** Parity is the temperature; ccompare is the
   thermometer. Don't revert the patient because the thermometer twitched.
2. **A similarity dip after a *faithful* change almost always means a downstream piece isn't
   ported yet.** The fix is to **port that downstream piece too**, not to revert the faithful
   upstream one. Approximations don't compose; faithful ports *do* — but only once their
   consumers exist. **Land the subsystem, not one orphaned half of it.**
3. **Only revert output that is genuinely WRONG** — output Ghidra would *never* emit, confirmed
   by reading Ghidra's IR/C via the oracle. Never revert because a noisy token gauge moved.
4. **Never invent a heuristic** (a "cycle gate", a "multi-exit check", a "trivial-case detector",
   a size threshold) to paper over a gap. If Ghidra makes a decision, Ghidra has code for it —
   find it and port *that*. A heuristic that happens to match a few corpus functions is the exact
   anti-pattern. **Any fix shaped "skip the case that breaks" rather than "compute the same
   answer Ghidra computes" is that species, however local it looks.**
5. **GROUND BEFORE YOU CODE — dump the actual IR and Ghidra's actual `--c` first.** The most
   expensive failure mode is *guessing the mechanism*: building a fix on what you assume the IR
   contains or what you remember Ghidra emits, then reverting when it doesn't.

New code is **always** a faithful port, never a hypothesis to test-and-revert. **A revert of
newly-written code is a process failure** — stop and investigate why non-faithful code was
generated.

If you catch yourself about to revert a parity-clean change because the corpus average dipped,
**stop** and re-read this section. And if you've reverted the same area twice, **stop guessing
and read the IR.**

## The oracle

There are **two** Ghidra oracles and they disagree by construction. `oracle/capture --c` is the
C++ decompiler alone — it answers *how the decompiler renders something*. analyzeHeadless output
(the Java layer included) answers *what the whole tool produces on a real binary*. **mosura ports
the C++ decompiler**, so rendering questions go to `capture --c`. Full rule and worked examples:
[`docs/measurement-rules.md` §2](docs/measurement-rules.md).

`scripts/setup-oracle.sh` (needs the pinned source and a C++ toolchain) builds the tools under
`oracle/`, all linked against Ghidra's `libdecomp_dbg.a`:

- `oracle/capture <sleighdir> <fixture.xml>` — disassembly + raw p-code (the golden generator);
  `--c` — **Ghidra's own decompiled C**; `--ir [action]` — Ghidra's IR at the start of a named
  action, the per-phase oracle behind `ir_parity`.
- `oracle/capture_trace` — the rule-application trace (`OPACTION_DEBUG`), diffed against mosura's
  `--debug opaction` by `scripts/trace-diff.sh`; `oracle/capture_typeprop` — the type-propagation
  twin; `oracle/capture_merge` — HighVariable membership and covers at the end of the merge cluster.

**Rebuild only through `scripts/setup-oracle.sh`.** The tools must be compiled with the same
preprocessor switches as the library (`-DCPUI_DEBUG -D__TERMINAL__`); without them the struct
layouts differ and the oracle *silently* decompiles differently from canonical Ghidra — no crash,
wrong answers. The header of `oracle/capture.cc` records the incident.

The subject's per-function Ghidra recipe and its limits — it can change block structure — are in
the header of `scripts/ghidra-decompile-subject.sh` and in
[`docs/measurement-rules.md` §1](docs/measurement-rules.md).

## Verification (the quality bar)

Every change is verified; never ship semantically-wrong output.

- `cargo test --workspace` must stay green (run it through a log file and read the exit code;
  a pipe reports the tail's). The three repository guards are part of it: no environment
  variable read anywhere, no tracked file naming a subject binary, no tracked file naming a
  developer's home directory.
- **`disasm_golden` — every golden instruction's disassembly and raw p-code must NEVER regress.**
- **`ir_parity` — the gate for the faithful port:** mosura's IR against Ghidra's at each pipeline
  stage (`capture --ir <action>`), structurally exact. A phase is not done until its parity is
  green on the datatests. This is the real port metric; faithfulness *is* the score.
- `decompile_corpus` — the structural-similarity score against Ghidra's C over the fixture corpus.
  **A coarse progress gauge, never a hard gate** — it must not block a faithful change.
- `ground_truth_parity` — the analysis against self-compiled programs whose oracle is the *known*
  source and build, not Ghidra; the home of every MVE (directive 4).
- **The recompile pipeline is measured by corpus rounds**, not by tests: a defect fix ships a
  pinning test; a behaviour-neutral change passes the identity gate (the emitted tree is
  byte-identical to the baseline's); an intended change to the emitted text goes through a round
  and lands on the verdict comparison — no EXACT lost, no new failure verdict, the eight gates OK.
  How to run one and what "stable" means: [`docs/corpus-round-runbook.md`](docs/corpus-round-runbook.md).
  How to quote what it says: [`docs/measurement-rules.md`](docs/measurement-rules.md). The
  opt-in gcc ground truth of the emit arms (`ground_truth_recompile_arms -- --ignored`) runs at plan
  closure and whenever a commit changes an arm, the emit plan or the oracle.

Loop for porting a phase: read the Ghidra source for that component → translate it
faithfully into `crates/mosura-core/src/decompile/` (mirroring Ghidra's file/class names) → diff
mosura's IR vs Ghidra's IR at that stage until exact → retire the corresponding prototype code →
record gotchas in memory.

## Third-party material

Committed test data includes vendor-produced fixtures and programs linking historical proprietary
run-times; `docs/third-party-test-binaries.md` inventories every one with its provenance and the
gate that needs it. **Do not add to it casually.** Compiler distributions, SDKs, manuals and subject
binaries are never committed — they are user-provided, located through `dev-config.toml`
(`dev-config.example.toml` lists every key), and their gates skip when absent (`docs/dependencies.md`).
Oracle fixtures are self-compiled minimal examples, never a subject's bytes. Nothing in the library,
the CLI, the tests or the scripts reads an environment variable for a location or a knob: knobs are
values (`switches::Knobs`, `--arms-off`), diagnostics are `--debug <spec>`, spec and FID data are
embedded with a `--data-dir` override (`crate::resources`); the guard tests enforce all of it.

## Conventions

- Respect agreed plan/design decisions; if a decision needs changing, ask first.
- Keep the disasm engine data-driven — no per-instruction or per-arch special-casing.
- Match Ghidra where it is the port target (formatting, structure, types); prefer
  faithfulness over "nicer" output.
- One branch per work package, small self-contained commits that each build; the gate numbers go
  in the message of the commit they were measured on; the suite runs once per package.
- A number is quoted with its denominator and its instrument, and never re-derived from someone
  else's report — read their work instead.

## Pointers

- **Measurement, instruments, and how claims go bad:** `docs/measurement-rules.md`.
- **Setup, layout, tests, the developer tier, the guards:** `docs/development.md`.
- **Plans:** `docs/port-plan.md` (the decompiler port), `docs/roadmap-100.md` (to a complete port),
  `docs/product/architecture.md` and `docs/product/plan-wp7-2026-09-05.md` (the product surface).
- **Recompilation:** `docs/corpus-round-runbook.md` (rounds), `docs/exact-arms.md` (the emit arms),
  `docs/semantic-equivalence.md` (the differential-execution check).
- **Open work:** `TODO.md` (the owner's backlog), `docs/tasklist-2026-09-08.md` (the queued items
  from the second subject).
- Per-Ghidra-class port status: `docs/coverage.md`. Debug-information track (DWARF/PDB/CodeView/
  Go/PEF; not started): `docs/debug-info-port-plan.md`.
- **"What is this file?"** — `mosura identify <binary>` prints the container, which loader
  claims it, the compiler evidence in the bytes, the resolved language/cspec and the FID databases
  that apply (`-o load.loader=native|le`, `-o load.cspec-x86-32=<id>` to test a hypothesis). The
  same binary is the product's command line: `mosura -S <dir> add <bin>`, `analyze`, `functions`,
  `decompile <fn>`, `emit <fn>`, `lift <hex>`, `disasm --bytes <hex>`, `read <addr> <len>`, and
  `mosura call <op>` for every operation (`mosura ops`). Reach for it before writing a throwaway.
- Detailed per-feature notes and gotchas: `.claude/memory/mosura-project.md`.
- Superseded (approximation-era, kept for history): `docs/decompiler-plan.md`,
  `docs/floats-plan.md`, `docs/switches-plan.md`, `docs/type-system-plan.md`.
