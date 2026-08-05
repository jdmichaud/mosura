# Working on mosura

mosura is a CLI **port of Ghidra's logic** (not its UI) in Rust: a SLEIGH disassembler
+ p-code lifter, a p-code interpreter, and a decompiler. Ghidra is the golden oracle —
mosura's output is validated against it.

**Master plan: [`docs/port-plan.md`](docs/port-plan.md). Live status: [`TODO.md`](TODO.md).**

> **Before quoting a number, retiring a claim, or trusting an instrument, read
> [`docs/measurement-rules.md`](docs/measurement-rules.md).** Every rule in it was bought by a
> real error here. You do not need it to start work; you need it the moment you are about to
> assert something measured.

## Operating directives

These come from the project owner and outrank convenience. They are here because they were
previously only in one agent's private notes, and the one most often broken — a single agent —
was nowhere in the repo at all.

1. **Exactness with the BINARY is the goal, not agreement with Ghidra's output.** Ghidra
   faithfulness is the *method*; the original binary's bytes are the target. The corpus is a
   diagnostic, never the objective.
2. **Exactly ONE agent at a time.** Never launch one while another exists — even if it looks
   idle. Stop the existing one first, and verify it stopped. (Messaging a stopped agent can
   revive it.)
3. **Don't stop. If you want to stop, don't.** Work continues until the task is done or the
   owner redirects.
4. **Don't block on questions — take the first option you would have proposed and keep going.**
   Report status, not choices.
5. **Retiring inventions is the primary track.** Non-Ghidra code is what has been holding the
   binary work back; it comes before new feature work. Finish an in-flight task before pivoting.
6. **Compiler quirks go through the cspec, never an `if (target)` in the decompiler core.**
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
final-C similarity score. Hard lesson (see `port-plan.md` §0): optimizing the
token-skeleton similarity score rewards approximations that coincidentally match Ghidra's
tokens and *punishes* faithful algorithms that produce correct-but-different output — it
optimizes *away* from Ghidra, and approximations don't compose. Mirror Ghidra's data
model and `Action`/`Rule` pipeline so faithfulness *is* the metric.

**No adaptation is grandfathered.** Any deviation from Ghidra's actual logic — however it was
justified earlier — is cancelled the moment it stands between us and a faithful port. A past
decision to approximate never protects the approximation. (Faithful cross-language translations
are not deviations; they *are* the port.)

**Instrument first, hypothesise second.** When the question is "which Ghidra mechanism produces
X?", do not chain source-reading guesses — run the rule-trace diff (`scripts/trace-diff.sh
<fixture>`, `oracle/capture_trace --trace`) or an oracle IR dump so the firing evidence *names*
the mechanism, then read the source to understand what was named. One trace beats five
plausible-but-wrong premise checks.

- Ghidra source (pinned to tag `Ghidra_12.0.3_build`, commit `09f14c92`): `../ghidra` —
  fetch + pin + compile the `.sla` with `scripts/setup-ghidra.sh` (`GHIDRA_SRC` overrides).
- Decompiler core to port: `../ghidra/Ghidra/Features/Decompiler/src/decompile/cpp`
  (e.g. `coreaction.cc`, `printc.cc`, `printlanguage.cc`, `funcdata*.cc`, `type.cc`,
  `jumptable.cc`).

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
   contains or what you remember Ghidra emits, then reverting when it doesn't. A whole session
   was lost guessing a cast mechanism five times — every premise was wrong, and reading the IR
   first would have shown it in minutes.

New code is **always** a faithful port, never a hypothesis to test-and-revert. **A revert of
newly-written code is a process failure** — stop and investigate why non-faithful code was
generated.

If you catch yourself about to revert a parity-clean change because the corpus average dipped,
**stop** and re-read this section. And if you've reverted the same area twice, **stop guessing
and read the IR.**

## Layout

```
<workspace>/
  ghidra/   pinned Ghidra source — the reference oracle (do not bump casually)
  mosura/   this project
```

- `crates/mosura/src/sleigh/` — SLEIGH engine (`sla` loader, `engine`, `emu`) + p-code IR.
  **Done, keep, never regress.**
- `crates/mosura/src/decompile/` — **the faithful port (new work)**: Ghidra's data model
  + `Action`/`Rule` pipeline, mirroring `decompile/cpp` file/class names. See `port-plan.md`.
- `crates/mosura/src/ccompare.rs` — structural C-similarity comparator (string in, score
  out), used by `decompile_corpus`.
- `oracle/capture.cc` — offline oracle tool, built by `scripts/setup-oracle.sh`.
- `goldens/` — committed disasm / p-code goldens.

## The oracle

There are **two** Ghidra oracles and they disagree by construction. `oracle/capture --c` is the
C++ decompiler alone — it answers *how the decompiler renders something*. `war2-survey/
ghidra-all.txt` is analyzeHeadless, Java layer included — it answers *what the whole tool
produces on a real binary*. **mosura ports the C++ decompiler**, so rendering questions go to
`capture --c`. Routing a question to the wrong one has falsified two approved framings; the
worked examples and the full rule are in
[`docs/measurement-rules.md` §2](docs/measurement-rules.md).

`scripts/setup-oracle.sh` (needs the pinned `ghidra/` + a C++ toolchain) builds `oracle/capture`:

- `oracle/capture <ghidra-src> <fixture.xml>` — dumps disasm + raw p-code.
- `oracle/capture <ghidra-src> <fixture.xml> --c` — dumps **Ghidra's own decompiled C**.
- **P0 work** (`port-plan.md`): extend `capture` to drive `decomp_dbg` to each action
  breakpoint and dump Ghidra's **per-phase IR** — the per-stage oracle for `tests/ir_parity.rs`.

Rebuild after editing `capture.cc`:

```sh
CPP=../ghidra/Ghidra/Features/Decompiler/src/decompile/cpp
g++ -std=c++11 -I"$CPP" -O2 -o oracle/capture oracle/capture.cc \
  -Wl,--whole-archive "$CPP/libdecomp_dbg.a" -Wl,--no-whole-archive -lbfd -lz
```

For WAR2 specifically, the per-function recipe's limits — including that it can change block
structure — are in `scripts/ghidra-decompile-war2.sh`'s header and in
[`docs/measurement-rules.md` §1](docs/measurement-rules.md).

## Verification (the quality bar)

Every change is verified; never ship semantically-wrong output.

- `cargo test --workspace` — must stay green.
- **`tests/disasm_golden.rs` — 254/254 disasm/p-code parity must NEVER regress.**
- **`tests/ir_parity.rs` (the gate for the faithful port)** — diffs mosura's IR against
  Ghidra's IR at each pipeline stage (post-heritage SSA tree, post-types, post-merge,
  structured blocks, C), **structurally exact**. A phase isn't done until its IR-parity
  is green on the datatests. This is the real port metric; faithfulness *is* the score.
- `tests/decompile_corpus.rs` — structural-similarity score against Ghidra's C over the x86-64
  datatests. **A coarse progress gauge, never a hard gate** — it must not block a faithful
  change.

Wrong-code gates (WAR2): `reached == cfg` per function, no undefined `goto` labels, no
fall-off-end, no empty `switch(){}` / `while(true){}`. A structuring change shows up in these
before it shows in the recompile.

Loop for porting a phase: read the Ghidra source for that component → translate it
faithfully into `src/decompile/` (mirroring Ghidra's file/class names) → diff mosura's
IR vs Ghidra's IR at that stage until exact → retire the corresponding prototype code →
record gotchas in memory.

## Conventions

- Respect agreed plan/design decisions; if a decision needs changing, ask first.
- Keep the disasm engine data-driven — no per-instruction or per-arch special-casing.
- Match Ghidra where it is the port target (formatting, structure, types); prefer
  faithfulness over "nicer" output.
- Commit/push only when asked.

## Pointers

- **Master plan: `docs/port-plan.md`.** Live status / phase checklist: `TODO.md`.
- **Measurement, instruments, and how claims go bad: `docs/measurement-rules.md`.**
- Per-Ghidra-class port status: `docs/coverage.md`.
- Detailed per-feature notes and gotchas: `.claude/memory/mosura-project.md`.
- Superseded (approximation-era, kept for history): `docs/decompiler-plan.md`,
  `floats-plan.md`, `switches-plan.md`, `type-system-plan.md`.
