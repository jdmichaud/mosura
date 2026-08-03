# Working on mosura

mosura is a CLI **port of Ghidra's logic** (not its UI) in Rust: a SLEIGH disassembler
+ p-code lifter, a p-code interpreter, and a decompiler. Ghidra is the golden oracle —
mosura's output is validated against it.

**Master plan: [`docs/port-plan.md`](docs/port-plan.md). Live status: [`TODO.md`](TODO.md).**

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

### Rule Zero, and its second clause (both bought with sessions, not hours)

**Rule Zero: before diagnosing why mosura's X differs from Ghidra's, READ GHIDRA'S OUTPUT FOR
THAT SPECIMEN.** It is usually already on disk (`war2-survey/ghidra-all.txt`, sections
`===== FUNC <va> =====`), costs one `awk`, and bounds the whole question. Four instrument
passes and five hypotheses were spent inside a rule Ghidra fires zero times on the fixture
because nobody looked first.

**Second clause — necessary is not sufficient: CONFIRM THE ORACLE DECOMPILED THE SAME
PROGRAM.** Reading Ghidra's output proves nothing if Ghidra was asked a different question.
The WAR2 per-function oracle imports only the requested bytes, so absent callees default to
*no parameters*; Ghidra's dead-code pass then deletes registers mosura correctly keeps live,
and deleting a register deletes the instructions that computed it — **which deletes basic
blocks and changes the block structure.** "Ghidra: 0 gotos, mosura: 3" was two different
programs, and it was read as our structuring defect for three sessions while CFG
granularity, `is_complex`, `select_goto` scoring and the collapse termination test were each
hunted and each found faithful.

So for any **structural** comparison — blocks, edges, gotos, labels, conditions, loop shape —
forcing the callee storage is **mandatory, not optional**:

```sh
GHIDRA_POSTSCRIPT=DecompileWithForcedParams.java GHIDRA_POSTSCRIPT_ARGS='63c35=EDX' \
  scripts/ghidra-decompile-war2.sh 63cbf 722c8 63c35 77dcb   # callees FIRST in the list
GHIDRA_POSTSCRIPT=DumpBlocks.java scripts/ghidra-decompile-war2.sh 77dcb   # Ghidra's partition
```

`DumpBlocks.java` prints Ghidra's own `HighFunction::getBasicBlocks` — the `BlockBasic` list
`CollapseStructure` runs on — and `MOSURA_CFG=1` prints the same fields, so the two partitions
diff line-for-line. Full ledger of the recipe's limits in `scripts/ghidra-decompile-war2.sh`'s
header; note the bias direction, because it is what made this survive: the pruning makes
*Ghidra's* output look better structured, so it reads as our bug.

### A death certificate is only valid for the evidence it was measured on

When you kill a hypothesis, **record what you measured it against**, because if that
measurement is later invalidated the hypothesis comes back. Two worked examples from one
arc:

- "The missing `PrintC::emitBlockGraph` loop is not the defect — there is no multi-component
  case here to emit." True of the 6-block graph it was measured on, false of the real
  8-block graph. The loop *was* the entire defect. It was recoverable only because the
  certificate said which graph it was measured on.
- "`rule_short_circuit` never declines on `is_complex`." The trace it was read from belonged
  to a **different function**. The conclusion survived; the evidence did not.

Corollary, and it has its own line because it is a standing trap: **a per-specimen instrument
must filter by function, or the operator must.** A bare `MOSURA_STRUCT=1` / `MOSURA_CFG=1`
dump interleaves *every* function `analyze_le_file` decompiles — callees included — so always
segment the output by its `CFG <name>` header before reading a single line of it.

### An inherited gate is a claim with an author and a date

"Blocked behind X", "gated on Y", "cast rules exhausted", "deferred with the Z lattice" — none of
these is a property of the code. Each is a **claim someone made at a commit**, and claims decay: the
prerequisite lands, the ground moves, or the search behind the word "exhausted" was never run.
**Three such gates were falsified in three days**, each by one read-only grounding pass, and in two
of them the agent citing the gate was the agent who had cited it to the lead an hour earlier.

Three rules, each bought:

1. **A GATE IS NOT RETIRED BY SATISFYING IT — someone has to go back and kill the note.**
   `docs/ir-cast-model-plan.md` said "Stage 0 COMPLETE" in its own text while work elsewhere was
   still being declined as "blocked behind retiring print-time re-inference". The prerequisite had
   landed months earlier. When you satisfy a prerequisite, hunt the notes that cite it.

2. **A GATE NOTE THAT COVERS MULTIPLE ITEMS RETIRES NONE OF THEM WHEN ONE IS EXAMINED.** One
   sentence in `setcasts.rs` deferred four things "with the composite/union lattice they concern".
   The four answers turned out to be: genuinely gated (`resolveUnion`), wrongly described AND
   measurably inert (`checkPointerIssues` — 0 occurrences in Ghidra's own WAR2 output), a live
   unported gap needing no lattice at all (the PTRADD refit — 59 measured firings, every one a
   pointer to a primitive), and one still open (the PTRSUB refit). **The bundling is HOW it
   survived**: examining any single item left the sentence standing, so the sentence kept being
   quoted. ⇒ **One claim per item, or the note is unfalsifiable in practice.**

3. **AN "EXHAUSTED" VERDICT IS A CLAIM ABOUT A SEARCH, AND IT DECAYS EVERY TIME THE GROUND MOVES
   UNDER IT.** "Cast rules exhausted" was written while `cast_standard` carried a live defect worth
   302 casts. And when you falsify part of such a claim, **say which part** — falsifying the
   parenthetical while explicitly refusing to claim the main sentence is what keeps the remainder
   trustworthy.

⇒ Before accepting any inherited "this is blocked", ground the specific token READ-ONLY. It costs
one pass and it has paid three times. And when you write a deferral yourself: one item, one reason,
and a **revival condition** that says what would make it wrong.

**Postscript, and it is the rule's strongest evidence: that one sentence deferred FOUR things, and
it was wrong about every one of them.** `resolveUnion` — genuinely gated, but for a different
reason. `checkPointerIssues` — wrongly described *and* measurably inert. The PTRADD refit — live,
needing no lattice at all, and porting it caught a rendering that was arithmetically false (below).
The PTRSUB refit — inert, and gated on the `ScopeLocal` **symbol query**, not the composite lattice
the note named. Four items, four different answers, **none of them the one the sentence asserted**.
The bundling is not incidental to that; it is the mechanism, because examining any single item left
the sentence standing.

### FALSE WHEN WRITTEN is a different failure from STALE — and it needs a different check

Every rule above treats a bad note as a claim that **decayed**. These did not. They were **never
true**:

- `cast.rs` deferred `findTruncation` because "mosura's `Datatype` has no struct or union
  metatype." `Datatype::Struct` landed `154b022` on **2026-06-25**; that comment is `844d5b1`,
  **2026-07-27** — a month later, with `Struct` already consumed by three modules.
- `ptrarith.rs`'s header called the lattice "primitive" in `86bd58f` at **19:20 on 2026-06-25**.
  `Array` and `Struct` landed in `154b022` at **15:15 the same day**, an ancestor of it. Four hours.

**The countermeasure differs, and that is the whole point.** A decayed claim is caught by
re-checking against *today's* tree. A false-when-written claim survives that check just as happily
— it looks like ordinary drift — and is caught only by checking the claim against the tree **as of
its own date**: `git blame` for the note's commit, then `git log --format=%ad -1 <commit>` on
whatever it asserts is absent, then `git merge-base --is-ancestor`. Two commands.

⇒ When a deferral rests on "X does not exist", **date X**. And correct it **additively**, keeping
the original wording inline — the error has to stay legible or the next reader cannot calibrate how
much to trust the surrounding text.

**Which deferrals to date-check FIRST — the split, once every audited note was dated per item:**

| claim, dated against its own commit | count | outcome |
|---|---|---|
| cites a **substrate** ("the lattice has no struct", "the primitive-lattice corpus") | 2 | **both FALSE WHEN WRITTEN** — by 4 hours and by a month |
| cites a **specific named function** ("`collapseIntMultMult` is deferred") | 5 | all **accurate when written**, refuted 3–17 days later |
| accurate then and now | 2 | — |

That is not a coincidence, and it is the practical rule: **a deferral citing a SUBSTRATE is at risk
of being false immediately**, because the substrate is edited by other people on other timelines and
the author never re-checks it. A deferral citing a **specific function** is usually true when
written and simply decays when someone ports it.

⇒ **Date the substrate claims first.** They are the ones that can be born wrong. And when you write
a deferral yourself, prefer naming the function you did not port over characterising the lattice —
the first ages honestly, the second can be false before the commit lands.

### A DECLARED VARIANT IS NOT AN INHABITED LATTICE

Correcting a substrate claim is itself a substrate claim, and it can be wrong the same way. Having
found "mosura's `Datatype` has no struct metatype" false — `Datatype::Struct` was added a month
before that note — the audit then asserted the struct work was "not lattice-blocked, merely
unwritten." **That was wrong, and it shipped in two commits before the census caught it.**

`Datatype::Struct` is declared at `types.rs:42` and read in five modules — and **constructed
nowhere**. Every occurrence is a `matches!`, a match arm, or a field read. The variant is
**uninhabited**, so *0 of 37* corpus SUBPIECEs and *0 of 1704* WAR2 SUBPIECEs carry a struct-typed
input, and every `TypeStruct::*` port would be inert.

⇒ **"Does the variant exist?" is the wrong question. Ask "does anything CONSTRUCT one?"** — one
grep, and it is the difference between a lattice you have and a lattice you can spell:

```sh
grep -rn "Datatype::Struct(" crates/mosura/src/decompile/   # a constructor, or only consumers?
```

And note the shape of the mistake, because it is the tempting one: the correction was *more* correct
than what it replaced and still wrong, so it read as progress. **A refutation earns no exemption
from the standard it just enforced.**

### Measure a rule where the rule runs

`ActionSetCasts` runs once, dead-last, on settled IR — a probe there sees a fixed picture. A
**mainloop rule** is re-applied to a graph that changes under it, so a probe on settled IR would
describe a state the rule never sees. The reach of `RulePtraddUndo` was therefore measured with a
probe **shaped as a `Rule`, registered in Ghidra's own `actprop` slot**, returning 0 — which keeps
it inert, because an `ActionPool` fixpoint counts changes and a rule reporting none cannot perturb
the pool's order or termination.

Same family as "confirm the oracle decompiled the same program": **prove the instrument observed
the state you are reasoning about.** For a rule, that means running as one.

### A bare count cannot answer the only question a gate asks

Every gate in this project is quoted in **functions**: which ones regressed, which ones are
byte-clean, which ones lost a call. So an instrument that prints a **total** cannot feed one. The
`MOSURA_PTRFIT` probe counted 59 misfitting PTRADDs and could not say *where* — and the pre-check
that decided the refit was safe to land was intersecting those 59 with the byte-clean 16, which is
a **set operation on function names**. Adding the function name to each row was the difference
between a number and a gate.

Same coin as "a total can hide a per-function truth" and "check SET MEMBERSHIP, not totals" — but
pointed at the instrument rather than the reading: **if a probe does not name its function, fix the
probe before you quote it.**

### An instrument's known bias belongs IN THE INSTRUMENT

`scripts/cast-census.py` reads **per line**, and its position test looks ahead for the start of an
operand — so a cast that *ends* a line is uncounted. Ghidra's pretty-printer wraps and mosura's
emitter does not, so **every mosura-vs-Ghidra cast count under-counts Ghidra**. That bias produced
a specimen (`threedim`, "8 vs 6" — whole-file it is **8 vs 8 with the identical multiset**), a lead
ruling, and a preference for which fixture to take first. One of the two signs that made the
specimen look well-guarded was fabricated by the tool.

The bias was left in place deliberately — fixing it would move the 9031 anchor and void every delta
measured against it — so the script now **prints the caveat on every run**. A known bias that lives
only in the operator's head is the same failure as a recipe that lives only in the operator's head.
⇒ **When you decline to fix a bias, make the instrument say so out loud.**

### The decision rule (read this before you revert anything)

The C-similarity (`ccompare`) is a **coarse gauge, never the gate.** It erases names,
types, and numbers, and it *rewards* a missing/empty rendering over a correct-but-verbose
one. Do not let it drive decisions. Concretely:

1. **A change that passes `ir_parity` + `disasm_golden` and matches Ghidra's IR is correct.
   KEEP it — even if the similarity score drops.** Parity is the temperature; ccompare is the
   thermometer. Don't revert the patient because the thermometer twitched.
2. **A similarity dip after a *faithful* change almost always means a downstream piece isn't
   ported yet** (e.g. heritage `normalizeWriteSize` produces `SUBPIECE`/`PIECE` that need
   Ghidra's sub-piece *rules*, or the for-loop detector to look through them). The fix is to
   **port that downstream piece too**, not to revert the faithful upstream one. Approximations
   don't compose; faithful ports *do* — but only once their consumers exist. Land the
   subsystem, not one orphaned half of it.
3. **Only revert output that is genuinely WRONG** — output Ghidra would *never* emit, confirmed
   by reading Ghidra's IR/C via the oracle (`oracle/capture --c`, `decomp_dbg`). Never revert
   because a noisy token gauge moved.
4. **Never invent a heuristic** (a "cycle gate," a "multi-exit check," a "trivial-case
   detector," a size threshold) to paper over a gap. If Ghidra makes a decision, Ghidra has
   code for it — find it (`jumptable.cc`, `heritage.cc`, `coreaction.cc`, …) and port *that*.
   A heuristic that happens to match a few corpus functions is the exact anti-pattern above.
5. **GROUND BEFORE YOU CODE — dump the actual IR and Ghidra's actual `--c` first.** The most
   expensive failure mode is *guessing the mechanism*: building a fix on what you assume the IR
   contains or what you remember Ghidra emits, then reverting when it doesn't work. Before
   writing a line: (a) dump mosura's IR for the target function (`f.print_raw()`, or a tiny
   `examples/` script over its ops) and *read* what's actually there; (b) run
   `oracle/capture ../ghidra <fixture> --c` and read Ghidra's actual output for that function.
   One real example beats five clever guesses. A whole session was lost guessing a cast
   mechanism five times — every premise (cast renderer, copy-prop guard, `normalizeWriteSize`,
   addrtied) was wrong, and reading the IR *first* would have shown it in minutes.

If you catch yourself about to `git checkout`/revert a parity-clean change because the
corpus average dipped, **stop** — re-read this section. The mandate is to convert Ghidra,
not to climb the gauge. And if you've reverted the same area twice, **stop guessing and read
the IR** (rule 5) — the mechanism is not what you think.

- Ghidra source (pinned to tag `Ghidra_12.0.3_build`, commit `09f14c92`): `../ghidra` —
  fetch + pin + compile the `.sla` with `scripts/setup-ghidra.sh` (`GHIDRA_SRC` overrides).
- Decompiler core to port: `../ghidra/Ghidra/Features/Decompiler/src/decompile/cpp`
  (e.g. `coreaction.cc`, `printc.cc`, `printlanguage.cc`, `funcdata*.cc`, `type.cc`,
  `jumptable.cc`).

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
  out), used by `decompile_corpus`. (The old `src/decomp/` prototype decompiler was removed.)
- `oracle/capture.cc` — offline oracle tool, built by `scripts/setup-oracle.sh`.
- `goldens/` — committed disasm / p-code goldens.

## The oracle

### ⭐ WHICH ORACLE ANSWERS WHICH QUESTION — check this BEFORE quoting a difference

There are two Ghidra oracles and **they disagree BY CONSTRUCTION**. Routing a question to the
wrong one has now falsified two approved framings, and both times the fix we were about to build
would have **invented a Java-layer behaviour into a C++ port**:

| oracle | what it is | answers |
|---|---|---|
| `oracle/capture --c` | the **C++ decompiler** alone, on an XML fixture. No Program, no symbol table. | how the decompiler **renders** something: names it generates, types, casts, literals, structure |
| `war2-survey/ghidra-all.txt` | **analyzeHeadless** — the full Ghidra, Java layer included, with a populated **symbol table** | what the whole tool produces on a real binary: recovered functions, call targets, applied symbols |

**mosura ports the C++ decompiler.** So for any question about what the decompiler itself emits,
`oracle/capture --c` is the reference and analyzeHeadless is the WRONG oracle — its output carries
names and types the Java layer authored, which the decompiler merely receives and prints verbatim.

**Ghidra's own source is the proof:** `ghidra_arch.hh:169` exists solely to recognise names "of form
FUN_.. or DAT_.." — i.e. the Java layer mints those, and the decompiler knows them as foreign.

The two worked examples, both of which cost a grounding pass and nearly cost a wrong port:

- **`undefined<N>` vs `xunknown<N>`** (task #9). `undefined4` comes from Ghidra's **Java** type
  manager; the C++ `TypeFactory` builds `xunknown4`. `xunknown<N>` IS the faithful port — the
  approved framing said the opposite.
- **`DAT_0008127a` vs `cRam0008127a`** (task #14). `DAT_` is a Java **symbol-table** name.
  `ScopeInternal::buildVariableName` (database.cc:2454) builds `<printNameBase stem><Space><addr>`,
  and `oracle/capture --c` emits exactly mosura's form, character for character. Porting toward
  `DAT_` would have been an invention — **and it would have retyped every global**, because the
  survey's declaration synthesis keys the C type off the identifier's first letter.

⇒ **STATE WHICH ORACLE YOU ARE QUOTING, every time.** If a "difference vs Ghidra" involves a NAME or
a TYPE NAME, suspect the Java layer first and re-ask `oracle/capture --c` before writing anything.

`scripts/setup-oracle.sh` (needs the pinned `ghidra/` + a C++ toolchain) builds
`oracle/capture`:

- `oracle/capture <ghidra-src> <fixture.xml>` — dumps disasm + raw p-code.
- `oracle/capture <ghidra-src> <fixture.xml> --c` — dumps **Ghidra's own decompiled C**.
- **P0 work** (`port-plan.md`): extend `capture` to drive `decomp_dbg` to each action
  breakpoint and dump Ghidra's **per-phase IR** (post-heritage SSA tree via `Funcdata::
  printRaw`, post-types, post-merge, the structured block tree) — the per-stage oracle for
  `tests/ir_parity.rs`.

Rebuild after editing `capture.cc`:

```sh
CPP=../ghidra/Ghidra/Features/Decompiler/src/decompile/cpp
g++ -std=c++11 -I"$CPP" -O2 -o oracle/capture oracle/capture.cc \
  -Wl,--whole-archive "$CPP/libdecomp_dbg.a" -Wl,--no-whole-archive -lbfd -lz
```

## Verification (the quality bar)

Every change is verified; never ship semantically-wrong output.

- `cargo test --workspace` — must stay green.
- **`tests/disasm_golden.rs` — 254/254 disasm/p-code parity must NEVER regress.**
- **`tests/ir_parity.rs` (the gate for the faithful port)** — diffs mosura's IR against
  Ghidra's IR at each pipeline stage (post-heritage SSA tree, post-types, post-merge,
  structured blocks, C), **structurally exact**. A phase isn't done until its IR-parity
  is green on the datatests. This is the real port metric; faithfulness *is* the score.
- `tests/decompile_corpus.rs` — the faithful pipeline's structural-similarity score (via
  `ccompare`) against Ghidra's C over the x86-64 datatests. **A coarse progress gauge,
  never a hard gate** — it must not block a faithful change (the trap the old
  `datatest_score` ratchet fell into).

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
- Detailed per-feature notes and gotchas: `.claude/memory/mosura-project.md` (also the
  live auto-memory).
- Superseded (approximation-era, kept for history): `docs/decompiler-plan.md`,
  `floats-plan.md`, `switches-plan.md`, `type-system-plan.md`.
