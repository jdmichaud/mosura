# Measurement rules

**Read this before you quote a number, retire a claim, or trust an instrument.**
Not before every task — [`AGENTS.md`](../AGENTS.md) is what you read to start work.

Every rule here was bought by a real error on this project, and each names the error. They are
all one idea: **an instrument, an oracle, or a note can tell you something false in a shape that
looks exactly like a result.** The countermeasures differ; the failure does not.

---

## 1. Rule Zero — read Ghidra's output for the specimen first

**Before diagnosing why mosura's X differs from Ghidra's, READ GHIDRA'S OUTPUT FOR THAT
SPECIMEN.** It is usually already on disk (`war2-survey/ghidra-all.txt`, sections
`===== FUNC <va> =====`), costs one `awk`, and bounds the whole question.

Four instrument passes and five hypotheses were spent inside a rule Ghidra fires **zero times**
on the fixture, because nobody looked first.

### Second clause — necessary is not sufficient: confirm the oracle decompiled the SAME PROGRAM

Reading Ghidra's output proves nothing if Ghidra was asked a different question. The WAR2
per-function oracle imports only the requested bytes, so absent callees default to *no
parameters*; Ghidra's dead-code pass then deletes registers mosura correctly keeps live, and
deleting a register deletes the instructions that computed it — **which deletes basic blocks and
changes the block structure.**

"Ghidra: 0 gotos, mosura: 3" was two different programs. It was read as our structuring defect
for three sessions while CFG granularity, `is_complex`, `select_goto` scoring and the collapse
termination test were each hunted and each found faithful.

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
header. **Note the bias direction, because it is what made this survive:** the pruning makes
*Ghidra's* output look better structured, so it reads as our bug.

---

## 2. Which oracle answers which question

There are two Ghidra oracles and **they disagree BY CONSTRUCTION**. Routing a question to the
wrong one has falsified two approved framings, and both times the fix we were about to build
would have **invented a Java-layer behaviour into a C++ port**.

| oracle | what it is | answers |
|---|---|---|
| `oracle/capture --c` | the **C++ decompiler** alone, on an XML fixture. No Program, no symbol table. | how the decompiler **renders** something: names it generates, types, casts, literals, structure |
| `war2-survey/ghidra-all.txt` | **analyzeHeadless** — the full Ghidra, Java layer included, with a populated **symbol table** and type manager | what the whole tool produces on a real binary: recovered functions, call targets, applied symbols |

**mosura ports the C++ decompiler.** For any question about what the decompiler itself emits,
`oracle/capture --c` is the reference and analyzeHeadless is the WRONG oracle — its output
carries names and types the Java layer authored, which the decompiler merely receives and prints
verbatim.

**Ghidra's own source is the proof:** `ghidra_arch.hh:169` exists solely to recognise names "of
form FUN_.. or DAT_.." — i.e. the Java layer mints those, and the decompiler knows them as
foreign.

Two worked examples, both of which nearly cost a wrong port:

- **`undefined<N>` vs `xunknown<N>`.** `undefined4` comes from Ghidra's **Java** type manager;
  the C++ `TypeFactory` builds `xunknown4`. **`xunknown<N>` IS the faithful port** — the approved
  framing said the opposite.
- **`DAT_0008127a` vs `cRam0008127a`.** `DAT_` is a Java **symbol-table** name.
  `ScopeInternal::buildVariableName` (database.cc:2454) builds `<printNameBase stem><Space><addr>`,
  and `oracle/capture --c` emits exactly mosura's form, character for character. Porting toward
  `DAT_` would have been an invention — **and it would have retyped every global**, because the
  survey's declaration synthesis keys the C type off the identifier's first letter.

⇒ **State which oracle you are quoting, every time.** If a "difference vs Ghidra" involves a NAME
or a TYPE NAME, suspect the Java layer first and re-ask `oracle/capture --c` before writing
anything.

**And there are questions neither oracle can answer.** On WAR2, `capture --c` cannot run (the
DOS/4GW loader problem is why `ghidra-all.txt` exists) and analyzeHeadless carries a Java type
model — so a **cast or type** comparison on WAR2 is confounded with no clean side. Ground those
on the corpus and carry the WAR2 numbers as unattributable.

---

## 3. Checking an inherited claim

"Blocked behind X", "gated on Y", "cast rules exhausted", "deferred with the Z lattice", "the
lattice has no struct" — **none of these is a property of the code.** Each is a claim someone made
at a commit. **Three such gates were falsified in three days**, each by one read-only grounding
pass, and in two of them the agent citing the gate was the agent who had cited it an hour earlier.

### The three ways a claim goes bad — and the first two checks miss the third

| mode | how it fails | check |
|---|---|---|
| **decayed** | true when written, overtaken later | re-check against today's tree |
| **born wrong** | false at the moment of writing | date it against **its own commit** |
| **true but vacuous** | the thing exists and is never produced | grep for a **constructor**, not the variant |

**Born wrong is real and it is not rare.** `cast.rs` deferred `findTruncation` because "mosura's
`Datatype` has no struct or union metatype" — `Datatype::Struct` landed `154b022` on
**2026-06-25**; that comment is `844d5b1`, **2026-07-27**, a month later, with `Struct` already
consumed by three modules. `ptrarith.rs`'s header called the lattice "primitive" in `86bd58f` at
**19:20 on 2026-06-25**; `Array` and `Struct` landed in `154b022` at **15:15 the same day**, an
ancestor of it. **Four hours.**

A decayed claim is caught by re-checking today's tree. A false-when-written claim survives that
check just as happily — it looks like ordinary drift. Catch it by checking the claim against the
tree **as of its own date**: `git blame` for the note's commit, `git log --format=%ad -1 <commit>`
on whatever it asserts is absent, then `git merge-base --is-ancestor`. Two commands.

**True-but-vacuous is the one that catches your own correction.** Having found the struct claim
false, the audit then asserted the work was "not lattice-blocked, merely unwritten." **That was
wrong and it shipped in two commits.** `Datatype::Struct` is declared and read in five modules —
and **constructed nowhere.** Every occurrence is a `matches!`, a match arm, or a field read. The
variant is uninhabited, so *0 of 37* corpus SUBPIECEs and *0 of 1704* WAR2 SUBPIECEs carry a
struct-typed input, and every `TypeStruct::*` port would be inert.

⇒ "Does the variant exist?" is the wrong question. Ask **"does anything CONSTRUCT one?"**

```sh
grep -rn "Datatype::Struct(" crates/mosura/src/decompile/   # a constructor, or only consumers?
```

Note the shape of that mistake, because it is the tempting one: **the correction was *more*
correct than what it replaced and still wrong, so it read as progress. A refutation earns no
exemption from the standard it just enforced.**

### Which claims to date-check first

Once every audited note was dated per item:

| claim, dated against its own commit | count | outcome |
|---|---|---|
| cites a **substrate** ("the lattice has no struct", "the primitive-lattice corpus") | 2 | **both FALSE WHEN WRITTEN** — by 4 hours and by a month |
| cites a **specific named function** ("`collapseIntMultMult` is deferred") | 5 | all **accurate when written**, refuted 3–17 days later |
| accurate then and now | 2 | — |

That is not a coincidence. **A deferral citing a SUBSTRATE is at risk of being false
immediately**, because the substrate is edited by other people on other timelines and the author
never re-checks it. A deferral citing a **specific function** is usually true when written and
simply decays when someone ports it.

⇒ **Date the substrate claims first.**

### Two more rules about gates

1. **A GATE IS NOT RETIRED BY SATISFYING IT — someone has to go back and kill the note.**
   `docs/ir-cast-model-plan.md` said "Stage 0 COMPLETE" in its own text while work elsewhere was
   still declined as "blocked behind retiring print-time re-inference". The prerequisite had
   landed months earlier. When you satisfy a prerequisite, hunt the notes that cite it.

2. **AN "EXHAUSTED" VERDICT IS A CLAIM ABOUT A SEARCH, AND IT DECAYS EVERY TIME THE GROUND
   MOVES.** "Cast rules exhausted" was written while `cast_standard` carried a live defect worth
   302 casts. And when you falsify *part* of such a claim, **say which part** — falsifying the
   parenthetical while explicitly refusing to claim the main sentence is what keeps the remainder
   trustworthy.

### How to write one so it ages honestly

**Name the function you did not port, or the variant that does not exist — never characterise the
lattice.** A lattice claim has three ways to rot; a name has none, because a name is
grep-checkable and an adjective is not.

Of eight audited deferrals, exactly one had its stated reason survive:
`inheritResolution`/`setStopTypePropagation`, gated on a union metatype — and it survived
**because `Datatype::Union` has no variant at all**, so there is nothing about it that could be
true-but-vacuous and nothing for a later commit to quietly satisfy.

One item, one reason, and a **revival condition** that says what would make it wrong.

---

## 4. Decompose along the dependency structure — in both directions

**Bundling hides difference.** One sentence in `setcasts.rs` deferred four things "with the
composite/union lattice they concern". The four answers were: genuinely gated (`resolveUnion`),
wrongly described *and* measurably inert (`checkPointerIssues` — 0 occurrences in Ghidra's own
WAR2 output), a live unported gap needing no lattice at all (the PTRADD refit — 59 measured
firings, every one a pointer to a primitive), and one still open (the PTRSUB refit, gated on the
`ScopeLocal` **symbol query**, not the lattice the note named).

**Four items, four different answers, none of them the one the sentence asserted** — and **the
bundling is HOW it survived**: examining any single item left the sentence standing, so the
sentence kept being quoted.

**But over-splitting invents independence, exactly as bundling hides difference.** Applying "one
item, one reason" mechanically produced its own error: `collapseIntMultMult` was filed as a
separate item, and **it is not separable at all** — its only caller in Ghidra is inside the
`while (valid && distributeOp != 0)` loop (ruleaction.cc:6463), where it exists solely to collapse
`(x * #c) * #d` produced by `distributeIntMultAdd`. Porting it alone would be **dead code**. The
filing asserted a separability that was never checked.

⇒ The rule is not "always split". It is **decompose along the dependency structure, and verify
the decomposition**: two things are separate items only if **each can land alone and mean
something.** Before splitting, ask who calls what. Before bundling, ask whether one reason really
covers both. **Both directions are claims, and both need the same evidence.**

---

## 5. A retraction must reach every copy of the claim

Additive correction keeps an error legible. It does **not** stop a stale copy being quoted,
because the copy is somewhere else. Worked example:

1. Task text filed `collapseIntMultMult` as "genuinely unported **and independent of the struct
   question**".
2. Measurement retracted the independence. **The retraction went into the commit message and a
   successor task.**
3. The **original task text was never touched**, so the next reader — reading the task, not the
   commit — quoted the retracted claim back as established and issued an instruction based on it.

**The commit is the audit trail; the task, the doc comment and the plan are what people actually
read.** A retraction that lands only in the trail did not happen, for practical purposes.

⇒ **Patch the claim where it was WRITTEN, not only where it was found wrong.** Mark it at the
point it appears (`❌ RETRACTED (<sha>) — was: "…"`, then the correction), so the stale sentence
cannot be read without its refutation. **Grep for the claim's own words before declaring the
retraction done** — a claim usually has more copies than you remember writing.

---

## 6. Instruments

### A death certificate is only valid for the evidence it was measured on

When you kill a hypothesis, **record what you measured it against** — if that measurement is later
invalidated, the hypothesis comes back:

- "The missing `PrintC::emitBlockGraph` loop is not the defect — there is no multi-component case
  here to emit." True of the 6-block graph it was measured on, false of the real 8-block graph.
  **The loop was the entire defect.** It was recoverable only because the certificate said which
  graph it was measured on.
- "`rule_short_circuit` never declines on `is_complex`." The trace it was read from belonged to a
  **different function**. The conclusion survived; the evidence did not.

**Corollary — a per-specimen instrument must filter by function, or the operator must.** A bare
`MOSURA_STRUCT=1` / `MOSURA_CFG=1` dump interleaves *every* function `analyze_le_file`
decompiles, callees included. Segment by the header before reading a line.

### Measure a rule where the rule runs

`ActionSetCasts` runs once, dead-last, on settled IR — a probe there sees a fixed picture. A
**mainloop rule** is re-applied to a graph that changes under it, so a probe on settled IR
describes a state the rule never sees. `RulePtraddUndo`'s reach was therefore measured with a
probe **shaped as a `Rule`, registered in Ghidra's own `actprop` slot**, returning 0 — which keeps
it inert, because an `ActionPool` fixpoint counts changes and a rule reporting none cannot perturb
the pool's order or termination.

Same family as Rule Zero's second clause: **prove the instrument observed the state you are
reasoning about.** For a rule, that means running as one.

### A bare count cannot answer the only question a gate asks

Every gate in this project is quoted in **functions**: which regressed, which are byte-clean,
which lost a call. An instrument that prints a **total** cannot feed one. `MOSURA_PTRFIT` counted
59 misfitting PTRADDs and could not say *where* — and the pre-check that decided the refit was
safe to land was intersecting those 59 with the byte-clean 16, **a set operation on function
names.** Adding the name to each row was the difference between a number and a gate.

⇒ **If a probe does not name its function, fix the probe before you quote it.**

### An identical total across a real change means the PREDICATE is broken

The reassuring reading of "the number didn't move" is that the code didn't move. The other
reading is that the instrument is measuring something that was never going to move, and it is
the more likely one whenever the change under test provably touched the population.

This happened **three times in one day** (2026-08-05), in three different shapes:

- A use-before-def detector counted the *declaration* `int4 iVar1;` as a read of `iVar1`. It
  flagged 1072 of 1303 functions and returned **exactly 5347 on four different emit images** —
  including two that differed by a landed fix. Scanning from the first statement instead: 938 /
  930 / 931 / 921, and the movement was the whole signal.
- "The 40 missed for-loops ARE the 40 false comma-whiles, one defect with two symptoms" was
  inferred from both sets having 40 members. Measured properly, **the intersection was 12.**
  Two populations of equal size, largely disjoint.
- A manifest row count read while the emit was still writing looked plausible and was wrong.

⇒ **Equal totals are a hypothesis to disprove, not a result.** Before reporting "no change",
either (a) show the SET, not the count — `members()` in `scripts/war2-wrongcode-scan.py` exists
because keying a delta on the *function* rather than the individual finding let one function
trade `pcVar4` for `pcVar3` and score as a wash; or (b) exhibit one input the predicate *should*
have flagged and show it flagged. A predicate that cannot move is not a stable measurement, it
is a broken one, and it will read as corroboration for as long as nobody checks.

Sibling of *A bare count cannot answer the only question a gate asks*, above, and of §7's
counting traps.

### A null result must distinguish the reasons it could be null

Counting only *declines* cannot separate "never needed" from "never a candidate". Count both.
Print metatypes on non-hits so a zero is distinguishable from a probe that never ran — *37 and
1704 rows prove it ran.*

### An instrument's known bias belongs IN the instrument

`scripts/cast-census.py` reads **per line**, and its position test looks ahead for the start of an
operand — so a cast that *ends* a line is uncounted. Ghidra's pretty-printer wraps and mosura's
emitter does not, so **every mosura-vs-Ghidra cast count under-counts Ghidra.** That bias produced
a specimen (`threedim`, "8 vs 6" — whole-file it is **8 vs 8 with the identical multiset**), a
ruling, and a preference for which fixture to take first. One of the two signs that made the
specimen look well-guarded was **fabricated by the tool.**

The bias was left in place deliberately — fixing it would move the anchor and void every delta
measured against it — so the script **prints the caveat on every run.**

⇒ **When you decline to fix a bias, make the instrument say so out loud.** A bias that lives only
in the operator's head is the same failure as a recipe that lives only in the operator's head.

### An instrument must be reproducible by someone who was not there

The cast census was quoted as a standing gate in two commits with **no definition anywhere in the
tree** — the delta was sound within the session that ran it; the absolutes were reproducible by
nobody. A gate whose recipe lives only in the operator is not a gate.

### A predicted signal is the most dangerous thing an instrument can fabricate

Told to watch `lanedivide` for an apparent regression as a masked-absence signal, the probe
**manufactured exactly that signal** — 65 functions with "a second change" — out of its own blind
spot (a one-letter regex that could not match two-letter stems). It arrived **pre-believed**,
because it confirmed a ruling.

⇒ **Read the raw diff rather than explaining the artifact.** A recurring "artifact" in a diff
instrument is a defect in the instrument until proven cosmetic.

### An instrument's silence about a subsystem is not agreement

`infertypes` fired **zero times in both traces** on every fixture — which read as agreement and
was really **invisibility**: `OPACTION_DEBUG` is a p-code-**op mutation** log, and
`ActionInferTypes` assigns types to **varnodes** and mutates no ops. Unnoticed for a whole
campaign.

Sharper still: **a non-event is invisible to a mutation log on both sides simultaneously.** A
SubvariableFlow trace that *aborts* mutates nothing, so two correctly-built instruments named the
subsystem and neither could explain why.

⇒ When two instruments agree a subsystem is implicated but neither can explain it, ask **what
class of event they both fail to record.**

### Read the SHARED section of a diff, not only the asymmetric ones

A count mismatch on a rule **both** engines fire is a divergence too, and it hides in plain sight:
`subvar_zext` 6 vs 10, `subzext` 8 vs 5 on the same fixture — the op trace had been naming
SubVariableFlow all along, in the section nobody read.

### Before rebuilding a dependency to obtain a capability, grep whether you already have it

`TYPEPROP_DEBUG` was assumed to need an explicit `-D` rebuild; `types.h:88-91` shows `CPUI_DEBUG`
already defines it. One grep would have settled it before a build.

---

## 7. Reading numbers

- **A total can hide a per-function truth.** `-j` off vs on produced **identical status totals**
  while **149 of 1303 functions generated different bytes.** "The flag changes nothing" would have
  passed on the totals alone and was flatly false.
- **"The metric is indecisive" must never be asserted from an aggregate.** Establish it at the
  granularity of the goal, or you are declaring a tie in a race you did not run.
- **Check set MEMBERSHIP, not totals.** Which functions, not how many.
- **Prove both sides of an A/B were built from the state you think.** `cargo build --release` does
  **not** rebuild `examples/` — use `cargo run --release --example …`. Validate a baseline file by
  confirming the functions whose output did *not* change show **zero** status disagreements.
- **Key survey files by the `FUN_xxxxxxxx` in each `.c`, never by manifest index** — the EMIT
  regenerates `manifest.tsv` and the index→VA mapping shifts when functions are discovered.
- **State which image each side of a byte comparison reads** (raw on-disk vs fixup-applied). The
  headline metric was wrong for weeks because the two sides differed.
- **Read what a predicate literally tests.** `compare.py` reports `%match` for length-mismatched
  functions and `%comparable-match` for same-length ones — ranking across both put a *truncated*
  function at the top of a "near-miss" list.
- **Measure a predicate's base rate on a control before quoting its hit rate.** 217 functions
  constant-fold a branch and most are fine; only the conjunction with call destruction meant
  anything.
- **When a probe reports a large pre-existing defect count, treat the SIZE as evidence the
  predicate is wrong** until proven otherwise.
- **A category name is not a diagnosis.** "codegen/regalloc" was a `cause_guess()` default branch —
  i.e. *unclassified* — and it survived for months as a supposed ceiling.
- **Numbers are stale unless stamped `@sha == HEAD`**, and say so when they are *carried* rather
  than re-measured.
- **A wrong-code gate must test the INVARIANT, not a SYMPTOM.** `reached == cfg` is an invariant;
  "no undefined labels" was a symptom of it, and the symptom saw 40% of the defect.
- **When you add a wrong-code scan, enumerate the shapes it does NOT cover** — never let a new scan
  imply completeness. And **when a change adds an output shape, extend the scan in the same
  commit**: a predicate cannot see a rendering that postdates it, and it will report the class
  closed.
- **"Removing it changed no output" ≠ "it never ran."** Only the first had a measurement behind it;
  an observer probe found the fold firing 90 times.
- **A flagged risk that measurement retires must be reported as loudly as one measurement
  confirms**, or the flag quietly becomes folklore.

---

## 8. Fixing things

- **Never fix a generated file — fix its generator.** `prelude.h` is generated on every EMIT; a
  hand-fix to the output was reverted by the next run and mislabelled 47 functions.
- **When an invention needs a fix, first check whether the faithful mechanism is already in the
  tree** — the fix may be a **deletion**. `RuleMultMult` needed a mask; Ghidra's
  `RuleAddMultCollapse` was already ported *with* one, in the same pool.
- **A variant match is not a metatype test.** Ghidra tests `getMetatype()`; matching the enum
  variant is equivalent only until a new variant appears, and then it silently drops it.
- **Faithfulness governs what we EMIT; the binary governs how we COMPILE it.** A wcc386 flag is
  justified by the original build's bytes, never by our type model — justifying one from our types
  is a category error, and it cost a revert.
- **Faithful-but-inert is a legitimate landed state — label it, with its measurement attached**,
  so a future consumer knows the inertness was conditional, not intrinsic.
- **Pre-file the prediction that would prove a retirement COMPLETE**, and state what a miss would
  mean. "136 → near 0; if not, a second unmasked site exists" landed exactly.

## 9. WGSS has ONE canonical computation

**Canonical: `scripts/war2-verdicts.sh`'s census** — over the recompile TSV's user rows,
`WGSS = 1 − Σ orig_insns·(1 − sim) / Σ orig_insns` (columns 9 and 7 of the
`recompile_check --out` contract). Every number in docs/byte-exact-status.md,
docs/plan-to-0.8.md and the campaign memories is this computation; quote no other.

Non-canonical variant on record: the wc2src-reconciliation session's ad-hoc awk
(`docs/wc2src-reconciliation.md` on the `wc2src-reconcile` branch, "WGSS 0.4687 by the
documented formula" for the same zc47 files the census scores 0.4840). The two differ by a
consistent ≈3.3% normalization — deltas agree, levels do not. The offset predates the
2026-08-24 campaign; do not mix the series. If a future session needs the census outside
the script, it is the one-liner above — not a re-derivation (the script exists precisely
because ad-hoc column picks have burned rounds before; see its header).

### The denominator is part of the series — a foreign-excluded run is not comparable to a full one

`recompile_check --exclude-foreign <file>` (foreign-module scope,
`docs/foreign-scope-plan.md`) drops the named third-party libraries from the denominator, so
its WGSS/EXACT are a **different series** from a full run — the same trap as the ad-hoc-awk
offset above, but silent, because the TSV looks identical. Two guards make it visible: the
output TSV's header carries an `EXCLUDE-FOREIGN=<file>@<hash>` stamp, and `war2-verdicts.sh`
prints a `!! FOREIGN-EXCLUDED SERIES` line when it sees one. **The canonical WAR2 series is the
FULL denominator (no `--exclude-foreign`)** until JD decides otherwise; a foreign-excluded number
is only ever reported *next to* the full one (both-numbers), never as the headline. Do not compare
a stamped TSV against an unstamped one.
