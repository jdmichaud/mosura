# Byte-exact recompilation — the architecture

*What has to exist for mosura to decompile a binary into source that the original toolchain
recompiles into the same bytes. WAR2.EXE is the first subject, not the design target: every
piece below is stated so that a second binary, compiler, or architecture costs configuration
rather than a rewrite.*

## 1. The problem, stated exactly

Given a linked image `B` and a toolchain `T`, find source `S` with

```
link(compile(S, T)) == B          (modulo where things are placed)
```

The decompiler alone cannot deliver this, and it is worth being precise about why. `compile`
is many-to-one: an enormous set of sources maps to the same bytes, and a much larger set maps
to bytes that are merely *equivalent*. A decompiler recovers a member of the equivalence class
of programs that compute what `B` computes. Byte-exactness asks for a member of a much smaller
set — the preimage of `B` under `compile` — and nothing in a decompiler's design aims there.
Ghidra in particular is built to produce *readable* C, which means deliberately discarding
exactly the information that determines code generation: which value lives in which register,
in what order independent statements run, whether a temporary exists at all.

So byte-exactness is an **inverse compilation** problem, and it decomposes into four questions
that need different machinery:

| # | question | state |
| --- | --- | --- |
| P1 | what does each function compute? | the existing Ghidra-faithful decompiler |
| P2 | what are its interfaces — prototype, convention, types, globals? | partial; the largest measured defect class |
| P3 | *which* of the equivalent C sources compiles to these bytes? | **absent** |
| P4 | what was the build — flags, TU grouping, order? | partial (per-function flag table) |

P3 is the one with no existing answer, and it is not answerable open-loop. The map from source
form to code is the compiler's own; its inverse is not something to derive from first
principles. It has to be **searched, with the compiler in the loop**.

## 2. Why the loop needs an instrument first

A search needs a signal that improves as the candidate gets closer. Byte agreement is not one:
one inserted instruction shifts every later byte, so a candidate one register-allocation choice
from exact scores the same as an unrelated function. That is not a hypothetical — under byte
comparison, 2074 of 2552 WAR2 mismatches scored under 25%, and 96% of them were attributed to
"unclassified". There was no gradient and no diagnosis.

`crates/mosura/src/recompile/` supplies both. Both sides are lifted with mosura's own SLEIGH
engine, the candidate object is **symbolically relinked** to the original's addresses (rather
than masking relocated bytes, which would also pass a candidate calling the wrong function),
the two instruction streams are aligned, and every divergence is named:

| class | means | whose problem |
| --- | --- | --- |
| `missing` | the candidate computes LESS than the original | **ours — a wrong-code bug** |
| `extra` | it computes more | ours — usually a spurious interface |
| `branch-target` | aligned, but control goes elsewhere | ours — structuring |
| `immediate` / `operand-form` | same operation, different constant or operand shape | ours — types, stack layout |
| `regalloc` | same program, different registers | **P3 — reachable by changing the C** |
| `selection` | a different instruction for the same job | P3, or flags |
| `encoding` | same instruction, different bytes | **not reachable from C** — flags or compiler |

That last row is the reason the taxonomy exists: work spent on an `encoding` row is wasted, and
work spent on a `missing` row is a correctness fix that would be worth doing even if
byte-exactness were abandoned. A single percentage cannot separate them.

## 3. The shape of the answer

```
        original bytes ──► lift ──► IR ──► emit(IR, θ) ──► C
                                              ▲            │
                                              │            ▼
                                          policy      toolchain driver
                                              │            │
                                              │            ▼
                                          attributed ◄── align+attribute ◄── object
                                            diff
```

The one structural change to the decompiler is the parameter **θ**.

Today emission is `IR → C`: one rendering, chosen by Ghidra's readability heuristics. For
byte-exactness it must become `IR × θ → C`, where θ ranges over renderings that are all
**semantics-preserving by construction** — the search may pick any of them and never produce
wrong code. Candidate axes, each of which demonstrably moves real compilers:

- temporary splitting vs merging (one variable per live range, or one reused);
- expression inlining vs an explicit temporary (changes evaluation order and pressure);
- declaration order (register allocators walk source order);
- statement order among independent statements;
- loop form (`while` / `do-while` / `for` / goto), and where the exit test sits;
- integer type width and signedness where the IR does not pin them;
- explicit cast placement;
- array indexing vs pointer arithmetic for the same address computation.

Mutating C *text* is not an option — it cannot be shown to preserve meaning. Generating from
the IR under an explicit choice vector can.

**Search where you must, model where you can.** Some of these axes have deterministic answers
for a given compiler: if Watcom's allocator assigns registers by order of first use in the
source, the declaration order that produces a target allocation can be *computed* rather than
searched. Those rules are not guessed at; they are measured by compiling probe programs
(`probe/`), and they turn a combinatorial search into a lookup. Search remains the fallback,
and the fallback must exist, because no model of a 1994 compiler will ever be complete.

## 4. Where compiler-specific knowledge is allowed to live

Exactly three places, none of them the decompiler core:

1. **cspec/pspec** — calling conventions, type sizes, register roles.
2. **the toolchain driver** — how to invoke the compiler, how to read its output and errors.
3. **the codegen model** — which θ axes matter for this compiler, and the measured rules.

An `if (target == watcom)` in the decompiler is the failure mode this exists to prevent: it
makes one binary pass and every other binary's behaviour undefined.

## 5. Feasibility

The compile round trip is ~1s through dosemu2 for one translation unit, and a batched session
amortizes far below that. A per-function search of a few dozen candidates is therefore seconds,
and the 3023 functions are independent — each compiles alone, so the whole population
parallelizes. This is what makes a search practical rather than theoretical, and it is why the
toolchain driver is a real subsystem (batching, content-addressed caching) rather than a call
to `system()`.

## 6. Order of work

1. **Instrument** — align + attribute. *Done.*
2. **Census** — every function's dominant cause, over a consistent emit/compile pair. Priorities
   come from this, not from memory.
3. **Toolchain driver** — batched, cached, so the loop costs milliseconds per candidate.
4. **The loop, end to end, on the narrowest θ** — prove a function one divergence from exact can
   be driven to exact automatically before widening anything.
5. **Widen θ + the policy table**, ordered by the census.
6. **Interface recovery (P2)** — inter-procedural prototype and convention inference. Almost
   certainly the largest single class, and the one that is a correctness bug rather than a
   cosmetic one.

## 7. What would make this fail, stated in advance

- **A ceiling that is not ours.** Hand-written assembler, and code from a compiler build we do
  not have, cannot be reached from C. These must be *identified* (a function whose divergences
  are all `encoding`, or whose original uses instructions no C construct produces) and excluded
  from the denominator, or the score becomes a measure of how much assembler the game has.
- **Overfitting to WAR2.** A knob that helps one binary and is not derived from a measured
  compiler rule is a liability. Every codegen rule must come with the probe that established it.
- **A search that optimizes the instrument instead of the goal.** The alignment score is a
  gradient, not the target; the target is `EXACT`. Accepting a θ that improves similarity while
  moving away from an exact match is the failure mode to watch, and it is why the verdict, not
  the score, gates acceptance.
