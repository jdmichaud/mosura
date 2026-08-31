# The Phase C pilot — results

Answers [`plan-to-0.8.md`](plan-to-0.8.md) §5 Phase C, which scheduled a pilot on the low-semantic
mid-size functions to decide the allocator design *before* building one: hill-climb declaration
order and the known statement-form axes with the compile loop, scoring matched rows, and publish
the per-function gain distribution.

**The answer, in three numbers.** The twelve free emit axes REACH 60.3 % of the population
(289 of 479 functions have more than one rendering); across all 289 the ascent improves NOTHING
(gain histogram `{0: 479}` over the whole selection); and the only lever that pays at all is
declaration order in *measured-selection* mode — compile both orders, keep the better —
**+67 matched rows = +0.00054 corpus WGSS** at two compiles per function.

That is a negative result about the INSTRUMENT, not about the hypothesis, and the distinction is
the point of this document: the axis set never touches the `extra` / `layout-shift` / `selection`
mass that §3 of the plan names, so Phase C's real question is still open and its prerequisite is
now known.

Baseline: `cb97296` (WGSS 0.5576, 857 EXACT). The census pair is `/data/be2/w6a-{rec,div}.tsv` —
the w6a tree is byte-identical to `base-cb97296` (`diff -rq` = 0) and its `rec.tsv` is
byte-identical to that tree's, which matters because `base-cb97296/` itself carries neither a
`div.tsv` nor a `prelude.h` and therefore cannot be recompiled in place.

---

## 1. The selection: 479 functions, not 403

The plan's "403 low-semantic mid-size functions" was measured before the five W-rounds landed.
Reproducing its own selection with its own script's definitions — `scripts/war2-mechanism-census.py`
`SEM = {'missing','branch-target'}` (:26), `MISMATCH && 20 <= orig_n < 200` (:52), the `<= 2` bin
(:56) — against the current baseline gives:

| bin | functions |
| --- | --- |
| 0 semantic rows | 104 |
| 1–2 semantic rows | 375 |
| **selection** | **479** |

18,906 instructions, mean sim 0.658, **6,334 insn-sim of loss carried**; row classes inside it:
extra 1,728 · regalloc 1,676 · layout-shift 1,535 · selection 935 · operand-form 897. All 479 are
manifest `kind = user`; 381 are game-scope. The set is materialised at
`/data/r6-scratch/w7c/pilot-set.tsv` (va, name, insns, sim, semantic rows).

Two notes carried rather than silently resolved: the plan's prose calls the semantic classes
"missing / extra / branch-target" while the script — which produced the published table — excludes
`extra`; and `0x10010` is in the selection although the reconciliation ledger names it hand-written
asm, so it has no C source form to hill-climb. It is reported, not filtered.

## 2. Method

**The two costs that shaped the harness.** A `war2_survey --only` invocation costs **111–130 s**
of load and analysis and **0.28 s** of actual emit per function-arm. Per-vector invocations are
therefore hopeless: the 6,144-vector exhaustive below would have cost 190 hours that way.

**Probe change (unlanded, branch `pilot-probe` in /data/mosura-w7).** `--arms θ1;θ2;…` emitted one
`src/` tree per arm and only ONE recovered tree, and probing from `src/` is forbidden (the trap in
`wc2src-reconciliation-4.md`: a src-copied probe recompiles every stack-convention callee with
register arguments and shows fake divergences). The probe adds a RECOVERED tree per arm
(`recovered-aNNNN/`, with the θ in `ARM.txt` beside it — by index, because a full choice vector
overruns the filename limit) and makes probe mode WRITE the recovered TU instead of printing it.
Arm 0 keeps today's behaviour exactly.

**Scoring — the harness's own number, in one pass.** For each (function, vector) pair the TU is
copied into a synthetic tree as `<k>.c` and a synthetic manifest repeats that function's row with
idx `k`; ONE `recompile_check` then scores every pair and its `equal` column IS the matched-rows
score, bit-identical to any other round's. Validation: the canonical rendering reproduces the
baseline exactly — 0x58e8c `equal` 29 / sim 0.408, 0x111bc 57 / 0.695, 0x57504 41 / 0.872, all
matching `w6a-rec.tsv`. 6,144 variants of one function score in a single run.

Scripts: `/data/r6-scratch/w7c/pilot/{pilot,applicability,e4b,exhaustive,declorder,declscale}.py`.
Re-run: `applicability.py <work> <pilot-set.tsv>` then `e4b.py <work> <applicability.json>` then
`declscale.py <work> <canonical-tree> <pilot-set.tsv>`; each is detached, resumable per artefact,
and stopped only by its PID tree.

**The axes.** Of the registry's twenty, seven are byte-WITNESSED arms already at their measured
values in `canonical_arm` (string-ops, sdiv-pow2, frame-fill, struct-copy, sparse-switch,
struct-return, swi) — witnessed choices are not free — and `shift-mask` is fixed for this target.
The twelve free axes are `return-width` (3 values), `local-width`, `compare-form`, `return-split`,
`cond-form`, `ext-cast`, `arm-order`, `struct-locals`, `narrow-tests`, `join-width`, `array-index`,
`sum-order` (2 each): a space of 3 × 2¹¹ = 6,144 renderings per function.

## 3. E4a — applicability: what the levers reach

One emit invocation, 479 functions × 14 vectors (canonical + the 13 single-axis alternatives),
210 s, no compiling.

| distinct renderings | functions |
| --- | --- |
| 1 (no axis reaches the function) | **190** (39.7 %) |
| 2 | 151 |
| 3 | 77 |
| 4 | 48 |
| 5 | 13 |
| **reached (≥ 2)** | **289 (60.3 %)** |

Per-axis reach — functions whose text changes when ONLY that axis moves:

| axis | functions | | axis | functions |
| --- | --- | --- | --- | --- |
| `local-width=storage` | 130 | | `sum-order=ghidra` | 11 |
| `ext-cast=ghidra` | 118 | | `narrow-tests=ghidra` | 6 |
| `array-index=ghidra` | 84 | | `return-width=storage` | 1 |
| `compare-form=complement` | 69 | | `join-width=ghidra` | 1 |
| `arm-order=ghidra` | 49 | | `struct-locals=ghidra` | 1 |
| `return-width=value` | 32 | | **`cond-form=nested`** | **0** |
| | | | **`return-split=paths`** | **0** |

Co-occurrence on one function (top): array-index+ext-cast 61 · ext-cast+local-width 40 ·
array-index+local-width 26 · compare-form+local-width 23 · ext-cast+return-width 21.

**Caveat:** single-axis reach is a LOWER bound — a text change appearing only for a COMBINATION of
axes would be missed here. The exhaustive of §5 is this pilot's no-interaction witness.

## 4. E4b — the ascent: zero, everywhere

Coordinate ascent from the canonical vector on the 289 REACHED functions (the other 190 are not
compiled: one text for every vector means one object and one score, so zero gain is a *theorem*
there, not a measurement). Round 0 scored 4,046 pairs — each function's own base plus its thirteen
single-axis alternatives — and **improved nothing**, so no base moved and the ascent was already at
its fixpoint.

> **Gain histogram over the whole selection: `{0: 479}`. Total matched rows gained: 0.**

The instrument discriminates, which is what makes this a measurement rather than a dead harness:
on `FUN_000111bc` the fourteen vectors score 57 / 55 / 54 — `compare-form=complement` costs two
matched rows and `sum-order=ghidra` costs three, and the canonical vector wins.

## 5. The exhaustive control on 0x58e8c

All **6,144** vectors, 3,017 s, scored in batches through the synthetic manifest.

- matched-rows distribution: **`{29: 6144}`** — exhaustive-best = ascent-best = canonical = 29.
- **greedy-vs-exhaustive gap: 0.**
- the 6,144 vectors produced **two distinct texts** (3,072 each), differing by one cast —
  `CONCAT22(…,(uint2)(uint1)(uVar2 >> 0x10))` vs `…(uint1)(uVar2 >> 0x10)` — discriminated by
  `ext-cast` alone. Eleven of the twelve axes are inert on this function.

## 6. E4c — declaration order at scale

`docs/declorder-irorder-results.md` §2.3/§2.4 established that declaration order is a BINARY lever
(all permutations of every multi-local candidate collapse to at most two outcome classes) whose
blast radius on currently-EXACT functions is **zero**, and closed the model-inverse negatively. One
reversal per function is therefore the whole measurement. Of the 479, **256** have two or more
declarations to reverse.

| mode | result |
| --- | --- |
| blind reversal | 13 improved (+67 rows), **16 worsened (−63)**, 227 unchanged → **net +4 rows** |
| measured selection (keep the better of the two) | **+67 rows = +66.0 weighted insn-sim = +0.00054 corpus WGSS**, 1.6 % of the 4,211 insn-sim those 256 carry |

Largest wins 0x3fd48 53→67, 0x19f58 22→33, 0x255d0 36→46, 0x511ac 22→31; largest losses −6 rows at
0x1bc90, 0x2f650, 0x31674, 0x32260, 0x47efc. **The blind form must not be built**; only the
measured-selection mode has a positive expectation, at two compiles per function and no model.

## 7. What this means for Phase C

**Two facts, which must not be conflated.**

1. **The axis set does not REACH 40 % of the band.** For those 190 functions every vector produces
   one text; their zero is a theorem about the levers, and says nothing about whether source form
   could reach their divergence.
2. **Where it does reach, the canonical choices already win — every time**, and the alternatives
   measurably lose. That is a positive result about the witnessed/canonical set: it is well tuned.

Neither licenses "the residue is the compiler's, ceiling ~0.75". The instrument never touched the
mass the plan's §3 ranks first inside these very functions — `extra` 1,728 rows, `layout-shift`
1,535, `selection` 935 — because none of them is an axis today.

**The fork, priced.**

- **(a) The allocator model-inverse is UNJUDGED.** The pilot was meant to decide it by putting
  source-shape pressure on allocation; no available lever moves allocation-relevant form, so the
  experiment could not run. It is neither supported nor refuted here.
- **(b) Building witnessed levers for the `extra` class is the PREREQUISITE**, not an alternative:
  temporaries, widths and idiom expansions are the largest class in this band and the twelve axes
  miss them entirely. Each would be an emit-layer arm with its own byte witness, in the shape of
  every landed one (string-ops, sdiv-pow2, frame-fill, struct-copy, sparse-switch).
- **(c) Declaration-order measured selection is real but small: +0.00054 WGSS for two compiles per
  function.** It is the first hard cost/benefit figure for the parked "measured selection / arms
  revival" architecture question, and it is JD's call, not a build recommendation.

**Caveats carried.** Single-axis reach is a lower bound (§3), with the 0x58e8c exhaustive as the
no-interaction witness (§5); the 190 unreached functions are theorem-zeros and were not compiled;
matched rows are `recompile_check`'s own `equal` column throughout; `0x10010` is hand-written asm
inside the selection, reported rather than filtered; and the harness's probe change is unlanded by
design — nothing in this document changed a shipped number.
