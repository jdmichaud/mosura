# Source forms — which C produces which Watcom code

The byte-exact campaign decomposes into P1 (what a function computes), P2 (its interfaces),
P3 (**which equivalent C source**), P4 (build flags). This document is P3's evidence base.

P1/P2/P4 are *recovery* problems: the answer is in the subject and can be read out. P3 is not.
Many different C sources compile to the same semantics and different bytes, the original's
source left no trace except through the code it produced, and so the only way to answer it is to
propose a form, compile it, and compare. That makes P3 a **search**, and everything below is
either a fact that shrinks the search space or a measurement of how the search behaves.

Everything here was measured with Watcom C 10.0a at `-4r -fpi87 -s -onatx -d1+` against
WAR2.EXE, in a single-function compile loop of about **one second per probe**. It is
compiler-specific by construction; treat the catalog as calibrated for this toolchain and re-run
the probes before trusting any of it on another.

## The loop

The whole method is that a single function's recompile-and-compare is cheap:

```
recompile_check <exe> <manifest.tsv> <srcdir> recover <WATCOM> \
    --cache <dir> --only <idx> [--verbose] [--divergences <tsv>]
```

Warm, this is ~0.25 s cache-hit and ~1 s for a real compile. Edit the one `.c`, re-run, read the
aligned diff. If a probe script takes minutes, something is wrong with the setup, not the tool.

**Score on matched instruction rows, not on similarity.** `--verbose` prints one row per aligned
instruction; counting the exactly-matching ones (`awk '/^  0006/{n++}'`) is a finer and more
monotone signal than the reported similarity, which mixes classes. The distinction matters for
hill-climbing: similarity moved ±0.01 on changes that moved matched rows by 10.

**Two traps, both paid for:**

* The compile cache keyed only on the unit's source, not the prelude, so a run with a missing
  `prelude.h` cached its COMPILE_FAIL and every later run kept hitting it. Fixed — the prelude is
  now part of the toolchain identity — but the general lesson stands: when a probe result looks
  impossible, suspect the cache before the compiler.
* Structural edits **invalidate declaration-order tuning** (see below). Do all structural work
  first and tune order last, or the tuning is measuring a source that no longer exists.

## Catalog — binary evidence → the C that reproduces it

Ordered by measured leverage on `FUN_0006c6f0`, the largest honestly-measured function
(1,963 bytes, 536 instructions).

### 1. Block layout order — the dominant lever

**Evidence:** the original interleaves blocks at their addresses; a block reached only by `goto`
sits where the original put it, not at the end of the function.

mosura's structurer emits goto-only blocks *after* the return, and Watcom emits them in source
order — so every such block lands past the epilogue, and every branch to it is wrong by the size
of everything in between. Relocating two blocks into the loop body they belong to, in the
original's order, moved matched rows from ~85 to ~140 (similarity 0.142 → 0.261). It is worth
more than every expression-level fix in this catalog combined.

**Recipe:** read the original's address order, and move each block in the C so that source order
matches address order. Seal the ends with explicit `goto`s.

### 2. Compare ladders are compiled `switch`es

**Evidence:** a chain of `CMP`/`JC`/`JBE`/`JZ` against ascending constants, ending in a common
join — Watcom's sparse-case tree, not an if-chain.

The decompiler flattens these into nested `if`s, which Watcom then re-compiles into a *different*
tree. Writing `switch` back regenerates the original shape. Two restored in this function.
Two details matter: the switch expression's **width** (`(int4)x & 0xf0` produced `CMP EAX`;
`x & 0xf0` on a byte lvalue produced `CMP AL`), and cases the original tree tests but the
decompiler dropped as unreachable-looking — the tree's shape encodes them.

### 3. Types, and where narrowing comes from

* A global recovered as `char` narrows every store to 8 bits (`MOV [x],AL`) where the original
  writes 32 (`MOV [x],EAX`). Retyping to `int` fixes the stores. **Caution:** it also re-rolls
  register allocation nearby (±15 rows measured), so it can look like a regression while being
  correct — judge it on the store rows, not the total.
* `*((uint1 *)p + 1) - 2` folds into byte arithmetic (`MOV AL` / `SUB AL`). Loading into an `int`
  temp *first* gives the original's `MOVZX` + 32-bit subtract.

### 4. Idioms that are library calls or intrinsics

* `REP MOVSD` ×n + `MOVSW` — a fixed-size copy. `memcpy` with `#pragma intrinsic` inlines, but as
  `REP MOVSD` + `SHR`/`AND` + `REP MOVSB` (a general size-dispatch). A **struct assignment**
  (`*(struct s30 *)a = *(struct s30 *)b`) reproduced the original's exact form.
* `FILD` / `FDIVR` / `FISTP` where the original has `MOV EAX,imm` / `CDQ` / `IDIV` — this is a
  decompiler artifact, not the subject: an `int8` (which the prelude types as `double`) cast
  around an integer division. Removing the cast restored the exact `IDIV` sequence.

### 5. Parameter access: cached vs re-read

**Evidence:** the original re-reads `[ESP+0x1c]` at each use rather than caching the parameter in
a register.

Declaring the parameter **`volatile`** reproduces this exactly, at zero instruction cost, and it
fixed the frame size at the same time. Where the original *does* cache, a plain local assigned
once from the parameter gives that. Per-region granularity is normal: this function re-reads in
three places and caches in two, and matching it means writing it that way.

### 6. Address-taken locals

**Evidence:** `SUB ESP,0xc` with a `LEA EAX,[ESP+4]` and a narrow store into the slot.

That is a real local array whose address escapes to a call. Declaring `int4 xBuf[3]` and passing
`xBuf` made the whole tail call sequence byte-exact and fixed the frame size. Attempts to fake it
were all worse: a never-taken guard emitted the guard; a pointer-pun read (`*(int4 *)&param`) was
folded away by Watcom.

### 7. Copy chains and phi residue

The decompiler emits `piVarN = piRamXXXX;` copies around calls and at merges — SSA phi residue
the original has none of. Deleting them, and instead assigning the global at the loop head and
updating it at the bottom (testing the *updated* value), removes both the copies and the
compensating loads.

### 8. Statement-level forms that change codegen

Each of these produced different bytes at otherwise identical sites, so each is a per-site probe
rather than a rule:

* `x = x + k` vs `x += k` vs `p = &x; *p += k`
* reusing one variable for two disjoint live ranges vs two variables (changes allocation)
* keeping a pre-decrement value in a second variable vs recomputing it
* compare direction and form: `99 < x`, `x >= 100`, and an early-`goto` form select different
  `JL`/`JLE`/`JGE` and different block order
* **where a constant is assigned** — Watcom sinks materialization to the use, so moving
  `iVar = 1` between two statements moves `MOV ECX,1` in the output

## Declaration order steers the register allocator

Recorded in [`byte-exact-status.md`](byte-exact-status.md) as a finding; the numbers, on this
function with the C otherwise byte-identical:

| declaration order | matched rows (of 536) |
| --- | --- |
| decompiler's natural order | 172 |
| reversed | 173 |
| first-use order | 173 |
| hill-climbed (~200 probes) | **184** |

Watcom breaks allocation ties on symbol order, so `printc`'s declaration sequence — currently the
decompiler's internal variable numbering, an artifact carrying no information about the original —
is a live input to code generation for every function in the corpus.

First-use order is the obvious principled heuristic and it is **not** the answer here (173 vs
184). It is a better *seed* than variable numbering, but the space is `n!` and the win came from
search. Sizing the heuristic corpus-wide (emit with first-use ordering, diff the EXACT count) is
still worth doing, because a cheap deterministic improvement that helps 2,893 functions beats a
per-function search that helps one.

## What hand-convergence reached, and where it stops

`FUN_0006c6f0`, one session, ~40 structural reconstructions plus ~200 tuning probes:

| | start | end |
| --- | --- | --- |
| similarity | 0.050 | 0.33 (peak 0.35) |
| exactly-matched rows | 27 / 536 | 177 (peak 184) |
| candidate instruction count | 474 | **536 — the original's, exactly** |
| entry region | diverged at row 1 | **byte-exact through `0x6c74a`** |

Everything recoverable was recovered: all nine call sites with correct arguments and conventions,
the phantom parameter, the address-taken buffer, two `switch`es, the copy idiom, integer division,
the mistyped global, and the block layout.

**The wall is register allocation, and it is coupled.** The residue is ~130 idiom rows and ~200
renames, and they are not independent: every structural edit re-rolls allocation in regions that
were not touched (±10 rows per probe, non-monotone). One rename cascade was traced to a site with
byte-identical instruction context on both sides where Watcom still chose a different scratch
register — a compiler-internal tie-break that no source lever reached. Hand-probing plateaued at
172–184 matched rows over the last ~30 probes.

This is the honest boundary of the manual method: it converges structure monotonically and then
stalls on allocation, because allocation is a global property of the function that no local edit
controls.

## The P3 engine — what the evidence says to build

The declaration-order result is the important one, and not because of its size: it proves that
**blind automated search over source form measurably converges on this compiler.** A search
needs three things, and this session produced all three:

1. **A cheap oracle** — the ~1 s single-function loop.
2. **A monotone score** — matched instruction rows.
3. **A mutation space with known-productive dimensions** — declaration order (`n!`, hill-climbs
   well), plus the per-site statement forms in §8 (small discrete choices, enumerable per site).

The natural shape is a hill-climber over (statement-form vector × declaration permutation),
seeded from the decompiler's emission and scored on matched rows, with restarts. `climb.py` in
the preserved artifacts is a working single-dimension version (declaration order only) and is the
seed for the general one.

Two design cautions the measurements imply:

* **Order the phases.** Structural mutations invalidate allocation tuning, so a search that
  interleaves them wastes its budget re-tuning. Structure to a fixpoint, then tune.
* **Do not score on similarity.** It is too coarse to hill-climb; matched rows is the metric that
  moved when the source improved.

Whether to build it is a scope decision, not a technical one: the machinery is corpus-wide (every
mismatching function is a candidate), and the alternative is accepting that large functions
converge structurally but not exactly.

## Preserved artifacts

`oracle/war2-convergence/` holds the working state, so the reconstructions are not lost:

* `FUN_0006c6f0.c` — the hand-converged source at its best structural state. Roughly forty
  reconstructions verified line-by-line against the disassembly; re-deriving it is a session of
  work.
* `climb.py` — the declaration-order hill-climber.
* `README.md` — how to resume.
