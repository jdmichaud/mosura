# Declaration order and IR-generation order — results

Answers [`declorder-irorder-handoff.md`](declorder-irorder-handoff.md). Companion to
[`watcom-dial-patch-results.md`](watcom-dial-patch-results.md), whose §3 and §5 this work both
extends and corrects.

Baseline: **zc27 = 764 EXACT / WGSS 0.4801** (`/data/be2/zc27-rec.tsv`), on branch `dial-patch`
fast-forwarded to master `0c00914`. Control run before any measurement: the rebuilt worktree
binary reproduces zc27 exactly — `0 flips, net +0.000 sim` — so the measurement path is sound at
the new baseline (`/data/be2/zc27-ctlA-rec.tsv`).

---

## 0. Two corrections to the dial-patch results, made before starting

Both were found by reading Open Watcom source for this follow-on, and both are now fixed in
`watcom-dial-patch-results.md`. They are recorded here because one of them changes what the
handoff asks for.

### 0.1 `ConfList` is in DECLARATION order, not reverse creation order

The dial-patch §3 mechanism said conflicts are prepended "so `ConfList` is in reverse creation
order", and marked the front-end link inferred. Traced now, in OW 1.0.0:

| step | file:line | effect on order |
| --- | --- | --- |
| `DeclList` appends the local to the symbol chain | `cc/c/cdecl2.c:623-641` | declaration order |
| `DoAutoDecl` walks that chain forward, calling `CGAutoDecl` | `cc/c/cgen2.c:1655,1670` | preserved |
| `BGAutoDecl` → `MakeAddrName` → `SAllocUserTemp` creates the `N_TEMP` | `cg/c/makeaddr.c:590` | temps created in declaration order |
| `AllocName` **prepends** onto `Names[N_TEMP]` | `cg/c/namelist.c:97` | **reversed** |
| `RoughSortTemps` walks `Names[N_TEMP]` **forward**, `AddConflictNode` **prepends** | `cg/c/dataflo.c:112-121`, `cg/c/conflict.c:61` | **reversed again** |

**Two prepends cancel.** `ConfList` is in declaration order, head = first declared. The
`AddConflictNode` prepend is real; quoting it alone was the error.

### 0.2 Register-copy-vs-constant argument pairs are NOT reachable from C

Dial-patch §5.4 partitioned the arg-setup class into "equal `stallable` → decided by the
source-order key" and "unequal `stallable` → unmoved by anything, separated by `StallCost` or
`height`", and put register-copy-vs-constant pairs in the second bucket. Wrong on both counts.
`MOV reg,reg` scores `stallable` 2 (one `N_REGISTER` operand) and `MOV reg,const` scores 0, and
`stallable` sits **above** the source-order key in `ScheduleIns`. My own recorded divergence
tables show the consequence:

| variant | `FUN_0004b750` site A (`0x4b767`) still divergent? |
| --- | --- |
| `reg0` (weights equalised only) | **yes** |
| `idorder` (source-order key reversed only) | **yes** |
| `reg0+idorder` (both) | **no — fixed** |

So a register/constant pair needs the `stallable` separation removed *before* the id key can
decide it. **Under stock 10.0a no instruction-creation order — and therefore no C source shape —
can flip a register/constant argument pair.** Only the *equal-`stallable`* subset
(`FUN_00073328`'s two `[EBP+disp]` loads, `FUN_0004b750`'s `0x4b758` constant/constant pair) is
reachable from our side.

**This narrows Item 2.** The handoff's framing — "the order is the code generator's
instruction-creation order — downstream of our C" — inherited my error and is true only of the
equal-`stallable` subset. §5 below re-scopes Item 2 accordingly.

---

## 1. Item 1 — the model-inverse predicate, and its pre-registered test

### 1.1 The predicate, derived from source (no calibration)

From the chain in §0.1 plus `AssignConflicts`/`GiveBestReg`:

```
predict(decl_order) -> {local -> physical register}

  conflist = decl_order                 # §0.1: the two prepends cancel
  order    = conflist                   # ConfBefore is strict '>' on savings;
                                        # all-equal savings => zero swaps => identity
  taken = {}
  for L in order:
      for reg in TABLE(width(L)):       # 10.0a: 4B [EAX,EDX,EBX,ECX,ESI,EDI,BP,SP]
          if overlaps(reg, excluded): continue        # regalloc.c:851
          if overlaps(reg, taken):    continue        # regalloc.c:850  (HW_Ovlap, PHYSICAL:
          result[L] = reg                             #   AL,AH ⊂ AX ⊂ EAX etc.)
          taken |= subregs(reg); break                # first candidate wins (saves > -1)
```

Closed form in the clean case: **the k-th declared local takes the k-th still-available table
entry.** Nothing here is fitted to the corpus; every step is a source line.

It rests on eleven assumptions, each a way to be wrong. The load-bearing ones: all movable locals
are cross-block (a local confined to one basic block gets its conflict from `FlowConflicts`'
**backward** scan instead, `liveinfo.c:234`, so its position is a statement-order property and
step 1 does not apply); savings are equal (`CalcSavings` is loop-depth weighted, so a loop counter
does **not** tie with a straight-line temp); and `CountRegMoves` ties at 0 for every candidate
(any call-argument, return-value or shift-count coupling breaks the tie by *score*, making table
order irrelevant).

### 1.2 The test — measure the equivalence classes, which needs no oracle

Two declaration orders that produce the same register assignment produce **byte-identical code**.
So the permutations of a function partition into equivalence classes, and this partition is
measurable **without knowing anything about the original**: compile every permutation and group
those that emit identical code. That makes the test unfitted — the original's bytes are used only
to label which class (if any) is the byte-exact one.

**Pre-registered, before running it:**

- **Prediction E1.** For each of the 12 ceiling candidates the measured partition of declaration
  permutations into identical-code classes will be reproduced exactly by `predict()` — same
  classes, same members.
- **Prediction E2 — I expect E1 to FAIL, on `FUN_000464b4`.** Its three locals are
  `uint4 uVar1`, `xunknown1 xVar2`, `xunknown1 xVar3`, and three of its six orders are byte-exact
  (`(u,x3,x2)`, `(x2,u,x3)`, `(x2,x3,u)`). Working `predict()` by hand with the physical-overlap
  rule gives `(u,x3,x2) → uVar1=EAX, xVar3=DL, xVar2=DH` but `(x2,u,x3) → xVar2=AL, uVar1=EDX,
  xVar3=AH` — two different assignments, which cannot both be byte-exact against one original.
  If the measured classes confirm that `(u,x3,x2)` and `(x2,u,x3)` really do emit identical code,
  the predicate is refuted as stated and the failure is in its assumption set, not in arithmetic.
- **Prediction E3.** `FUN_0006a720` (3 locals, no byte-exact order) is the sharpest test of the
  assumptions: under assumptions 1–8 `predict()` names an order for every function, so it must
  wrongly claim one exists here unless an assumption visibly fails.
- **The bar for building the arm.** `predict()` must reproduce the measured partition on **all
  12** candidates — the 3 winners *and* the 9 non-winners. Reproducing only the winners is
  fitting, and does not count.
- **What closes Item 1 negatively.** If no compiler-free predicate reproduces the 12-candidate
  partition, report that and stop; the permutation search stays a ceiling, not a lever. Per the
  handoff, that is an allowed and complete outcome.
- **If E1 holds**, only then: gate design, the 44-function EXACT probe battery, and one corpus
  round against zc27 with pre-registered flips (≤3 EXACT) and WGSS.

### 1.3 The population, re-sized

The handoff carries dial-patch §4.8's figure — 332 EXACT functions ride on an allocation tie — as
the blast radius. That is the right number for a *compiler* dial, but the wrong one for this arm:
the arm can only fire where a function has ≥2 permutable register temps.

| population (zc27) | count |
| --- | --- |
| functions with ≥2 movable register temps | 1,236 |
| …**currently EXACT** — the actual blast radius | **44** |
| …SAME_SHAPE | 19 |
| ceiling candidate set (SAME_SHAPE ∩ regalloc, 2–4 temps) | 12 |

Movable-temp histogram: 407 functions with 2, 252 with 3, 194 with 4, 116 with 5, 90 with 6,
60 with 7, 117 with ≥8. So the handoff's "compile all currently-EXACT candidates, not a sample"
requirement costs one batched run of 44 units, not a corpus round.

---

## 2. Item 1 — the measurement

### 2.1 Method

For each candidate, every permutation of the movable declarations was compiled against stock
10.0a and grouped by emitted-code identity (the divergence table's candidate-side rows are a
faithful fingerprint: for a SAME_SHAPE function every instruction aligns, and zero rows means
byte-exact). Batched one permutation-round per dosemu session.
Harness: `held-patches/declorder_classes.py`; predicate: `held-patches/predict_regs.py`.

### 2.2 The 12 ceiling candidates: the predicate fails, 2 of 12

| idx | function | widths | measured classes | predicted classes | |
| --- | --- | --- | --- | --- | --- |
| 00262 | `FUN_0001798c` | 4,4 | 2 | 2 | OK |
| 00278 | `FUN_00018afc` | 1,4,4 | **1** | 6 | FAIL |
| 01104 | `FUN_00032bd4` | 4,4 | **1** | 2 | FAIL |
| 01112 | `FUN_0003320c` | 4,4,2 | **2** | 6 | FAIL |
| 01113 | `FUN_00033254` | 4,4,2 | **2** | 6 | FAIL |
| 01116 | `FUN_0003333c` | 4,4,4 | **2** | 6 | FAIL |
| 01118 | `FUN_00033380` | 4,4,4 | **2** | 6 | FAIL |
| 01120 | `FUN_000333c4` | 4,4,4 | **2** | 6 | FAIL |
| 01678 | `FUN_000464b4` | 4,1,1 | **2** | 4 | FAIL |
| 01908 | `FUN_0004c6c0` | 4,4 | **1** | 2 | FAIL |
| 02458 | `FUN_0005fb24` | 4,4 | 2 | 2 | OK |
| 02675 | `FUN_0006a720` | 4,4,4 | **2** | 6 | FAIL |

**2 of 12**, and both passes are two-local functions where the predicate has only two options to
choose between — the other two two-local functions measure **one** class and it fails them.
**Prediction E1: refuted. Prediction E2: held**, though for a weaker reason than the real one —
I expected an arithmetic mismatch on one function; the failure is structural and hits nine.
**Prediction E3: held** — `FUN_0006a720` is the sharpest case, and the predicate names a distinct
order for each of its six permutations where measurement finds two outcomes.

### 2.3 What the measurement found instead: declaration order is a BINARY lever

Every multi-local candidate collapses its permutations into **at most two** classes:

```
FUN_0006a720   3 int4 locals, 6 orders -> 2 outcomes   {p0,p2,p5} | {p1,p3,p4}
FUN_0003320c   3 locals,      6 orders -> 2 outcomes   {p0,p3,p5} | {p1,p2,p4}   (x5 family)
FUN_000464b4   3 locals,      6 orders -> 2 outcomes   {p1,p2,p3} = EXACT | {p0,p4,p5}
FUN_00018afc   3 locals,      6 orders -> 1 outcome
```

Three same-width `int4` locals in `FUN_0006a720`: a positional mapping onto the register table
predicts six assignments; the compiler produces **two**. So declaration order does not index the
register table. It flips **one residual tie** and nothing else.

That names the assumption that broke — number 6 of the eleven: `CountRegMoves` decides most
registers **by score**, and where a score is strictly maximal, table order never enters. Only the
choice the scores leave tied is reachable, and predicting *which* choice that is requires the
scores, which require the instruction stream, which requires the compiler.

### 2.4 The blast radius, probed in full: zero

The handoff requires all currently-EXACT functions with ≥2 movable temps be compiled, not sampled
("the aggregation arm lost five EXACTs to a three-function sample"). All 44 were:

| | count |
| --- | --- |
| currently-EXACT functions probed | **44** (32 with 2 locals, 9 with 3, 3 with 4) |
| with more than one permutation class — i.e. breakable by reordering | **0** |
| with exactly one class — declaration order cannot change them at all | **44** |

Including three functions with 24 permutations each, all collapsing to one class. **A
declaration-order arm cannot break a single currently-EXACT function.** The blast radius is not
332 (dial-patch §4.8, which measured a *compiler* dial) and not 44 — it is zero.

This is self-consistent with §2.3: a function is byte-exact because our C already produces the
original's assignment, and it does so because that assignment is score-determined rather than
tie-determined — which is exactly the condition under which declaration order has nothing to flip.

---

## 3. Item 1 — verdict

> **The model-inverse is CLOSED NEGATIVELY, on the handoff's own terms.**
> The predicate derived from source — the only one the mechanism supports — reproduces the
> measured partition on 2 of 12 candidates, both trivial. The reason is structural, not a
> detail to patch: declaration order reaches only the residual tie that `CountRegMoves` leaves,
> and identifying that tie needs the scores, hence the instruction stream, hence the compiler.
> A compiler-free predicate of this kind does not exist. Per the handoff, the permutation search
> stays a **ceiling, not a lever**.

Two things worth keeping from the attempt:

1. **Declaration order is a binary lever, not an n! one.** On every multi-local function measured
   it produces at most two distinct outputs. That makes *measured selection* — compile both, keep
   the better — cost about two compiles per function rather than n!, which is the first hard cost
   figure for the "measured selection / arms revival" question `allocator-model-thread` parks for
   JD. The prize is still only the ~+3 EXACT of the ceiling, so the cost side improving does not
   by itself make it worth building; but the number is now known rather than feared.
2. **The risk is zero, measured in full.** Whatever is built on this axis cannot regress a
   currently-EXACT function. That retires the blast-radius worry that shaped the handoff's design.

---

*(Item 2 follows)*
