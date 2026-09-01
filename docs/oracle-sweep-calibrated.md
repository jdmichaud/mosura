# The calibrated oracle sweep — the first honest Ghidra-vs-mosura divergence map

Every generative sweep this project ran before 2026-09-01 compared us against Ghidra decompiling
under **the wrong calling convention**. The residual maps they produced were doubly stale: an
0.483-era baseline *and* `x86win` instead of `watcall`. This document is the first sweep taken
with the oracle root built from our own compiler spec, and it is mostly a document about the
instrument.

**The answer, in three numbers.** Of the corpus loss carried by the 2,721 scored functions,
**64.9 % sits in ISOLATION-SENSITIVE pairs** — where Ghidra's context-poor fixture recovered no
parameters, invented `extraout_`/`unaff_` pseudo-variables, or left calls argument-less that we
give arguments. The **clean residue is 1,512 pairs carrying 18,333 loss**, and its largest class
is not a printing gap but a *variable-count* gap: **164 TUs where we declare more locals than
Ghidra, 149 of them in the same direction**. Chasing that class to its cause produced the first
faithful-port landing from a sweep: **+3 EXACT, WGSS 0.5576 → 0.5589, six flips all upward**.

Baseline: master `3eff9a8` (emit byte-identical to `f632070`; both decompile identically to the
`g1` tree, `diff -rq` = 0 over 3,023 TUs). Sweep artifacts under `/data/r6-scratch/w7c/K`.

---

## 1. Why every earlier sweep was measuring the harness

An oracle capture takes its calling convention from the compiler spec the Ghidra **root**
resolves, and a compiler id an `.ldefs` does not register falls back to the language default
**silently** — no error, no warning, just different C. `arch=x86:LE:32:default:watcom` yields
watcall under a root that registers watcom and `__fastcall` under one that does not.

Six instrument failures were found in the days before this sweep, of which five were capture
comparisons that had to be withdrawn; the source-read findings survived. The full account is in
the `wc2src-reconcile` ledger. Two fixes make the class impossible rather than merely detectable:

- `scripts/make-oracle-root.sh` builds the root from the repo's own vendored processors plus
  `specs/x86-32-watcom.cspec`, so the oracle and the decompiler provably read one spec file;
- `oraclecache` keys on the resolved root, so captures cannot be served across roots.

**The calibration rule is in-band and run-fatal:** a watcom capture prints NO convention keyword.
`__fastcall` means `x86win`, `__regparm3` means gcc. This sweep checked it after every one of its
29 chunks; it never fired.

## 2. Method

`war2_oracle_sweep` over all **2,803 `kind=user`** functions of the `3eff9a8` emit: each
function's bytes as a standalone fixture, Ghidra's C beside mosura's pure-pipeline C, scored with
`ccompare::similarity`. **2,721 scored, 82 ORACLE_FAIL, mean score 0.9421, 821 byte-identical.**

Classes are formed by counting constructs on both sides and attributing a divergence to every
construct whose count differs. **They are ENVELOPES** — the whole loss of every TU carrying the
delta — so they overlap and do not sum, and they locate work rather than pricing it.

Three disciplines were applied before any class was ranked, and two of them killed a headline:

1. **Isolation sensitivity.** Sweep fixtures are context-poor; pairs showing that poverty are
   separated *before* ranking, not flagged afterwards.
2. **Structural presence.** A class claiming we lack or add a construct is checked on a specimen.
   This killed a `deref-cast` class that read **65 % of clean loss, "we emit FEWER in 739 of 741
   TUs"** — we print `*((uint2 *)(x))` where Ghidra prints `*(uint2 *)(x)`, and the counter had
   missed our extra parenthesis. Corrected, the class inverts to 93 TUs where we emit *more*. A
   second counter was matching `goto LAB_x;` as a declaration.
3. **Cross-reference against the closed record**, so nothing is re-derived: W7 piece ops (shared
   limit), the β short-circuit thread, L1w (parked), call rows (placement).

## 3. The headline: two thirds of the loss is the fixture, not the port

```
  pairs scored                  2,721      corpus loss they carry   52,222
  ISOLATION-SENSITIVE           1,209      loss 33,890   (64.9 %)
  CLEAN residue                 1,512      loss 18,333
```

The purest specimen is the sweep's worst-scoring function, `0x686bc` (score 0.241): Ghidra prints
`void func(void)` with three bare calls; we print five parameters and full argument lists. **That
is the fixture's poverty, not our defect.** Any residual map built without this cut is measuring
the harness — which is what the earlier maps were doing, for a second reason on top of the cspec.

## 4. The clean residue

```
 class          TUs    loss     %   game  band   direction        mark
 local-decl     164    5700  31.1%  112   126   MORE 149/FEWER 15  NEW
 deref-cast      93    3514  19.2%   56    74   MORE  90/FEWER  3  NEW
 array-index     30    1129   6.2%   19    29   MORE   8/FEWER 22  NEW
 short-circuit   14     849   4.6%   11    14   MORE   8/FEWER  6  KNOWN-OPEN
 while           14     744   4.1%   12    14   MORE   6/FEWER  8  KNOWN-OPEN
 piece-ops       16     574   3.1%   15    16   MORE  10/FEWER  6  KNOWN-CLOSED
 do-while         6     475   2.6%    4     5   MORE   3/FEWER  3  KNOWN-OPEN
 for             11     458   2.5%    9    11   MORE   8/FEWER  3  NEW
 goto             3     286   1.6%    3     3   MORE   3/FEWER  0  NEW
 halt/trap        3      53   0.3%    0     2   MORE   0/FEWER  3  KNOWN-NAMED
```

`piece-ops` deserves its mark: this is the first corpus-scale measurement of W7's shared-limit
question under the correct cspec, and at **16 clean TUs / 574 loss / 3.1 %** it is consistent with
that closure rather than reopening it. `halt/trap` is the named-but-unported halt-type concept.
`goto` is the only class where we emit unstructured control Ghidra does not.

## 5. `local-decl`: a three-way split, and two different mechanisms

Cross-crossed against the parked `merge-datatype` port (`28cb07b`, Ghidra's `ActionMergeType`
bucketing by datatype where we bucket by storage), which cherry-picks onto the current baseline
cleanly. Of the 149 MORE-locals TUs:

```
  collapsed to Ghidra's EXACT count   56
  moved toward Ghidra                 16
  held (port changes nothing)         75
  moved AWAY                           2
  summed |excess locals|   207 -> 110   (-47 %)
```

The worked specimen `0x63410` goes ghidra 5 / baseline 7 / ported 5 — an exact collapse. Over the
164 TUs the port also raises mean Ghidra-similarity 0.8847 → 0.8878.

**So roughly half the class is the parked port**, whose measured price was −0.00182 WGSS. That is
the decision on the table: *the faithful port is the principal cause of the corpus's largest clean
divergence class, it is measurably more Ghidra-faithful, and it costs recompilation score.*

Context-fairness for the held half was discharged without a locked capture: the two highest-loss
held TUs contain **zero calls**, so no callee-prototype confound is possible. One of them
(`0x103c2`) suggested boolean explicitness as the mechanism — and the census refused it at **11 of
84 excess (13 %)**, so the story was not adopted. **65 of the 75 held TUs remain unnamed.**

## 6. The other half: a self-declared port gap, and the landing

The remaining named mechanism is not a merge or explicitness step at all. We printed

```
  ours:   bVar7 = iVar4 != 1;  iVar4 = iVar4 + -1;  } while (bVar7);
  Ghidra: iVar3 = iVar3 + -1;  } while (iVar3 != 0);
  original: DEC ESI / DEC ECX / DEC EBX, branching on the DEC's OWN flags
```

`RuleEqual2Zero` rewrites `(a + c) == 0` into `a == -c`; Ghidra guards that with "make sure the
sum is only used in comparisons" (`ruleaction.cc:5867-5869`), and mosura omitted the guard behind
a DEBT note claiming it suppressed a firing switchloop's jumptable recovery needed.

**What the guard actually does is DEFER.** On the first mainloop pass a space that is not
dead-removal eligible yet has every Varnode marked live, so SLEIGH's never-read parity chain
(`INT_AND sum,0xff` → POPCOUNT → PF) still hangs off the sum. *Both* decompilers are in that
position; Ghidra's rule declines and fires a pass later on cleaned IR. Ours fired at the first
opportunity — the pass where the dead chain still lives — and rewrote the loop condition onto the
pre-decrement value, so the C needed a `bool` carrier and the compiler emitted a `CMP r,1` beside
the `DEC`. Origin ruled out on the way: not a lifting divergence (the mask is SLEIGH's own parity
model, in Ghidra's raw p-code too) and not the subvariable family.

The debt note's premise did not reproduce at HEAD, so it was deleted rather than edited.
**Landed `0c5016f`:**

```
  WGSS   0.5576 -> 0.5589        EXACT  858 -> 861
  flips  6, ALL UPWARD (3 MISMATCH->EXACT, 3 MISMATCH->SAME_SHAPE), zero down
  extra `CMP r,1`  105 rows / 66 TUs  ->  13 rows / 13 TUs
  specimens 0x103c2, 0x104c1: 8 -> 0 each, sim 0.063->0.128 and 0.087->0.115
```

A cross-thread hypothesis was tested and refuted here: the `INT_AND` artifact is **not** the
source of L1b's mass. Function overlap with the L1b extra-mask set is 70 % against a 61 % base
rate, and against an **82 %** size-matched expectation it is *below* chance — and the mechanism
excludes causation anyway, since the dead parity chain lives in `unique` space and never reaches
compiled output.

## 7. Three harness rules this round paid for

1. **A single corpus round is not evidence — repeat until stable, and state the run count.** The
   K-7 round's *first* run read WGSS 0.5520 / EXACT 851 with ten EXACT→MISMATCH flips. Runs 2 and
   3 read 0.5589 / 861, identical to each other and fully cached. Run 1 was contaminated.
2. **A down whose source text did not change is a harness artifact until proven otherwise.** For
   the first of those ten flips the TU was byte-identical, the manifest row identical, the prelude
   identical — and re-checking that unit against a clean cache gave EXACT from *both* trees.
3. **`extra` divergence rows carry the CANDIDATE's addresses**, so they must never be joined to
   original pcs. A join on exact pc returned 11 of 9,290 and would have been reported as a clean
   refutation; the valid join is function-level.

The run-1 contamination **cleared itself** because unadjudicated compile results are no longer
cached (`CompileOutput::adjudicated`) — the bad units simply recompiled. Its cause is **not
named**: the Watcom work directory is per-PID and self-removing, unit filenames cannot collide in
8.3 space, and there is no evidence of a concurrent round in the window. `~/.dosemu/drive_c` is
shared per user and is the one real cross-worktree channel, but nothing was written to it during
the window. No fix is proposed for an unnamed cause.

## 8. Open

- **K-5d**: the 65 unnamed held `local-decl` TUs, same trace-diff method.
- **The parked `merge-datatype` port** is a decision, not a build order: half the largest clean
  class, more Ghidra-faithful, −0.00182 WGSS.
- `deref-cast` (MORE 90/3) and `array-index` (FEWER 22/8) are the next two clean classes.
- The isolation-sensitive pool is **not** a defect list, and should not be mined as one without a
  context-fair capture method.
