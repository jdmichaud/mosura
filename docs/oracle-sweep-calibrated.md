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
 deref-cast      67    2539  13.8%   43    52   MORE  67/FEWER  0  NEW
 array-index     31    1138   6.2%   20    30   MORE   8/FEWER 23  NEW
 short-circuit   14     849   4.6%   11    14   MORE   8/FEWER  6  KNOWN-OPEN
 while           14     744   4.1%   12    14   MORE   6/FEWER  8  KNOWN-OPEN
 piece-ops       16     574   3.1%   15    16   MORE  10/FEWER  6  KNOWN-CLOSED
 do-while         6     475   2.6%    4     5   MORE   3/FEWER  3  KNOWN-OPEN
 for             11     458   2.5%    9    11   MORE   8/FEWER  3  NEW
 goto             3     286   1.6%    3     3   MORE   3/FEWER  0  NEW
 halt/trap        3      53   0.3%    0     2   MORE   0/FEWER  3  KNOWN-NAMED
```

**Two rows are corrections, and both corrections are the same failure.** `deref-cast` first read
**93 / 3,514**; the counter could not see a pointer-to-pointer cast, so 23 TUs where Ghidra spells
`*(char **)x` were scored as ours-only — the row above is the corrected 67 / 2,539 (§8).
`array-index` first read **30 / 1,129**; that counter could not see an array *declaration*, because
both printers spell one `int4 aiStack_60 [9];` with a space and `\w+\[` will not cross it — uses
were counted, declarations were not. Normalizing whitespace before matching moves it to the
**31 / 1,138** above (one TU joins, `00923`; one delta deepens, `01476` −7 → −8), with the game and
band cuts and the direction recut on the same members. Two classes, two counters, one rule:
**normalize before matching** (§9).

`piece-ops` deserves its mark: this is the first corpus-scale measurement of W7's shared-limit
question under the correct cspec, and at **16 clean TUs / 574 loss / 3.1 %** it is consistent with
that closure rather than reopening it. `halt/trap` is the named-but-unported halt-type concept.
`goto` is the only class where we emit unstructured control Ghidra does not.

## 5. `local-decl`: a three-way split, and two different mechanisms

Cross-checked against the parked `merge-datatype` port (`28cb07b`, Ghidra's `ActionMergeType`
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

**Update after the `RuleEqual2Zero` landing of §6.** Re-measured on `0c5016f`, the class is
smaller and the split moves: of the 149 MORE-locals TUs, **17 were resolved by that landing alone**
and 132 survive (loss 4,070); of those the parked port moves **66** and **66 are held** (loss
1,045). So "65 unnamed" reads **66 / 1,045** at the current baseline, and the fix found through
this class took a bite out of the class itself. The held half's mechanism is located but not
attributed: our `classes_interfere` declines 57 COPY merges on `idx 00011` for cover intersection,
while `build_dominant_copy` — the transformation that exists to dissolve exactly those — is
attempted ONCE on that function and once across 20 held TUs. Whether Ghidra's covers are narrower
or its trims simply fire is not decidable from the console: `HighVariable::printCover` prints
"Cover dirty" once later phases set the flag (variable.hh:188), which is what `oracle/capture_merge`
was built for.

> **SUPERSEDED 2026-09-02 by Order O.** The paragraph above says the held half's mechanism is
> "located but not attributed", and names two candidates the console could not decide between:
> narrower covers, or trims that simply fire. `oracle/capture_merge` was built to decide it, and
> it did — but the answer is neither candidate. It is a third thing: Ghidra's `copyShadow`
> exemption lives INSIDE the one interference test every merge site shares
> (`HighIntersectTest::testBlockIntersection`, variable.cc:978), and ours is not consulted at the
> COPY-merge site.
>
> The attribution is PARTIAL, and Bob's four figures matter more than the headline. In his words:
>
> > · **24 of 57** on `00011` are Ghidra-merges-we-decline, predicted 57/57 with zero off-diagonal
> >   by the missing `copyShadow` exemption;
> > · **33** are not divergences at all — we decline and so does Ghidra, so §5's "57 declines" was
> >   never 57 divergences, and that sentence of mine was loose;
> > · **01661's 94** declines are all correct, so its held loss is a different mechanism entirely;
> > · **02714** leaves **6 pairs** the exemption does not explain.
>
> So the sentence above should read: *attributed in part — at most 24 of 57 on `00011`, by the
> missing `copyShadow` exemption; a second mechanism remains on `02714`, and `01661` is not this
> class at all.* The "57 declines" figure in the superseded text is therefore not a divergence
> count and must not be quoted as one. Full account: the `wc2src-reconcile` ledger,
> `docs/wc2src-reconciliation-4.md`, Order O.

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

## 7. Five harness rules this round paid for

1. **A single corpus round is not evidence — repeat until stable, and state the run count.** The
   K-7 round's *first* run read WGSS 0.5520 / EXACT 851 with ten EXACT→MISMATCH flips. Runs 2 and
   3 read 0.5589 / 861, identical to each other and fully cached. Run 1 was contaminated.
2. **A down whose source text did not change is a harness artifact until proven otherwise.** For
   the first of those ten flips the TU was byte-identical, the manifest row identical, the prelude
   identical — and re-checking that unit against a clean cache gave EXACT from *both* trees.
3. **`extra` divergence rows carry the CANDIDATE's addresses**, so they must never be joined to
   original pcs. A join on exact pc returned 11 of 9,290 and would have been reported as a clean
   refutation; the valid join is function-level.

4. **A calibration must be able to FAIL for the instrument at hand.** The house rule for captures
   is "a watcom capture prints NO convention keyword" — and applied to `oracle/capture_trace` it
   passes vacuously, because a rule trace never prints a prototype: the watcom, windows AND gcc
   probes all yield zero keywords. A check that cannot fail proves nothing. The non-vacuous
   substitute for trace tools is **root-sensitivity**: the calibrated root yields 7,342 trace
   lines, a root without a watcom spec dies with `No sleigh specification for x86:LE:32:default`.
   Assert the property the instrument can actually violate.
5. **The console cannot show a cover, so do not ask it to.** `HighVariable::printCover` is
   `if ((highflags & coverdirty)==0) internalCover.print(s); else s << "Cover dirty"`
   (variable.hh:188), and later phases set that flag, so `decomp_dbg` reports membership but never
   the cover that DECIDED the membership. `oracle/capture_merge` exists for exactly that gap: it
   stops at the end of the merge cluster and prints each member's cover through
   `Varnode::getCover()`, which recomputes on access (varnode.hh:202).

The run-1 contamination **cleared itself** because unadjudicated compile results are no longer
cached (`CompileOutput::adjudicated`) — the bad units simply recompiled. Its cause is **not
named**: the Watcom work directory is per-PID and self-removing, unit filenames cannot collide in
8.3 space, and there is no evidence of a concurrent round in the window. `~/.dosemu/drive_c` is
shared per user and is the one real cross-worktree channel, but nothing was written to it during
the window. No fix is proposed for an unnamed cause.

## 8. `deref-cast`: the class that burned its counter three times, and a slate item

**The class is 67 TUs / 2,539 loss, not the 93 / 3,514 of §4's table.** §4's figure was measured
with a counter that could not see a pointer-to-pointer cast; 26 % of the class (23 TUs, 808 loss)
was Ghidra spelling `*(char **)x` where the pattern only matched `*(char *)x`. That was the second
of three counting failures in this one class — see §2's discipline and §9 below.

**Mechanism.** Ghidra's `checkArrayDeref` (printc.cc:353-368) has no width test at all — implied,
written, SEGMENTOP unwrap, PTRSUB/PTRADD, true. Our printer carried one (added by 677bef8 to fix
`heapstring`'s 1-byte store through an `xunknown8 *`). Ghidra decides width one layer up, and
**not symmetrically**: a STORE whose value size disagrees with the pointee gets a CAST on the
POINTER (`TypeOpStore::getInputCast`, typeop.cc:536-538), and that CAST is what makes
`checkArrayDeref` decline; a LOAD instead POSTPONES, casting the loaded VALUE (`TypeOpLoad::
getInputCast`, :454-461). A printer gate cannot tell a load from a store, so loads were getting
the store's rendering. cast.rs's own not-ported arm had already named the fix and its revival
condition.

**The faithful pair** — port both overrides, delete `Load`/`Store` from that arm, then remove the
printer gate — measured on `b2654ea`, two stable rounds:

```
  build                 EXACT      WGSS      class Σ|delta|   class exact hits
  baseline b2654ea       866      0.5594          86                0
  whole pair             863      0.5594          38               47
  LOAD-only (WITHDRAWN)  865      0.5583          38               49
```

The pair's four downs are one one-character change — the store's pointer cast `int2 *` → `uint2 *`
— and **Ghidra prints `uint2 *`**, so the candidate is the faithful spelling. The compiled cost is
one operand form (`XOR EDX,EDX` → `XOR DH,DH`): neither spelling is wrong code, but the original's
codegen is what a *signed* short produces, so the unfaithful spelling happened to match the real
compiler. We pay 3 EXACT to agree with Ghidra where Ghidra disagrees with the source.

**THE CENTRE LINE: the LOAD-only half looked cheaper and was wrong code.** At −1 EXACT against
−3 it was the attractive option, and it keeps the entire class gain (Σ|delta| 38, 49 exact hits —
the store half contributes nothing textual). It also manufactures **155 width-mismatched
cast→subscript stores across 63 TUs**: `*(xunknown2 *)(param_1 + 4) = x` becoming `param_1[4] = x`
on an `xunknown1 *` narrows a 2-byte write to 1 byte, and the mirror widens 1 byte to 4. Removing
the printer gate without porting the STORE override leaves nothing to re-insert the cast, so
`checkArrayDeref` fires on every PTRADD-fed store and prints at the POINTEE's width. **The two
verdict drops were the arbiter noticing.** A wrong-code scan of the whole pair finds ZERO such
conversions — the store override prevents exactly this — so the halves are not separable: the
store override is the safety half, not a cost to trim. **The LOAD-only probe must never be revived
without it.**

**The class is two families, and the pair addresses one of them.** *Shape 1, doubled indirection*:
we cast at every level (`*((code *)*((xunknown4 *)x))`) where Ghidra casts once to a doubled
pointer (`**(code **)x`) — the pair fixes this wherever the PTRADD exists, and it is where the 47
exact hits come from. *Shape 2, a narrow read through a typed pointer*: Ghidra indexes and
truncates the value (`(uint4)(uint1)param_4[1]`), we re-cast the pointer (`*(uint1 *)(param_4 + 1)`)
— and the pair CANNOT fix it, for a reason that lives upstream of casts. **Both sides LIFT one
byte**: at `heritage` Ghidra's op is `u0x00017000:1 = *(ram,…)`, exactly ours. The two-byte load
with a `SUB21` truncation that Ghidra shows by `copymarker` is `RuleExpandLoad`'s PRODUCT — Ghidra
fires it, we decline, because our PTRADD output carries `Pointer(uint1)` where the element is 2.
That decline is Order L's port gap: the missing PTRADD branch in `propagate_add_pointer`
(infertypes.rs:540 against typeop.cc:1268), recorded in the `wc2src-reconcile` ledger at `b5d240d`.
So casting the pointer is the correct answer to the IR our override is given TODAY, and Order M
changes that IR — which is precisely why the slate waits for M rather than being decided now. The
20 non-movers in the table above are that family, kept in the denominator rather than dropped.

Slate, held for Order M's round and to be re-measured on the post-M base: **(a)** the whole pair
at −3 EXACT, WGSS flat, no wrong code; or **(c)** park, with both overrides unported and their
revival condition standing in cast.rs. Neither meets the zero-verdict-regression bar, so it is a
decision rather than a landing.

Both were measured after M's round; the numbers are in §11.

## 9. The counter burned three times — the worked sequence

Each failure produced a confident wrong answer and a different discipline caught it. This is the
part of the method worth carrying to the next class.

1. **The extra paren.** We print `*((T *)x)`, Ghidra `*(T *)x`. The first table read
   *"we emit FEWER in 739 of 741 TUs, 65 % of clean loss"*. Caught by the **structural-presence
   check** — read a specimen and both sides have the construct.
2. **The double star.** `*(char **)x`: `\*\)` cannot match `**)`. 26 % of the class evaporated.
   Caught by **per-site comparison** of cast forms.
3. **The spaced double star.** We print `code * *`, Ghidra `code **`; `\*+` will not cross the
   space. This produced a fictitious *"48 of 67 overshoot, 0 exact"* and a recommendation against
   the change. Caught only by **tracing a specimen** — reading the C.

A fourth failure, in Order N, is the same family one layer up and is the one to remember. A
census of negated-comparison sites read **237**, was corrected to **233** when a regex turned out
to be matching `>>` as `>`, and the round then measured **242 → 4** with a single shift-normalized
scanner over both sides. The first correction was a miscount. The second was not: the earlier
figures came from a **different scanner** than the one that measured the result, so both numbers
looked equally quotable and only one was comparable. **One scanner measures both sides, always** —
a before/after pair produced by two scanners is not a measurement, and nothing about the numbers
advertises the mismatch.

Two rules came out of it. **Normalize before matching** (`re.sub(r'\s+','',text)`): spelling
differences between two printers are the norm, and this class alone spells one construct three
ways. **Report Σ|delta|, never a signed sum**: a class is defined by one-sided deltas, so
overshoot cancels undershoot and a signed total reads as convergence when the change has merely
redistributed the error. Both a signed sum and an absolute sum on a wrong counter were reported
and withdrawn before the third measurement settled it.

## 10. Open

- **K-5d**: the 65 unnamed held `local-decl` TUs, same trace-diff method. Partially attributed
  since — see the §5 supersession for what Order O did and did not account for.
- **The parked `merge-datatype` port** is a decision, not a build order: half the largest clean
  class, more Ghidra-faithful, −0.00182 WGSS.
- `array-index` is the next clean class to open (§4: 31 TUs / 1,138 loss, FEWER 23 / MORE 8).
  `deref-cast` is no longer "next" — it is measured and on the slate (§8, §11), and its
  corrected direction is MORE 67 / FEWER 0.
- The isolation-sensitive pool is **not** a defect list, and should not be mined as one without a
  context-fair capture method.

## 11. Slate, 2026-09-02 — numbers only

Four measured options, **all on one base**: master `78287fb`, **867 EXACT / WGSS 0.5607**, all
`kind=user`. Each row is stable at two rounds; the recommendation is not here.

```
  option                    EXACT     WGSS      delta        verdict flips
  park                        867     0.5607    —            —
  M alone (a9f7eef)           867     0.5601    −0.00058     0
  pair alone (70ebc6c)        864     0.5607    −0.00007     4, all down
  M + pair (fe10559)          864     0.5601    −0.00065     4, all down
  O(2) (a40b3dc)              pending its round
```

**M and the pair are additive to the digit** (−0.00058 + −0.00007 = −0.00065) and the stacked run's
four flips are the same four functions as the pair alone, so the two changes do not interact.

What each buys: **M** corrects a wrong pointee type in the IR — a latent wrong-code source for
every consumer of the pointee width — for no verdict movement. **The pair** ports Ghidra's two
`getInputCast` overrides and removes the printer width gate they replace, converging `deref-cast`
by Σ|delta| 86 → 38 with 47 of 67 TUs landing exactly on Ghidra's count, at the cost of three
EXACT; its four downs are one one-character change (`int2 *` → `uint2 *`) that **Ghidra also
prints**, costing one operand form in the compiled output, with no wrong code on either side.

Neither meets the zero-verdict-regression bar, which is why they are a decision rather than a
landing. The LOAD-only half of the pair is **not** an option: it looked cheaper at −1 EXACT and
produces 155 width-mismatched stores across 63 TUs (§8).
