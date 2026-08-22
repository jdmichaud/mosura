# The Watcom dial-patch experiment — results

Companion to [`watcom-dial-patch-experiment.md`](watcom-dial-patch-experiment.md) (the brief).
Baseline at handoff: **zc26 = 764 EXACT / WGSS 0.4801**, tree clean at `172b1aa`; this work runs
in worktree `/data/wt-dialpatch` on branch `dial-patch`, off `61378c0`.

Run by a separate agent (Opus 5), 2026-08-22, per §9 of the brief.

---

## 0. Pre-registration

Recorded **before** the corresponding measurement, per brief §6 ("pre-register the ceiling and the
specimens") and memory `experiment-discipline`.

### PR-1 — Dial A, table order (registered before any corpus run)

The brief's Dial A names `DoubleRegs[]` in `bld/cg/intel/386/c/386rgtbl.c` as the allocation-order
dial and asks for a patch that changes the *order*, not a wholesale disable.

- **Prediction A1.** If the shipped 10.x compilers all carry the same allocation-order table, the
  table-order leg of the interim-build hypothesis is dead on direct evidence and no table-order
  patch is justified as a hypothesis test.
- **Prediction A2.** A patch that swaps two entries of that table is only a valid *dial* if the
  table is not also the parameter-passing table. If it is, the patch is a wholesale change to the
  calling convention and, per §6, can support at most an invariance reading — it must be rejected
  as an instrument rather than run against the corpus.

### PR-2 — declaration-order ceiling (registered before the census below was run)

After the Dial-A reconnaissance produced the finding in §3, the follow-on question is how much
EXACT is reachable by changing the order in which locals are DECLARED in our emitted C.

- **Specimens.** The six strict regalloc-only SAME_SHAPE functions are the pass/fail set:
  `FUN_0005fb24`, `FUN_0002724c`, `FUN_0001798c`, `FUN_000464b4`, `FUN_0006a720`, `FUN_00073936`.
- **Prediction B1.** Of those six, the three with ≥2 permutable register temps and a clean
  two-register swap (`FUN_000464b4`, `FUN_0005fb24`, `FUN_0001798c`) have a byte-exact
  declaration order; `FUN_0002724c` (one local) and `FUN_00073936` (two-instruction function,
  uninitialised read) do not; `FUN_0006a720` is unknown.
  *(B1 was checked before the census and is reported in §3.3.)*
- **Prediction B2 — the ceiling.** Over the whole SAME_SHAPE ∩ regalloc candidate set restricted
  to functions with 2..4 permutable locals, I predict **15–35 %** of candidates have some
  byte-exact declaration order. Below 10 % would make the lever marginal; above 50 % would mean
  declaration order is the dominant residue in this class.
- **Prediction B3 — MISMATCH set.** Over `MISMATCH` functions carrying a regalloc class (which by
  construction also carry other classes), I predict **under 5 %** reachable, because the other
  classes are not addressed by reordering declarations.
- **What would falsify the finding.** If reordering declarations changed nothing anywhere, or if
  the exact orders found were not reproducible on a re-run, the mechanism claim in §3 is wrong.

### PR-3 — Dial B, scheduler (registered before any Dial-B patch)

- **Prediction C1.** `InsStallable`'s operand-class weights are small immediates in the compiled
  binary and can be changed without collateral effect on any other transform — i.e. Dial B, unlike
  Dial A's table, is a genuinely isolated dial.
- **Prediction C2.** If WAR2's scheduler priority differs from 10.0a's by those weights, patching
  them should reorder the watsched holdout windows (`FUN_00073328`, `FUN_00019344`,
  `FUN_0004b750`'s 6th call site) toward the original. If the holdouts do not move, the operand
  weights are not the difference.

### PR-4 — Dial A, tie order (registered before the corpus run)

The live Dial-A hypothesis after the table-order leg died (§2) is the brief's own §4 "tie-order"
version. The located predicate is `GiveBestReg`'s equal-score test (`regalloc.c:855–861`,
10.0a file offset `0x59ea3`); the minimal order-changing edit is `JG` → `JGE`, which makes the
**last** entry of the register table win an equal-score tie instead of the first.

- **Prediction D1 (isolation).** The parameter-passing convention is unaffected: incoming
  arguments still arrive in EAX, EDX, EBX, ECX.
- **Prediction D2 (breadth).** Because `saves == best_saves` is the *common* case (most candidate
  registers score 0), this edit will not be a narrow tie flip — it will shift allocation toward
  the tail of the table across most functions, including allocating EBP as a general temp.
- **Prediction D3 (the discriminating test).**
  - *Under the interim-build/dial hypothesis* (WAR2's compiler broke allocation ties the other
    way): the patched corpus should convert a substantial share of the regalloc residue, i.e.
    EXACT should RISE, and in particular the strict regalloc-only specimens should flip.
  - *Under the declaration-order model established in §3* (the tie is decided by the order the
    temps reach the allocator, which our C controls): the patch should convert essentially
    nothing and should destroy a large fraction of the existing 764 EXACT, because those 764 are
    exact under the stock first-wins rule.
  I predict the second: **EXACT falls sharply (I pre-register "below 300"), WGSS falls, and none
  of the six strict specimens converts.** If EXACT instead rises, the declaration-order model is
  wrong and the interim-build hypothesis is alive.
- **Interpretation limit, registered in advance.** Per brief §6, a change this broad can support
  only a directional/invariance reading. A large fall refutes "WAR2's compiler broke ties
  last-wins"; it does **not** by itself prove no tie-break dial differs, only that this one, in
  this direction, is not it.

---

*(results follow — sections filled in as each measurement completes)*
