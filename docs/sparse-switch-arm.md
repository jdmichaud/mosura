# The `sparse-switch = switch` emitter arm — a compare tree printed as the sparse `switch` it came from

## The shape

Watcom 10.0a compiles a sparse `switch` (no jump table) into a balanced compare tree over the
scrutinee: pivot = the lower median of the sorted case set, recursively, each pivot one `CMP p`
with a `JB` (below subtree) and a `JBE`/`JE` (the equal case), the last compare of a subtree
range-pruned (a singleton reached as the only value left is never compared). Ghidra structures
the tree as nested if/else on one variable and prints it as such; Watcom then recompiles that
if/else chain sequentially, never as the tree — so the bytes diverge on every such function.
Watcom rebuilds the tree from the CASE SET alone (fable-b, wc2src-reconciliation-4 W5: the
lower-median check reproduces 0x14620's pivot sequence 0x11 → 0xd/0x14 → …), so the arm's job is
to recover the set and print the `switch`; probes srcform4/16 took 0x14620 from 0.376 to 0.812
(12 cases, bodies in address order, scrutinee inlined).

## The recognizer (`try_emit_sparse_switch`, hooked at the top of `emit_if`)

An emitter arm over the structured tree (Ghidra has no such mechanism — `BlockSwitch` comes only
from `BRANCHIND`). Rules, each named by the 0x14620 fixture's diagnostics:

- **Root only.** The outermost `if` whose condition compares one scrutinee against a constant; an
  `if` whose parent is already a compare on the same scrutinee is inside the tree.
- **The scrutinee's identity** (`SparseKey`): its HighVariable — or, when Watcom re-loads it
  before every compare (the first census: `[Ptradd, Load, IntLess, Cbranch]` in every inner
  condition block of 0x122b0/0x49a20, `[Piece, IntEqual, …]` at 0x173b4), the load of `base + off`
  with the base by HighVariable, or the PIECE of two highs. A re-loaded scrutinee prints as the
  expression itself (`switch (*(uint2 *)(param_1 + 0x1a))`), which is also fable-b's inline form.
- **A pure condition block** has no side effect and every live op's output is consumed inside
  the block (the scrutinee's own re-load / address / piece ops qualify; a value a body reads does
  not) — not a whitelist of opcodes.
- **Walk with interval narrowing.** Each condition yields the value ranges for which it is true
  (`sparse_true_ranges`; `CondAnd`/`CondOr` mirror the printer's own polarity —
  `operand_oriented ^ cond_flip` per operand, the node kind as the connective, the `if`'s
  `negated` complementing the whole); the then-branch gets `reach ∩ true`, the else-branch or the
  fall-out the complement. An `if` without else falls out through its own unconditional goto
  record when it has one (`if (4 < u) {..} goto LAB;`), else to what follows the tree.
- **Lists.** A `List` node walks in order: a compare-`if` without else narrows the reach for the
  next component; the last component is the leaf. An `if` whose CONDITION is a `List` (Ghidra
  folds `if (u < 0x13) {..return;}` ahead of the next if's own compare) narrows through the
  leading compares and prints, as a case body, with the list's last component as its condition
  (`sparse_cond_override`). A non-last `IfElse` in a list whose branches both flow into the
  components after it is a JOIN: its leaves carry that continuation.
- **Leaves → cases.** A leaf reached with ONE value whose body is not the tail is that value's
  case (range-pruned singletons included: 0x10 after `CMP AL,0xf`, 0x13 after `CMP AL,0x12`). A
  leaf that is the tail, a bare `return;` (the epilogue COPYs tolerated) or a goto to the tail:
  its values that were compared for equality or as a pivot (the same constant compared twice —
  Ghidra attributes the `JB`'s and the `JBE`'s compares to their own jump pcs) are explicit EMPTY
  cases (0xd: `CMP AL,0xd; JBE post-switch`); its never-compared values (0xe) are the default. A
  multi-valued leaf with any other body is not a tree — bail. A goto-only leaf merges its values
  into the case that owns the target block (`case 4: case 0x10:`).
- **Range leaves.** Watcom merges consecutive cases sharing a body into a range check (`CMP AL,1;
  JB default; CMP AL,6; JBE body` = `case 1: … case 6:`; `CMP AX,1; JBE A` under a pivot = `{0,1}`):
  a multi-valued leaf with a body whose bounds are compared constants (or the domain's floor) is a
  run of labels; an unbounded one (the `[0,3]` below 0x1201c's pivot 4, whose sub-node is an
  `if (call() != 0)`) is not a tree — bail. A wide leaf with a body is the default's body.
- **A pivot is required.** Watcom's tree signature is one constant compared by range and by
  equality/range at one CMP (`CMP p; JB; JBE`), emitted even for two or three cases (0x122b0's
  outer {8, 9} and inner {0, 1, 2}, 0x14cc0's {0xe, 0x1c}); a chain of plain equalities is the
  if-chain the source wrote — 0x12360 was EXACT as `if (p == 3) .. else if (p == 0) .. else if
  (p == 2)` and lost it as a switch on the w5a round, with 0x124ec/0x1812c/0x7015e/0x16e3c alike.
- **Loop-owned trees decline.** When the enclosing `while(true)`'s condition holds the tree's
  `JB` guard (0x1201c), the switch the body alone can print recompiles worse than the if-chain
  (-0.146 on w5a): the walk declines instead of narrowing.
- **Never past the exit.** A jump's landing node never climbs into a list/if that holds the
  switch's exit block: 0x4822c's tail A climbed into `[A-if, LAB_0004830b]` and the shared
  `func_5a0ec(); return;` printed inside `case 0/1/4` AND after the switch — `E1017 label
  already defined` on four TUs of w5a (0x4822c 0x29dcc 0x4963c 0x5d394).
- **Two cases suffice with a pivot.** Watcom emits the JB/JBE tree even for a 2-case switch
  (0x122b0's outer `switch (*param_2) { case 8: case 9: }`, the constant 8 compared twice); a
  plain equality chain has no pivot and stays if/else.
- **Melded ranges.** Ghidra's `RuleRangeMeld` prints `x >= 0xfe` as `(x + 2) < 2`; a compare whose
  operand is `INT_ADD(scrutinee, c)` is the wrapped interval `[-c, k-1-c]`.
- **Nested switches on other fields** (0x122b0: `case 9: switch (param_2[1]) …`) fall out naturally:
  each root is its own tree; a re-loaded scrutinee's COPY into a variable read only by the tree is
  suppressed.
- **Compare witness.** The IR cannot carry the JB/JBE distinction: Ghidra canonicalizes `CMP AL,4;
  JB` on its fall-through edge to `3 < x` and `CMP AL,0xf; JBE` to `x < 0x10`, so a pivot's `JB`
  side and a run's `JBE` bound look identical in the p-code. The arm reads the original jump
  instead (`buildconfig::sparse_cmps_from_evidence`, the rep-string arms' witness pattern): every
  Jcc pc — and the CMP's pc for its first jump, where Ghidra puts the flag compare — maps to the
  CMP's immediate and the jump's kind (`JB`/`JAE` = LT, `JBE`/`JA` = LE, `JE`/`JNE` = EQ); the
  survey and the fixture test feed it through `RecoveredChoices::sparse_cmp_sites`. Without a
  witness the walk reads the canonical forms back (`c < x` = `!(x < c+1)`). A run `[a, b]` is
  delimited by `JB a` below (or the floor) and `JBE`/`JA b` above (or the ceiling); a pivot is one
  constant under two kinds; a `JB p` side alone ([0, p-1]) is the subtree's or the default's.
- **Compares cut to gotos.** A basic block holding only a scrutinee compare whose branch the
  collapse turned into `if (u != 1) goto LAB;` (0x48604, 0x13c74, 0x4822c's `if (!(u <= 1)) goto`)
  is a tree node: the jump is a leaf out of the tree, the rest of the reach falls into the next
  list component. A leaf that lands OUTSIDE the tree prints as its `goto` (`default: goto
  LAB_00013cca;` — the after-switch code the default skips, per the bytes' layout), never as the
  target block's contents (the 0x4822c duplicate-label bug).
- **Siblings.** An earlier list sibling that compares the scrutinee owns the tree (the second `if`
  is its continuation — `if (u < 3) break;` above 0x1201c's `== 4` root); a later one continues it
  (0x14ac8's `if (u < 2) {..}` then `if (u <= 2) .. else ..`): the walk runs over the list from the
  root (top-level roots included), up to a closing bare `return`, and the printer skips the
  consumed siblings. A nested list component flattens into the walk.
- **List-condition roots.** Ghidra folds a preceding `if` into the next test's condition list
  (0x14ac8: `if (u < 2) {..}` ahead of `u <= 2`), so the root's compare is the list's LAST
  component and the leading ifs are tree nodes; a leading pure statement (0x2d7fc's
  `puVar3 = param_1 + 8`, a shared address the compiler hoisted to the subtree's root) prints
  above the switch. A node inside such a condition list is never a root of its own.
- **Root heads.** A root whose condition list begins with statements — an `if` on another
  variable, calls, the very call that defines the scrutinee (0x4ccc4: `if (cVar1 == 0) ..;
  func_58bec(..); iVar2 = func_59060();` ahead of `iVar2 < 2`) — prints them above the switch;
  only the tree compares among the leading components are walked. Signed trees (`JL`/`JLE`
  pivots on an `int`) go through the same witness kinds.
- **Loop-condition narrowing.** A tree whose `JB` guard became the enclosing loop's condition
  (0x1201c: `while(true) { .. if (u < 3) break; <tree> }`) walks with the body's reach — the
  values the loop condition admits (`u >= 3`) — so the guard's side never turns into labels.
- **Where a jump lands.** A leaf that jumps into (or falls into) a block resolves to the
  outermost list/if entered at that block, never its bare condition block, so the default's
  body and a compared value that reaches the same code print once, as `case 0: default:`
  (0x4fbcc); a case's body ends with the `goto` an enclosing if/list takes after it (Ghidra's
  BlockGoto follows the wrapped node's whole body — 0x4fbcc's `case 0x20: ..; goto LAB_0004fc8a;`),
  or `break` when that target is the switch's exit. A compare block that also computes a pure
  value the cases share (0x2d7fc's `puVar3 = param_1 + 8` inside the `< 0x26` block) is a tree
  node whose statement prints above the switch.
- **Runs vs. pivots at the floor.** `CMP AL,1; JB exit; JBE exit` (0x2d7fc) is not a run
  `{0, 1}`: the `JB 1` puts 0 below the range (default) and 1 is the pivot's empty case — a run
  admits no `JB k` cut inside it. An equality the IR folded away still counts when the bytes hold
  it: Ghidra rewrites `!(x <= 0xfe)` on a byte to `x == 0xff` and drops the redundant
  `CMP AL,0xff; JE`, so `case 0xff:` survives only as an EQ witness right after a tree compare.
- **Default merge.** A leaf that jumps where the default jumps (`CMP 1; JNE default` leaving 0 on
  the default's edge) is the default unless its value was compared by itself.
- **Reference-printer fix found on the way (Ghidra parity, wrong code).** A short-circuit node
  standing as a statement whose cut edge is a conditional goto (Ghidra's `BlockIfGoto` wrapping a
  `BlockCondition`, block.cc:1799) printed as an empty `else { }`: the record sits on the
  condition's exit block, which the spine emit never reached — 0x4fbcc sent every value of 11..25
  to the wrong target. It now prints `if (cond) goto LAB;` with the whole condition.
- **Declines (by design).** 0x1201c: Ghidra absorbed `x == 1 && func() != 0` into the do-while's
  condition, so case 1's body is the loop exit — the if-chain prints unchanged. 0x173b4: not a tree
  problem — the stack store `xStack_14 = ..` at 0x173e0 is killed and re-materialized as a COPY at
  the compare's pc, the condition block shrinks and `ruleBlockOr` (faithful) merges it; a
  stack-store placement parity item, tracked outside this arm. First evidence (trace-diff on the
  specimen `x86_173b4`, 2026-08-27): `RuleStoreVarnode` fires 11× in Ghidra vs 6× in mosura — the
  five misses sit at the call pcs 0x1740e/0x17423/0x1742e/0x1743c/0x17448 — and Ghidra's
  `ActionDeadCode` touches 0x173e0 (the `xStack_14` store) where mosura's never does; mosura's kill
  of that store between structure derivations comes from an untraced path (a MOSURA_TRACE gap to
  close first). Lead: the diff's only mosura-only ACTION is `dominantcopy [ActionDominantCopy]` (1×, Ghidra fires
  none on this specimen), and the value that reaches the final C is a fresh `u0x10048 = COPY
  [0x812d1]` at 0x173ed — the compare's pc — while both sides still hold the original
  `*(EBP-4) = AL` STORE at 0x173e0 when the 0x1740a phis form. Start the thread there.
  Instrument note: PORT_CLASS_MAP still names `ActionConsume`, which no longer exists.
- **Print.** `switch (S)` with the scrutinee's defining load inlined when the tree's compares are
  its only uses (through every member of its HighVariable); empty cases first, then bodies in
  address order (Watcom lays bodies out in source order), `default:` last; a case breaks by
  Ghidra's rule (one out-edge, not the last); join groups print `body; goto L;` for every member
  but the address-last, which prints `body; L: continuation`.

Fixture `oracle/fixtures/x86_14620_sparse_switch.xml` (a self-compiled MVE with the specimen's case set; the WAR2 address is provenance only), test
`tests/sparse_switch.rs`: the case set {4, 0xc, 0xd, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
0x19, 0x1a}, `case 0xd: break;`, `case 4: case 0x10:`, `switch (*((uint1 *)(param_1 + 6)))`.

## Acceptance (fable-b, w4b2 tree)

26 game TUs / 1,523 loss: 0x2d7fc (21 consts, 268) 0x429d0 (4, 218) 0x23c40 (3, 132) 0x45ba0
(3, 109) 0x14620 (10, 83) 0x28d98 (5, 68) 0x21f30 (6, 66) 0x1201c (3, 57) 0x122b0 (5, 44)
0x488c8 (5, 43) 0x173b4 (3, 42) 0x4822c (3, 41) 0x4fbcc (6, 33) 0x4ccc4 (5, 33) 0x48604 (3, 33)
0x49a20 (3, 31) 0x4a640 (3, 30) 0x14b44 (3, 29) 0x3ea40 (3, 23) 0x14ac8 (3, 23) 0x18b98 (3, 23)
0x3d470 (3, 22) 0x151ac (3, 18) 0x151e8 (3, 18) 0x13c74 (4, 18) 0x13dc4 (4, 18). Byte-side
check: the recognizer's case set must be a superset of the constants compared against the
scrutinee register in the original; two-constant sets (0x45ba0 0x49a20 0x14b44) are likely if/else
chains, not trees.

**Landed 2026-08-27 — round `w5c` vs `w4b2`:** WGSS 0.5507 → 0.5568 (+0.0061; 71 movers, 61 up /
10 down, weighted net +746.9 insn-sim), EXACT 851 → 856 (0x13c74, 0x13dc4, 0x14ac8, 0x14cc0,
0x4ccc4), SAME_SHAPE +6 (0x2bc8c 0x4921c 0x4abac 0x4afec 0x4b5d0 0x4b684), COMPILE_FAIL at the
baseline 1, no verdict regression; game TUs printing a switch 33 → 88. Downs: five are the
BlockIfGoto-over-BlockCondition fix printing a previously dropped test (0x20310 −0.317, 0x1cdc0,
0x2a360, 0x6b1a9, 0x65a68 — wrong-code corrections), five are form residues on byte-real trees
(0x507d4 −0.044, 0x5d394 −0.017, 0x5b38c −0.008, 0x6f089 −0.003, 0x66100 −0.002). Gated suite 972
pass / 0 fail. Follow-ups: the dead `uVar1 = *p;` copy left above a re-loaded scrutinee's switch
(0x2d7fc, 0x4822c), the nested-pair residues, the 0x173b4 stack-store placement thread.
