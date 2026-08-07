---
name: task5-condconst
description: Task #5 port ActionConditionalConst (conditional-constant propagation) — Commit A landed, Commit B (wire) measured + GATED
metadata:
  node_type: memory
  type: project
  originSessionId: c0fe6b35-0fb2-4ed2-90d8-ec93de63680c
---

Task #5 (owner ccprop1): faithful port of Ghidra ActionConditionalConst (condconst) — propagate a
guard's compared-to constant into the guarded block (`if(x==c)` => dominated reads of x become c).

STATE (2026-07-08): ✅ **COMPLETE — both commits LANDED on master.** Commit A `b3163dc` (unwired module
+ 8 tests), Commit B `654f4f5` (wire + coverage PORTED). Base `e0f2d96`. Post-land re-verify on master:
suite 344/0, corpus avg 0.8882→0.8893, condconst 0.814→0.862, elseif 0.899→0.915, zero regressions.
Task #5 marked completed. Lead approved both (whole-action port + placement after ActionDeterminedBranch).

## Commit A `b3163dc` — condconst.rs DEFINED-BUT-UNWIRED (byte-identical corpus, self-approved)
Whole faithful port: apply (coreaction.cc:4514) + findConstCompare (INT_EQUAL/NOTEQUAL + BOOL_NEGATE
peel) + propagateConstant (direct dominated-read replace + pushConstant const-fold + MULTIEQUAL
phiNodeEdges) + full phi machinery (collectReachable/flowToAlternatePath/flowTogether/handlePhiNodes/
placeCopy/placeMultipleConstants/testAlternatePath) + FlowBlock::restrictedByConditional (block.cc:405)
+ findCommonBlock (block.cc:796). 8 unit tests (direct-replace, pushConstant 7+9=>0x10, findConstCompare
forms, restrictedByConditional, findCommonBlock, phi propagate/decline=condconst_conn, testAltPath).
coverage.md MISSING->HELD. Suite 344/0.
KEY port decisions (all verified against Ghidra):
- getOutRevIndex = target.in_edges.position(condblock) — consistent with mosura MULTIEQUAL input
  ordering (heritage.rs:1177: phi slot i == in_edges[i]).
- eval_const (rules.rs:32 = executeSimple) returning None SUBSUMES Ghidra's `special` eval-type guard
  (verified: none of the ops eval_const folds are `special` in typeop.cc — LOAD/STORE/CALL/BRANCH/
  MULTIEQUAL/INDIRECT/CAST/SEGMENTOP/CPOOLREF/NEW). The isFloatingPointOp guard is kept EXPLICIT
  because eval_const DOES fold float ops that Ghidra deliberately skips.
- boolean_flip is UNSET at this pipeline point (mosura sets it only at the end via ActionOrientBranches;
  Ghidra's ActionNormalizeBranches is likewise after the fullloop) => flipEdge=false, correct.

## Commit B `654f4f5` — the wire (LANDED). pipeline.rs universal_action():
`.then(super::determinedbranch::ActionDeterminedBranch)` immediately followed by
`.then(super::condconst::ActionConditionalConst)` (before the sweep2 NonzeroMask/Consume/pool/deadcode).
Mirrors Ghidra mainloop determinedbranch->condconst(last)->loop-reruns-oppool1; mosura's sweep2/sweep3
fold the substitutions.
GATE MEASUREMENT (baseline b3163dc avg 0.8882 -> wired 0.8893): ONLY 2 fixtures move, both +, no regress,
nothing newly <0.70: **condconst 0.814->0.862 (+0.048)**, **elseif 0.899->0.915 (+0.016)**. Suite 344/0.
The 3 condconst1 propagations land BYTE-EXACT vs Ghidra (`*p=param_3`, `p[2]=10`, `p[4]=0x10`).
Residual condconst gap to 1.0 = stray `int4* pVar1` return vs Ghidra `void` = P6 return/prototype (task #6),
INDEPENDENT of condconst. On lead go: keep the wire + flip coverage.md HELD->PORTED + commit.

## Instrument facts (for reference)
- Corpus scores ONLY condconst1 (first function; oracle `--c` + mosura both decompile first bytechunk).
  condconst_copy/condconst_conn are Ghidra's own stringmatch assertions (guide faithfulness, not score).
- trace-diff.sh condconst: condconst fires 1x Ghidra / 0x mosura (pre-port).
See [[direction-faithful-port]], [[port-all-faithful-rules]], [[gate-byte-identical-only]].
