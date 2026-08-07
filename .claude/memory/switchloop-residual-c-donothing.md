---
name: switchloop-residual-c-donothing
description: "✅ LANDED `78de54a` (2026-07-17, lead GO): switchloop residual C closed — trace-proven donothing→mergerequired→dominantcopy chain; ActionDoNothing+checkImpliedCover+isMoveable+finalTransform-gates+per-high naming; 0.9379→0.9408/57, switchloop→0.877, 4 wrong-code classes closed, near_switch retired. Follow-ons: mergeOp blind-trim, DominantCopy/CopyMarker, RedundBranch, mergeIndirect."
metadata:
  node_type: memory
  type: project
  originSessionId: 9beadf25-4682-4e85-94fa-f326d85ed777
---

# switchloop residual C — re-grounding + build (swc1, 2026-07-17, base `fdcfa50`)

## Re-grounding verdict (trace-proven, capture_trace + probe)
Old classification CORRECTED. The three components on HEAD:
1. **accumulator≠param_1** — NOT a merge failure: mosura's read-only merge already unions
   EDI(i)+both phis+all 10 case values into ONE high (probe: high 757). The C split it because
   `name_of` named per-VARNODE (param check on the instance) → `uVar2` read-uninitialized +
   `param_1` unused = silent wrong-code. Root = per-high naming + missing flattening.
2. **div-result cover conflict** — REAL, was emitting wrong code (`uVar2 = uVar2/10; if (uVar2 <
   0x96)` reads post-div). Ghidra resolves via mergeOp trims + the bool going EXPLICIT
   (checkImpliedCover), NOT only merge machinery.
3. **uint4-vs-int4** — DISSOLVED pre-session (both `int4 iVar` + `(int4)` div cast).

**The named mechanism chain (Ghidra trace DEBUG 552-561 on switchloop):** `push_multi`
(RulePushMulti, already ported) → **`donothing` ×3** = ActionDoNothing (coreaction.cc:3466, wired
:5683 fullloop tail) → removeDoNothingBlock (funcdata_block.cc:327) → blockRemoveInternal(:254,
preserve arm) → pushMultiequals (:84) — removes the marker-only join blocks (0x100063/0x100081/
0x1000c4) producing the single 13-input header phi → **`mergerequired`** (Merge::mergeOp,
merge.cc:719) BLIND-SEQUENTIAL trims slots 0..k until cover-clean (trimOpInput :692 — the late
per-case COPYs u0x10000085..a9, consecutive uniques at pred-block stops) → **`dominantcopy`**
(ActionDominantCopy) consolidates the redundant slot-10 copy. The case-4 `bVar1` =
ActionMarkImplied::checkImpliedCover (coreaction.cc:3376) via Merge::inflateTest, evaluated at the
required-merges-only high state (:5717-5720 ordering — MarkImplied BEFORE MergeCopy/Adjacent/Type).

## Built (all faithful) — ✅ LANDED `78de54a` (one commit, lead GO 2026-07-17; post-commit verify: suite 430/0, corpus 0.9408/57 @78de54a, jumptable 6/6, must-holds hold, tree clean)
- **determinedbranch.rs**: hasOnlyMarkers (block.cc:2580), isDoNothing (:2596), unblockedMulti
  (:2534), pushMultiequals (funcdata_block.cc:84), blockRemoveInternal preserve arm (:254) with
  removeFromFlow edge order (block.cc:1545), removeDoNothingBlock (:327), ActionDoNothing
  (coreaction.cc:3466) + 2 unit tests. Wired pipeline.rs fullloop tail (DeadCode→**DoNothing**→
  SwitchNorm, Ghidra :5682-5684).
- **printc.rs is_explicit**: checkImpliedCover arm (coreaction.cc:3376) w/ copyShadow +
  partialCopyShadow exemptions (the piece branch — needed because mosura's merge_addrtied is
  cross-size where Ghidra HighVariable instances are same-size); state = new merge.rs
  `merge_required_only`. mergesnip::partial_copy_shadow → pub(crate).
- **printc.rs is_moveable**: PcodeOp::isMoveable (op.cc:178) faithful.
- **printc.rs for_parts**: rewritten to BlockWhileDo::finalTransform gates (block.cc:3356): typed
  structured lastOp (block.hh:239 overrides — Switch/If have NONE = the decline that keeps
  switchloop a while), tail sizeOut==1→head, findLoopVariable tail-slot (:3164) + isMoveable,
  findInitializer sizeIn==2 (:3223).
- **printc.rs name_of**: per-HighVariable param naming (a high containing a param input instance
  IS that param — Ghidra names highs, not varnodes).
- **ADAPTATIONS RETIRED**: structure.rs `near_switch` (no Ghidra analogue; dead protection since
  #23 — was blocking ifswitch/guard orientation once donothing removed the empty guard block);
  for_parts' any-body-input iterator scan; printc basic_blocks_of (dead).

## Measured (landed numbers @78de54a)
avg **0.9379→0.9408**, 57/60. Movers: switchloop 0.851→**0.877**, noforloop_iterused
0.852→**1.000** (oracle-exact; baseline for-hoist was WRONG code — iRam=iVar1*100 read
pre-increment), loopcomment 0.788→0.790 (healed DROPPED `iStack_28 < 200` conjunct + uninit
`(uint1)iVar1`→param_3, both Ghidra-exact), elseif 0.918→0.915 (better form `!= 0x1d` if; dip =
gauge noise vs Ghidra's goto-based else-if, pre-existing P7 gap). Byte-changed score-neutral:
partialsplit (extraout_RDI→param_1 = Ghidra-exact), multiret (self-assign → materialized
snapshot; fixture oracle-unmappable). ALL must-holds byte-identical. Suite **430/0** (428+2 new),
jumptable 6/6, clippy 79==79, corpus runtime flat. **4 wrong-code classes closed** (case-4
read-after-write; split-name lost init; dropped conjunct; illegal iterate hoist).

## Residuals filed (switchloop 0.877 → ~Ghidra)
- Piece B: full Merge::mergeOp blind-sequential trim + forced-union semantics (merge.cc:719) —
  gives Ghidra's `iVar3 = 2; param_1 = param_1 + 2;` per-case statement order (the trim copies at
  block stops). mosura today trims only the genuinely-conflicting div slots (find_marker_trim).
- Piece C2: ActionDominantCopy/ActionCopyMarker (coreaction.cc:5723/5729) — dedups the second
  `param_1 = uVar2` in case 4.
- ActionRedundBranch (coreaction.cc:5658, mainloop deadcontrolflow) — fires 2x on switchloop in
  Ghidra, unported.
- mergeOp for INDIRECT (mergeIndirect) still the read-only model.
