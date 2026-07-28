# printc re-derivation audit — state Ghidra freezes in-pipeline

**Status: COMPLETE.** Four times a faithful port had been blocked by mosura **re-deriving at print
time** something Ghidra computes once in the pipeline and never revisits, each found by tripping over
it. This audit converted the rest into a list and then worked the list to the end: #1-#5 and #6+#7
moved to Ghidra's slot, #8 measured to have no effect, #9 declined for a stated reason. It is kept
as a record of the class and as the probe to reach for when the signature recurs — see *How to use
this* at the bottom.

## The organizing fact

Ghidra's tail (coreaction.cc:5717-5735):

```
5717  ActionAssignHigh        HighVariables assigned
5718  ActionMergeRequired
5719  ActionMarkExplicit      explicit/implied classification frozen
5720  ActionMarkImplied       "This must come BEFORE general merging"
5721  ActionMergeMultiEntry
5722  ActionMergeCopy
5723  ActionDominantCopy
      ActionMarkIndirectOnly
5726  ActionMergeAdjacent
5727  ActionMergeType         merging COMPLETE
      ActionHideShadow
      ActionCopyMarker        opMarkNonPrinting frozen
      ActionOutputPrototype / ActionInputPrototype / ActionMapGlobals
5734  ActionNameVars          names frozen
5735  ActionSetCasts          <-- the ONLY later action, and it CREATES Varnodes
      ActionFinalStructure
```

**Everything the printer consumes is fixed at or before 5734. `ActionSetCasts` is the only thing that
runs afterwards, and it adds Varnodes and rewires op outputs.** So any quantity mosura recomputes at
print time is computed over a graph Ghidra never analyzed — one containing CAST ops and Varnodes that
did not exist when the corresponding Ghidra pass ran.

That is the whole class. Every instance below is a special case of it.

## Closed

| # | quantity | Ghidra source / slot | how it was closed |
| --- | --- | --- | --- |
| 1 | HighVariables (the merge) | `Merge`, 5717-5727 | `e66d54b` — frozen by `ActionMergeType` at the slot; printc consumes, `.expect()`s, no recompute path left |
| 2 | per-Varnode data-types | `ActionInferTypes::writeBack`, coreaction.cc:5043 (mainloop) | `95144f3` per-Varnode commit + `990b40e` separate high-facing channel |
| 3 | output token, SUBPIECE/PIECE | `TypeOpSubpiece`/`TypeOpPiece::getOutputToken`, typeop.cc:2142/2063 | `844d5b1` |
| 4 | explicit/implied, trailing chain | `ActionMarkImplied`, 5720 | `2c32c36` — frozen, read from the flag |
| 5 | explicit/implied, leading chain, for post-freeze Varnodes | `ActionMarkExplicit`, 5719 | `bf813d4` — `classified_upto` early exit; also closed a latent out-of-bounds at `slot_write[v.0]` |
| 6+7 | **`nonprinting`** and the **Covers** it consumes | `ActionCopyMarker` / `Merge::markInternalCopies` (merge.cc:1444), 5729; Cover belongs to `HighVariable`, built 5717-5727 | `8c9c6bb` — `merge::ActionCopyMarker` at the slot, **and DEMONSTRATED**, see below |
| 8 | **names** | `ActionNameVars`, 5734 | **no defect** — measured nil, see below |
| 9 | output token, CALLOTHER | `TypeOpCallother::getOutputLocal`, typeop.cc:865 | **deliberate non-port**, see below |

**The audit is complete.** Every quantity printc re-derived has been either moved to Ghidra's slot
(#1-#5, #6+#7), measured to have no effect (#8), or declined for a stated reason (#9). Nothing here
is abandoned or pending.

## #6+#7: demonstrated, then closed

They were one item, not two: `covers` had exactly one consumer in printc, the copy-marker pass. Moving
that pass to Ghidra's slot **changed real output**, so this class is no longer "structurally exposed,
not yet demonstrated" — it is demonstrated, with a named mechanism.

WAR2 `FUN_000722c8`, the only one of 1286 functions to move (corpus stayed byte-identical). Before:

```c
  pRam00000000000a8014 = (int4 *)pVar4;
  pRam00000000000a8014 = pVar4;          // <- dropped
```

The mechanism, read off the IR rather than argued:

- Pre-cast the function has two COPYs from the same source `u0x17200` into the `r0xa8014`
  HighVariable — `op59 @722f6` and `op101 @722fb`. Two copy-ins ⇒ `markRedundantCopies`
  (merge.cc:1252) ⇒ `op101`, dominated by `op59` with no intervening write, is marked non-printing.
- `ActionSetCasts::castOutput` (coreaction.cc:2532) then **rewires `op59`**: it is given a fresh
  post-freeze unique to write (`VarnodeId(271)`, its own singleton HighVariable) and a new
  `CAST` takes over producing `r0xa8014`.
- Post-cast, `op59` is therefore no longer a COPY *into* that HighVariable. The high is left with one
  copy-in, never reaches `multiCopy`, and the redundant-copy pass never examines `op101` — so the
  print-time recompute lost the mark and emitted the duplicate assignment.

Note which op the cast rewired: not the marked one, the *dominating* one. Every arm of
`markInternalCopies` relates an output's HighVariable to its inputs', so rewiring any participant is
enough; the marked op's own Varnode index was below `classified_upto` and looked untouched.

Closed by moving the pass to `merge::ActionCopyMarker`, after `ActionMergeType` and before
`ActionSetCasts`, with printc consuming `Funcdata::nonprinting` via `.expect()` and no recompute path
left. Scans: 1286/1286 WAR2 functions emitted both sides, one file changed by one line, rendered
call-expression count identical everywhere (5224); corpus byte-identical over all 62 fixtures.

## #8: measured, and the exposure is nil

printc assigns names at print time (`names`, `var_counter`, `name_of`) where Ghidra freezes them at
`ActionNameVars` (5734), one slot before `ActionSetCasts`. The audit called the exposure "narrow";
it is in fact **zero**, measured on both halves.

**Structurally**, closed by construction rather than by luck. Across all 62 fixtures there are 38
Varnodes created after the classification froze, and **none of them is explicit** — so none can
reach naming. `ActionSetCasts` calls `setImplied()` on its outputs at creation (coreaction.cc:2594)
and `bf813d4`'s `classified_upto` early exit returns that flag verbatim.

**Observationally**, comparing mosura's declared locals against `oracle/capture --c` on all 60
oracle-backed fixtures: **33 identical**, 8 differing in variable *count* (a merge/structure
difference, not naming), 19 differing in *type prefix*, and — the discriminator — **0 differing in
numbering**. Numbering is exactly what a naming pass run over a different graph would scramble, so
its total absence rules out the slot as a cause.

The 19 prefix differences are two *other* mechanisms, both filed as their own work rather than as
audit residue:

* the prefix follows the inferred data-type (`uVar1`/`axVar1`, `iStack_c`/`xStack_c`,
  `pStack_10`/`pxStack_10`) — the type-inference axis;
* symbol-kind recognition — Ghidra produces `in_FS_OFFSET` (partialsplit, piecestruct, switchhide),
  `in_stack_00000008` (longdouble), `xRam000000000030101c` (partialunion) where mosura makes an
  ordinary local. That is `linkSymbols`/`lookForFuncParamNames` (coreaction.cc:2930/2858), adjacent
  to `ActionNameVars` but a different mechanism.

## #9: a deliberate non-port

`TypeOpCallother::getOutputLocal` (typeop.cc:865) consults the **userop's own** output table. mosura
does not model per-userop output types, so emitting `undefined` here would assert a model that has
not been ported. Declined on that basis, not deferred — it becomes portable if and when the userop
output model lands.

## How to use this

When a faithful port produces output Ghidra would not emit, check this list **before** hypothesizing
a mechanism. The failure signature is consistent: the port is correct, and a print-time
recomputation disagrees with a frozen decision because it is looking at the post-cast graph.

Cheapest probe: does the divergence involve a Varnode with index ≥ `Funcdata::classified_upto`, or an
op whose output `ActionSetCasts` rewired? If so, this class is the first suspect. Widen "involve" to
the whole neighbourhood the quantity is computed from — #6+#7 was lost through a rewired op that the
marked op merely shared a HighVariable with.
