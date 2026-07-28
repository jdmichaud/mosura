# printc re-derivation audit — state Ghidra freezes in-pipeline

Read-only audit. Four times now a faithful port has been blocked by mosura **re-deriving at print
time** something Ghidra computes once in the pipeline and never revisits. Each was found by tripping
over it. This converts the rest into a list.

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
| 6+7 | **`nonprinting`** and the **Covers** it consumes | `ActionCopyMarker` / `Merge::markInternalCopies` (merge.cc:1444), 5729; Cover belongs to `HighVariable`, built 5717-5727 | `merge::ActionCopyMarker` at the slot — **and DEMONSTRATED**, see below |

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

## Open

| # | quantity | where | Ghidra source / slot | reachable by post-freeze Varnodes? | can it override a frozen flag? |
| --- | --- | --- | --- | --- | --- |
| 8 | **names** | `printc.rs` `names`, `var_counter`, `name_of` | `ActionNameVars`, 5734 — **before** the casts | Partly — a CAST output is `setImplied` and unnamed, and the CAST produces the *original* Varnode which was already named, so the exposure is narrow | No |
| 9 | output token, CALLOTHER | `cast.rs` `output_token` `_` arm | `TypeOpCallother::getOutputLocal`, typeop.cc:865 — consults the **userop's own** table | n/a | Deliberately left: mosura does not model per-userop output types, so claiming `undefined` would assert an unported model |

#8 is real but narrow, for the reason in the table.

## How to use this

When a faithful port produces output Ghidra would not emit, check this list **before** hypothesizing
a mechanism. The failure signature is consistent: the port is correct, and a print-time
recomputation disagrees with a frozen decision because it is looking at the post-cast graph.

Cheapest probe: does the divergence involve a Varnode with index ≥ `Funcdata::classified_upto`, or an
op whose output `ActionSetCasts` rewired? If so, this class is the first suspect. Widen "involve" to
the whole neighbourhood the quantity is computed from — #6+#7 was lost through a rewired op that the
marked op merely shared a HighVariable with.
