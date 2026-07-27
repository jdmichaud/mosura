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

## Open

| # | quantity | where | Ghidra source / slot | reachable by post-freeze Varnodes? | can it override a frozen flag? |
| --- | --- | --- | --- | --- | --- |
| 6 | **Covers** | `printc.rs` `covers: all_covers(f)` | Cover belongs to `HighVariable`, built 5717-5727 — **before** the casts | **Yes** — `all_covers` walks every Varnode, so CAST outputs and the rewired op outputs are included, and liveness shifts when an op's output moves to a fresh unique | No flag to override, but it feeds #7 and `check_implied_cover` |
| 7 | **`nonprinting`** | `printc.rs` `copy_marker_nonprinting(f, high_of, high_members, covers)` | `ActionCopyMarker` / `Merge::markInternalCopies`, a pipeline action **before** `ActionNameVars` | **Yes** — computed from the post-cast graph *and* from #6's post-cast covers | It decides statement suppression, so a wrong answer both adds and drops statements |
| 8 | **names** | `printc.rs` `names`, `var_counter`, `name_of` | `ActionNameVars`, 5734 — **before** the casts | Partly — a CAST output is `setImplied` and unnamed, and the CAST produces the *original* Varnode which was already named, so the exposure is narrow | No |
| 9 | output token, CALLOTHER | `cast.rs` `output_token` `_` arm | `TypeOpCallother::getOutputLocal`, typeop.cc:865 — consults the **userop's own** table | n/a | Deliberately left: mosura does not model per-userop output types, so claiming `undefined` would assert an unported model |

**#6 and #7 are the substantive open entries**, and they are coupled — #7 consumes #6. Both are
reachable and perturbable *by construction*; neither has yet been shown to produce an actual
divergence, and I am not claiming one. The honest status is "structurally exposed, not yet
demonstrated" — the same status #1 had before `heapstring` demonstrated it, and #5 had before the
duplicated call demonstrated it.

#8 is real but narrow, for the reason in the table.

## How to use this

When a faithful port produces output Ghidra would not emit, check this list **before** hypothesizing
a mechanism. The failure signature is consistent: the port is correct, and a print-time
recomputation disagrees with a frozen decision because it is looking at the post-cast graph.

Cheapest probe: does the divergence involve a Varnode with index ≥ `Funcdata::classified_upto`, or an
op whose output `ActionSetCasts` rewired? If so, this class is the first suspect.
