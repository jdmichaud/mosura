---
name: empty-bodies-take-the-permissive-branch
description: "An empty function body does not make a ported Ghidra body query merely imprecise — it makes it return the OPPOSITE answer, silently taking the permissive branch"
metadata:
  node_type: memory
  type: project
---

**mosura computes function bodies once, after the worklist converges; Ghidra maintains them
incrementally, so in Ghidra a body is ALWAYS current.** Every ported `getFunctionContaining`,
`getFunctionsOverlapping`, or "subtract the bodies from this set" therefore runs against EMPTY
bodies during analysis. The trap is that this does not degrade gracefully.

**The class: an empty body silently selects the permissive branch, so the guard reads as GREEN
and its result looks like a feature.** Two instances measured on 2026-08-07 (task #7, `83fc4c6`):

1. `AddressTable.checkForCollisionAtTarget` (AddressTable.java:1339) is `if (func != null &&
   offcut) { ...decide... } return false;`. With empty bodies `getFunctionContaining` answered
   `None`, the whole decision was skipped, and it fell through to `return false` = "no collision".
   `AddressTableAnalyzer` then built a pointer table over `compgoto.gcc-x86-64`'s computed-goto
   label array and made 4 DATA references. Those 4 refs looked like recovered data — they were the
   artifact of a question never asked. With bodies current Ghidra's real branch runs: the labels
   are offcut inside the function, every ref to them is a `COMPUTED_JUMP`, the loop (:1358) exits
   without returning, and it reports a COLLISION and refuses the table.
2. `ConstantPropagationAnalyzer.findLocationsRemoveFunctionBodies` (:264-268) SUBTRACTS each
   overlapping body. With empty bodies the subtraction removed only the entry-point ADDRESS, so
   the extent stayed ONE range whose minimum was `entry + 1` — an OFFCUT address inside the first
   instruction — and pass 3 (:296-303) started constant propagation there, over a garbage decode.

**Why:** the fix for both is the same call (`refresh_function_bodies`), and its absence is not a
missing refinement — it is a wrong answer that presents as extra output. Note the direction: fixing
it made the corpus reference count go DOWN (1290 -> 1288). A body-query fix can legitimately REMOVE
results, so do not read a decrease as a regression here; see [[absolute-vs-differential-wrongcode]]
and [[gauge-counting-traps]].

**How to apply:** when porting anything that asks a body question, call `refresh_function_bodies`
first, and before believing any guard that "already passes", check whether it passes because the
body was empty. The pre-flight is [[could-it-have-come-out-otherwise]]: `func != null` whose answer
is fixed at `false` is not a guard.

**The paired vacuity trap, same task.** A unit test that calls `analyzer.added(&mut p, &set, ..)`
DIRECTLY cannot gate the analyzer's CHANNEL — `analysis_type()` never runs on that path, so
flipping `Instruction` back to `Function` leaves it GREEN. The channel is only gateable through a
real analysis run (`ground_truth_parity`). One test named itself "THE CHANNEL GATE" and actually
gated the body refresh. Revert-check each half against the specific thing it claims to name, not
against "the fix". See [[command-queue-modelled-as-change-channel]] for the sibling channel defect.
