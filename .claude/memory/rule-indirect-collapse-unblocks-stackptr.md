---
name: rule-indirect-collapse-unblocks-stackptr
description: "2026-07-29: the stack-pointer fix's 25 panics were NOT an indirect_source problem — mosura lacked RuleIndirectCollapse (ruleaction.cc:3157) entirely. Porting it: panics 25→0, stale guard links 19444→0. indirect_source alone is provably INERT."
metadata: 
  node_type: memory
  type: project
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-29T07:42:24.574Z
---

# The stack-pointer fix's blocker was a missing RULE, not a missing flag

Board task #1 was framed as "port `PcodeOp::indirect_source` and make dead-code refuse to destroy a
flagged op". **Both halves of that framing were wrong**, settled from Ghidra source plus in-pipeline
instrumentation (never by elimination).

## What Ghidra actually does
- `indirect_source` (op.hh:85) is **transient, with no production writers**. Ghidra clears it on every
  alive op at the top of each `ActionDeadCode::apply` (coreaction.cc:3965) and re-derives it in the
  same pass's consume propagation (coreaction.cc:3656/3661). Those two lines are the **only** setters
  in the tree — `heritage.cc`/`newIndirectOp`/`double.cc` never touch it. So the "set-and-never-clear
  keeps dead ops alive" worry cannot arise from a faithful port.
- **`ActionDeadCode` never reads the flag.** Its destroy loop (coreaction.cc:4038-4044) has no
  `isIndirectSource()` check. The only readers are `RuleEarlyRemoval` (ruleaction.cc:31) and
  `opDestroyRecursive` (funcdata_op.cc:242, no mosura counterpart). What keeps a guarded COPY alive is
  the `pushConsumed(~0, indop->getOut(), …)` in the INDIRECT consume case — and **only when the COPY's
  output OVERLAPS the INDIRECT's output**.

## The measurement that redirected the work
Porting `indirect_source` faithfully (all 5 sites) was **completely inert on the subject**: panics 25→25,
stale links 19444→19444, surviving-op count identical to the digit. Landed anyway at `914e087`
(faithful, corpus byte-identical) — but it fixes nothing on its own.

In-pipeline instrumentation showed every stranded case is a `Copy` guarded op with
`characterizeOverlap == 0`: `recover_stack`'s push→COPY-into-`stack:fffffffc:4`, guarded by
`guardStores` INDIRECTs over `ram` globals. Different spaces ⇒ no overlap ⇒ **Ghidra deliberately does
nothing there**.

## The real gap
mosura lacked **`RuleIndirectCollapse`** (ruleaction.cc:3157, Ghidra's `actprop` pool slot 40 at
coreaction.cc:5551) entirely. Overlap==0 falls through its COPY branch to
`totalReplace(out, in(0)); opDestroy(op)` — the STORE became a COPY to unrelated storage, so the
INDIRECT is pointless. It also collapses when the `iop` is already dead (`if (!indop->isDead())` is
simply skipped), so it repairs stranding **regardless of pass ordering**.

Result: **panics 25→0** (the subject 1286/1286), **stale guard links 19444→0** (731 fns→0), ops surviving
dead-code 104668→88160 (−15.8%, i.e. MORE dead code removed — the clear-side risk inverted).

## Gotchas worth keeping
- Two of its arms are inert **by construction, not by adaptation**: `nolocalalias` has no producer in
  mosura (Ghidra sets it at varmap.cc:1375, `ScopeLocal`), and `spacebase_ptr` is never set because
  the LoadGuard/`discoverIndexedStackPointers` subsystem is an already-documented omission
  (heritage.rs:1392, varmap.rs:447). With those unset, Ghidra's own code takes `else return 0`.
- **The missing `nolocalalias` producer is now quantified**: Ghidra's FINAL IR has **0 INDIRECTs** on
  `pointerrel`/`stackstring` where mosura has 26/56. That is the prime suspect for the statement-order
  drift that made those two fixtures dip (0.9542→0.9535, pure reordering, no content change) — the
  next brick if that dip needs closing.
- Post-hoc probing of destroyed ops is a trap: `op_destroy` clears the output, so an overlap computed
  after the fact reads as "no output". Measure inside the pipeline.

Related: (subject-profile note `band-root-cause`), (subject-profile note `byte-exact-campaign`), [[faithful-type-of-wrong-ir]],
[[gate-byte-identical-only]], [[numbers-stale-unless-sha-stamped]].
