---
name: direction-retire-inventions-first
description: "USER PIVOT 2026-07-29: pause the subject-driven work, retire ALL remaining non-Ghidra inventions as the primary track — the subject wasn't progressing fast enough BECAUSE of them. Finish the in-flight task first, then pivot."
metadata:
  type: project
---

**USER DIRECTION 2026-07-29 (verbatim intent): "we will pause our work on the subject then and switch back to retiring those inventions. the subject do not progress fast enough because of those so we need to focus on it."** Plus: **"We will not interrupt the task in progress, we will finish it and then pivot."**

⇒ **Finish task #2** (the spacebase-placeholder port completing Stage B — the last the subject-driven task), **then the invention-retirement track becomes PRIMARY** (task #4). the subject-specific work (COMPILE_FAIL ladder, emitter symbolization, per-function residuals) is **PARKED** (task #3).

## The evidence that makes this the right call, not just a preference
**Every the subject wall this month was an invention masking a gap:**
- `XMM0:8` masked the merged-cover gap (mixfloatint's dropped `float8` return).
- `RAX:8` masked narrow-switch recovery at **4 the subject dispatch sites** AND made **every x86-32 function render `void`**.
- `RDI..R9:8` masked piecestruct's narrow param AND **the entire missing stack-trial subsystem** (task #2's whole subject).
- The invented multi-exit heuristic **silently destroyed the subject switch bodies for the whole campaign while being corpus-inert.**

⇒ Retiring inventions systematically beats discovering them one specimen at a time. **Corpus-inertness is NOT evidence of harmlessness** — see [[adaptations-inventory]] for the re-verified ~15 remaining, each a latent trap.

## THE RETIREMENT PROTOCOL (mandatory per item)
1. Read the adaptation AND what it stands in for in Ghidra (file:line both sides).
2. **EXPECT AN APPARENT REGRESSION.** First hypothesis on any break: *this adaptation was crutching a missing faithful mechanism* — find and port THAT. **Never restore the adaptation; never invent a gate to make the path behave** (the `7b6d36c` failure mode).
3. **Trace-diff FIRST** on any behavioural difference (rules+actions, provenance-stamped).
4. Battery before landing: suite+clippy · absolute call gauge BLOCKING (no fn loses a call it emits) · strict-subset audit · empty-switch/empty-loop scan 0 · byte-stability of the byte-clean set · corpus per-fixture vs pinned baseline (wrong-code gates only; a faithful port otherwise LANDS).
5. **MEASURE the subject IMPACT PER RETIREMENT** (byte-clean · deficit · COMPILE_FAIL) so the invention-bottleneck thesis is tested quantitatively, item by item.
6. Subsystems land WHOLE — no deferred half is grandfathered (Stage B's own carve-out is the cautionary example).

## SEQUENCE (by the subject blast radius, not by ease)
**WAVE 1 — bounded, immediate the subject payoff:** **A3** `RSP=0x20` → cspec `<stackpointer>` (on x86:LE:32 ESP is 0x10 ⇒ stack recovery INERT, **0 of 1286 stack locals**; a written patch is already held, re-test it first since the heritage core may cure its 12-call regression) · **G1** the up-front alias CLONE-PROBE (Ghidra has none; `AliasChecker::gather` runs from `ScopeLocal::restructureVarnode` on the real guarded graph — Stage B had to flip its flag and the control proved it LOAD-BEARING ⇒ actively entangled; couples with A3) · **F1** `RuleEqual2Zero`'s missing all-descendants-bool guard (switchloop DEPENDS on the extra firing ⇒ textbook masked-absence).
**WAVE 2 — print-time → IR-time (B-cluster):** B2 stack naming/typing + spacebase `getSubType` stub (the subject-relevant, pairs with wave 1) · B1 `is_explicit` → ActionMarkExplicit/MarkImplied · B4 switch print heuristics → BlockSwitch · B3 print De Morgan → the MISSING ActionNormalizeBranches.
**WAVE 3 — the C-cluster foundation (unblocks four at once):** C1 persistent BlockGraph (gates C2 edge-reversal, D1 merge-in-the-loop, D3 orient/prefer) then C3 persistent HighVariable.
**WAVE 4 — remainder:** D2 addrtied-at-creation · F2 nzmask-not-width bool propagation · phi slot order by addInEdge order · minors · the hardcoded-x86-64 sweep remainder.

Related: [[goal-is-the-binary-not-ghidra]] (the goal is unchanged — this is a change of ROUTE) · [[port-all-faithful-rules]] · [[faithful-ports-land-not-held]] · [[finish-parked-before-new]] (which is why #2 finishes first).
