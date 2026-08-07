---
name: switchloop-dup-propagatecopy
description: "switchloop's duplicate-statement bug (iVar1=2; iVar1=2;) RE-DIAGNOSED @59cedd6 (pcopy1, premise-first): NOT propagatecopy — it's RuleSubvarZext (SubVariableFlow) OVER-firing (123x vs Ghidra 12x) on an 8-byte r0x8/RCX range that Ghidra keeps 4-byte via switchnorm + mainloop re-heritage. Faithful port doing its job on wrong upstream IR."
metadata:
  node_type: memory
  type: project
  originSessionId: 9beadf25-4682-4e85-94fa-f326d85ed777
---

## switchloop `iVar1 = 2; iVar1 = 2;` dup statements = SubVariableFlow over-fire on a wrong 8-byte r0x8 range (NOT propagatecopy)

RE-INSTRUMENTED premise-first @ HEAD `59cedd6` (pcopy1, 2026-07-11). The prior framing (base c73a074: "propagatecopy collapsing degenerate wide phis") is FALSIFIED on HEAD — this is the 5th lead-authored task premise instrument-first has re-framed (see [[faithful-type-of-wrong-ir]], [[numbers-stale-unless-sha-stamped]]). ALL probes read-only; tree left clean. Mover-class task, gated + reported, WAITING on lead.

**Bisected mechanism (dump --ir at pipeline stages + MOSURA_TRACE + trace-diff.sh + diagnostic subvar-off toggle):**
- Raw lift: r0x8 (RCX) written 8-byte by `mov ecx,N` (`RCX=#0x1`, SLEIGH zext idiom — IDENTICAL in Ghidra raw), 4-byte by computed cases, read 8-byte by the switch-index LEA `INT_ADD RCX:8 + -1`, read 4-byte by the cmp/switch (ECX). Dual-width, same as Ghidra.
- After heritage (pre-pool): mosura forms r0x8 as an **8-byte range** (because the LEA reads r0x8:8). Every def SINGLE: `r0x8:8=COPY #N:8`, `r0x8:8=PIECE(SUBPIECE(r0x8:8,4),val)` (normalizeWriteSize), single 8-byte phis, reads = `SUBPIECE(r0x8:8,0):4`. NO dup yet.
- After default_rule_pool: r0x8 narrowed 8→4 and **EVERY def DUPLICATED** into two parallel 4-byte SSA chains (two distinct ops/vns per site, each ndesc≥1 — genuine parallel chains, not one op printed twice). COPYs `r0x8:4=COPY #N:4` ×2, phis `r0x8:4=MULTIEQUAL` ×2, at loop-header 0x100027 AND switch-merges 0x100063/81/c4.
- Duplicator CONFIRMED by toggle: commenting the 5 RuleSubvar* rules → dup count 0 (but introduces other artifacts — subvar does real work; disabling is the diagnostic, NOT the fix). propagatecopy only folds constants onto the ALREADY-duplicated COPYs (two `r0x8:4=COPY` exist before it touches them). mosura's RuleSubvarZext is a FAITHFUL port of Ghidra's (subflow.cc, identical structure) — the over-fire is the faithful rule working on wrong IR.

**ROOT (per [[faithful-type-of-wrong-ir]]):** the dup is the faithful type of WRONG upstream IR = r0x8 being an 8-byte range. Ghidra keeps RCX→ECX 4-byte, so SubVariableFlow barely fires (12x vs mosura 123x) and never duplicates. trace-diff @59cedd6: Ghidra fires (mosura NEVER) **switchnorm 2x, pullsub_multi 1x, pullsub_indirect, push_multi 2x, heritage 2x, returnrecovery/start/prototypetypes/constbase each 2x** ⇒ Ghidra's MAINLOOP ITERATED TWICE: ActionSwitchNorm normalizes the jumptable (absorbs the 8-byte LEA index; this is ALSO the `switch(iVar1-1)` cases 0..8 vs Ghidra `switch(ECX)` cases 1..9 off-by-one) → re-heritage narrows RCX→ECX 4-byte → clean. mosura runs once, keeps the 8-byte LEA, pool laboriously narrows 8→4 via SubVariableFlow which over-fires + duplicates.

**LANDED (191d3fa, pcopy1):** the pullsub cluster (RulePullsubMulti/PullsubIndirect/PushMulti, coreaction.cc:5516-18, missing faithful rules) landed as the PARTIAL mitigation — switchloop +0.019 (accumulator narrows), floatcast −0.054 (faithful-exposes-gap #21/#22), suite 403/0, corpus 0.9213/56. The selector dups SURVIVE (loop-header phi, hasLoopIn guard) — the COMPLETE fix is the 8-byte-r0x8 root = **task #23** (ActionSwitchNorm + mainloop-reheritage).

**VERDICT: DEEPER than bounded; task premise wrong on two counts** — (1) NOT propagatecopy (it's subvar_zext over-fire), (2) NOT mainloop-independent (Ghidra's clean 4-byte r0x8 is intrinsically mainloop-repeat: switchnorm + 2nd-pass re-heritage). Candidate faithful fixes: [primary] fold into the switchnorm/jumptable + mainloop-reheritage cluster ([[task8-mainloop-repeat]], [[task8-jumpbasic-port-plan]]); [bounded-but-partial] port the missing faithful RulePullsubMulti/RulePullsubIndirect (coreaction.cc:5516-17, "analysis" pool) + RulePushMulti (:5518, "nodejoin") — but RulePullsubMulti guards `hasLoopIn()==0` so it will NOT narrow switchloop's loop-header phi 0x100027, only the switch-merges → partial. Do NOT patch SubVariableFlow to dedup (= adaptation hiding wrong IR, forbidden). Repro: `cargo run -q --example dump -- switchloop --ir`; `scripts/trace-diff.sh switchloop`.
