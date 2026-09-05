---
name: task24-trycallpull-plan
description: "Task #24 (SubZext@74 induction-phi payback) GROUNDED to a definitive root + bounded faithful fix: port Ghidra SubvariableFlow::tryCallPull (subflow.cc:208) + the traceForward CALL/CALLIND arm. The forloop_varused/noforloop_iterused dip from landing RuleSubZext (4fa456c)."
metadata: 
  node_type: memory
  type: project
  originSessionId: 9beadf25-4682-4e85-94fa-f326d85ed777
---

# Task #24 — loop-induction-phi narrowing = port `tryCallPull` (SubvariableFlow Stage-4 CALL pull)

Follows RuleSubZext landing (`4fa456c`; see [[task9-stage3-blocker]] Session-17). Landing SubZext dipped
forloop_varused 1.000→0.914 and noforloop_iterused 0.754→0.732 — both the SAME loop-induction 8-byte-phi
render (`uVar1=(uint4)uVar2; for(uVar2=0; (int4)uVar1<n; uVar2=uVar1+1)`). Ghidra ships these clean.

## ROOT CAUSE — definitively instrumented (session subvar1, base 4fa456c, read-only, tree clean)
NOT consume, NOT nzmask, NOT andmask (my andmask-preemption candidate was FALSIFIED by instrumentation).
- `RuleSubvarSubpiece` (rules.rs:4460) DOES seed on the phi's `SUBPIECE r0x18:8 #0 @0x400585`. Instrumented
  the seed guard: consume=0xffffffff, nzm=0xffffffff, mask=0xffffffff, consume_ok=true, descend non-empty →
  the guard `(consume & mask) != consume` PASSES. So the seed is fine.
- The seed's `do_trace()` returns false. Instrumented the abort (temp prints in process_next_work, reverted):
  **`trace_forward` returns false on the loop phi (VarnodeId 450) 16×.** The induction phi is passed to a
  call (`CALL r0x400440 ... r0x18:8` @0x40057d), and mosura's `SubvariableFlow::trace_forward` CALL/CALLIND
  arm is a **Stage-4 stub** — subvarflow.rs:905 `_ => return false`. Forward trace hits the CALL → aborts the
  whole transform → the phi never narrows → stays 8-byte.
- Ghidra `traceForward` (subflow.cc:616-623) handles CALL via `tryCallPull` (subflow.cc:208): emits a
  `parameter_patch` narrowing the call arg in place. That's why Ghidra passes the induction NARROW
  (`func(...,uVar1)` uint4) and mosura WIDE (`func(...,uVar2)` uint8); Ghidra's subvar_subpiece @0x400585
  narrows the phi, mosura's can't.

## FAITHFUL FIX (bounded, ~30 lines) — port `tryCallPull` + the traceForward CALL arm
1. **`try_call_pull(op, rvn, slot) -> bool`** (subflow.cc:208):
   - `slot == 0 → false` (target operand, not a param).
   - non-aggressive: `(vn.get_consume() & !mask) != 0 → false`.
   - Ghidra `getCallSpecs(op) == null → false`. mosura: CALLOTHER = `isCallWithoutSpec` has no spec; a plain
     CALL/CALLIND has one. (mosura has no explicit FuncCallSpecs object — model "has a spec" as `code ==
     CALL || CALLIND`; confirm no CALLOTHER reaches here.)
   - `isInputActive() → false`. mosura = `self.fd.active_inputs.contains_key(&op)` (funcdata.rs:63,
     ParamActive per CALL). This is the KEY timing gate: it refuses while param recovery is mid-flight, then
     allows in a LATER mainloop pass after commit (Session-14's requirement; the iterating mainloop 25cb50b
     provides the later pass).
   - `isInputLocked() && !isDotdotdot() → false`: mosura has no input-lock → skip.
   - else emit the Parameter patch + `pullcount += 1`. **REUSE `add_terminal_patch_same_op(op, rvn, slot)`
     (subvarflow.rs:527)** — it already pushes `PatchType::Parameter{patch_op, in1:rvn, slot}` + pullcount++;
     do_replacement materializes it at subvarflow.rs:1208 (`op_set_input(pullop, slot, v)`). Materialization
     side is ALREADY DONE (Stage-1).
2. **traceForward CALL/CALLIND arm** (subflow.cc:614-623), replace the `_ => return false` at subvarflow.rs:905:
   `OpCode::Call | OpCode::Callind => { callcount += 1; let slot = if callcount>1 { get_repeat_slot(op, vn, slot, iter) } else { slot }; if !self.try_call_pull(op, rvn, slot) { return false; } hcount += 1; }`
   - Need a `callcount` local in trace_forward (alongside dcount/hcount).
   - Port a faithful `getRepeatSlot` (op.cc) — next input slot > current holding the same varnode (a value
     passed as 2+ args to ONE call). Rare on the corpus but faithfulness requires it.

## ✅ LANDED `d3637fa` (lead GO, 2026-07-11) — task #24 DONE
Ported try_call_pull + get_repeat_slot + traceForward CALL/CALLIND arm + 3 unit tests
(call-pull narrows arg / refuses active_inputs / refuses slot-0) + coverage.md. Suite 406/0,
switch 6/6, corpus 0.9197→0.9222 (+0.0025, 56/60), 5 up / 0 down, forloop_varused byte-identical
to Ghidra. The SubZext(#18)+tryCallPull(#24) arc: 0.9213→0.9222 (+0.0009 above pre-SubZext) —
land-then-payback vindicated. REMAINING Stage-4 (separate follow-up, NOT warm off this): RuleSubvarSext
(trace_forward_sext/trace_backward_sext stubs, subflow.cc:867+, needs sextrestrictions +
aggressive_ext_trim + isPersist/isTypeLock) + RulePtrFlow (needs Varnode::isPtrFlow aggressive flag).

## BUILT + MEASURED (superseded by LANDED above)
Ported `try_call_pull` + `get_repeat_slot` + the traceForward CALL/CALLIND arm into subvarflow.rs
(+75/-5, builds clean, suite 403/0). Reused `add_terminal_patch_same_op` for the Parameter patch.
**PURE NET-POSITIVE — 5 UP, 0 DOWN vs 4fa456c (avg 0.9197→0.9222, +0.0025, 56/60, switch 6/6):**
forloop_varused 0.914→**1.000** (+0.086, byte-identical to Ghidra), noforloop_iterused 0.732→0.767
(+0.035), noforloop_alias 0.988→**1.000** (+0.012), elseif 0.904→0.915 (+0.011), loopcomment
0.742→0.751 (+0.009). vs pre-SubZext 0.9213 = +0.0009 ABOVE. Only residual dip in the whole arc =
modulo −0.003 (from SubZext, NOT tryCallPull — separate diagnostic). On go: add subvarflow unit test
(call-pull narrows arg / refuses active_inputs / refuses slot-0) + coverage.md, commit (Fable 5 trailer).

## GATE / MEASURE
Faithful Stage-4 port → LANDS per [[faithful-ports-land-not-held]]. It is a MOVER (tryCallPull fires on ANY
narrow value passed to a call, not just loop inductions → corpus reach broader than the 2 forloop fixtures;
should recover forloop_varused/noforloop_iterused, may move others) → report per-fixture delta @sha + WAIT,
do NOT self-approve. Suite green + switch 6/6 each commit; coverage.md in-commit; NEVER git add -A; Fable 5
trailer. Reported grounding to lead; awaiting go-to-build.

## GOTCHAS
- `git diff` external difftool (icdiff) missing → use `--no-ext-diff`.
- dumpc `cargo run -q --example dumpc -- <stem>`; IR `dump -- <stem> --ir`; trace `--debug opaction ... --example
  trace -- <stem>`; oracle `oracle/capture <ghidra> <fixture.xml> --c/--ir -`; `scripts/trace-diff.sh <stem>`
  (KEEP=1 keeps raw traces).
