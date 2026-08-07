---
name: war2-remediation-campaign
description: "WAR2 remediation campaign (decompiler agent, task board #1-#3) COMPLETE: Stage 1 __watcall + Stage 2 printc LANDED; Stage 3 closed-faithful (no build). SHAs + why-not-Stage-3."
metadata: 
  node_type: memory
  type: project
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-23T21:31:33.523Z
---

**WAR2 recompilation-parity remediation (decompiler agent, master).** Three-stage campaign off
docs/war2-function-status.md; re-measure protocol = EMIT (`examples/war2_survey.rs`) + `war2-survey/
compile.sh` (dosemu2 wcc386) + `compare.py`. Ran re-measures in isolated dirs `war2-survey-v2`
(Stage 1) / `war2-survey-v3` (Stage 2) to avoid clobbering the survey agent's `war2-survey/`.

- **Stage 1 ✅ LANDED** `e097ea8` (code) + `8544a8b` (doc). Threaded `(Program.language_id,
  compiler_spec_id)` into `raw_funcdata_flow_image_overrides` → analysis path resolves the `__watcall`
  cspec. **void_proto 1169→247** (922 funcs gained params), **extraout 626→93**. Corpus byte-identical.
- **Stage 2 ✅ LANDED (bounded scope)** `b4ac8f4` (code) + `ad50898` (doc). printc renders CALLOTHER→
  userop name (in/cpuid/rdtsc/swi), INT_SBORROW→SBORROW<n>, POPCOUNT→POPCOUNT; threaded `.sla` userop
  table onto Funcdata. **COMPILE_FAIL 229→137** (E1063 113→4, zero regressions). Corpus byte-identical.
  Write-up docs/decompiler-bug-callother-ellipsis-leak.md. **Type-error tail (137 remaining CF) = deep
  C-cluster type-inference foundation (task board #4)** — NOT bounded printc; per faithful-type-of-wrong-ir.
- **Stage 3 ✅ CLOSED-FAITHFUL — NO BUILD** (lead-verified `f23b362` on master; doc
  docs/decompiler-nonbug-bare-call-return-faithful.md). Task #3 (capture the bare call-result return,
  first as an isolated activeoutput lifecycle, then re-scoped to cross-function prototype propagation)
  was DISPROVEN twice by instrument-first, before any non-faithful code: (1) oracle/capture --c showed
  mosura is BYTE-IDENTICAL to the ISOLATED oracle (bare-return both drop, used-result both capture);
  (2) the lead BUILT analyzeHeadless (full Ghidra 12.0.3, at /data/tools/ghidra_12.0.3_PUBLIC/build/
  dist/.../support/) and confirmed **FULL-analysis Ghidra ALSO drops the minimal bare-call-result
  return** (`void FUN(void){ FUN_00100010(); return; }`) — the callee recovers non-void but
  `ancestorOpUse` rejects the CALL in full-analysis too (funcdata_varnode.cc:70-72 == mosura
  recover.rs:473). So capturing it would BEAT Ghidra = non-faithful, REJECTED. Tail-call `jmp B` →
  Ghidra makes the caller a THUNK (the survey's 3 thunk cases, separate). **The prior d51 menu-E
  grounding — that Ghidra captures via a persistent isolated activeoutput lifecycle — was WRONG
  (it misread full-analysis output); corrected.** Branch `stage3-trial-lifecycle` @ `7600b6e`
  (`Funcdata::call_output_locks` + `recover_call_output_locks` = faithful funcLinkOutput isOutputLocked
  port, byte-neutral but INERT) stays UNMERGED as the documented dead-end (d51 don't-land-inert-
  scaffolding). Residual extraout_ (93) = scoped per-case analyzeHeadless diff (killedbycall-faithful
  vs divergence), a separate future investigation — NOT this campaign.

**🏁 CAMPAIGN COMPLETE (2026-07-23):** Stage 0 panic ✅ + Stage 1 __watcall ✅ (void_proto 1169→247) +
Stage 2 printc ✅ (COMPILE_FAIL 229→137) + Stage 3 closed-faithful ✅ (no build). Remaining WAR2 gap =
codegen/regalloc (dominant MISMATCH) + C-cluster type foundation (task #4) + scoped extraout_ diff —
all DEEP/user-investment, out of the 3-stage scope. See also [[war2-recompile-survey]] (lead's index).

Related: [[decompiler-misport-backlog]] (D5 return-capture), [[war2-issues-become-source-tests]],
[[bounded-levers-exhausted]] (C-cluster = deep foundation).
