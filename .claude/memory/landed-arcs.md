---
name: landed-arcs
description: Index of CLOSED porting arcs — one line each, with the landing SHA and any deferred remainder. Moved out of MEMORY.md, which is for current work.
metadata:
  type: project
---

Moved out of MEMORY.md 2026-08-06: the index is for what is LIVE, and these are history whose
detail lives in the named topic files and in git. Consult when re-opening one of these areas.

- [task27-coarse-register-ssa-splituses](task27-coarse-register-ssa-splituses.md) — splitUses `0143097`.
- [task10-isbooleanflip-condnegate](task10-isbooleanflip-condnegate.md) — branch-negation in IR. Follow-up: global ActionNormalizeBranches.
- [task8-jumpbasic-port-plan](task8-jumpbasic-port-plan.md) — JumpBasic subsystem `a162673`.
- [task24-trycallpull-plan](task24-trycallpull-plan.md) — tryCallPull `d3637fa`; remaining: RuleSubvarSext + RulePtrFlow.
- [task9-subvariableflow-plan](task9-subvariableflow-plan.md) — SubVariableFlow landed. [task9-stage3-blocker](task9-stage3-blocker.md) — RESOLVED `4fa456c`.
- [task6-lanedivide-plan](task6-lanedivide-plan.md) — LaneDivide LIVE `2993771`.
- [task6-call-output-in-rax](task6-call-output-in-rax.md) — ActiveReturn CALL-output chain `2be93b4`.
- [task-guardcalls-ram](task-guardcalls-ram.md) — guardCalls ram-globals `e73a1c0`.
- [task-sb-spacebase-placeholder](task-sb-spacebase-placeholder.md) — #7 S1 ram branch `cf14470`.
- [task5-condconst](task5-condconst.md) — ActionConditionalConst ✅.
- [task4-modulo-signed-magic](task4-modulo-signed-magic.md) — RuleConstFold isCollapsible guard `28d07c2`.
- [task20-defuse-divopt-plan](task20-defuse-divopt-plan.md) — RuleDivOpt de-fused `071886c`.
- [task11-float-nan-plan](task11-float-nan-plan.md) — float/NAN cluster ✅; deferred: RuleIgnoreNan CBRANCH.
- [task2-p4-types-grounding](task2-p4-types-grounding.md) — P4 C1+C3 landed; C2/C4/C5 deferred.
- [task15-phase1b-tail](task15-splitstore-blocked.md) — Phase-1b tail; SubNormal `9f9ebca`; gotchas in-file.
